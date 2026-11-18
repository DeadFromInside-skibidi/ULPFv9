//! Compiled hot path for ULPF.
//!
//! `Engine` turns a batch of raw journal records into Arrow column buffers of
//! the event store (unified schema, `EVENT_COLUMNS` order), with no Python
//! object per event and the GIL released while it works:
//!
//!   detect -> parse (syslog, CEF, LEEF, key=value, JSON) -> normalise
//!   (timestamps, severity, actions, protocols, field mapping) -> worker fields
//!   -> enrichment from per-IP lookups -> row, BLAKE2b row MAC, Arrow buffers
//!
//! Equivalence rule: a line is processed here only when every step reproduces
//! the Python pipeline exactly; otherwise its index is returned in
//! `Batch.delegated` and the caller runs it through the Python pipeline, in
//! order. `tests/test_native_lane.py` compares both paths row by row.
//!
//! `legacy` keeps the 9.0 dict-based `build_normalized_event` (opt-in, slower).

mod analytics;
mod apg;
mod bloom;
mod crypto;
mod hot;
mod intel;
mod bench;
mod anomaly;
mod detect;
mod drift;
mod engine;
mod ffi;
mod listen;
mod legacy;
mod norm;
mod parsers;
mod pysem;
mod scan;
mod timefmt;
mod val;

use engine::{BatchArgs, Columns, Core, Geo, Ioc};
use norm::Tables;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyCapsule, PyDict, PyFloat, PyList, PyLong, PyString, PyTuple};
use std::ffi::CString;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::sync::Arc;
use val::{Map, Val};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn tables_from(d: &Bound<'_, PyDict>) -> PyResult<Tables> {
    let get = |k: &str| -> PyResult<Bound<'_, PyAny>> {
        d.get_item(k)?.ok_or_else(|| PyValueError::new_err(format!("Engine: missing table {k}")))
    };
    let dict = |k: &str| -> PyResult<Bound<'_, PyDict>> { Ok(get(k)?.downcast_into::<PyDict>()?) };
    let smap = |k: &str| -> PyResult<HashMap<String, String>> {
        dict(k)?.iter().map(|(a, b)| Ok((a.extract()?, b.extract()?))).collect()
    };
    let paths = |k: &str| -> PyResult<HashMap<String, Vec<String>>> {
        dict(k)?.iter().map(|(a, b)| Ok((a.extract()?, b.extract()?))).collect()
    };
    let imap = |k: &str| -> PyResult<HashMap<String, i64>> {
        dict(k)?.iter().map(|(a, b)| Ok((a.extract()?, b.extract()?))).collect()
    };
    Ok(Tables {
        aliases: paths("aliases")?,
        schema_paths: paths("schema_paths")?,
        action_map: smap("action_map")?,
        direction_map: smap("direction_map")?,
        protocol_map: dict("protocol_map")?.iter().map(|(a, b)| Ok((a.extract()?, b.extract()?))).collect::<PyResult<_>>()?,
        protocol_names: imap("protocol_names")?,
        syslog_sev: dict("syslog_sev")?.iter().map(|(a, b)| Ok((a.extract()?, b.extract()?))).collect::<PyResult<_>>()?,
        cef_sev: imap("cef_sev")?,
        text_sev: imap("text_sev")?,
        categories: get("categories")?.extract()?,
        category_aliases: smap("category_aliases")?,
        nullish: get("nullish")?.extract::<Vec<String>>()?.into_iter().collect::<HashSet<_>>(),
        int_fields: get("int_fields")?.extract::<Vec<String>>()?.into_iter().collect::<HashSet<_>>(),
        schema_version: get("schema_version")?.extract()?,
    })
}

/// A scalar Python value (GeoIP record fields) as a Val.
fn py_val(v: &Bound<'_, PyAny>) -> PyResult<Val> {
    Ok(if v.is_none() {
        Val::Null
    } else if v.is_instance_of::<PyBool>() {
        Val::Bool(v.extract()?)
    } else if v.is_instance_of::<PyLong>() {
        Val::Int(v.extract()?)
    } else if v.is_instance_of::<PyFloat>() {
        Val::Float(v.extract()?)
    } else if v.is_instance_of::<PyString>() {
        Val::string(v.extract()?)
    } else {
        Val::string(v.str()?.extract()?)
    })
}

/// Any Python value of an event dict as a Val (containers recursively; other objects as str()).
fn py_any(v: &Bound<'_, PyAny>) -> PyResult<Val> {
    if let Ok(l) = v.downcast::<PyList>() {
        return Ok(Val::List(l.iter().map(|x| py_any(&x)).collect::<PyResult<_>>()?));
    }
    if let Ok(d) = v.downcast::<PyDict>() {
        let mut m = Map::new();
        for (k, x) in d.iter() {
            m.set(k.str()?.extract::<String>()?, py_any(&x)?);
        }
        return Ok(Val::Map(m));
    }
    py_val(v)
}

fn val_to_py(py: Python<'_>, v: &Val) -> PyObject {
    match v {
        Val::Null => py.None(),
        Val::Bool(b) => b.into_py(py),
        Val::Int(i) => i.into_py(py),
        Val::Float(f) => f.into_py(py),
        Val::Str(s) => s.into_py(py),
        Val::List(l) => PyList::new_bound(py, l.iter().map(|x| val_to_py(py, x))).into_any().unbind(),
        Val::Map(m) => {
            let d = PyDict::new_bound(py);
            for (k, x) in &m.0 {
                let _ = d.set_item(k.as_ref(), val_to_py(py, x));
            }
            d.into_any().unbind()
        }
    }
}

fn num_to_py(py: Python<'_>, n: anomaly::Num) -> PyObject {
    match n {
        anomaly::Num::I(i) => i.into_py(py),
        anomaly::Num::F(f) => f.into_py(py),
    }
}

/// The store rows of a batch, for `pyarrow.record_batch(obj)` (Arrow PyCapsule interface:
/// the column buffers move to pyarrow without a copy). Consumed by the first import.
#[pyclass]
struct ArrowBatch {
    inner: Option<(ffi::ArrowSchema, ffi::ArrowArray)>,
}

#[pymethods]
impl ArrowBatch {
    #[pyo3(signature = (requested_schema=None))]
    fn __arrow_c_array__<'py>(&mut self, py: Python<'py>, requested_schema: Option<PyObject>)
                              -> PyResult<(Bound<'py, PyCapsule>, Bound<'py, PyCapsule>)> {
        let _ = requested_schema; // the store schema is the only one offered
        let (schema, array) = self.inner.take()
            .ok_or_else(|| PyRuntimeError::new_err("the batch was already imported"))?;
        let sc = PyCapsule::new_bound(py, schema, Some(CString::new("arrow_schema").unwrap()))?;
        let ac = PyCapsule::new_bound(py, array, Some(CString::new("arrow_array").unwrap()))?;
        Ok((sc, ac))
    }
}

/// Sigma rules and routes compiled for native events (`SigmaEngine.ir()`, `Router.ir()`).
#[pyclass(frozen)]
struct Analytics {
    sigma: Option<analytics::Sigma>,
    router: Option<analytics::Router>,
}

#[pymethods]
impl Analytics {
    #[new]
    #[pyo3(signature = (sigma=None, router=None))]
    fn new(sigma: Option<&str>, router: Option<&str>) -> PyResult<Self> {
        let sigma = sigma.map(analytics::Sigma::from_json).transpose().map_err(PyValueError::new_err)?;
        let router = router.map(analytics::Router::from_json).transpose().map_err(PyValueError::new_err)?;
        Ok(Analytics { sigma, router })
    }

    #[getter]
    fn rules(&self) -> usize {
        self.sigma.as_ref().map(|s| s.len()).unwrap_or(0)
    }

    /// Prefilter effect so far: (events, candidate rules, conditions evaluated).
    fn sigma_stats(&self) -> (u64, u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        self.sigma.as_ref().map(|s| (s.stats[0].load(Relaxed), s.stats[1].load(Relaxed), s.stats[2].load(Relaxed)))
            .unwrap_or((0, 0, 0))
    }

    /// `SigmaEngine.match` on one event given as JSON (tests and benchmarks): the hits as JSON,
    /// or None when the event is undecided (Python decides).
    fn sigma_match_json(&self, py: Python<'_>, event_json: &str) -> PyResult<Option<String>> {
        let sig = self.sigma.as_ref().ok_or_else(|| PyValueError::new_err("no Sigma rules loaded"))?;
        let j: serde_json::Value = serde_json::from_str(event_json).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let ev = match parsers::to_val(&j) {
            Ok(Val::Map(m)) => m,
            Ok(_) => return Err(PyValueError::new_err("the event must be a JSON object")),
            Err(_) => return Ok(None),          // values the native lane leaves to Python (non-ASCII)
        };
        Ok(py.allow_threads(|| {
            let mut out = String::new();
            sig.match_json(&ev, &mut out).ok().map(|_| out)
        }))
    }
}

/// Per-event anomaly state (`AnomalyDetector.analyse_event`), shared by every batch of a worker.
#[pyclass]
struct AnomalyState {
    st: anomaly::State,
}

#[pymethods]
impl AnomalyState {
    #[new]
    #[pyo3(signature = (window, z_threshold, max_known_ips, warmup, max_novelty=None))]
    fn new(window: usize, z_threshold: f64, max_known_ips: usize, warmup: i64, max_novelty: Option<f64>) -> Self {
        AnomalyState { st: anomaly::State::new(anomaly::Config { window, z_threshold, max_known_ips, warmup,
                                                                  max_novelty }) }
    }

    #[getter]
    fn total_events(&self) -> i64 {
        self.st.total
    }

    /// Analyse a batch in record order: the native events of `batch` (after `finish`) merged
    /// with Python-path events `py` = [(index, severity, src_ip, dst_ip, bytes_in, bytes_out,
    /// event_id)] (pass `batch=None` for a batch of Python events only).
    /// Returns (findings, severities): findings are ("severity_spike" | "bytes_spike", value,
    /// mean, std, z, event_id) or ("new_ip", ip, endpoint, event_id) in order; severities are
    /// `e.get("severity", 0) or 0` of every event, for the batch-level checks.
    #[pyo3(signature = (batch, py))]
    fn analyse(&mut self, pyth: Python<'_>, batch: Option<PyRef<'_, Batch>>, py: &Bound<'_, PyList>)
               -> PyResult<(Vec<PyObject>, Vec<PyObject>)> {
        struct PyObs {
            idx: usize,
            vals: [Val; 5],
            event_id: Val,
        }
        let mut items: Vec<PyObs> = Vec::with_capacity(py.len());
        for t in py.iter() {
            let t = t.downcast::<PyTuple>()?;
            items.push(PyObs {
                idx: t.get_item(0)?.extract()?,
                vals: [py_any(&t.get_item(1)?)?, py_any(&t.get_item(2)?)?, py_any(&t.get_item(3)?)?,
                       py_any(&t.get_item(4)?)?, py_any(&t.get_item(5)?)?],
                event_id: py_any(&t.get_item(6)?)?,
            });
        }
        let empty: Vec<Option<Map>> = Vec::new();
        let events = batch.as_ref().map(|b| &b.events).unwrap_or(&empty);
        let mut findings: Vec<PyObject> = Vec::new();
        let mut sevs: Vec<PyObject> = Vec::with_capacity(events.len() + items.len());
        let mut buf: Vec<anomaly::Finding> = Vec::new();
        let mut pi = 0;
        let n = events.len().max(items.iter().map(|x| x.idx + 1).max().unwrap_or(0));
        for i in 0..n {
            let native = events.get(i).and_then(|e| e.as_ref());
            let (obs, eid, sev): (anomaly::Obs, Val, Val) = if let Some(ev) = native {
                let net = ev.sub_ref("network");
                (anomaly::Obs { severity: Some(ev.get("severity").unwrap_or(&Val::Int(0))),
                                ips: [ev.sub_ref("source").get("ip"), ev.sub_ref("destination").get("ip")],
                                bytes: [net.get("bytes_in"), net.get("bytes_out")] },
                 ev.get("event_id").cloned().unwrap_or(Val::Null), ev.get("severity").cloned().unwrap_or(Val::Int(0)))
            } else if pi < items.len() && items[pi].idx == i {
                let it = &items[pi];
                pi += 1;
                (anomaly::Obs { severity: Some(&it.vals[0]), ips: [Some(&it.vals[1]), Some(&it.vals[2])],
                                bytes: [Some(&it.vals[3]), Some(&it.vals[4])] },
                 it.event_id.clone(), it.vals[0].clone())
            } else {
                continue;
            };
            buf.clear();
            self.st.analyse(&obs, &mut buf).map_err(pyo3::exceptions::PyTypeError::new_err)?;
            sevs.push(if sev.truthy() { val_to_py(pyth, &sev) } else { 0i64.into_py(pyth) });
            for f in buf.drain(..) {
                findings.push(match f {
                    anomaly::Finding::Spike(kind, v, mean, std, z) =>
                        (kind, num_to_py(pyth, v), mean, std, z, val_to_py(pyth, &eid)).into_py(pyth),
                    anomaly::Finding::NewIp(ip, endpoint) =>
                        ("new_ip", val_to_py(pyth, &ip), endpoint, val_to_py(pyth, &eid)).into_py(pyth),
                });
            }
        }
        if pi != items.len() {
            return Err(PyValueError::new_err("python events must be in index order and not native"));
        }
        Ok((findings, sevs))
    }
}

/// An immutable snapshot of the adaptive learned parsers (`registry.AnchorIndex`): pattern,
/// rank and learned source per parser, in the index's order. None = a pattern Python must run.
#[pyclass(frozen)]
struct ApgSet {
    set: Arc<apg::Set>,
}

#[pymethods]
impl ApgSet {
    /// `extracts`: per parser, JSON {"names", "kv_format", "kv_names": [[key, name]],
    /// "defaults": [[name, value]]} for the core to extract the fields, or None (Python does).
    #[new]
    #[pyo3(signature = (patterns, ranks, sources, extracts=None))]
    fn new(patterns: Vec<Option<String>>, ranks: Vec<u32>, sources: Vec<String>,
           extracts: Option<Vec<Option<String>>>) -> PyResult<Self> {
        if patterns.len() != ranks.len() || patterns.len() != sources.len() {
            return Err(PyValueError::new_err("patterns, ranks and sources differ in length"));
        }
        let mut ex = Vec::new();
        for j in extracts.unwrap_or_default() {
            ex.push(match j {
                None => None,
                Some(j) => {
                    let v: serde_json::Value = serde_json::from_str(&j).map_err(|e| PyValueError::new_err(e.to_string()))?;
                    let strs = |k: &str| -> Vec<String> {
                        v[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect()).unwrap_or_default()
                    };
                    let pairs = |k: &str| -> Vec<(String, String)> {
                        v[k].as_array().map(|a| a.iter().filter_map(|p| Some((p[0].as_str()?.to_owned(), p[1].as_str()?.to_owned()))).collect()).unwrap_or_default()
                    };
                    Some(apg::Extract { names: strs("names"), kv_format: v["kv_format"].as_bool().unwrap_or(false),
                                        kv_names: pairs("kv_names"), defaults: pairs("defaults") })
                }
            });
        }
        Ok(ApgSet { set: Arc::new(apg::Set::build(patterns, ranks, sources, ex)) })
    }

    /// Parsers whose pattern did not compile here (Python runs them).
    #[getter]
    fn failed(&self) -> Vec<usize> {
        self.set.failed().to_vec()
    }

    /// The winning parser for `line`: (index, fields dict) when the core extracted them, else
    /// (index, [group values]); None = no parser matches; (-1, []) = undecided (the caller runs
    /// the Python index).
    fn first_match(&self, py: Python<'_>, line: &str, source: &str) -> PyResult<Option<(i64, PyObject)>> {
        let set = self.set.clone();
        Ok(match py.allow_threads(|| set.first_match(line, source)) {
            apg::Hit::None => None,
            apg::Hit::Undecided => Some((-1, PyList::empty_bound(py).into_py(py))),
            apg::Hit::Parser(i, _, Some(fields)) => {
                let d = PyDict::new_bound(py);
                for (k, v) in fields {
                    d.set_item(k, v)?;
                }
                Some((i as i64, d.into_py(py)))
            }
            apg::Hit::Parser(i, g, None) => Some((i as i64, g.into_py(py))),
        })
    }
}

/// The current `ApgSet`, swapped atomically (ArcSwap): readers never lock, and a reader keeps
/// the snapshot it loaded for the whole lookup.
#[pyclass(frozen)]
struct ApgMatcher {
    cur: arc_swap::ArcSwap<apg::Set>,
    version: std::sync::atomic::AtomicU64,
}

#[pymethods]
impl ApgMatcher {
    #[new]
    fn new() -> Self {
        ApgMatcher { cur: arc_swap::ArcSwap::from_pointee(apg::Set::build(Vec::new(), Vec::new(), Vec::new(), Vec::new())),
                     version: std::sync::atomic::AtomicU64::new(0) }
    }

    /// Publish `set`; returns the new version.
    fn publish(&self, set: &ApgSet) -> u64 {
        self.cur.store(set.set.clone());
        self.version.fetch_add(1, std::sync::atomic::Ordering::AcqRel) + 1
    }

    fn current(&self) -> ApgSet {
        ApgSet { set: self.cur.load_full() }
    }

    #[getter]
    fn version(&self) -> u64 {
        self.version.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// The lakehouse hot tier: a memory-mapped ring file (see `hot.rs`). One writer per file.
#[pyclass(frozen)]
struct HotRing {
    ring: hot::Ring,
}

#[pymethods]
impl HotRing {
    /// Open `path`, creating a ring with `capacity` data bytes when it does not exist.
    #[new]
    #[pyo3(signature = (path, capacity=0))]
    fn new(path: &str, capacity: u64) -> PyResult<Self> {
        Ok(HotRing { ring: hot::Ring::open(path, capacity).map_err(PyValueError::new_err)? })
    }

    /// Append (partition key, payload); returns its position, or None when the ring is full of
    /// records not yet flushed to the cold tier.
    fn append(&self, py: Python<'_>, key: &str, payload: &[u8]) -> PyResult<Option<u64>> {
        let r = &self.ring;
        py.allow_threads(|| r.append(key, payload)).map_err(PyValueError::new_err)
    }

    /// Records from `pos`: ([(pos, seq, key, payload)], next position, bytes lost to overwrite).
    #[pyo3(signature = (pos, max_bytes=16 << 20))]
    fn read(&self, py: Python<'_>, pos: u64, max_bytes: u64) -> (Vec<(u64, u64, String, PyObject)>, u64, u64) {
        let r = &self.ring;
        let (recs, next, skipped) = py.allow_threads(|| r.read(pos, max_bytes));
        (recs.into_iter().map(|x| (x.pos, x.seq, x.key, PyBytes::new_bound(py, &x.payload).into_py(py))).collect(),
         next, skipped)
    }

    fn set_flushed(&self, pos: u64) -> PyResult<()> {
        self.ring.set_flushed(pos).map_err(PyRuntimeError::new_err)
    }

    /// msync everything appended so far (before acknowledging the source of the records).
    fn sync(&self, py: Python<'_>) -> PyResult<()> {
        let r = &self.ring;
        py.allow_threads(|| r.sync()).map_err(PyRuntimeError::new_err)
    }

    #[getter]
    fn head(&self) -> u64 {
        self.ring.head()
    }
    #[getter]
    fn tail(&self) -> u64 {
        self.ring.tail()
    }
    #[getter]
    fn flushed(&self) -> u64 {
        self.ring.flushed()
    }
    #[getter]
    fn capacity(&self) -> u64 {
        self.ring.capacity()
    }
}

/// Bloom filter over string values (lakehouse file pruning; see `bloom.rs`).
#[pyclass]
struct Bloom {
    b: bloom::Bloom,
}

#[pymethods]
impl Bloom {
    #[new]
    #[pyo3(signature = (ndv, fpp=0.01))]
    fn new(ndv: u64, fpp: f64) -> Self {
        Bloom { b: bloom::Bloom::new(ndv, fpp) }
    }

    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        Ok(Bloom { b: bloom::Bloom::from_bytes(data).map_err(PyValueError::new_err)? })
    }

    /// Add every non-null value: an Arrow string array (read in place through the C Data
    /// Interface), or any iterable (str, or anything whose str() is indexed).
    fn add_many(&mut self, values: &Bound<'_, PyAny>) -> PyResult<()> {
        if values.hasattr("__arrow_c_array__")? {
            let caps = values.call_method0("__arrow_c_array__")?;
            let (sc, ac): (Bound<'_, PyCapsule>, Bound<'_, PyCapsule>) = caps.extract()?;
            let b = &mut self.b;
            // SAFETY: the capsules hold valid ArrowSchema / ArrowArray structs (Arrow PyCapsule
            // protocol) and stay alive, unreleased, until this call returns.
            return unsafe {
                ffi::for_each_utf8(sc.pointer() as *const ffi::ArrowSchema, ac.pointer() as *const ffi::ArrowArray,
                                   |v| b.add(v))
            }.map_err(PyValueError::new_err);
        }
        for v in values.iter()? {
            let v = v?;
            if v.is_none() {
                continue;
            }
            match v.downcast::<PyString>() {
                Ok(s) => self.b.add(s.to_str()?.as_bytes()),
                Err(_) => self.b.add(v.str()?.to_str()?.as_bytes()),
            }
        }
        Ok(())
    }

    fn __contains__(&self, v: &str) -> bool {
        self.b.contains(v.as_bytes())
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.b.to_bytes())
    }
}

/// Format-drift windows (`DriftMonitor.observe_items`), shared by every batch of a worker.
#[pyclass]
struct DriftState {
    st: drift::State,
}

#[pymethods]
impl DriftState {
    #[new]
    fn new(sample_lines: u64, min_interval_seconds: f64, threshold: f64) -> Self {
        DriftState { st: drift::State::new(sample_lines, min_interval_seconds, threshold) }
    }

    /// Observe a batch in record order: the native events of `batch` merged with Python-path
    /// items `py` = [(index, raw_format, structure signature, raw_event)]. Returns the drifts:
    /// [(index, family, base_dist, base_lines, dist, lines, similarity, event_id, journal_seq,
    /// node_id)], distributions as [(signature, share)] in Python's order; the last three are
    /// None for Python-path events.
    #[pyo3(signature = (input_name, source, batch, py))]
    fn observe(&mut self, pyth: Python<'_>, input_name: &str, source: &str, batch: Option<PyRef<'_, Batch>>,
               py: &Bound<'_, PyList>) -> PyResult<Vec<PyObject>> {
        let mut items: Vec<(usize, Option<String>, String, String)> = Vec::with_capacity(py.len());
        for t in py.iter() {
            let t = t.downcast::<PyTuple>()?;
            items.push((t.get_item(0)?.extract()?, t.get_item(1)?.extract().ok(),
                        t.get_item(2)?.extract::<Option<String>>()?.unwrap_or_default(),
                        t.get_item(3)?.extract::<Option<String>>()?.unwrap_or_default()));
        }
        let empty: Vec<Option<Map>> = Vec::new();
        let events = batch.as_ref().map(|b| &b.events).unwrap_or(&empty);
        let n = events.len().max(items.iter().map(|x| x.0 + 1).max().unwrap_or(0));
        let mut out = Vec::new();
        let mut pi = 0;
        for i in 0..n {
            let (fired, refs) = if let Some(ev) = events.get(i).and_then(|e| e.as_ref()) {
                let sig = engine::structure_signature(ev);
                let raw = match ev.get("raw_event") {
                    Some(Val::Str(s)) => s.as_str(),
                    _ => "",
                };
                let it = drift::Item { fmt: ev.get_str("raw_format"), sig: &sig, raw };
                let e = ev.sub_ref("evidence");
                (self.st.observe(input_name, source, &it),
                 Some((ev.get("event_id").cloned().unwrap_or(Val::Null), e.get("journal_seq").cloned().unwrap_or(Val::Null),
                       e.get("node_id").cloned().unwrap_or(Val::Null))))
            } else if pi < items.len() && items[pi].0 == i {
                let (_, fmt, sig, raw) = &items[pi];
                pi += 1;
                (self.st.observe(input_name, source, &drift::Item { fmt: fmt.as_deref(), sig, raw }), None)
            } else {
                continue;
            };
            if let Some(f) = fired {
                let (eid, seq, node) = match refs {
                    Some((a, b, c)) => (val_to_py(pyth, &a), val_to_py(pyth, &b), val_to_py(pyth, &c)),
                    None => (pyth.None(), pyth.None(), pyth.None()),
                };
                out.push((i, f.family, f.base_dist, f.base_lines, f.dist, f.lines, f.sim, eid, seq, node).into_py(pyth));
            }
        }
        if pi != items.len() {
            return Err(PyValueError::new_err("python events must be in index order and not native"));
        }
        Ok(out)
    }
}

#[pyclass(frozen)]
struct Engine {
    core: Arc<Core>,
}

#[pymethods]
impl Engine {
    #[new]
    fn new(tables: &Bound<'_, PyDict>) -> PyResult<Self> {
        Ok(Engine { core: Arc::new(Core { t: tables_from(tables)?, det: detect::Detector::new(), p: parsers::Parsers::new() }) })
    }

    /// Pass 1 over one dispatcher batch (raw records, their SHA-256 digests).
    #[pyo3(signature = (raws, digests, first_seq, node, input_name, source, source_ip, now))]
    #[allow(clippy::too_many_arguments)]
    fn parse(&self, py: Python<'_>, raws: &Bound<'_, PyList>, digests: Vec<Vec<u8>>, first_seq: i64, node: String,
             input_name: String, source: String, source_ip: String, now: String) -> PyResult<Batch> {
        if raws.len() != digests.len() {
            return Err(PyValueError::new_err("raws and digests differ in length"));
        }
        // zero-copy: the records are read where Python holds them. The bytes objects are
        // immutable and `keep` holds a reference to each until the core is done.
        let mut keep: Vec<Bound<'_, PyBytes>> = Vec::with_capacity(raws.len());
        let mut parts: Vec<(usize, usize)> = Vec::with_capacity(raws.len());
        for r in raws.iter() {
            let b = r.downcast_into::<PyBytes>()?;
            let s = b.as_bytes();
            parts.push((s.as_ptr() as usize, s.len()));
            keep.push(b);
        }
        let core = self.core.clone();
        let events = py.allow_threads(move || {
            let a = BatchArgs { node: &node, input_name: &input_name, source: &source,
                                source_ip: &source_ip, now: &now };
            parts.iter().zip(digests.iter()).enumerate()
                .map(|(i, (&(p, n), d))| {
                    let r = unsafe { std::slice::from_raw_parts(p as *const u8, n) };
                    core.one(r, d, first_seq + i as i64, &a)
                })
                .collect::<Vec<Option<Map>>>()
        });
        drop(keep);
        let delegated = events.iter().enumerate().filter(|(_, e)| e.is_none()).map(|(i, _)| i).collect();
        let native = events.iter().enumerate().filter(|(_, e)| e.is_some()).map(|(i, _)| i).collect();
        Ok(Batch { events, first_seq, done: false, delegated, native })
    }

    /// Per-stage cost in ns of one record, repeated `n` times (profiling aid).
    fn profile(&self, raw: Vec<u8>, n: usize) -> Vec<(String, f64)> {
        use std::time::Instant;
        let core = &self.core;
        let a = BatchArgs { node: "n", input_name: "i", source: "s", source_ip: "", now: "2026-01-01T00:00:00.000+00:00" };
        let digest = [0u8; 32];
        let line = std::str::from_utf8(&raw).unwrap().trim();
        let mut out = Vec::new();
        let t = Instant::now();
        for _ in 0..n { let mut j = None; std::hint::black_box(core.det.detect(line, &mut j)); }
        out.push(("detect".into(), t.elapsed().as_nanos() as f64 / n as f64));
        let t = Instant::now();
        for _ in 0..n { std::hint::black_box(engine::event_id("n", 1)); }
        out.push(("event_id".into(), t.elapsed().as_nanos() as f64 / n as f64));
        let t = Instant::now();
        for _ in 0..n { std::hint::black_box(norm::new_event("x", "now", "1.1.0")); }
        out.push(("new_event".into(), t.elapsed().as_nanos() as f64 / n as f64));
        let t = Instant::now();
        let mut ev = None;
        for _ in 0..n { ev = core.one(&raw, &digest, 1, &a); }
        out.push(("one".into(), t.elapsed().as_nanos() as f64 / n as f64));
        let ev = ev.unwrap();
        let t = Instant::now();
        for _ in 0..n { let mut e = ev.clone(); engine::enrich(&mut e, &HashMap::default(), &HashMap::default(), &[], None); std::hint::black_box(e); }
        out.push(("clone+enrich".into(), t.elapsed().as_nanos() as f64 / n as f64));
        let t = Instant::now();
        let mut cols = Columns::new(n);
        for _ in 0..n { cols.append(&ev, Some(&[7u8; 32])).unwrap(); }
        std::hint::black_box(cols.finish());
        out.push(("row+mac".into(), t.elapsed().as_nanos() as f64 / n as f64));
        let t = Instant::now();
        let mut cols = Columns::new(n);
        for _ in 0..n { cols.append(&ev, None).unwrap(); }
        std::hint::black_box(cols.finish());
        out.push(("row".into(), t.elapsed().as_nanos() as f64 / n as f64));
        let t = Instant::now();
        let mut s = String::with_capacity(4096);
        for _ in 0..n { s.clear(); val::write_json_map(&ev, &mut s, &["raw_event", "parsed_fields"]); }
        out.push(("norm_json".into(), t.elapsed().as_nanos() as f64 / n as f64));
        out.push(("norm_json_bytes".into(), s.len() as f64));
        out
    }
}

#[pyclass]
struct Batch {
    events: Vec<Option<Map>>,
    first_seq: i64,
    done: bool,
    delegated: Vec<usize>,
    native: Vec<usize>,
}

#[pymethods]
impl Batch {
    /// Indices of the records the Python pipeline must process (in order).
    #[getter]
    fn delegated(&self) -> Vec<usize> {
        self.delegated.clone()
    }

    #[getter]
    fn native(&self) -> Vec<usize> {
        self.native.clone()
    }

    /// Distinct source/destination addresses to look up (GeoIP, IOCs).
    fn ips(&self) -> Vec<String> {
        engine::distinct_ips(&self.events)
    }

    /// Pass 2: enrichment, input tags, store rows (Arrow buffers) and optionally the events
    /// (JSON array) and correlation projections (JSON array), for the native records only.
    ///
    /// geo: {ip: (country, cc, city, lat, lon)}   ioc: {ip: (category, confidence, tag)}
    /// key_runs: [(first_seq, last_seq, key)] for row MACs, or None
    ///
    /// analytics: an `Analytics`; with Sigma rules, projections carry their hits ("sigma"; null
    /// for the native positions in "sigma_undecided", which Python evaluates); with routes,
    /// "targets" holds each native event's sink indices and "unrouted" their count.
    /// The enriched events stay in the batch (`drift_items`, `events_json`, `AnomalyState`).
    /// intel: an `IocMatcher` (replaces the ioc dict: IPs, domains, URLs, hashes, ... of the raw text too).
    #[pyo3(signature = (geo, ioc, tags, key_runs=None, want_events=false, want_projections=false, analytics=None, intel=None))]
    #[allow(clippy::too_many_arguments)]
    fn finish<'py>(&mut self, py: Python<'py>, geo: &Bound<'py, PyDict>, ioc: &Bound<'py, PyDict>, tags: Vec<String>,
                   key_runs: Option<Vec<(i64, i64, Vec<u8>)>>, want_events: bool, want_projections: bool,
                   analytics: Option<Py<Analytics>>, intel: Option<Py<IocMatcher>>) -> PyResult<Bound<'py, PyDict>> {
        if self.done {
            return Err(PyRuntimeError::new_err("Batch.finish() was already called"));
        }
        self.done = true;
        let mut g: HashMap<String, Geo> = HashMap::default();
        for (k, v) in geo.iter() {
            let t = v.downcast::<PyTuple>()?;
            g.insert(k.extract()?, Geo { country: py_val(&t.get_item(0)?)?, cc: py_val(&t.get_item(1)?)?,
                                         city: py_val(&t.get_item(2)?)?, lat: py_val(&t.get_item(3)?)?,
                                         lon: py_val(&t.get_item(4)?)? });
        }
        let mut io: HashMap<String, Ioc> = HashMap::default();
        for (k, v) in ioc.iter() {
            let t = v.downcast::<PyTuple>()?;
            io.insert(k.extract()?, Ioc { cat: t.get_item(0)?.extract()?, conf: t.get_item(1)?.extract()?,
                                          tag: t.get_item(2)?.extract()? });
        }
        let first_seq = self.first_seq;
        let mut events = std::mem::take(&mut self.events);
        let an = analytics.as_ref().map(|a| a.get());
        let im = intel.as_ref().map(|m| m.get().inner.load_full());
        let (out, events) = py.allow_threads(move || -> Result<(Finished, Vec<Option<Map>>), String> {
            let mut idx = Vec::new();
            let mut cols = Columns::new(events.len());
            for (i, ev) in events.iter_mut().enumerate() {
                let Some(ev) = ev else { continue };
                engine::enrich(ev, &g, &io, &tags, im.as_deref());
                let seq = first_seq + i as i64;
                let key = key_runs.as_ref().and_then(|runs| {
                    runs.iter().find(|(a, b, _)| *a <= seq && seq <= *b).map(|(_, _, k)| k.as_slice())
                });
                cols.append(ev, key)?;
                idx.push(i);
            }
            let (n, cols) = cols.finish();
            let natives: Vec<&Map> = events.iter().flatten().collect();
            let ev_json = if want_events { Some(engine::events_json(&natives)) } else { None };
            let sigma = an.and_then(|a| a.sigma.as_ref());
            let mut undecided = Vec::new();
            let mut matches = 0usize;
            let proj = if want_projections {
                let mut s = String::from("[");
                let mut hits = String::new();
                for (j, ev) in natives.iter().enumerate() {
                    if j > 0 {
                        s.push(',');
                    }
                    match sigma {
                        None => engine::write_projection(ev, &mut s),
                        Some(sg) => {
                            hits.clear();
                            match sg.match_json(ev, &mut hits) {
                                Ok(k) => {
                                    matches += k;
                                    engine::write_projection_with(ev, Some(&hits), &mut s)
                                }
                                Err(_) => {
                                    undecided.push(j);
                                    engine::write_projection_with(ev, Some("null"), &mut s)
                                }
                            }
                        }
                    }
                }
                s.push(']');
                Some(s)
            } else {
                None
            };
            let (targets, unrouted) = match an.and_then(|a| a.router.as_ref()) {
                Some(r) => {
                    let mut un = 0;
                    let t = natives.iter().map(|ev| {
                        let (t, u) = r.targets(ev);
                        un += u as usize;
                        t
                    }).collect();
                    (Some(t), un)
                }
                None => (None, 0),
            };
            Ok((Finished { idx, n, cols, ev_json, proj, undecided, matches, targets, unrouted }, events))
        }).map_err(PyRuntimeError::new_err)?;
        self.events = events;
        let d = PyDict::new_bound(py);
        d.set_item("n", out.n)?;
        d.set_item("rows", out.idx)?;
        d.set_item("sigma_undecided", out.undecided)?;
        d.set_item("sigma_matches", out.matches)?;
        // every native event routed alike (the common case): one list instead of one per event
        let uniform = match &out.targets {
            Some(t) if !t.is_empty() && t.iter().all(|x| *x == t[0]) => Some(t[0].clone()),
            _ => None,
        };
        if uniform.is_some() {
            d.set_item("targets", py.None())?;
        } else {
            d.set_item("targets", out.targets)?;
        }
        d.set_item("targets_uniform", uniform)?;
        d.set_item("unrouted", out.unrouted)?;
        let (schema, array) = ffi::export(out.n, out.cols);
        d.set_item("arrow", Py::new(py, ArrowBatch { inner: Some((schema, array)) })?)?;
        d.set_item("events", out.ev_json.map(|s| PyBytes::new_bound(py, s.as_bytes())))?;
        d.set_item("projections", out.proj.map(|s| PyBytes::new_bound(py, s.as_bytes())))?;
        Ok(d)
    }

    /// The finished native events at `positions` (indices into `native`) as a JSON array.
    fn events_json<'py>(&self, py: Python<'py>, positions: Vec<usize>) -> PyResult<Bound<'py, PyBytes>> {
        if !self.done {
            return Err(PyRuntimeError::new_err("Batch.finish() must run first"));
        }
        let natives: Vec<&Map> = self.events.iter().flatten().collect();
        let picked = positions.iter().map(|&p| natives.get(p).copied()
            .ok_or_else(|| PyValueError::new_err("position out of range"))).collect::<PyResult<Vec<_>>>()?;
        let s = py.allow_threads(|| engine::events_json(&picked));
        Ok(PyBytes::new_bound(py, s.as_bytes()))
    }

    /// For format-drift monitoring, per native event in order:
    /// (raw_format, structure signature, raw_event, event_id, journal_seq, node_id).
    fn drift_items(&self, py: Python<'_>) -> PyResult<Vec<PyObject>> {
        if !self.done {
            return Err(PyRuntimeError::new_err("Batch.finish() must run first"));
        }
        let g = |m: &Map, k: &str| val_to_py(py, m.get(k).unwrap_or(&Val::Null));
        Ok(self.events.iter().flatten().map(|ev| {
            let e = ev.sub_ref("evidence");
            (g(ev, "raw_format"), engine::structure_signature(ev), g(ev, "raw_event"), g(ev, "event_id"),
             g(e, "journal_seq"), g(e, "node_id")).into_py(py)
        }).collect())
    }
}

struct Finished {
    idx: Vec<usize>,
    n: usize,
    cols: Vec<engine::Column>,
    ev_json: Option<String>,
    proj: Option<String>,
    undecided: Vec<usize>,
    matches: usize,
    targets: Option<Vec<Vec<usize>>>,
    unrouted: usize,
}

/// Native `_parse_ts` subset, exposed for tests (None = Python decides).
#[pyfunction]
fn parse_ts_native(ts: &str) -> Option<String> {
    timefmt::parse_ts(ts)
}

/// A network listener on the core's Tokio runtime (`listen`): it frames and decodes, and
/// hands batches to the Python input that journals them.
#[pyclass]
struct NativeListener {
    h: Option<listen::Handle>,
}

#[pymethods]
impl NativeListener {
    /// config: JSON (see `ulpf.runtime.inputs.native`); binds before returning.
    #[new]
    fn new(py: Python<'_>, config: &str) -> PyResult<Self> {
        let cfg: serde_json::Value = serde_json::from_str(config).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let h = py.allow_threads(|| listen::start(&cfg)).map_err(PyValueError::new_err)?;
        Ok(NativeListener { h: Some(h) })
    }

    #[getter]
    fn bound_port(&self) -> u16 {
        self.h.as_ref().map(|h| h.bound_port).unwrap_or(0)
    }

    /// The next batch, waiting up to `timeout_ms` (GIL released): (input or None, source,
    /// [records], receive time), or None.
    fn next_batch<'py>(&self, py: Python<'py>, timeout_ms: u64) -> PyResult<Option<Bound<'py, PyTuple>>> {
        let Some(h) = self.h.as_ref() else { return Ok(None) };
        let got = py.allow_threads(|| {
            let mut rx = h.rx.lock().unwrap();
            h.rt.block_on(async { tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), rx.recv()).await })
        });
        match got {
            Ok(Some(out)) => {
                h.shared.stats.received.fetch_add(out.records.len() as u64, std::sync::atomic::Ordering::Relaxed);
                let recs = PyList::new_bound(py, out.records.iter().map(|r| PyBytes::new_bound(py, r)));
                Ok(Some(PyTuple::new_bound(py, [out.input.into_py(py), out.source.into_py(py), recs.into_any().unbind(),
                                                out.ts.into_py(py)])))
            }
            _ => Ok(None),
        }
    }

    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new_bound(py);
        if let Some(h) = &self.h {
            for (k, v) in h.shared.stats.snapshot() {
                d.set_item(k, v)?;
            }
            d.set_item("last_error", h.shared.stats.last_error.lock().unwrap().clone())?;
        }
        Ok(d)
    }

    /// Stop accepting, flush what the tasks hold, then shut the runtime down.
    fn stop(&mut self, py: Python<'_>) {
        if let Some(h) = self.h.take() {
            let _ = h.stop.send(true);
            py.allow_threads(|| {
                std::thread::sleep(std::time::Duration::from_millis(100));
                h.rt.shutdown_timeout(std::time::Duration::from_secs(2));
            });
        }
    }

    /// Batches still queued after `stop` (drained by the input before it exits).
    fn drain<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyTuple>>> {
        let mut out = Vec::new();
        while let Some(t) = self.next_batch(py, 0)? {
            out.push(t);
        }
        Ok(out)
    }
}

/// The listeners' decoders, for `tests/test_native_listeners.py`:
/// kind "syslog_stream" (framing, [chunks]) -> ([records], oversize count);
/// "syslog_datagram" (telemetry, data) -> [records]; "netflow" (exporter, [packets],
/// mapped_dotted) -> [records | error]; "snmp" (config json, data) -> record | error;
/// "otlp" (fallback source, body) -> [(source, [records])] | error.
#[pyfunction]
fn _listener_probe(py: Python<'_>, kind: &str, a: &Bound<'_, PyAny>, b: &Bound<'_, PyAny>, c: Option<bool>)
                   -> PyResult<PyObject> {
    let to_bytes = |v: &Bound<'_, PyAny>| -> PyResult<Vec<u8>> { v.extract::<Vec<u8>>() };
    Ok(match kind {
        "syslog_stream" => {
            let chunks: Vec<Vec<u8>> = b.extract()?;
            let refs: Vec<&[u8]> = chunks.iter().map(|x| x.as_slice()).collect();
            let (recs, over) = listen::syslog::frame_stream(&a.extract::<String>()?, &refs).map_err(PyValueError::new_err)?;
            (recs.into_iter().map(|r| PyBytes::new_bound(py, &r).unbind()).collect::<Vec<_>>(), over).into_py(py)
        }
        "syslog_datagram" => listen::syslog::datagram_records(&to_bytes(b)?, a.extract()?).into_iter()
            .map(|r| PyBytes::new_bound(py, &r).unbind()).collect::<Vec<_>>().into_py(py),
        "netflow" => {
            let packets: Vec<Vec<u8>> = b.extract()?;
            listen::netflow::decode_packets(&packets, &a.extract::<String>()?, c.unwrap_or(false)).into_iter()
                .map(|r| match r {
                    Ok(recs) => recs.into_iter().map(|x| PyBytes::new_bound(py, &x).unbind()).collect::<Vec<_>>().into_py(py),
                    Err(e) => e.into_py(py),
                }).collect::<Vec<_>>().into_py(py)
        }
        "snmp" => {
            let cfg: serde_json::Value = serde_json::from_str(&a.extract::<String>()?)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            let mut rx = listen::snmp::receiver(&cfg).map_err(PyValueError::new_err)?;
            match rx.parse(&to_bytes(b)?) {
                Ok((rec, resp)) => (PyBytes::new_bound(py, &listen::snmp::record(rec, "10.0.0.9")).unbind(),
                                    resp.map(|r| PyBytes::new_bound(py, &r).unbind())).into_py(py),
                Err(e) => e.into_py(py),
            }
        }
        "otlp" => match listen::otlp::decode_request(&to_bytes(b)?, &a.extract::<String>()?) {
            Ok(groups) => groups.into_iter().map(|(src, recs)| {
                (src, recs.into_iter().map(|r| PyBytes::new_bound(py, &r).unbind()).collect::<Vec<_>>())
            }).collect::<Vec<_>>().into_py(py),
            Err(e) => e.into_py(py),
        },
        _ => return Err(PyValueError::new_err(format!("unknown probe {kind}"))),
    })
}

/// The hand-written matchers of `scan`, with the results Python's `re` gives for the same
/// pattern (groups as str or None; findall lists), for `tests/test_native_scan.py`.
#[pyfunction]
fn _scan_probe(py: Python<'_>, name: &str, text: &str) -> PyResult<PyObject> {
    let sp = |s: Option<scan::Span>| s.map(|(a, b)| text[a..b].to_string());
    Ok(match name {
        "rfc3164" => scan::rfc3164(text).map(|g| g.map(sp).to_vec()).into_py(py),
        "plain" => scan::plain(text).map(|g| g.map(sp).to_vec()).into_py(py),
        "rfc5424" => scan::rfc5424(text).map(|g| g.map(sp).to_vec()).into_py(py),
        "ip" => {
            let mut v = Vec::new();
            scan::ipv4_findall(text, &mut v);
            v.into_iter().map(|x| sp(Some(x)).unwrap()).collect::<Vec<_>>().into_py(py)
        }
        "port" => {
            let mut v = Vec::new();
            scan::port_findall(text, &mut v);
            v.into_iter().map(|x| sp(Some(x)).unwrap()).collect::<Vec<_>>().into_py(py)
        }
        "cisco_pair" => {
            let mut v = Vec::new();
            scan::cisco_pairs(text, &mut v);
            v.into_iter().map(|(a, b)| (sp(Some(a)).unwrap(), sp(Some(b)).unwrap())).collect::<Vec<_>>().into_py(py)
        }
        "ssh" => scan::ssh(text).map(|(a, b, c)| (sp(Some(a)), sp(Some(b)), sp(Some(c)))).into_py(py),
        "cisco_mnemonic" => scan::cisco_mnemonic(text).map(|d| d.to_string()).into_py(py),
        "sd_param" => {
            let mut v = Vec::new();
            scan::sd_params(text, &mut v);
            v.into_iter().map(|(k, q, u)| (sp(Some(k)).unwrap(), sp(q), sp(u))).collect::<Vec<_>>().into_py(py)
        }
        "kv_any" => apg::kv_any(text).into_iter().map(|(k, v)| (k.to_owned(), v.to_owned())).collect::<Vec<_>>().into_py(py),
        "ext_split" => {
            let mut v = Vec::new();
            scan::ext_split(text, &mut v);
            v.into_iter().map(|(a, b, k)| (a, b, sp(Some(k)).unwrap())).collect::<Vec<_>>().into_py(py)
        }
        _ => return Err(PyValueError::new_err(format!("unknown matcher {name}"))),
    })
}

/// `ulpf.runtime.ids.event_id`, exposed for tests.
#[pyfunction]
fn event_id(node: &str, seq: i64) -> String {
    engine::event_id(node, seq)
}

#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Threat-intelligence indicators (`intel::Matcher`), swapped atomically on reload: matching
/// never locks, and a batch keeps the snapshot it started with.
#[pyclass(frozen)]
struct IocMatcher {
    inner: arc_swap::ArcSwap<intel::Matcher>,
}

#[pymethods]
impl IocMatcher {
    #[new]
    fn new() -> PyResult<Self> {
        let empty = intel::Matcher::from_bytes(b"ULPFIOC1        ").map_err(PyValueError::new_err)?;
        Ok(IocMatcher { inner: arc_swap::ArcSwap::from_pointee(empty) })
    }

    /// Replace the indicators with a snapshot (`ulpf.intelligence.tip.snapshot`); returns their count.
    fn load_bytes(&self, py: Python<'_>, data: &[u8]) -> PyResult<usize> {
        let m = py.allow_threads(|| intel::Matcher::from_bytes(data)).map_err(PyValueError::new_err)?;
        let n = m.entries.len();
        self.inner.store(std::sync::Arc::new(m));
        Ok(n)
    }

    fn load(&self, py: Python<'_>, path: &str) -> PyResult<usize> {
        let data = std::fs::read(path).map_err(|e| PyValueError::new_err(format!("{path}: {e}")))?;
        self.load_bytes(py, &data)
    }

    /// The first indicator among (source IP, destination IP, tokens of the text):
    /// (ioc_type, value, category, confidence, id, source, actor, campaign, kill_chain) or None.
    #[pyo3(signature = (src_ip=None, dst_ip=None, text=None))]
    #[allow(clippy::type_complexity)]
    fn match_event(&self, src_ip: Option<&str>, dst_ip: Option<&str>, text: Option<&str>)
                   -> Option<(&'static str, String, String, f64, String, String, String, String, String)> {
        let m = self.inner.load();
        let h = m.match_event(src_ip, dst_ip, text)?;
        let e = &m.entries[h.entry as usize];
        let st = |i: u32| m.strings[i as usize].clone();
        Some((intel::KINDS[h.kind as usize], h.value, st(e.cat), e.conf, st(e.id), st(e.source), st(e.actor),
              st(e.campaign), st(e.kill)))
    }

    /// Match many texts (benchmarks): number of events with a hit.
    fn count_matches(&self, py: Python<'_>, texts: Vec<String>) -> usize {
        let m = self.inner.load_full();
        py.allow_threads(|| texts.iter().filter(|t| m.match_event(None, None, Some(t)).is_some()).count())
    }

    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let m = self.inner.load();
        let d = PyDict::new_bound(py);
        d.set_item("indicators", m.entries.len())?;
        d.set_item("memory_bytes", m.memory())?;
        for (i, k) in intel::KINDS.iter().enumerate().skip(1) {
            d.set_item(*k, m.counts[i])?;
        }
        Ok(d)
    }
}

#[pymodule]
fn ulpf_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(parse_ts_native, m)?)?;
    m.add_function(wrap_pyfunction!(event_id, m)?)?;
    m.add_function(wrap_pyfunction!(_scan_probe, m)?)?;
    m.add_function(wrap_pyfunction!(_listener_probe, m)?)?;
    m.add_class::<NativeListener>()?;
    m.add_class::<Engine>()?;
    m.add_class::<Batch>()?;
    m.add_class::<ArrowBatch>()?;
    m.add_class::<Analytics>()?;
    m.add_class::<AnomalyState>()?;
    m.add_class::<DriftState>()?;
    m.add_class::<ApgSet>()?;
    m.add_class::<ApgMatcher>()?;
    m.add_class::<IocMatcher>()?;
    m.add_class::<HotRing>()?;
    m.add_class::<Bloom>()?;
    legacy::register(m)?;
    crypto::register(m)?;
    Ok(())
}
