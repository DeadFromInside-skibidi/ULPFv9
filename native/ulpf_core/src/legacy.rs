//! Legacy dict-based normalisation core (ULPF 9.0, `ULPF_NATIVE=1`).
//!
//! `build_normalized_event` is a drop-in replacement for
//! `ulpf.engine.normalizer.build_normalized_event`: every parser ends in it, so
//! it is the shared hot path (event construction, field mapping, timestamp,
//! severity, action, protocol and direction normalisation, raw hash).
//!
//! Equivalence rule: the native code handles only inputs whose Python
//! semantics it reproduces exactly (ASCII strings, plain ints, the common
//! timestamp shapes). Anything else is delegated to the Python reference
//! implementation, passed in once through `init()`. The Python module stays
//! the specification; `tests/test_native.py` compares both on every corpus line.

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::sync::GILOnceCell;
use pyo3::types::{PyDict, PyList, PyLong, PyString, PyTuple};
use pyo3::{intern, PyObject};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

struct Ctx {
    // Python reference implementations used for delegation
    parse_ts: PyObject,
    normalize_severity: PyObject,
    normalize_action: PyObject,
    normalize_protocol: PyObject,
    normalize_direction: PyObject,
    to_int: PyObject,
    resolve_field: PyObject,
    utc_now: PyObject,
    new_uuid: PyObject,
    canonical_category: PyObject,
    sha256_py: PyObject,
    schema_version: PyObject,
    // tables (copied from the Python module, so there is one source of truth)
    aliases: HashMap<String, Vec<String>>,
    schema_paths: HashMap<String, Vec<String>>,
    action_map: HashMap<String, String>,
    direction_map: HashMap<String, String>,
    protocol_map: HashMap<u32, String>,
    protocol_names: HashMap<String, u32>,
    syslog_sev: HashMap<u32, i64>,
    cef_sev: HashMap<String, i64>,
    text_sev: HashMap<String, i64>,
    categories: Vec<String>,
    category_aliases: HashMap<String, String>,
    nullish: Vec<String>,
    int_fields: Vec<String>,
}

static CTX: GILOnceCell<Ctx> = GILOnceCell::new();
static RESOLVE: Mutex<Option<HashMap<String, Option<Vec<String>>>>> = Mutex::new(None);
const RESOLVE_MAX: usize = 20_000;

fn ctx(py: Python<'_>) -> PyResult<&Ctx> {
    CTX.get(py).ok_or_else(|| PyRuntimeError::new_err("ulpf_core.init() was not called"))
}

fn str_map(d: &Bound<'_, PyDict>) -> PyResult<HashMap<String, String>> {
    let mut m = HashMap::new();
    for (k, v) in d.iter() {
        m.insert(k.extract::<String>()?, v.extract::<String>()?);
    }
    Ok(m)
}

fn path_map(d: &Bound<'_, PyDict>) -> PyResult<HashMap<String, Vec<String>>> {
    let mut m = HashMap::new();
    for (k, v) in d.iter() {
        let t: Vec<String> = v.extract()?;
        m.insert(k.extract::<String>()?, t);
    }
    Ok(m)
}

/// Register the Python reference functions and tables.
#[pyfunction]
fn init(py: Python<'_>, refs: &Bound<'_, PyDict>) -> PyResult<()> {
    let get = |k: &str| -> PyResult<Bound<'_, PyAny>> {
        refs.get_item(k)?.ok_or_else(|| PyRuntimeError::new_err(format!("init: missing {k}")))
    };
    let dict = |k: &str| -> PyResult<Bound<'_, PyDict>> { Ok(get(k)?.downcast_into::<PyDict>()?) };
    let mut protocol_map = HashMap::new();
    for (k, v) in dict("protocol_map")?.iter() {
        protocol_map.insert(k.extract::<u32>()?, v.extract::<String>()?);
    }
    let mut protocol_names = HashMap::new();
    for (k, v) in dict("protocol_names")?.iter() {
        protocol_names.insert(k.extract::<String>()?, v.extract::<u32>()?);
    }
    let mut syslog_sev = HashMap::new();
    for (k, v) in dict("syslog_sev")?.iter() {
        syslog_sev.insert(k.extract::<u32>()?, v.extract::<i64>()?);
    }
    let int_map = |k: &str| -> PyResult<HashMap<String, i64>> {
        let mut m = HashMap::new();
        for (a, b) in dict(k)?.iter() {
            m.insert(a.extract::<String>()?, b.extract::<i64>()?);
        }
        Ok(m)
    };
    let c = Ctx {
        parse_ts: get("parse_ts")?.unbind(),
        normalize_severity: get("normalize_severity")?.unbind(),
        normalize_action: get("normalize_action")?.unbind(),
        normalize_protocol: get("normalize_protocol")?.unbind(),
        normalize_direction: get("normalize_direction")?.unbind(),
        to_int: get("to_int")?.unbind(),
        resolve_field: get("resolve_field")?.unbind(),
        utc_now: get("utc_now")?.unbind(),
        new_uuid: get("new_uuid")?.unbind(),
        canonical_category: get("canonical_category")?.unbind(),
        sha256_py: get("sha256_py")?.unbind(),
        schema_version: get("schema_version")?.unbind(),
        aliases: path_map(&dict("aliases")?)?,
        schema_paths: path_map(&dict("schema_paths")?)?,
        action_map: str_map(&dict("action_map")?)?,
        direction_map: str_map(&dict("direction_map")?)?,
        protocol_map,
        protocol_names,
        syslog_sev,
        cef_sev: int_map("cef_sev")?,
        text_sev: int_map("text_sev")?,
        categories: get("categories")?.extract()?,
        category_aliases: str_map(&dict("category_aliases")?)?,
        nullish: get("nullish")?.extract()?,
        int_fields: get("int_fields")?.extract()?,
    };
    let _ = CTX.set(py, c);
    *RESOLVE.lock().unwrap() = Some(HashMap::new());
    Ok(())
}

// ---------------------------------------------------------------------------
// String helpers with Python semantics (ASCII only; callers delegate otherwise)
// ---------------------------------------------------------------------------

/// Python `str.strip()` whitespace restricted to ASCII (includes \x1c-\x1f).
fn is_py_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c | 0x1c | 0x1d | 0x1e | 0x1f)
}

fn py_strip(s: &str) -> &str {
    let b = s.as_bytes();
    let mut i = 0;
    let mut j = b.len();
    while i < j && is_py_ws(b[i]) {
        i += 1;
    }
    while j > i && is_py_ws(b[j - 1]) {
        j -= 1;
    }
    &s[i..j]
}

fn ascii_str<'a>(v: &'a Bound<'_, PyAny>) -> Option<String> {
    if !v.is_exact_instance_of::<PyString>() {
        return None;
    }
    let s = v.downcast::<PyString>().ok()?.to_str().ok()?;
    if s.is_ascii() {
        Some(s.to_owned())
    } else {
        None
    }
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn severity_label(v: i64) -> &'static str {
    match v {
        0 => "unknown",
        1 | 2 => "info",
        3 | 4 => "low",
        5 | 6 => "medium",
        7 | 8 => "high",
        9 | 10 => "critical",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Dates (proleptic Gregorian, UTC)
// ---------------------------------------------------------------------------

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn iso_utc(epoch_s: i64, micro: i64) -> String {
    let days = epoch_s.div_euclid(86400);
    let secs = epoch_s.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let (h, mi, s) = (secs / 3600, secs % 3600 / 60, secs % 60);
    if micro != 0 {
        format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{micro:06}+00:00")
    } else {
        format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}+00:00")
    }
}

fn num(s: &str) -> Option<i64> {
    if all_digits(s) {
        s.parse().ok()
    } else {
        None
    }
}

/// Strict subset of `datetime.fromisoformat` (Python 3.11): YYYY-MM-DD, optional
/// [T ]HH:MM:SS, optional .fff or .ffffff, optional Z or ±HH:MM. None = delegate.
fn parse_iso(ts: &str) -> Option<String> {
    let b = ts.as_bytes();
    if b.len() < 10 {
        return None;
    }
    let (y, mo, d) = (num(&ts[0..4])?, num(&ts[5..7])?, num(&ts[8..10])?);
    if !(2..=9998).contains(&y) || !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo) {
        return None;
    }
    let (mut h, mut mi, mut s, mut micro, mut off) = (0i64, 0i64, 0i64, 0i64, 0i64);
    let mut rest = &ts[10..];
    if !rest.is_empty() {
        let sep = rest.as_bytes()[0];
        if sep != b'T' && sep != b' ' {
            return None;
        }
        rest = &rest[1..];
        let rb = rest.as_bytes();
        if rb.len() < 8 || rb[2] != b':' || rb[5] != b':' {
            return None;
        }
        h = num(&rest[0..2])?;
        mi = num(&rest[3..5])?;
        s = num(&rest[6..8])?;
        if h > 23 || mi > 59 || s > 59 {
            return None;
        }
        rest = &rest[8..];
        if rest.starts_with('.') {
            let n = rest[1..].bytes().take_while(|c| c.is_ascii_digit()).count();
            if n == 3 {
                micro = num(&rest[1..4])? * 1000;
            } else if n == 6 {
                micro = num(&rest[1..7])?;
            } else {
                return None;
            }
            rest = &rest[1 + n..];
        }
        if rest == "Z" || rest == "z" {
            rest = "";
        } else if !rest.is_empty() {
            let rb = rest.as_bytes();
            if rb.len() != 6 || (rb[0] != b'+' && rb[0] != b'-') || rb[3] != b':' {
                return None;
            }
            let oh = num(&rest[1..3])?;
            let om = num(&rest[4..6])?;
            if oh > 23 || om > 59 {
                return None;
            }
            off = (oh * 60 + om) * if rb[0] == b'-' { -1 } else { 1 };
            rest = "";
        }
        if !rest.is_empty() {
            return None;
        }
    } else {
        return None; // date-only: rare; leave to Python
    }
    let epoch = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s - off * 60;
    let (yy, _, _) = civil_from_days(epoch.div_euclid(86400));
    if !(2..=9998).contains(&yy) {
        return None;
    }
    Some(iso_utc(epoch, micro))
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

fn py_int_field(s: &str) -> Option<i64> {
    // Python int() of a 2-char slice: surrounding spaces allowed, digits only here
    let t = s.trim_matches(' ');
    num(t)
}

/// RFC 3164 "Oct 11 22:14:15": most recent past occurrence (year inferred).
fn parse_rfc3164(ts: &str) -> Option<String> {
    let mon = MONTHS.iter().position(|m| *m == &ts[0..3])? as i64 + 1;
    let d = py_int_field(&ts[4..6])?;
    let h = py_int_field(&ts[7..9])?;
    let mi = py_int_field(&ts[10..12])?;
    let s = py_int_field(&ts[13..15])?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    let now_s = now.as_secs() as i64;
    let now_us = now.subsec_micros() as i64;
    let (ny, _, _) = civil_from_days(now_s.div_euclid(86400));
    if h > 23 || mi > 59 || s > 59 || d < 1 || d > days_in_month(ny, mon) {
        return None;
    }
    if mon == 2 && d == 29 {
        return None; // year rollback could hit a non-leap year: leave to Python
    }
    let mut epoch = days_from_civil(ny, mon, d) * 86400 + h * 3600 + mi * 60 + s;
    // dt - now > timedelta(days=1)  (now has microseconds)
    if (epoch - now_s) * 1_000_000 - now_us > 86_400 * 1_000_000 {
        epoch = days_from_civil(ny - 1, mon, d) * 86400 + h * 3600 + mi * 60 + s;
    }
    Some(iso_utc(epoch, 0))
}

/// `_parse_ts` native subset; None = ask Python.
fn parse_ts_native(ts: &str) -> Option<String> {
    let b = ts.as_bytes();
    if b.len() == 10 && all_digits(ts) {
        let v: i64 = ts.parse().ok()?;
        return Some(iso_utc(v, 0));
    }
    if b.iter().all(|c| c.is_ascii_digit() || *c == b'.') {
        return None; // other epoch forms: float semantics, delegate
    }
    if b.len() >= 10 && b[4] == b'-' && b[7] == b'-' {
        return parse_iso(ts);
    }
    if b.len() == 15 && b[3] == b' ' && b[9] == b':' && b[12] == b':' {
        return parse_rfc3164(ts);
    }
    None
}

// ---------------------------------------------------------------------------
// Normalisation helpers
// ---------------------------------------------------------------------------

fn normalize_timestamp<'py>(
    py: Python<'py>,
    c: &Ctx,
    ts: &Bound<'py, PyAny>,
) -> PyResult<(Bound<'py, PyAny>, Bound<'py, PyAny>)> {
    let none = py.None().into_bound(py);
    if ts.is_none() {
        return Ok((c.utc_now.bind(py).call0()?, none));
    }
    let s_obj = if ts.is_exact_instance_of::<PyString>() { ts.clone() } else { ts.str()?.into_any() };
    let full = s_obj.downcast::<PyString>()?.to_str();
    let parsed: Bound<'py, PyAny>;
    let orig: Bound<'py, PyAny>;
    match full {
        Ok(raw) if raw.is_ascii() => {
            let st = py_strip(raw);
            if st.is_empty() {
                return Ok((c.utc_now.bind(py).call0()?, none));
            }
            orig = PyString::new_bound(py, st).into_any();
            parsed = match parse_ts_native(st) {
                Some(v) => PyString::new_bound(py, &v).into_any(),
                None => c.parse_ts.bind(py).call1((orig.clone(),))?,
            };
        }
        _ => {
            let st = s_obj.call_method0(intern!(py, "strip"))?;
            if st.len()? == 0 {
                return Ok((c.utc_now.bind(py).call0()?, none));
            }
            parsed = c.parse_ts.bind(py).call1((st.clone(),))?;
            orig = st;
        }
    }
    if parsed.is_none() {
        return Ok((c.utc_now.bind(py).call0()?, orig));
    }
    Ok((parsed, orig))
}

fn normalize_severity<'py>(
    py: Python<'py>,
    c: &Ctx,
    raw: &Bound<'py, PyAny>,
    source: &str,
) -> PyResult<(i64, &'static str)> {
    if raw.is_none() {
        return Ok((0, "unknown"));
    }
    let s: Option<String> = if raw.is_exact_instance_of::<PyLong>() {
        raw.extract::<i64>().ok().map(|v| v.to_string())
    } else {
        ascii_str(raw)
    };
    if let Some(s0) = s {
        if s0.is_empty() {
            return Ok((0, "unknown"));
        }
        let s = py_strip(&s0).to_ascii_lowercase();
        if all_digits(&s) && s.len() <= 18 {
            let v: u64 = s.parse().unwrap();
            let val = if source == "syslog" {
                if v <= u32::MAX as u64 { *c.syslog_sev.get(&(v as u32)).unwrap_or(&0) } else { 0 }
            } else {
                v.min(10) as i64
            };
            return Ok((val, severity_label(val)));
        }
        let bare = s.trim_start_matches('-');
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
            && !matches!(bare, "inf" | "nan" | "infinity")   // float() accepts these: Python decides
        {
            let val = if source == "cef" && c.cef_sev.contains_key(&s) {
                c.cef_sev[&s]
            } else {
                *c.text_sev.get(&s).or_else(|| c.cef_sev.get(&s)).unwrap_or(&0)
            };
            return Ok((val, severity_label(val)));
        }
    }
    let r = c.normalize_severity.bind(py).call1((raw, source))?;
    let t = r.downcast::<PyTuple>()?;
    let v: i64 = t.get_item(0)?.extract()?;
    Ok((v, severity_label(v)))
}

fn action_native(c: &Ctx, s: &str) -> String {
    if let Some(h) = c.action_map.get(s) {
        return h.clone();
    }
    let compact: String = s.chars().filter(|ch| *ch != '-' && *ch != '_').collect();
    if let Some(h) = c.action_map.get(&compact) {
        return h.clone();
    }
    for tok in s.split(|ch: char| !(ch.is_ascii_lowercase() || ch.is_ascii_digit())) {
        if let Some(h) = c.action_map.get(tok) {
            return h.clone();
        }
    }
    "other".to_string()
}

fn normalize_action<'py>(py: Python<'py>, c: &Ctx, raw: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    if let Some(s) = ascii_str(raw) {
        let s = py_strip(&s).to_ascii_lowercase();
        let out = if s.is_empty() { "other".to_string() } else { action_native(c, &s) };
        return Ok(PyString::new_bound(py, &out).into_any());
    }
    c.normalize_action.bind(py).call1((raw,))
}

fn normalize_protocol<'py>(
    py: Python<'py>,
    c: &Ctx,
    raw: &Bound<'py, PyAny>,
) -> PyResult<(Bound<'py, PyAny>, Bound<'py, PyAny>)> {
    let s: Option<String> = if raw.is_exact_instance_of::<PyLong>() {
        raw.extract::<i64>().ok().map(|v| v.to_string())
    } else {
        ascii_str(raw)
    };
    if let Some(s0) = s {
        let st = py_strip(&s0);
        if st.is_empty() {
            return Ok((py.None().into_bound(py), py.None().into_bound(py)));
        }
        if all_digits(st) && st.len() <= 9 {
            let n: u32 = st.parse().unwrap();
            let name = c.protocol_map.get(&n).cloned().unwrap_or_else(|| st.to_string());
            return Ok((PyString::new_bound(py, &name).into_any(), n.into_py(py).into_bound(py)));
        }
        if !all_digits(st) {
            let num = match c.protocol_names.get(&st.to_ascii_lowercase()) {
                Some(n) => n.into_py(py).into_bound(py),
                None => py.None().into_bound(py),
            };
            return Ok((PyString::new_bound(py, &st.to_ascii_uppercase()).into_any(), num));
        }
    }
    let r = c.normalize_protocol.bind(py).call1((raw,))?;
    let t = r.downcast::<PyTuple>()?;
    Ok((t.get_item(0)?, t.get_item(1)?))
}

fn normalize_direction<'py>(py: Python<'py>, c: &Ctx, raw: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    if let Some(s) = ascii_str(raw) {
        let k = py_strip(&s).to_ascii_lowercase();
        let v = c.direction_map.get(&k).map(|x| x.as_str()).unwrap_or("unknown");
        return Ok(PyString::new_bound(py, v).into_any());
    }
    c.normalize_direction.bind(py).call1((raw,))
}

fn canonical_category<'py>(py: Python<'py>, c: &Ctx, cat: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    if let Some(s) = ascii_str(cat) {
        if s.is_empty() {
            return Ok(intern!(py, "other").clone().into_any());
        }
        let l = s.to_ascii_lowercase();
        let out = if let Some(a) = c.category_aliases.get(&l) {
            a.clone()
        } else if c.categories.contains(&l) {
            l
        } else {
            "other".to_string()
        };
        return Ok(PyString::new_bound(py, &out).into_any());
    }
    c.canonical_category.bind(py).call1((cat,))
}

/// `_resolve_field` for ASCII keys, with the same bounded memo.
fn resolve_native(c: &Ctx, key: &str) -> Option<Vec<String>> {
    {
        let g = RESOLVE.lock().unwrap();
        if let Some(m) = g.as_ref() {
            if let Some(v) = m.get(key) {
                return v.clone();
            }
        }
    }
    let mut target = c.aliases.get(key).cloned();
    if target.is_none() {
        let k = key.to_ascii_lowercase();
        target = c.schema_paths.get(&k).or_else(|| c.aliases.get(&k)).cloned();
        if target.is_none() && k.contains('.') {
            let last = k.rsplit('.').next().unwrap_or("");
            target = c.aliases.get(last).cloned();
        }
        if target.is_none() {
            let compact: String = k.chars().filter(|ch| *ch != '_' && *ch != '-').collect();
            target = c.aliases.get(&compact).cloned();
        }
    }
    let mut g = RESOLVE.lock().unwrap();
    let m = g.get_or_insert_with(HashMap::new);
    if m.len() >= RESOLVE_MAX {
        m.clear();
    }
    m.insert(key.to_string(), target.clone());
    target
}

fn apply_field_mappings<'py>(
    py: Python<'py>,
    c: &Ctx,
    parsed: &Bound<'py, PyDict>,
    event: &Bound<'py, PyDict>,
) -> PyResult<()> {
    for (key, value) in parsed.iter() {
        if value.is_none() {
            continue;
        }
        let target: Option<Vec<String>> = match ascii_str(&key) {
            Some(k) => resolve_native(c, &k),
            None => {
                let r = c.resolve_field.bind(py).call1((key.clone(),))?;
                if r.is_none() {
                    None
                } else {
                    Some(r.extract::<Vec<String>>()?)
                }
            }
        };
        let Some(target) = target else { continue };
        if value.is_exact_instance_of::<PyString>() {
            // a string that is not valid UTF-8 (lone surrogate) cannot be nullish
            if let Ok(vs) = value.downcast::<PyString>()?.to_str() {
                if c.nullish.iter().any(|n| n == vs) {
                    continue;
                }
            }
        } else if value.is_exact_instance_of::<PyDict>() || value.is_exact_instance_of::<PyList>() {
            continue;
        }
        let fin = target.last().unwrap();
        let mut v = value.clone();
        if c.int_fields.iter().any(|f| f == fin) {
            if v.is_exact_instance_of::<PyLong>() {
                if v.extract::<i64>().is_err() {
                    continue; // outside 64-bit: dropped, as in _to_int
                }
            } else if let Some(s) = ascii_str(&v).filter(|s| all_digits(s) && s.len() <= 18) {
                v = s.parse::<i64>().unwrap().into_py(py).into_bound(py);
            } else {
                v = c.to_int.bind(py).call1((v,))?;
                if v.is_none() {
                    continue;
                }
            }
        }
        let g0 = event.get_item(&target[0])?.unwrap();
        let g0 = g0.downcast::<PyDict>()?;
        if target.len() == 2 {
            g0.set_item(fin, v)?;
        } else {
            let g1 = g0.get_item(&target[1])?.unwrap();
            g1.downcast::<PyDict>()?.set_item(fin, v)?;
        }
    }
    let user = event.get_item(intern!(py, "user"))?.unwrap();
    let user = user.downcast::<PyDict>()?;
    let name = user.get_item(intern!(py, "name"))?.unwrap();
    if !name.is_truthy()? {
        let tgt = user.get_item(intern!(py, "target"))?.unwrap().get_item(intern!(py, "name"))?;
        let v = if tgt.is_truthy()? {
            tgt
        } else {
            user.get_item(intern!(py, "source"))?.unwrap().get_item(intern!(py, "name"))?
        };
        user.set_item(intern!(py, "name"), v)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Event construction (key order identical to ulpf.engine.schema)
// ---------------------------------------------------------------------------

fn nones<'py>(py: Python<'py>, keys: &[&str]) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new_bound(py);
    for k in keys {
        d.set_item(PyString::intern_bound(py, k), py.None())?;
    }
    Ok(d)
}

const ENDPOINT: [&str; 6] = ["ip", "port", "mac", "hostname", "interface", "zone"];
const NETWORK: [&str; 11] = ["protocol", "protocol_number", "direction", "bytes_in", "bytes_out", "bytes_total",
    "packets_in", "packets_out", "application", "session_id", "vlan_id"];
const DEVICE: [&str; 7] = ["vendor", "product", "version", "hostname", "ip", "type", "serial"];
const RULE: [&str; 5] = ["id", "name", "description", "action", "category"];
const GEO: [&str; 10] = ["src_country", "src_country_code", "src_city", "src_latitude", "src_longitude",
    "dst_country", "dst_country_code", "dst_city", "dst_latitude", "dst_longitude"];

fn new_event<'py>(
    py: Python<'py>,
    c: &Ctx,
    event_id: &Bound<'py, PyAny>,
    ts: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyDict>> {
    let none = py.None();
    let e = PyDict::new_bound(py);
    let eid = if event_id.is_truthy()? { event_id.clone() } else { c.new_uuid.bind(py).call0()? };
    e.set_item(intern!(py, "event_id"), eid)?;
    e.set_item(intern!(py, "timestamp"), ts)?;
    e.set_item(intern!(py, "timestamp_original"), &none)?;
    e.set_item(intern!(py, "category"), intern!(py, "other"))?;
    e.set_item(intern!(py, "event_type"), &none)?;
    e.set_item(intern!(py, "action"), intern!(py, "other"))?;
    e.set_item(intern!(py, "severity"), 0)?;
    e.set_item(intern!(py, "severity_label"), intern!(py, "unknown"))?;
    e.set_item(intern!(py, "source"), nones(py, &ENDPOINT)?)?;
    e.set_item(intern!(py, "destination"), nones(py, &ENDPOINT)?)?;
    e.set_item(intern!(py, "network"), nones(py, &NETWORK)?)?;
    e.set_item(intern!(py, "device"), nones(py, &DEVICE)?)?;
    e.set_item(intern!(py, "rule"), nones(py, &RULE)?)?;
    let threat = PyDict::new_bound(py);
    threat.set_item(intern!(py, "category"), &none)?;
    threat.set_item(intern!(py, "signature"), &none)?;
    threat.set_item(intern!(py, "signature_id"), &none)?;
    threat.set_item(intern!(py, "cve"), PyList::empty_bound(py))?;
    threat.set_item(intern!(py, "confidence"), &none)?;
    threat.set_item(intern!(py, "ioc_type"), &none)?;
    threat.set_item(intern!(py, "ioc_value"), &none)?;
    e.set_item(intern!(py, "threat"), threat)?;
    let user = nones(py, &["name", "domain", "id", "email", "group"])?;
    user.set_item(intern!(py, "source"), nones(py, &["name", "domain", "id"])?)?;
    user.set_item(intern!(py, "target"), nones(py, &["name", "domain", "id"])?)?;
    e.set_item(intern!(py, "user"), user)?;
    e.set_item(intern!(py, "geo"), nones(py, &GEO)?)?;
    e.set_item(intern!(py, "raw_event"), &none)?;
    e.set_item(intern!(py, "raw_format"), &none)?;
    e.set_item(intern!(py, "parsed_fields"), PyDict::new_bound(py))?;
    e.set_item(intern!(py, "tags"), PyList::empty_bound(py))?;
    e.set_item(intern!(py, "extensions"), PyDict::new_bound(py))?;
    let sv = c.schema_version.bind(py);
    let meta = PyDict::new_bound(py);
    meta.set_item(intern!(py, "ingestion_time"), ts)?;
    meta.set_item(intern!(py, "schema_version"), sv)?;
    meta.set_item(intern!(py, "processing_time_ms"), &none)?;
    meta.set_item(intern!(py, "pipeline_version"), sv)?;
    meta.set_item(intern!(py, "parser_id"), &none)?;
    meta.set_item(intern!(py, "parser_name"), &none)?;
    meta.set_item(intern!(py, "detection_confidence"), &none)?;
    meta.set_item(intern!(py, "normalization_version"), sv)?;
    meta.set_item(intern!(py, "raw_hash_sha256"), &none)?;
    meta.set_item(intern!(py, "parser_version"), &none)?;
    meta.set_item(intern!(py, "source_fingerprint"), &none)?;
    meta.set_item(intern!(py, "parser_confidence"), &none)?;
    meta.set_item(intern!(py, "template_id"), &none)?;
    e.set_item(intern!(py, "metadata"), meta)?;
    e.set_item(intern!(py, "message"), &none)?;
    e.set_item(intern!(py, "correlation_id"), &none)?;
    e.set_item(intern!(py, "related_events"), PyList::empty_bound(py))?;
    let ev = PyDict::new_bound(py);
    ev.set_item(intern!(py, "raw_hash"), &none)?;
    ev.set_item(intern!(py, "chain_of_custody"), PyList::empty_bound(py))?;
    e.set_item(intern!(py, "evidence"), ev)?;
    Ok(e)
}

fn sub<'py>(e: &Bound<'py, PyDict>, k: &Bound<'py, PyString>) -> PyResult<Bound<'py, PyDict>> {
    Ok(e.get_item(k)?.unwrap().downcast_into::<PyDict>()?)
}

/// Drop-in for `ulpf.engine.normalizer.build_normalized_event`.
#[pyfunction]
#[pyo3(signature = (*, raw_line, raw_format, parsed_fields, parser_id, parser_name, timestamp_str=None,
    severity_raw=None, severity_source=None, category=None, event_type=None, device_vendor=None,
    device_product=None, device_version=None, message=None, raw_hash=None, event_id=None,
    timestamp_now=None, parser_version=None))]
#[allow(clippy::too_many_arguments)]
fn build_normalized_event<'py>(
    py: Python<'py>,
    raw_line: Bound<'py, PyAny>,
    raw_format: Bound<'py, PyAny>,
    parsed_fields: Bound<'py, PyDict>,
    parser_id: Bound<'py, PyAny>,
    parser_name: Bound<'py, PyAny>,
    timestamp_str: Option<Bound<'py, PyAny>>,
    severity_raw: Option<Bound<'py, PyAny>>,
    severity_source: Option<Bound<'py, PyAny>>,
    category: Option<Bound<'py, PyAny>>,
    event_type: Option<Bound<'py, PyAny>>,
    device_vendor: Option<Bound<'py, PyAny>>,
    device_product: Option<Bound<'py, PyAny>>,
    device_version: Option<Bound<'py, PyAny>>,
    message: Option<Bound<'py, PyAny>>,
    raw_hash: Option<Bound<'py, PyAny>>,
    event_id: Option<Bound<'py, PyAny>>,
    timestamp_now: Option<Bound<'py, PyAny>>,
    parser_version: Option<Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyDict>> {
    let c = ctx(py)?;
    let none = py.None().into_bound(py);
    let opt = |o: Option<Bound<'py, PyAny>>| o.unwrap_or_else(|| none.clone());
    let ts_now = match timestamp_now {
        Some(t) if t.is_truthy()? => t,
        _ => c.utc_now.bind(py).call0()?,
    };
    let event = new_event(py, c, &opt(event_id), &ts_now)?;
    event.set_item(intern!(py, "raw_event"), &raw_line)?;
    event.set_item(intern!(py, "raw_format"), raw_format)?;
    event.set_item(intern!(py, "parsed_fields"), &parsed_fields)?;
    let cat = category.unwrap_or_else(|| intern!(py, "other").clone().into_any());
    event.set_item(intern!(py, "category"), canonical_category(py, c, &cat)?)?;
    event.set_item(intern!(py, "event_type"), opt(event_type))?;
    event.set_item(intern!(py, "message"), opt(message))?;

    let (ts_norm, ts_orig) = normalize_timestamp(py, c, &opt(timestamp_str))?;
    event.set_item(intern!(py, "timestamp"), ts_norm)?;
    event.set_item(intern!(py, "timestamp_original"), ts_orig)?;

    // Only "syslog" and "cef" change behaviour; anything else (or None) acts as "generic"
    let src = match &severity_source {
        Some(s) => ascii_str(s).unwrap_or_default(),
        None => "generic".to_string(),
    };
    let (sev, label) = normalize_severity(py, c, &opt(severity_raw), &src)?;
    event.set_item(intern!(py, "severity"), sev)?;
    event.set_item(intern!(py, "severity_label"), label)?;

    let device = sub(&event, intern!(py, "device"))?;
    device.set_item(intern!(py, "vendor"), opt(device_vendor))?;
    device.set_item(intern!(py, "product"), opt(device_product))?;
    device.set_item(intern!(py, "version"), opt(device_version))?;

    apply_field_mappings(py, c, &parsed_fields, &event)?;

    for k in ["action", "act", "status"] {
        if let Some(v) = parsed_fields.get_item(k)? {
            event.set_item(intern!(py, "action"), normalize_action(py, c, &v)?)?;
            break;
        }
    }

    let net = sub(&event, intern!(py, "network"))?;
    let proto = net.get_item(intern!(py, "protocol"))?.unwrap();
    if !proto.is_none() {
        let (name, n) = normalize_protocol(py, c, &proto)?;
        net.set_item(intern!(py, "protocol"), name)?;
        if net.get_item(intern!(py, "protocol_number"))?.unwrap().is_none() {
            net.set_item(intern!(py, "protocol_number"), n)?;
        }
    }
    let dir = net.get_item(intern!(py, "direction"))?.unwrap();
    if !dir.is_none() {
        net.set_item(intern!(py, "direction"), normalize_direction(py, c, &dir)?)?;
    }
    let bt = net.get_item(intern!(py, "bytes_total"))?.unwrap();
    let bi = net.get_item(intern!(py, "bytes_in"))?.unwrap();
    let bo = net.get_item(intern!(py, "bytes_out"))?.unwrap();
    if bt.is_none() && (!bi.is_none() || !bo.is_none()) {
        let zero = 0i64.into_py(py).into_bound(py);
        let a = if bi.is_truthy()? { bi } else { zero.clone() };
        let b = if bo.is_truthy()? { bo } else { zero };
        let total = a.add(b)?;
        if total.extract::<i64>().is_ok() || !total.is_exact_instance_of::<PyLong>() {
            net.set_item(intern!(py, "bytes_total"), total)?;
        }
    }

    let rh = match raw_hash {
        Some(h) if !h.is_none() => h,
        _ => match raw_line.downcast::<PyString>().ok().and_then(|s| s.to_str().ok()) {
            Some(s) => PyString::new_bound(py, &hex::encode(Sha256::digest(s.as_bytes()))).into_any(),
            None => c.sha256_py.bind(py).call1((&raw_line,))?,
        },
    };
    sub(&event, intern!(py, "evidence"))?.set_item(intern!(py, "raw_hash"), &rh)?;
    let meta = sub(&event, intern!(py, "metadata"))?;
    meta.set_item(intern!(py, "raw_hash_sha256"), &rh)?;
    meta.set_item(intern!(py, "parser_id"), parser_id)?;
    meta.set_item(intern!(py, "parser_name"), parser_name)?;
    meta.set_item(intern!(py, "parser_version"), opt(parser_version))?;
    Ok(event)
}

/// Native `_parse_ts` subset, exposed for tests (None = would delegate).
#[pyfunction]
fn parse_ts_fast(ts: &str) -> Option<String> {
    if ts.is_ascii() {
        parse_ts_native(ts)
    } else {
        None
    }
}

/// Registers the legacy dict-based builder (kept under tests/test_native.py).
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(init, m)?)?;
    m.add_function(wrap_pyfunction!(build_normalized_event, m)?)?;
    m.add_function(wrap_pyfunction!(parse_ts_fast, m)?)?;
    Ok(())
}
