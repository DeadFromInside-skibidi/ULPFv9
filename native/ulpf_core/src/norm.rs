//! Dict-free port of `ulpf.engine.normalizer.build_normalized_event` and its helpers.
//!
//! Every function returns `Err(Delegate)` where the Python result depends on a
//! behaviour this module does not reproduce (float syntax, `inf`/`nan`,
//! containers, non-ASCII text); the batch engine then sends the whole line to
//! the Python pipeline. There are no calls back into Python.

use crate::timefmt;
use crate::val::{Key, Map, Val};
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

/// Per-stage nanoseconds of `Build::build` (feature `stage-timing`, for optimisation work).
#[cfg(feature = "stage-timing")]
pub mod timing {
    use std::sync::atomic::{AtomicU64, Ordering};
    pub const NAMES: [&str; 8] = ["new_event", "base fields", "timestamp", "severity", "field mappings", "action",
                                  "network", "tail"];
    pub static T: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
    pub fn add(i: usize, d: std::time::Duration) {
        T[i].fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
    }
}

macro_rules! timed {
    ($i:expr, $e:expr) => {{
        #[cfg(feature = "stage-timing")]
        let _t = std::time::Instant::now();
        let r = $e;
        #[cfg(feature = "stage-timing")]
        crate::norm::timing::add($i, _t.elapsed());
        r
    }};
}

#[derive(Debug)]
pub struct Delegate;
pub type R<T> = Result<T, Delegate>;

/// Lookup tables, copied from the Python modules at start-up (one source of truth).
pub struct Tables {
    pub aliases: HashMap<String, Vec<String>>,
    pub schema_paths: HashMap<String, Vec<String>>,
    pub action_map: HashMap<String, String>,
    pub direction_map: HashMap<String, String>,
    pub protocol_map: HashMap<u64, String>,
    pub protocol_names: HashMap<String, i64>,
    pub syslog_sev: HashMap<u64, i64>,
    pub cef_sev: HashMap<String, i64>,
    pub text_sev: HashMap<String, i64>,
    pub categories: Vec<String>,
    pub category_aliases: HashMap<String, String>,
    pub nullish: HashSet<String>,
    pub int_fields: HashSet<String>,
    pub schema_version: String,
}

/// Python `str.strip()` on ASCII text (includes \x1c-\x1f).
pub fn is_py_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c | 0x1c | 0x1d | 0x1e | 0x1f)
}

pub fn py_strip(s: &str) -> &str {
    let b = s.as_bytes();
    let (mut i, mut j) = (0, b.len());
    while i < j && is_py_ws(b[i]) {
        i += 1;
    }
    while j > i && is_py_ws(b[j - 1]) {
        j -= 1;
    }
    &s[i..j]
}

pub fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// `^[+-]?(\d+\.?\d*|\.\d+)$`: float() and Rust agree on these exactly.
fn simple_decimal(s: &str) -> bool {
    let t = s.strip_prefix(['+', '-']).unwrap_or(s);
    let (a, b) = match t.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (t, None),
    };
    let a_ok = a.bytes().all(|c| c.is_ascii_digit());
    let b_ok = b.map(|x| x.bytes().all(|c| c.is_ascii_digit())).unwrap_or(true);
    a_ok && b_ok && (!a.is_empty() || b.map(|x| !x.is_empty()).unwrap_or(false))
}

/// Could Python's float() accept `s` (lower-cased, stripped) in a way not covered above?
fn maybe_float(s: &str) -> bool {
    let bare = s.trim_start_matches(['+', '-']);
    if matches!(bare, "inf" | "infinity" | "nan") {
        return true;
    }
    s.bytes().any(|c| c.is_ascii_digit()) && s.bytes().all(|c| c.is_ascii_digit() || b"+-.e_".contains(&c))
}

fn to_text(v: &Val) -> R<String> {
    let s = v.py_str().ok_or(Delegate)?;
    if s.is_ascii() {
        Ok(s)
    } else {
        Err(Delegate)
    }
}

pub fn severity_label(v: i64) -> &'static str {
    match v {
        1 | 2 => "info",
        3 | 4 => "low",
        5 | 6 => "medium",
        7 | 8 => "high",
        9 | 10 => "critical",
        _ => "unknown",
    }
}

impl Tables {
    pub fn canonical_category(&self, name: Option<&str>) -> String {
        let n = match name {
            Some(n) if !n.is_empty() => n.to_ascii_lowercase(),
            _ => return "other".into(),
        };
        if let Some(a) = self.category_aliases.get(&n) {
            return a.clone();
        }
        if self.categories.contains(&n) {
            n
        } else {
            "other".into()
        }
    }

    pub fn normalize_severity(&self, raw: &Val, source: &str) -> R<i64> {
        if raw.is_null() || matches!(raw, Val::Str(s) if s.is_empty()) {
            return Ok(0);
        }
        let s0 = to_text(raw)?;
        let s = py_strip(&s0).to_ascii_lowercase();
        if all_digits(&s) {
            if source == "syslog" {
                return Ok(s.parse::<u64>().ok().and_then(|v| self.syslog_sev.get(&v).copied()).unwrap_or(0));
            }
            return Ok(if s.len() > 18 { 10 } else { s.parse::<i64>().unwrap().min(10) });
        }
        if simple_decimal(&s) {
            let f: f64 = s.parse().map_err(|_| Delegate)?;
            let r = f.round_ties_even();
            return Ok(r.clamp(0.0, 10.0) as i64);
        }
        if maybe_float(&s) {
            return Err(Delegate);
        }
        Ok(if source == "cef" && self.cef_sev.contains_key(&s) {
            self.cef_sev[&s]
        } else {
            *self.text_sev.get(&s).or_else(|| self.cef_sev.get(&s)).unwrap_or(&0)
        })
    }

    fn action_str(&self, s: &str) -> String {
        if let Some(h) = self.action_map.get(s) {
            return h.clone();
        }
        let compact: String = s.chars().filter(|c| *c != '-' && *c != '_').collect();
        if let Some(h) = self.action_map.get(&compact) {
            return h.clone();
        }
        for tok in s.split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit())) {
            if let Some(h) = self.action_map.get(tok) {
                return h.clone();
            }
        }
        "other".into()
    }

    pub fn normalize_action(&self, raw: &Val) -> R<String> {
        if raw.is_null() {
            return Ok("other".into());
        }
        let s0 = to_text(raw)?;
        let s = py_strip(&s0).to_ascii_lowercase();
        Ok(if s.is_empty() { "other".into() } else { self.action_str(&s) })
    }

    fn normalize_protocol(&self, raw: &Val) -> R<(Val, Val)> {
        let s0 = to_text(raw)?;
        let s = py_strip(&s0);
        if s.is_empty() {
            return Ok((Val::Null, Val::Null));
        }
        if all_digits(s) {
            let n: i64 = s.parse().map_err(|_| Delegate)?; // beyond 64 bits: Python decides
            let name = self.protocol_map.get(&(n as u64)).cloned().unwrap_or_else(|| s.to_string());
            return Ok((Val::string(name), Val::Int(n)));
        }
        let num = self.protocol_names.get(&s.to_ascii_lowercase()).map(|n| Val::Int(*n)).unwrap_or(Val::Null);
        Ok((Val::string(s.to_ascii_uppercase()), num))
    }

    fn normalize_direction(&self, raw: &Val) -> R<Val> {
        let s0 = to_text(raw)?;
        let k = py_strip(&s0).to_ascii_lowercase();
        Ok(Val::s(self.direction_map.get(&k).map(|x| x.as_str()).unwrap_or("unknown")))
    }

    /// `_to_int`: Ok(None) = dropped from the unified field.
    fn to_int(&self, v: &Val) -> R<Option<i64>> {
        Ok(match v {
            Val::Int(i) => Some(*i),
            Val::Bool(b) => Some(*b as i64),
            Val::Float(f) => {
                if f.is_finite() && f.trunc() >= -9.223372036854776e18 && f.trunc() < 9.223372036854776e18 {
                    Some(f.trunc() as i64)
                } else {
                    None
                }
            }
            Val::Str(s) => {
                if !s.is_ascii() {
                    return Err(Delegate);
                }
                let t = py_strip(s);
                let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
                if all_digits(digits) {
                    t.parse::<i64>().ok() // outside 64 bits: dropped, as in Python
                } else if simple_decimal(t) {
                    let f: f64 = t.parse().map_err(|_| Delegate)?;
                    let tr = f.trunc();
                    if tr >= -9.223372036854776e18 && tr < 9.223372036854776e18 {
                        Some(tr as i64)
                    } else {
                        None
                    }
                } else if maybe_float(&t.to_ascii_lowercase()) {
                    return Err(Delegate);
                } else {
                    None
                }
            }
            Val::Null | Val::List(_) | Val::Map(_) => None,
        })
    }

    pub fn resolve(&self, key: &str) -> Option<&Vec<String>> {
        if let Some(t) = self.aliases.get(key) {
            return Some(t);
        }
        // lower-cased and compacted forms in a stack buffer (keys are short)
        let mut low_buf = [0u8; 96];
        let lowered;
        let k: &str = if key.bytes().any(|b| b.is_ascii_uppercase()) {
            if key.len() <= low_buf.len() {
                for (d, s) in low_buf.iter_mut().zip(key.bytes()) {
                    *d = s.to_ascii_lowercase();
                }
                std::str::from_utf8(&low_buf[..key.len()]).unwrap_or(key)
            } else {
                lowered = key.to_ascii_lowercase();
                &lowered
            }
        } else {
            key
        };
        if let Some(t) = self.schema_paths.get(k).or_else(|| self.aliases.get(k)) {
            return Some(t);
        }
        if k.contains('.') {
            if let Some(t) = self.aliases.get(k.rsplit('.').next().unwrap_or("")) {
                return Some(t);
            }
        }
        if !k.contains(['_', '-']) {
            return None; // compacting changes nothing: already looked up above
        }
        let mut buf = [0u8; 96];
        if k.len() <= buf.len() {
            let mut n = 0;
            for c in k.bytes().filter(|c| *c != b'_' && *c != b'-') {
                buf[n] = c;
                n += 1;
            }
            return self.aliases.get(std::str::from_utf8(&buf[..n]).ok()?);
        }
        let compact: String = k.chars().filter(|c| *c != '_' && *c != '-').collect();
        self.aliases.get(&compact)
    }

    pub fn apply_field_mappings(&self, parsed: &Map, event: &mut Map) -> R<()> {
        for (key, value) in &parsed.0 {
            if !key.is_ascii() {
                return Err(Delegate);
            }
            let Some(target) = self.resolve(key) else { continue };
            let value = match value {
                Val::Null | Val::List(_) | Val::Map(_) => continue,
                Val::Str(s) if self.nullish.contains(s.as_str()) => continue,
                v => v,
            };
            let fin = target.last().unwrap();
            let v = if self.int_fields.contains(fin) {
                match self.to_int(value)? {
                    Some(i) => Val::Int(i),
                    None => continue,
                }
            } else {
                value.clone()
            };
            let g = event.sub(&target[0]);
            if target.len() == 2 {
                g.set_str(fin, v);
            } else {
                g.sub(&target[1]).set_str(fin, v);
            }
        }
        let user = event.sub("user");
        if !user.get("name").map(|v| v.truthy()).unwrap_or(false) {
            let t = user.sub_ref("target").get("name").cloned().unwrap_or(Val::Null);
            let v = if t.truthy() { t } else { user.sub_ref("source").get("name").cloned().unwrap_or(Val::Null) };
            user.set("name", v);
        }
        Ok(())
    }

    /// `normalize_timestamp`: (normalised, original).
    fn normalize_timestamp(&self, ts: Option<&Val>, now: &str) -> R<(String, Val)> {
        let Some(ts) = ts.filter(|t| !t.is_null()) else { return Ok((now.to_string(), Val::Null)) };
        let s0 = to_text(ts)?;
        let s = py_strip(&s0);
        if s.is_empty() {
            return Ok((now.to_string(), Val::Null));
        }
        match timefmt::parse_ts(s) {
            Some(iso) => Ok((iso, Val::s(s))),
            None => Err(Delegate), // a later strptime format or dateutil might still parse it
        }
    }
}

fn nones(keys: &[&'static str]) -> Val {
    Val::Map(Map::with(keys.iter().map(|k| (Key::Borrowed(*k), Val::Null)).collect()))
}

const ENDPOINT: [&str; 6] = ["ip", "port", "mac", "hostname", "interface", "zone"];
const NETWORK: [&str; 11] = ["protocol", "protocol_number", "direction", "bytes_in", "bytes_out", "bytes_total",
    "packets_in", "packets_out", "application", "session_id", "vlan_id"];
const DEVICE: [&str; 7] = ["vendor", "product", "version", "hostname", "ip", "type", "serial"];
const RULE: [&str; 5] = ["id", "name", "description", "action", "category"];
const GEO: [&str; 10] = ["src_country", "src_country_code", "src_city", "src_latitude", "src_longitude",
    "dst_country", "dst_country_code", "dst_city", "dst_latitude", "dst_longitude"];

fn k(s: &'static str) -> Key {
    Key::Borrowed(s)
}

/// `schema.new_unified_event` (same key order).
pub fn new_event(event_id: &str, now: &str, schema_version: &str) -> Map {
    let sv = Val::s(schema_version);
    let mut user = match nones(&["name", "domain", "id", "email", "group"]) {
        Val::Map(m) => m,
        _ => unreachable!(),
    };
    user.set("source", nones(&["name", "domain", "id"]));
    user.set("target", nones(&["name", "domain", "id"]));
    Map::with(vec![
        (k("event_id"), Val::s(event_id)),
        (k("timestamp"), Val::s(now)),
        (k("timestamp_original"), Val::Null),
        (k("category"), Val::s("other")),
        (k("event_type"), Val::Null),
        (k("action"), Val::s("other")),
        (k("severity"), Val::Int(0)),
        (k("severity_label"), Val::s("unknown")),
        (k("source"), nones(&ENDPOINT)),
        (k("destination"), nones(&ENDPOINT)),
        (k("network"), nones(&NETWORK)),
        (k("device"), nones(&DEVICE)),
        (k("rule"), nones(&RULE)),
        (k("threat"), Val::Map(Map::with(vec![
            (k("category"), Val::Null), (k("signature"), Val::Null), (k("signature_id"), Val::Null),
            (k("cve"), Val::List(vec![])), (k("confidence"), Val::Null), (k("ioc_type"), Val::Null),
            (k("ioc_value"), Val::Null)]))),
        (k("user"), Val::Map(user)),
        (k("geo"), nones(&GEO)),
        (k("raw_event"), Val::Null),
        (k("raw_format"), Val::Null),
        (k("parsed_fields"), Val::Map(Map::new())),
        (k("tags"), Val::List(vec![])),
        (k("extensions"), Val::Map(Map::new())),
        (k("metadata"), Val::Map(Map::with(vec![
            (k("ingestion_time"), Val::s(now)), (k("schema_version"), sv.clone()),
            (k("processing_time_ms"), Val::Null), (k("pipeline_version"), sv.clone()),
            (k("parser_id"), Val::Null), (k("parser_name"), Val::Null),
            (k("detection_confidence"), Val::Null), (k("normalization_version"), sv),
            (k("raw_hash_sha256"), Val::Null), (k("parser_version"), Val::Null),
            (k("source_fingerprint"), Val::Null), (k("parser_confidence"), Val::Null),
            (k("template_id"), Val::Null)]))),
        (k("message"), Val::Null),
        (k("correlation_id"), Val::Null),
        (k("related_events"), Val::List(vec![])),
        (k("evidence"), Val::Map(Map::with(vec![(k("raw_hash"), Val::Null),
                                                (k("chain_of_custody"), Val::List(vec![]))]))),
    ])
}

/// Arguments of `build_normalized_event` (parsers fill these in).
pub struct Build<'a> {
    pub raw_line: &'a str,
    pub raw_format: &'static str,
    pub parsed: Map,
    pub parser_id: &'static str,
    pub parser_name: &'static str,
    pub parser_version: &'static str,
    pub timestamp: Option<Val>,
    pub severity_raw: Val,
    pub severity_source: &'static str,
    pub category: String,
    pub event_type: Val,
    pub vendor: Val,
    pub product: Val,
    pub version: Val,
    pub message: Val,
}

pub struct Ctx<'a> {
    pub t: &'a Tables,
    pub event_id: &'a str,
    pub now: &'a str,
    pub raw_hash: &'a str,
}

impl Build<'_> {
    pub fn build(self, c: &Ctx) -> R<Map> {
        let t = c.t;
        let mut ev = timed!(0, new_event(c.event_id, c.now, &t.schema_version));
        timed!(1, {
            ev.set("raw_event", Val::s(self.raw_line));
            ev.set("raw_format", Val::s(self.raw_format));
            ev.set("category", Val::string(t.canonical_category(Some(&self.category))));
            ev.set("event_type", self.event_type);
            ev.set("message", self.message);
        });
        let (ts, orig) = timed!(2, t.normalize_timestamp(self.timestamp.as_ref(), c.now))?;
        ev.set("timestamp", Val::string(ts));
        ev.set("timestamp_original", orig);
        let sev = timed!(3, t.normalize_severity(&self.severity_raw, self.severity_source))?;
        ev.set("severity", Val::Int(sev));
        ev.set("severity_label", Val::s(severity_label(sev)));
        {
            let dev = ev.sub("device");
            dev.set("vendor", self.vendor);
            dev.set("product", self.product);
            dev.set("version", self.version);
        }
        timed!(4, t.apply_field_mappings(&self.parsed, &mut ev))?;
        timed!(5, {
            for key in ["action", "act", "status"] {
                if let Some(v) = self.parsed.get(key) {
                    let a = t.normalize_action(v)?;
                    ev.set("action", Val::string(a));
                    break;
                }
            }
            Ok::<(), Delegate>(())
        })?;
        timed!(6, {
            let net = ev.sub("network");
            let proto = net.get("protocol").cloned().unwrap_or(Val::Null);
            if !proto.is_null() {
                let (name, num) = t.normalize_protocol(&proto)?;
                net.set("protocol", name);
                if net.get("protocol_number").map(|v| v.is_null()).unwrap_or(true) {
                    net.set("protocol_number", num);
                }
            }
            let dir = net.get("direction").cloned().unwrap_or(Val::Null);
            if !dir.is_null() {
                let d = t.normalize_direction(&dir)?;
                net.set("direction", d);
            }
            let int_of = |v: Option<&Val>| match v {
                Some(Val::Int(i)) => Some(*i),
                _ => None,
            };
            let bt = net.get("bytes_total").map(|v| v.is_null()).unwrap_or(true);
            let (bi, bo) = (int_of(net.get("bytes_in")), int_of(net.get("bytes_out")));
            if bt && (bi.is_some() || bo.is_some()) {
                if let Some(total) = bi.unwrap_or(0).checked_add(bo.unwrap_or(0)) {
                    net.set("bytes_total", Val::Int(total));
                }
            }
            Ok::<(), Delegate>(())
        })?;
        timed!(7, {
            ev.sub("evidence").set("raw_hash", Val::s(c.raw_hash));
            let meta = ev.sub("metadata");
            meta.set("raw_hash_sha256", Val::s(c.raw_hash));
            meta.set("parser_id", Val::s(self.parser_id));
            meta.set("parser_name", Val::s(self.parser_name));
            meta.set("parser_version", Val::s(self.parser_version));
        });
        ev.set("parsed_fields", Val::Map(self.parsed));
        Ok(ev)
    }
}
