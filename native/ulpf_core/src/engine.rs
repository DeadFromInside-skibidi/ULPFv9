//! Batch engine: raw journal records -> unified events -> Arrow columns of the
//! event store, without Python objects per event.
//!
//! Pass 1 (`parse`) detects, parses and normalises every line it can reproduce
//! exactly and adds the worker's fields; every other line is reported in
//! `delegated` for the Python pipeline. Pass 2 (`finish`) applies GeoIP / IOC
//! enrichment from per-IP lookups the caller did in Python (one per distinct
//! address, not per event), the input's tags, and builds the store rows
//! (EVENT_COLUMNS order, `ulpf.storage.database.event_to_row` semantics)
//! including the BLAKE2b row MAC.

use crate::detect::{Detector, Fmt};
use crate::norm::{py_strip, Ctx, Tables};
use crate::parsers::Parsers;
use crate::val::{write_json, write_json_key, write_json_map, write_json_str, Key, Map, Val};
use sha2::{Digest, Sha256};
use rustc_hash::FxHashMap as HashMap;

pub struct Core {
    pub t: Tables,
    pub det: Detector,
    pub p: Parsers,
}

pub struct BatchArgs<'a> {
    pub node: &'a str,
    pub input_name: &'a str,
    pub source: &'a str,
    pub source_ip: &'a str,
    pub now: &'a str,
}

/// RFC 4122-style version-8 UUID from SHA-256("{node}:{seq}:0") (`ulpf.runtime.ids.event_id`).
pub fn event_id(node: &str, seq: i64) -> String {
    let mut h = Sha256::new();
    h.update(node.as_bytes());
    h.update(b":");
    h.update(itoa::Buffer::new().format(seq).as_bytes());
    h.update(b":0");
    let d = h.finalize();
    let mut hx = [0u8; 32];
    hex::encode_to_slice(&d[..16], &mut hx).unwrap();
    let hx = std::str::from_utf8(&hx).unwrap();
    let variant = b"89ab"[(u8::from_str_radix(&hx[16..17], 16).unwrap() & 3) as usize] as char;
    let mut out = String::with_capacity(36);
    out.push_str(&hx[..8]);
    out.push('-');
    out.push_str(&hx[8..12]);
    out.push_str("-8");
    out.push_str(&hx[13..16]);
    out.push('-');
    out.push(variant);
    out.push_str(&hx[17..20]);
    out.push('-');
    out.push_str(&hx[20..32]);
    out
}

/// Printable ASCII (and tab): the only text whose Python string semantics
/// (strip, lower, \s, \d, \w, isdigit) this crate reproduces.
fn printable_ascii(b: &[u8]) -> bool {
    b.iter().all(|c| (0x20..0x7f).contains(c) || *c == b'\t')
}

impl Core {
    /// One raw record -> its event, or None (delegate to Python).
    pub fn one(&self, raw: &[u8], digest: &[u8], seq: i64, a: &BatchArgs) -> Option<Map> {
        let mut end = raw.len();
        while end > 0 && (raw[end - 1] == b'\n' || raw[end - 1] == b'\r') {
            end -= 1; // worker: decode(...).rstrip("\r\n")
        }
        let body = &raw[..end];
        if !printable_ascii(body) {
            return None;
        }
        let text = std::str::from_utf8(body).ok()?;
        let line = py_strip(text);
        if line.is_empty() || line.starts_with('#') {
            return None; // skipped lines and W3C directives (stream state): Python
        }
        let mut json = None;
        let (fmt, conf) = self.det.detect(line, &mut json);
        let eid = event_id(a.node, seq);
        let raw_hash = hex::encode(digest);
        let c = Ctx { t: &self.t, event_id: &eid, now: a.now, raw_hash: &raw_hash };
        let ev = match fmt {
            Fmt::Syslog => self.p.syslog(line, &c),
            Fmt::Cef => self.p.cef(line, &c),
            Fmt::Leef => self.p.leef(line, &c),
            Fmt::Kv => self.p.kv(line, &c),
            Fmt::Json => self.p.json(line, json?, &c),
            Fmt::Other => return None,
        };
        let mut ev = ev.ok()?;
        ev.sub("metadata").set("detection_confidence", Val::Float(conf));
        // worker additions (ulpf.runtime.worker.WorkerState.process)
        {
            let e = ev.sub("evidence");
            e.set("journal_seq", Val::Int(seq));
            e.set("node_id", Val::s(a.node));
        }
        ev.set("event_kind", Val::s("log"));
        {
            let m = ev.sub("metadata");
            m.set("input", Val::s(a.input_name));
            m.set("ingestion_source", Val::s(a.source));
            if !a.source_ip.is_empty() {
                m.set("ingestion_source_ip", Val::s(a.source_ip));
            }
        }
        if !a.source_ip.is_empty() {
            let dev = ev.sub("device");
            if !dev.get("ip").map(|v| v.truthy()).unwrap_or(false) {
                dev.set("ip", Val::s(a.source_ip));
            }
        }
        Some(ev)
    }
}

/// Distinct string source/destination addresses of the parsed events (for the Python lookups).
pub fn distinct_ips(events: &[Option<Map>]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let mut set = rustc_hash::FxHashSet::default();
    for ev in events.iter().flatten() {
        for side in ["source", "destination"] {
            if let Some(Val::Str(ip)) = ev.sub_ref(side).get("ip") {
                if !ip.is_empty() && set.insert(ip.clone()) {
                    seen.push(ip.to_string());
                }
            }
        }
    }
    seen
}

pub struct Geo {
    pub country: Val,
    pub cc: Val,
    pub city: Val,
    pub lat: Val,
    pub lon: Val,
}

pub struct Ioc {
    pub cat: String,
    pub conf: f64,
    pub tag: String,
}

/// threat.* and tags of a threat-intelligence match (`ulpf.intelligence.tip.matcher.apply_hit`).
fn intel_hit(ev: &mut Map, m: &crate::intel::Matcher, hit: &crate::intel::Hit, tags: &mut Vec<String>) {
    let e = &m.entries[hit.entry as usize];
    let st = |i: u32| -> Val {
        let s = m.strings[i as usize].as_str();
        if s.is_empty() { Val::Null } else { Val::s(s) }
    };
    let cat = m.strings[e.cat as usize].as_str();
    let cat = if cat.is_empty() { "Unknown" } else { cat };
    let th = ev.sub("threat");
    th.set("category", Val::s(cat));
    th.set("confidence", Val::Float(e.conf));
    th.set("ioc_type", Val::s(crate::intel::KINDS[hit.kind as usize]));
    th.set("ioc_value", Val::s(&hit.value));
    th.set_str("intel", Val::Map(Map::with(vec![
        (Key::Borrowed("id"), st(e.id)), (Key::Borrowed("source"), st(e.source)),
        (Key::Borrowed("threat_actor"), st(e.actor)), (Key::Borrowed("campaign"), st(e.campaign)),
        (Key::Borrowed("kill_chain_phase"), st(e.kill)),
    ])));
    tags.push(format!("threat:{}", cat.to_lowercase().replace(' ', "_")));
    tags.push("ioc_match".into());
}

const SUSPICIOUS_PORTS: [i64; 12] = [4444, 5555, 6666, 6667, 8888, 9999, 31337, 12345, 27374, 1080, 9050, 9150];

/// `ulpf.engine.enricher.enrich_event` with lookups done by the caller, then the input's tags.
pub fn enrich(ev: &mut Map, geo: &HashMap<String, Geo>, ioc: &HashMap<String, Ioc>, input_tags: &[String],
              intel: Option<&crate::intel::Matcher>) {
    let src_ip = ev.sub_ref("source").get("ip").cloned().unwrap_or(Val::Null);
    let dst_ip = ev.sub_ref("destination").get("ip").cloned().unwrap_or(Val::Null);
    let lookup = |ip: &Val| -> Option<&Geo> { ip.as_str().and_then(|s| geo.get(s)) };
    let (sg, dg) = (lookup(&src_ip), lookup(&dst_ip));
    {
        let g = ev.sub("geo");
        let put = |g: &mut Map, k: &'static str, v: Option<&Val>| g.set(k, v.cloned().unwrap_or(Val::Null));
        put(g, "src_country", sg.map(|x| &x.country));
        put(g, "src_country_code", sg.map(|x| &x.cc));
        put(g, "src_city", sg.map(|x| &x.city));
        put(g, "src_latitude", sg.map(|x| &x.lat));
        put(g, "src_longitude", sg.map(|x| &x.lon));
        put(g, "dst_country", dg.map(|x| &x.country));
        put(g, "dst_country_code", dg.map(|x| &x.cc));
        put(g, "dst_city", dg.map(|x| &x.city));
        put(g, "dst_latitude", dg.map(|x| &x.lat));
        put(g, "dst_longitude", dg.map(|x| &x.lon));
    }
    let mut tags: Vec<String> = match ev.get("tags") {
        Some(Val::List(l)) => l.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect(),
        _ => vec![],
    };
    if let Some(m) = intel {
        fn ip(v: &Val) -> Option<&str> {
            if v.truthy() { v.as_str() } else { None }
        }
        if let Some(hit) = m.match_event(ip(&src_ip), ip(&dst_ip), ev.get_str("raw_event")) {
            intel_hit(ev, m, &hit, &mut tags);
        }
    }
    for ip in [&src_ip, &dst_ip] {
        if intel.is_some() || !ip.truthy() {
            continue;
        }
        if let Some(hit) = ip.as_str().and_then(|s| ioc.get(s)) {
            let th = ev.sub("threat");
            th.set("category", Val::s(&hit.cat));
            th.set("confidence", Val::Float(hit.conf));
            th.set("ioc_type", Val::s("ip"));
            th.set("ioc_value", ip.clone());
            tags.push(hit.tag.clone());
            tags.push("ioc_match".into());
            break;
        }
    }
    let sev = match ev.get("severity") {
        Some(Val::Int(i)) => *i,
        _ => 0,
    };
    if sev >= 9 {
        tags.push("critical_severity".into());
    } else if sev >= 7 {
        tags.push("high_severity".into());
    }
    match ev.get_str("action") {
        Some("blocked" | "dropped" | "denied") => tags.push("blocked_traffic".into()),
        Some("detected" | "alerted") => tags.push("security_alert".into()),
        _ => {}
    }
    if let Some(Val::Int(port)) = ev.sub_ref("destination").get("port") {
        if SUSPICIOUS_PORTS.contains(port) {
            tags.push(format!("suspicious_port:{port}"));
        }
    }
    if let Some(cat) = ev.get_str("category").filter(|c| !c.is_empty()) {
        tags.push(format!("category:{cat}"));
    }
    let g = ev.sub_ref("geo");
    let (scc, dcc) = (g.get("src_country_code"), g.get("dst_country_code"));
    if let (Some(Val::Str(a)), Some(Val::Str(b))) = (scc, dcc) {
        let bad = ["XX", "??", "ZZ"];
        if !a.is_empty() && !b.is_empty() && a != b && !bad.contains(&a.as_str()) && !bad.contains(&b.as_str()) {
            tags.push("cross_border".into());
        }
    }
    if tags.len() > 1 {
        let mut seen = rustc_hash::FxHashSet::default();
        tags.retain(|t| seen.insert(t.clone()));
    }
    tags.extend(input_tags.iter().cloned());
    ev.set("tags", Val::List(tags.into_iter().map(Val::string).collect()));
}

// ---------------------------------------------------------------------------
// Store rows, written straight into Arrow column buffers
// ---------------------------------------------------------------------------

/// Python `str(v)` (`_str_or_none` for non-None values) appended to `out`.
fn push_text(v: &Val, out: &mut String) {
    match v {
        Val::Str(s) => out.push_str(s),
        Val::Int(i) => out.push_str(itoa::Buffer::new().format(*i)),
        Val::Bool(true) => out.push_str("True"),
        Val::Bool(false) => out.push_str("False"),
        Val::Float(f) => crate::val::push_float_repr(*f, out),
        Val::Null => out.push_str("None"),
        // never reached for store columns (field mapping skips containers)
        other => write_json(other, out),
    }
}

/// `_safe_int` into the INTEGER (32-bit) store columns.
fn safe_i32(v: Option<&Val>) -> Option<i32> {
    match v {
        Some(Val::Int(i)) if (-2_147_483_648..=2_147_483_647).contains(i) => Some(*i as i32),
        Some(Val::Bool(b)) => Some(*b as i32),
        _ => None,
    }
}

/// EVENT_COLUMNS: name and kind ('s' string, 'i' INTEGER).
pub const LAYOUT: [(&str, char); 24] = [
    ("event_id", 's'), ("timestamp", 's'), ("timestamp_original", 's'), ("category", 's'), ("event_type", 's'),
    ("action", 's'), ("severity", 'i'), ("severity_label", 's'), ("source_ip", 's'), ("source_port", 'i'),
    ("destination_ip", 's'), ("destination_port", 'i'), ("protocol", 's'), ("device_vendor", 's'),
    ("device_product", 's'), ("raw_event", 's'), ("raw_format", 's'), ("raw_hash", 's'), ("parsed_fields", 's'),
    ("normalised_json", 's'), ("message", 's'), ("tags", 's'), ("correlation_id", 's'), ("row_mac", 's'),
];

pub struct Column {
    pub name: &'static str,
    pub kind: char,
    pub validity: Vec<u8>,
    pub offsets: Vec<u8>,   // string columns: n + 1 little-endian i32
    pub data: Vec<u8>,      // string bytes, or little-endian i32 values
    pub nulls: usize,
    text: String,           // string bytes while building
    start: usize,           // where the current row's value starts in `text`
}

impl Column {
    fn new(name: &'static str, kind: char, cap: usize) -> Self {
        let mut c = Column { name, kind, validity: Vec::with_capacity(cap / 8 + 1), offsets: Vec::new(), data: Vec::new(),
                             nulls: 0, text: String::new(), start: 0 };
        if kind == 's' {
            c.offsets.reserve((cap + 1) * 4);
            c.offsets.extend_from_slice(&0i32.to_le_bytes());
        } else {
            c.data.reserve(cap * 4);
        }
        c
    }

    fn mark(&mut self, row: usize, valid: bool) {
        if row % 8 == 0 {
            self.validity.push(0);
        }
        if valid {
            *self.validity.last_mut().unwrap() |= 1 << (row % 8);
        } else {
            self.nulls += 1;
        }
    }

    /// Begin a string value; write it into the returned buffer, then call `end`.
    fn begin(&mut self) -> &mut String {
        self.start = self.text.len();
        &mut self.text
    }

    fn end(&mut self, row: usize, valid: bool) -> Result<(), String> {
        self.mark(row, valid);
        let off = i32::try_from(self.text.len()).map_err(|_| format!("column {} exceeds 2 GiB", self.name))?;
        self.offsets.extend_from_slice(&off.to_le_bytes());
        Ok(())
    }

    fn put_str(&mut self, row: usize, v: Option<&Val>) -> Result<(), String> {
        match v {
            None | Some(Val::Null) => {
                self.start = self.text.len();
                self.end(row, false)
            }
            Some(x) => {
                push_text(x, self.begin());
                self.end(row, true)
            }
        }
    }

    fn put_int(&mut self, row: usize, v: Option<i32>) {
        self.mark(row, v.is_some());
        self.data.extend_from_slice(&v.unwrap_or(0).to_le_bytes());
    }

    /// The current row's value: None for NULL.
    fn current(&self, row: usize) -> Option<&str> {
        if self.validity[row / 8] & (1 << (row % 8)) == 0 {
            None
        } else {
            Some(&self.text[self.start..])
        }
    }

    fn current_int(&self, row: usize) -> Option<i32> {
        if self.validity[row / 8] & (1 << (row % 8)) == 0 {
            None
        } else {
            let o = row * 4;
            Some(i32::from_le_bytes(self.data[o..o + 4].try_into().unwrap()))
        }
    }

    fn finish(mut self) -> Self {
        if self.kind == 's' {
            self.data = std::mem::take(&mut self.text).into_bytes();
        }
        self
    }
}

pub struct Columns {
    cols: Vec<Column>,
    n: usize,
    mac_input: Vec<u8>, // one row's MAC input, hashed in one call
}

impl Columns {
    pub fn new(cap: usize) -> Self {
        Columns { cols: LAYOUT.iter().map(|(n, k)| Column::new(n, *k, cap)).collect(), n: 0,
                  mac_input: Vec::with_capacity(8192) }
    }

    /// Append `event_to_row(ev)` (with its row MAC when `key` is given).
    pub fn append(&mut self, ev: &Map, key: Option<&[u8]>) -> Result<(), String> {
        let r = self.n;
        let src = ev.sub_ref("source");
        let dst = ev.sub_ref("destination");
        let dev = ev.sub_ref("device");
        let net = ev.sub_ref("network");
        let or = crate::val::or_chain;
        let c = &mut self.cols;
        c[0].put_str(r, ev.get("event_id"))?;
        c[1].put_str(r, ev.get("timestamp"))?;
        c[2].put_str(r, ev.get("timestamp_original"))?;
        c[3].put_str(r, ev.get("category"))?;
        c[4].put_str(r, ev.get("event_type"))?;
        c[5].put_str(r, ev.get("action"))?;
        c[6].put_int(r, Some(safe_i32(ev.get("severity")).unwrap_or(0)));
        c[7].put_str(r, ev.get("severity_label"))?;
        c[8].put_str(r, or(&[src.get("ip"), src.get("hostname")]))?;
        c[9].put_int(r, safe_i32(src.get("port")));
        c[10].put_str(r, or(&[dst.get("ip"), dst.get("hostname"), dev.get("hostname")]))?;
        c[11].put_int(r, safe_i32(dst.get("port")));
        c[12].put_str(r, net.get("protocol"))?;
        c[13].put_str(r, dev.get("vendor"))?;
        c[14].put_str(r, dev.get("product"))?;
        c[15].put_str(r, ev.get("raw_event"))?;
        c[16].put_str(r, ev.get("raw_format"))?;
        c[17].put_str(r, ev.sub_ref("evidence").get("raw_hash"))?;
        match ev.get("parsed_fields") {
            Some(Val::Map(m)) => write_json_map(m, c[18].begin(), &[]),
            _ => c[18].begin().push_str("{}"),
        }
        c[18].end(r, true)?;
        write_json_map(ev, c[19].begin(), &["raw_event", "parsed_fields"]);
        c[19].end(r, true)?;
        c[20].put_str(r, ev.get("message"))?;
        write_json(ev.get("tags").unwrap_or(&Val::List(vec![])), c[21].begin());
        c[21].end(r, true)?;
        c[22].put_str(r, ev.get("correlation_id"))?;
        match key {
            Some(k) => {
                let mac = self.mac(r, k);
                self.cols[23].begin().push_str(&mac);
                self.cols[23].end(r, true)?;
            }
            None => self.cols[23].put_str(r, None)?,
        }
        self.n += 1;
        Ok(())
    }

    /// `ulpf.storage.database.row_mac`: keyed BLAKE2b-256 over every column but row_mac,
    /// joined with U+001F, NULL as U+0000.
    fn mac(&mut self, r: usize, key: &[u8]) -> String {
        let buf = &mut self.mac_input;
        buf.clear();
        for (i, col) in self.cols[..23].iter().enumerate() {
            if i > 0 {
                buf.push(0x1f);
            }
            if col.kind == 's' {
                match col.current(r) {
                    Some(v) => buf.extend_from_slice(v.as_bytes()),
                    None => buf.push(0),
                };
            } else {
                match col.current_int(r) {
                    Some(v) => buf.extend_from_slice(itoa::Buffer::new().format(v).as_bytes()),
                    None => buf.push(0),
                };
            }
        }
        blake2b_simd::Params::new().hash_length(32).key(&key[..key.len().min(64)]).hash(buf).to_hex().to_string()
    }

    pub fn finish(self) -> (usize, Vec<Column>) {
        (self.n, self.cols.into_iter().map(Column::finish).collect())
    }
}

/// `ulpf.runtime.analytics.structure_signature` for a built-in format (native events never
/// are `auto_detected` or `raw_fallback`).
pub fn structure_signature(ev: &Map) -> String {
    let fmt = match ev.get("raw_format") {
        Some(Val::Str(s)) if !s.is_empty() => s.as_str(),
        _ => "unknown",
    };
    let mut keys: Vec<&str> = match ev.get("parsed_fields") {
        Some(Val::Map(m)) => m.0.iter().map(|(k, _)| k.as_ref()).collect(),
        _ => vec![],
    };
    keys.sort_unstable(); // str order is byte order for the ASCII keys of native events
    keys.truncate(60);
    let mut s = String::with_capacity(fmt.len() + 1 + keys.iter().map(|k| k.len() + 1).sum::<usize>());
    s.push_str(fmt);
    s.push(':');
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(k);
    }
    s
}

/// The fields `ulpf.runtime.worker.project` keeps, as one JSON object; `sigma` is the
/// JSON of the Sigma hits when the worker evaluates rules (`null`: Python fills it in).
pub fn write_projection_with(ev: &Map, sigma: Option<&str>, out: &mut String) {
    write_projection(ev, out);
    if let Some(h) = sigma {
        out.pop();
        out.push_str(",\"sigma\":");
        out.push_str(h);
        out.push('}');
    }
}

/// The fields `ulpf.runtime.worker.project` keeps, as one JSON object.
pub fn write_projection(ev: &Map, out: &mut String) {
    // written directly (same keys and order as the dict project() builds), without a copy
    let null = Val::Null;
    let val = |m: &Map, k: &str, out: &mut String| write_json(m.get(k).unwrap_or(&null), out);
    out.push('{');
    for (i, k) in ["event_id", "timestamp", "category", "action", "severity", "message", "event_type", "raw_format"]
        .iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_json_key(&Key::Borrowed(k), out);
        val(ev, k, out);
    }
    // same groups, keys and order as worker._PROJ_GROUPS
    for (name, keys) in [("source", &["ip", "hostname", "mac", "port"][..]), ("destination", &["ip", "hostname", "port"]),
                         ("device", &["hostname", "ip", "product", "vendor"]),
                         ("user", &["name", "domain", "id", "email", "source"]),
                         ("network", &["session_id", "bytes_in", "bytes_out", "protocol"]),
                         ("threat", &["ioc_value", "category", "signature"]), ("rule", &["name"]),
                         ("geo", &["src_country_code", "src_city", "src_latitude", "src_longitude"])] {
        let m = ev.sub_ref(name);
        out.push(',');
        write_json_key(&Key::Borrowed(name), out);
        out.push('{');
        for (i, k) in keys.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            write_json_key(&Key::Borrowed(k), out);
            val(m, k, out);
        }
        out.push('}');
    }
    out.push('}');
}

pub fn events_json(events: &[&Map]) -> String {
    let mut out = String::with_capacity(events.len() * 2048);
    out.push('[');
    for (i, ev) in events.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_json_map(ev, &mut out, &[]);
    }
    out.push(']');
    out
}

#[allow(dead_code)]
pub fn json_str(s: &str) -> String {
    let mut out = String::new();
    write_json_str(s, &mut out);
    out
}
