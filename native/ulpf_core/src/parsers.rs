//! Ports of the stateless built-in parsers: syslog (RFC 3164 / 5424 / plain), CEF,
//! LEEF, key=value and JSON. Each returns `Err(Delegate)` where the Python parser
//! would return None (the line then goes through APG / raw fallback in Python) or
//! where its result cannot be reproduced exactly.

use crate::norm::{py_strip, Build, Ctx, Delegate, R};
use crate::scan;
use crate::val::{or_chain, Key, Map, Val};
use regex::Regex;

pub struct Parsers {
    prefix_hostname: Regex,
    prefix_iso: Regex,
    prefix_syslog_ts: Regex,
    leef_version: Regex,
}

fn s(x: &str) -> Val {
    Val::s(x)
}

fn kk(x: &str) -> Key {
    Key::owned(x)
}

const FACILITY: [(u32, &str); 20] = [
    (0, "kern"), (1, "user"), (2, "mail"), (3, "daemon"), (4, "auth"), (5, "syslog"), (6, "lpr"), (7, "news"),
    (8, "uucp"), (9, "cron"), (10, "authpriv"), (11, "ftp"), (16, "local0"), (17, "local1"), (18, "local2"),
    (19, "local3"), (20, "local4"), (21, "local5"), (22, "local6"), (23, "local7"),
];

fn contains_any(h: &str, words: &[&str]) -> bool {
    words.iter().any(|w| h.contains(w))
}

impl Parsers {
    pub fn new() -> Self {
        let r = |p: &str| Regex::new(p).unwrap();
        Parsers {
            prefix_hostname: r(concat!(r"(?:^<\d{1,3}>)?(?:\d\s+)?",
                r"(?:(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
                r"|\d{4}-\d{2}-\d{2}T\S+)", r"\s+([\w.\-]+)\s")),
            prefix_iso: r(r"\b(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b"),
            prefix_syslog_ts: r(r"\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"),
            leef_version: r(r"^\d+(\.\d+)?$"),
        }
    }

    // -----------------------------------------------------------------------
    // Syslog
    // -----------------------------------------------------------------------

    pub fn syslog(&self, line: &str, c: &Ctx) -> R<Map> {
        if let Some(m) = scan::rfc5424(line) {
            let g = |i: usize| m[i - 1].map(|(a, b)| &line[a..b]).unwrap_or("");
            let pri: i64 = g(1).parse().map_err(|_| Delegate)?;
            let (ver, ts, host, app, procid, msgid) = (g(2), g(3), g(4), g(5), g(6), g(7));
            let mut sd = g(8);
            let msg = g(9);
            if sd == "-" {
                sd = "";
            }
            let (fac, sev) = (pri >> 3, pri & 7);
            let mut p = self.syslog_fields(pri, fac, sev, ts, host, app, procid, msg, sd);
            p.set("syslog_version", s(ver));
            p.set("msgid", s(msgid));
            if !sd.is_empty() {
                let mut params = Vec::new();
                scan::sd_params(sd, &mut params);
                for ((ka, kb), q, u) in params {
                    let v = q.or(u).map(|(a, b)| &sd[a..b]).unwrap_or("");
                    p.set(kk(&sd[ka..kb].to_ascii_lowercase()), Val::string(v.replace("\\\"", "\"").replace("\\]", "]")));
                }
            }
            let cat = syslog_cat(app, msg);
            return Build {
                raw_line: line, raw_format: "syslog", parsed: p, parser_id: "syslog", parser_name: "Syslog Parser",
                parser_version: "1.1.0", timestamp: if ts != "-" { Some(s(ts)) } else { None },
                severity_raw: Val::Int(sev), severity_source: "syslog", category: cat.into(),
                event_type: s("syslog_rfc5424"), vendor: s("Generic"),
                product: s(if app != "-" { app } else { "syslog" }), version: Val::Null, message: s(msg),
            }.build(c);
        }
        if let Some(m) = scan::rfc3164(line) {
            let g = |i: usize| m[i - 1].map(|(a, b)| &line[a..b]).unwrap_or("");
            let pri: i64 = g(1).parse().map_err(|_| Delegate)?;
            let (ts, host, app, pid, msg) = (g(2), g(3), g(4), g(5), g(6));
            let (fac, sev) = (pri >> 3, pri & 7);
            let p = self.syslog_fields(pri, fac, sev, ts, host, app, pid, msg, "");
            return Build {
                raw_line: line, raw_format: "syslog", parsed: p, parser_id: "syslog", parser_name: "Syslog Parser",
                parser_version: "1.1.0", timestamp: Some(s(ts)), severity_raw: Val::Int(sev),
                severity_source: "syslog", category: syslog_cat(app, msg).into(), event_type: s("syslog_rfc3164"),
                vendor: s("Generic"), product: s(if app.is_empty() { "syslog" } else { app }), version: Val::Null,
                message: s(msg),
            }.build(c);
        }
        if let Some(m) = scan::plain(line) {
            let g = |i: usize| m[i - 1].map(|(a, b)| &line[a..b]).unwrap_or("");
            let (ts, host, app, pid, msg) = (g(1), g(2), g(3), g(4), g(5));
            let both = format!("{app} {msg}");
            let sev = scan::cisco_mnemonic(&both).map(|d| d as i64).unwrap_or(6);
            let p = self.syslog_fields(0, 0, sev, ts, host, app, pid, msg, "");
            return Build {
                raw_line: line, raw_format: "syslog", parsed: p, parser_id: "syslog", parser_name: "Syslog Parser",
                parser_version: "1.1.0", timestamp: Some(s(ts)), severity_raw: Val::Int(sev),
                severity_source: "syslog", category: syslog_cat(app, msg).into(), event_type: s("syslog_plain"),
                vendor: s("Generic"), product: s(if app.is_empty() { "syslog" } else { app }), version: Val::Null,
                message: s(msg),
            }.build(c);
        }
        Err(Delegate)
    }

    #[allow(clippy::too_many_arguments)]
    fn syslog_fields(&self, pri: i64, fac: i64, sev: i64, ts: &str, host: &str, app: &str, pid: &str, msg: &str,
                     sd: &str) -> Map {
        let fname = FACILITY.iter().find(|(f, _)| *f as i64 == fac).map(|x| x.1).unwrap_or("unknown");
        let mut p = Map::new();
        p.set("pri", Val::string(pri.to_string()));
        p.set("facility", Val::string(fac.to_string()));
        p.set("facility_name", s(fname));
        p.set("syslog_severity", Val::string(sev.to_string()));
        p.set("timestamp", s(ts));
        p.set("hostname", s(host));
        p.set("app_name", s(app));
        p.set("pid", s(pid));
        p.set("message", s(msg));
        p.set("devname", s(host));
        let search = if sd.is_empty() { msg.to_string() } else { format!("{sd} {msg}") };
        if msg.contains(" from ") && msg.contains(" port ") {
            if let Some((u, a, pt)) = scan::ssh(msg) {
                p.set("user", s(&msg[u.0..u.1]));
                p.set("src_ip", s(&msg[a.0..a.1]));
                p.set("src_port", s(&msg[pt.0..pt.1]));
            }
        }
        let sp = |x: scan::Span| &search[x.0..x.1];
        let mut pairs = Vec::new();
        scan::cisco_pairs(&search, &mut pairs);
        if let Some((a, pt)) = pairs.first() {
            p.set("src_ip", s(sp(*a)));
            p.set("src_port", s(sp(*pt)));
        }
        if let Some((a, pt)) = pairs.get(1) {
            p.set("dst_ip", s(sp(*a)));
            p.set("dst_port", s(sp(*pt)));
        }
        if !p.contains("src_ip") || !p.contains("dst_ip") {
            let mut ips = Vec::new();
            scan::ipv4_findall(&search, &mut ips);
            if !ips.is_empty() && !p.contains("src_ip") {
                p.set("src_ip", s(sp(ips[0])));
            }
            if ips.len() >= 2 && !p.contains("dst_ip") {
                p.set("dst_ip", s(sp(ips[1])));
            }
        }
        if !p.contains("src_port") || !p.contains("dst_port") {
            let mut ports = Vec::new();
            scan::port_findall(&search, &mut ports);
            if !ports.is_empty() && !p.contains("src_port") {
                p.set("src_port", s(sp(ports[0])));
            }
            if ports.len() >= 2 && !p.contains("dst_port") {
                p.set("dst_port", s(sp(ports[1])));
            }
        }
        let ml = msg.to_ascii_lowercase();
        let action = if contains_any(&ml, &["failed password", "authentication failure", "invalid user", "fail"]) {
            Some("failed")
        } else if contains_any(&ml, &["denied", "deny"]) {
            Some("denied")
        } else if contains_any(&ml, &["drop", "dropped"]) {
            Some("dropped")
        } else if contains_any(&ml, &["blocked", "block"]) {
            Some("blocked")
        } else if contains_any(&ml, &["accepted", "permit", "success", "established", "allowed"]) {
            Some("allowed")
        } else {
            None
        };
        if let Some(a) = action {
            p.set("action", s(a));
        }
        p
    }

    // -----------------------------------------------------------------------
    // CEF
    // -----------------------------------------------------------------------

    /// `parse_cef_extension`
    fn cef_extension(&self, ext: &str) -> Map {
        let mut out = Map::new();
        let has_esc = ext.contains('\\');
        let mut keys = Vec::new(); // (match start, match end, key span)
        scan::ext_split(ext, &mut keys);
        for (i, (_, end, (ka, kb))) in keys.iter().enumerate() {
            let stop = keys.get(i + 1).map(|k| k.0).unwrap_or(ext.len());
            let v = py_strip(&ext[*end..stop]);
            out.set(kk(&ext[*ka..*kb]), Val::string(if has_esc { cef_unescape(v) } else { v.to_string() }));
        }
        out
    }

    pub fn cef(&self, line: &str, c: &Ctx) -> R<Map> {
        let idx = match line.find("CEF:") {
            Some(i) => i,
            None => line.to_ascii_uppercase().find("CEF:").ok_or(Delegate)?,
        };
        let prefix = &line[..idx];
        let parts = split_unescaped_pipes(&line[idx + 4..], 7);
        if parts.len() < 7 {
            return Err(Delegate);
        }
        let h: Vec<String> = parts.iter().take(7).map(|p| cef_unescape(p)).collect();
        let ext_str = parts.get(7).copied().unwrap_or("");
        let (version, vendor, product, dev_ver, sig_id, name, sev) = (&h[0], &h[1], &h[2], &h[3], &h[4], &h[5], &h[6]);
        if !crate::norm::all_digits(py_strip(version)) {
            return Err(Delegate);
        }
        let mut parsed = self.cef_extension(ext_str);
        let labels: Vec<String> = parsed.0.iter().filter(|(k, _)| k.ends_with("Label")).map(|(k, _)| k.to_string()).collect();
        for key in labels {
            let base = &key[..key.len() - 5];
            let label = parsed.get_str(&key).unwrap_or("").to_string();
            if parsed.contains(base) && !label.is_empty() && !parsed.contains(&label) {
                let v = parsed.get(base).cloned().unwrap();
                parsed.set(kk(&label), v);
            }
        }
        let mut mapped = Map::new();
        for (k, v) in &parsed.0 {
            mapped.set(kk(cef_fmap(k).unwrap_or(k)), v.clone());
        }
        for d in [&mut parsed, &mut mapped] {
            d.set("cef_version", s(version));
            d.set("signature_id", s(sig_id));
            d.set("event_name", s(name));
        }
        let mut syslog_hostname: Option<String> = None;
        if !py_strip(prefix).is_empty() {
            if let Some(m) = self.prefix_hostname.captures(prefix) {
                syslog_hostname = Some(m[1].to_string());
                parsed.set("syslog_hostname", s(&m[1]));
            }
        }
        let mut ts: Option<Val> = or_chain(&[mapped.get("timestamp"), mapped.get("start_time")]).cloned();
        if !ts.as_ref().map(|t| t.truthy()).unwrap_or(false) && !py_strip(prefix).is_empty() {
            if let Some(m) = self.prefix_iso.captures(prefix).or_else(|| self.prefix_syslog_ts.captures(prefix)) {
                ts = Some(s(&m[1]));
            }
        }
        let cat_field = mapped.get("cat").map(|v| v.py_str().ok_or(Delegate)).transpose()?.unwrap_or_default();
        let cat = cef_categorize(&format!("{vendor} {product} {name} {cat_field} {sig_id}").to_ascii_lowercase());
        let mut msg_text: Val = or_chain(&[mapped.get("message")]).filter(|v| v.truthy()).cloned()
            .unwrap_or_else(|| s(name));
        if msg_text.truthy() {
            let t = msg_text.py_str().ok_or(Delegate)?;
            if matches!(py_strip(&t).to_ascii_lowercase().as_str(), "drop" | "allow" | "block" | "deny" | "accept" | "pass") {
                msg_text = Val::Str(if !name.is_empty() {
                    format!("{product} {name} enforcement").into()
                } else {
                    format!("{product} rule {sig_id}").into()
                });
            }
        }
        if !mapped.contains("action") {
            let msg_c = mapped.get("message").map(|v| v.py_str().ok_or(Delegate)).transpose()?.unwrap_or_default();
            for cand in [name.as_str(), msg_c.as_str(), sig_id.as_str()] {
                if cand.is_empty() {
                    continue;
                }
                let cl = py_strip(cand).to_ascii_lowercase();
                if contains_any(&cl, &["failed logon", "logon failed", "failure", "fail", "bad password", "4625"]) {
                    mapped.set("action", s("denied"));
                    break;
                }
                if contains_any(&cl, &["allow", "accept", "pass", "permit", "success"]) {
                    mapped.set("action", s("allowed"));
                    break;
                }
                if contains_any(&cl, &["block", "drop", "deny", "denied", "reject", "prevented"]) {
                    mapped.set("action", s("blocked"));
                    break;
                }
            }
        }
        let rule_cat = mapped.get("cat").filter(|v| v.truthy()).cloned();
        let mut ev = Build {
            raw_line: line, raw_format: "cef", parsed: mapped, parser_id: "cef", parser_name: "CEF Parser",
            parser_version: "1.2.0", timestamp: ts, severity_raw: s(sev), severity_source: "cef",
            category: cat.into(), event_type: Val::string(format!("cef_{sig_id}")), vendor: s(vendor),
            product: s(product), version: s(dev_ver), message: msg_text,
        }.build(c)?;
        let rule_name = or_chain(&[parsed.get("RuleName")]).filter(|v| v.truthy()).cloned().unwrap_or_else(|| s(name));
        ev.set("parsed_fields", Val::Map(parsed));
        {
            let rule = ev.sub("rule");
            rule.set("id", s(sig_id));
            rule.set("name", rule_name);
            if let Some(rc) = rule_cat {
                rule.set("category", rc);
            }
        }
        let category = ev.get_str("category").unwrap_or("").to_string();
        let severity = match ev.get("severity") {
            Some(Val::Int(i)) => *i,
            _ => 0,
        };
        if matches!(category.as_str(), "ids_ips" | "web" | "endpoint") || severity >= 7 {
            let th = ev.sub("threat");
            th.set("signature", s(name));
            th.set("signature_id", s(sig_id));
        }
        if let Some(hn) = syslog_hostname {
            let dev = ev.sub("device");
            if !dev.get("hostname").map(|v| v.truthy()).unwrap_or(false) {
                dev.set("hostname", s(&hn));
            }
        }
        Ok(ev)
    }

    // -----------------------------------------------------------------------
    // LEEF
    // -----------------------------------------------------------------------

    pub fn leef(&self, line: &str, c: &Ctx) -> R<Map> {
        let idx = line.find("LEEF:").ok_or(Delegate)?;
        let prefix = &line[..idx];
        let mut parts: Vec<&str> = line[idx + 5..].splitn(6, '|').collect();
        if parts.len() < 5 {
            return Err(Delegate);
        }
        if parts.len() == 5 {
            parts.push("");
        }
        let (version, vendor, product, dev_ver, event_id) = (parts[0], parts[1], parts[2], parts[3], parts[4]);
        let mut kv_str = parts[5];
        if !self.leef_version.is_match(py_strip(version)) {
            return Err(Delegate);
        }
        let mut delim = "\t".to_string();
        if version.starts_with('2') {
            if let Some((head, tail)) = kv_str.split_once('|') {
                if !head.contains('=') {
                    match decode_delimiter(head)? {
                        Some(d) => {
                            delim = d;
                            kv_str = tail;
                        }
                        None => {}
                    }
                }
            }
        }
        let mut raw_pairs = Map::new();
        if kv_str.contains(delim.as_str()) {
            for pair in kv_str.split(delim.as_str()) {
                if let Some((k, v)) = pair.split_once('=') {
                    let k = py_strip(k);
                    if !k.is_empty() {
                        raw_pairs.set(kk(k), s(py_strip(v)));
                    }
                }
            }
        } else if kv_str.contains('=') {
            raw_pairs = self.cef_extension(kv_str);
        }
        let mut parsed = Map::new();
        for (k, v) in &raw_pairs.0 {
            parsed.set(kk(leef_fmap(k).unwrap_or(k)), v.clone());
        }
        parsed.set("leef_version", s(version));
        parsed.set("event_id", s(event_id));
        let mut ts = parsed.get("timestamp").cloned();
        if !ts.as_ref().map(|t| t.truthy()).unwrap_or(false) && !py_strip(prefix).is_empty() {
            if let Some(m) = self.prefix_iso.captures(prefix).or_else(|| self.prefix_syslog_ts.captures(prefix)) {
                ts = Some(s(&m[1]));
            }
        }
        let msg_text = parsed.get("message").filter(|v| v.truthy()).cloned()
            .unwrap_or_else(|| Val::string(format!("{product}: {event_id}")));
        let raw_cat = raw_pairs.get_str("cat").unwrap_or("").to_string();
        let cat = leef_categorize(&format!("{product} {event_id} {raw_cat}").to_ascii_lowercase());
        let sev = parsed.get("severity").cloned().unwrap_or(Val::Null);
        let mut ev = Build {
            raw_line: line, raw_format: "leef", parsed, parser_id: "leef", parser_name: "LEEF Parser",
            parser_version: "1.1.0", timestamp: ts, severity_raw: sev, severity_source: "generic",
            category: cat.into(), event_type: Val::string(format!("leef_{event_id}")), vendor: s(vendor),
            product: s(product), version: s(dev_ver), message: msg_text.clone(),
        }.build(c)?;
        {
            let rule = ev.sub("rule");
            rule.set("id", s(event_id));
            if !raw_cat.is_empty() {
                rule.set("category", s(&raw_cat));
            }
        }
        if ev.get_str("category") == Some("ids_ips") {
            let th = ev.sub("threat");
            th.set("signature", msg_text);
            th.set("signature_id", s(event_id));
        }
        Ok(ev)
    }

    // -----------------------------------------------------------------------
    // Key=value
    // -----------------------------------------------------------------------

    pub fn kv(&self, line: &str, c: &Ctx) -> R<Map> {
        let matches = kv_findall(line);
        if matches.len() < 3 {
            return Err(Delegate);
        }
        let mut p = Map::new();
        for (key, quoted, unquoted) in matches {
            p.set(kk(&key.to_ascii_lowercase()), s(if !quoted.is_empty() { quoted } else { unquoted }));
        }
        let mut ts: Option<String> = None;
        for k in ["date", "time", "eventtime", "timestamp", "start"] {
            if let Some(v) = p.get_str(k) {
                ts = Some(v.to_string());
                break;
            }
        }
        if let (Some(d), Some(t)) = (p.get_str("date"), p.get_str("time")) {
            ts = Some(format!("{d} {t}"));
        }
        if ts.as_deref().map(|t| t.is_empty()).unwrap_or(true) {
            let head = &line[..line.len().min(60)];
            if let Some(m) = self.prefix_iso.captures(head).or_else(|| self.prefix_syslog_ts.captures(head)) {
                ts = Some(m[1].to_string());
            }
        }
        let sev = or_chain(&[p.get("level"), p.get("severity"), p.get("pri")]).cloned().unwrap_or(Val::Null);
        let msg = match or_chain(&[p.get("msg"), p.get("message"), p.get("logdesc")]).filter(|v| v.truthy()) {
            Some(v) => v.clone(),
            None => {
                let ty = |d: &str| capitalize(p.get_str("type").unwrap_or(d));
                Val::Str(if let Some(v) = p.get_str("virus").filter(|v| !v.is_empty()) {
                    format!("Infection detected: {v}").into()
                } else if let Some(a) = p.get_str("attack").filter(|v| !v.is_empty()) {
                    format!("Attack blocked: {a}").into()
                } else if let Some(a) = p.get_str("action").filter(|v| !v.is_empty()) {
                    format!("{} session {a}", ty("traffic")).into()
                } else {
                    format!("{} log event", ty("system")).into()
                })
            }
        };
        let (vendor, product) = if p.contains("devname") || p.contains("devid") {
            (s("Fortinet"), s("FortiGate"))
        } else if p.contains("serial") && p.contains("type") {
            (s(p.get_str("vendor").unwrap_or("Unknown")), s(p.get_str("type").unwrap_or("KV Source")))
        } else {
            (s("Unknown"), s("KV Source"))
        };
        let t = p.get_str("type").unwrap_or("").to_ascii_lowercase();
        let st = p.get_str("subtype").unwrap_or("").to_ascii_lowercase();
        let cat = kv_cat(&format!("{t} {st}"));
        let event_type = or_chain(&[p.get("type"), p.get("subtype")]).filter(|v| v.truthy()).cloned()
            .unwrap_or_else(|| s("kv_event"));
        Build {
            raw_line: line, raw_format: "kv", parsed: p, parser_id: "kv", parser_name: "Key-Value Parser",
            parser_version: "1.0.0", timestamp: ts.map(Val::string), severity_raw: sev, severity_source: "generic",
            category: cat.into(), event_type, vendor, product, version: Val::Null, message: msg,
        }.build(c)
    }

    // -----------------------------------------------------------------------
    // JSON
    // -----------------------------------------------------------------------

    pub fn json(&self, line: &str, data: serde_json::Value, c: &Ctx) -> R<Map> {
        let serde_json::Value::Object(obj) = data else { return Err(Delegate) };
        let source_is_str = matches!(obj.get("source"), Some(serde_json::Value::String(_)));
        let source_str = obj.get("source").and_then(|v| v.as_str()).map(|x| x.to_string());
        let mut flat = Map::new();
        flatten(&obj, "", &mut flat)?;
        // lower-cased key -> original key (the last one wins, as in the dict comprehension)
        let mut lower: Vec<(String, String)> = Vec::new();
        for (k, _) in &flat.0 {
            let l = k.to_ascii_lowercase();
            if let Some(slot) = lower.iter_mut().find(|(lk, _)| *lk == l) {
                slot.1 = k.to_string();
            } else {
                lower.push((l, k.to_string()));
            }
        }
        let find = |cands: &[&str]| -> Option<Val> {
            for cand in cands {
                if let Some((_, key)) = lower.iter().find(|(lk, _)| lk == cand) {
                    let v = flat.get(key).unwrap();
                    if !v.is_none_or_empty() {
                        return Some(v.clone());
                    }
                }
            }
            for cand in cands {
                let suffix = format!(".{cand}");
                for (lk, key) in &lower {
                    if lk.ends_with(&suffix) {
                        let v = flat.get(key).unwrap();
                        if !v.is_none_or_empty() {
                            return Some(v.clone());
                        }
                    }
                }
            }
            None
        };
        let ts = find(&["timestamp", "@timestamp", "time", "datetime", "date", "event_time", "eventtime", "created", "ts"]);
        let sev = find(&["severity", "level", "priority", "sev", "risk", "threat_level", "log.level"]);
        let msg = find(&["message", "msg", "description", "summary", "event_message", "detail"]);
        let mut vendor = or_chain(&[flat.get("vendor"), flat.get("device_vendor"), flat.get("observer.vendor")]).cloned();
        if vendor.as_ref().map(|v| v.is_null()).unwrap_or(true) && source_is_str {
            vendor = source_str.map(Val::string);
        }
        let product = or_chain(&[flat.get("product"), flat.get("device_product"), flat.get("observer.product"),
                                 flat.get("service")]).filter(|v| v.truthy()).cloned().unwrap_or_else(|| s("JSON Source"));
        let event_type = or_chain(&[flat.get("event_type"), flat.get("type"), flat.get("event.action")])
            .filter(|v| v.truthy()).cloned().unwrap_or_else(|| s("json_event"));
        let text = |v: &Val| v.py_str().ok_or(Delegate);
        let vendor_s = match vendor.filter(|v| v.truthy()) {
            Some(v) => text(&v)?,
            None => "Unknown".into(),
        };
        let cat = json_cat(&flat);
        Build {
            raw_line: line, raw_format: "json", timestamp: ts.map(|t| text(&t).map(Val::string)).transpose()?,
            severity_raw: sev.unwrap_or(Val::Null), severity_source: "generic", category: cat.into(),
            event_type: Val::string(text(&event_type)?), vendor: Val::string(vendor_s), product: Val::string(text(&product)?),
            version: Val::Null, message: match msg {
                Some(m) => Val::string(text(&m)?),
                None => Val::Null,
            },
            parsed: flat, parser_id: "json", parser_name: "JSON Parser", parser_version: "1.1.0",
        }.build(c)
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn syslog_cat(app: &str, msg: &str) -> &'static str {
    let c = format!("{app} {msg}").to_ascii_lowercase();
    let has = |ws: &[&str]| contains_any(&c, ws);
    if has(&["%sec", "%fw", "iptables", "firewall", "acl"]) { return "firewall"; }
    if has(&["%ids", "intrusion", "attack", "exploit"]) { return "ids_ips"; }
    if has(&["sshd", "login", "auth", "pam"]) { return "authentication"; }
    if has(&["%lineproto", "%link", "%ospf", "%bgp"]) { return "network"; }
    if has(&["dns", "named", "bind"]) { return "dns"; }
    if has(&["%sys", "kernel", "systemd"]) { return "system"; }
    "network"
}

fn cef_categorize(c: &str) -> &'static str {
    const RULES: [(&str, &[&str]); 8] = [
        ("authentication", &["active directory", "logon", "login", "auth", "kerberos", "ldap", "radius", "saml", "sso",
                             "password", "credential", "4624", "4625"]),
        ("endpoint", &["crowdstrike", "falcon", "endpoint", "process", "sensor", "edr", "antivirus", "filepath"]),
        ("web", &["waf", "web", "asm", "sql injection", "xss", "cross-site", "http", "uri", "url", "injection"]),
        ("dns", &["dns", "bind", "named"]),
        ("firewall", &["firewall", "fw", "iptables", "palo alto", "pa-", "fortigate", "fgt", "asa", "checkpoint",
                       "check point", "threat alert"]),
        ("ids_ips", &["ids", "ips", "intrusion", "snort", "suricata", "threat"]),
        ("vpn", &["vpn", "tunnel"]),
        ("proxy", &["proxy", "squid"]),
    ];
    for (cat, words) in RULES {
        if contains_any(c, words) {
            return cat;
        }
    }
    "network"
}

fn leef_categorize(c: &str) -> &'static str {
    if contains_any(c, &["ids", "ips", "intrusion", "snort", "suricata", "attack", "trojan", "recon"]) { return "ids_ips"; }
    if contains_any(c, &["firewall", "fw"]) { return "firewall"; }
    if c.contains("dns") { return "dns"; }
    if contains_any(c, &["auth", "login", "logon"]) { return "authentication"; }
    "network"
}

fn kv_cat(c: &str) -> &'static str {
    if c.contains("traffic") || c.contains("forward") { return "firewall"; }
    if contains_any(c, &["utm", "ips", "virus", "attack"]) { return "ids_ips"; }
    if c.contains("event") && c.contains("vpn") { return "vpn"; }
    if c.contains("dns") { return "dns"; }
    if c.contains("auth") || c.contains("login") { return "authentication"; }
    if c.contains("web") || c.contains("waf") { return "web"; }
    "network"
}

fn json_cat(flat: &Map) -> &'static str {
    let txt = flat.0.iter().filter_map(|(_, v)| v.as_str()).collect::<Vec<_>>().join(" ").to_ascii_lowercase();
    let keys = flat.0.iter().map(|(k, _)| k.as_ref()).collect::<Vec<_>>().join(" ").to_ascii_lowercase();
    if contains_any(&txt, &["waf", "xss", "sqli", "sql injection", "injection", "modsecurity"]) { return "web"; }
    if contains_any(&txt, &["firewall", "fw_rule"]) { return "firewall"; }
    if contains_any(&txt, &["intrusion", "ids_alert", "suricata", "snort"]) { return "ids_ips"; }
    if contains_any(&txt, &["login", "logon", "authentication"]) || keys.contains("auth") { return "authentication"; }
    if txt.contains("dns") || keys.contains("query") || keys.contains("qname") { return "dns"; }
    if keys.contains("http") || keys.contains("url") || keys.contains("uri") { return "web"; }
    "network"
}

fn capitalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, ch) in s.chars().enumerate() {
        if i == 0 {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch.to_ascii_lowercase());
        }
    }
    out
}

fn cef_fmap(k: &str) -> Option<&'static str> {
    Some(match k {
        "src" => "src_ip", "dst" => "dst_ip", "spt" => "src_port", "dpt" => "dst_port", "smac" => "src_mac",
        "dmac" => "dst_mac", "shost" => "src_host", "dhost" => "dst_host", "proto" => "protocol",
        "in" => "bytes_in", "out" => "bytes_out", "act" => "action", "suser" => "suser", "duser" => "duser",
        "rt" => "timestamp", "end" => "end_time", "start" => "start_time", "msg" => "message",
        "reason" => "reason", "app" => "application", "requestUrl" => "url", "request" => "url",
        "fname" => "filename", "deviceExternalId" => "devid", "deviceDirection" => "direction",
        "sourceTranslatedAddress" => "src_nat_ip", "destinationTranslatedAddress" => "dst_nat_ip",
        _ => return None,
    })
}

fn leef_fmap(k: &str) -> Option<&'static str> {
    Some(match k {
        "src" => "src_ip", "dst" => "dst_ip", "srcPort" => "src_port", "dstPort" => "dst_port",
        "srcMAC" => "src_mac", "dstMAC" => "dst_mac", "proto" => "protocol", "srcBytes" => "bytes_out",
        "dstBytes" => "bytes_in", "action" => "action", "usrName" => "user", "identSrc" => "user",
        "devTime" => "timestamp", "sev" => "severity", "policy" => "rule_name", "url" => "url",
        "msg" => "message", "message" => "message", "srcPackets" => "sentpkt", "dstPackets" => "rcvdpkt",
        _ => return None,
    })
}

/// CEF escapes: \= \\ \n \r \|
fn cef_unescape(v: &str) -> String {
    if !v.contains('\\') {
        return v.to_string();
    }
    let b = v.as_bytes();
    let mut out = String::with_capacity(v.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            let rep = match b[i + 1] {
                b'=' => Some('='),
                b'\\' => Some('\\'),
                b'n' => Some('\n'),
                b'r' => Some('\r'),
                b'|' => Some('|'),
                _ => None,
            };
            if let Some(r) = rep {
                out.push(r);
                i += 2;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// `re.split(r"(?<!\\)\|", s, maxsplit)`
fn split_unescaped_pipes(s: &str, maxsplit: usize) -> Vec<&str> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    for i in 0..b.len() {
        if out.len() == maxsplit {
            break;
        }
        if b[i] == b'|' && (i == 0 || b[i - 1] != b'\\') {
            out.push(&s[start..i]);
            start = i + 1;
        }
    }
    out.push(&s[start..]);
    out
}

/// LEEF 2.0 delimiter field. Ok(None) = not a delimiter; Err = Python decides.
fn decode_delimiter(field: &str) -> R<Option<String>> {
    let f = py_strip(field);
    if f.is_empty() {
        return Ok(Some("\t".into()));
    }
    if f.len() == 1 {
        return Ok(Some(f.to_string()));
    }
    let low = f.to_ascii_lowercase();
    if low == "\\t" || low == "tab" {
        return Ok(Some("\t".into()));
    }
    let hex = low.strip_prefix("0x").or_else(|| low.strip_prefix('x')).unwrap_or(&low);
    if !(1..=4).contains(&hex.len()) {
        return Ok(None);
    }
    if !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(Delegate); // int(x, 16) accepts more (underscores, signs)
    }
    let code = u32::from_str_radix(hex, 16).map_err(|_| Delegate)?;
    match char::from_u32(code) {
        Some(ch) if ch == '\t' || (ch.is_ascii() && !ch.is_ascii_control()) => Ok(Some(ch.to_string())),
        _ => Err(Delegate),
    }
}

/// `_KV.findall(line)` for
/// `([\w.]+)=(?:"([^"]*)"|((?:(?![\s,;]+|:(?=[a-zA-Z_][\w.-]*=))\S)+))`
fn kv_findall(line: &str) -> Vec<(&str, &str, &str)> {
    let b = line.as_bytes();
    let n = b.len();
    let is_key = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'.';
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < n {
        // the key run ends where the first non-[\w.] character is; it must be '='
        if !is_key(b[pos]) {
            pos += 1;
            continue;
        }
        let mut j = pos;
        while j < n && is_key(b[j]) {
            j += 1;
        }
        if j >= n || b[j] != b'=' {
            pos += 1;
            continue;
        }
        let key = &line[pos..j];
        let v = j + 1;
        // alternative 1: "quoted"
        if v < n && b[v] == b'"' {
            if let Some(close) = line[v + 1..].find('"') {
                let q = &line[v + 1..v + 1 + close];
                out.push((key, q, ""));
                pos = v + 1 + close + 1;
                continue;
            }
        }
        // alternative 2: unquoted run of \S, stopping before [\s,;] or ':' + key=
        let mut e = v;
        while e < n {
            let ch = b[e];
            if ch == b' ' || ch == b'\t' || ch == b',' || ch == b';' {
                break;
            }
            if ch == b':' && colon_starts_key(&b[e + 1..]) {
                break;
            }
            e += 1;
        }
        if e > v {
            out.push((key, "", &line[v..e]));
            pos = e;
        } else {
            pos += 1;
        }
    }
    out
}

/// `(?=[a-zA-Z_][\w.-]*=)`
fn colon_starts_key(rest: &[u8]) -> bool {
    if rest.is_empty() || !(rest[0].is_ascii_alphabetic() || rest[0] == b'_') {
        return false;
    }
    let mut i = 1;
    while i < rest.len() && (rest[i].is_ascii_alphanumeric() || rest[i] == b'_' || rest[i] == b'.' || rest[i] == b'-') {
        i += 1;
    }
    i < rest.len() && rest[i] == b'='
}

/// `_flatten`; non-ASCII strings and integers beyond 64 bits are left to Python.
fn flatten(obj: &serde_json::Map<String, serde_json::Value>, prefix: &str, out: &mut Map) -> R<()> {
    for (k, v) in obj {
        if !k.is_ascii() {
            return Err(Delegate);
        }
        let nk = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
        match v {
            serde_json::Value::Object(o) => flatten(o, &nk, out)?,
            serde_json::Value::Array(a) if a.first().map(|x| x.is_object()).unwrap_or(false) => {
                for (i, item) in a.iter().enumerate() {
                    if let serde_json::Value::Object(o) = item {
                        flatten(o, &format!("{nk}[{i}]"), out)?;
                    }
                }
            }
            other => out.set(Key::from(nk), to_val(other)?),
        }
    }
    Ok(())
}

pub fn to_val(v: &serde_json::Value) -> R<Val> {
    Ok(match v {
        serde_json::Value::Null => Val::Null,
        serde_json::Value::Bool(b) => Val::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Val::Int(i)
            } else if n.is_u64() {
                return Err(Delegate); // above i64: Python keeps an int, every consumer must agree
            } else {
                Val::Float(n.as_f64().ok_or(Delegate)?)
            }
        }
        serde_json::Value::String(s) => {
            if !s.is_ascii() {
                return Err(Delegate);
            }
            Val::s(s)
        }
        serde_json::Value::Array(a) => Val::List(a.iter().map(to_val).collect::<R<Vec<_>>>()?),
        serde_json::Value::Object(o) => {
            let mut m = Map::new();
            for (k, x) in o {
                if !k.is_ascii() {
                    return Err(Delegate);
                }
                m.set(Key::owned(k), to_val(x)?);
            }
            Val::Map(m)
        }
    })
}
