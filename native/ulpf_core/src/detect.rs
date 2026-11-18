//! Port of `ulpf.engine.detector.detect_format` for printable-ASCII lines.

use regex::Regex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fmt {
    Cef,
    Leef,
    Syslog,
    Json,
    Kv,
    /// xml, w3c, csv, unknown, JSON arrays, undecidable JSON: the Python pipeline handles them
    Other,
}

pub struct Detector {
    cef: Regex,
    leef: Regex,
    xml_tag: Regex,
    clf: Regex,
    ipv4: Regex,
    fallback: Vec<(Fmt, Regex, f64)>,
    kv_pair: Regex,
}

const HTTP_METHODS: [&str; 9] = ["GET", "POST", "CONNECT", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE"];

impl Detector {
    pub fn new() -> Self {
        let r = |p: &str| Regex::new(p).unwrap();
        Detector {
            cef: r(r"(?i)(?:^|[\s|])CEF:\d+\|"),
            leef: r(r"(?i)(?:^|[\s|])LEEF:\d+"),
            xml_tag: r(r"<\w+[\s>]"),
            clf: r(r"^\S+\s+\S+\s+\S+\s+\[\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}"),
            ipv4: r(r"^\d{1,3}(?:\.\d{1,3}){3}$"),
            fallback: vec![
                (Fmt::Cef, r(r"(?i)CEF:\d+\|"), 0.98),
                (Fmt::Leef, r(r"(?i)LEEF:\d+\.\d+\|"), 0.98),
                (Fmt::Syslog, r(r"^<\d{1,3}>\d{1,2}\s+\d{4}-\d{2}-\d{2}T"), 0.95),
                (Fmt::Syslog, r(r"^<\d{1,3}>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+"), 0.92),
                (Fmt::Syslog, r(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+"), 0.80),
                (Fmt::Other, r(r"^#(Fields|Version|Date|Software|Start-Date):"), 0.97),
                (Fmt::Other, r(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+\s+\S+\s+\d+\s+"), 0.75),
            ],
            kv_pair: r(r"[\w.]+=[^\s]+"),
        }
    }

    /// (format, confidence) for a stripped, printable-ASCII line. `json` is the parsed
    /// object when the line was detected as JSON (so it is decoded once).
    pub fn detect(&self, s: &str, json: &mut Option<serde_json::Value>) -> (Fmt, f64) {
        let b = s.as_bytes();
        let first = b[0];
        if s.contains("CEF:") || s.contains("cef:") {
            if s.starts_with("CEF:") || self.cef.is_match(s) {
                return (Fmt::Cef, 0.98);
            }
        }
        if s.contains("LEEF:") || s.contains("leef:") {
            if s.starts_with("LEEF:") || self.leef.is_match(s) {
                return (Fmt::Leef, 0.98);
            }
        }
        if first == b'<' {
            if b.len() > 1 && b[1].is_ascii_digit() {
                let close = s[1..].find('>').map(|i| i + 1);
                if let Some(c) = close.filter(|c| *c > 0 && *c < 6) {
                    let after = &b[c + 1..];
                    if !after.is_empty() && after[0].is_ascii_digit() {
                        return (Fmt::Syslog, 0.95);
                    }
                    return (Fmt::Syslog, 0.92);
                }
                return (Fmt::Syslog, 0.90);
            }
            if s.starts_with("<Event") || s.starts_with("<?xml") {
                return (Fmt::Other, 0.92);
            }
            if !s.starts_with("<!") && (s.contains("</") || (s.ends_with('>') && self.xml_tag.is_match(s))) {
                return (Fmt::Other, 0.90);
            }
        }
        if first == b'{' && s.ends_with('}') {
            match serde_json::from_str::<serde_json::Value>(s) {
                Ok(v) => {
                    *json = Some(v);
                    return (Fmt::Json, 0.97);
                }
                // Python's json module accepts some things serde_json does not (NaN,
                // huge integers, deep nesting): it decides
                Err(_) => return (Fmt::Other, 0.0),
            }
        }
        if first == b'[' && s.ends_with(']') {
            return (Fmt::Other, 0.0);
        }
        if s.starts_with("#Fields:") {
            return (Fmt::Other, 0.97);
        }
        if s.contains(" [") && s.contains("] \"") && self.clf.is_match(s) {
            return (Fmt::Other, 0.90);
        }
        if b.len() > 19 && b[4] == b'-' && b[7] == b'-' && b[10] == b' ' && b[13] == b':' && b[16] == b':' {
            let parts: Vec<&str> = s.split_ascii_whitespace().collect();
            if parts.len() >= 6 {
                let (t1, t2) = (parts[2], parts[3]);
                if !t1.starts_with('[') && !t2.starts_with('[') && !t1.starts_with('<') {
                    let up1 = t1.to_ascii_uppercase();
                    let up2 = t2.to_ascii_uppercase();
                    if self.ipv4.is_match(t1) || HTTP_METHODS.contains(&up1.as_str())
                        || HTTP_METHODS.contains(&up2.as_str()) {
                        return (Fmt::Other, 0.75);
                    }
                }
            }
        }
        if s.contains('=') {
            let eq = s.bytes().filter(|c| *c == b'=').count();
            if eq >= 3 {
                let sp = s.bytes().filter(|c| *c == b' ' || *c == b'\t').count();
                if sp >= 2 && (eq as f64) / ((sp + 1).max(1) as f64) > 0.4 {
                    return (Fmt::Kv, 0.85);
                }
            }
        }
        if s.contains(',') && s.bytes().filter(|c| *c == b',').count() >= 3
            && s.bytes().filter(|c| *c == b'=').count() < 2 {
            return (Fmt::Other, 0.70);
        }
        self.fallback(s)
    }

    fn fallback(&self, s: &str) -> (Fmt, f64) {
        for (fmt, re, conf) in &self.fallback {
            if re.is_match(s) {
                return (*fmt, *conf);
            }
        }
        if s.bytes().filter(|c| *c == b'=').count() >= 3 {
            let found: Vec<&str> = self.kv_pair.find_iter(s).map(|m| m.as_str()).collect();
            if found.len() >= 3 {
                let joined = found.iter().map(|x| x.len()).sum::<usize>() + found.len() - 1;
                if joined as f64 / (s.len().max(1) as f64) > 0.4 {
                    return (Fmt::Kv, 0.85);
                }
            }
        }
        (Fmt::Other, 0.30)
    }
}
