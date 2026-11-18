//! Learned-parser (APG) dispatch: the anchored regexes of every live adaptive parser in one
//! `RegexSet` (one linear-time pass over the line), then captures with the winning parser.
//!
//! The patterns are the ones `ulpf.intelligence.auto_parser.compiler` builds for Python `re`.
//! Both engines agree on lines of printable ASCII plus tab: `\s` `\d` `\w` cover the same
//! characters there (Python's `\s` adds U+001C..U+001F) and with no newline Python's `$` cannot
//! match before a trailing `\n`. Any other line, and any parser whose pattern does not compile
//! here, is left to Python (`Hit::Undecided`) so results never differ.
//!
//! Winner: lowest (rank, parser source != line source, index), as `registry.AnchorIndex.match`.

use regex::{Regex, RegexBuilder, RegexSetBuilder, RegexSet};

const SIZE_LIMIT: usize = 16 << 20;       // per compiled program (bounds memory per worker)

pub struct Parser {
    re: Option<Regex>,
    extract: Option<Extract>,
    rank: u32,
    source: String,
}

pub struct Set {
    set: Option<RegexSet>,
    ids: Vec<usize>,            // set pattern -> parser index
    parsers: Vec<Parser>,
    failed: Vec<usize>,
}

pub enum Hit {
    None,
    Undecided,
    /// (parser, group values, fields when the core extracted them)
    Parser(usize, Vec<Option<String>>, Option<Vec<(String, String)>>),
}

pub fn safe_line(s: &str) -> bool {
    s.bytes().all(|b| (0x20..0x7f).contains(&b) || b == b'\t')
}

impl Set {
    pub fn build(patterns: Vec<Option<String>>, ranks: Vec<u32>, sources: Vec<String>,
                 extracts: Vec<Option<Extract>>) -> Set {
        let mut extracts = extracts.into_iter();
        let mut parsers = Vec::with_capacity(patterns.len());
        let mut failed = Vec::new();
        let mut ids = Vec::new();
        let mut srcs = Vec::new();
        for (i, ((p, rank), source)) in patterns.into_iter().zip(ranks).zip(sources).enumerate() {
            let re = p.as_deref().and_then(|p| RegexBuilder::new(p).size_limit(SIZE_LIMIT).build().ok());
            match (&re, p) {
                (Some(_), Some(p)) => {
                    ids.push(i);
                    srcs.push(p);
                }
                _ => failed.push(i),
            }
            parsers.push(Parser { re, extract: extracts.next().flatten(), rank, source });
        }
        let set = RegexSetBuilder::new(&srcs).size_limit(SIZE_LIMIT * 4).build().ok();
        if set.is_none() {
            failed = (0..parsers.len()).collect();
        }
        Set { set, ids, parsers, failed }
    }

    pub fn failed(&self) -> &[usize] {
        &self.failed
    }

    fn key(&self, i: usize, source: &str) -> (u32, bool, usize) {
        let p = &self.parsers[i];
        (p.rank, p.source != source, i)
    }

    pub fn first_match(&self, line: &str, source: &str) -> Hit {
        if self.parsers.is_empty() {
            return Hit::None;
        }
        let set = match &self.set {
            Some(s) if safe_line(line) => s,
            _ => return Hit::Undecided,
        };
        let best = set.matches(line).iter().map(|k| self.ids[k]).min_by_key(|&i| self.key(i, source));
        // a parser only Python can run might rank above the winner
        if let Some(&f) = self.failed.iter().min_by_key(|&&i| self.key(i, source)) {
            if best.map_or(true, |b| self.key(f, source) < self.key(b, source)) {
                return Hit::Undecided;
            }
        }
        let Some(i) = best else { return Hit::None };
        let re = self.parsers[i].re.as_ref().expect("compiled");
        match re.captures(line) {
            Some(c) => {
                let groups: Vec<Option<String>> = (1..c.len()).map(|g| c.get(g).map(|m| m.as_str().to_owned())).collect();
                let fields = self.parsers[i].extract.as_ref().map(|x| x.run(&groups, line));
                Hit::Parser(i, groups, fields)
            }
            None => Hit::Undecided,     // unreachable: the set matched this pattern
        }
    }
}

/// `compiler._build_extractor` for one parser, when every default is a safe string.
pub struct Extract {
    pub names: Vec<String>,
    pub kv_format: bool,
    pub kv_names: Vec<(String, String)>,
    pub defaults: Vec<(String, String)>,
}

fn is_key(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-'
}

fn is_sep(b: u8) -> bool {
    b == b' ' || b == b'\t' || b == b',' || b == b';' || b == b'|'
}

/// The lookahead of `_KV_ANY` at `p`: `\t | [\s,;|]+[\w.\-]+= | [\s,;|]*$` (safe lines).
fn kv_stop(s: &[u8], p: usize) -> bool {
    if s.get(p) == Some(&b'\t') {
        return true;
    }
    let mut q = p;
    while q < s.len() && is_sep(s[q]) {
        q += 1;
    }
    if q == s.len() {
        return true;
    }
    if q == p {
        return false;
    }
    let k = q;
    while q < s.len() && is_key(s[q]) {
        q += 1;
    }
    q > k && s.get(q) == Some(&b'=')
}

/// `_KV_ANY.findall(line)` on a safe line: [(key, value with its quotes)].
pub fn kv_any(line: &str) -> Vec<(&str, &str)> {
    let s = line.as_bytes();
    let mut out = Vec::new();
    let mut p = 0;
    while p < s.len() {
        // the key is the whole [\w.\-] run from p, and must be followed by '='
        let mut q = p;
        while q < s.len() && is_key(s[q]) {
            q += 1;
        }
        if q == p || s.get(q) != Some(&b'=') {
            p += 1;
            continue;
        }
        let v = q + 1;
        let mut end = None;
        if s.get(v) == Some(&b'"') {
            let mut r = v + 1;
            while r < s.len() && s[r] != b'"' {
                r += if s[r] == b'\\' && r + 1 < s.len() { 2 } else if s[r] == b'\\' { s.len() } else { 1 };
            }
            if r < s.len() && s[r] == b'"' && kv_stop(s, r + 1) {
                end = Some(r + 1);
            }
        }
        let e = end.unwrap_or_else(|| (v..=s.len()).find(|&e| kv_stop(s, e)).unwrap_or(s.len()));
        out.push((&line[p..q], &line[v..e]));
        p = e;
    }
    out
}

fn py_strip(s: &str) -> &str {
    s.trim_matches(|c| c == ' ' || c == '\t')
}

impl Extract {
    /// The parser's fields, in Python dict order.
    pub fn run(&self, groups: &[Option<String>], line: &str) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self.defaults.clone();
        fn set(out: &mut Vec<(String, String)>, k: &str, v: String, overwrite: bool) {
            match out.iter_mut().find(|(x, _)| x == k) {
                Some(slot) => {
                    if overwrite {
                        slot.1 = v
                    }
                }
                None => out.push((k.to_owned(), v)),
            }
        }
        for (name, g) in self.names.iter().zip(groups) {
            if let Some(v) = g {
                let mut v = py_strip(v);
                if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
                    v = &v[1..v.len() - 1];
                }
                set(&mut out, name, v.to_owned(), true);
            }
        }
        if self.kv_format {
            for (k, v) in kv_any(line) {
                let name = self.kv_names.iter().find(|(o, _)| o == k).map_or(k, |(_, n)| n.as_str());
                set(&mut out, name, v.trim_matches('"').to_owned(), false);
            }
        }
        // nested metadata blocks, e.g. "ps_id:26156;env:prod"
        let snapshot: Vec<String> = out.iter().map(|(_, v)| v.clone()).collect();   // list(result.items())
        for v in snapshot {
            if !(v.contains(';') && (v.contains(':') || v.contains('='))) {
                continue;
            }
            for part in v.split(';') {
                let part = py_strip(part);
                let sep = if part.contains(':') { ':' } else if part.contains('=') { '=' } else { continue };
                let (sk, sv) = part.split_once(sep).unwrap();
                if !py_strip(sk).is_empty() {
                    set(&mut out, &format!("metadata.{}", py_strip(sk)), py_strip(sv).to_owned(), true);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(p: &[&str], ranks: &[u32], srcs: &[&str]) -> Set {
        Set::build(p.iter().map(|s| Some(s.to_string())).collect(), ranks.to_vec(),
                   srcs.iter().map(|s| s.to_string()).collect(), Vec::new())
    }

    #[test]
    fn priority_and_captures() {
        let s = set(&[r"^\s*a\s+(?P<g0>\S+)\s*$", r"^\s*a\s+(?P<g0>\d+)\s*$"], &[1, 0], &["", ""]);
        match s.first_match("a 12", "") {
            Hit::Parser(i, g, _) => assert_eq!((i, g), (1, vec![Some("12".into())])),
            _ => panic!(),
        }
        match s.first_match("a x", "") {
            Hit::Parser(i, _, _) => assert_eq!(i, 0),
            _ => panic!(),
        }
        assert!(matches!(s.first_match("b", ""), Hit::None));
        assert!(matches!(s.first_match("a \u{e9}", ""), Hit::Undecided));
        assert!(matches!(s.first_match("a 1\n", ""), Hit::Undecided));
    }

    #[test]
    fn source_breaks_ties_and_failed_parsers_defer() {
        let s = set(&[r"^x(?P<g0>.*)$", r"^x(?P<g0>.*)$"], &[0, 0], &["10.0.0.1", "10.0.0.2"]);
        assert!(matches!(s.first_match("xy", "10.0.0.2"), Hit::Parser(1, _, _)));
        assert!(matches!(s.first_match("xy", "other"), Hit::Parser(0, _, _)));
        let s = Set::build(vec![None, Some(r"^x$".into())], vec![0, 1], vec!["".into(), "".into()], Vec::new());
        assert!(matches!(s.first_match("x", ""), Hit::Undecided));
        let s = Set::build(vec![Some(r"^x$".into()), None], vec![0, 1], vec!["".into(), "".into()], Vec::new());
        assert!(matches!(s.first_match("x", ""), Hit::Parser(0, _, _)));
        assert!(matches!(s.first_match("y", ""), Hit::Undecided));
    }
}
