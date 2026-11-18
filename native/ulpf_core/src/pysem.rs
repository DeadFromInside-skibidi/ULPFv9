//! Python value semantics the analytics stages need on native events: `==`
//! across int/float/bool, `float(str)`, exact int/float comparison and strict
//! IPv4 parsing (`ipaddress.IPv4Address`).
//!
//! Functions return `Err(Undecided)` where Python's answer depends on behaviour
//! not reproduced here (non-ASCII text); the caller then asks Python.

use crate::norm::is_py_ws;
use crate::val::{Map, Val};
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Undecided;
pub type U<T> = Result<T, Undecided>;

/// Exact comparison of an integer with a float (Python compares them without rounding).
pub fn cmp_int_float(i: i128, f: f64) -> Option<Ordering> {
    if f.is_nan() {
        return None;
    }
    const LIM: f64 = 1.7014118346046923e38; // 2**127
    if f >= LIM {
        return Some(Ordering::Less);
    }
    if f < -LIM {
        return Some(Ordering::Greater);
    }
    let t = f.trunc();
    let ti = t as i128;
    match i.cmp(&ti) {
        Ordering::Equal => {
            let frac = f - t;
            Some(if frac > 0.0 {
                Ordering::Less
            } else if frac < 0.0 {
                Ordering::Greater
            } else {
                Ordering::Equal
            })
        }
        o => Some(o),
    }
}

fn num(v: &Val) -> Option<Result<i128, f64>> {
    match v {
        Val::Bool(b) => Some(Ok(*b as i128)),
        Val::Int(i) => Some(Ok(*i as i128)),
        Val::Float(f) => Some(Err(*f)),
        _ => None,
    }
}

/// Python `a == b` for JSON-like values.
pub fn py_eq(a: &Val, b: &Val) -> bool {
    if let (Some(x), Some(y)) = (num(a), num(b)) {
        return match (x, y) {
            (Ok(i), Ok(j)) => i == j,
            (Err(f), Err(g)) => f == g,
            (Ok(i), Err(f)) | (Err(f), Ok(i)) => cmp_int_float(i, f) == Some(Ordering::Equal),
        };
    }
    match (a, b) {
        (Val::Null, Val::Null) => true,
        (Val::Str(x), Val::Str(y)) => x == y,
        (Val::List(x), Val::List(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| py_eq(p, q)),
        (Val::Map(x), Val::Map(y)) => map_eq(x, y),
        _ => false,
    }
}

fn map_eq(x: &Map, y: &Map) -> bool {
    x.len() == y.len() && x.0.iter().all(|(k, v)| y.get(k).map(|w| py_eq(v, w)).unwrap_or(false))
}

/// Python `float(s)` for ASCII text: Ok(None) when it raises ValueError.
pub fn py_float(s: &str) -> U<Option<f64>> {
    if !s.is_ascii() {
        return Err(Undecided); // float() accepts Unicode digits and spaces
    }
    let b = s.as_bytes();
    let (mut i, mut j) = (0, b.len());
    while i < j && is_py_ws(b[i]) {
        i += 1;
    }
    while j > i && is_py_ws(b[j - 1]) {
        j -= 1;
    }
    let t = &s[i..j];
    let body = t.strip_prefix(['+', '-']).unwrap_or(t);
    let low = body.to_ascii_lowercase();
    if matches!(low.as_str(), "inf" | "infinity" | "nan") {
        return Ok(t.parse::<f64>().ok());
    }
    // [digits][.digits][e[sign]digits], underscores only between two digits
    let bb = body.as_bytes();
    let mut p = 0;
    let digits = |p: &mut usize| -> Option<usize> {
        let start = *p;
        let mut n = 0;
        while *p < bb.len() {
            let c = bb[*p];
            if c.is_ascii_digit() {
                n += 1;
                *p += 1;
            } else if c == b'_' && *p > start && bb[*p - 1].is_ascii_digit()
                && *p + 1 < bb.len() && bb[*p + 1].is_ascii_digit() {
                *p += 1;
            } else {
                break;
            }
        }
        Some(n)
    };
    let int_digits = digits(&mut p).unwrap();
    let mut frac_digits = 0;
    if p < bb.len() && bb[p] == b'.' {
        p += 1;
        frac_digits = digits(&mut p).unwrap();
    }
    if int_digits + frac_digits == 0 {
        return Ok(None);
    }
    if p < bb.len() && (bb[p] == b'e' || bb[p] == b'E') {
        p += 1;
        if p < bb.len() && (bb[p] == b'+' || bb[p] == b'-') {
            p += 1;
        }
        if digits(&mut p).unwrap() == 0 {
            return Ok(None);
        }
    }
    if p != bb.len() {
        return Ok(None);
    }
    let clean: String = t.chars().filter(|c| *c != '_').collect();
    Ok(clean.parse::<f64>().ok())
}

/// `ipaddress.IPv4Address(s)` as an integer (None: not a valid IPv4 address).
pub fn parse_ipv4(s: &str) -> Option<u32> {
    let mut out: u32 = 0;
    let mut n = 0;
    for oct in s.split('.') {
        n += 1;
        if n > 4 || oct.is_empty() || oct.len() > 3 || !oct.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if oct != "0" && oct.starts_with('0') {
            return None;
        }
        let v: u32 = oct.parse().ok()?;
        if v > 255 {
            return None;
        }
        out = (out << 8) | v;
    }
    if n == 4 {
        Some(out)
    } else {
        None
    }
}

/// An `ipaddress.ip_network(...)` as Python prints it (`10.0.0.0/8`, `fc00::/7`).
#[derive(Clone, Debug)]
pub enum Net {
    V4 { addr: u32, mask: u32 },
    /// Membership of IPv6 addresses is decided by Python (version-dependent parsing).
    V6,
}

impl Net {
    pub fn parse(s: &str) -> Option<Net> {
        let (a, len) = s.split_once('/')?;
        let len: u32 = len.parse().ok()?;
        if a.contains(':') {
            return Some(Net::V6);
        }
        let addr = parse_ipv4(a)?;
        if len > 32 {
            return None;
        }
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        Some(Net::V4 { addr: addr & mask, mask })
    }

    /// `ipaddress.ip_address(s.split("%")[0]) in net`
    pub fn contains(&self, s: &str) -> U<bool> {
        let s = s.split('%').next().unwrap_or("");
        if s.contains(':') || !s.is_ascii() {
            return Err(Undecided); // IPv6 text: Python's parser decides
        }
        Ok(match (self, parse_ipv4(s)) {
            (Net::V4 { addr, mask }, Some(ip)) => ip & mask == *addr,
            _ => false, // invalid address, or an IPv4 address against an IPv6 network
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_like_python() {
        for (s, want) in [("1", Some(1.0)), (" 2.5 ", Some(2.5)), ("1_000", Some(1000.0)), ("1__0", None),
                          ("_1", None), ("1_", None), (".5", Some(0.5)), ("5.", Some(5.0)), ("5.e3", Some(5000.0)),
                          ("e3", None), ("1e", None), ("-inf", Some(f64::NEG_INFINITY)), ("abc", None), ("", None),
                          ("1e1_0", Some(1e10)), ("0x10", None), ("1.5e-3", Some(0.0015)), ("+.5e+1", Some(5.0))] {
            assert_eq!(py_float(s).unwrap(), want, "{s}");
        }
        assert!(py_float("nan").unwrap().unwrap().is_nan());
    }

    #[test]
    fn ipv4_strict() {
        assert_eq!(parse_ipv4("10.0.0.1"), Some(0x0a000001));
        for bad in ["010.0.0.1", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.4/32", "", "1..2.3", " 1.2.3.4"] {
            assert_eq!(parse_ipv4(bad), None, "{bad}");
        }
        let n = Net::parse("10.0.0.0/8").unwrap();
        assert_eq!(n.contains("10.9.8.7"), Ok(true));
        assert_eq!(n.contains("11.0.0.1"), Ok(false));
        assert_eq!(n.contains("10.0.0.1%eth0"), Ok(true));
        assert_eq!(n.contains("fe80::1"), Err(Undecided));
    }

    #[test]
    fn int_float_compare() {
        assert_eq!(cmp_int_float(3, 3.0), Some(Ordering::Equal));
        assert_eq!(cmp_int_float(3, 3.5), Some(Ordering::Less));
        assert_eq!(cmp_int_float(-3, -3.5), Some(Ordering::Greater));
        assert_eq!(cmp_int_float(9007199254740993, 9007199254740992.0), Some(Ordering::Greater));
        assert!(py_eq(&Val::Int(1), &Val::Bool(true)));
        assert!(py_eq(&Val::Float(2.0), &Val::Int(2)));
        assert!(!py_eq(&Val::Str("1".into()), &Val::Int(1)));
    }
}
