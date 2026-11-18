//! Ordered, JSON-like values with the Python semantics the pipeline relies on:
//! dict insertion order, `str()`, truthiness and `repr(float)`.

use compact_str::CompactString;
use std::fmt::Write;

/// Strings of up to 24 bytes are stored inline (no heap allocation): most field
/// names and values of log events (addresses, ports, actions, short words).
pub type SmallStr = CompactString;

/// A map key: a schema key (static, never needs JSON escaping) or a vendor key.
/// Keys compare and hash by their text, whichever variant holds it.
#[derive(Clone, Debug)]
pub enum Key {
    Borrowed(&'static str),
    Owned(SmallStr),
}

impl std::ops::Deref for Key {
    type Target = str;
    #[inline]
    fn deref(&self) -> &str {
        match self {
            Key::Borrowed(s) => s,
            Key::Owned(s) => s.as_str(),
        }
    }
}

impl AsRef<str> for Key {
    #[inline]
    fn as_ref(&self) -> &str {
        self
    }
}

impl PartialEq for Key {
    #[inline]
    fn eq(&self, o: &Key) -> bool {
        **self == **o
    }
}

impl Eq for Key {}

impl PartialEq<str> for Key {
    #[inline]
    fn eq(&self, o: &str) -> bool {
        &**self == o
    }
}

impl PartialEq<&str> for Key {
    #[inline]
    fn eq(&self, o: &&str) -> bool {
        &**self == *o
    }
}

impl std::hash::Hash for Key {
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        (**self).hash(h)
    }
}

impl From<&'static str> for Key {
    #[inline]
    fn from(s: &'static str) -> Key {
        Key::Borrowed(s)
    }
}

impl From<String> for Key {
    #[inline]
    fn from(s: String) -> Key {
        Key::Owned(SmallStr::from(s))
    }
}

impl From<SmallStr> for Key {
    #[inline]
    fn from(s: SmallStr) -> Key {
        Key::Owned(s)
    }
}

impl Key {
    pub fn owned(s: &str) -> Key {
        Key::Owned(SmallStr::new(s))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(SmallStr),
    List(Vec<Val>),
    Map(Map),
}

/// Insertion-ordered map. Assigning an existing key keeps its position (Python dict).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Map(pub Vec<(Key, Val)>);

impl Map {
    pub fn new() -> Self {
        Map(Vec::new())
    }

    pub fn with(items: Vec<(Key, Val)>) -> Self {
        Map(items)
    }

    pub fn get(&self, k: &str) -> Option<&Val> {
        self.0.iter().find(|(key, _)| key == k).map(|(_, v)| v)
    }

    pub fn get_mut(&mut self, k: &str) -> Option<&mut Val> {
        self.0.iter_mut().find(|(key, _)| key == k).map(|(_, v)| v)
    }

    pub fn contains(&self, k: &str) -> bool {
        self.0.iter().any(|(key, _)| key == k)
    }

    pub fn set(&mut self, k: impl Into<Key>, v: Val) {
        let k = k.into();
        if let Some(slot) = self.0.iter_mut().find(|(key, _)| *key == k) {
            slot.1 = v;
        } else {
            self.0.push((k, v));
        }
    }

    /// `set` without allocating the key when it is already present (the common case for
    /// schema fields, which the event skeleton creates).
    pub fn set_str(&mut self, k: &str, v: Val) {
        if let Some(slot) = self.0.iter_mut().find(|(key, _)| key == k) {
            slot.1 = v;
        } else {
            self.0.push((Key::owned(k), v));
        }
    }

    /// `d.get(k)` as a string slice when the value is a str.
    pub fn get_str(&self, k: &str) -> Option<&str> {
        match self.get(k) {
            Some(Val::Str(s)) => Some(s),
            _ => None,
        }
    }

    /// Nested sub-map (`event["source"]`); the schema guarantees it exists.
    pub fn sub(&mut self, k: &str) -> &mut Map {
        match self.get_mut(k) {
            Some(Val::Map(m)) => m,
            _ => panic!("schema group {k} missing"),
        }
    }

    pub fn sub_ref(&self, k: &str) -> &Map {
        match self.get(k) {
            Some(Val::Map(m)) => m,
            _ => panic!("schema group {k} missing"),
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Val {
    pub fn s(x: &str) -> Val {
        Val::Str(SmallStr::new(x))
    }

    pub fn string(x: String) -> Val {
        Val::Str(SmallStr::from(x))
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Val::Null)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Val::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Python truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            Val::Null => false,
            Val::Bool(b) => *b,
            Val::Int(i) => *i != 0,
            Val::Float(f) => *f != 0.0,
            Val::Str(s) => !s.is_empty(),
            Val::List(l) => !l.is_empty(),
            Val::Map(m) => m.len() != 0,
        }
    }

    /// Python `str(v)`. None for containers (their repr is not reproduced: callers delegate).
    pub fn py_str(&self) -> Option<String> {
        match self {
            Val::Null => Some("None".into()),
            Val::Bool(true) => Some("True".into()),
            Val::Bool(false) => Some("False".into()),
            Val::Int(i) => Some(itoa::Buffer::new().format(*i).to_string()),
            Val::Float(f) => Some(py_float_repr(*f)),
            Val::Str(s) => Some(s.to_string()),
            Val::List(_) | Val::Map(_) => None,
        }
    }

    /// `v in (None, "")`
    pub fn is_none_or_empty(&self) -> bool {
        match self {
            Val::Null => true,
            Val::Str(s) => s.is_empty(),
            _ => false,
        }
    }
}

/// `a or b or c ...` over optional dict lookups: the first truthy operand, else the last one.
pub fn or_chain<'a>(vals: &[Option<&'a Val>]) -> Option<&'a Val> {
    let mut last = None;
    for v in vals {
        last = *v;
        if let Some(x) = v {
            if x.truthy() {
                return Some(x);
            }
        }
    }
    last
}

thread_local! {
    // events repeat few distinct floats (confidences, coordinates of the same addresses)
    static FLOAT_REPR: std::cell::RefCell<rustc_hash::FxHashMap<u64, SmallStr>> =
        std::cell::RefCell::new(rustc_hash::FxHashMap::default());
}

/// `py_float_repr` written to `out`, through a bounded per-thread cache.
pub fn push_float_repr(f: f64, out: &mut String) {
    FLOAT_REPR.with(|c| {
        let mut c = c.borrow_mut();
        if let Some(s) = c.get(&f.to_bits()) {
            out.push_str(s);
            return;
        }
        let s = py_float_repr(f);
        out.push_str(&s);
        if c.len() >= 4096 {
            c.clear();
        }
        c.insert(f.to_bits(), SmallStr::from(s));
    })
}

/// CPython `repr(float)` ("short" float_repr_style).
pub fn py_float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    // Rust's `{:e}` prints the shortest round-tripping digits, like CPython's repr
    let e = format!("{:e}", f);
    let (mant, exp) = e.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    let neg = mant.starts_with('-');
    let digits: String = mant.chars().filter(|c| c.is_ascii_digit()).collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let n = digits.len() as i32;
    let decpt = exp + 1; // position of the decimal point relative to the digits
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if decpt <= -4 || decpt > 16 {
        out.push_str(&digits[..1]);
        if n > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let x = decpt - 1;
        let _ = write!(out, "e{}{:02}", if x < 0 { '-' } else { '+' }, x.abs());
    } else if decpt <= 0 {
        out.push_str("0.");
        for _ in 0..(-decpt) {
            out.push('0');
        }
        out.push_str(digits);
    } else if decpt >= n {
        out.push_str(digits);
        for _ in 0..(decpt - n) {
            out.push('0');
        }
        out.push_str(".0");
    } else {
        out.push_str(&digits[..decpt as usize]);
        out.push('.');
        out.push_str(&digits[decpt as usize..]);
    }
    out
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

/// True if any byte of `x` is < 0x20, '"' or '\\' (SWAR: eight bytes at a time).
#[inline(always)]
fn needs_escape8(x: u64) -> bool {
    const ONES: u64 = 0x0101_0101_0101_0101;
    const HIGH: u64 = 0x8080_8080_8080_8080;
    let zero = |v: u64| v.wrapping_sub(ONES) & !v & HIGH;
    let ctrl = x.wrapping_sub(ONES * 0x20) & !x & HIGH;
    ctrl | zero(x ^ (ONES * b'"' as u64)) | zero(x ^ (ONES * b'\\' as u64)) != 0
}

/// Index of the first byte JSON must escape, or `b.len()`.
#[inline]
fn first_escape(b: &[u8]) -> usize {
    let mut i = 0;
    while i + 8 <= b.len() {
        let x = u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        if needs_escape8(x) {
            break;
        }
        i += 8;
    }
    while i < b.len() {
        let c = b[i];
        if c < 0x20 || c == b'"' || c == b'\\' {
            return i;
        }
        i += 1;
    }
    i
}

/// A schema key (a static identifier: nothing to escape) followed by ':'.
#[inline]
pub fn write_json_key(k: &Key, out: &mut String) {
    match k {
        Key::Borrowed(s) => {
            out.reserve(s.len() + 3);
            out.push('"');
            out.push_str(s);
            out.push_str("\":");
        }
        Key::Owned(s) => {
            write_json_str(s, out);
            out.push(':');
        }
    }
}

pub fn write_json_str(s: &str, out: &mut String) {
    let b = s.as_bytes();
    let first = first_escape(b);
    if first == b.len() {
        out.reserve(b.len() + 2);
        out.push('"');
        out.push_str(s);
        out.push('"');
        return;
    }
    out.push('"');
    out.push_str(&s[..first]);
    // copy runs of plain bytes; only the characters JSON requires are escaped
    let mut start = first;
    for (i, &c) in b.iter().enumerate().skip(first) {
        let esc = match c {
            b'"' => "\\\"",
            b'\\' => "\\\\",
            b'\n' => "\\n",
            b'\r' => "\\r",
            b'\t' => "\\t",
            0x08 => "\\b",
            0x0c => "\\f",
            c if c < 0x20 => "",
            _ => continue,
        };
        out.push_str(&s[start..i]);
        if esc.is_empty() {
            let _ = write!(out, "\\u{:04x}", c);
        } else {
            out.push_str(esc);
        }
        start = i + 1;
    }
    out.push_str(&s[start..]);
    out.push('"');
}

pub fn write_json(v: &Val, out: &mut String) {
    match v {
        Val::Null => out.push_str("null"),
        Val::Bool(true) => out.push_str("true"),
        Val::Bool(false) => out.push_str("false"),
        Val::Int(i) => out.push_str(itoa::Buffer::new().format(*i)),
        Val::Float(f) => {
            if f.is_finite() {
                push_float_repr(*f, out);
            } else {
                out.push_str("null");
            }
        }
        Val::Str(s) => write_json_str(s, out),
        Val::List(l) => {
            out.push('[');
            for (i, x) in l.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(x, out);
            }
            out.push(']');
        }
        Val::Map(m) => write_json_map(m, out, &[]),
    }
}

/// A map as a JSON object, leaving out ``skip`` keys (top level only).
/// JSON fragments of a static key: `"k":`, `,"k":`, `"k":null`, `,"k":null`. Rendered once per
/// key and kept (static keys are the schema's, a bounded set), so a null field of the event
/// skeleton costs one copy.
struct Frags {
    key: &'static str,
    next_key: &'static str,
    null: &'static str,
    next_null: &'static str,
}

thread_local! {
    static FRAGS: std::cell::RefCell<rustc_hash::FxHashMap<(usize, usize), &'static Frags>> =
        std::cell::RefCell::new(rustc_hash::FxHashMap::default());
}

#[inline]
fn frags(s: &'static str) -> &'static Frags {
    FRAGS.with(|m| {
        *m.borrow_mut().entry((s.as_ptr() as usize, s.len())).or_insert_with(|| {
            let leak = |x: String| -> &'static str { Box::leak(x.into_boxed_str()) };
            Box::leak(Box::new(Frags { key: leak(format!("\"{s}\":")), next_key: leak(format!(",\"{s}\":")),
                                       null: leak(format!("\"{s}\":null")), next_null: leak(format!(",\"{s}\":null")) }))
        })
    })
}

pub fn write_json_map(m: &Map, out: &mut String, skip: &[&str]) {
    out.push('{');
    let mut first = true;
    for (k, v) in &m.0 {
        if !skip.is_empty() && skip.contains(&k.as_ref()) {
            continue;
        }
        match k {
            Key::Borrowed(s) => {
                let f = frags(s);
                match v {
                    Val::Null => out.push_str(if first { f.null } else { f.next_null }),
                    _ => {
                        out.push_str(if first { f.key } else { f.next_key });
                        write_json(v, out);
                    }
                }
            }
            Key::Owned(_) => {
                if !first {
                    out.push(',');
                }
                write_json_key(k, out);
                write_json(v, out);
            }
        }
        first = false;
    }
    out.push('}');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_strings_escape_like_orjson() {
        let mut out = String::new();
        for (s, want) in [("plain text", "\"plain text\""), ("a\"b", "\"a\\\"b\""), ("x\\y", "\"x\\\\y\""),
                          ("tab\there", "\"tab\\there\""), ("12345678\n", "\"12345678\\n\""),
                          ("\u{1}", "\"\\u0001\""), ("abcdefghijklmnop\"", "\"abcdefghijklmnop\\\"\""),
                          ("~~~~~~~~\x7f", "\"~~~~~~~~\x7f\""), ("", "\"\"")] {
            out.clear();
            write_json_str(s, &mut out);
            assert_eq!(out, want, "{s:?}");
        }
        for s in ["", "a", "~", " !#$%&'()*+,-./0123456789:;<=>?@AZ[]^_`az{|}~", "é ü"] {
            let x = s.as_bytes();
            assert_eq!(first_escape(x), x.len(), "{s}");
        }
    }

    #[test]
    fn float_repr_matches_cpython() {
        for (f, s) in [(1e16, "1e+16"), (1.5e-5, "1.5e-05"), (0.0001, "0.0001"), (123456789.123, "123456789.123"),
                       (1e22, "1e+22"), (1.0, "1.0"), (1e15, "1000000000000000.0"), (0.5, "0.5"), (-2.5, "-2.5"),
                       (1760000000.5, "1760000000.5"), (1.2345678901234567e17, "1.2345678901234566e+17"),
                       (0.1 + 0.2, "0.30000000000000004")] {
            assert_eq!(py_float_repr(f), s, "{f}");
        }
    }
}
