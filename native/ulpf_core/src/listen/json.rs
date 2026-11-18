//! `orjson.dumps` for the records the listeners journal (so a record is the same
//! bytes whichever implementation decoded it): compact separators, only `"`,
//! `\` and control characters escaped, integers up to 64 bits, and orjson's float
//! form (shortest round-trip digits; scientific below 1e-5 and from 1e16, the
//! exponent unpadded with a sign: `1e-7`, `1e+16`).

use serde_json::Value as J;
use std::fmt::Write;

pub fn dumps(v: &J) -> Vec<u8> {
    let mut s = String::with_capacity(256);
    write(v, &mut s);
    s.into_bytes()
}

pub fn write(v: &J, out: &mut String) {
    match v {
        J::Null => out.push_str("null"),
        J::Bool(true) => out.push_str("true"),
        J::Bool(false) => out.push_str("false"),
        J::Number(n) => {
            if let Some(u) = n.as_u64() {
                out.push_str(itoa::Buffer::new().format(u));
            } else if let Some(i) = n.as_i64() {
                out.push_str(itoa::Buffer::new().format(i));
            } else {
                float(n.as_f64().unwrap_or(f64::NAN), out);
            }
        }
        J::String(s) => string(s, out),
        J::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(x, out);
            }
            out.push(']');
        }
        J::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                string(k, out);
                out.push(':');
                write(x, out);
            }
            out.push('}');
        }
    }
}

pub fn string(s: &str, out: &mut String) {
    out.push('"');
    let mut start = 0;
    for (i, c) in s.bytes().enumerate() {
        let esc: Option<&str> = match c {
            b'"' => Some("\\\""),
            b'\\' => Some("\\\\"),
            b'\n' => Some("\\n"),
            b'\r' => Some("\\r"),
            b'\t' => Some("\\t"),
            0x08 => Some("\\b"),
            0x0c => Some("\\f"),
            c if c < 0x20 => Some(""),
            _ => None,
        };
        if let Some(e) = esc {
            out.push_str(&s[start..i]);
            if e.is_empty() {
                let _ = write!(out, "\\u{:04x}", c);
            } else {
                out.push_str(e);
            }
            start = i + 1;
        }
    }
    out.push_str(&s[start..]);
    out.push('"');
}

/// orjson's float text.
pub fn float(f: f64, out: &mut String) {
    if !f.is_finite() {
        out.push_str("null");
        return;
    }
    if f == 0.0 {
        out.push_str(if f.is_sign_negative() { "-0.0" } else { "0.0" });
        return;
    }
    let e = format!("{:e}", f); // shortest round-trip digits
    let (mant, exp) = e.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    let neg = mant.starts_with('-');
    let digits: String = mant.chars().filter(|c| c.is_ascii_digit()).collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let n = digits.len() as i32;
    if neg {
        out.push('-');
    }
    if !(-5..16).contains(&exp) {
        out.push_str(&digits[..1]);
        if n > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let _ = write!(out, "e{}{}", if exp < 0 { '-' } else { '+' }, exp.abs());
        return;
    }
    let decpt = exp + 1;
    if decpt <= 0 {
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
}

/// A JSON object builder that keeps insertion order (`dict` semantics: re-setting a key
/// keeps its position).
#[derive(Default, Clone)]
pub struct Obj(pub serde_json::Map<String, J>);

impl Obj {
    pub fn set(&mut self, k: &str, v: impl Into<J>) {
        self.0.insert(k.to_string(), v.into());
    }

    pub fn into_value(self) -> J {
        J::Object(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_like_orjson() {
        for (f, want) in [(1e16, "1e+16"), (1.5e-5, "0.000015"), (0.1, "0.1"), (1.0, "1.0"), (1e-7, "1e-7"),
                          (1e-6, "1e-6"), (1e-5, "0.00001"), (1e15, "1000000000000000.0"), (1.5e16, "1.5e+16"),
                          (5e-324, "5e-324"), (1.7976931348623157e308, "1.7976931348623157e+308"), (-2.5, "-2.5"),
                          (1.23e-18, "1.23e-18"), (9999999999999998.0, "9999999999999998.0")] {
            let mut s = String::new();
            float(f, &mut s);
            assert_eq!(s, want, "{f}");
        }
    }
}
