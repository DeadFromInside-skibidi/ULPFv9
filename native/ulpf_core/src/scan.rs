//! Hand-written matchers for the hot regular expressions of the built-in
//! parsers (`ulpf/parsers/syslog_parser.py`, `cef_parser.py`). Each one gives
//! exactly the spans Python's `re` gives for its pattern on the text the core
//! handles (printable ASCII and tab, where `\s` is space or tab, `\w` is
//! `[A-Za-z0-9_]`); the pattern is quoted above every function, together with
//! why backtracking cannot change the result. Separator searches use `memchr`,
//! which picks SSE2 / AVX2 (x86-64) or NEON (aarch64) at run time.
//!
//! `tests/test_native_scan.py` compares every matcher with Python's `re` on
//! generated text (`ulpf_core._scan_probe`).

use memchr::memchr;

pub type Span = (usize, usize);

#[inline]
fn ws(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

#[inline]
fn word(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

#[inline]
fn digits(b: &[u8], mut i: usize, max: usize) -> usize {
    let start = i;
    while i < b.len() && i - start < max && b[i].is_ascii_digit() {
        i += 1;
    }
    i
}

#[inline]
fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && ws(b[i]) {
        i += 1;
    }
    i
}

#[inline]
fn skip_nonws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && !ws(b[i]) {
        i += 1;
    }
    i
}

/// `<(\d{1,3})>` at 0; returns (pri span, position after '>').
fn pri(b: &[u8]) -> Option<(Span, usize)> {
    if b.first() != Some(&b'<') {
        return None;
    }
    let e = digits(b, 1, 3);
    // \d{1,3} then '>': a fourth digit cannot be '>', and fewer digits leave a digit before '>'
    if e == 1 || e >= b.len() || b[e] != b'>' {
        return None;
    }
    Some(((1, e), e + 1))
}

/// `\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}` at `i`; returns the end.
fn bsd_ts(b: &[u8], i: usize) -> Option<usize> {
    if i + 3 > b.len() || !b[i..i + 3].iter().all(|c| word(*c)) {
        return None;
    }
    let mut p = i + 3;
    let q = skip_ws(b, p);
    if q == p {
        return None;
    }
    p = q;
    let d = digits(b, p, 2);
    if d == p {
        return None;
    }
    let q = skip_ws(b, d);
    if q == d {
        return None; // \d{1,2}\s+: with two digits backtracking to one leaves a digit, not \s
    }
    p = q;
    for k in 0..3 {
        if p + 2 > b.len() || !b[p].is_ascii_digit() || !b[p + 1].is_ascii_digit() {
            return None;
        }
        p += 2;
        if k < 2 {
            if p >= b.len() || b[p] != b':' {
                return None;
            }
            p += 1;
        }
    }
    Some(p)
}

/// RFC 3164 / plain tail: `\s+(\S+)\s+(?:(\S+?)(?:\[(\d+)\])?:\s*)?(.*)` at `i`
/// (DOTALL). Groups: host, app, pid, msg.
fn bsd_tail(b: &[u8], i: usize) -> Option<[Option<Span>; 4]> {
    let p = skip_ws(b, i);
    if p == i {
        return None;
    }
    let host_end = skip_nonws(b, p);
    if host_end == p {
        return None;
    }
    let t0 = skip_ws(b, host_end);
    if t0 == host_end {
        return None; // \S+ is greedy and \s+ must follow it
    }
    // (\S+?) is lazy: try tag lengths 1, 2, ... (the tag can only grow over \S); at each
    // end p the greedy optional "[digits]" is tried before the bare ":"
    let mut tag = None;
    let mut q = t0 + 1; // the tag is b[t0..q], all \S
    loop {
        if q < b.len() && b[q] == b'[' {
            let d = digits(b, q + 1, usize::MAX);
            if d > q + 1 && d + 1 < b.len() && b[d] == b']' && b[d + 1] == b':' {
                tag = Some(((t0, q), Some((q + 1, d)), d + 2));
                break;
            }
        }
        if q < b.len() && b[q] == b':' {
            tag = Some(((t0, q), None, q + 1));
            break;
        }
        if q >= b.len() || ws(b[q]) {
            break; // \S+? cannot grow: the optional group is skipped
        }
        q += 1;
    }
    let host = Some((p, host_end));
    Some(match tag {
        Some((app, pid, after)) => [host, Some(app), pid, Some((skip_ws(b, after), b.len()))],
        None => [host, None, None, Some((t0, b.len()))],
    })
}

/// `^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(?:(\S+?)(?:\[(\d+)\])?:\s*)?(.*)`
/// Groups 1-6: pri, timestamp, host, app, pid, msg.
pub fn rfc3164(line: &str) -> Option<[Option<Span>; 6]> {
    let b = line.as_bytes();
    let (p, after) = pri(b)?;
    let te = bsd_ts(b, after)?;
    let t = bsd_tail(b, te)?;
    Some([Some(p), Some((after, te)), t[0], t[1], t[2], t[3]])
}

/// `^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(?:(\S+?)(?:\[(\d+)\])?:\s*)?(.*)`
/// Groups 1-5: timestamp, host, app, pid, msg.
pub fn plain(line: &str) -> Option<[Option<Span>; 5]> {
    let b = line.as_bytes();
    let te = bsd_ts(b, 0)?;
    let t = bsd_tail(b, te)?;
    Some([Some((0, te)), t[0], t[1], t[2], t[3]])
}

/// `^<(\d{1,3})>(\d{1,2})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(-|(?:\[(?:[^\]\\]|\\.)*\])+)?\s*(.*)`
/// (DOTALL). Groups 1-9: pri, version, timestamp, host, app, procid, msgid, sd, msg.
/// Every \S+ is greedy and followed by \s (or by optional parts), so no
/// backtracking applies; the SD element scan is deterministic too ('\' takes
/// the next character, ']' closes), and a block that does not close ends the
/// group after the last complete block.
pub fn rfc5424(line: &str) -> Option<[Option<Span>; 9]> {
    let b = line.as_bytes();
    let (p, mut i) = pri(b)?;
    let ve = digits(b, i, 2);
    if ve == i {
        return None;
    }
    let ver = (i, ve);
    let mut q = skip_ws(b, ve);
    if q == ve {
        return None;
    }
    let mut toks = [(0usize, 0usize); 5];
    for (k, tok) in toks.iter_mut().enumerate() {
        i = q;
        let e = skip_nonws(b, i);
        if e == i {
            return None;
        }
        *tok = (i, e);
        q = skip_ws(b, e);
        if k < 4 && q == e {
            return None;
        }
    }
    // after the 7th token: \s* (q is already past it)
    let mut sd = None;
    let mut pos = q;
    if pos < b.len() && b[pos] == b'-' {
        sd = Some((pos, pos + 1));
        pos += 1;
    } else {
        let start = pos;
        let mut end = None;
        let mut j = pos;
        while j < b.len() && b[j] == b'[' {
            let mut k = j + 1;
            let mut closed = None;
            while k < b.len() {
                match b[k] {
                    b']' => {
                        closed = Some(k + 1);
                        break;
                    }
                    b'\\' => {
                        if k + 1 >= b.len() {
                            break;
                        }
                        k += 2;
                    }
                    _ => k += 1,
                }
            }
            match closed {
                Some(c) => {
                    end = Some(c);
                    j = c;
                }
                None => break,
            }
        }
        if let Some(e) = end {
            sd = Some((start, e));
            pos = e;
        }
    }
    let m = skip_ws(b, pos);
    Some([Some(p), Some(ver), Some(toks[0]), Some(toks[1]), Some(toks[2]), Some(toks[3]), Some(toks[4]), sd,
          Some((m, b.len()))])
}

/// `findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")`: a digit run that starts at a word
/// boundary, three dots with 1-3 digits between them, and a last run of 1-3 digits followed
/// by a non-word character or the end (backtracking a run shorter leaves a digit, which is
/// neither '.' nor a boundary).
pub fn ipv4_findall(text: &str, out: &mut Vec<Span>) {
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() && (i == 0 || !word(b[i - 1])) {
            if let Some(e) = dotted4(b, i, |b, e| e >= b.len() || !word(b[e])) {
                out.push((i, e));
                i = e;
                continue;
            }
        }
        i += 1;
    }
}

/// `\d{1,3}(?:\.\d{1,3}){3}` at `i`, then `tail(b, end)` must hold.
#[inline]
fn dotted4(b: &[u8], i: usize, tail: impl Fn(&[u8], usize) -> bool) -> Option<usize> {
    let mut p = i;
    for k in 0..4 {
        let e = digits(b, p, 3);
        if e == p {
            return None;
        }
        if k < 3 {
            if e >= b.len() || b[e] != b'.' {
                return None;
            }
            p = e + 1;
        } else {
            return if tail(b, e) { Some(e) } else { None };
        }
    }
    None
}

/// `findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\((\d+)\)")` -> [(address, port)]
pub fn cisco_pairs(text: &str, out: &mut Vec<(Span, Span)>) {
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() && (i == 0 || !word(b[i - 1])) {
            if let Some(e) = dotted4(b, i, |b, e| e < b.len() && b[e] == b'(') {
                let d = digits(b, e + 1, usize::MAX);
                if d > e + 1 && d < b.len() && b[d] == b')' {
                    out.push(((i, e), (e + 1, d)));
                    i = d + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
}

/// `findall(r"(?:port|pt)\s*[=:]\s*(\d+)", re.I)` -> digit spans
pub fn port_findall(text: &str, out: &mut Vec<Span>) {
    let b = text.as_bytes();
    let lower = |c: u8| c.to_ascii_lowercase();
    let mut i = 0;
    'scan: while i < b.len() {
        if lower(b[i]) == b'p' {
            // "port" and "pt" differ in their second letter: at most one can match here
            for kw in [&b"port"[..], &b"pt"[..]] {
                if i + kw.len() <= b.len() && b[i..i + kw.len()].iter().zip(kw).all(|(c, k)| lower(*c) == *k) {
                    let p = skip_ws(b, i + kw.len());
                    if p < b.len() && (b[p] == b'=' || b[p] == b':') {
                        let q = skip_ws(b, p + 1);
                        let d = digits(b, q, usize::MAX);
                        if d > q {
                            out.push((q, d));
                            i = d;
                            continue 'scan;
                        }
                    }
                }
            }
        }
        i += 1;
    }
}

/// `search(r"\bfor (?:invalid user )?(\S+) from ([0-9A-Fa-f.:]+) port (\d+)")`
/// -> (user, address, port). The optional group is tried first; if the rest fails
/// with it, the line is tried without it.
pub fn ssh(msg: &str) -> Option<(Span, Span, Span)> {
    let b = msg.as_bytes();
    let mut from = 0;
    while let Some(off) = memchr::memmem::find(&b[from..], b"for ") {
        let i = from + off;
        from = i + 1;
        if i > 0 && word(b[i - 1]) {
            continue;
        }
        let after = i + 4;
        let rest = |s: usize| -> Option<(Span, Span, Span)> {
            let ue = skip_nonws(b, s);
            if ue == s || !b[ue..].starts_with(b" from ") {
                return None;
            }
            let a = ue + 6;
            let mut ae = a;
            while ae < b.len() && (b[ae].is_ascii_hexdigit() || b[ae] == b'.' || b[ae] == b':') {
                ae += 1;
            }
            if ae == a || !b[ae..].starts_with(b" port ") {
                return None;
            }
            let ps = ae + 6;
            let pe = digits(b, ps, usize::MAX);
            if pe == ps {
                return None;
            }
            Some(((s, ue), (a, ae), (ps, pe)))
        };
        if b[after..].starts_with(b"invalid user ") {
            if let Some(r) = rest(after + 13) {
                return Some(r);
            }
        }
        if let Some(r) = rest(after) {
            return Some(r);
        }
    }
    None
}

/// `search(r"%[A-Z0-9_]+-([0-7])-[A-Z0-9_]+")` -> the severity digit
pub fn cisco_mnemonic(text: &str) -> Option<u8> {
    let b = text.as_bytes();
    let cls = |c: u8| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_';
    let mut from = 0;
    while let Some(off) = memchr(b'%', &b[from..]) {
        let i = from + off;
        from = i + 1;
        let mut p = i + 1;
        while p < b.len() && cls(b[p]) {
            p += 1;
        }
        if p == i + 1 || p + 3 > b.len() || b[p] != b'-' || !(b'0'..=b'7').contains(&b[p + 1]) || b[p + 2] != b'-' {
            continue;
        }
        if p + 3 < b.len() && cls(b[p + 3]) {
            return Some(b[p + 1] - b'0');
        }
    }
    None
}

/// `finditer(r'([\w.-]+)=(?:"((?:[^"\\]|\\.)*)"|(\S+))')` -> (key, quoted, unquoted).
/// A key run that does not end in '=' fails at every start inside it, so the scan
/// resumes after the run; an unterminated quote falls back to the \S+ alternative.
pub fn sd_params(sd: &str, out: &mut Vec<(Span, Option<Span>, Option<Span>)>) {
    let b = sd.as_bytes();
    let cls = |c: u8| word(c) || c == b'.' || c == b'-';
    let mut i = 0;
    while i < b.len() {
        if !cls(b[i]) {
            i += 1;
            continue;
        }
        let mut e = i;
        while e < b.len() && cls(b[e]) {
            e += 1;
        }
        if e >= b.len() || b[e] != b'=' {
            i = e;
            continue;
        }
        let v = e + 1;
        if v < b.len() && b[v] == b'"' {
            let mut k = v + 1;
            let mut close = None;
            while k < b.len() {
                match b[k] {
                    b'"' => {
                        close = Some(k);
                        break;
                    }
                    b'\\' if k + 1 < b.len() => k += 2,
                    b'\\' => break,
                    _ => k += 1,
                }
            }
            if let Some(c) = close {
                out.push(((i, e), Some((v + 1, c)), None));
                i = c + 1;
                continue;
            }
        }
        let ve = skip_nonws(b, v);
        if ve > v {
            out.push(((i, e), None, Some((v, ve))));
            i = ve;
        } else {
            i = e; // every start inside the key run fails the same way
        }
    }
}

/// `finditer(r"(?:^|\s+)([A-Za-z0-9_.\[\]-]+)=")` -> (match start, match end, key span)
pub fn ext_split(ext: &str, out: &mut Vec<(usize, usize, Span)>) {
    let b = ext.as_bytes();
    let cls = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'[' | b']' | b'-');
    let key_at = |k: usize| -> Option<usize> {
        let mut e = k;
        while e < b.len() && cls(b[e]) {
            e += 1;
        }
        if e > k && e < b.len() && b[e] == b'=' {
            Some(e)
        } else {
            None
        }
    };
    let mut i = 0;
    while i < b.len() {
        if i == 0 {
            if let Some(e) = key_at(0) {
                out.push((0, e + 1, (0, e)));
                i = e + 1;
                continue;
            }
        }
        if ws(b[i]) {
            let k = skip_ws(b, i);
            if let Some(e) = key_at(k) {
                out.push((i, e + 1, (k, e)));
                i = e + 1;
                continue;
            }
            // every start inside this whitespace run reaches the same key and fails
            i = k;
            continue;
        }
        // the next match can only start at whitespace
        match b[i..].iter().position(|c| ws(*c)) {
            Some(off) => i += off,
            None => break,
        }
    }
}
