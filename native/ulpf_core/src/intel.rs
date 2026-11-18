//! Threat-intelligence matching (`ulpf.intelligence.tip`): millions of indicators against each event.
//!
//! Exact indicators (IP addresses, domains, URLs, MD5 / SHA-1 / SHA-256, e-mail addresses) are keyed by
//! a 64-bit (randomly keyed) SipHash of (kind, normalised value); a Cuckoo filter (16-bit fingerprints, 4-slot buckets)
//! answers the common case — not an indicator — from two buckets, and an exact hash map confirms the
//! rest. CIDR blocks: one lookup per distinct prefix length. Wildcard domains (`*.evil.com`): one lookup
//! per parent label. Mutexes and registry keys: Aho-Corasick over the lower-cased text.
//!
//! An event's candidates, in order: source IP, destination IP, then the tokens of its raw text (URLs and
//! their hosts, e-mail addresses and their domains, hashes, IPv4 addresses, domains), then mutex /
//! registry hits. The first candidate that is an indicator wins. The Python fallback
//! (`ulpf/intelligence/tip/matcher.py`) applies the same rules; `tests/test_tip.py` compares them.
//!
//! Snapshot (written by Python): `ULPFIOC1 | u32 n | n x (u32 len, utf-8) | u32 m |
//! m x (u8 kind, u8 flags, u32 value, f64 confidence, u32 category, u32 actor, u32 campaign, u32 kill_chain,
//! u32 id, u32 source)` (little endian; u32 fields index the string table). Flag 1: match the event's
//! source / destination IP only, never IPs in its text (the legacy `config/iocs.json` feed).

use rustc_hash::FxHashMap as HashMap;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};

pub const KINDS: [&str; 12] = ["", "ip", "cidr", "domain", "domain_wildcard", "url", "md5", "sha1", "sha256",
                               "email", "mutex", "registry"];
const IP: u8 = 1;
const CIDR: u8 = 2;
const DOMAIN: u8 = 3;
const WILD: u8 = 4;
const URL: u8 = 5;
const MD5: u8 = 6;
const SHA1: u8 = 7;
const SHA256: u8 = 8;
const EMAIL: u8 = 9;
const MUTEX: u8 = 10;
const REGISTRY: u8 = 11;
const MAX_TEXT: usize = 64 * 1024;

pub struct Entry {
    pub kind: u8,
    pub fields_only: bool,
    pub conf: f64,
    pub cat: u32,
    pub actor: u32,
    pub campaign: u32,
    pub kill: u32,
    pub id: u32,
    pub source: u32,
    pub value: u32,
}

// ------------------------------------------------------------------------------------------ hashing

/// Seeds drawn once per process (from the OS-seeded `RandomState`): feed values and event text
/// cannot be crafted offline to collide. Every hit is verified against the stored value, so a
/// collision can never produce a false match; snapshots store values, never hashes.
fn seeds() -> &'static [u64; 4] {
    static SEED: std::sync::OnceLock<[u64; 4]> = std::sync::OnceLock::new();
    SEED.get_or_init(|| {
        let rs = std::hash::RandomState::new();
        let mut out = [0u64; 4];
        for (i, s) in out.iter_mut().enumerate() {
            let mut h = rs.build_hasher();
            (i as u64 ^ 0x9e37_79b9_7f4a_7c15).hash(&mut h);
            *s = h.finish() | 1;
        }
        out
    })
}

#[inline(always)]
fn fold(a: u64, b: u64) -> u64 {
    let r = (a as u128).wrapping_mul(b as u128);
    (r as u64) ^ ((r >> 64) as u64)
}

#[inline(always)]
fn rd64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

/// Keyed folded-multiply hash of (kind, value): a few ns for a domain, ~10x cheaper than SipHash.
#[inline]
fn key(kind: u8, v: &[u8]) -> u64 {
    let s = seeds();
    let mut h = s[0] ^ ((kind as u64) << 56) ^ (v.len() as u64);
    let mut c = v;
    while c.len() >= 16 {
        h = fold(rd64(c) ^ s[1], rd64(&c[8..]) ^ h);
        c = &c[16..];
    }
    let (a, b) = if c.len() >= 8 {
        (rd64(c), rd64(&c[c.len() - 8..]))
    } else if c.len() >= 4 {
        let lo = u32::from_le_bytes(c[..4].try_into().unwrap()) as u64;
        let hi = u32::from_le_bytes(c[c.len() - 4..].try_into().unwrap()) as u64;
        (lo, hi)
    } else if !c.is_empty() {
        ((c[0] as u64) << 16 | (c[c.len() / 2] as u64) << 8 | c[c.len() - 1] as u64, 0)
    } else {
        (0, 0)
    };
    h = fold(a ^ s[2], b ^ h);
    fold(h ^ s[3], s[1] ^ (v.len() as u64))
}

fn ip_bytes(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => v4.octets().to_vec(),
            None => a.octets().to_vec(),
        },
    }
}

// ------------------------------------------------------------------------------------------ cuckoo filter

pub struct Cuckoo {
    buckets: Vec<[u16; 4]>,
    n: usize,
    pub len: usize,
}

fn fp(h: u64) -> u16 {
    let f = (h >> 48) as u16;
    if f == 0 { 1 } else { f }
}

/// Bucket of a hash: multiply-shift range reduction, so the table is sized exactly (no power of
/// two): 2M indicators fit ~4 MB instead of 8, which stays in a typical L3 cache.
#[inline]
fn range(x: u64, n: usize) -> usize {
    (((x & 0xffff_ffff) * n as u64) >> 32) as usize
}

/// The other bucket of fingerprint f: (H(f) - i) mod n, an involution (alt(alt(i)) == i).
#[inline]
fn alt(i: usize, f: u16, n: usize) -> usize {
    let h = range((f as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 32, n);
    let x = h + n - i;
    if x >= n { x - n } else { x }
}

impl Cuckoo {
    pub fn with_capacity(k: usize) -> Cuckoo {
        let n = ((k as f64 / 4.0 / 0.95).ceil() as usize).max(16);
        Cuckoo { buckets: vec![[0u16; 4]; n], n, len: 0 }
    }

    pub fn insert(&mut self, h: u64) -> bool {
        let f = fp(h);
        let i1 = range(h, self.n);
        let i2 = alt(i1, f, self.n);
        for i in [i1, i2] {
            if let Some(s) = self.buckets[i].iter_mut().find(|s| **s == 0) {
                *s = f;
                self.len += 1;
                return true;
            }
        }
        let (mut i, mut f) = (i1, f);
        for k in 0..2000 {
            let slot = (k * 7 + i) % 4;
            std::mem::swap(&mut f, &mut self.buckets[i][slot]);
            i = alt(i, f, self.n);
            if let Some(s) = self.buckets[i].iter_mut().find(|s| **s == 0) {
                *s = f;
                self.len += 1;
                return true;
            }
        }
        false                                   // full (one fingerprint is now lost): rebuild larger
    }

    #[inline]
    pub fn contains(&self, h: u64) -> bool {
        let f = fp(h);
        let i1 = range(h, self.n);
        self.buckets[i1].contains(&f) || self.buckets[alt(i1, f, self.n)].contains(&f)
    }

    pub fn bytes(&self) -> usize {
        self.buckets.len() * 8
    }
}

// ------------------------------------------------------------------------------------------ normalisation

/// scheme://host[:port]/path?query (lower-case scheme and host, default ports and fragment removed).
pub fn norm_url(s: &str) -> Option<String> {
    let s = s.trim();
    let (scheme, rest) = s.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "ftp" | "hxxp" | "hxxps") {
        return None;
    }
    let scheme = scheme.replace("hxxp", "http");
    let rest = rest.split('#').next().unwrap_or("");
    let cut = rest.find(['/', '?']).unwrap_or(rest.len());
    let (auth, path) = rest.split_at(cut);
    let host_port = auth.rsplit('@').next().unwrap_or("").to_ascii_lowercase();
    let mut host = host_port.as_str();
    if let Some((h, p)) = host_port.rsplit_once(':') {
        if !h.ends_with(']') || host_port.starts_with('[') {
            if (scheme == "http" && p == "80") || (scheme == "https" && p == "443") || (scheme == "ftp" && p == "21") {
                host = h;
            }
        }
    }
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return None;
    }
    let path = if path.is_empty() { "/" } else { path };
    Some(format!("{scheme}://{host}{path}"))
}

/// `norm_url` of an ASCII token into `buf` without allocating, in one pass: Some((length, host
/// start, host end)) where buf[host start..host end] is the lower-case host[:port]; None when the
/// token is not a URL or the result would not fit (the caller then uses `norm_url`).
fn url_into(tok: &[u8], buf: &mut [u8]) -> Option<(usize, usize, usize)> {
    let mut sep = None;
    for i in 0..tok.len().saturating_sub(2) {
        if tok[i] == b':' && tok[i + 1] == b'/' && tok[i + 2] == b'/' {
            sep = Some(i);
            break;
        }
    }
    let sep = sep?;
    let (scheme, rest) = (&tok[..sep], &tok[sep + 3..]);
    let scheme: &[u8] = if scheme.eq_ignore_ascii_case(b"http") || scheme.eq_ignore_ascii_case(b"hxxp") {
        b"http"
    } else if scheme.eq_ignore_ascii_case(b"https") || scheme.eq_ignore_ascii_case(b"hxxps") {
        b"https"
    } else if scheme.eq_ignore_ascii_case(b"ftp") {
        b"ftp"
    } else {
        return None;
    };
    // rest up to '#'; host part up to the first '/' or '?'
    let mut cut = rest.len();
    let mut end = rest.len();
    for (i, &c) in rest.iter().enumerate() {
        if c == b'#' {
            cut = cut.min(i);
            end = i;
            break;
        }
        if (c == b'/' || c == b'?') && cut == rest.len() {
            cut = i;
        }
    }
    let (auth, path) = (&rest[..cut], &rest[cut..end]);
    let mut at = 0;
    let mut colon = None;
    for (i, &c) in auth.iter().enumerate() {
        if c == b'@' {
            at = i + 1;
            colon = None;
        } else if c == b':' {
            colon = Some(i);
        }
    }
    let hp = &auth[at..];
    let mut host = hp;
    if let Some(ci) = colon {
        let ci = ci - at;
        let (h, p) = (&hp[..ci], &hp[ci + 1..]);
        if !h.ends_with(b"]") || hp.starts_with(b"[") {
            if (scheme == b"http" && p == b"80") || (scheme == b"https" && p == b"443") || (scheme == b"ftp" && p == b"21") {
                host = h;
            }
        }
    }
    let mut hn = host.len();
    while hn > 0 && host[hn - 1] == b'.' {
        hn -= 1;
    }
    let host = &host[..hn];
    if host.is_empty() {
        return None;
    }
    let path: &[u8] = if path.is_empty() { b"/" } else { path };
    let n = scheme.len() + 3 + host.len() + path.len();
    if n > buf.len() {
        return None;
    }
    let o = scheme.len() + 3;
    buf[..scheme.len()].copy_from_slice(scheme);
    buf[scheme.len()..o].copy_from_slice(b"://");
    buf[o..o + host.len()].copy_from_slice(host);
    buf[o..o + host.len()].make_ascii_lowercase();
    buf[o + host.len()..n].copy_from_slice(path);
    Some((n, o, o + host.len()))
}

/// `url_host` of a normalised URL given its host[:port] part.
fn host_of(hp: &[u8]) -> &[u8] {
    if hp.first() == Some(&b'[') {
        let mut s = 0;
        while s < hp.len() && hp[s] == b'[' {
            s += 1;
        }
        let rest = &hp[s..];
        return &rest[..rest.iter().position(|&c| c == b']').unwrap_or(rest.len())];
    }
    match hp.iter().rposition(|&c| c == b':') {
        Some(i) => &hp[..i],
        None => hp,
    }
}

pub fn url_host(u: &str) -> Option<&str> {
    let rest = u.split_once("://")?.1;
    let cut = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let auth = &rest[..cut];
    let hp = auth.rsplit('@').next()?;
    if hp.starts_with('[') {
        return Some(hp.trim_start_matches('[').split(']').next().unwrap_or(""));
    }
    Some(hp.rsplit_once(':').map(|(h, _)| h).unwrap_or(hp))
}

fn hive_variants(k: &str) -> Vec<String> {
    let k = k.trim().to_ascii_lowercase().replace('/', "\\");
    let pairs = [("hkey_local_machine\\", "hklm\\"), ("hkey_current_user\\", "hkcu\\"), ("hkey_classes_root\\", "hkcr\\"),
                 ("hkey_users\\", "hku\\"), ("hkey_current_config\\", "hkcc\\"), ("\\registry\\machine\\", "hklm\\"),
                 ("\\registry\\user\\", "hku\\")];
    let mut out = vec![k.clone()];
    for (long, short) in pairs {
        if let Some(rest) = k.strip_prefix(long) {
            out.push(format!("{short}{rest}"));
        } else if let Some(rest) = k.strip_prefix(short) {
            out.push(format!("{long}{rest}"));
        }
    }
    let escaped: Vec<String> = out.iter().map(|v| json_escaped(v)).collect();
    out.extend(escaped);
    out.sort();
    out.dedup();
    out
}

/// A pattern as it appears inside a JSON string (backslashes doubled): JSON-encoded raw events.
fn json_escaped(v: &str) -> String {
    v.replace('\\', "\\\\")
}

// ------------------------------------------------------------------------------------------ text tokens
//
// Zero-allocation scan: byte-class tables, candidates lower-cased into stack buffers, the first
// indicator ends the scan. Only URL tokens (normalised into a String) and the hit's value allocate.

const fn byte_table(extra: &[u8], alnum: bool) -> [bool; 256] {
    let mut t = [false; 256];
    let mut i = 0;
    while i < 256 {
        let c = i as u8;
        t[i] = alnum && c.is_ascii_alphanumeric();
        i += 1;
    }
    let mut j = 0;
    while j < extra.len() {
        t[extra[j] as usize] = true;
        j += 1;
    }
    t
}

static TOKEN: [bool; 256] = byte_table(b"._%+@:/?#=&~-[]", true);
static SPLIT: [bool; 256] = byte_table(b"/:?#=&@%+~[]", false);
static EDGE: [bool; 256] = byte_table(b".,;:)]'\"-_!?(", false);
static LABEL: [bool; 256] = byte_table(b"-_", true);

/// Token bytes (0x80) and what they say a token may be: 1 '.' or '@', 2 ':', 4 '/'.
static CLASS: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        if TOKEN[i] {
            t[i] = 0x80 | match i as u8 { b'.' | b'@' => 1, b':' => 2, b'/' => 4, _ => 0 };
        }
        i += 1;
    }
    t
};

/// The token around position `x` (a token byte): (start, end, marks).
#[inline]
fn token_at(b: &[u8], x: usize) -> (usize, usize, u8) {
    let mut s = x;
    let mut marks = 0u8;
    while s > 0 {
        let k = CLASS[b[s - 1] as usize];
        if k == 0 {
            break;
        }
        marks |= k;
        s -= 1;
    }
    let mut e = x;
    while e < b.len() {
        let k = CLASS[b[e] as usize];
        if k == 0 {
            break;
        }
        marks |= k;
        e += 1;
    }
    (s, e, marks)
}

/// `Ipv4Addr::from_str` on bytes: four decimal octets, no leading zeros, each at most 255.
fn ipv4(b: &[u8]) -> Option<Ipv4Addr> {
    if b.len() < 7 || b.len() > 15 {
        return None;
    }
    let mut oct = [0u8; 4];
    let mut k = 0;
    let mut val: u32 = 0;
    let mut digits = 0;
    let mut lead0 = false;
    for &c in b {
        if c == b'.' {
            if digits == 0 || k == 3 {
                return None;
            }
            oct[k] = val as u8;
            k += 1;
            val = 0;
            digits = 0;
            lead0 = false;
            continue;
        }
        if !c.is_ascii_digit() || digits == 3 || lead0 {
            return None;                       // a leading "0" may not be followed by digits
        }
        if digits == 0 && c == b'0' {
            lead0 = true;
        }
        val = val * 10 + (c - b'0') as u32;
        if val > 255 {
            return None;
        }
        digits += 1;
    }
    if digits == 0 || k != 3 {
        return None;
    }
    oct[3] = val as u8;
    Some(Ipv4Addr::from(oct))
}

fn trim_edges(s: &[u8]) -> &[u8] {
    let mut a = 0;
    let mut b = s.len();
    while a < b && EDGE[s[a] as usize] {
        a += 1;
    }
    while b > a && EDGE[s[b - 1] as usize] {
        b -= 1;
    }
    &s[a..b]
}

fn starts_ci(s: &[u8], p: &[u8]) -> bool {
    s.len() >= p.len() && s[..p.len()].eq_ignore_ascii_case(p)
}

/// `norm_domain` into `buf` (lower case, trailing dots dropped); None when not a domain.
fn domain_into<'a>(s: &[u8], buf: &'a mut [u8; 256]) -> Option<&'a [u8]> {
    let mut n = s.len();
    while n > 0 && s[n - 1] == b'.' {
        n -= 1;
    }
    let s = &s[..n];
    if s.is_empty() || s.len() > 253 {
        return None;
    }
    let (mut dots, mut label) = (0usize, 0usize);
    for (i, &c) in s.iter().enumerate() {
        if c == b'.' {
            if label == 0 {
                return None;
            }
            dots += 1;
            label = 0;
        } else {
            if !LABEL[c as usize] {
                return None;
            }
            label += 1;
            if label > 63 {
                return None;
            }
        }
        buf[i] = c.to_ascii_lowercase();
    }
    if dots == 0 || label == 0 {
        return None;
    }
    Some(&buf[..s.len()])
}

/// The last label is 2-24 ASCII letters (a part of free text worth treating as a domain).
fn plausible_tld(s: &[u8]) -> bool {
    let mut n = s.len();
    while n > 0 && s[n - 1] == b'.' {
        n -= 1;
    }
    let s = &s[..n];
    let start = s.iter().rposition(|&c| c == b'.').map(|i| i + 1).unwrap_or(0);
    let tld = &s[start..];
    (2..=24).contains(&tld.len()) && tld.iter().all(|c| c.is_ascii_alphabetic())
}

fn to_str(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

// ------------------------------------------------------------------------------------------ matcher

pub struct Matcher {
    pub strings: Vec<String>,
    pub entries: Vec<Entry>,
    filter: Cuckoo,
    exact: HashMap<u64, u32>,
    cidr4: Vec<(u8, HashMap<u32, u32>)>,
    cidr6: Vec<(u8, HashMap<u128, u32>)>,
    ac: Option<(aho_corasick::AhoCorasick, Vec<u32>)>,
    ac_bs: Option<usize>,
    pub counts: [usize; 12],
}

pub struct Hit {
    pub entry: u32,
    pub kind: u8,
    pub value: String,
}

fn rd_u32(b: &[u8], p: &mut usize) -> Result<u32, String> {
    let s = b.get(*p..*p + 4).ok_or("truncated snapshot")?;
    *p += 4;
    Ok(u32::from_le_bytes(s.try_into().unwrap()))
}

impl Matcher {
    pub fn from_bytes(b: &[u8]) -> Result<Matcher, String> {
        if b.len() < 16 || &b[..8] != b"ULPFIOC1" {
            return Err("not a ULPF indicator snapshot".into());
        }
        let mut p = 8;
        let n = rd_u32(b, &mut p)? as usize;
        if n > 50_000_000 {
            return Err("snapshot string table too large".into());
        }
        let mut strings = Vec::with_capacity(n);
        for _ in 0..n {
            let l = rd_u32(b, &mut p)? as usize;
            let s = b.get(p..p + l).ok_or("truncated snapshot")?;
            strings.push(String::from_utf8(s.to_vec()).map_err(|_| "snapshot: invalid UTF-8")?);
            p += l;
        }
        let m = rd_u32(b, &mut p)? as usize;
        if m > 50_000_000 {
            return Err("snapshot has too many indicators".into());
        }
        let mut entries = Vec::with_capacity(m);
        let mut values = Vec::with_capacity(m);
        for _ in 0..m {
            let kind = *b.get(p).ok_or("truncated snapshot")?;
            let flags = *b.get(p + 1).ok_or("truncated snapshot")?;
            p += 2;
            let v = rd_u32(b, &mut p)?;
            let conf = f64::from_le_bytes(b.get(p..p + 8).ok_or("truncated snapshot")?.try_into().unwrap());
            p += 8;
            let mut f = [0u32; 6];
            for x in f.iter_mut() {
                *x = rd_u32(b, &mut p)?;
            }
            if kind as usize >= KINDS.len() || kind == 0 || f.iter().chain([&v]).any(|&i| i as usize >= strings.len()) {
                return Err("snapshot: bad indicator record".into());
            }
            entries.push(Entry { kind, fields_only: flags & 1 != 0, conf, cat: f[0], actor: f[1], campaign: f[2], kill: f[3], id: f[4], source: f[5], value: v });
            values.push(v);
        }
        Matcher::build(strings, entries, values)
    }

    fn build(strings: Vec<String>, entries: Vec<Entry>, values: Vec<u32>) -> Result<Matcher, String> {
        let mut exact: HashMap<u64, u32> = HashMap::default();
        exact.reserve(entries.len());
        let mut c4: HashMap<u8, HashMap<u32, u32>> = HashMap::default();
        let mut c6: HashMap<u8, HashMap<u128, u32>> = HashMap::default();
        let mut pats: Vec<String> = Vec::new();
        let mut pat_entry: Vec<u32> = Vec::new();
        let mut counts = [0usize; 12];
        for (i, (e, &v)) in entries.iter().zip(&values).enumerate() {
            let val = strings[v as usize].as_str();
            let i = i as u32;
            counts[e.kind as usize] += 1;
            match e.kind {
                IP => {
                    if let Ok(ip) = val.parse::<IpAddr>() {
                        exact.entry(key(IP, &ip_bytes(&ip))).or_insert(i);
                    }
                }
                CIDR => {
                    let Some((net, len)) = val.split_once('/') else { continue };
                    let Ok(len) = len.parse::<u8>() else { continue };
                    match net.parse::<IpAddr>() {
                        Ok(IpAddr::V4(a)) if len <= 32 => {
                            let m = if len == 0 { 0 } else { u32::MAX << (32 - len) };
                            c4.entry(len).or_default().entry(u32::from(a) & m).or_insert(i);
                        }
                        Ok(IpAddr::V6(a)) if len <= 128 => {
                            let m = if len == 0 { 0 } else { u128::MAX << (128 - len) };
                            c6.entry(len).or_default().entry(u128::from(a) & m).or_insert(i);
                        }
                        _ => {}
                    }
                }
                MUTEX => {
                    let low = val.to_ascii_lowercase();
                    if low.contains('\\') {
                        pats.push(json_escaped(&low));
                        pat_entry.push(i);
                    }
                    pats.push(low);
                    pat_entry.push(i);
                }
                REGISTRY => {
                    for p in hive_variants(val) {
                        pats.push(p);
                        pat_entry.push(i);
                    }
                }
                k => {
                    exact.entry(key(k, val.as_bytes())).or_insert(i);
                }
            }
        }
        let mut filter = Cuckoo::with_capacity(exact.len());
        loop {
            let ok = exact.keys().all(|&h| filter.insert(h));
            if ok {
                break;
            }
            filter = Cuckoo::with_capacity(filter.buckets.len() * 4 * 11 / 10);   // +10%
        }
        let mut cidr4: Vec<_> = c4.into_iter().collect();
        cidr4.sort_by(|a, b| b.0.cmp(&a.0));          // most specific first
        let mut cidr6: Vec<_> = c6.into_iter().collect();
        cidr6.sort_by(|a, b| b.0.cmp(&a.0));
        // every pattern holds a backslash within `ac_bs` bytes of its start: no match can begin before
        // (first backslash of the text) - ac_bs, and a text without one has none
        let ac_bs = pats.iter().map(|p| p.find('\\')).collect::<Option<Vec<_>>>().and_then(|v| v.into_iter().max());
        let ac = if pats.is_empty() {
            None
        } else {
            Some((aho_corasick::AhoCorasick::builder().match_kind(aho_corasick::MatchKind::LeftmostLongest)
                .ascii_case_insensitive(true).build(&pats).map_err(|e| format!("mutex / registry patterns: {e}"))?, pat_entry))
        };
        Ok(Matcher { strings, entries, filter, exact, cidr4, cidr6, ac, ac_bs, counts })
    }

    #[inline]
    fn exact_hit(&self, kind: u8, v: &[u8]) -> Option<u32> {
        self.exact_hit_h(key(kind, v), kind, v)
    }

    /// `exact_hit` with the key already computed; the stored value is compared, so a hash
    /// collision never matches.
    #[inline]
    fn exact_hit_h(&self, h: u64, kind: u8, v: &[u8]) -> Option<u32> {
        if !self.filter.contains(h) {
            return None;
        }
        let e = *self.exact.get(&h)?;
        let ent = &self.entries[e as usize];
        let stored = self.strings[ent.value as usize].as_str();
        let same = if kind == IP {
            stored.parse::<IpAddr>().map(|a| ip_bytes(&a) == v).unwrap_or(false)
        } else {
            ent.kind == kind && stored.as_bytes() == v
        };
        if same { Some(e) } else { None }
    }

    fn ip_hit(&self, ip: &IpAddr) -> Option<(u32, u8)> {
        let v4 = match ip {
            IpAddr::V4(a) => Some(*a),
            IpAddr::V6(a) => a.to_ipv4_mapped(),
        };
        if let Some(a) = v4 {
            if let Some(e) = self.exact_hit(IP, &a.octets()) {
                return Some((e, IP));
            }
            let a = u32::from(a);
            for (len, m) in &self.cidr4 {
                let mask = if *len == 0 { 0 } else { u32::MAX << (32 - len) };
                if let Some(&e) = m.get(&(a & mask)) {
                    return Some((e, CIDR));
                }
            }
        } else if let IpAddr::V6(v6) = ip {
            if let Some(e) = self.exact_hit(IP, &v6.octets()) {
                return Some((e, IP));
            }
            let a = u128::from(*v6);
            for (len, m) in &self.cidr6 {
                let mask = if *len == 0 { 0 } else { u128::MAX << (128 - len) };
                if let Some(&e) = m.get(&(a & mask)) {
                    return Some((e, CIDR));
                }
            }
        }
        None
    }

    /// An IP from the event text (indicators restricted to the source / destination fields skip it).
    fn text_ip_hit(&self, ip: &IpAddr) -> Option<(u32, u8)> {
        self.ip_hit(ip).filter(|(e, _)| !self.entries[*e as usize].fields_only)
    }

    fn domain_hit(&self, d: &[u8]) -> Option<(u32, u8)> {
        if let Some(e) = self.exact_hit(DOMAIN, d) {
            return Some((e, DOMAIN));
        }
        let mut rest = d;
        while let Some(i) = rest.iter().position(|&c| c == b'.') {
            rest = &rest[i + 1..];
            if !rest.contains(&b'.') {
                break;                                 // never a whole TLD
            }
            if let Some(e) = self.exact_hit(WILD, rest) {
                return Some((e, WILD));
            }
        }
        None
    }

    /// The first indicator among the event's candidates.
    pub fn match_event(&self, src_ip: Option<&str>, dst_ip: Option<&str>, text: Option<&str>) -> Option<Hit> {
        for ip in [src_ip, dst_ip].into_iter().flatten() {
            if let Ok(a) = ip.trim().parse::<IpAddr>() {
                if let Some((e, k)) = self.ip_hit(&a) {
                    return Some(Hit { entry: e, kind: k, value: ip.to_string() });
                }
            }
        }
        let text = text?;
        let t = if text.len() > MAX_TEXT { &text[..text.floor_char_boundary(MAX_TEXT)] } else { text };
        if let Some(h) = self.scan_text(t.as_bytes()) {
            return Some(h);
        }
        if let Some((ac, pe)) = &self.ac {
            let start = match self.ac_bs {
                None => Some(0),
                Some(k) => memchr::memchr(b'\\', t.as_bytes()).map(|bs| t.floor_char_boundary(bs.saturating_sub(k))),
            };
            if let Some(m) = start.and_then(|st| ac.find(aho_corasick::Input::new(t).span(st..t.len()))) {
                let e = pe[m.pattern().as_usize()];
                return Some(Hit { entry: e, kind: self.entries[e as usize].kind, value: t[m.start()..m.end()].to_string() });
            }
        }
        None
    }

    /// Candidate tokens in order, found from anchors instead of classifying every byte: memchr for
    /// '.', '@', '/' (IPs, domains, e-mail, URLs), and one probe every 32 bytes for the remaining
    /// candidates, tokens of 32+ bytes (hashes), since such a token always covers a probe position.
    /// Visits exactly the tokens the byte-by-byte definition (`tokens` in matcher.py) keeps.
    fn scan_text(&self, b: &[u8]) -> Option<Hit> {
        let mut dbuf = [0u8; 256];
        let mut ubuf = [0u8; 1024];
        let n = b.len();
        let mut pos = 0;
        while pos < n {
            let anchor = memchr::memchr3(b'.', b'@', b'/', &b[pos..]).map_or(n, |x| x + pos);
            let mut found = None;
            let mut p = (pos + 31) & !31;
            while p < anchor {
                if CLASS[b[p] as usize] == 0 {
                    p += 32;
                    continue;
                }
                let t = token_at(b, p);
                if t.1 - t.0 >= 32 {
                    found = Some(t);
                    break;
                }
                p = (t.1 + 32) & !31;
            }
            let (s, e, marks) = match found {
                Some(t) => t,
                None if anchor < n => token_at(b, anchor),
                None => break,
            };
            pos = e;
            if marks & 1 == 0 && marks & 6 != 6 && e - s < 32 {
                continue;
            }
            let tok = trim_edges(&b[s..e]);
            if tok.len() < 4 {
                continue;
            }
            if let Some(h) = self.scan_token(tok, &mut dbuf, &mut ubuf) {
                return Some(h);
            }
        }
        None
    }

    fn scan_token(&self, tok: &[u8], dbuf: &mut [u8; 256], ubuf: &mut [u8; 1024]) -> Option<Hit> {
        if starts_ci(tok, b"http://") || starts_ci(tok, b"https://") || starts_ci(tok, b"hxxp")
            || starts_ci(tok, b"ftp://") {
            let owned;
            let (u, host): (&str, &[u8]) = match url_into(tok, ubuf) {
                Some((n, hs, he)) => {
                    let u = std::str::from_utf8(&ubuf[..n]).unwrap_or("");
                    (u, host_of(&u.as_bytes()[hs..he]))
                }
                None => {
                    // longer than the buffer (or not a URL): the allocating normaliser decides
                    let Some(x) = norm_url(std::str::from_utf8(tok).unwrap_or("")) else { return None };
                    owned = x;
                    let h = url_host(&owned).unwrap_or("");
                    (owned.as_str(), h.as_bytes())
                }
            };
            if let Some(e) = self.exact_hit(URL, u.as_bytes()) {
                return Some(Hit { entry: e, kind: URL, value: u.to_string() });
            }
            let ipish = host.first().is_some_and(|c| c.is_ascii_digit()) || host.contains(&b':');
            match std::str::from_utf8(host).ok().filter(|_| ipish).and_then(|h| h.parse::<IpAddr>().ok()) {
                Some(ip) => {
                    if let Some((e, k)) = self.text_ip_hit(&ip) {
                        return Some(Hit { entry: e, kind: k, value: ip.to_string() });
                    }
                }
                None => {
                    if let Some(d) = domain_into(host, dbuf) {
                        if let Some((e, k)) = self.domain_hit(d) {
                            return Some(Hit { entry: e, kind: k, value: to_str(d) });
                        }
                    }
                }
            }
            return None;
        }
        if let Some(at) = tok.iter().position(|&c| c == b'@') {
            let (local, dom) = (&tok[..at], &tok[at + 1..]);
            if !local.is_empty() && !dom.contains(&b'@') {
                if let Some(d) = domain_into(dom, dbuf) {
                    let n = local.len() + 1 + d.len();
                    let mut long = Vec::new();
                    let ebuf: &mut [u8] = if n <= ubuf.len() {
                        &mut ubuf[..n]
                    } else {
                        long.resize(n, 0);
                        &mut long
                    };
                    ebuf[..local.len()].copy_from_slice(local);
                    ebuf[..local.len()].make_ascii_lowercase();
                    ebuf[local.len()] = b'@';
                    ebuf[local.len() + 1..].copy_from_slice(d);
                    if let Some(e) = self.exact_hit(EMAIL, ebuf) {
                        return Some(Hit { entry: e, kind: EMAIL, value: to_str(ebuf) });
                    }
                    if let Some((e, k)) = self.domain_hit(d) {
                        return Some(Hit { entry: e, kind: k, value: to_str(d) });
                    }
                    return None;
                }
            }
        }
        for part in tok.split(|&c| SPLIT[c as usize]) {
            let part = trim_edges(part);
            if part.len() < 4 {
                continue;
            }
            if part[0].is_ascii_digit() {
                if let Some(a) = ipv4(part) {
                    if let Some((e, k)) = self.text_ip_hit(&IpAddr::V4(a)) {
                        return Some(Hit { entry: e, kind: k, value: to_str(part) });
                    }
                    continue;
                }
            }
            if part.iter().all(|c| c.is_ascii_hexdigit()) {
                let k = match part.len() { 32 => MD5, 40 => SHA1, 64 => SHA256, _ => 0 };
                if k != 0 {
                    let mut hbuf = [0u8; 64];
                    hbuf[..part.len()].copy_from_slice(part);
                    let h = &mut hbuf[..part.len()];
                    h.make_ascii_lowercase();
                    if let Some(e) = self.exact_hit(k, h) {
                        return Some(Hit { entry: e, kind: k, value: to_str(h) });
                    }
                }
                continue;
            }
            if plausible_tld(part) {
                if let Some(d) = domain_into(part, dbuf) {
                    if let Some((e, k)) = self.domain_hit(d) {
                        return Some(Hit { entry: e, kind: k, value: to_str(d) });
                    }
                }
            }
        }
        None
    }


    pub fn memory(&self) -> usize {
        self.filter.bytes() + self.exact.capacity() * 16 + self.entries.len() * std::mem::size_of::<Entry>()
            + self.strings.iter().map(|s| s.len() + 24).sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(rows: &[(u8, &str)]) -> Vec<u8> {
        let mut strings: Vec<String> = vec![String::new(), "malware".into()];
        let mut out = b"ULPFIOC1".to_vec();
        for (_, v) in rows {
            strings.push(v.to_string());
        }
        out.extend((strings.len() as u32).to_le_bytes());
        for s in &strings {
            out.extend((s.len() as u32).to_le_bytes());
            out.extend(s.as_bytes());
        }
        out.extend((rows.len() as u32).to_le_bytes());
        for (i, (k, _)) in rows.iter().enumerate() {
            out.push(*k);
            out.push(0);
            out.extend(((i + 2) as u32).to_le_bytes());
            out.extend(0.9f64.to_le_bytes());
            for f in [1u32, 0, 0, 0, 0, 0] {
                out.extend(f.to_le_bytes());
            }
        }
        out
    }

    #[test]
    fn kinds_match() {
        let m = Matcher::from_bytes(&snap(&[(IP, "203.0.113.9"), (CIDR, "198.51.100.0/24"), (DOMAIN, "evil.example"),
                                            (WILD, "bad.test"), (URL, "http://x.example/a?b=1"),
                                            (SHA256, &"ab".repeat(32)), (EMAIL, "spy@phish.example"),
                                            (MUTEX, "Global\\EvilMutex"), (REGISTRY, "HKLM\\Software\\Evil")])).unwrap();
        let k = |s: Option<&str>, d: Option<&str>, t: Option<&str>| m.match_event(s, d, t).map(|h| (KINDS[h.kind as usize], h.value));
        assert_eq!(k(Some("203.0.113.9"), None, None), Some(("ip", "203.0.113.9".into())));
        assert_eq!(k(None, Some("198.51.100.77"), None), Some(("cidr", "198.51.100.77".into())));
        assert_eq!(k(None, None, Some("query a.b.Bad.Test. done")), Some(("domain_wildcard", "a.b.bad.test".into())));
        assert_eq!(k(None, None, Some("GET HTTP://X.example:80/a?b=1 ok")), Some(("url", "http://x.example/a?b=1".into())));
        assert_eq!(k(None, None, Some(&format!("SHA256={}", "AB".repeat(32)))), Some(("sha256", "ab".repeat(32))));
        assert_eq!(k(None, None, Some("from: Spy@Phish.Example")), Some(("email", "spy@phish.example".into())));
        assert_eq!(k(None, None, Some("mutant global\\evilmutex created")).map(|x| x.0), Some("mutex"));
        assert_eq!(k(None, None, Some("TargetObject=HKEY_LOCAL_MACHINE\\SOFTWARE\\Evil\\Run")).map(|x| x.0), Some("registry"));
        assert_eq!(k(Some("10.0.0.1"), None, Some("all clean here example.com 1.2.3.4")), None);
        assert!(Matcher::from_bytes(b"ULPFIOC1\xff\xff\xff\xff").is_err());
    }

    #[test]
    fn ipv4_parser_agrees_with_std() {
        let cases = ["1.2.3.4", "0.0.0.0", "255.255.255.255", "256.1.1.1", "01.2.3.4", "1.2.3.04", "1.2.3", "1.2.3.4.5",
                     "1..2.3", "1.2.3.", ".1.2.3", "10.0.0.10", "100.200.250.255", "1.2.3.4a", "1234.1.1.1", "0.10.0.0",
                     "00.1.1.1", "1.2.3.400", "9.9.9.9"];
        for c in cases {
            assert_eq!(ipv4(c.as_bytes()), c.parse::<Ipv4Addr>().ok(), "{c}");
        }
        let mut x: u64 = 7;
        for _ in 0..200_000 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let s: String = (0..(x >> 60) as usize + 3).map(|i| b"0123456789.."[((x >> (i * 4)) % 12) as usize] as char).collect();
            assert_eq!(ipv4(s.as_bytes()), s.parse::<Ipv4Addr>().ok(), "{s}");
        }
    }

    #[test]
    fn cuckoo_has_no_false_negatives() {
        let mut c = Cuckoo::with_capacity(100_000);
        for i in 0..100_000u64 {
            assert!(c.insert(key(IP, &i.to_le_bytes())));
        }
        assert!((0..100_000u64).all(|i| c.contains(key(IP, &i.to_le_bytes()))));
        let fp = (100_000..200_000u64).filter(|i| c.contains(key(IP, &i.to_le_bytes()))).count();
        assert!(fp < 200, "{fp}");
    }
}
