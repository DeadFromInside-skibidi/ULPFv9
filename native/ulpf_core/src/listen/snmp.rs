//! SNMP trap receiver: `ulpf.runtime.inputs.snmp.parse_message` on a Tokio UDP
//! socket (same records, same rejections). v1 / v2c with community checks
//! (InformRequests acknowledged); v3 USM with HMAC-MD5-96, HMAC-SHA-96 and the
//! HMAC-SHA-2 family of RFC 7860, AES-128-CFB privacy (RFC 3826) and AES-192 /
//! AES-256 with the key extension of draft-blumenthal-aes-usm-04. Keys are
//! derived from the passwords once (RFC 3414 A.2) and localised per engine ID.

use super::json::{dumps, Obj};
use super::{addr, peer_text, udp_sockets, Out, Shared};
use hmac::{Hmac, Mac};
use serde_json::Value as J;
use sha2::Digest;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub type R<T> = Result<T, String>;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Auth {
    None,
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Auth {
    pub fn from(s: &str) -> R<Auth> {
        Ok(match s {
            "none" => Auth::None,
            "md5" => Auth::Md5,
            "sha" => Auth::Sha1,
            "sha224" => Auth::Sha224,
            "sha256" => Auth::Sha256,
            "sha384" => Auth::Sha384,
            "sha512" => Auth::Sha512,
            o => return Err(format!("snmp: unknown auth protocol {o}")),
        })
    }

    fn mac_len(self) -> usize {
        match self {
            Auth::Md5 | Auth::Sha1 => 12,
            Auth::Sha224 => 16,
            Auth::Sha256 => 24,
            Auth::Sha384 => 32,
            Auth::Sha512 => 48,
            Auth::None => 0,
        }
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Auth::Md5 => md5::Md5::digest(data).to_vec(),
            Auth::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Auth::Sha224 => sha2::Sha224::digest(data).to_vec(),
            Auth::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Auth::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Auth::Sha512 => sha2::Sha512::digest(data).to_vec(),
            Auth::None => vec![],
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        macro_rules! h {
            ($t:ty) => {{
                let mut m = <Hmac<$t>>::new_from_slice(key).unwrap();
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }};
        }
        match self {
            Auth::Md5 => h!(md5::Md5),
            Auth::Sha1 => h!(sha1::Sha1),
            Auth::Sha224 => h!(sha2::Sha224),
            Auth::Sha256 => h!(sha2::Sha256),
            Auth::Sha384 => h!(sha2::Sha384),
            Auth::Sha512 => h!(sha2::Sha512),
            Auth::None => vec![],
        }
    }

    /// RFC 3414 A.2: hash 1 MiB of the repeated password.
    pub fn password_to_key(self, pw: &[u8]) -> Vec<u8> {
        if pw.is_empty() {
            return self.hash(&[]);
        }
        let mut data = Vec::with_capacity(1 << 20);
        while data.len() < 1 << 20 {
            data.extend_from_slice(pw);
        }
        data.truncate(1 << 20);
        self.hash(&data)
    }

    pub fn localize(self, key: &[u8], engine: &[u8]) -> Vec<u8> {
        let mut d = key.to_vec();
        d.extend_from_slice(engine);
        d.extend_from_slice(key);
        self.hash(&d)
    }

    /// draft-blumenthal-aes-usm-04: extend with the hash of the key so far.
    pub fn extend(self, mut key: Vec<u8>, size: usize) -> Vec<u8> {
        while key.len() < size {
            let h = self.hash(&key);
            key.extend_from_slice(&h);
        }
        key.truncate(size);
        key
    }
}

pub struct User {
    pub auth: Auth,
    pub auth_key: Option<Vec<u8>>,
    pub priv_size: Option<usize>,  // AES key bytes; None: no privacy
    pub priv_key: Option<Vec<u8>>,
}

pub fn priv_size(p: &str) -> R<Option<usize>> {
    Ok(match p {
        "none" => None,
        "aes" | "aes128" => Some(16),
        "aes192" => Some(24),
        "aes256" => Some(32),
        o => return Err(format!("snmp: unknown privacy protocol {o}")),
    })
}

// ---------------------------------------------------------------------------
// BER (Python slicing semantics: short values are truncated, not errors)
// ---------------------------------------------------------------------------

fn idx(b: &[u8], i: usize) -> R<u8> {
    b.get(i).copied().ok_or_else(|| "index out of range".to_string())
}

fn sl(b: &[u8], a: usize, e: usize) -> &[u8] {
    let a = a.min(b.len());
    &b[a..e.clamp(a, b.len())]
}

/// (tag, value, next index)
pub fn ber_read(b: &[u8], i: usize) -> R<(u8, &[u8], usize)> {
    let tag = idx(b, i)?;
    let mut ln = idx(b, i + 1)? as usize;
    let mut j = i + 2;
    if ln & 0x80 != 0 {
        let n = ln & 0x7f;
        ln = sl(b, j, j + n).iter().fold(0usize, |a, c| a.saturating_mul(256).saturating_add(*c as usize));
        j += n;
    }
    Ok((tag, sl(b, j, j.saturating_add(ln)), j.saturating_add(ln)))
}

pub fn ber_items(b: &[u8]) -> R<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let (t, v, n) = ber_read(b, i)?;
        out.push((t, v));
        i = n;
    }
    Ok(out)
}

fn ber_int(v: &[u8]) -> R<i128> {
    if v.is_empty() {
        return Ok(0);
    }
    if v.len() > 16 {
        return Err("integer too large".into());
    }
    let mut x: i128 = if v[0] & 0x80 != 0 { -1 } else { 0 };
    for c in v {
        x = (x << 8) | *c as i128;
    }
    Ok(x)
}

fn ber_uint(v: &[u8]) -> R<u128> {
    if v.len() > 16 && v[..v.len() - 16].iter().any(|c| *c != 0) {
        return Err("integer too large".into());
    }
    Ok(v.iter().fold(0u128, |a, c| (a << 8) | *c as u128))
}

fn ber_oid(v: &[u8]) -> R<String> {
    if v.is_empty() {
        return Ok(String::new());
    }
    let mut parts = vec![(v[0] / 40) as u128, (v[0] % 40) as u128];
    let mut n: u128 = 0;
    for c in &v[1..] {
        n = n.checked_mul(128).ok_or("OID component too large")? | (c & 0x7f) as u128;
        if c & 0x80 == 0 {
            parts.push(n);
            n = 0;
        }
    }
    Ok(parts.iter().map(|p| p.to_string()).collect::<Vec<_>>().join("."))
}

/// `str.isprintable()`: no Other (Cc, Cf, Cs, Co, Cn) and no Separator except the space.
fn isprintable(s: &str) -> bool {
    use unicode_general_category::{get_general_category as gc, GeneralCategory as G};
    s.chars().all(|c| c == ' ' || !matches!(gc(c), G::Control | G::Format | G::Surrogate | G::PrivateUse
                                            | G::Unassigned | G::LineSeparator | G::ParagraphSeparator
                                            | G::SpaceSeparator))
}

fn int_json(x: i128) -> R<J> {
    if let Ok(i) = i64::try_from(x) {
        Ok(J::from(i))
    } else if let Ok(u) = u64::try_from(x) {
        Ok(J::from(u))
    } else {
        Err("Integer exceeds 64-bit range".into())
    }
}

fn ber_value(tag: u8, v: &[u8]) -> R<J> {
    Ok(match tag {
        0x02 => int_json(ber_int(v)?)?,
        0x04 => match std::str::from_utf8(v) {
            Ok(s) if isprintable(s) => J::from(s),
            _ => J::from(hex::encode(v)),
        },
        0x06 => J::from(ber_oid(v)?),
        0x40 if v.len() == 4 => J::from(Ipv4Addr::new(v[0], v[1], v[2], v[3]).to_string()),
        0x41 | 0x42 | 0x43 | 0x46 | 0x47 => {
            let u = ber_uint(v)?;
            J::from(u64::try_from(u).map_err(|_| "Integer exceeds 64-bit range".to_string())?)
        }
        0x05 | 0x80 | 0x81 | 0x82 => J::Null,
        _ => J::from(hex::encode(v)),
    })
}

fn enc_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let b: Vec<u8> = n.to_be_bytes().iter().skip_while(|x| **x == 0).copied().collect();
    let mut out = vec![0x80 | b.len() as u8];
    out.extend(b);
    out
}

fn tlv(tag: u8, v: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(enc_len(v.len()));
    out.extend_from_slice(v);
    out
}

fn enc_small_int(n: u8) -> Vec<u8> {
    tlv(0x02, &[n])
}

const TRAP_NAMES: [(&str, &str, &str); 6] = [
    ("1.3.6.1.6.3.1.1.5.1", "coldStart", "system"), ("1.3.6.1.6.3.1.1.5.2", "warmStart", "system"),
    ("1.3.6.1.6.3.1.1.5.3", "linkDown", "network"), ("1.3.6.1.6.3.1.1.5.4", "linkUp", "network"),
    ("1.3.6.1.6.3.1.1.5.5", "authenticationFailure", "authentication"),
    ("1.3.6.1.6.3.1.1.5.6", "egpNeighborLoss", "network"),
];
const SNMP_TRAP_OID: &str = "1.3.6.1.6.3.1.1.4.1.0";
const SYS_UPTIME: &str = "1.3.6.1.2.1.1.3.0";

fn get<'a>(items: &'a [(u8, &'a [u8])], i: usize) -> R<&'a (u8, &'a [u8])> {
    items.get(i).ok_or_else(|| "list index out of range".to_string())
}

/// `str(ip)` -> bytes.decode("utf-8", "replace")
fn decode_replace(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn pdu(tag: u8, body: &[u8]) -> R<Obj> {
    let items = ber_items(body)?;
    let mut rec = Obj::default();
    let (binds, mut trap_oid, mut uptime);
    if tag == 0xA4 {
        let enterprise = ber_oid(get(&items, 0)?.1)?;
        let (t1, v1) = *get(&items, 1)?;
        let agent = ber_value(t1, v1)?;
        let generic = ber_int(get(&items, 2)?.1)?;
        let specific = ber_int(get(&items, 3)?.1)?;
        let (t4, v4) = *get(&items, 4)?;
        uptime = ber_value(t4, v4)?;
        trap_oid = if generic < 6 {
            // Python indexing: negative counts from the end
            let i = if generic < 0 { 6 + generic } else { generic };
            if i < 0 {
                return Err("list index out of range".into());
            }
            J::from(TRAP_NAMES[i as usize].0)
        } else {
            J::from(format!("{enterprise}.0.{specific}"))
        };
        binds = get(&items, 5)?.1;
        rec.set("agent_address", agent);
        rec.set("enterprise", enterprise);
        rec.set("generic_trap", int_json(generic)?);
        rec.set("specific_trap", int_json(specific)?);
        rec.set("uptime", uptime.clone());
    } else if tag == 0xA7 || tag == 0xA6 || tag == 0xA8 {
        rec.set("request_id", int_json(ber_int(get(&items, 0)?.1)?)?);
        binds = get(&items, 3)?.1;
        trap_oid = J::Null;
        uptime = J::Null;
    } else {
        return Err(format!("not a trap PDU (tag 0x{tag:02x})"));
    }
    let mut varbinds = Obj::default();
    for (_t, vb) in ber_items(binds)? {
        let inner = ber_items(vb)?;
        if inner.len() < 2 {
            return Err("not enough values to unpack".into());
        }
        let oid = ber_oid(inner[0].1)?;
        let val = ber_value(inner[1].0, inner[1].1)?;
        if oid == SNMP_TRAP_OID {
            trap_oid = val;
        } else if oid == SYS_UPTIME {
            uptime = val;
        } else {
            varbinds.set(&oid, val);
        }
    }
    let (name, category) = match trap_oid.as_str().and_then(|t| TRAP_NAMES.iter().find(|(o, _, _)| *o == t)) {
        Some((_, n, c)) => (J::from(*n), J::from(*c)),
        None => (J::Null, J::Null),
    };
    rec.set("trap_oid", trap_oid);
    rec.set("trap_name", name);
    rec.set("category", category);
    rec.set("uptime", uptime);
    rec.set("varbinds", varbinds.into_value());
    rec.set("pdu", if tag == 0xA6 { "inform" } else { "trap" });
    Ok(rec)
}

pub struct Receiver {
    pub communities: Vec<String>,
    pub users: HashMap<String, User>,
    localized: HashMap<(Vec<u8>, String, bool), Vec<u8>>,   // (engine id, user, priv?) -> key
}

/// Rejections that count as authentication failures (`SnmpTrapInput.auth_failures`).
pub fn is_auth_failure(e: &str) -> bool {
    e.contains("authentication") || e.contains("community") || e.contains("user")
}

impl Receiver {
    pub fn new(communities: Vec<String>, users: HashMap<String, User>) -> Self {
        Receiver { communities, users, localized: HashMap::new() }
    }

    /// One message: (record, response datagram).
    pub fn parse(&mut self, data: &[u8]) -> R<(Obj, Option<Vec<u8>>)> {
        let (tag, msg, _) = ber_read(data, 0)?;
        if tag != 0x30 {
            return Err("not an SNMP message".into());
        }
        let items = ber_items(msg)?;
        let version = ber_int(get(&items, 0)?.1)?;
        if version == 0 || version == 1 {
            let community = decode_replace(get(&items, 1)?.1);
            if !self.communities.is_empty() && !self.communities.contains(&community) {
                return Err(format!("unknown community '{community}'"));
            }
            let (ptag, pbody) = *get(&items, 2)?;
            let mut rec = pdu(ptag, pbody)?;
            rec.set("version", if version == 1 { "v2c" } else { "v1" });
            rec.set("community", community);
            let mut resp = None;
            if ptag == 0xA6 {
                let pi = ber_items(pbody)?;
                if pi.len() < 4 {
                    return Err("not enough values to unpack".into());
                }
                let mut body = tlv(0x02, pi[0].1);
                body.extend(enc_small_int(0));
                body.extend(enc_small_int(0));
                body.extend(tlv(0x30, pi[3].1));
                let mut m = enc_small_int(version as u8);
                m.extend(tlv(0x04, get(&items, 1)?.1));
                m.extend(tlv(0xA2, &body));
                resp = Some(tlv(0x30, &m));
            }
            return Ok((rec, resp));
        }
        if version == 3 {
            return Ok((self.v3(data, &items)?, None));
        }
        Err(format!("unsupported SNMP version {version}"))
    }

    fn key(&mut self, engine: &[u8], name: &str, privacy: bool) -> Vec<u8> {
        let k = (engine.to_vec(), name.to_string(), privacy);
        if let Some(v) = self.localized.get(&k) {
            return v.clone();
        }
        let u = &self.users[name];
        let v = if privacy {
            u.auth.extend(u.auth.localize(u.priv_key.as_ref().unwrap(), engine), u.priv_size.unwrap())
        } else {
            u.auth.localize(u.auth_key.as_ref().unwrap(), engine)
        };
        if self.localized.len() > 10_000 {
            self.localized.clear();
        }
        self.localized.insert(k, v.clone());
        v
    }

    fn v3(&mut self, data: &[u8], items: &[(u8, &[u8])]) -> R<Obj> {
        let gd = ber_items(get(items, 1)?.1)?;
        let fl = get(&gd, 2)?.1;
        let flags = fl.first().copied().unwrap_or(0);
        let sp = ber_items(ber_read(get(items, 2)?.1, 0)?.1)?;
        let engine = get(&sp, 0)?.1;
        let boots = ber_int(get(&sp, 1)?.1)?;
        let etime = ber_int(get(&sp, 2)?.1)?;
        let user_name = decode_replace(get(&sp, 3)?.1);
        let auth_params = get(&sp, 4)?.1;
        let priv_params = get(&sp, 5)?.1;
        let Some(user) = self.users.get(&user_name) else {
            return Err(format!("unknown SNMPv3 user '{user_name}'"));
        };
        let (auth, has_priv) = (user.auth, user.priv_size.is_some());
        if flags & 1 != 0 {
            if auth == Auth::None {
                return Err(format!("user '{user_name}' sent an authenticated message but has no auth key"));
            }
            let key = self.key(engine, &user_name, false);
            // data.find(auth_params): the first occurrence (an empty value is found at 0)
            let pos = if auth_params.is_empty() { 0 } else {
                memchr::memmem::find(data, auth_params).ok_or("authentication parameters not found")?
            };
            let mut zeroed = data.to_vec();
            for b in &mut zeroed[pos..pos + auth_params.len()] {
                *b = 0;
            }
            let mac = auth.hmac(&key, &zeroed);
            let mac = &mac[..auth.mac_len().min(mac.len())];
            if mac.len() != auth_params.len() || !constant_time_eq(mac, auth_params) {
                return Err(format!("authentication failed for user '{user_name}'"));
            }
        } else if auth != Auth::None {
            return Err(format!("user '{user_name}' requires authentication"));
        }
        let (_st, mut scoped) = *get(items, 3)?;
        let plain;
        if flags & 2 != 0 {
            if !has_priv {
                return Err(format!("user '{user_name}' has no privacy key"));
            }
            if !(0..=u32::MAX as i128).contains(&boots) || !(0..=u32::MAX as i128).contains(&etime) {
                return Err("int too big to convert".into());
            }
            if priv_params.len() != 8 {
                return Err("Invalid IV size".into());
            }
            let key = self.key(engine, &user_name, true);
            let mut iv = Vec::with_capacity(16);
            iv.extend_from_slice(&(boots as u32).to_be_bytes());
            iv.extend_from_slice(&(etime as u32).to_be_bytes());
            iv.extend_from_slice(priv_params);
            plain = aes_cfb_decrypt(&key, &iv, scoped)?;
            let (_t, s, _) = ber_read(&plain, 0)?;
            scoped = s;
        }
        let si = ber_items(scoped)?;
        let (ptag, pbody) = *get(&si, 2)?;
        let mut rec = pdu(ptag, pbody)?;
        rec.set("version", "v3");
        rec.set("user", user_name);
        rec.set("engine_id", hex::encode(engine));
        rec.set("context", decode_replace(get(&si, 1)?.1));
        rec.set("authenticated", flags & 1 != 0);
        rec.set("encrypted", flags & 2 != 0);
        Ok(rec)
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn aes_cfb_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> R<Vec<u8>> {
    use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
    let mut buf = data.to_vec();
    match key.len() {
        16 => cfb_mode::Decryptor::<aes::Aes128>::new_from_slices(key, iv).map_err(|e| e.to_string())?.decrypt(&mut buf),
        24 => cfb_mode::Decryptor::<aes::Aes192>::new_from_slices(key, iv).map_err(|e| e.to_string())?.decrypt(&mut buf),
        32 => cfb_mode::Decryptor::<aes::Aes256>::new_from_slices(key, iv).map_err(|e| e.to_string())?.decrypt(&mut buf),
        _ => return Err("Invalid key size".into()),
    }
    Ok(buf)
}

/// The receiver a listener config describes (`communities`, `v3_users` with passwords).
pub fn receiver(cfg: &J) -> R<Receiver> {
    let communities = cfg.get("communities").and_then(|v| v.as_array()).into_iter().flatten()
        .filter_map(|x| x.as_str().map(String::from)).collect();
    let mut users = HashMap::new();
    for u in cfg.get("v3_users").and_then(|v| v.as_array()).into_iter().flatten() {
        let name = u.get("name").and_then(|v| v.as_str()).ok_or("snmp: v3 user name is required")?;
        let auth = Auth::from(u.get("auth_protocol").and_then(|v| v.as_str()).unwrap_or("sha"))?;
        let ps = priv_size(u.get("priv_protocol").and_then(|v| v.as_str()).unwrap_or("none"))?;
        let pw = |k: &str| u.get(k).and_then(|v| v.as_str()).map(|s| s.as_bytes().to_vec());
        let auth_key = if auth != Auth::None {
            Some(auth.password_to_key(&pw("auth_password").ok_or("snmp: auth password missing")?))
        } else {
            None
        };
        let priv_key = match ps {
            Some(_) => Some(auth.password_to_key(&pw("priv_password").ok_or("snmp: privacy password missing")?)),
            None => None,
        };
        users.insert(name.to_string(), User { auth, auth_key, priv_size: ps, priv_key });
    }
    Ok(Receiver::new(communities, users))
}

pub fn start(cfg: &J, sh: Arc<Shared>) -> R<u16> {
    let a = addr(cfg)?;
    let rx = receiver(cfg)?;
    let socks = udp_sockets(a, 1, false, 4 << 20)?;
    let port = socks[0].local_addr().map_err(|e| e.to_string())?.port();
    let s = tokio::net::UdpSocket::from_std(socks.into_iter().next().unwrap()).map_err(|e| e.to_string())?;
    tokio::spawn(run(s, sh, rx));
    Ok(port)
}

/// The journal record of a parsed trap (`rec["agent"]`, `setdefault("agent_address")`).
pub fn record(mut rec: Obj, agent: &str) -> Vec<u8> {
    rec.set("agent", agent);
    if !rec.0.contains_key("agent_address") {
        rec.set("agent_address", agent);
    }
    dumps(&rec.into_value())
}

async fn run(s: tokio::net::UdpSocket, sh: Arc<Shared>, mut rx: Receiver) {
    let mut buf = vec![0u8; 65536];
    let mut stop = sh.stop.clone();
    loop {
        tokio::select! {
            r = s.recv_from(&mut buf) => {
                let (n, peer) = match r {
                    Ok(x) => x,
                    Err(e) => { sh.stats.error(format!("udp: {e}")); continue }
                };
                if !sh.filter.allowed(peer.ip()) {
                    sh.stats.dropped_denied.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let agent = peer_text(&peer);
                match rx.parse(&buf[..n]) {
                    Ok((rec, resp)) => {
                        sh.try_send(Out { input: None, source: agent.clone(), records: vec![record(rec, &agent)],
                                          ts: super::now() });
                        if let Some(r) = resp {
                            let _ = s.send_to(&r, peer).await;
                        }
                    }
                    Err(e) => {
                        if is_auth_failure(&e) {
                            sh.stats.auth_failures.fetch_add(1, Ordering::Relaxed);
                        }
                        sh.stats.error(format!("{agent}: {e}"));
                    }
                }
            }
            _ = stop.changed() => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3414_key_vectors() {
        let k = Auth::Md5.password_to_key(b"maplesyrup");
        assert_eq!(hex::encode(&k), "9faf3283884e92834ebc9847d8edd963");
        assert_eq!(hex::encode(Auth::Md5.localize(&k, &hex::decode("000000000000000000000002").unwrap())),
                   "526f5eed9fcce26f8964c2930787d82b");
        let k = Auth::Sha1.password_to_key(b"maplesyrup");
        assert_eq!(hex::encode(&k), "9fb5cc0381497b3793528939ff788d5d79145211");
        assert_eq!(hex::encode(Auth::Sha1.localize(&k, &hex::decode("000000000000000000000002").unwrap())),
                   "6695febc9288e36282235fc7151f128497b38f3f");
    }
}
