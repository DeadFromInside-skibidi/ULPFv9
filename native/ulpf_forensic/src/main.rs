//! ulpf-forensic-verify (compiled): verifies ULPF raw journals, evidence seals and
//! Merkle inclusion proofs on an air-gapped workstation, without the SIEM server
//! or a Python interpreter. Same rules and findings as `ulpf/forensic_verify.py`.
//!
//!   ulpf-forensic-verify journal --journal DIR [--seals DIR] [--pubkey evidence.pub]
//!                                [--journal-key journal.key] [--json]
//!   ulpf-forensic-verify proof --proof proof.json --seal seal.json [--pubkey evidence.pub]
//!
//! Exit status: 0 verified, 1 problems found, 2 usage error.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

const VERSION: &str = "10.0.0";
const MAGIC: &[u8; 4] = b"ULJB";
const HDR: usize = 32;
const REC: usize = 56;
const FLAG_ENC: u8 = 1;
const ERASED_MAGIC: &[u8] = b"\x00ULPF-ERASED\x00";
const MAX_BLOCK: u32 = 1 << 30;
const MAX_LOCATE_BITS: usize = 1 << 27;
const CRC_POLY: u32 = 0xEDB8_8320;

struct Report {
    problems: Vec<Value>,
    notes: Vec<String>,
    stats: Map<String, Value>,
}

impl Report {
    fn new() -> Self {
        let mut stats = Map::new();
        for k in ["segments", "blocks", "records", "erased_records", "bytes", "seals", "signatures_checked",
                  "merkle_roots_checked"] {
            stats.insert(k.into(), json!(0u64));
        }
        Report { problems: vec![], notes: vec![], stats }
    }
    fn bump(&mut self, k: &str, n: u64) {
        let v = self.stats.get(k).and_then(|v| v.as_u64()).unwrap_or(0) + n;
        self.stats.insert(k.into(), json!(v));
    }
    fn problem(&mut self, kind: &str, msg: String, mut wher: Map<String, Value>) {
        wher.insert("kind".into(), json!(kind));
        wher.insert("message".into(), json!(msg));
        self.problems.push(Value::Object(wher));
    }
}

macro_rules! at {
    ($($k:expr => $v:expr),* $(,)?) => {{ let mut m = Map::new(); $( m.insert($k.to_string(), json!($v)); )* m }};
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn leaf(seq: u64, digest: &[u8]) -> [u8; 32] {
    sha256(&[b"ulpf-leaf", &seq.to_be_bytes(), digest])
}

fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return sha256(&[b""]);
    }
    let mut cur: Vec<[u8; 32]> = leaves.to_vec();
    while cur.len() > 1 {
        let mut nxt = Vec::with_capacity(cur.len() / 2 + 1);
        let mut i = 0;
        while i + 1 < cur.len() {
            nxt.push(sha256(&[&cur[i], &cur[i + 1]]));
            i += 2;
        }
        if cur.len() % 2 == 1 {
            nxt.push(cur[cur.len() - 1]);
        }
        cur = nxt;
    }
    cur[0]
}

// ---------------------------------------------------------------------------
// Python-compatible canonical JSON: json.dumps(sort_keys=True, separators=(",", ":"))
// ---------------------------------------------------------------------------

fn py_float(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    let s = format!("{:e}", f); // shortest round-trip digits, e.g. "-1.7317e9"
    let (neg, s) = if let Some(r) = s.strip_prefix('-') { (true, r.to_string()) } else { (false, s) };
    let (mant, exp) = s.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let n = digits.len() as i32;
    let body = if (-4..16).contains(&exp) {
        if exp >= n - 1 {
            format!("{}{}.0", digits, "0".repeat((exp - (n - 1)) as usize))
        } else if exp >= 0 {
            format!("{}.{}", &digits[..(exp + 1) as usize], &digits[(exp + 1) as usize..])
        } else {
            format!("0.{}{}", "0".repeat((-exp - 1) as usize), digits)
        }
    } else {
        let m = if n > 1 { format!("{}.{}", &digits[..1], &digits[1..]) } else { digits.clone() };
        format!("{}e{}{:02}", m, if exp < 0 { '-' } else { '+' }, exp.abs())
    };
    if neg { format!("-{}", body) } else { body }
}

fn py_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", u));
                }
            }
        }
    }
    out.push('"');
}

fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                out.push_str(&n.to_string())
            } else {
                out.push_str(&py_float(n.as_f64().unwrap_or(0.0)))
            }
        }
        Value::String(s) => py_str(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                py_str(k, out);
                out.push(':');
                canonical(&m[*k], out);
            }
            out.push('}');
        }
    }
}

fn canonical_without(v: &Value, skip: &[&str]) -> Vec<u8> {
    let mut m = v.as_object().cloned().unwrap_or_default();
    for k in skip {
        m.remove(*k);
    }
    let mut s = String::new();
    canonical(&Value::Object(m), &mut s);
    s.into_bytes()
}

fn seal_hash(seal: &Value) -> String {
    hex::encode(sha256(&[&canonical_without(seal, &["seal_hash", "hmac_sha256", "signature", "_file"])]))
}

fn ed_verify(pub_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
    let (Ok(p), Ok(s)) = (hex::decode(pub_hex), hex::decode(sig_hex)) else { return false };
    let (Ok(p), Ok(s)) = (<[u8; 32]>::try_from(p.as_slice()), <[u8; 64]>::try_from(s.as_slice())) else {
        return false;
    };
    match VerifyingKey::from_bytes(&p) {
        Ok(vk) => vk.verify(msg, &Signature::from_bytes(&s)).is_ok(),
        Err(_) => false,
    }
}

fn read_pubkey(path: &str) -> Result<[u8; 32], String> {
    let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let text = String::from_utf8_lossy(&data).trim().to_string();
    if text.starts_with("-----BEGIN") {
        let b64: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = b64_decode(&b64).ok_or("bad PEM base64")?;
        let prefix = hex::decode("302a300506032b6570032100").unwrap();
        if der.len() != 44 || !der.starts_with(&prefix) {
            return Err("not an Ed25519 SubjectPublicKeyInfo".into());
        }
        return Ok(der[12..].try_into().unwrap());
    }
    if text.len() == 64 {
        return hex::decode(&text).map_err(|e| e.to_string())?.try_into().map_err(|_| "bad key".into());
    }
    data.try_into().map_err(|_| "unrecognised public key".into())
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b'\r' | b'\n' | b' ' => continue,
            _ => return None,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// CRC-32 single-bit error location (see forensic_verify.locate_bit_flip)
// ---------------------------------------------------------------------------

fn locate_bit_flip(payload: &[u8], stored: u32) -> Option<(usize, u8)> {
    let n = payload.len();
    let syndrome = crc32fast::hash(payload) ^ stored;
    if syndrome == 0 || n == 0 || 8 * n > MAX_LOCATE_BITS {
        return None;
    }
    let mut d: u32 = 1;
    for m in 0..=(8 * n) {
        if d == syndrome && m > 0 {
            let nk = (m + 7) / 8;
            if nk > n {
                return None;
            }
            let k = n - nk;
            let j = ((8 - (m % 8)) % 8) as u8;
            let mut fixed = payload.to_vec();
            fixed[k] ^= 1 << j;
            return if crc32fast::hash(&fixed) == stored { Some((k, j)) } else { None };
        }
        d = (d >> 1) ^ if d & 1 == 1 { CRC_POLY } else { 0 };
    }
    None
}

// ---------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------

struct Rec {
    seq: u64,
    digest: [u8; 32],
}

fn segments(dir: &Path) -> Vec<(u64, PathBuf)> {
    let mut v: Vec<(u64, PathBuf)> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    if name.starts_with("seg-") && name.ends_with(".ulj") {
                        name[4..name.len() - 4].parse::<u64>().ok().map(|f| (f, e.path()))
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn parse_records(payload: &[u8], bfirst: u64, count: u32, seg: &str, base: Option<u64>, rep: &mut Report,
                 out: &mut Vec<Rec>) {
    let mut pos = 0usize;
    for i in 0..count as u64 {
        if pos + REC > payload.len() {
            rep.problem("framing", format!("block truncated inside record {}", bfirst + i),
                        at!("segment" => seg, "seq" => bfirst + i));
            return;
        }
        let r = &payload[pos..pos + REC];
        let seq = u64::from_le_bytes(r[0..8].try_into().unwrap());
        let sl = u16::from_le_bytes(r[16..18].try_into().unwrap()) as usize;
        let il = u16::from_le_bytes(r[18..20].try_into().unwrap()) as usize;
        let rl = u32::from_le_bytes(r[20..24].try_into().unwrap()) as usize;
        let digest: [u8; 32] = r[24..56].try_into().unwrap();
        let raw_at = pos + REC + sl + il;
        if raw_at + rl > payload.len() {
            rep.problem("framing", format!("record {seq} overruns its block"), at!("segment" => seg, "seq" => seq));
            return;
        }
        if seq != bfirst + i {
            rep.problem("sequence", format!("record {i} of block {bfirst} carries sequence {seq}"),
                        at!("segment" => seg, "seq" => bfirst + i));
        }
        let raw = &payload[raw_at..raw_at + rl];
        if sha256(&[raw]) != digest {
            if raw.starts_with(ERASED_MAGIC) {
                rep.bump("erased_records", 1);
            } else {
                let mut w = at!("segment" => seg, "seq" => seq);
                match base {
                    Some(b) => {
                        w.insert("offset".into(), json!(b + raw_at as u64));
                        w.insert("length".into(), json!(rl));
                    }
                    None => {
                        w.insert("record_index".into(), json!(i));
                    }
                }
                rep.problem("record_hash", format!("record {seq}: raw bytes do not match their SHA-256"), w);
            }
        }
        out.push(Rec { seq, digest });
        pos = raw_at + rl;
    }
}

fn scan_journal(dir: &Path, key: Option<&[u8]>, rep: &mut Report, mut sink: impl FnMut(&Rec, &mut Report)) {
    let aead = key.map(|k| Aes256Gcm::new_from_slice(k).expect("32-byte key"));
    let segs = segments(dir);
    let mut expected: Option<u64> = None;
    for (si, (first, path)) in segs.iter().enumerate() {
        let seg = path.file_name().unwrap().to_string_lossy().to_string();
        rep.bump("segments", 1);
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        rep.bump("bytes", size);
        if let Some(e) = expected {
            if *first != e {
                rep.problem("gap", format!("segment starts at record {first}, expected {e}"),
                            at!("segment" => seg, "seq" => e));
            }
        }
        expected = Some(*first);
        let Ok(f) = File::open(path) else {
            rep.problem("io", "segment unreadable".into(), at!("segment" => seg));
            continue;
        };
        let mut f = BufReader::with_capacity(1 << 20, f);
        let mut offset: u64 = 0;
        let last = si == segs.len() - 1;
        while offset < size {
            let mut hdr = [0u8; HDR];
            if f.read_exact(&mut hdr).is_err() {
                if last {
                    rep.notes.push(format!("{seg}: torn header at the tail (offset {offset}); crash mid-write"));
                } else {
                    rep.problem("truncated", "segment ends inside a block header".into(),
                                at!("segment" => seg, "offset" => offset));
                }
                break;
            }
            let bfirst = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
            let count = u32::from_le_bytes(hdr[16..20].try_into().unwrap());
            let plen = u32::from_le_bytes(hdr[20..24].try_into().unwrap());
            let crc = u32::from_le_bytes(hdr[24..28].try_into().unwrap());
            let flags = hdr[5];
            if &hdr[0..4] != MAGIC || plen > MAX_BLOCK {
                rep.problem("block_header", "invalid block header; rest of segment unreadable".into(),
                            at!("segment" => seg, "offset" => offset, "seq" => expected));
                break;
            }
            let mut payload = vec![0u8; plen as usize];
            if f.read_exact(&mut payload).is_err() {
                if last {
                    rep.notes.push(format!("{seg}: torn block at the tail (offset {offset}); crash mid-write"));
                } else {
                    rep.problem("truncated", "segment ends inside a block".into(),
                                at!("segment" => seg, "offset" => offset, "seq" => bfirst));
                }
                break;
            }
            rep.bump("blocks", 1);
            if Some(bfirst) != expected {
                rep.problem("gap", format!("block starts at record {bfirst}, expected {:?}", expected),
                            at!("segment" => seg, "offset" => offset, "seq" => expected));
            }
            let pay_off = offset + HDR as u64;
            if crc32fast::hash(&payload) != crc {
                let mut w = at!("segment" => seg, "offset" => pay_off, "seq" => bfirst,
                                "seq_last" => bfirst + count as u64 - 1);
                let mut msg = format!("block {}..{} fails its CRC-32", bfirst, bfirst + count as u64 - 1);
                if let Some((k, j)) = locate_bit_flip(&payload, crc) {
                    w.insert("offset".into(), json!(pay_off + k as u64));
                    w.insert("bit".into(), json!(j));
                    msg.push_str(&format!(": single bit flipped at byte offset {} (bit {j})", pay_off + k as u64));
                }
                if flags & FLAG_ENC == 0 {
                    let mut tmp = Report::new();
                    let mut sinkv = Vec::new();
                    parse_records(&payload, bfirst, count, &seg, Some(pay_off), &mut tmp, &mut sinkv);
                    if let Some(s) = tmp.problems.iter().find(|p| p["kind"] == "record_hash").map(|p| p["seq"].clone()) {
                        w.insert("seq".into(), s.clone());
                        w.insert("seq_altered".into(), s);
                    }
                }
                rep.problem("block_crc", msg, w);
            }
            let (plain, base) = if flags & FLAG_ENC != 0 {
                let Some(a) = aead.as_ref() else {
                    rep.problem("encrypted", "encrypted block: pass --journal-key".into(),
                                at!("segment" => seg, "offset" => offset, "seq" => bfirst));
                    expected = Some(bfirst + count as u64);
                    offset = pay_off + plen as u64;
                    continue;
                };
                let mut aad = bfirst.to_le_bytes().to_vec();
                aad.extend_from_slice(&count.to_le_bytes());
                match a.decrypt(Nonce::from_slice(&payload[..12]), Payload { msg: &payload[12..], aad: &aad }) {
                    Ok(p) => (p, None),
                    Err(_) => {
                        rep.problem("aead", format!("block {}..{}: AES-GCM authentication failed", bfirst,
                                                    bfirst + count as u64 - 1),
                                    at!("segment" => seg, "offset" => offset, "seq" => bfirst));
                        expected = Some(bfirst + count as u64);
                        offset = pay_off + plen as u64;
                        continue;
                    }
                }
            } else {
                (payload, Some(pay_off))
            };
            let mut recs = Vec::with_capacity(count as usize);
            parse_records(&plain, bfirst, count, &seg, base, rep, &mut recs);
            rep.bump("records", recs.len() as u64);
            for r in &recs {
                sink(r, rep);
            }
            expected = Some(bfirst + count as u64);
            offset = pay_off + plen as u64;
        }
    }
}

// ---------------------------------------------------------------------------
// Seals
// ---------------------------------------------------------------------------

fn load_seals(dir: &Path) -> Vec<Value> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with("seal-") && n.ends_with(".json")).collect())
        .unwrap_or_default();
    names.sort();
    names.iter().filter_map(|n| {
        let text = std::fs::read_to_string(dir.join(n)).ok()?;
        let mut v: Value = serde_json::from_str(&text).ok()?;
        v.as_object_mut()?.insert("_file".into(), json!(n));
        Some(v)
    }).collect()
}

fn s_u64(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(|x| x.as_u64()).unwrap_or(0)
}

fn s_str<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("")
}

fn check_chain(seals: &[Value], pinned: Option<[u8; 32]>, rep: &mut Report) {
    let mut prev: Option<String> = None;
    let mut expected_signer: Option<String> = None;
    for s in seals {
        let sid = at!("seal" => s_str(s, "_file"), "seq" => s_u64(s, "first_seq"), "seq_last" => s_u64(s, "last_seq"));
        rep.bump("seals", 1);
        if seal_hash(s) != s_str(s, "seal_hash") {
            rep.problem("seal_hash", "seal content does not match its hash (edited seal file)".into(), sid.clone());
        }
        if let Some(p) = &prev {
            if s_str(s, "prev_seal_hash") != p {
                rep.problem("seal_chain", "prev_seal_hash does not match the previous seal".into(), sid.clone());
            }
        }
        prev = Some(s_str(s, "seal_hash").to_string());
        if s.get("version").and_then(|v| v.as_u64()).unwrap_or(1) < 2 {
            rep.notes.push(format!("{}: version-1 HMAC seal not checked", s_str(s, "_file")));
            expected_signer = None;
            continue;
        }
        if let Some(anchor) = s.get("anchor").filter(|a| a.is_object()) {
            let ident = s_str(anchor, "identity_pub");
            if pinned.is_some_and(|p| hex::encode(p) != ident) {
                rep.problem("anchor_identity", "chain anchored by an unknown identity key".into(), sid.clone());
            } else if !ed_verify(ident, &canonical_without(anchor, &["signature"]), s_str(anchor, "signature")) {
                rep.problem("anchor_signature", "anchor signature invalid".into(), sid.clone());
            }
            if s_str(anchor, "genesis_pub") != s_str(s, "signer_pub") {
                rep.problem("anchor_signer", "seal not signed by the key its anchor certifies".into(), sid.clone());
            }
            if expected_signer.is_some() {
                rep.notes.push(format!("{}: signing chain re-anchored", s_str(s, "_file")));
            }
        } else if expected_signer.is_none() {
            rep.problem("uncertified", "signing key not certified (no anchor and no previous seal)".into(), sid.clone());
        } else if expected_signer.as_deref() != Some(s_str(s, "signer_pub")) {
            rep.problem("fs_chain", "signed by a key the previous seal did not name".into(), sid.clone());
        }
        if !ed_verify(s_str(s, "signer_pub"), s_str(s, "seal_hash").as_bytes(), s_str(s, "signature")) {
            rep.problem("seal_signature", "Ed25519 signature invalid".into(), sid.clone());
        }
        rep.bump("signatures_checked", 1);
        expected_signer = Some(s_str(s, "next_pub").to_string());
    }
    if pinned.is_none() {
        rep.notes.push("no --pubkey given: anchors were not pinned".into());
    }
}

fn verify_journal(jdir: &Path, sdir: Option<&Path>, pinned: Option<[u8; 32]>, key: Option<&[u8]>) -> Report {
    let mut rep = Report::new();
    let mut seals = sdir.map(load_seals).unwrap_or_default();
    seals.sort_by_key(|s| s_u64(s, "first_seq"));
    check_chain(&seals, pinned, &mut rep);
    let mut si = 0usize;
    let mut window: Vec<[u8; 32]> = Vec::new();
    let mut last_seq = 0u64;
    let close = |s: &Value, window: &mut Vec<[u8; 32]>, rep: &mut Report| {
        let want = (s_u64(s, "last_seq") - s_u64(s, "first_seq") + 1) as usize;
        let sid = at!("seal" => s_str(s, "_file"), "seq" => s_u64(s, "first_seq"), "seq_last" => s_u64(s, "last_seq"));
        if window.len() != want {
            rep.problem("seal_records_missing", format!("{} sealed record(s) missing from the journal",
                                                        want - window.len()), sid);
        } else if hex::encode(merkle_root(window)) != s_str(s, "merkle_root") {
            rep.problem("merkle_root", "Merkle root recomputed from the journal does not match the seal".into(), sid);
        } else {
            rep.bump("merkle_roots_checked", 1);
        }
        window.clear();
    };
    scan_journal(jdir, key, &mut rep, |r, rep| {
        last_seq = r.seq;
        while si < seals.len() && r.seq > s_u64(&seals[si], "last_seq") {
            close(&seals[si], &mut window, rep);
            si += 1;
        }
        if si < seals.len() && s_u64(&seals[si], "first_seq") <= r.seq {
            window.push(leaf(r.seq, &r.digest));
            if r.seq == s_u64(&seals[si], "last_seq") {
                close(&seals[si], &mut window, rep);
                si += 1;
            }
        }
    });
    while si < seals.len() {
        let s = seals[si].clone();
        if s_u64(&s, "first_seq") > last_seq {
            rep.problem("seal_records_missing", "sealed records are not in the journal".into(),
                        at!("seal" => s_str(&s, "_file"), "seq" => s_u64(&s, "first_seq")));
        } else {
            close(&s, &mut window, &mut rep);
        }
        si += 1;
    }
    rep
}

fn verify_proofs(proof: &Path, seal: &Path, pinned: Option<[u8; 32]>) -> Result<Report, String> {
    let proofs: Value = serde_json::from_str(&std::fs::read_to_string(proof).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let seal: Value = serde_json::from_str(&std::fs::read_to_string(seal).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let mut rep = Report::new();
    check_chain(std::slice::from_ref(&seal), pinned, &mut rep);
    let list = if proofs.is_array() { proofs.as_array().unwrap().clone() } else { vec![proofs] };
    for p in list {
        let seq = s_u64(&p, "seq");
        let digest = hex::decode(s_str(&p, "raw_sha256")).unwrap_or_default();
        let mut h = leaf(seq, &digest);
        for step in p.get("proof").and_then(|x| x.as_array()).cloned().unwrap_or_default() {
            let sib = hex::decode(s_str(&step, "hash")).unwrap_or_default();
            h = if s_str(&step, "side") == "left" { sha256(&[&sib, &h]) } else { sha256(&[&h, &sib]) };
        }
        if hex::encode(h) != s_str(&seal, "merkle_root") {
            rep.problem("proof", format!("record {seq}: Merkle proof does not reach the seal root"), at!("seq" => seq));
        }
    }
    Ok(rep)
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args[1] == "-h" || args[1] == "--help" {
        eprintln!("ulpf-forensic-verify {VERSION}\n  journal --journal DIR [--seals DIR] [--pubkey PEM] [--journal-key FILE] [--json]\n  proof --proof FILE --seal FILE [--pubkey PEM] [--json]");
        std::process::exit(2);
    }
    if args[1] == "--version" {
        println!("{VERSION}");
        return;
    }
    let pinned = match arg(&args, "--pubkey").map(|p| read_pubkey(&p)) {
        Some(Ok(k)) => Some(k),
        Some(Err(e)) => {
            eprintln!("{e}");
            std::process::exit(2)
        }
        None => None,
    };
    let rep = match args[1].as_str() {
        "journal" => {
            let Some(j) = arg(&args, "--journal") else {
                eprintln!("--journal is required");
                std::process::exit(2)
            };
            let key = arg(&args, "--journal-key").map(|p| std::fs::read(p).expect("journal key unreadable"));
            if key.as_ref().is_some_and(|k| k.len() != 32) {
                eprintln!("journal key must be 32 bytes");
                std::process::exit(2);
            }
            let sd = arg(&args, "--seals").map(PathBuf::from);
            verify_journal(Path::new(&j), sd.as_deref(), pinned, key.as_deref())
        }
        "proof" => match (arg(&args, "--proof"), arg(&args, "--seal")) {
            (Some(p), Some(s)) => verify_proofs(Path::new(&p), Path::new(&s), pinned).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(2)
            }),
            _ => {
                eprintln!("--proof and --seal are required");
                std::process::exit(2)
            }
        },
        other => {
            eprintln!("unknown command {other}");
            std::process::exit(2)
        }
    };
    let valid = rep.problems.is_empty();
    let mut out = Map::new();
    out.insert("tool".into(), json!("ulpf-forensic-verify"));
    out.insert("engine".into(), json!("rust"));
    out.insert("version".into(), json!(VERSION));
    out.insert("valid".into(), json!(valid));
    for (k, v) in rep.stats {
        out.insert(k, v);
    }
    out.insert("problems".into(), Value::Array(rep.problems));
    out.insert("notes".into(), json!(rep.notes));
    if args.iter().any(|a| a == "--json") {
        println!("{}", serde_json::to_string_pretty(&Value::Object(out)).unwrap());
    } else {
        println!("ulpf-forensic-verify {VERSION} (rust): {}", if valid { "VERIFIED" } else { "FAILED" });
        for (k, v) in out.iter() {
            if v.is_u64() && v.as_u64() != Some(0) {
                println!("  {k:22} {v}");
            }
        }
        for p in out["problems"].as_array().unwrap() {
            println!("  PROBLEM [{}] {} {}", p["kind"].as_str().unwrap_or(""), p["message"].as_str().unwrap_or(""),
                     ["segment", "seal", "offset", "bit", "seq", "seq_last", "seq_altered"].iter()
                         .filter_map(|k| p.get(*k).filter(|v| !v.is_null()).map(|v| format!("{k}={v}")))
                         .collect::<Vec<_>>().join(", "));
        }
        for n in out["notes"].as_array().unwrap() {
            println!("  note: {}", n.as_str().unwrap_or(""));
        }
    }
    std::process::exit(if valid { 0 } else { 1 });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn python_float_repr() {
        assert_eq!(py_float(1731700000.123456), "1731700000.123456");
        assert_eq!(py_float(1.0), "1.0");
        assert_eq!(py_float(1e16), "1e+16");
        assert_eq!(py_float(1.5e-5), "1.5e-05");
        assert_eq!(py_float(0.001), "0.001");
        assert_eq!(py_float(123.0), "123.0");
    }
    #[test]
    fn bit_flip_located() {
        let data: Vec<u8> = (0..4096u32).map(|i| (i * 7) as u8).collect();
        let crc = crc32fast::hash(&data);
        let mut bad = data.clone();
        bad[1234] ^= 1 << 5;
        assert_eq!(locate_bit_flip(&bad, crc), Some((1234, 5)));
    }
}
