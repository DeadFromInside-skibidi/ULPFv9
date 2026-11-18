//! NetFlow v5 / v9 and IPFIX (v10) collector: the decoder of
//! `ulpf.runtime.inputs.netflow.FlowDecoder` (same records, same key order,
//! same template-state file), on a Tokio UDP socket.
//!
//! Templates (v9 / IPFIX) are cached per (exporter, observation domain, template
//! ID) and saved to the state file every few seconds, so data that arrives right
//! after a restart decodes. Data for an unknown template is counted, not guessed.
//! A packet the decoder rejects (truncated header, unknown version, a field past
//! the end) yields no records and counts as an error, as in Python.

use super::json::{dumps, Obj};
use super::{addr, opt_str, peer_text, udp_sockets, Out, Shared};
use serde_json::Value as J;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub fn start(cfg: &J, sh: Arc<Shared>) -> Result<u16, String> {
    let a = addr(cfg)?;
    let socks = udp_sockets(a, 1, false, 8 << 20)?;
    let port = socks[0].local_addr().map_err(|e| e.to_string())?.port();
    let dec = Decoder::new(opt_str(cfg, "state_path").map(String::from),
                           cfg.get("ipv6_mapped_dotted").and_then(|v| v.as_bool()).unwrap_or(false));
    let s = tokio::net::UdpSocket::from_std(socks.into_iter().next().unwrap()).map_err(|e| e.to_string())?;
    tokio::spawn(run(s, sh, dec));
    Ok(port)
}

async fn run(s: tokio::net::UdpSocket, sh: Arc<Shared>, mut dec: Decoder) {
    let mut buf = vec![0u8; 65536];
    let mut stop = sh.stop.clone();
    let mut save = tokio::time::interval(std::time::Duration::from_secs(5));
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
                let exporter = peer_text(&peer);
                let before = dec.unknown_template;
                match dec.decode(&buf[..n], &exporter) {
                    Ok(flows) => {
                        sh.stats.unknown_template.fetch_add(dec.unknown_template - before, Ordering::Relaxed);
                        if !flows.is_empty() {
                            let records = flows.into_iter().map(|f| dumps(&f)).collect();
                            sh.try_send(Out { input: None, source: exporter, records, ts: super::now() });
                        }
                    }
                    Err(e) => sh.stats.error(format!("{exporter}: {e}")),
                }
            }
            _ = save.tick() => dec.save(),
            _ = stop.changed() => break,
        }
    }
    dec.save();
}

const PROTO: [(u64, &str); 8] = [(1, "icmp"), (6, "tcp"), (17, "udp"), (47, "gre"), (50, "esp"), (51, "ah"),
                                 (58, "ipv6-icmp"), (132, "sctp")];

/// IANA IPFIX information elements (and the NetFlow v9 ids they share): `netflow.IE`
fn ie_name(ie: u32) -> Option<&'static str> {
    Some(match ie {
        1 => "bytes", 2 => "packets", 3 => "flows", 4 => "protocol", 5 => "tos", 6 => "tcp_flags", 7 => "src_port",
        8 => "src_ip", 9 => "src_mask", 10 => "input_if", 11 => "dst_port", 12 => "dst_ip", 13 => "dst_mask",
        14 => "output_if", 15 => "next_hop", 16 => "src_as", 17 => "dst_as", 18 => "bgp_next_hop",
        21 => "last_switched", 22 => "first_switched", 23 => "bytes_out", 24 => "packets_out", 27 => "src_ip",
        28 => "dst_ip", 29 => "src_mask", 30 => "dst_mask", 32 => "icmp_type", 34 => "sampling_interval",
        35 => "sampling_algorithm", 52 => "min_ttl", 53 => "max_ttl", 56 => "src_mac", 57 => "dst_mac",
        58 => "vlan_id", 59 => "post_vlan_id", 60 => "ip_version", 61 => "direction", 62 => "next_hop",
        80 => "dst_mac", 81 => "src_mac", 85 => "bytes_total", 86 => "packets_total", 136 => "flow_end_reason",
        148 => "flow_id", 150 => "flow_start_seconds", 151 => "flow_end_seconds",
        152 => "flow_start_ms", 153 => "flow_end_ms", 154 => "flow_start_us", 155 => "flow_end_us",
        176 => "icmp_type", 177 => "icmp_code", 225 => "nat_src_ip", 226 => "nat_dst_ip",
        227 => "nat_src_port", 228 => "nat_dst_port", 233 => "firewall_event",
        _ => return None,
    })
}

/// `str(ipaddress.IPv6Address(b))` (`_compress_hextets`; Python 3.13+ prints IPv4-mapped
/// addresses with a dotted quad)
pub fn ipv6_text(a: Ipv6Addr, mapped_dotted: bool) -> String {
    if mapped_dotted {
        if let Some(v4) = a.to_ipv4_mapped() {
            return format!("::ffff:{v4}");
        }
    }
    let h: Vec<String> = a.segments().iter().map(|x| format!("{x:x}")).collect();
    let (mut best_start, mut best_len) = (usize::MAX, 0usize);
    let (mut start, mut len) = (usize::MAX, 0usize);
    for (i, x) in h.iter().enumerate() {
        if x == "0" {
            len += 1;
            if start == usize::MAX {
                start = i;
            }
            if len > best_len {
                best_len = len;
                best_start = start;
            }
        } else {
            len = 0;
            start = usize::MAX;
        }
    }
    if best_len > 1 {
        let end = best_start + best_len;
        let mut out: Vec<String> = h[..best_start].to_vec();
        out.push(String::new());
        out.extend(h[end..].iter().cloned());
        if end == h.len() {
            out.push(String::new());
        }
        if best_start == 0 {
            out.insert(0, String::new());
        }
        return out.join(":");
    }
    h.join(":")
}

fn value(ie: u32, data: &[u8], dotted: bool) -> J {
    match ie {
        8 | 12 | 15 | 18 | 225 | 226 if data.len() == 4 => {
            return J::from(Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string())
        }
        27 | 28 | 62 | 63 if data.len() == 16 => {
            let b: [u8; 16] = data.try_into().unwrap();
            return J::from(ipv6_text(Ipv6Addr::from(b), dotted));
        }
        56 | 57 | 80 | 81 if data.len() == 6 => {
            return J::from(data.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"))
        }
        _ => {}
    }
    if data.len() <= 8 {
        J::from(data.iter().fold(0u64, |a, b| (a << 8) | *b as u64))
    } else {
        J::from(hex::encode(data))
    }
}

/// Flow times from 1970 up to 3001-01-01 (`netflow._MAX_TIME`); others reject the packet.
const MAX_TIME: f64 = 32536850400.0;

/// `iso` with the range check of the Python decoder.
fn iso_checked(sec: f64) -> Result<String, String> {
    if !(0.0..MAX_TIME).contains(&sec) {
        return Err(format!("flow time {sec} out of range"));
    }
    Ok(iso(sec))
}

/// `time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(sec)) + f".{int(sec % 1 * 1000):03d}Z"`
fn iso(sec: f64) -> String {
    let whole = sec.floor() as i64;
    let ms = (sec.rem_euclid(1.0) * 1000.0) as i64;
    let days = whole.div_euclid(86400);
    let rem = whole.rem_euclid(86400);
    let (y, m, d) = civil(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// days since 1970-01-01 -> (year, month, day), proleptic Gregorian
fn civil(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A time field's value; a field longer than 8 bytes is hex text and Python's arithmetic
/// on it raises (the packet is rejected).
fn int_field(v: &J, k: &str) -> Result<u64, String> {
    v.as_u64().ok_or_else(|| format!("unsupported operand type for {k}: 'str'"))
}

/// `_finish`: absolute ISO times, protocol name.
fn finish(mut rec: Obj, unix_secs: u64, uptime: Option<u64>) -> Result<J, String> {
    if let Some(up) = uptime {
        for (a, b) in [("first_switched", "start"), ("last_switched", "end")] {
            if let Some(v) = rec.0.shift_remove(a) {
                let t = int_field(&v, a)? as i128;
                let sec = unix_secs as f64 - (up as i128 - t) as f64 / 1000.0;
                rec.set(b, iso_checked(sec)?);
            }
        }
    }
    for (a, b, div) in [("flow_start_seconds", "start", 1.0), ("flow_end_seconds", "end", 1.0),
                        ("flow_start_ms", "start", 1000.0), ("flow_end_ms", "end", 1000.0),
                        ("flow_start_us", "start", 1e6), ("flow_end_us", "end", 1e6)] {
        if let Some(v) = rec.0.shift_remove(a) {
            rec.set(b, iso_checked(int_field(&v, a)? as f64 / div)?);
        }
    }
    if let Some(p) = rec.0.get("protocol").and_then(|v| v.as_u64()) {
        rec.set("protocol_number", p);
        let name = PROTO.iter().find(|(n, _)| *n == p).map(|(_, s)| s.to_string()).unwrap_or_else(|| p.to_string());
        rec.set("protocol", name);
    }
    if !rec.0.contains_key("timestamp") {
        let ts = match rec.0.get("end") {
            Some(J::String(s)) if !s.is_empty() => s.clone(),
            _ => iso_checked(unix_secs as f64)?,
        };
        rec.set("timestamp", ts);
    }
    Ok(rec.into_value())
}

fn be16(b: &[u8], i: usize) -> Result<u16, String> {
    b.get(i..i + 2).map(|x| u16::from_be_bytes([x[0], x[1]])).ok_or_else(|| "unpack requires a buffer of 2 bytes".into())
}

fn be32(b: &[u8], i: usize) -> Result<u32, String> {
    b.get(i..i + 4).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]))
        .ok_or_else(|| "unpack requires a buffer of 4 bytes".into())
}

/// `body[a:b]` (Python slicing never fails)
fn sl(b: &[u8], a: usize, e: usize) -> &[u8] {
    let a = a.min(b.len());
    &b[a..e.clamp(a, b.len())]
}

pub struct Decoder {
    templates: HashMap<String, Vec<(u32, u32)>>,
    order: Vec<String>,
    state_path: Option<String>,
    pub unknown_template: u64,
    dirty: bool,
    dotted: bool,
}

impl Decoder {
    pub fn new(state_path: Option<String>, dotted: bool) -> Self {
        let mut d = Decoder { templates: HashMap::new(), order: Vec::new(), state_path, unknown_template: 0,
                              dirty: false, dotted };
        if let Some(p) = &d.state_path {
            if let Ok(text) = std::fs::read_to_string(p) {
                if let Ok(J::Object(m)) = serde_json::from_str::<J>(&text) {
                    for (k, v) in m {
                        let fields: Vec<(u32, u32)> = v.as_array().into_iter().flatten().filter_map(|x| {
                            let a = x.as_array()?;
                            Some((a.first()?.as_u64()? as u32, a.get(1)?.as_u64()? as u32))
                        }).collect();
                        d.order.push(k.clone());
                        d.templates.insert(k, fields);
                    }
                }
            }
        }
        d
    }

    /// Same file as `FlowDecoder.save` (`json.dump(self.templates)`).
    pub fn save(&mut self) {
        let Some(p) = &self.state_path else { return };
        if !self.dirty {
            return;
        }
        let mut m = serde_json::Map::new();
        for k in &self.order {
            let v: Vec<J> = self.templates[k].iter().map(|(a, b)| J::from(vec![*a, *b])).collect();
            m.insert(k.clone(), J::from(v));
        }
        let text = serde_json::to_string(&J::Object(m)).unwrap_or_default().replace("\":", "\": ").replace(",", ", ");
        let tmp = format!("{p}.tmp");
        if std::fs::write(&tmp, text).is_ok() && std::fs::rename(&tmp, p).is_ok() {
            self.dirty = false;
        }
    }

    fn set_template(&mut self, key: String, fields: Vec<(u32, u32)>) {
        if self.templates.get(&key) != Some(&fields) {
            if !self.templates.contains_key(&key) {
                self.order.push(key.clone());
            }
            self.templates.insert(key, fields);
            self.dirty = true;
        }
    }

    pub fn decode(&mut self, data: &[u8], exporter: &str) -> Result<Vec<J>, String> {
        if data.len() < 4 {
            return Ok(vec![]);
        }
        match be16(data, 0)? {
            5 => self.v5(data, exporter),
            9 => self.v9(data, exporter),
            10 => self.ipfix(data, exporter),
            v => Err(format!("unsupported NetFlow version {v}")),
        }
    }

    fn v5(&mut self, data: &[u8], exporter: &str) -> Result<Vec<J>, String> {
        if data.len() < 12 {
            return Err("unpack requires a buffer of 10 bytes".into());
        }
        let count = be16(data, 2)? as usize;
        let uptime = be32(data, 4)? as u64;
        let secs = be32(data, 8)? as u64;
        let mut out = Vec::new();
        for i in 0..count {
            let off = 24 + i * 48;
            let r = sl(data, off, off + 48);
            if r.len() < 48 {
                break;
            }
            let ip = |o: usize| Ipv4Addr::new(r[o], r[o + 1], r[o + 2], r[o + 3]).to_string();
            let mut rec = Obj::default();
            rec.set("netflow_version", 5);
            rec.set("exporter", exporter);
            rec.set("src_ip", ip(0));
            rec.set("dst_ip", ip(4));
            rec.set("next_hop", ip(8));
            rec.set("input_if", be16(r, 12)?);
            rec.set("output_if", be16(r, 14)?);
            rec.set("packets", be32(r, 16)?);
            rec.set("bytes", be32(r, 20)?);
            rec.set("first_switched", be32(r, 24)?);
            rec.set("last_switched", be32(r, 28)?);
            rec.set("src_port", be16(r, 32)?);
            rec.set("dst_port", be16(r, 34)?);
            rec.set("tcp_flags", r[37]);
            rec.set("protocol", r[38]);
            rec.set("tos", r[39]);
            rec.set("src_as", be16(r, 40)?);
            rec.set("dst_as", be16(r, 42)?);
            rec.set("src_mask", r[44]);
            rec.set("dst_mask", r[45]);
            out.push(finish(rec, secs, Some(uptime))?);
        }
        Ok(out)
    }

    fn v9(&mut self, data: &[u8], exporter: &str) -> Result<Vec<J>, String> {
        if data.len() < 20 {
            return Err("unpack requires a buffer of 18 bytes".into());
        }
        let uptime = be32(data, 4)? as u64;
        let secs = be32(data, 8)? as u64;
        let source_id = be32(data, 16)?;
        let mut off = 20;
        let mut out = Vec::new();
        while off + 4 <= data.len() {
            let fs_id = be16(data, off)?;
            let length = be16(data, off + 2)? as usize;
            if length < 4 {
                break;
            }
            let body = sl(data, off + 4, off + length);
            if fs_id == 0 {
                let mut p = 0;
                while p + 4 <= body.len() {
                    let tid = be16(body, p)?;
                    let n = be16(body, p + 2)? as usize;
                    let mut fields = Vec::with_capacity(n);
                    for k in 0..n {
                        let f = sl(body, p + 4 + 4 * k, p + 8 + 4 * k);
                        if f.len() < 4 {
                            return Err("unpack requires a buffer of 4 bytes".into());
                        }
                        fields.push((be16(f, 0)? as u32, be16(f, 2)? as u32));
                    }
                    self.set_template(format!("{exporter}|{source_id}|{tid}"), fields);
                    p += 4 + 4 * n;
                }
            } else if fs_id == 1 {
                let mut p = 0;
                while p + 6 <= body.len() {
                    let tid = be16(body, p)?;
                    let scope_len = be16(body, p + 2)? as usize;
                    let opt_len = be16(body, p + 4)? as usize;
                    let n = (scope_len + opt_len) / 4;
                    let mut fields = Vec::with_capacity(n);
                    for k in 0..n {
                        let f = sl(body, p + 6 + 4 * k, p + 10 + 4 * k);
                        if f.len() < 4 {
                            return Err("unpack requires a buffer of 4 bytes".into());
                        }
                        fields.push((be16(f, 0)? as u32, be16(f, 2)? as u32));
                    }
                    self.set_template(format!("{exporter}|{source_id}|{tid}"), fields);
                    p += 6 + scope_len + opt_len;
                }
            } else if fs_id >= 256 {
                out.extend(self.data(body, &format!("{exporter}|{source_id}|{fs_id}"), exporter, 9, secs, Some(uptime))?);
            }
            off += length;
        }
        Ok(out)
    }

    fn ipfix(&mut self, data: &[u8], exporter: &str) -> Result<Vec<J>, String> {
        if data.len() < 16 {
            return Err("unpack requires a buffer of 14 bytes".into());
        }
        let export_time = be32(data, 4)? as u64;
        let domain = be32(data, 12)?;
        let mut off = 16;
        let mut out = Vec::new();
        while off + 4 <= data.len() {
            let set_id = be16(data, off)?;
            let length = be16(data, off + 2)? as usize;
            if length < 4 {
                break;
            }
            let body = sl(data, off + 4, off + length);
            if set_id == 2 || set_id == 3 {
                let mut p = 0;
                while p + 4 <= body.len() {
                    let tid = be16(body, p)?;
                    let n = be16(body, p + 2)? as usize;
                    p += 4;
                    if set_id == 3 {
                        p += 2;
                    }
                    let mut fields = Vec::with_capacity(n);
                    for _ in 0..n {
                        let f = sl(body, p, p + 4);
                        if f.len() < 4 {
                            return Err("unpack requires a buffer of 4 bytes".into());
                        }
                        let mut ie = be16(f, 0)? as u32;
                        let ln = be16(f, 2)? as u32;
                        p += 4;
                        if ie & 0x8000 != 0 {
                            p += 4;
                            ie = 0x10000 | (ie & 0x7FFF);
                        }
                        fields.push((ie, ln));
                    }
                    self.set_template(format!("{exporter}|{domain}|{tid}"), fields);
                    if body.len() < p + 4 {
                        break;
                    }
                }
            } else if set_id >= 256 {
                out.extend(self.data(body, &format!("{exporter}|{domain}|{set_id}"), exporter, 10, export_time, None)?);
            }
            off += length;
        }
        Ok(out)
    }

    fn data(&mut self, body: &[u8], key: &str, exporter: &str, version: u64, secs: u64, uptime: Option<u64>)
            -> Result<Vec<J>, String> {
        let Some(tpl) = self.templates.get(key).cloned() else {
            self.unknown_template += 1;
            return Ok(vec![]);
        };
        let tid: u64 = key.rsplit('|').next().unwrap().parse().unwrap_or(0);
        let fixed: usize = tpl.iter().filter(|(_, l)| *l != 65535).map(|(_, l)| *l as usize).sum();
        let mut out = Vec::new();
        let mut p = 0usize;
        while body.len().saturating_sub(p) >= fixed.max(1) && p <= body.len() {
            let mut rec = Obj::default();
            rec.set("netflow_version", version);
            rec.set("exporter", exporter);
            rec.set("template_id", tid);
            for (ie, ln) in &tpl {
                let mut ln = *ln as usize;
                if ln == 65535 {
                    ln = *body.get(p).ok_or("index out of range")? as usize;
                    p += 1;
                    if ln == 255 {
                        let f = sl(body, p, p + 2);
                        if f.len() < 2 {
                            return Err("unpack requires a buffer of 2 bytes".into());
                        }
                        ln = u16::from_be_bytes([f[0], f[1]]) as usize;
                        p += 2;
                    }
                }
                let raw = sl(body, p, p + ln);
                p += ln;
                let name = match ie_name(*ie) {
                    Some(n) => n.to_string(),
                    None if *ie < 0x10000 => format!("ie_{ie}"),
                    None => format!("pen_ie_{}", ie & 0xFFFF),
                };
                rec.set(&name, value(*ie, raw, self.dotted));
            }
            out.push(finish(rec, secs, uptime)?);
            if fixed == 0 {
                break;
            }
        }
        Ok(out)
    }
}

/// Decode a sequence of packets from one exporter (for the equivalence tests): per packet,
/// the records as JSON bytes, or the error.
pub fn decode_packets(packets: &[Vec<u8>], exporter: &str, dotted: bool) -> Vec<Result<Vec<Vec<u8>>, String>> {
    let mut d = Decoder::new(None, dotted);
    packets.iter().map(|p| d.decode(p, exporter).map(|fs| fs.iter().map(dumps).collect())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_like_python() {
        for (a, want) in [("::ffff:1.2.3.4", "::ffff:102:304"), ("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"),
                          ("2001:0:0:1:0:0:0:1", "2001:0:0:1::1"), ("fe80::", "fe80::"), ("::", "::"),
                          ("1:0:0:2:0:0:0:3", "1:0:0:2::3"), ("0:0:1::", "0:0:1::"), ("1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"),
                          ("1:0:2:3:4:5:6:7", "1:0:2:3:4:5:6:7")] {
            assert_eq!(ipv6_text(a.parse().unwrap(), false), want, "{a}");
        }
        assert_eq!(ipv6_text("::ffff:1.2.3.4".parse().unwrap(), true), "::ffff:1.2.3.4");
    }

    #[test]
    fn iso_like_python() {
        assert_eq!(iso(0.0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso(1760000000.5), "2025-10-09T08:53:20.500Z");
        assert_eq!(iso(951782400.999), "2000-02-29T00:00:00.998Z"); // float rounding, as Python
        assert_eq!(iso(-1.25), "1969-12-31T23:59:58.750Z");
    }
}
