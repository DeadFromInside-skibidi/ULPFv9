//! Syslog over UDP (RFC 5426), TCP (RFC 6587) and TLS (RFC 5425).
//!
//! Framing is `ulpf.runtime.inputs.syslog`'s: a datagram is one message unless
//! it packs several lines; a stream is octet-counted (`<len> <msg>`) or
//! newline-delimited, detected per connection (or fixed by `framing`). Records
//! are the frame bytes without the delimiter.
//!
//! TLS (rustls, TLS 1.2 / 1.3): one certificate, or several chosen by the SNI
//! name the client sends (`tls.sni_certs`); `tls.sni_routes` journals each
//! connection's records under the input its server name maps to; `tls.client_ca`
//! makes a client certificate signed by that CA mandatory.

use super::{addr, opt_str, opt_u64, peer_text, tcp_listener, udp_sockets, Out, Shared};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use serde_json::Value as J;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const MAX_FRAME: usize = 1024 * 1024;

pub fn start(cfg: &J, sh: Arc<Shared>, threads: usize) -> Result<u16, String> {
    let a = addr(cfg)?;
    let reuseport = cfg.get("reuseport").and_then(|v| v.as_bool()).unwrap_or(true);
    match opt_str(cfg, "protocol").unwrap_or("tcp") {
        "udp" => {
            let telemetry = opt_str(cfg, "telemetry").unwrap_or("none") != "none";
            let socks = udp_sockets(a, threads, reuseport, 8 << 20)?;
            let port = socks[0].local_addr().map_err(|e| e.to_string())?.port();
            for s in socks {
                let s = tokio::net::UdpSocket::from_std(s).map_err(|e| e.to_string())?;
                tokio::spawn(udp_loop(s, sh.clone(), telemetry));
            }
            Ok(port)
        }
        proto @ ("tcp" | "tls") => {
            let framing = Framing::from(opt_str(cfg, "framing").unwrap_or("auto"))?;
            let tls = if proto == "tls" { Some(Tls::from(cfg.get("tls").unwrap_or(&J::Null))?) } else { None };
            let l = tcp_listener(a, reuseport)?;
            let port = l.local_addr().map_err(|e| e.to_string())?.port();
            let l = tokio::net::TcpListener::from_std(l).map_err(|e| e.to_string())?;
            tokio::spawn(accept_loop(l, sh, framing, tls.map(Arc::new)));
            Ok(port)
        }
        p => Err(format!("syslog: unknown protocol {p}")),
    }
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

/// `bytes.splitlines()`: \n, \r\n and \r end a line.
fn splitlines(b: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\n' => {
                out.push(&b[start..i]);
                start = i + 1;
            }
            b'\r' => {
                out.push(&b[start..i]);
                if i + 1 < b.len() && b[i + 1] == b'\n' {
                    i += 1;
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < b.len() {
        out.push(&b[start..]);
    }
    out
}

/// `bytes.strip()` is empty
fn blank(b: &[u8]) -> bool {
    b.iter().all(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
}

fn rstrip_crlf(b: &[u8]) -> &[u8] {
    let mut e = b.len();
    while e > 0 && (b[e - 1] == b'\r' || b[e - 1] == b'\n') {
        e -= 1;
    }
    &b[..e]
}

/// The records of one datagram (`_Udp.datagram_received`).
pub fn datagram_records(data: &[u8], telemetry: bool) -> Vec<Vec<u8>> {
    if telemetry {
        return if data.is_empty() { vec![] } else { vec![data.to_vec()] };
    }
    let trimmed = rstrip_crlf(data);
    let parts: Vec<&[u8]> = if trimmed.contains(&b'\n') { splitlines(data) } else { vec![trimmed] };
    parts.into_iter().filter(|r| !blank(r)).map(|r| r.to_vec()).collect()
}

/// Per-source pending records, flushed when full or aged (`_Batcher`).
struct Batcher {
    pending: HashMap<String, (Vec<Vec<u8>>, std::time::Instant)>,
}

impl Batcher {
    fn new() -> Self {
        Batcher { pending: HashMap::new() }
    }

    fn add(&mut self, sh: &Shared, source: &str, rec: Vec<u8>) -> Option<Out> {
        let e = self.pending.entry(source.to_string()).or_insert_with(|| (Vec::new(), std::time::Instant::now()));
        e.0.push(rec);
        if e.0.len() >= sh.batch {
            let (recs, _) = self.pending.remove(source).unwrap();
            return Some(Out { input: None, source: source.to_string(), records: recs, ts: super::now() });
        }
        None
    }

    fn aged(&mut self, sh: &Shared, all: bool) -> Vec<Out> {
        let keys: Vec<String> = self.pending.iter()
            .filter(|(_, (_, t))| all || t.elapsed() >= sh.flush).map(|(k, _)| k.clone()).collect();
        keys.into_iter().filter_map(|k| self.pending.remove(&k).map(|(recs, _)| Out {
            input: None, source: k, records: recs, ts: super::now() })).collect()
    }
}

async fn udp_loop(s: tokio::net::UdpSocket, sh: Arc<Shared>, telemetry: bool) {
    let mut buf = vec![0u8; 65536];
    let mut b = Batcher::new();
    let mut stop = sh.stop.clone();
    let mut tick = tokio::time::interval(sh.flush / 2);
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
                let src = peer_text(&peer);
                for rec in datagram_records(&buf[..n], telemetry) {
                    if let Some(out) = b.add(&sh, &src, rec) {
                        sh.try_send(out);
                    }
                }
            }
            _ = tick.tick() => for out in b.aged(&sh, false) { sh.try_send(out) },
            _ = stop.changed() => break,
        }
    }
    for out in b.aged(&sh, true) {
        sh.try_send(out);
    }
}

// ---------------------------------------------------------------------------
// TCP / TLS streams
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
pub enum Framing {
    Auto,
    Newline,
    Octet,
}

impl Framing {
    fn from(s: &str) -> Result<Framing, String> {
        Ok(match s {
            "auto" => Framing::Auto,
            "newline" => Framing::Newline,
            "octet" => Framing::Octet,
            o => Err(format!("syslog: unknown framing {o}"))?,
        })
    }
}

/// The stream framer of `_Tcp` (one per connection).
pub struct Framer {
    buf: Vec<u8>,
    octet: Option<bool>,
}

/// `^(\d{1,7}) ` at the start of `b`: (length, header size)
fn octet_header(b: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < b.len() && i < 7 && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 || i >= b.len() || b[i] != b' ' {
        return None;
    }
    // \d{1,7} then ' ': an eighth digit is neither
    if i == 7 && b.len() > 7 && b[7].is_ascii_digit() {
        return None;
    }
    Some((std::str::from_utf8(&b[..i]).ok()?.parse().ok()?, i + 1))
}

impl Framer {
    pub fn new(f: Framing) -> Self {
        Framer { buf: Vec::new(), octet: match f { Framing::Auto => None, Framing::Octet => Some(true),
                                                    Framing::Newline => Some(false) } }
    }

    /// Feed received bytes; complete records go to `out`. Returns true when the buffer
    /// overflowed (counted as oversize and dropped).
    pub fn feed(&mut self, data: &[u8], out: &mut Vec<Vec<u8>>) -> bool {
        self.buf.extend_from_slice(data);
        if self.octet.is_none() {
            if octet_header(&self.buf).is_some() {
                self.octet = Some(true);
            } else if self.buf.len() < 9 && self.buf.first().map(|c| c.is_ascii_digit()).unwrap_or(false)
                && !self.buf.contains(&b' ') {
                return false; // not decidable yet
            } else {
                self.octet = Some(false);
            }
        }
        if self.octet == Some(true) {
            self.octets(out);
        } else {
            self.lines(out);
        }
        if self.buf.len() > MAX_FRAME {
            self.buf.clear();
            return true;
        }
        false
    }

    fn lines(&mut self, out: &mut Vec<Vec<u8>>) {
        let mut pos = 0;
        while let Some(off) = memchr::memchr(b'\n', &self.buf[pos..]) {
            let nl = pos + off;
            let mut rec = &self.buf[pos..nl];
            while let Some(b'\r') = rec.last() {
                rec = &rec[..rec.len() - 1];
            }
            if !blank(rec) {
                out.push(rec.to_vec());
            }
            pos = nl + 1;
        }
        self.buf.drain(..pos);
    }

    fn octets(&mut self, out: &mut Vec<Vec<u8>>) {
        while !self.buf.is_empty() {
            let Some((n, start)) = octet_header(&self.buf) else {
                self.octet = Some(false);
                self.lines(out);
                return;
            };
            if n == 0 || n > MAX_FRAME {
                self.octet = Some(false);
                self.lines(out);
                return;
            }
            if self.buf.len() < start + n {
                return;
            }
            let rec = rstrip_crlf(&self.buf[start..start + n]).to_vec();
            self.buf.drain(..start + n);
            if !blank(&rec) {
                out.push(rec);
            }
        }
    }

    /// The connection closed: what is left is one last record (`connection_lost`).
    pub fn finish(&mut self, out: &mut Vec<Vec<u8>>) {
        if !blank(&self.buf) {
            out.push(rstrip_crlf(&self.buf).to_vec());
        }
        self.buf.clear();
    }
}

struct Tls {
    config: Arc<rustls::ServerConfig>,
    routes: HashMap<String, String>,
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("tls cert {path}: {e}"))?;
    rustls_pemfile::certs(&mut std::io::BufReader::new(f)).collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("tls cert {path}: {e}"))
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("tls key {path}: {e}"))?;
    rustls_pemfile::private_key(&mut std::io::BufReader::new(f)).map_err(|e| format!("tls key {path}: {e}"))?
        .ok_or_else(|| format!("tls key {path}: no private key"))
}

fn certified(cert: &str, key: Option<&str>) -> Result<Arc<CertifiedKey>, String> {
    let chain = load_certs(cert)?;
    let key = load_key(key.unwrap_or(cert))?;
    let signer = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| format!("tls key: {e}"))?;
    Ok(Arc::new(CertifiedKey::new(chain, signer)))
}

/// Certificates by SNI name, with a default for clients that send none or an unknown one.
#[derive(Debug)]
struct SniResolver {
    by_name: HashMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        hello.server_name().and_then(|n| self.by_name.get(&n.to_ascii_lowercase()).cloned()).or_else(|| self.default.clone())
    }
}

impl Tls {
    fn from(v: &J) -> Result<Tls, String> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let default = match opt_str(v, "cert") {
            Some(c) => Some(certified(c, opt_str(v, "key"))?),
            None => None,
        };
        let mut by_name = HashMap::new();
        for e in v.get("sni_certs").and_then(|x| x.as_array()).into_iter().flatten() {
            let name = opt_str(e, "server_name").ok_or("tls.sni_certs: server_name is required")?;
            let cert = opt_str(e, "cert").ok_or("tls.sni_certs: cert is required")?;
            by_name.insert(name.to_ascii_lowercase(), certified(cert, opt_str(e, "key"))?);
        }
        if default.is_none() && by_name.is_empty() {
            return Err("tls: a certificate (tls.cert or tls.sni_certs) is required".into());
        }
        let builder = rustls::ServerConfig::builder();
        let builder = match opt_str(v, "client_ca") {
            Some(ca) => {
                let mut roots = rustls::RootCertStore::empty();
                for c in load_certs(ca)? {
                    roots.add(c).map_err(|e| format!("tls client_ca: {e}"))?;
                }
                let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build().map_err(|e| format!("tls client_ca: {e}"))?;
                builder.with_client_cert_verifier(verifier)
            }
            None => builder.with_no_client_auth(),
        };
        let mut config = builder.with_cert_resolver(Arc::new(SniResolver { by_name, default }));
        // no resumption tickets: a sender that closes right after writing (no reads) would leave
        // them unread, and on Windows its close then resets the connection, discarding records
        // the listener had not read yet
        config.send_tls13_tickets = 0;
        let routes = v.get("sni_routes").and_then(|x| x.as_object()).map(|m| m.iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.to_ascii_lowercase(), s.to_string()))).collect()).unwrap_or_default();
        Ok(Tls { config: Arc::new(config), routes })
    }
}

async fn accept_loop(l: tokio::net::TcpListener, sh: Arc<Shared>, framing: Framing, tls: Option<Arc<Tls>>) {
    let acceptor = tls.as_ref().map(|t| tokio_rustls::TlsAcceptor::from(t.config.clone()));
    let mut stop = sh.stop.clone();
    loop {
        tokio::select! {
            r = l.accept() => {
                let (sock, peer) = match r {
                    Ok(x) => x,
                    Err(e) => { sh.stats.error(format!("accept: {e}")); continue }
                };
                if !sh.filter.allowed(peer.ip()) {
                    sh.stats.dropped_denied.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let _ = sock.set_nodelay(true);
                sh.stats.connections.fetch_add(1, Ordering::Relaxed);
                let sh = sh.clone();
                match (&acceptor, &tls) {
                    (Some(acc), Some(t)) => {
                        let acc = acc.clone();
                        let t = t.clone();
                        tokio::spawn(async move {
                            match acc.accept(sock).await {
                                Ok(stream) => {
                                    let sni = stream.get_ref().1.server_name().map(|s| s.to_ascii_lowercase());
                                    let input = sni.and_then(|n| t.routes.get(&n).cloned());
                                    connection(stream, peer, sh, framing, input).await
                                }
                                Err(e) => {
                                    sh.stats.tls_failures.fetch_add(1, Ordering::Relaxed);
                                    sh.stats.error(format!("tls handshake from {}: {e}", peer_text(&peer)));
                                }
                            }
                        });
                    }
                    _ => { tokio::spawn(connection(sock, peer, sh, framing, None)); }
                }
            }
            _ = stop.changed() => break,
        }
    }
}

async fn connection<S: AsyncRead + Unpin>(mut s: S, peer: SocketAddr, sh: Arc<Shared>, framing: Framing,
                                         input: Option<String>) {
    let src = peer_text(&peer);
    let mut fr = Framer::new(framing);
    let mut buf = vec![0u8; 64 * 1024];
    let mut pending: Vec<Vec<u8>> = Vec::new();
    let mut stop = sh.stop.clone();
    let mut tick = tokio::time::interval(sh.flush);
    let flush = |pending: &mut Vec<Vec<u8>>| Out { input: input.clone(), source: src.clone(),
                                                    records: std::mem::take(pending), ts: super::now() };
    loop {
        tokio::select! {
            r = s.read(&mut buf) => {
                let n = match r {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                sh.stats.bytes.fetch_add(n as u64, Ordering::Relaxed);
                if fr.feed(&buf[..n], &mut pending) {
                    sh.stats.dropped_oversize.fetch_add(1, Ordering::Relaxed);
                }
                if pending.len() >= sh.batch {
                    let out = flush(&mut pending);
                    sh.send(out).await;           // waits while Python is behind: the sender slows down
                }
            }
            _ = tick.tick() => if !pending.is_empty() {
                let out = flush(&mut pending);
                sh.send(out).await;
            },
            _ = stop.changed() => break,
        }
    }
    fr.finish(&mut pending);
    if !pending.is_empty() {
        let out = flush(&mut pending);
        sh.send(out).await;
    }
}

/// Framing of a whole byte stream, chunked as `chunks` (for the equivalence tests).
pub fn frame_stream(framing: &str, chunks: &[&[u8]]) -> Result<(Vec<Vec<u8>>, u64), String> {
    let mut fr = Framer::new(Framing::from(framing)?);
    let mut out = Vec::new();
    let mut over = 0;
    for c in chunks {
        if fr.feed(c, &mut out) {
            over += 1;
        }
    }
    fr.finish(&mut out);
    Ok((out, over))
}

#[allow(dead_code)]
pub fn opt(v: &J, k: &str) -> u64 {
    opt_u64(v, k, 0)
}
