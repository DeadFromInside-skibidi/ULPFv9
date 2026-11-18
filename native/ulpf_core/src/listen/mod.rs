//! Network listeners on a Tokio runtime: syslog over UDP / TCP / TLS (RFC 5426,
//! 6587, 5425, with SNI routing and client-certificate validation), NetFlow v5 /
//! v9 / IPFIX with template caching, SNMP traps (v1, v2c, v3 USM) and OTLP logs
//! over gRPC.
//!
//! A listener only frames and decodes: its batches (input, source, records) go
//! through a bounded channel to the Python input, which rate-limits and
//! journals them (`Input.accept`) as for every other input. When the channel is
//! full, TCP / TLS / gRPC connections stop reading (the sender is slowed down)
//! and UDP datagrams are counted as dropped. Sockets are bound before `start`
//! returns, so a busy port is reported at once.
//!
//! The decoders produce the records the Python inputs produce, byte for byte
//! (`tests/test_native_listeners.py` compares them).

pub mod json;
pub mod netflow;
pub mod otlp;
pub mod snmp;
pub mod syslog;

use serde_json::Value as J;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch};

/// One hand-off to Python: records of one source, journaled under `input` (None: the
/// listener's own input name).
pub struct Out {
    pub input: Option<String>,
    pub source: String,
    pub records: Vec<Vec<u8>>,
    pub ts: f64,
}

#[derive(Default)]
pub struct Stats {
    pub received: AtomicU64,
    pub bytes: AtomicU64,
    pub dropped_overflow: AtomicU64,
    pub dropped_oversize: AtomicU64,
    pub dropped_denied: AtomicU64,
    pub connections: AtomicU64,
    pub errors: AtomicU64,
    pub tls_failures: AtomicU64,
    pub auth_failures: AtomicU64,
    pub unknown_template: AtomicU64,
    pub last_error: Mutex<Option<String>>,
}

impl Stats {
    pub fn error(&self, msg: impl Into<String>) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        *self.last_error.lock().unwrap() = Some(msg.into());
    }

    pub fn snapshot(&self) -> Vec<(&'static str, u64)> {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        vec![("received", g(&self.received)), ("bytes", g(&self.bytes)),
             ("dropped_overflow", g(&self.dropped_overflow)), ("dropped_oversize", g(&self.dropped_oversize)),
             ("dropped_denied", g(&self.dropped_denied)), ("connections", g(&self.connections)),
             ("errors", g(&self.errors)), ("tls_failures", g(&self.tls_failures)),
             ("auth_failures", g(&self.auth_failures)), ("unknown_template", g(&self.unknown_template))]
    }
}

pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// `allow_sources`: CIDR allow-list (empty: everyone), as `SourceFilter`.
#[derive(Clone, Default)]
pub struct Filter {
    nets: Vec<(IpAddr, u8)>,
}

impl Filter {
    pub fn new(cidrs: &[String]) -> Result<Self, String> {
        let mut nets = Vec::new();
        for c in cidrs {
            let (a, l) = c.split_once('/').unwrap_or((c.as_str(), ""));
            let ip: IpAddr = a.trim().parse().map_err(|_| format!("allow_sources: bad network {c}"))?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            let len: u8 = if l.is_empty() { max } else { l.trim().parse().map_err(|_| format!("allow_sources: {c}"))? };
            if len > max {
                return Err(format!("allow_sources: bad prefix in {c}"));
            }
            nets.push((ip, len));
        }
        Ok(Filter { nets })
    }

    pub fn allowed(&self, ip: IpAddr) -> bool {
        if self.nets.is_empty() {
            return true;
        }
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        self.nets.iter().any(|(net, len)| match (net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let m = if *len == 0 { 0 } else { u32::MAX << (32 - *len as u32) };
                u32::from(*n) & m == u32::from(a) & m
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let m = if *len == 0 { 0 } else { u128::MAX << (128 - *len as u32) };
                u128::from(*n) & m == u128::from(a) & m
            }
            _ => false,
        })
    }
}

/// The peer address as Python prints it (`addr[0]` of a socket address).
pub fn peer_text(a: &SocketAddr) -> String {
    match a.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
        v4 => v4.to_string(),
    }
}

/// What every listener task shares.
pub struct Shared {
    pub tx: mpsc::Sender<Out>,
    pub stats: Stats,
    pub filter: Filter,
    pub stop: watch::Receiver<bool>,
    pub batch: usize,
    pub flush: Duration,
}

impl Shared {
    /// Flow-controlled hand-off (TCP, TLS, gRPC): waits while Python is behind.
    pub async fn send(&self, out: Out) {
        let n = out.records.len() as u64;
        if self.tx.send(out).await.is_err() {
            self.stats.dropped_overflow.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// UDP hand-off: a full queue drops (UDP has no flow control).
    pub fn try_send(&self, out: Out) {
        let n = out.records.len() as u64;
        if self.tx.try_send(out).is_err() {
            self.stats.dropped_overflow.fetch_add(n, Ordering::Relaxed);
            self.stats.received.fetch_add(n, Ordering::Relaxed);
        }
    }
}

pub fn opt_str<'a>(v: &'a J, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|x| x.as_str())
}

pub fn opt_u64(v: &J, k: &str, d: u64) -> u64 {
    v.get(k).and_then(|x| x.as_u64()).unwrap_or(d)
}

/// A running listener.
pub struct Handle {
    pub rt: tokio::runtime::Runtime,
    pub rx: Mutex<mpsc::Receiver<Out>>,
    pub shared: Arc<Shared>,
    pub bound_port: u16,
    pub stop: watch::Sender<bool>,
}

/// Start the listener a config describes (JSON from `ulpf.runtime.inputs.native`).
pub fn start(cfg: &J) -> Result<Handle, String> {
    let threads = opt_u64(cfg, "threads", 2).clamp(1, 64) as usize;
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(threads).enable_all()
        .thread_name("ulpf-listen").build().map_err(|e| e.to_string())?;
    let (tx, rx) = mpsc::channel::<Out>(opt_u64(cfg, "queue_batches", 256).max(1) as usize);
    let (stop_tx, stop_rx) = watch::channel(false);
    let allow: Vec<String> = cfg.get("allow_sources").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    let shared = Arc::new(Shared {
        tx, stats: Stats::default(), filter: Filter::new(&allow)?, stop: stop_rx,
        batch: opt_u64(cfg, "batch", 1000).max(1) as usize,
        flush: Duration::from_millis(opt_u64(cfg, "flush_ms", 50).max(1)),
    });
    let kind = opt_str(cfg, "kind").ok_or("listener: kind is required")?;
    let _guard = rt.enter();
    let bound_port = match kind {
        "syslog" => syslog::start(cfg, shared.clone(), threads)?,
        "netflow" => netflow::start(cfg, shared.clone())?,
        "snmp" => snmp::start(cfg, shared.clone())?,
        "otlp_grpc" => otlp::start(cfg, shared.clone())?,
        k => return Err(format!("listener: unknown kind {k}")),
    };
    drop(_guard);
    Ok(Handle { rt, rx: Mutex::new(rx), shared, bound_port, stop: stop_tx })
}

/// A bound std socket address from (host, port).
pub fn addr(cfg: &J) -> Result<SocketAddr, String> {
    let host = opt_str(cfg, "host").unwrap_or("0.0.0.0");
    let port = opt_u64(cfg, "port", 0);
    let ip: IpAddr = host.parse().map_err(|_| format!("listener: host must be an IP address, got {host}"))?;
    Ok(SocketAddr::new(ip, port as u16))
}

/// UDP sockets for `addr`: with `reuseport` on Linux, `n` sockets on one port (the kernel
/// spreads datagrams across them); elsewhere one socket (Windows: SO_REUSEADDR semantics
/// differ, and IOCP already completes receives on every runtime thread).
pub fn udp_sockets(a: SocketAddr, n: usize, reuseport: bool, rcvbuf: usize) -> Result<Vec<std::net::UdpSocket>, String> {
    use socket2::{Domain, Protocol, Socket, Type};
    let count = if reuseport && cfg!(target_os = "linux") { n.max(1) } else { 1 };
    let mut out = Vec::new();
    let mut port = a.port();
    for _ in 0..count {
        let s = Socket::new(Domain::for_address(a), Type::DGRAM, Some(Protocol::UDP)).map_err(|e| e.to_string())?;
        #[cfg(target_os = "linux")]
        if count > 1 {
            s.set_reuse_port(true).map_err(|e| e.to_string())?;
        }
        let _ = s.set_recv_buffer_size(rcvbuf);
        s.bind(&SocketAddr::new(a.ip(), port).into()).map_err(|e| format!("bind {a}: {e}"))?;
        s.set_nonblocking(true).map_err(|e| e.to_string())?;
        let std: std::net::UdpSocket = s.into();
        #[cfg(windows)]
        disable_udp_connreset(&std);
        port = std.local_addr().map_err(|e| e.to_string())?.port(); // port 0: the others share the chosen one
        out.push(std);
    }
    Ok(out)
}

/// Windows reports an ICMP port-unreachable for an earlier send as WSAECONNRESET on the next
/// receive of a UDP socket (`SIO_UDP_CONNRESET` off, as `base.disable_udp_connreset`).
#[cfg(windows)]
fn disable_udp_connreset(s: &std::net::UdpSocket) {
    use std::os::windows::io::AsRawSocket;
    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
    extern "system" {
        fn WSAIoctl(s: usize, code: u32, inb: *const u32, inl: u32, outb: *mut u8, outl: u32, ret: *mut u32,
                    ov: *mut u8, cr: *mut u8) -> i32;
    }
    let off: u32 = 0;
    let mut ret: u32 = 0;
    unsafe {
        WSAIoctl(s.as_raw_socket() as usize, SIO_UDP_CONNRESET, &off, 4, std::ptr::null_mut(), 0, &mut ret,
                 std::ptr::null_mut(), std::ptr::null_mut());
    }
}

/// A TCP listener for `addr` with SO_REUSEADDR (and SO_REUSEPORT on Linux when asked).
pub fn tcp_listener(a: SocketAddr, reuseport: bool) -> Result<std::net::TcpListener, String> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::for_address(a), Type::STREAM, Some(Protocol::TCP)).map_err(|e| e.to_string())?;
    #[cfg(not(windows))]
    let _ = s.set_reuse_address(true);   // Windows: SO_REUSEADDR would let another process steal the port
    #[cfg(target_os = "linux")]
    if reuseport {
        let _ = s.set_reuse_port(true);
    }
    let _ = reuseport;
    s.bind(&a.into()).map_err(|e| format!("bind {a}: {e}"))?;
    s.listen(1024).map_err(|e| e.to_string())?;
    s.set_nonblocking(true).map_err(|e| e.to_string())?;
    Ok(s.into())
}
