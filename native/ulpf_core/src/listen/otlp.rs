//! OTLP logs over gRPC (`opentelemetry.proto.collector.logs.v1.LogsService/Export`).
//!
//! The ExportLogsServiceRequest is decoded as the HTTP input decodes it
//! (`ulpf.runtime.inputs.http.otlp_protobuf_records` + `otlp_to_records`), so a
//! log record is journaled as the same bytes whichever transport delivered it:
//! a non-empty string body as it is, anything else as compact JSON of the
//! record (+ resource). Records are grouped by source: service.name, else the
//! log file path, else host.name, else the client address. Requests may be
//! gzip-compressed; `api_key` (when set) must arrive as `authorization: Bearer`.

use super::json::{dumps, Obj};
use super::{addr, opt_str, opt_u64, tcp_listener, Out, Shared};
use serde_json::Value as J;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::{Request, Response, Status};

type R<T> = Result<T, String>;

// ---------------------------------------------------------------------------
// Protobuf (the HTTP input's decoder)
// ---------------------------------------------------------------------------

enum F<'a> {
    V(u64),
    B(&'a [u8]),
}

fn varint(b: &[u8], i: &mut usize) -> R<u64> {
    let (mut shift, mut result) = (0u32, 0u128);
    loop {
        let c = *b.get(*i).ok_or("index out of range")?;
        *i += 1;
        result |= ((c & 0x7f) as u128) << shift;
        if c & 0x80 == 0 {
            // Python ints are unbounded; the decoded fields are at most 64 bits wide
            return u64::try_from(result & u64::MAX as u128).map_err(|e| e.to_string());
        }
        shift += 7;
        if shift > 70 {
            return Err("varint too long".into());
        }
    }
}

fn sl(b: &[u8], a: usize, e: usize) -> &[u8] {
    let a = a.min(b.len());
    &b[a..e.clamp(a, b.len())]
}

/// `_fields`: (field number, value)
fn fields(b: &[u8]) -> R<Vec<(u64, F<'_>)>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let key = varint(b, &mut i)?;
        let (fnum, wt) = (key >> 3, key & 7);
        let v = match wt {
            0 => F::V(varint(b, &mut i)?),
            1 => {
                let v = sl(b, i, i + 8);
                i += 8;
                F::B(v)
            }
            2 => {
                let ln = varint(b, &mut i)? as usize;
                let v = sl(b, i, i.saturating_add(ln));
                i = i.saturating_add(ln);
                F::B(v)
            }
            5 => {
                let v = sl(b, i, i + 4);
                i += 4;
                F::B(v)
            }
            w => return Err(format!("unsupported protobuf wire type {w}")),
        };
        out.push((fnum, v));
    }
    Ok(out)
}

fn bytes<'a>(f: &F<'a>) -> R<&'a [u8]> {
    match f {
        F::B(b) => Ok(b),
        F::V(_) => Err("a bytes-like object is required, not 'int'".into()),
    }
}

fn text(f: &F) -> R<String> {
    Ok(String::from_utf8_lossy(bytes(f)?).into_owned())
}

fn fixed64(f: &F) -> R<u64> {
    let b = bytes(f)?;
    b.try_into().map(u64::from_le_bytes).map_err(|_| "unpack requires a buffer of 8 bytes".into())
}

fn any_value(b: &[u8]) -> R<J> {
    for (fnum, v) in fields(b)? {
        match fnum {
            1 => return Ok(J::from(text(&v)?)),
            2 => return Ok(J::from(match v { F::V(x) => x != 0, F::B(b) => !b.is_empty() })),
            3 => {
                let x = match v { F::V(x) => x, F::B(_) => return Err("'<=' not supported".into()) };
                return Ok(if x >= 1 << 63 { J::from(x as i64) } else { J::from(x) });
            }
            4 => {
                let b = bytes(&v)?;
                let f = f64::from_le_bytes(b.try_into().map_err(|_| "unpack requires a buffer of 8 bytes")?);
                return Ok(serde_json::Number::from_f64(f).map(J::Number).unwrap_or(J::Null));
            }
            5 => {
                let mut out = Vec::new();
                for (f2, x) in fields(bytes(&v)?)? {
                    if f2 == 1 {
                        out.push(any_value(bytes(&x)?)?);
                    }
                }
                return Ok(J::Array(out));
            }
            6 => {
                let mut m = Obj::default();
                for (f2, x) in fields(bytes(&v)?)? {
                    if f2 == 1 {
                        let (k, val) = kv(bytes(&x)?)?;
                        m.set(&k, val);
                    }
                }
                return Ok(m.into_value());
            }
            7 => return Ok(J::from(hex::encode(bytes(&v)?))),
            _ => {}
        }
    }
    Ok(J::Null)
}

fn kv(b: &[u8]) -> R<(String, J)> {
    let (mut key, mut val) = (String::new(), J::Null);
    for (fnum, v) in fields(b)? {
        match fnum {
            1 => key = text(&v)?,
            2 => val = any_value(bytes(&v)?)?,
            _ => {}
        }
    }
    Ok((key, val))
}

fn log_record(b: &[u8]) -> R<Obj> {
    let mut r = Obj::default();
    let mut attrs = Obj::default();
    r.set("attributes", J::Object(Default::default()));
    for (fnum, v) in fields(b)? {
        match fnum {
            1 => r.set("time_unix_nano", fixed64(&v)?),
            11 => r.set("observed_time_unix_nano", fixed64(&v)?),
            2 => r.set("severity_number", match v { F::V(x) => J::from(x), F::B(_) => return Err("severity".into()) }),
            3 => r.set("severity_text", text(&v)?),
            5 => r.set("body", any_value(bytes(&v)?)?),
            6 => {
                let (k, val) = kv(bytes(&v)?)?;
                attrs.set(&k, val);
            }
            9 => r.set("trace_id", hex::encode(bytes(&v)?)),
            10 => r.set("span_id", hex::encode(bytes(&v)?)),
            12 => r.set("event_name", text(&v)?),
            _ => {}
        }
    }
    r.set("attributes", attrs.into_value());
    Ok(r)
}

/// `otlp_protobuf_records`: [(resource attributes, log record)]
pub fn records(body: &[u8]) -> R<Vec<(Obj, Obj)>> {
    let mut out = Vec::new();
    for (fnum, rl) in fields(body)? {
        if fnum != 1 {
            continue;
        }
        let mut resource = Obj::default();
        let mut scopes = Vec::new();
        for (f2, v) in fields(bytes(&rl)?)? {
            if f2 == 1 {
                let mut res = Obj::default();
                for (f3, a) in fields(bytes(&v)?)? {
                    if f3 == 1 {
                        let (k, val) = kv(bytes(&a)?)?;
                        res.set(&k, val);
                    }
                }
                resource = res;
            } else if f2 == 2 {
                scopes.push(bytes(&v)?);
            }
        }
        for sl_ in scopes {
            for (f3, v) in fields(sl_)? {
                if f3 == 2 {
                    out.push((resource.clone(), log_record(bytes(&v)?)?));
                }
            }
        }
    }
    Ok(out)
}

/// Python truthiness of a JSON value.
fn truthy(v: &J) -> bool {
    match v {
        J::Null => false,
        J::Bool(b) => *b,
        J::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        J::String(s) => !s.is_empty(),
        J::Array(a) => !a.is_empty(),
        J::Object(m) => !m.is_empty(),
    }
}

/// Python `repr()` of a JSON value (for `str()` of a container source).
fn py_repr(v: &J, out: &mut String) {
    match v {
        J::Null => out.push_str("None"),
        J::Bool(true) => out.push_str("True"),
        J::Bool(false) => out.push_str("False"),
        J::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => out.push_str(&i.to_string()),
            (_, Some(u)) => out.push_str(&u.to_string()),
            _ => out.push_str(&crate::val::py_float_repr(n.as_f64().unwrap_or(0.0))),
        },
        J::String(s) => {
            let q = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
            out.push(q);
            for c in s.chars() {
                match c {
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if c == q => {
                        out.push('\\');
                        out.push(c);
                    }
                    c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\x{:02x}", c as u32)),
                    c => out.push(c),
                }
            }
            out.push(q);
        }
        J::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                py_repr(x, out);
            }
            out.push(']');
        }
        J::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                py_repr(&J::String(k.clone()), out);
                out.push_str(": ");
                py_repr(x, out);
            }
            out.push('}');
        }
    }
}

fn py_str(v: &J) -> String {
    match v {
        J::String(s) => s.clone(),
        J::Number(n) if n.as_f64().is_some() && n.as_i64().is_none() && n.as_u64().is_none() =>
            crate::val::py_float_repr(n.as_f64().unwrap()),
        other => {
            let mut s = String::new();
            py_repr(other, &mut s);
            s
        }
    }
}

/// `otlp_to_records`: journal records grouped by source, in first-seen order.
pub fn to_records(pairs: Vec<(Obj, Obj)>, fallback: &str) -> Vec<(String, Vec<Vec<u8>>)> {
    let mut by: Vec<(String, Vec<Vec<u8>>)> = Vec::new();
    for (resource, rec) in pairs {
        let attrs = rec.0.get("attributes").cloned().unwrap_or(J::Null);
        let pick = [resource.0.get("service.name"), attrs.get("log.file.path"), resource.0.get("host.name")]
            .into_iter().flatten().find(|v| truthy(v)).map(py_str).unwrap_or_else(|| fallback.to_string());
        let raw = match rec.0.get("body") {
            // str.strip(): Unicode White_Space plus \x1c-\x1f (str.isspace)
            Some(J::String(s)) if !s.trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c))
                .is_empty() => s.as_bytes().to_vec(),
            _ => {
                let mut doc = Obj::default();
                for (k, v) in &rec.0 {
                    let empty = matches!(v, J::Null) || matches!(v, J::Object(m) if m.is_empty())
                        || matches!(v, J::Array(a) if a.is_empty());
                    if !empty {
                        doc.set(k, v.clone());
                    }
                }
                if !resource.0.is_empty() {
                    doc.set("resource", resource.into_value());
                }
                dumps(&doc.into_value())
            }
        };
        match by.iter_mut().find(|(s, _)| *s == pick) {
            Some((_, v)) => v.push(raw),
            None => by.push((pick, vec![raw])),
        }
    }
    by
}

// ---------------------------------------------------------------------------
// gRPC
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct RawCodec;

struct RawEnc;
struct RawDec;

impl Encoder for RawEnc {
    type Item = Vec<u8>;
    type Error = Status;
    fn encode(&mut self, item: Vec<u8>, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        use bytes::BufMut;
        dst.put_slice(&item);
        Ok(())
    }
}

impl Decoder for RawDec {
    type Item = Vec<u8>;
    type Error = Status;
    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Vec<u8>>, Status> {
        use bytes::Buf;
        let mut v = vec![0u8; src.remaining()];
        src.copy_to_slice(&mut v);
        Ok(Some(v))
    }
}

impl Codec for RawCodec {
    type Encode = Vec<u8>;
    type Decode = Vec<u8>;
    type Encoder = RawEnc;
    type Decoder = RawDec;
    fn encoder(&mut self) -> RawEnc {
        RawEnc
    }
    fn decoder(&mut self) -> RawDec {
        RawDec
    }
}

#[derive(Clone)]
struct Logs {
    sh: Arc<Shared>,
    api_key: Option<Arc<String>>,
    max_bytes: usize,
}

const PATH: &str = "/opentelemetry.proto.collector.logs.v1.LogsService/Export";

impl tonic::server::NamedService for Logs {
    const NAME: &'static str = "opentelemetry.proto.collector.logs.v1.LogsService";
}

struct Export(Logs);

impl tonic::server::UnaryService<Vec<u8>> for Export {
    type Response = Vec<u8>;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Vec<u8>>, Status>> + Send>>;

    fn call(&mut self, req: Request<Vec<u8>>) -> Self::Future {
        let logs = self.0.clone();
        Box::pin(async move {
            if let Some(key) = &logs.api_key {
                let ok = req.metadata().get("authorization").and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer ")).map(|v| constant_eq(v.as_bytes(), key.as_bytes()))
                    .unwrap_or(false);
                if !ok {
                    logs.sh.stats.auth_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Err(Status::unauthenticated("a valid API key is required"));
                }
            }
            let client = req.remote_addr().map(|a| super::peer_text(&a)).unwrap_or_else(|| "otlp".into());
            let body = req.into_inner();
            logs.sh.stats.bytes.fetch_add(body.len() as u64, std::sync::atomic::Ordering::Relaxed);
            let pairs = records(&body).map_err(|e| {
                logs.sh.stats.error(format!("{client}: invalid OTLP payload: {e}"));
                Status::invalid_argument(format!("invalid OTLP payload: {e}"))
            })?;
            for (source, recs) in to_records(pairs, &client) {
                logs.sh.send(Out { input: None, source, records: recs, ts: super::now() }).await;
            }
            Ok(Response::new(Vec::new()))   // an empty ExportLogsServiceResponse: everything accepted
        })
    }
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl<B> tower_service::Service<http::Request<B>> for Logs
where
    B: http_body::Body<Data = bytes::Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send + 'static,
{
    type Response = http::Response<tonic::body::BoxBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let logs = self.clone();
        if req.uri().path() == PATH {
            Box::pin(async move {
                let mut grpc = tonic::server::Grpc::new(RawCodec)
                    .accept_compressed(tonic::codec::CompressionEncoding::Gzip)
                    .apply_max_message_size_config(Some(logs.max_bytes), None);
                Ok(grpc.unary(Export(logs), req).await)
            })
        } else {
            Box::pin(async move { Ok(Status::unimplemented("only LogsService/Export is served").into_http()) })
        }
    }
}

pub fn start(cfg: &J, sh: Arc<Shared>) -> R<u16> {
    let a = addr(cfg)?;
    let l = tcp_listener(a, false)?;
    let port = l.local_addr().map_err(|e| e.to_string())?.port();
    let listener = tokio::net::TcpListener::from_std(l).map_err(|e| e.to_string())?;
    let incoming = tonic::transport::server::TcpIncoming::from_listener(listener, true, None)
        .map_err(|e| e.to_string())?;
    let logs = Logs { sh: sh.clone(), api_key: opt_str(cfg, "api_key").map(|s| Arc::new(s.to_string())),
                      max_bytes: (opt_u64(cfg, "max_body_mb", 16).max(1) as usize) << 20 };
    let mut builder = tonic::transport::Server::builder();
    if let Some(tls) = cfg.get("tls").filter(|t| t.get("cert").is_some()) {
        let read = |k: &str| -> R<Option<Vec<u8>>> {
            match opt_str(tls, k) {
                Some(p) => std::fs::read(p).map(Some).map_err(|e| format!("tls {k} {p}: {e}")),
                None => Ok(None),
            }
        };
        let cert = read("cert")?.unwrap();
        let key = read("key")?.unwrap_or_else(|| cert.clone());
        let mut t = tonic::transport::ServerTlsConfig::new().identity(tonic::transport::Identity::from_pem(cert, key));
        if let Some(ca) = read("client_ca")? {
            t = t.client_ca_root(tonic::transport::Certificate::from_pem(ca));
        }
        builder = builder.tls_config(t).map_err(|e| format!("otlp tls: {e}"))?;
    }
    let mut stop = sh.stop.clone();
    let router = builder.add_service(logs);
    tokio::spawn(async move {
        let shutdown = async move {
            let _ = stop.changed().await;
        };
        if let Err(e) = router.serve_with_incoming_shutdown(incoming, shutdown).await {
            sh.stats.error(format!("otlp server: {e}"));
        }
    });
    Ok(port)
}

/// Decode an ExportLogsServiceRequest into journal records (for the equivalence tests).
pub fn decode_request(body: &[u8], fallback: &str) -> R<Vec<(String, Vec<Vec<u8>>)>> {
    Ok(to_records(records(body)?, fallback))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(mut n: u64, out: &mut Vec<u8>) {
        loop {
            let b = (n & 0x7f) as u8;
            n >>= 7;
            out.push(if n != 0 { b | 0x80 } else { b });
            if n == 0 {
                return;
            }
        }
    }

    fn field(f: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        varint((f << 3) | 2, &mut out);
        varint(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        out
    }

    fn request(service: &str, bodies: &[&str]) -> Vec<u8> {
        let kv = [field(1, b"service.name"), field(2, &field(1, service.as_bytes()))].concat();
        let resource = field(1, &kv);
        let logs: Vec<u8> = bodies.iter().map(|b| field(2, &field(5, &field(1, b.as_bytes())))).collect::<Vec<_>>().concat();
        field(1, &[field(1, &resource), field(2, &logs)].concat())
    }

    /// A tonic client exports gzip-compressed logs with a bearer key; a wrong key is refused.
    #[test]
    fn grpc_export_end_to_end() {
        let cfg = serde_json::json!({"kind": "otlp_grpc", "host": "127.0.0.1", "port": 0, "api_key": "s3cret"});
        let h = crate::listen::start(&cfg).unwrap();
        let port = h.bound_port;
        let path = http::uri::PathAndQuery::from_static(PATH);
        let send = |key: &'static str, body: Vec<u8>| {
            let path = path.clone();
            h.rt.block_on(async move {
                let ch = tonic::transport::Channel::from_shared(format!("http://127.0.0.1:{port}")).unwrap()
                    .connect().await.unwrap();
                let mut g = tonic::client::Grpc::new(ch).send_compressed(tonic::codec::CompressionEncoding::Gzip);
                g.ready().await.unwrap();
                let mut req = Request::new(body);
                req.metadata_mut().insert("authorization", format!("Bearer {key}").parse().unwrap());
                g.unary(req, path, RawCodec).await.map(|r| r.into_inner())
            })
        };
        let ok = send("s3cret", request("checkout", &["order placed", "payment failed"]));
        assert_eq!(ok.unwrap(), Vec::<u8>::new());
        let denied = send("wrong", request("x", &["nope"]));
        assert_eq!(denied.unwrap_err().code(), tonic::Code::Unauthenticated);
        let out = h.rt.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(5), h.rx.lock().unwrap().recv()).await
        }).unwrap().unwrap();
        assert_eq!(out.source, "checkout");
        assert_eq!(out.records, vec![b"order placed".to_vec(), b"payment failed".to_vec()]);
        let _ = h.stop.send(true);
    }
}
