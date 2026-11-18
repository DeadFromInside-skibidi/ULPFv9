"""
Syslog output: RFC 5424, LEEF (QRadar), CEF (ArcSight), JSON lines, or the raw
original line (``format: raw``, forwarding selected events at their source size) over
UDP, TCP or TLS. TCP/TLS use RFC 6587 octet counting (as RFC 5425 requires
for TLS), so messages containing newlines stay intact.
"""
from __future__ import annotations

import socket
import ssl

import orjson

from ulpf.engine.views import apply_view
from ulpf.ingestion.forwarder import SEV_TO_SYSLOG, format_rfc5424
from ulpf.runtime.buffer import Segment
from ulpf.runtime.retry import RetriableError
from ulpf.runtime.sinks.base import Sink, client_ssl_context
from ulpf import __version__

_PRODUCT_VERSION = ".".join(__version__.split(".")[:2])   # CEF/LEEF "device version" field

_MAX_UDP = 65000


def _cef_esc_header(v) -> str:
    return str(v if v is not None else "").replace("\\", "\\\\").replace("|", "\\|")


def _cef_esc_ext(v) -> str:
    return (str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n"))


def _common(e: dict) -> dict:
    src, dst = e.get("source") or {}, e.get("destination") or {}
    net, user = e.get("network") or {}, e.get("user") or {}
    return {"src": src.get("ip"), "dst": dst.get("ip"), "spt": src.get("port"), "dpt": dst.get("port"),
            "proto": net.get("protocol"), "suser": user.get("name"), "act": e.get("action"),
            "cat": e.get("category"), "msg": e.get("message"), "rt": e.get("timestamp"),
            "externalId": e.get("event_id"), "cs1": (e.get("evidence") or {}).get("raw_hash"),
            "cs1Label": "rawSha256", "cs2": e.get("raw_format"), "cs2Label": "ulpfFormat"}


def format_cef(e: dict) -> bytes:
    sev = int(e.get("severity") or 0)
    ext = " ".join(f"{k}={_cef_esc_ext(v)}" for k, v in _common(e).items() if v not in (None, ""))
    head = "|".join(_cef_esc_header(x) for x in ("CEF:0", "ULPF", "ULPF", _PRODUCT_VERSION,
                                                    e.get("event_type") or e.get("category") or "event",
                                                    (e.get("message") or e.get("action") or "event")[:128], sev))
    return f"{head}|{ext}".encode("utf-8", "replace")


def format_leef(e: dict) -> bytes:
    c = _common(e)
    attrs = {"devTime": c["rt"], "devTimeFormat": "yyyy-MM-dd'T'HH:mm:ss.SSSXXX", "src": c["src"],
             "dst": c["dst"], "srcPort": c["spt"], "dstPort": c["dpt"], "proto": c["proto"],
             "usrName": c["suser"], "sev": e.get("severity"), "cat": c["cat"], "action": c["act"],
             "msg": c["msg"], "ulpfEventId": e.get("event_id"), "ulpfRawSha256": c["cs1"],
             "ulpfFormat": c["cs2"]}
    body = "\t".join(f"{k}={str(v).replace(chr(9), ' ')}" for k, v in attrs.items() if v not in (None, ""))
    eid = e.get("event_type") or e.get("category") or "event"
    return f"LEEF:1.0|ULPF|ULPF|{_PRODUCT_VERSION}|{eid}|{body}".encode("utf-8", "replace")


class SyslogSink(Sink):
    def __init__(self, name, options, context=None):
        super().__init__(name, options, context)
        self._sock = None

    def encode(self, events: list[dict]) -> bytes:
        fmt = self.opts.get("format", "rfc5424")
        out = []
        for e in events:
            if fmt == "raw":
                # The original line as received: the SIEM parses (and bills) it as if the device
                # had sent it directly. ULPF keeps the normalised copy and the journal locally.
                msg = (e.get("raw_event") or "").encode("utf-8", "replace")
            elif fmt == "cef":
                msg = format_cef(e)
            elif fmt == "leef":
                msg = format_leef(e)
            elif fmt == "json":
                msg = orjson.dumps(apply_view(e, self.view), default=str)
            else:
                msg = format_rfc5424(e, body=apply_view(e, self.view) if self.view != "unified" else None)
            if fmt in ("cef", "leef", "json"):
                sev = SEV_TO_SYSLOG.get(int(e.get("severity") or 0), 6)
                host = ((e.get("device") or {}).get("hostname") or "ulpf").replace(" ", "_")
                msg = f"<{16 * 8 + sev}>1 {e.get('timestamp') or '-'} {host} ULPF - - - ".encode() + msg
            out.append(msg)
        # One record per frame; frames are length-prefixed so newlines inside messages survive
        return b"".join(str(len(m)).encode() + b" " + m for m in out)

    def records(self, payload: bytes) -> list[bytes]:
        out, i = [], 0
        while i < len(payload):
            sp = payload.index(b" ", i)
            n = int(payload[i:sp])
            out.append(payload[sp + 1:sp + 1 + n])
            i = sp + 1 + n
        return out

    def _connect(self):
        o = self.opts
        if o["protocol"] == "udp":
            fam = socket.AF_INET6 if ":" in o["host"] else socket.AF_INET
            return socket.socket(fam, socket.SOCK_DGRAM)
        s = socket.create_connection((o["host"], o["port"]), timeout=30)
        if o["protocol"] == "tls":
            ctx = client_ssl_context(o.get("tls")) or ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=(o.get("tls") or {}).get("server_name") or o["host"])
        return s

    def deliver(self, payload: bytes, seg: Segment) -> None:
        o = self.opts
        try:
            if self._sock is None:
                self._sock = self._connect()
            if o["protocol"] == "udp":
                for m in self.records(payload):
                    self._sock.sendto(m[:_MAX_UDP], (o["host"], o["port"]))
            else:
                self._sock.sendall(payload)
        except OSError as e:
            self.close()
            raise RetriableError(f"syslog {o['host']}:{o['port']}: {e}") from e

    def health(self) -> dict:
        return {"ok": True, "connected": self._sock is not None}

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
