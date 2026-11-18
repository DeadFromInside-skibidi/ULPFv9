"""
SIEM Forwarder
===============
Forwards normalized events to a downstream SIEM / log collector as RFC 5424
syslog messages. The normalized event is carried as structured data plus a
JSON message body so receivers can index it without a custom parser.

UDP: one datagram per event (RFC 5426).
TCP: octet-counted framing (RFC 6587 §3.4.1), persistent connection with
     automatic reconnect.
"""
from __future__ import annotations

import logging
import socket
import threading
from datetime import datetime, timezone

import orjson

logger = logging.getLogger(__name__)

# ULPF 0-10 severity → syslog severity (0 = emergency … 7 = debug)
SEV_TO_SYSLOG = {0: 7, 1: 6, 2: 6, 3: 5, 4: 5, 5: 4, 6: 4, 7: 3, 8: 2, 9: 1, 10: 0}
_FACILITY_LOCAL0 = 16
_MAX_UDP = 65000


def _sd_escape(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def format_rfc5424(event: dict, app_name: str = "ULPF", body: dict | None = None) -> bytes:
    """Render one normalized event as an RFC 5424 syslog message.

    The header and structured data always come from the unified event;
    ``body`` (e.g. an ECS or OCSF view) replaces the JSON message if given.
    """
    sev = SEV_TO_SYSLOG.get(event.get("severity") or 0, 6)
    pri = _FACILITY_LOCAL0 * 8 + sev
    ts = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
    host = ((event.get("device") or {}).get("hostname") or "ulpf").replace(" ", "_")[:255]
    msgid = (event.get("category") or "-").replace(" ", "_")[:32]
    src = event.get("source") or {}
    dst = event.get("destination") or {}
    params = {
        "eid": event.get("event_id", "-"),
        "fmt": event.get("raw_format") or "unknown",
        "act": event.get("action") or "other",
        "sev": event.get("severity") or 0,
        "src": src.get("ip") or "-",
        "dst": dst.get("ip") or "-",
        "hash": (event.get("evidence") or {}).get("raw_hash") or "-",
    }
    sd = "[ulpf@32473 " + " ".join(f'{k}="{_sd_escape(v)}"' for k, v in params.items()) + "]"
    payload = orjson.dumps(event if body is None else body, default=str)
    return f"<{pri}>1 {ts} {host} {app_name} - {msgid} {sd} ".encode("utf-8", errors="replace") + payload


class SiemForwarder:
    """Thread-safe RFC 5424 forwarder over UDP or TCP."""

    def __init__(self, host: str, port: int = 514, proto: str = "udp", timeout: float = 5.0):
        self.host = host
        self.port = int(port)
        self.proto = proto.lower()
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()
        self.sent = 0
        self.errors = 0

    @classmethod
    def from_target(cls, target: str, proto: str = "udp") -> "SiemForwarder":
        host, _, port = target.rpartition(":")
        if not host:
            host, port = target, "514"
        return cls(host, int(port), proto)

    def _connect(self) -> socket.socket:
        if self.proto == "tcp":
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        else:
            sock = socket.socket(socket.AF_INET6 if ":" in self.host else socket.AF_INET, socket.SOCK_DGRAM)
        return sock

    def send(self, events: list[dict]) -> int:
        """Forward events; returns how many were handed to the transport."""
        if not events:
            return 0
        sent = 0
        with self._lock:
            for event in events:
                msg = format_rfc5424(event)
                for attempt in (1, 2):
                    try:
                        if self._sock is None:
                            self._sock = self._connect()
                        if self.proto == "tcp":
                            self._sock.sendall(str(len(msg)).encode() + b" " + msg)
                        else:
                            self._sock.sendto(msg[:_MAX_UDP], (self.host, self.port))
                        sent += 1
                        break
                    except OSError as e:
                        self._close_unlocked()
                        if attempt == 2:
                            self.errors += 1
                            logger.warning(f"SIEM forward to {self.host}:{self.port} failed: {e}")
            self.sent += sent
        return sent

    def _close_unlocked(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def close(self) -> None:
        with self._lock:
            self._close_unlocked()
