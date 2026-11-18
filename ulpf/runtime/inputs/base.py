"""
Input interface.

An input runs ``run(stop)`` in its own thread until ``stop`` is set; if it
raises, the supervisor restarts it with exponential backoff. It hands raw
records to ``ctx.ingest(source, raws)``, which journals them (durable) and
dispatches them to the workers. ``ingest`` blocks when the pipeline is
saturated — inputs with flow control (TCP, files, Kafka, HTTP) slow down,
and inputs without it (UDP) count what they cannot accept.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time

logger = logging.getLogger(__name__)


class InputStats:
    __slots__ = ("received", "ingested", "bytes", "dropped_rate_limit", "dropped_overflow",
                 "dropped_denied", "dropped_oversize", "errors", "connections", "restarts",
                 "last_error", "last_record")

    def __init__(self):
        for k in self.__slots__:
            setattr(self, k, 0)
        self.last_error = None
        self.last_record = None

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}


class SourceFilter:
    """allow_sources: CIDR allow-list for network inputs (empty = allow all)."""

    def __init__(self, cidrs: list[str]):
        self.nets = [ipaddress.ip_network(c, strict=False) for c in cidrs or []]

    def allowed(self, ip: str) -> bool:
        if not self.nets:
            return True
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.nets)


class RateLimiter:
    """Per-source token bucket. ``take`` returns how many of n records are admitted."""

    def __init__(self, eps: float):
        self.eps = float(eps or 0)
        self._buckets: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def take(self, source: str, n: int) -> int:
        if self.eps <= 0:
            return n
        now = time.monotonic()
        with self._lock:
            b = self._buckets.get(source)
            if b is None:
                b = self._buckets[source] = [self.eps, now]
                if len(self._buckets) > 100_000:
                    self._buckets.clear()
            tokens = min(self.eps, b[0] + (now - b[1]) * self.eps)
            admitted = min(n, int(tokens))
            b[0], b[1] = tokens - admitted, now
            return admitted

    def wait_time(self, source: str, n: int) -> float:
        return 0.0 if self.eps <= 0 else n / self.eps


def disable_udp_connreset(sock) -> None:
    """Windows reports an ICMP port-unreachable for an earlier ``sendto`` as WSAECONNRESET on
    the next ``recvfrom`` of a UDP socket; a listener must not stop because one peer went away."""
    import socket
    if hasattr(socket, "SIO_UDP_CONNRESET"):
        try:
            sock.ioctl(socket.SIO_UDP_CONNRESET, False)
        except (OSError, ValueError):
            pass


def udp_socket(host: str, port: int, rcvbuf: int = 8 * 2**20):
    import socket
    sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    except OSError:
        pass
    disable_udp_connreset(sock)
    sock.bind((host, port))
    sock.settimeout(0.5)
    return sock


class Input:
    """Base class. Subclasses implement ``run(stop)``."""

    def __init__(self, name: str, options: dict, ctx):
        self.name = name
        self.opts = options
        self.ctx = ctx
        self.stats = InputStats()
        self.filter = SourceFilter(options.get("allow_sources") or [])
        self.max_line = int(options.get("max_line_bytes", 1024 * 1024))
        self.last_seq: int | None = None    # journal sequence of the last record this input journaled

    def run(self, stop: threading.Event) -> None:
        raise NotImplementedError

    def accept(self, source: str, raws: list[bytes], recv_ts: float | None = None,
               block: bool = True, input_name: str | None = None) -> int:
        """Size-check, rate-limit and ingest records. Returns how many were accepted.
        ``input_name``: journal them under another input (TLS SNI routing)."""
        st = self.stats
        st.received += len(raws)
        if self.max_line:
            kept = [r for r in raws if len(r) <= self.max_line]
            st.dropped_oversize += len(raws) - len(kept)
            raws = kept
        if not raws:
            return 0
        n = self.ctx.rate_limiter(self.name).take(source, len(raws))
        if n < len(raws):
            if block:
                # Flow-controlled inputs wait for tokens instead of dropping
                time.sleep(min(1.0, self.ctx.rate_limiter(self.name).wait_time(source, len(raws) - n)))
                n = len(raws)
            else:
                st.dropped_rate_limit += len(raws) - n
                raws = raws[:n]
        if not raws:
            return 0
        first = self.ctx.ingest(input_name or self.name, source, raws, recv_ts)
        self.last_seq = first + len(raws) - 1
        st.ingested += len(raws)
        st.bytes += sum(len(r) for r in raws)
        st.last_record = time.time()
        return len(raws)

    def describe(self) -> dict:
        return {"name": self.name, "type": self.opts.get("type"), **self.stats.to_dict()}
