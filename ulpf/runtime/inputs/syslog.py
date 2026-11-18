"""
Syslog input: UDP (RFC 5426), TCP (RFC 6587) and TLS (RFC 5425).

TCP and TLS accept newline-delimited and octet-counted framing
(``<len> <msg>``), detected per connection. Records are the exact frame
bytes (without the delimiter), so the journal keeps what the device sent.

Socket callbacks run on an asyncio loop; a feeder thread does the blocking
ingest. When the hand-off queue fills, TCP/TLS connections pause reading
(flow control back to the sender) and UDP datagrams are counted as dropped
(UDP has no flow control).
"""
from __future__ import annotations

import asyncio
import logging
import queue
import re
import ssl
import threading
import time

from ulpf.runtime.inputs.base import Input, disable_udp_connreset

logger = logging.getLogger(__name__)

_OCTET = re.compile(rb"^(\d{1,7}) ")
_MAX_FRAME = 1024 * 1024
_FLUSH_SECONDS = 0.05
_BATCH = 1000


def server_ssl_context(tls: dict) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(tls["cert"], tls.get("key") or None)
    if tls.get("client_ca"):
        ctx.load_verify_locations(tls["client_ca"])
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


class _Batcher:
    """Collects records per source and hands full or aged batches to the feeder queue."""

    def __init__(self, inp: "SyslogInput"):
        self.inp = inp
        self.pending: dict[str, list[bytes]] = {}
        self.first_at: dict[str, float] = {}

    def add(self, source: str, rec: bytes) -> None:
        lst = self.pending.get(source)
        if lst is None:
            lst = self.pending[source] = []
            self.first_at[source] = time.monotonic()
        lst.append(rec)
        if len(lst) >= _BATCH:
            self.flush(source)

    def flush(self, source: str | None = None) -> None:
        keys = [source] if source else list(self.pending)
        for k in keys:
            lst = self.pending.pop(k, None)
            self.first_at.pop(k, None)
            if lst:
                self.inp.handoff(k, lst)

    def flush_aged(self) -> None:
        now = time.monotonic()
        for k, t in list(self.first_at.items()):
            if now - t >= _FLUSH_SECONDS:
                self.flush(k)


class _Udp(asyncio.DatagramProtocol):
    def __init__(self, inp: "SyslogInput", batcher: _Batcher):
        self.inp, self.b = inp, batcher

    def datagram_received(self, data: bytes, addr) -> None:
        st = self.inp.stats
        ip = addr[0]
        if not self.inp.filter.allowed(ip):
            st.dropped_denied += 1
            return
        if self.inp.opts.get("telemetry", "none") != "none":
            if data:
                self.b.add(ip, data)          # binary telemetry frame: one datagram, bytes untouched
            return
        # One datagram is one message (RFC 5426); some senders pack several lines
        for rec in data.splitlines() if b"\n" in data.rstrip(b"\r\n") else (data.rstrip(b"\r\n"),):
            if rec.strip():
                self.b.add(ip, rec)


class _Tcp(asyncio.Protocol):
    def __init__(self, inp: "SyslogInput", batcher: _Batcher, framing: str):
        self.inp, self.b, self.framing = inp, batcher, framing
        self.buf = b""
        self.octet: bool | None = None if framing == "auto" else framing == "octet"
        self.ip = ""

    def connection_made(self, transport) -> None:
        self.transport = transport
        peer = transport.get_extra_info("peername") or ("", 0)
        self.ip = peer[0]
        if not self.inp.filter.allowed(self.ip):
            self.inp.stats.dropped_denied += 1
            transport.close()
            return
        self.inp.stats.connections += 1
        self.inp.register_transport(transport)

    def data_received(self, data: bytes) -> None:
        self.buf += data
        if self.octet is None:
            if _OCTET.match(self.buf):
                self.octet = True
            elif len(self.buf) < 9 and self.buf[:1].isdigit() and b" " not in self.buf:
                return
            else:
                self.octet = False
        if self.octet:
            self._octets()
        else:
            self._lines()
        if len(self.buf) > _MAX_FRAME:
            self.inp.stats.dropped_oversize += 1
            self.buf = b""

    def _lines(self) -> None:
        buf = self.buf
        pos = 0
        while True:
            nl = buf.find(b"\n", pos)
            if nl < 0:
                break
            rec = buf[pos:nl].rstrip(b"\r")
            if rec.strip():
                self.b.add(self.ip, rec)
            pos = nl + 1
        self.buf = buf[pos:]

    def _octets(self) -> None:
        while self.buf:
            m = _OCTET.match(self.buf)
            if not m:
                self.octet = False
                self._lines()
                return
            n = int(m.group(1))
            start = m.end()
            if n <= 0 or n > _MAX_FRAME:
                self.octet = False
                self._lines()
                return
            if len(self.buf) < start + n:
                return
            rec = self.buf[start:start + n].rstrip(b"\r\n")
            self.buf = self.buf[start + n:]
            if rec.strip():
                self.b.add(self.ip, rec)

    def connection_lost(self, exc) -> None:
        if self.buf.strip():
            self.b.add(self.ip, self.buf.rstrip(b"\r\n"))
        self.buf = b""
        self.b.flush(self.ip)
        self.inp.unregister_transport(getattr(self, "transport", None))


class SyslogInput(Input):
    def __init__(self, name, options, ctx):
        super().__init__(name, options, ctx)
        self.q: queue.Queue = queue.Queue(maxsize=256)
        self._transports: set = set()
        self._paused = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self.bound_port: int | None = None

    # ---- loop side ----------------------------------------------------
    def register_transport(self, t) -> None:
        self._transports.add(t)
        if self._paused:
            t.pause_reading()

    def unregister_transport(self, t) -> None:
        self._transports.discard(t)

    def handoff(self, source: str, records: list[bytes]) -> None:
        try:
            self.q.put_nowait((source, records, time.time()))
        except queue.Full:
            if self.opts["protocol"] == "udp":
                self.stats.dropped_overflow += len(records)
                self.stats.received += len(records)
                return
            # TCP/TLS: never drop — wait briefly, and pause every connection meanwhile
            self._pause()
            self.q.put((source, records, time.time()))
        if self.q.qsize() > self.q.maxsize * 0.8:
            self._pause()

    def _pause(self) -> None:
        if not self._paused:
            self._paused = True
            for t in list(self._transports):
                try:
                    t.pause_reading()
                except Exception:
                    pass

    def _maybe_resume(self) -> None:
        if self._paused and self.q.qsize() < self.q.maxsize * 0.3:
            self._paused = False
            for t in list(self._transports):
                try:
                    t.resume_reading()
                except Exception:
                    pass

    # ---- feeder -------------------------------------------------------
    def _feed(self, stop: threading.Event) -> None:
        proto = self.opts["protocol"]
        while not (stop.is_set() and self.q.empty()):
            try:
                source, recs, ts = self.q.get(timeout=0.2)
            except queue.Empty:
                continue
            self.accept(source, recs, ts, block=proto != "udp")
            if self._paused and self._loop is not None:
                self._loop.call_soon_threadsafe(self._maybe_resume)

    # ---- lifecycle ----------------------------------------------------
    def run(self, stop: threading.Event) -> None:
        feeder = threading.Thread(target=self._feed, args=(stop,), name=f"ulpf-in-{self.name}-feed",
                                  daemon=True)
        feeder.start()
        loop = asyncio.new_event_loop()
        self._loop = loop
        try:
            loop.run_until_complete(self._serve(stop))
        finally:
            loop.close()
            self._loop = None
            feeder.join(10)

    async def _serve(self, stop: threading.Event) -> None:
        loop = asyncio.get_running_loop()
        o = self.opts
        batcher = _Batcher(self)
        servers = []
        if o["protocol"] == "udp":
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _Udp(self, batcher), local_addr=(o["host"], o["port"]))
            sock = transport.get_extra_info("socket")
            try:
                import socket
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            except OSError:
                pass
            disable_udp_connreset(sock)
            self.bound_port = sock.getsockname()[1]
            servers.append(transport)
        else:
            ssl_ctx = server_ssl_context(o["tls"]) if o["protocol"] == "tls" else None
            server = await loop.create_server(lambda: _Tcp(self, batcher, o.get("framing", "auto")),
                                              o["host"], o["port"], ssl=ssl_ctx, reuse_address=True)
            self.bound_port = server.sockets[0].getsockname()[1]
            servers.append(server)
        logger.info(f"input {self.name}: syslog {o['protocol']} on {o['host']}:{self.bound_port}")
        try:
            while not stop.is_set():
                await asyncio.sleep(_FLUSH_SECONDS / 2)
                batcher.flush_aged()
                self._maybe_resume()
        finally:
            for s in servers:
                s.close()
            for t in list(self._transports):
                t.close()
            await asyncio.sleep(0.05)
            batcher.flush()
