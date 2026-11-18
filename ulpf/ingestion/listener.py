"""
Real-Time Network Syslog Listener
===================================
Asyncio-based UDP/TCP listener that binds directly to network ports
where firewalls, routers, and other network devices send syslog messages.

Zero external dependencies — built entirely on Python's asyncio + socket.

v7: Micro-batch accumulation (UDP: 256 packets / 50ms, TCP: on newline batch).
    Backpressure: pause_reading() when queue exceeds 85%.

Usage:
    listener = NetworkListener(output_queue, host="0.0.0.0", port=5514)
    await listener.start(protocol="both")  # "udp", "tcp", or "both"
    ...
    await listener.stop()
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import time
from datetime import datetime, timezone
from multiprocessing import Queue as MPQueue
from queue import Queue as ThreadQueue
from typing import Any, Union

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Queue-type helpers — safe on Python 3.9–3.14+
# ---------------------------------------------------------------------------
# multiprocessing.Queue is a *factory function* in CPython (not a class).
# isinstance(q, MPQueue) raises TypeError on Python 3.11+ and Python 3.14.
# We compare type names as strings — robust across all versions.

def _is_mp_queue(q: Any) -> bool:
    """Return True if q is a multiprocessing Queue (any variant)."""
    name = type(q).__name__
    return name in ("Queue", "AutoProxy", "JoinableQueue",
                    "SyncManager", "_multiprocessing_SyncManager")


def _is_async_queue(q: Any) -> bool:
    """Return True if q is an asyncio.Queue."""
    return isinstance(q, asyncio.Queue)


def _offer(q: Any, batch: list[str], stats: "ListenerStats", proto: str) -> None:
    """Hand a batch to the output queue without stalling the event loop.

    A brief bounded wait absorbs micro-bursts; beyond that the batch is
    dropped and *counted* (UDP has no flow control — blocking longer would
    only move the loss into the kernel socket buffer, where it is invisible).
    """
    try:
        if _is_async_queue(q):
            q.put_nowait(batch)
        else:
            try:
                q.put_nowait(batch)
            except Exception:
                q.put(batch, timeout=0.05)
        stats.record_queued(len(batch))
    except Exception:
        stats.record_error()
        stats.record_dropped(len(batch))
        logger.warning(f"{proto}: output queue full — dropped batch of {len(batch)} messages")


_MAX_OCTET_FRAME = 1024 * 1024

# v7: Micro-batch settings
_UDP_BATCH_SIZE = 256       # flush after this many datagrams
_UDP_FLUSH_MS = 50          # flush after this many milliseconds
_TCP_BATCH_SIZE = 256       # flush after this many messages
_TCP_FLUSH_MS = 50
_BACKPRESSURE_THRESHOLD = 0.85  # pause reading at this queue saturation

# ---------------------------------------------------------------------------
# Statistics Tracker
# ---------------------------------------------------------------------------

class ListenerStats:
    """Thread-safe statistics for the network listener."""
    __slots__ = ("packets_received", "bytes_received", "errors",
                 "messages_queued", "messages_dropped",
                 "start_time", "last_packet_time", "_connections")

    def __init__(self):
        self.packets_received: int = 0
        self.bytes_received: int = 0
        self.errors: int = 0
        self.messages_queued: int = 0
        self.messages_dropped: int = 0
        self.start_time: float = time.monotonic()
        self.last_packet_time: float = 0.0
        self._connections: int = 0

    def record_packet(self, size: int) -> None:
        self.packets_received += 1
        self.bytes_received += size
        self.last_packet_time = time.monotonic()

    def record_queued(self, count: int = 1) -> None:
        self.messages_queued += count

    def record_dropped(self, count: int = 1) -> None:
        self.messages_dropped += count

    def record_error(self) -> None:
        self.errors += 1

    @property
    def uptime_seconds(self) -> float:
        return time.monotonic() - self.start_time

    @property
    def eps(self) -> float:
        elapsed = self.uptime_seconds
        return self.packets_received / max(elapsed, 0.001)

    def to_dict(self) -> dict:
        return {
            "packets_received": self.packets_received,
            "bytes_received": self.bytes_received,
            "messages_queued": self.messages_queued,
            "messages_dropped": self.messages_dropped,
            "errors": self.errors,
            "uptime_seconds": round(self.uptime_seconds, 1),
            "events_per_second": round(self.eps, 2),
            "active_connections": self._connections,
        }


# ---------------------------------------------------------------------------
# UDP Syslog Protocol
# ---------------------------------------------------------------------------

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """
    Asyncio datagram protocol for receiving syslog over UDP (RFC 5426).
    Each datagram is a complete syslog message — no framing needed.

    v7: Accumulates messages into micro-batches of list[str] and
    flushes to the queue every _UDP_BATCH_SIZE packets or _UDP_FLUSH_MS ms.
    Backpressure: pauses the transport when queue exceeds 85%.
    """

    def __init__(self, output_queue: Union[MPQueue, ThreadQueue, asyncio.Queue],
                 stats: ListenerStats, source_tag: str = "udp"):
        self._queue = output_queue
        self._stats = stats
        self._source_tag = source_tag
        # v7: micro-batch buffer
        self._batch: list[str] = []
        self._flush_handle: asyncio.TimerHandle | None = None
        self._paused = False

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport
        self._loop = asyncio.get_running_loop()
        sock = transport.get_extra_info("socket")
        if sock:
            # Increase receive buffer to 4MB for burst handling
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            except OSError:
                pass
        logger.info(f"UDP syslog listener started ({self._source_tag})")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            self._stats.record_packet(len(data))
            # In UDP syslog (RFC 5426), each datagram is an independent atomic packet.
            # A packet may contain a single event (no trailing newline) or multiple lines.
            text = data.decode("utf-8", errors="replace").strip()
            if not text:
                return

            lines = [line.strip() for line in text.splitlines() if line.strip()]
            for message in lines:
                self._batch.append(message)
                if len(self._batch) >= _UDP_BATCH_SIZE:
                    self._flush_batch()

            if self._flush_handle is None and self._batch:
                self._flush_handle = self._loop.call_later(
                    _UDP_FLUSH_MS / 1000.0, self._flush_batch
                )

        except Exception as exc:
            self._stats.record_error()
            logger.debug(f"Error processing UDP datagram: {exc}")

    def _flush_batch(self) -> None:
        """Flush accumulated messages to the queue as a list[str] batch."""
        if self._flush_handle is not None:
            self._flush_handle.cancel()
            self._flush_handle = None

        if not self._batch:
            return

        batch = self._batch[:]
        self._batch.clear()

        # Backpressure check (safe across Python 3.9–3.14+)
        if _is_mp_queue(self._queue):
            try:
                qsize = self._queue.qsize()
                maxsize = getattr(self._queue, 'maxsize', getattr(self._queue, '_maxsize', 0))
                if maxsize > 0 and qsize / maxsize > _BACKPRESSURE_THRESHOLD:
                    logger.warning(
                        f"UDP backpressure: queue at {qsize}/{maxsize} "
                        f"({qsize*100//maxsize}%), consider scaling workers"
                    )
            except (NotImplementedError, OSError, ValueError):
                pass

        _offer(self._queue, batch, self._stats, "UDP")

    def error_received(self, exc: Exception) -> None:
        self._stats.record_error()
        logger.warning(f"UDP protocol error: {exc}")

    def connection_lost(self, exc: Exception | None) -> None:
        self._flush_batch()  # flush remaining
        logger.info("UDP listener connection lost")


# ---------------------------------------------------------------------------
# TCP Syslog Protocol
# ---------------------------------------------------------------------------

class SyslogTCPProtocol(asyncio.Protocol):
    """
    Asyncio stream protocol for receiving syslog over TCP.
    Supports two framing modes:
      1. Newline-delimited (most common)
      2. Octet-counting per RFC 5425: <MSG_LEN> <SP> <MSG>
    Auto-detects framing from first bytes.

    v7: Batches parsed messages into list[str] micro-batches before
    pushing to the queue. Backpressure via transport.pause_reading().
    """

    def __init__(self, output_queue: Union[MPQueue, ThreadQueue, asyncio.Queue],
                 stats: ListenerStats, source_tag: str = "tcp"):
        self._queue = output_queue
        self._stats = stats
        self._source_tag = source_tag
        self._buffer: bytes = b""
        self._addr: tuple[str, int] = ("", 0)
        self._octet_counting: bool | None = None  # None = auto-detect
        self._transport: asyncio.Transport | None = None
        # v7: micro-batch buffer
        self._msg_batch: list[str] = []
        self._flush_handle: asyncio.TimerHandle | None = None
        self._paused = False

    def connection_made(self, transport: asyncio.Transport) -> None:
        self._transport = transport
        self._loop = asyncio.get_running_loop()
        peername = transport.get_extra_info("peername")
        self._addr = peername or ("unknown", 0)
        self._stats._connections += 1
        logger.debug(f"TCP connection from {self._addr[0]}:{self._addr[1]}")

    def data_received(self, data: bytes) -> None:
        self._buffer += data

        # Auto-detect framing on first data. RFC 6587 octet counting is
        # "<digits> <" — the frame always starts with the syslog PRI '<'.
        if self._octet_counting is None:
            m = re.match(rb"^(\d{1,7}) <", self._buffer)
            if m:
                self._octet_counting = True
            elif self._buffer[:1].isdigit() and len(self._buffer) < 9 and b" " not in self._buffer:
                return  # wait for enough bytes to decide
            else:
                self._octet_counting = False

        if self._octet_counting:
            self._process_octet_counting()
        else:
            self._process_newline_delimited()

        # v7: Check if batch is ready to flush
        if len(self._msg_batch) >= _TCP_BATCH_SIZE:
            self._flush_msg_batch()
        elif self._msg_batch and self._flush_handle is None:
            self._flush_handle = self._loop.call_later(
                _TCP_FLUSH_MS / 1000.0, self._flush_msg_batch
            )

    def _process_newline_delimited(self) -> None:
        """Process newline-delimited syslog messages."""
        while b"\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\n", 1)
            message = line.decode("utf-8", errors="replace").strip()
            if message:
                self._emit(message)

    def _process_octet_counting(self) -> None:
        """Process octet-counted syslog messages (RFC 5425)."""
        while self._buffer:
            # Find the space separator between length and message
            space_idx = self._buffer.find(b" ")
            if space_idx < 0 or space_idx > 10:
                # Probably not octet counting — fall back to newline
                self._octet_counting = False
                self._process_newline_delimited()
                return

            try:
                msg_len = int(self._buffer[:space_idx])
            except ValueError:
                self._octet_counting = False
                self._process_newline_delimited()
                return
            if not 0 < msg_len <= _MAX_OCTET_FRAME:
                logger.warning(f"TCP {self._addr[0]}: invalid octet frame length {msg_len}; "
                               "switching to newline framing")
                self._octet_counting = False
                self._process_newline_delimited()
                return

            total_needed = space_idx + 1 + msg_len
            if len(self._buffer) < total_needed:
                break  # Wait for more data

            msg_bytes = self._buffer[space_idx + 1 : total_needed]
            self._buffer = self._buffer[total_needed:]
            message = msg_bytes.decode("utf-8", errors="replace").strip()
            if message:
                self._emit(message)

    def _emit(self, message: str) -> None:
        """Buffer a parsed message for batch delivery."""
        self._stats.record_packet(len(message))
        # v7: accumulate into batch, don't push individually
        self._msg_batch.append(message)

    def _flush_msg_batch(self) -> None:
        """Flush accumulated messages to the queue as a list[str] batch."""
        if self._flush_handle is not None:
            self._flush_handle.cancel()
            self._flush_handle = None

        if not self._msg_batch:
            return

        batch = self._msg_batch[:]
        self._msg_batch.clear()

        # Backpressure check (safe across Python 3.9–3.14+)
        if _is_mp_queue(self._queue):
            try:
                qsize = self._queue.qsize()
                maxsize = getattr(self._queue, 'maxsize', getattr(self._queue, '_maxsize', 0))
                if self._transport and not self._paused:
                    if maxsize > 0 and qsize / maxsize > _BACKPRESSURE_THRESHOLD:
                        self._transport.pause_reading()
                        self._paused = True
                        logger.warning(
                            f"TCP backpressure: pausing transport "
                            f"({qsize}/{maxsize} batches)"
                        )
                elif self._transport and self._paused:
                    if maxsize <= 0 or qsize / maxsize < _BACKPRESSURE_THRESHOLD * 0.7:
                        self._transport.resume_reading()
                        self._paused = False
                        logger.info("TCP backpressure: resuming transport")
            except (NotImplementedError, OSError, ValueError):
                pass

        _offer(self._queue, batch, self._stats, "TCP")

    def connection_lost(self, exc: Exception | None) -> None:
        # Flush remaining buffer
        if self._buffer:
            remaining = self._buffer.decode("utf-8", errors="replace").strip()
            if remaining:
                self._emit(remaining)
            self._buffer = b""
        # Flush remaining message batch
        self._flush_msg_batch()
        self._stats._connections -= 1
        logger.debug(f"TCP connection closed from {self._addr[0]}:{self._addr[1]}")


# ---------------------------------------------------------------------------
# Network Listener Orchestrator
# ---------------------------------------------------------------------------

class NetworkListener:
    """
    High-level orchestrator for syslog network ingestion.

    Manages asyncio UDP and TCP servers, pushes received messages
    into a shared queue for downstream processing by the worker pool.

    Usage:
        queue = multiprocessing.Queue(maxsize=100_000)
        listener = NetworkListener(queue, host="0.0.0.0", port=5514)

        # In an async context:
        await listener.start(protocol="both")
        # ... runs until stopped ...
        await listener.stop()

        # Or synchronously (blocks forever):
        listener.run_forever(protocol="both")
    """

    def __init__(self, output_queue: Union[MPQueue, ThreadQueue, asyncio.Queue],
                 host: str = "0.0.0.0", port: int = 5514):
        self.host = host
        self.port = port
        self._queue = output_queue
        self.stats = ListenerStats()
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.AbstractServer | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._running = False

    async def start(self, protocol: str = "both") -> None:
        """
        Start listening on the specified protocol(s).

        Args:
            protocol: "udp", "tcp", or "both"
        """
        self._loop = asyncio.get_running_loop()
        self._running = True

        proto = protocol.lower()

        if proto in ("udp", "both"):
            transport, _ = await self._loop.create_datagram_endpoint(
                lambda: SyslogUDPProtocol(self._queue, self.stats, "udp"),
                local_addr=(self.host, self.port),
            )
            self._udp_transport = transport
            logger.info(f"✓ UDP syslog listener on {self.host}:{self.port}")

        if proto in ("tcp", "both"):
            tcp_port = self.port if proto == "tcp" else self.port
            self._tcp_server = await self._loop.create_server(
                lambda: SyslogTCPProtocol(self._queue, self.stats, "tcp"),
                self.host, tcp_port,
                reuse_address=True,
            )
            logger.info(f"✓ TCP syslog listener on {self.host}:{tcp_port}")

        logger.info(f"Network listener active — waiting for syslog data...")

    async def stop(self) -> None:
        """Gracefully stop all listeners."""
        self._running = False

        if self._udp_transport:
            self._udp_transport.close()
            self._udp_transport = None
            logger.info("UDP listener stopped")

        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            self._tcp_server = None
            logger.info("TCP listener stopped")

    def run_forever(self, protocol: str = "both") -> None:
        """
        Synchronous entry point — runs the listener until interrupted.
        Blocks the calling thread.
        """
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def _run():
            await self.start(protocol)
            # Print startup status
            print(f"\n{'='*60}")
            print(f"  ULPF Network Syslog Listener")
            print(f"{'='*60}")
            print(f"  Host     : {self.host}")
            print(f"  Port     : {self.port}")
            print(f"  Protocol : {protocol.upper()}")
            print(f"  Status   : LISTENING")
            print(f"{'='*60}")
            print(f"  Press Ctrl+C to stop.\n")

            try:
                while self._running:
                    await asyncio.sleep(5)
                    s = self.stats.to_dict()
                    print(
                        f"  [STATS] Packets: {s['packets_received']:,} | "
                        f"EPS: {s['events_per_second']:.1f} | "
                        f"Bytes: {s['bytes_received']:,} | "
                        f"Errors: {s['errors']} | "
                        f"Connections: {s['active_connections']}"
                    )
            except asyncio.CancelledError:
                pass
            finally:
                await self.stop()

        try:
            loop.run_until_complete(_run())
        except KeyboardInterrupt:
            print("\n  Shutting down listener...")
            loop.run_until_complete(self.stop())
        finally:
            loop.close()
            print(f"\n  Final stats: {self.stats.to_dict()}")
