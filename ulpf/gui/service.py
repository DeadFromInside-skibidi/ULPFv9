"""
ULPF Application Service Layer
================================
Wraps the ULPFPlugin so the GUI never touches engine internals directly.
Every method is safe to call from any thread; long-running operations should
still be dispatched to QThread workers.

Live ingestion (network listener + traffic simulator)
------------------------------------------------------
Received lines are handed to an *ingestion session*:

  * process mode (default): a multiprocess ``WorkerPool`` parses in parallel
    and writes Parquet shards that are bulk-loaded into the shared DuckDB
    connection. Workers return a small event sample and detected anomalies
    for the live views. Real throughput scales with cores.
  * thread mode (``workers=0`` or if processes cannot start): parsing and
    storage run on one background thread in this process.

All figures shown in the GUI (EPS, packets, drops, DNA similarity) are
measured, never synthesised.
"""
from __future__ import annotations

import collections
import logging
import os
import queue
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ulpf.platform.paths import (
    get_data_dir,
    get_db_path,
    get_default_log_sources,
    get_system_info,
    open_folder,
)

logger = logging.getLogger("ulpf.gui.service")


def _default_data_dir() -> Path:
    return get_data_dir()


def _default_workers() -> int:
    env = os.environ.get("ULPF_GUI_WORKERS")
    if env is not None:
        try:
            return max(0, int(env))
        except ValueError:
            pass
    return min(4, max(1, (os.cpu_count() or 2) - 1))


def _demo_line_pool() -> list[str]:
    """Lines for the traffic simulator: the bundled demo_data corpus."""
    import sys
    search = []
    base = getattr(sys, "_MEIPASS", None)
    if base:
        search.append(Path(base) / "demo_data")
    search.append(Path(__file__).resolve().parent.parent.parent / "demo_data")
    search.append(Path(sys.executable).parent / "demo_data")
    for d in search:
        if d.is_dir():
            pool: list[str] = []
            for p in sorted(d.glob("*.log")):
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    pool.extend(l.strip() for l in f if l.strip() and not l.startswith("#"))
            if pool:
                return pool
    return [
        '<165>1 2024-01-01T00:00:00Z host app - - - test log',
        'CEF:0|Security|ThreatManager|1.0|100|Drop Attack|8|src=10.0.0.1 dst=10.0.0.2 act=drop',
        'date=2024-08-28 time=10:15:00 devname="FGT60D" srcip=192.168.1.10 dstip=8.8.8.8 action="allow"',
        '{"timestamp": "2024-08-28T10:15:00Z", "src_ip": "10.0.0.5", "action": "block", "severity": 7}',
    ]


class _CounterRate:
    """Events/second derived from a monotonically increasing counter (sampled on read)."""

    def __init__(self, read_counter, window: float = 3.0):
        self._read = read_counter
        self.window = window
        self._samples: collections.deque[tuple[float, int]] = collections.deque()
        self._lock = threading.Lock()

    def rate(self) -> float:
        now = time.time()
        value = self._read()
        with self._lock:
            self._samples.append((now, value))
            while len(self._samples) > 2 and now - self._samples[1][0] >= self.window:
                self._samples.popleft()
            t0, v0 = self._samples[0]
        if now - t0 < 0.2:
            return 0.0
        return round(max(0, value - v0) / (now - t0), 1)


class _ThroughputMeter:
    """Sliding-window events-per-second from completion timestamps."""

    def __init__(self, window: float = 3.0):
        self.window = window
        self._samples: collections.deque[tuple[float, int]] = collections.deque()
        self._lock = threading.Lock()

    def add(self, count: int, ts: float | None = None) -> None:
        if count <= 0:
            return
        ts = ts or time.time()
        with self._lock:
            self._samples.append((ts, count))
            cutoff = ts - self.window
            while self._samples and self._samples[0][0] < cutoff:
                self._samples.popleft()

    def rate(self) -> float:
        now = time.time()
        with self._lock:
            cutoff = now - self.window
            while self._samples and self._samples[0][0] < cutoff:
                self._samples.popleft()
            if not self._samples:
                return 0.0
            total = sum(c for _, c in self._samples)
            span = max(now - self._samples[0][0], 0.5)
        return round(total / span, 1)

    def clear(self) -> None:
        with self._lock:
            self._samples.clear()


class _IngestSession:
    """One generation of live ingestion (listener sockets + parse/store engine)."""

    def __init__(self, service: "ULPFService", host: str, port: int, proto: str,
                 workers: int, siem_host: str | None, siem_port: int | None, save_local: bool):
        self.service = service
        self.host, self.port, self.proto = host, int(port), proto.upper()
        self.save_local = save_local
        self.stop_event = threading.Event()
        self.stats = {"packets": 0, "bytes": 0, "simulated": 0, "dropped": 0,
                      "last_packet": "—", "recent": collections.deque(maxlen=30),
                      "bind_errors": []}
        self.threads: list[threading.Thread] = []
        self.pool = None
        self.mode = "thread"
        self.parse_rate: _CounterRate | None = None
        self.persist_rate: _CounterRate | None = None
        self._lines: queue.Queue = queue.Queue(maxsize=2_000)  # batches of lines
        self._forwarder = None
        if siem_host and siem_port:
            from ulpf.ingestion.forwarder import SiemForwarder
            self._forwarder = SiemForwarder(siem_host, int(siem_port))

        if workers > 0:
            try:
                from ulpf.ingestion.workers import WorkerPool
                self.pool = WorkerPool(num_workers=workers, batch_size=1000, sample_size=25,
                                       anomaly_detection=True)
                self.pool.start(db=service._plugin.storage if save_local else None,
                                save_local=save_local, siem_host=siem_host, siem_port=siem_port,
                                on_batch=service._on_worker_batch)
                self.mode = f"process ({workers} workers)"
                pool = self.pool
                self.parse_rate = _CounterRate(lambda: pool.total_success.value)
                self.persist_rate = _CounterRate(lambda: pool.total_persisted)
            except Exception as e:
                logger.warning(f"Worker processes unavailable ({e}); using in-process ingestion")
                self.pool = None
        self._dispatch = threading.Thread(target=self._dispatch_loop, name="ulpf-ingest-dispatch", daemon=True)
        self._dispatch.start()
        self.threads.append(self._dispatch)

    @property
    def running(self) -> bool:
        return not self.stop_event.is_set()

    # ---- producer side ----

    def offer(self, lines: list[str], simulated: bool = False) -> int:
        """Queue a list of lines for processing. Returns how many were accepted.

        Lists (not single lines) travel through the queue to keep per-line
        locking off the hot path. Network input never blocks the socket
        reader for long: if the engine is saturated the batch is dropped and
        counted. The simulator waits instead (it is an offered load).
        """
        try:
            self._lines.put(lines, timeout=0.25 if simulated else 0.02)
            return len(lines)
        except queue.Full:
            if not simulated:
                self.stats["dropped"] += len(lines)
            return 0

    def _dispatch_loop(self) -> None:
        """Batch queued lines into the worker pool or the in-process pipeline."""
        while not (self.stop_event.is_set() and self._lines.empty()):
            batch: list[str] = []
            try:
                batch.extend(self._lines.get(timeout=0.05))
                while len(batch) < 2000:
                    batch.extend(self._lines.get_nowait())
            except queue.Empty:
                pass
            if not batch:
                continue
            try:
                if self.pool is not None:
                    self.pool.submit_batch(batch)
                else:
                    self.service._process_inline(batch, self)
            except Exception:
                logger.exception("Ingestion dispatch failed")

    # ---- listeners ----

    def start_listeners(self) -> None:
        if self.proto in ("UDP", "BOTH"):
            t = threading.Thread(target=self._udp_loop, name="ulpf-listener-udp", daemon=True)
            t.start()
            self.threads.append(t)
        if self.proto in ("TCP", "BOTH"):
            t = threading.Thread(target=self._tcp_loop, name="ulpf-listener-tcp", daemon=True)
            t.start()
            self.threads.append(t)

    def _record(self, lines: list[str], nbytes: int, addr: tuple) -> None:
        s = self.stats
        s["packets"] += len(lines)
        s["bytes"] += nbytes
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        s["last_packet"] = ts
        s["recent"].append(f"[{ts}] From {addr[0]}:{addr[1]} ({nbytes}B) -> {lines[0][:90]}")

    def _udp_loop(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            except OSError:
                pass
            sock.bind((self.host, self.port))
            sock.settimeout(0.5)
        except OSError as e:
            self.stats["bind_errors"].append(f"UDP {self.host}:{self.port}: {e}")
            logger.error(f"Could not bind UDP listener to {self.host}:{self.port}: {e}")
            return
        logger.info(f"UDP listener active on {self.host}:{self.port}")
        pending: list[str] = []
        last_flush = time.monotonic()
        with sock:
            while not self.stop_event.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                    text = data.decode("utf-8", errors="replace")
                    lines = [l.strip() for l in text.splitlines() if l.strip()]
                    if lines:
                        self._record(lines, len(data), addr)
                        pending.extend(lines)
                except socket.timeout:
                    pass
                except OSError:
                    if self.stop_event.is_set():
                        break
                # Micro-batch: flush every 256 messages or 20 ms
                now = time.monotonic()
                if pending and (len(pending) >= 256 or now - last_flush >= 0.02):
                    self.offer(pending)
                    pending = []
                    last_flush = now
                sock.settimeout(0.02 if pending else 0.5)
            if pending:
                self.offer(pending)

    def _tcp_loop(self) -> None:
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(64)
            server.settimeout(0.5)
        except OSError as e:
            self.stats["bind_errors"].append(f"TCP {self.host}:{self.port}: {e}")
            logger.error(f"Could not bind TCP listener to {self.host}:{self.port}: {e}")
            return
        logger.info(f"TCP listener active on {self.host}:{self.port}")
        with server:
            while not self.stop_event.is_set():
                try:
                    conn, addr = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(target=self._tcp_client, args=(conn, addr), daemon=True).start()

    def _tcp_client(self, conn: socket.socket, addr: tuple) -> None:
        buf = b""
        conn.settimeout(0.5)
        with conn:
            while not self.stop_event.is_set():
                try:
                    data = conn.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break
                buf += data
                if b"\n" in buf:
                    chunk, _, buf = buf.rpartition(b"\n")
                    lines = [l.strip() for l in chunk.decode("utf-8", errors="replace").split("\n") if l.strip()]
                    if lines:
                        self._record(lines, len(chunk), addr)
                        self.offer(lines)
            tail = buf.decode("utf-8", errors="replace").strip()
            if tail:
                self._record([tail], len(buf), addr)
                self.offer([tail])

    # ---- shutdown ----

    def stop(self) -> dict:
        self.stop_event.set()
        for t in self.threads:
            t.join(timeout=5.0)
        metrics = {}
        if self.pool is not None:
            metrics = self.pool.stop()
        if self._forwarder is not None:
            self._forwarder.close()
        return metrics


class ULPFService:
    """Application-level service that wraps the ULPF plugin for GUI use."""

    def __init__(self, data_dir: Path | str | None = None):
        self._data_dir = Path(data_dir) if data_dir else _default_data_dir()
        self._data_dir.mkdir(parents=True, exist_ok=True)

        self._plugin = None
        self._mode = "local"
        self._state = "STOPPED"    # STOPPED | STARTING | RUNNING | ERROR
        self._error: str = ""
        self._start_time: float = 0.0
        self._on_ingest_callback = None
        self._last_notify = 0.0

        self._session: _IngestSession | None = None
        self._session_lock = threading.Lock()
        self._meter = _ThroughputMeter()
        self._live_counts = {"processed": 0, "stored": 0, "failed": 0}

        self._recent_events_cache: collections.deque = collections.deque(maxlen=1000)
        self._recent_cache_lock = threading.Lock()
        self._live_anomalies: collections.deque = collections.deque(maxlen=2000)
        self._pending_anomalies: list[dict] = []
        self._anomaly_lock = threading.Lock()
        self._last_anomaly_flush = 0.0

        self._sim_thread: threading.Thread | None = None
        self._sim_stop = threading.Event()
        self._sim_rate = 0

        self._analytics_lock = threading.Lock()
        self._last_dna_sample = 0.0
        self._last_corr_sample = 0.0
        self._live_dna_telemetry: dict[str, Any] = {}
        self._cached_correlation_groups: list[dict] = []
        self._live_correlator = None

    # ── Callbacks / telemetry ─────────────────────────────────────────

    def set_on_ingest_callback(self, callback):
        """Register a callback invoked (throttled to 10 Hz) whenever new events are stored."""
        self._on_ingest_callback = callback

    def _notify(self, force: bool = False) -> None:
        now = time.time()
        if self._on_ingest_callback and (force or now - self._last_notify >= 0.1):
            self._last_notify = now
            try:
                self._on_ingest_callback()
            except Exception:
                logger.debug("ingest callback failed", exc_info=True)

    def get_live_eps(self) -> float:
        """Measured events/second fully processed over the last ~3 seconds.

        Process mode reads the workers' shared completion counter; thread mode
        and file/paste ingestion use completion timestamps.
        """
        s = self._session
        if s is not None and s.parse_rate is not None:
            return max(s.parse_rate.rate(), self._meter.rate())
        return self._meter.rate()

    def get_persist_eps(self) -> float:
        """Measured events/second committed to DuckDB (process mode)."""
        s = self._session
        if s is not None and s.persist_rate is not None:
            return s.persist_rate.rate()
        return self._meter.rate()

    def get_live_dna_telemetry(self) -> dict[str, Any]:
        """Most recent live Log DNA match/drift evaluation (empty until traffic arrives)."""
        return dict(self._live_dna_telemetry)

    # ── Lifecycle ─────────────────────────────────────────────────────

    def initialize(self, start_listener: bool = True) -> bool:
        """Initialize the ULPF engine. Returns True on success."""
        try:
            self._state = "STARTING"
            from ulpf.plugin.interface import ULPFPlugin

            self._plugin = ULPFPlugin()
            db_path = os.environ.get("ULPF_DB_PATH") or str(self._data_dir / "ulpf.duckdb")
            self._plugin.initialize({
                "storage_backend": "duckdb",
                "storage_path": db_path,
                "evidence_dir": str(self._data_dir / "evidence"),
            })
            self._plugin.start()
            self._state = "RUNNING"
            self._start_time = time.time()

            try:
                initial = self._plugin.storage.query(limit=200)
                with self._recent_cache_lock:
                    self._recent_events_cache.extend(reversed(initial))
            except Exception:
                logger.debug("Could not pre-seed recent events", exc_info=True)

            if start_listener and os.environ.get("ULPF_NO_AUTO_LISTENER") != "1":
                self.start_network_listener(host="0.0.0.0", port=5514, proto="BOTH")
            logger.info(f"ULPF Service initialized (data_dir={self._data_dir})")
            return True
        except Exception as e:
            self._state = "ERROR"
            self._error = str(e)
            logger.error(f"ULPF Service init failed: {e}")
            return False

    def shutdown(self):
        """Gracefully shut down everything (drains in-flight events). Idempotent."""
        if self._state == "STOPPED" and self._plugin is None:
            return
        self.stop_traffic_simulation()
        self.stop_network_listener()
        if self._plugin:
            try:
                self._plugin.shutdown()
            except Exception as e:
                logger.error(f"Shutdown error: {e}")
        self._plugin = None
        self._state = "STOPPED"
        logger.info("ULPF Service shut down.")

    # ── Live ingestion ────────────────────────────────────────────────

    def start_network_listener(self, host: str = "0.0.0.0", port: int = 5514, proto: str = "UDP",
                               workers: int | None = None, siem_host: str | None = None,
                               siem_port: int | None = None, save_local: bool = True) -> dict[str, Any]:
        """Start (or restart) the syslog listener and its ingestion engine."""
        if not self._plugin or self._state != "RUNNING":
            return {"success": False, "error": "Engine not running"}
        self.stop_network_listener()
        n_workers = _default_workers() if workers is None else max(0, min(int(workers), os.cpu_count() or 1))
        with self._session_lock:
            self._session = _IngestSession(self, host, int(port), proto, n_workers,
                                           siem_host, siem_port, save_local)
            self._session.start_listeners()
            session = self._session
        time.sleep(0.05)  # let bind errors surface
        errors = list(session.stats["bind_errors"])
        return {
            "success": not errors or len(errors) < (2 if session.proto == "BOTH" else 1),
            "host": session.host, "port": session.port, "proto": session.proto,
            "mode": session.mode, "errors": errors,
        }

    def stop_network_listener(self) -> dict[str, Any]:
        """Stop listening and drain everything already received into storage."""
        with self._session_lock:
            session, self._session = self._session, None
        if session is None:
            return {"success": True, "message": "Listener not running"}
        metrics = session.stop()
        self._flush_anomalies(force=True)
        self._notify(force=True)
        return {"success": True, "message": "Listener stopped", "worker_metrics": metrics}

    def get_listener_status(self) -> dict[str, Any]:
        s = self._session
        if s is None:
            return {"running": False, "host": "0.0.0.0", "port": 5514, "proto": "UDP",
                    "packets": 0, "bytes": 0, "last_packet": "—", "recent": [], "dropped": 0,
                    "simulated": 0, "mode": "stopped", "live_eps": 0.0}
        st = s.stats
        status = {
            "running": s.running and len(st["bind_errors"]) < (2 if s.proto == "BOTH" else 1),
            "host": s.host, "port": s.port, "proto": s.proto,
            "packets": st["packets"], "bytes": st["bytes"], "last_packet": st["last_packet"],
            "recent": list(st["recent"]), "dropped": st["dropped"], "simulated": st["simulated"],
            "mode": s.mode, "errors": list(st["bind_errors"]), "live_eps": self.get_live_eps(),
            "persist_eps": self.get_persist_eps(), "queued_batches": s._lines.qsize(),
        }
        if s.pool is not None:
            status["workers"] = s.pool.get_metrics()
        return status

    def _process_inline(self, lines: list[str], session: _IngestSession) -> None:
        """Thread-mode ingestion: parse, analyse and store one batch in-process."""
        pipeline = self._plugin.pipeline
        events = []
        failed = 0
        for line in lines:
            r = pipeline.process_line(line)
            if r.get("success"):
                events.append(r["event"])
            elif not r.get("skipped"):
                failed += 1
        stored = 0
        if events and session.save_local:
            stored = self._plugin.storage.store_events_bulk(events)
        if session._forwarder is not None and events:
            session._forwarder.send(events)
        anomalies = []
        detector = self._plugin.anomaly_detector
        if detector and events:
            anomalies = detector.analyse_batch(events)
            if anomalies and session.save_local:
                with self._anomaly_lock:
                    self._pending_anomalies.extend(anomalies)
                self._flush_anomalies()
        self._after_batch(len(events), stored if session.save_local else len(events), failed,
                          events[-25:], anomalies)

    def _flush_anomalies(self, force: bool = False) -> None:
        """Persist buffered anomalies in one commit (each DuckDB commit costs a WAL sync)."""
        now = time.time()
        with self._anomaly_lock:
            if not self._pending_anomalies or (not force and now - self._last_anomaly_flush < 1.0
                                               and len(self._pending_anomalies) < 20_000):
                return
            batch, self._pending_anomalies = self._pending_anomalies, []
            self._last_anomaly_flush = now
        if self._plugin and self._plugin.storage:
            try:
                self._plugin.storage.store_anomalies_bulk(batch)
            except Exception:
                logger.debug("Could not store anomalies", exc_info=True)

    def _on_worker_batch(self, msg: dict) -> None:
        """WorkerPool callback (writer thread): fold a worker status message into live state."""
        anomalies = msg.get("anomalies") or []
        if anomalies:
            with self._anomaly_lock:
                self._pending_anomalies.extend(anomalies)
        self._flush_anomalies()
        self._after_batch(msg.get("success", 0), msg.get("success", 0), msg.get("failed", 0),
                          msg.get("sample") or [], anomalies, from_workers=True)

    def _after_batch(self, n_ok: int, n_stored: int, n_failed: int, sample: list[dict],
                     anomalies: list[dict], from_workers: bool = False) -> None:
        if not from_workers:
            self._meter.add(n_ok)
        self._live_counts["processed"] += n_ok + n_failed
        self._live_counts["stored"] += n_stored
        self._live_counts["failed"] += n_failed
        if sample:
            with self._recent_cache_lock:
                self._recent_events_cache.extend(sample)
        if anomalies:
            self._live_anomalies.extend(anomalies)
        if sample:
            self._maybe_run_live_analytics(sample)
        self._notify()

    def _maybe_run_live_analytics(self, sample: list[dict]) -> None:
        """Throttled Log DNA + correlation on a sample of live traffic (off the hot path)."""
        now = time.time()
        if now - self._last_dna_sample >= 2.0:
            self._last_dna_sample = now
            threading.Thread(target=self._live_dna, args=(list(sample),), daemon=True).start()
        if now - self._last_corr_sample >= 2.0:
            self._last_corr_sample = now
            threading.Thread(target=self._live_correlate, args=(list(sample),), daemon=True).start()

    def _live_dna(self, events: list[dict]) -> None:
        if not self._analytics_lock.acquire(blocking=False):
            return
        try:
            from ulpf.intelligence.log_dna import LogDNA
            dna = LogDNA(db_path=str(self._data_dir / "log_dna_db.json"))
            by_fmt: dict[str, list[str]] = {}
            for ev in events:
                if ev.get("raw_event"):
                    by_fmt.setdefault(ev.get("raw_format", "unknown"), []).append(ev["raw_event"])
            known = {p.get("source_label") for p in dna.list_known()}
            # Profile each newly seen live format from up to 25 real lines
            for fmt, lines in by_fmt.items():
                label = f"live_{fmt}"
                if label not in known and len(lines) >= 3:
                    dna.register(dna.fingerprint(lines, source_label=label))
            fmt, lines = max(by_fmt.items(), key=lambda kv: len(kv[1]), default=(None, []))
            if not lines:
                return
            fid, score = dna.match(lines)
            drift = dna.detect_drift(fid, lines) if fid else {"drift_detected": False, "similarity_score": score}
            self._live_dna_telemetry = {
                "match": {
                    "matched": fid is not None,
                    "fingerprint_id": fid,
                    "source_label": dna.database.get(fid, {}).get("source_label") if fid else None,
                    "similarity": round(score, 4),
                    "evaluated_format": fmt,
                },
                "drift": drift,
                "timestamp": time.time(),
                "sample_count": len(lines),
                "profiles_count": len(dna.database),
            }
        except Exception:
            logger.debug("Live DNA analysis failed", exc_info=True)
        finally:
            self._analytics_lock.release()

    def _live_correlate(self, events: list[dict]) -> None:
        try:
            from ulpf.intelligence.correlation import EventCorrelator
            if self._live_correlator is None:
                self._live_correlator = EventCorrelator(60.0, max_groups=500)
            for e in events:
                self._live_correlator.add_and_correlate(e)
            self._cached_correlation_groups = self._live_correlator.get_results()[:100]
        except Exception:
            logger.debug("Live correlation failed", exc_info=True)

    # ── Traffic simulator ─────────────────────────────────────────────

    def start_traffic_simulation(self, rate_eps: int = 25000) -> bool:
        """Replay the bundled demo corpus into live ingestion at a target offered rate.

        The rate is what is *offered*; the EPS shown in the GUI is what the
        engine actually completes. Simulated lines are counted separately
        from received network packets.
        """
        if self._sim_thread and self._sim_thread.is_alive():
            return True
        if self._session is None:
            res = self.start_network_listener()
            if not res.get("success") and self._session is None:
                return False
        self._sim_rate = max(10, int(rate_eps))
        self._sim_stop.clear()

        def _sim_loop():
            pool = _demo_line_pool()
            idx = 0
            injected = 0
            t0 = time.perf_counter()
            while not self._sim_stop.is_set():
                session = self._session
                if session is None:
                    break
                due = int((time.perf_counter() - t0) * self._sim_rate) - injected
                if due <= 0:
                    time.sleep(0.002)
                    continue
                n = min(due, 2000)
                chunk = [pool[(idx + j) % len(pool)] for j in range(n)]
                accepted = session.offer(chunk, simulated=True)
                idx += accepted
                injected += accepted
                session.stats["simulated"] += accepted
                if accepted < n:
                    # Engine saturated: stop owing the backlog so the offered rate stays honest
                    t0 = time.perf_counter() - injected / self._sim_rate

        self._sim_thread = threading.Thread(target=_sim_loop, name="ulpf-traffic-sim", daemon=True)
        self._sim_thread.start()
        logger.info(f"Traffic simulation offering {self._sim_rate} EPS")
        return True

    def stop_traffic_simulation(self) -> bool:
        self._sim_stop.set()
        if self._sim_thread:
            self._sim_thread.join(timeout=2.0)
            self._sim_thread = None
        return False

    def toggle_traffic_simulation(self) -> bool:
        if self.is_traffic_simulation_active():
            self.stop_traffic_simulation()
            return False
        return self.start_traffic_simulation()

    def is_traffic_simulation_active(self) -> bool:
        return bool(self._sim_thread and self._sim_thread.is_alive())

    # ── Remote / SIEM ─────────────────────────────────────────────────

    def test_remote_server(self, host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
        """Test TCP reachability of a remote SIEM receiver."""
        t0 = time.perf_counter()
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                pass
            rtt = (time.perf_counter() - t0) * 1000.0
            return {"success": True, "latency_ms": round(rtt, 2),
                    "message": f"Connection established to {host}:{port} in {rtt:.1f}ms"}
        except OSError as e:
            return {"success": False, "latency_ms": 0.0, "message": f"Connection failed to {host}:{port}: {e}"}

    def forward_events_to_server(self, host: str, port: int, proto: str = "UDP", limit: int = 50) -> dict[str, Any]:
        """Forward stored events to a remote SIEM as RFC 5424 syslog."""
        events = self.query_events(limit=limit, use_cache=False)
        if not events:
            return {"success": True, "count": 0, "message": "No stored events available to forward."}
        from ulpf.ingestion.forwarder import SiemForwarder
        p = "tcp" if "tcp" in proto.lower() else "udp"
        fwd = SiemForwarder(host, int(port), p)
        try:
            sent = fwd.send(events)
        finally:
            fwd.close()
        ok = sent == len(events)
        return {"success": ok, "count": sent,
                "message": f"Forwarded {sent}/{len(events)} events to {host}:{port} via {p.upper()}"}

    # ── State ─────────────────────────────────────────────────────────

    @property
    def state(self) -> str:
        return self._state

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def error(self) -> str:
        return self._error

    @property
    def plugin(self):
        return self._plugin

    @property
    def data_dir(self) -> Path:
        return self._data_dir

    @property
    def uptime(self) -> float:
        return time.time() - self._start_time if self._start_time else 0.0

    # ── Health ────────────────────────────────────────────────────────

    def health(self) -> dict:
        if self._plugin and self._state == "RUNNING":
            try:
                return self._plugin.health()
            except Exception as e:
                return {"status": "error", "error": str(e)}
        return {"status": self._state.lower(), "error": self._error}

    def metrics(self) -> dict:
        """Pipeline metrics merged with live-ingestion (worker) counts."""
        if not self._plugin:
            return {}
        m = self._plugin.metrics()
        ok = m.get("successful", 0) + self._live_counts["stored"]
        failed = m.get("failed", 0) + self._live_counts["failed"]
        m["events_successful"] = ok
        m["events_failed"] = failed
        m["success_rate_pct"] = round(ok / max(ok + failed, 1) * 100, 2)
        return m

    # ── Storage ───────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        res = {"total_events": 0, "by_format": {}, "by_category": {}, "by_severity": {}}
        if self._plugin and self._plugin.storage:
            try:
                res = self._plugin.storage.stats()
            except Exception as e:
                res = {"error": str(e), "total_events": 0, "by_format": {}, "by_category": {}, "by_severity": {}}
        res["live_eps"] = self.get_live_eps()
        return res

    def get_storage_info(self) -> dict:
        db = self._plugin.storage if self._plugin else None
        db_path = getattr(db, "db_path", None) or str(get_db_path())
        size = 0
        for p in (db_path, db_path + ".wal"):
            if os.path.exists(p):
                size += os.path.getsize(p)
        stats = self.get_stats()
        return {
            "backend": "DuckDB",
            "path": db_path,
            "size_bytes": size,
            "size_mb": round(size / (1024 * 1024), 2),
            "total_events": stats.get("total_events", 0),
            "read_only": bool(getattr(db, "read_only", False)),
            "healthy": self._state == "RUNNING",
        }

    def purge_raw_fallback_events(self) -> int:
        if not self._plugin or not self._plugin.storage:
            return 0
        try:
            n = self._plugin.storage.purge_raw_fallback()
            with self._recent_cache_lock:
                kept = [e for e in self._recent_events_cache if e.get("raw_format") != "raw_fallback"]
                self._recent_events_cache.clear()
                self._recent_events_cache.extend(kept)
            return n
        except Exception as e:
            logger.error(f"Failed to purge raw fallback events: {e}")
            return 0

    def reset_database(self) -> bool:
        if not self._plugin or not self._plugin.storage:
            return False
        try:
            self._plugin.storage.reset_database()
            with self._recent_cache_lock:
                self._recent_events_cache.clear()
            self._live_anomalies.clear()
            if self._plugin.anomaly_detector is not None:
                self._plugin.anomaly_detector.anomalies.clear()
            self._cached_correlation_groups = []
            self._live_correlator = None
            return True
        except Exception as e:
            logger.error(f"Failed to reset database: {e}")
            return False

    # ── Ingestion (files / paste) ─────────────────────────────────────

    def ingest_file(self, filepath: str) -> dict:
        """Stream a log file through the pipeline in bounded batches and store it."""
        if not self._plugin or self._state != "RUNNING":
            return {"success": False, "error": "Engine not running"}
        if not os.path.isfile(filepath):
            return {"success": False, "error": f"File not found: {filepath}"}
        try:
            pipeline = self._plugin.pipeline
            db = self._plugin.storage
            detector = self._plugin.anomaly_detector
            total = accepted = rejected = skipped = stored = anomaly_count = 0
            formats: dict[str, int] = {}
            sample: list[dict] = []
            t0 = time.perf_counter()
            for results in pipeline.iter_file(filepath, batch_size=5000):
                events = []
                for r in results:
                    if r.get("success"):
                        events.append(r["event"])
                        f = r["event"]["raw_format"]
                        formats[f] = formats.get(f, 0) + 1
                    elif r.get("skipped"):
                        skipped += 1
                    else:
                        rejected += 1
                total += len(results)
                accepted += len(events)
                if events:
                    stored += db.store_events_bulk(events)
                    if detector:
                        anomalies = detector.analyse_batch(events)
                        if anomalies:
                            db.store_anomalies_bulk(anomalies)
                            self._live_anomalies.extend(anomalies)
                            anomaly_count += len(anomalies)
                    with self._recent_cache_lock:
                        self._recent_events_cache.extend(events[-200:])
                    if len(sample) < 50:
                        sample.extend(events[:50 - len(sample)])
            elapsed = time.perf_counter() - t0
            if sample:
                threading.Thread(target=self._live_dna, args=(sample,), daemon=True).start()
            self._notify(force=True)
            return {
                "success": True, "file": filepath, "total_lines": total,
                "events_accepted": accepted, "events_rejected": rejected, "headers_skipped": skipped,
                "stored": stored, "anomalies": anomaly_count, "format_distribution": formats,
                "elapsed_sec": round(elapsed, 3),
                "events_per_second": round(accepted / elapsed, 1) if elapsed > 0 else 0.0,
            }
        except Exception as e:
            logger.exception("Ingestion error")
            return {"success": False, "error": str(e)}

    def ingest_text(self, text: str) -> dict:
        """Ingest raw text (multi-line log paste) as one stream."""
        if not self._plugin or self._state != "RUNNING":
            return {"success": False, "error": "Engine not running"}
        try:
            results = self._plugin.pipeline.process_text(text)
            if not results:
                return {"success": False, "error": "No lines to process"}
            events = [r["event"] for r in results if r.get("success")]
            failed = sum(1 for r in results if not r.get("success") and not r.get("skipped"))
            db = self._plugin.storage
            stored = db.store_events_bulk(events) if events else 0
            detector = self._plugin.anomaly_detector
            if detector and events:
                anomalies = detector.analyse_batch(events)
                if anomalies:
                    db.store_anomalies_bulk(anomalies)
                    self._live_anomalies.extend(anomalies)
            with self._recent_cache_lock:
                self._recent_events_cache.extend(events[-200:])
            self._notify(force=True)
            return {"success": True, "total_lines": len(results), "events_accepted": len(events),
                    "events_rejected": failed, "stored": stored}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── Events ────────────────────────────────────────────────────────

    def query_events(self, filters: dict | None = None, limit: int = 100, offset: int = 0,
                     use_cache: bool = True) -> list[dict]:
        """Query events, newest first.

        Unfiltered first-page requests are served from the in-memory ring of
        recently ingested events (no DB round-trip, never blocks on ingestion)
        when it holds enough events; everything else queries DuckDB.
        """
        if use_cache and not filters and offset == 0:
            with self._recent_cache_lock:
                if len(self._recent_events_cache) >= limit:
                    n = len(self._recent_events_cache)
                    return [self._recent_events_cache[i] for i in range(n - 1, n - 1 - limit, -1)]
        if not self._plugin or not self._plugin.storage:
            return []
        try:
            return self._plugin.storage.query(filters=filters, limit=limit, offset=offset)
        except Exception as e:
            logger.error(f"Query error: {e}")
            return []

    def count_events(self, filters: dict | None = None) -> int:
        if not self._plugin or not self._plugin.storage:
            return 0
        try:
            return self._plugin.storage.count_events(filters)
        except Exception:
            return 0

    def search_events(self, query: str, limit: int = 50) -> list[dict]:
        if not self._plugin or not self._plugin.storage:
            return []
        try:
            return self._plugin.storage.search(query=query, limit=limit)
        except Exception as e:
            logger.error(f"Search error: {e}")
            return []

    def get_event(self, event_id: str) -> dict | None:
        if not self._plugin or not self._plugin.storage:
            return None
        try:
            return self._plugin.storage.get_event(event_id)
        except Exception:
            return None

    def get_unparsed_logs(self, limit: int = 15) -> list[str]:
        """Raw lines no parser recognised (raw_fallback) — input for Auto-Learn."""
        events = self.query_events(filters={"raw_format": "raw_fallback"}, limit=limit, use_cache=False)
        return [e.get("raw_event") for e in events if e.get("raw_event")]

    # ── Parsers ───────────────────────────────────────────────────────

    def list_parsers(self) -> list[dict]:
        if not self._plugin or not self._plugin.pipeline:
            return []
        try:
            return self._plugin.pipeline.registry.list_parsers()
        except Exception:
            return []

    def test_parser(self, raw_line: str) -> dict | list[dict]:
        if not self._plugin or not self._plugin.pipeline:
            return {"success": False, "error": "Engine not running"}
        try:
            lines = [l.strip() for l in raw_line.splitlines() if l.strip()]
            if len(lines) > 1:
                return self._plugin.pipeline.process_text(raw_line)
            return self._plugin.pipeline.process_line(raw_line)
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── Auto-Learn ────────────────────────────────────────────────────

    def _is_known_line(self, line: str) -> bool:
        """True if a built-in parser already handles this line."""
        pipeline = self._plugin.pipeline
        det = pipeline._detect(line)
        parser = pipeline.registry.get_parser_for_format(det["format_name"])
        if parser is None:
            return False
        try:
            event = parser.parse(line)
        except Exception:
            return False
        return event is not None

    def auto_learn(self, lines: list[str]) -> dict:
        """Learn, validate, persist and activate parsers for unknown formats in ``lines``."""
        if not self._plugin or not self._plugin.pipeline or not self._plugin.pipeline.auto_engine:
            return {"success": False, "error": "Auto-parser engine not running"}
        try:
            engine = self._plugin.pipeline.auto_engine
            report = engine.learn(lines, is_known=self._is_known_line, save=True)
            accepted = report.pop("accepted")
            out = {
                "success": bool(accepted),
                "total_lines": report["total_lines"],
                "known_lines": report["known_lines"],
                "unknown_lines": report["unknown_lines"],
                "covered_lines": report["covered_lines"],
                "coverage_pct": report.get("coverage_pct", 0.0),
                "parsers": [{
                    "parser_id": a["parser_id"], "family": a["family"], "template": a["template"],
                    "accuracy": a["accuracy"], "parse_time_ms": a["parse_time_ms"],
                    "lines": a["lines"], "saved_to": a["saved_to"],
                    "fields": [{"name": f.name, "type": f.field_type, "position": f.position}
                               for f in a["spec"].fields],
                } for a in accepted],
                "rejected": report["rejected"],
            }
            if accepted:
                first = out["parsers"][0]
                out.update({k: first[k] for k in ("parser_id", "family", "template", "fields", "saved_to")})
            elif report.get("error"):
                out["error"] = report["error"]
            elif report["rejected"]:
                out["error"] = report["rejected"][0]["reason"]
            return out
        except Exception as e:
            logger.exception("Auto-learn failed")
            return {"success": False, "error": str(e)}

    def list_learned_parsers(self) -> list[dict]:
        try:
            if self._plugin and self._plugin.pipeline and self._plugin.pipeline.auto_engine:
                specs = self._plugin.pipeline.auto_engine.registry.list_parsers()
            else:
                from ulpf.intelligence.auto_parser.registry import AutoParserRegistry
                specs = AutoParserRegistry().list_parsers()
            return [{
                "parser_id": s.parser_id, "version": s.version, "family": s.source_family,
                "state": s.state, "fields_count": len(s.fields), "template": s.template,
                "confidence": s.confidence, "created_at": s.created_at,
                "accuracy": s.metadata.get("validation_accuracy"),
            } for s in specs]
        except Exception as e:
            logger.debug(f"Error listing learned parsers: {e}")
            return []

    # ── Log DNA ───────────────────────────────────────────────────────

    def _dna(self):
        from ulpf.intelligence.log_dna import LogDNA
        return LogDNA(db_path=str(self._data_dir / "log_dna_db.json"))

    def log_dna_fingerprint(self, lines: list[str], label: str = "") -> dict:
        try:
            dna = self._dna()
            fp = dna.fingerprint(lines, source_label=label)
            fid = dna.register(fp)
            return {"success": True, "fingerprint": fp.to_dict(), "fingerprint_id": fid}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def log_dna_match(self, lines: list[str]) -> dict:
        try:
            fid, score = self._dna().match(lines)
            return {"matched": fid is not None, "fingerprint_id": fid, "similarity": score}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def log_dna_list(self) -> list[dict]:
        try:
            return self._dna().list_known()
        except Exception:
            return []

    def log_dna_drift(self, fingerprint_id: str, lines: list[str]) -> dict:
        try:
            return self._dna().detect_drift(fingerprint_id, lines)
        except Exception as e:
            return {"drift_detected": False, "error": str(e)}

    # ── Correlation ───────────────────────────────────────────────────

    def correlate(self, limit: int = 200, window: float = 60.0,
                  target_ids: list[str] | None = None) -> list[dict]:
        """Correlate the most recent stored events (or the given event IDs)."""
        if not self._plugin or not self._plugin.storage:
            return []
        try:
            db = self._plugin.storage
            ids = [t.strip() for t in (target_ids or []) if t and t.strip()]
            events = db.get_events(ids) if ids else db.query(limit=limit)
            if not events:
                return []
            from ulpf.intelligence.correlation import EventCorrelator
            correlator = EventCorrelator(window)
            correlator.add_events(events)
            correlator.correlate()
            results = correlator.get_results()
            for g in correlator.groups:
                db.set_correlation([e["event_id"] for e in g.events if e.get("event_id")], g.correlation_id)
            return results
        except Exception as e:
            logger.error(f"Correlation error: {e}")
            return []

    # ── Anomalies ─────────────────────────────────────────────────────

    def get_anomalies(self, limit: int = 100) -> list[dict]:
        """Most recent anomalies: live (this session) first, then persisted history."""
        live = list(self._live_anomalies)[-limit:]
        if len(live) < limit and self._plugin and self._plugin.storage:
            try:
                stored = self._plugin.storage.query_anomalies(limit - len(live))
                live = list(reversed(stored)) + live
            except Exception:
                pass
        return live[-limit:]

    def get_anomaly_baseline(self) -> dict:
        """Baseline statistics from the live detector, else aggregated from DuckDB."""
        report = {}
        if self._plugin and self._plugin.anomaly_detector:
            report = self._plugin.anomaly_detector.get_baseline_report()
        sev_info = report.get("severity", {})
        if (not sev_info or sev_info.get("samples", 0) == 0) and self._plugin and self._plugin.storage:
            try:
                db = self._plugin.storage
                with db._conn_lock:
                    row = db.conn.execute(
                        "SELECT AVG(severity), COALESCE(STDDEV_SAMP(severity), 0.0), COUNT(*), "
                        "COUNT(DISTINCT source_ip) FROM events").fetchone()
                if row and row[2] > 0:
                    report["severity"] = {"mean": round(float(row[0] or 0.0), 2),
                                          "std_dev": round(float(row[1] or 0.0), 2), "samples": int(row[2])}
                    report["known_ips"] = int(row[3] or 0)
            except Exception as e:
                logger.error(f"Error computing database baseline: {e}")
        return report

    # ── Forensics ─────────────────────────────────────────────────────

    def forensic_create_chain(self, description: str = "", tags: list[str] | None = None) -> dict:
        if not self._plugin or not self._plugin.forensic_builder:
            return {"error": "Forensics not available"}
        try:
            chain = self._plugin.forensic_builder.create_chain(description, tags)
            return {"chain_id": chain.chain_id, "created_at": chain.created_at}
        except Exception as e:
            return {"error": str(e)}

    def forensic_build_from_events(self, limit: int = 100, description: str = "",
                                   tags: list[str] | None = None) -> dict:
        if not self._plugin or not self._plugin.forensic_builder:
            return {"error": "Forensics not available"}
        try:
            events = self.query_events(limit=limit, use_cache=False)
            if not events:
                return {"error": "No events available"}
            chain = self._plugin.forensic_builder.build_from_events(
                events, description=description or "Desktop-generated chain", tags=tags)
            return chain.to_dict()
        except Exception as e:
            return {"error": str(e)}

    def forensic_verify(self, chain_id: str) -> dict:
        if not self._plugin or not self._plugin.forensic_builder:
            return {"valid": False, "message": "Forensics not available"}
        try:
            return self._plugin.forensic_builder.verify_chain(chain_id)
        except Exception as e:
            return {"valid": False, "message": str(e)}

    def forensic_export(self, chain_id: str) -> dict:
        if not self._plugin or not self._plugin.forensic_builder:
            return {"error": "Forensics not available"}
        try:
            filepath = self._plugin.forensic_builder.export_package(chain_id)
            return {"success": True, "filepath": filepath}
        except Exception as e:
            return {"error": str(e)}

    def forensic_verify_package(self, filepath: str) -> dict:
        from ulpf.intelligence.forensic import verify_package
        try:
            return verify_package(filepath)
        except Exception as e:
            return {"valid": False, "problems": [str(e)]}

    def forensic_list_chains(self) -> list[dict]:
        if not self._plugin or not self._plugin.forensic_builder:
            return []
        try:
            return self._plugin.forensic_builder.list_chains()
        except Exception:
            return []

    # ── Schema ────────────────────────────────────────────────────────

    def get_schema(self) -> dict:
        """The unified event schema: field catalogue plus an empty event template."""
        from ulpf.engine.schema import SCHEMA_DEFINITION, _TEMPLATE
        return {**_TEMPLATE, "_definition": SCHEMA_DEFINITION}

    # ── Export ────────────────────────────────────────────────────────

    def export_events_json(self, filepath: str, limit: int = 10000) -> dict:
        import json
        try:
            events = self.query_events(limit=limit, use_cache=False)
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(events, f, indent=2, ensure_ascii=False, default=str)
            return {"success": True, "count": len(events), "path": filepath}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def export_events_csv(self, filepath: str, limit: int = 10000) -> dict:
        import csv
        try:
            events = self.query_events(limit=limit, use_cache=False)
            if not events:
                return {"success": False, "error": "No events to export"}
            fields = ["event_id", "timestamp", "category", "severity", "severity_label", "action",
                      "source_ip", "source_port", "destination_ip", "destination_port", "protocol",
                      "device_vendor", "device_product", "raw_format", "tags", "message"]
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                for e in events:
                    src, dst = e.get("source") or {}, e.get("destination") or {}
                    dev, net = e.get("device") or {}, e.get("network") or {}
                    writer.writerow({
                        "event_id": e.get("event_id"), "timestamp": e.get("timestamp"),
                        "category": e.get("category"), "severity": e.get("severity"),
                        "severity_label": e.get("severity_label"), "action": e.get("action"),
                        "source_ip": src.get("ip"), "source_port": src.get("port"),
                        "destination_ip": dst.get("ip"), "destination_port": dst.get("port"),
                        "protocol": net.get("protocol"), "device_vendor": dev.get("vendor"),
                        "device_product": dev.get("product"), "raw_format": e.get("raw_format"),
                        "tags": ";".join(e.get("tags") or []), "message": (e.get("message") or "")[:500],
                    })
            return {"success": True, "count": len(events), "path": filepath}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── Platform & Environment ────────────────────────────────────────

    def get_platform_info(self) -> dict[str, Any]:
        return get_system_info()

    def get_default_log_sources(self) -> list[dict[str, Any]]:
        return get_default_log_sources()

    def open_data_folder(self) -> bool:
        return open_folder(self._data_dir)
