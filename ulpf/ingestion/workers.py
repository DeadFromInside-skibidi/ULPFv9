"""
Multiprocessing Worker Pool
==============================
Producer-consumer architecture that bypasses the GIL by parsing in separate
OS processes.

    producer ──list[str] batches──▶ N worker processes ──parquet shards──▶ spool dir
                                          │                                  │
                                          └──small status messages──▶ writer thread
                                                                          │
                                                       DuckDB read_parquet (C++)

Workers never pickle full events back to the host: each batch is written as
a typed Parquet shard (published by atomic rename) and the host's writer
thread bulk-loads shards with DuckDB's native Parquet reader. Only counters,
an optional event sample and detected anomalies travel over the queue.

Durability: shards live in ``<data dir>/spool/<pool-id>/`` until ingested.
Shards left behind by a crashed pool are recovered on the next start. A shard
DuckDB cannot read is quarantined as ``*.bad`` instead of blocking the spool.
"""
from __future__ import annotations

import logging
import multiprocessing as mp
import os
import signal
import time
from multiprocessing import Queue as MPQueue
from queue import Empty, Full
from threading import Event, Lock, Thread
from typing import Any, Callable

logger = logging.getLogger(__name__)

_POISON_PILL = "__ULPF_SHUTDOWN__"

_DEFAULT_BATCH_SIZE = int(os.environ.get("ULPF_BATCH_SIZE", "500"))
_MAX_BATCH_QUEUE_SIZE = int(os.environ.get("ULPF_MAX_QUEUE", "250"))  # max *batches* per queue
_FLUSH_INTERVAL_SEC = 0.1
# Each DuckDB commit pays a WAL sync (~80 ms measured on a laptop SSD), so
# shards are loaded in groups: at most ~2 commits/s at 500 ms ingest latency.
_INGEST_INTERVAL_SEC = 0.5
_INGEST_MAX_FILES = 128


# ---------------------------------------------------------------------------
# Process-local pipeline (module-level functions are picklable)
# ---------------------------------------------------------------------------

def _get_pipeline():
    pipeline = getattr(_get_pipeline, "_pipeline", None)
    if pipeline is None:
        from ulpf.engine.pipeline import Pipeline
        pipeline = Pipeline()
        _get_pipeline._pipeline = pipeline
    return pipeline


def _process_single_log(raw_line: str) -> dict | None:
    try:
        return _get_pipeline().process_line(raw_line)
    except Exception as e:
        logger.error(f"Worker unhandled exception processing line: {e}")
        return {"success": False, "error": str(e)}


def _benchmark_process_batch(batch_lines: list[str]) -> tuple[int, int, float, dict]:
    """Process a batch; returns (success_count, failure_count, time_ms, format_counts)."""
    try:
        pipeline = _get_pipeline()
        t0 = time.perf_counter()
        results = pipeline.process_batch(batch_lines)
        elapsed = (time.perf_counter() - t0) * 1000
        ok = fail = 0
        formats: dict[str, int] = {}
        for r in results:
            if r.get("success"):
                ok += 1
                fmt = r["event"]["raw_format"]
                formats[fmt] = formats.get(fmt, 0) + 1
            elif not r.get("skipped"):
                fail += 1
        return ok, fail, elapsed, formats
    except Exception as e:
        logger.error(f"Worker unhandled exception processing batch: {e}")
        return 0, len(batch_lines), 0.0, {}


def _process_batch_lines(batch: list) -> list[dict]:
    """Process a batch of lines or (line, sender_ip) tuples."""
    pipeline = _get_pipeline()
    out = []
    for item in batch:
        if isinstance(item, tuple):
            line, sender = item[0], item[1] if len(item) > 1 else ""
        else:
            line, sender = item, ""
        if not line or not line.strip():
            continue
        result = pipeline.process_line(line, source_ip=sender or "")
        if sender and result.get("success"):
            event = result["event"]
            event["metadata"]["ingestion_source_ip"] = sender
            if not event["device"]["ip"]:
                event["device"]["ip"] = sender
        out.append(result)
    return out


def write_parquet_shard(events: list[dict], shard_dir: str) -> str | None:
    """Write events as a typed Parquet shard, published atomically. Returns the path."""
    if not events:
        return None
    import uuid
    import pyarrow.parquet as pq
    from ulpf.storage.database import event_to_row, rows_to_arrow

    table = rows_to_arrow([event_to_row(e) for e in events])
    path = os.path.join(shard_dir, f"shard_{os.getpid()}_{uuid.uuid4().hex}.parquet")
    tmp = path + ".tmp"
    pq.write_table(table, tmp, compression="lz4")
    os.replace(tmp, path)
    return path


# Back-compat name used by older benchmark scripts
def _batch_to_parquet(results: list[dict], shard_dir: str | None = None) -> str | None:
    import tempfile
    events = [r["event"] for r in results if isinstance(r, dict) and r.get("success")]
    return write_parquet_shard(events, shard_dir or tempfile.gettempdir())


def _pid_alive(pid: int) -> bool:
    try:
        import psutil
        return psutil.pid_exists(pid)
    except ImportError:
        if os.name == "nt":
            return True  # cannot tell without psutil; never steal a live spool
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True


# ---------------------------------------------------------------------------
# Worker Pool
# ---------------------------------------------------------------------------

class WorkerPool:
    """
    Multiprocessing worker pool with producer-consumer architecture.

    Args:
        num_workers: worker processes (default: CPU count - 1)
        input_queue: optional shared queue (e.g. fed by NetworkListener); by
                     default each worker gets its own queue (striped dispatch)
        batch_size: lines per batch for submit()
        max_queue_size: max batches per queue (backpressure bound)
        sample_size: events per batch sent back to the host (for live views)
        anomaly_detection: run the anomaly detector inside workers and send
                           detected anomalies back
    """

    def __init__(
        self,
        num_workers: int | None = None,
        input_queue: MPQueue | None = None,
        batch_size: int = _DEFAULT_BATCH_SIZE,
        max_queue_size: int = _MAX_BATCH_QUEUE_SIZE,
        sample_size: int = 0,
        anomaly_detection: bool = False,
    ):
        self.num_workers = num_workers or max(1, (os.cpu_count() or 4) - 1)
        self.batch_size = batch_size
        self.sample_size = sample_size
        self.anomaly_detection = anomaly_detection
        self._custom_input_queue = input_queue is not None
        self.input_queue = input_queue or MPQueue(maxsize=max_queue_size)
        if self._custom_input_queue:
            self.worker_queues = [self.input_queue] * self.num_workers
        else:
            self.worker_queues = [MPQueue(maxsize=max_queue_size) for _ in range(self.num_workers)]
        self.output_queue: MPQueue = MPQueue(maxsize=max_queue_size * 8)
        self._rr_idx = 0

        self._workers: list[mp.Process] = []
        self._writer_thread: Thread | None = None
        self._stop_event = Event()
        self._running = False
        self._db = None
        self._owns_db = False
        self._on_batch: Callable[[dict], None] | None = None

        self._pending_buffer: list = []
        self._buffer_lock = Lock()
        self._flush_event = Event()
        self._flush_thread: Thread | None = None

        # Counters updated by workers (one locked add per batch)
        self.total_processed = mp.Value("q", 0)
        self.total_success = mp.Value("q", 0)
        self.total_failed = mp.Value("q", 0)
        # Counters updated by the host writer thread
        self.total_persisted = 0
        self.total_quarantined_files = 0
        self.shard_dir: str | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, db_path: str | None = None, is_network: bool = False,
              siem_host: str | None = None, siem_port: int | None = None,
              save_local: bool = True, db: Any = None,
              on_batch: Callable[[dict], None] | None = None,
              siem_proto: str = "udp") -> None:
        """Start workers and the host-side writer.

        Args:
            db_path: event store path (ignored when ``db`` is given)
            db: an already-open Database to ingest into (shares its connection)
            on_batch: callback invoked (on the writer thread) with each worker
                      status message: counts, ``sample`` events, ``anomalies``
        """
        import uuid
        from ulpf.platform.paths import get_data_dir

        self._running = True
        self._stop_event.clear()
        self._flush_event.clear()
        self._on_batch = on_batch

        spool_root = os.path.join(str(get_data_dir()), "spool")
        self.shard_dir = os.path.join(spool_root, uuid.uuid4().hex)
        os.makedirs(self.shard_dir, exist_ok=True)
        with open(os.path.join(self.shard_dir, "owner.pid"), "w") as f:
            f.write(str(os.getpid()))

        if save_local:
            if db is not None:
                self._db, self._owns_db = db, False
            else:
                from ulpf.storage import create_storage
                self._db, self._owns_db = create_storage(path=db_path), True
            self._recover_orphans(spool_root)

        self._flush_thread = Thread(target=self._flush_thread_loop, name="ulpf-buffer-flusher", daemon=True)
        self._flush_thread.start()

        for i in range(self.num_workers):
            p = mp.Process(
                target=_worker_loop,
                args=(self.worker_queues[i], self.output_queue, is_network,
                      self.total_processed, self.total_success, self.total_failed,
                      self.shard_dir if save_local else None,
                      siem_host, siem_port, siem_proto,
                      self.sample_size, self.anomaly_detection),
                name=f"ulpf-worker-{i}",
                daemon=True,
            )
            p.start()
            self._workers.append(p)
            logger.info(f"Started worker process {p.name} (PID: {p.pid})")

        self._writer_thread = Thread(target=self._writer_loop, name="ulpf-batch-writer", daemon=True)
        self._writer_thread.start()
        logger.info(f"Worker pool started: {self.num_workers} workers, batch_size={self.batch_size}")

    def stop(self, timeout: float = 30.0) -> dict:
        """Drain queues, stop workers, ingest remaining shards. Returns final metrics."""
        self._running = False
        self._flush_buffer()
        if self._flush_thread:
            self._flush_event.set()
            self._flush_thread.join(timeout=2.0)

        logger.info("Stopping worker pool...")
        unique_queues = list(dict.fromkeys(self.worker_queues))
        pills_per_queue = self.num_workers if self._custom_input_queue else 1
        for q in unique_queues:
            for _ in range(pills_per_queue):
                try:
                    q.put(_POISON_PILL, timeout=timeout)
                except Full:
                    logger.error("Could not deliver shutdown signal: worker queue full")

        deadline = time.monotonic() + timeout
        for p in self._workers:
            p.join(timeout=max(0.1, deadline - time.monotonic()))
            if p.is_alive():
                logger.warning(f"Force terminating worker {p.name}")
                p.terminate()
        self._workers.clear()

        self._stop_event.set()
        if self._writer_thread:
            self._writer_thread.join(timeout=timeout)
            self._writer_thread = None

        if self.shard_dir:
            try:
                leftovers = [f for f in os.listdir(self.shard_dir) if f.endswith(".parquet")]
                if not leftovers:
                    for f in os.listdir(self.shard_dir):
                        os.remove(os.path.join(self.shard_dir, f))
                    os.rmdir(self.shard_dir)
            except OSError:
                pass

        if self._owns_db and self._db is not None:
            self._db.close()
        metrics = self.get_metrics()
        logger.info(f"Worker pool stopped. Metrics: {metrics}")
        return metrics

    # ------------------------------------------------------------------
    # Producer API
    # ------------------------------------------------------------------

    def submit(self, raw_line: str) -> None:
        """Submit a raw log line (auto-batched; flushed by size or every 100 ms)."""
        if not self._running:
            return
        with self._buffer_lock:
            self._pending_buffer.append(raw_line)
            full = len(self._pending_buffer) >= self.batch_size
        if full:
            self._flush_buffer()
        else:
            self._flush_event.set()

    def submit_batch(self, lines: list) -> None:
        """Submit lines (or (line, sender_ip) tuples) in batch_size chunks."""
        if not self._running:
            return
        cleaned = [l for l in lines if l and (l[0] if isinstance(l, tuple) else l).strip()]
        for i in range(0, len(cleaned), self.batch_size):
            self._enqueue_batch(cleaned[i:i + self.batch_size])

    def _flush_buffer(self) -> None:
        with self._buffer_lock:
            if not self._pending_buffer:
                return
            batch = self._pending_buffer
            self._pending_buffer = []
        self._enqueue_batch(batch)

    def _enqueue_batch(self, batch: list) -> None:
        """Striped round-robin dispatch; blocks (backpressure) rather than dropping."""
        n = self.num_workers
        for attempt in range(n):
            q = self.worker_queues[(self._rr_idx + attempt) % n]
            try:
                q.put_nowait(batch)
                self._rr_idx = (self._rr_idx + attempt + 1) % n
                return
            except Full:
                continue
        # Every queue is full: apply backpressure to the producer
        q = self.worker_queues[self._rr_idx % n]
        self._rr_idx = (self._rr_idx + 1) % n
        while True:
            try:
                q.put(batch, timeout=1.0)
                return
            except Full:
                if not any(p.is_alive() for p in self._workers):
                    raise RuntimeError("All ULPF worker processes have exited; cannot enqueue")
                logger.warning(f"Worker queues saturated — producer blocked on {len(batch)} lines")

    def get_queue_depth(self) -> int:
        depth = 0
        for q in dict.fromkeys(self.worker_queues):
            try:
                depth += q.qsize()
            except (NotImplementedError, OSError):
                pass
        return depth

    def _flush_thread_loop(self) -> None:
        while self._running:
            self._flush_event.wait(timeout=_FLUSH_INTERVAL_SEC)
            self._flush_event.clear()
            if self._pending_buffer:
                self._flush_buffer()

    def get_metrics(self) -> dict:
        processed = self.total_processed.value
        success = self.total_success.value
        try:
            out_q = self.output_queue.qsize()
        except (NotImplementedError, OSError):
            out_q = -1
        return {
            "total_processed": processed,
            "total_success": success,
            "total_failed": self.total_failed.value,
            "total_persisted": self.total_persisted,
            "quarantined_shards": self.total_quarantined_files,
            "success_rate": round(success / max(processed, 1) * 100, 2),
            "input_queue_size": self.get_queue_depth(),
            "output_queue_size": out_q,
            "num_workers": self.num_workers,
            "batch_size": self.batch_size,
        }

    # ------------------------------------------------------------------
    # Host-side writer
    # ------------------------------------------------------------------

    def _recover_orphans(self, spool_root: str) -> None:
        """Ingest shards left behind by pools whose owning process died."""
        try:
            entries = os.listdir(spool_root)
        except OSError:
            return
        for name in entries:
            d = os.path.join(spool_root, name)
            if d == self.shard_dir or not os.path.isdir(d):
                continue
            try:
                with open(os.path.join(d, "owner.pid")) as f:
                    owner = int(f.read().strip() or 0)
            except (OSError, ValueError):
                owner = 0
            if owner and _pid_alive(owner):
                continue
            files = [os.path.join(d, f) for f in os.listdir(d) if f.endswith(".parquet")]
            if files:
                logger.warning(f"Recovering {len(files)} orphaned spool shard(s) from {d}")
                if self._ingest(files):
                    continue  # store unavailable; leave the spool for a later attempt
            try:
                for f in os.listdir(d):
                    if not f.endswith(".bad"):
                        os.remove(os.path.join(d, f))
                os.rmdir(d)
            except OSError:
                pass

    def _ingest(self, files: list[str]) -> list[str]:
        """Bulk-load shards. Returns shards that must be retried later."""
        if not files or self._db is None:
            return []
        import duckdb
        unreadable = (duckdb.IOException, duckdb.InvalidInputException)
        retry: list[str] = []
        try:
            self.total_persisted += self._db.ingest_parquet(files)
            ok_files = files
        except unreadable as e:
            logger.error(f"Bulk shard ingest failed ({e}); retrying shards individually")
            ok_files = []
            for i, f in enumerate(files):
                try:
                    self.total_persisted += self._db.ingest_parquet([f])
                    ok_files.append(f)
                except unreadable as e2:
                    logger.error(f"Quarantining unreadable shard {f}: {e2}")
                    self.total_quarantined_files += 1
                    try:
                        os.replace(f, f + ".bad")
                    except OSError:
                        pass
                except Exception as e2:
                    logger.error(f"Shard ingest error, will retry: {e2}")
                    retry.extend(files[i:])
                    break
        except Exception as e:
            # Store-level problem (locked, disk full …): keep every shard for retry
            logger.error(f"Shard ingest error, will retry {len(files)} shard(s): {e}")
            return list(files)
        for f in ok_files:
            try:
                os.remove(f)
            except OSError:
                logger.warning(f"Could not delete ingested shard {f}")
        return retry

    def _handle(self, msg: Any, pending: list[str]) -> None:
        if isinstance(msg, dict):
            if msg.get("file"):
                pending.append(msg["file"])
            if self._on_batch is not None:
                try:
                    self._on_batch(msg)
                except Exception:
                    logger.debug("on_batch callback failed", exc_info=True)
        elif isinstance(msg, list):
            # Results produced synchronously by the host (legacy path)
            events = [r["event"] for r in msg if isinstance(r, dict) and r.get("success")]
            if events and self._db is not None:
                self.total_persisted += self._db.insert_batch(events)

    def _writer_loop(self) -> None:
        pending: list[str] = []
        last_ingest = time.monotonic()
        while True:
            try:
                msg = self.output_queue.get(timeout=_INGEST_INTERVAL_SEC)
            except Empty:
                msg = None
            if msg is not None and msg != _POISON_PILL:
                self._handle(msg, pending)
            now = time.monotonic()
            if pending and (len(pending) >= _INGEST_MAX_FILES or now - last_ingest >= _INGEST_INTERVAL_SEC
                            or msg is None):
                pending = self._ingest(pending)
                last_ingest = now
            if self._stop_event.is_set() and msg is None:
                break
        # Final drain: anything still queued after the workers exited
        while True:
            try:
                msg = self.output_queue.get_nowait()
            except Empty:
                break
            if msg != _POISON_PILL:
                self._handle(msg, pending)
        if self.shard_dir and os.path.isdir(self.shard_dir):
            on_disk = [os.path.join(self.shard_dir, f) for f in os.listdir(self.shard_dir)
                       if f.endswith(".parquet")]
            pending = list(dict.fromkeys(pending + on_disk))
        self._ingest(pending)
        logger.info("Batch writer stopped")


# ---------------------------------------------------------------------------
# Worker process main loop
# ---------------------------------------------------------------------------

def _worker_loop(
    input_queue: MPQueue,
    output_queue: MPQueue,
    is_network: bool,
    total_processed,
    total_success,
    total_failed,
    shard_dir: str | None = None,
    siem_host: str | None = None,
    siem_port: int | None = None,
    siem_proto: str = "udp",
    sample_size: int = 0,
    anomaly_detection: bool = False,
) -> None:
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (ValueError, OSError):
        pass

    pid = os.getpid()
    _get_pipeline()
    from ulpf.engine.perf import tune_gc
    tune_gc()
    detector = None
    if anomaly_detection:
        from ulpf.intelligence.anomaly import AnomalyDetector
        detector = AnomalyDetector()
    forwarder = None
    if siem_host and siem_port:
        from ulpf.ingestion.forwarder import SiemForwarder
        forwarder = SiemForwarder(siem_host, siem_port, siem_proto)
    logger.info(f"Worker {pid} started")

    while True:
        try:
            item = input_queue.get(timeout=1.0)
        except Empty:
            continue
        except (EOFError, OSError):
            break
        if item == _POISON_PILL:
            break

        try:
            if isinstance(item, dict):
                batch = [(item.get("raw", ""), item.get("source_ip") or "")]
            elif isinstance(item, str):
                batch = [l for l in item.splitlines() if l.strip()]
            else:
                batch = []
                for s in item:
                    if isinstance(s, str) and "\n" in s:
                        batch.extend(l for l in s.splitlines() if l.strip())
                    else:
                        batch.append(s)

            results = _process_batch_lines(batch)
            events = [r["event"] for r in results if r.get("success")]
            skipped = sum(1 for r in results if r.get("skipped"))
            failed = len(results) - len(events) - skipped

            anomalies: list[dict] = []
            if detector is not None and events:
                anomalies = detector.analyse_batch(events)[:200]
            if forwarder is not None and events:
                forwarder.send(events)

            shard = write_parquet_shard(events, shard_dir) if shard_dir else None
            formats: dict[str, int] = {}
            for e in events:
                f = e["raw_format"]
                formats[f] = formats.get(f, 0) + 1

            with total_processed.get_lock():
                total_processed.value += len(results)
            with total_success.get_lock():
                total_success.value += len(events)
            if failed:
                with total_failed.get_lock():
                    total_failed.value += failed

            output_queue.put({
                "type": "batch", "pid": pid, "processed": len(results), "success": len(events),
                "failed": failed, "skipped": skipped, "file": shard, "formats": formats,
                "sample": events[-sample_size:] if sample_size else [],
                "anomalies": anomalies, "ts": time.time(),
            })
        except Exception as e:
            logger.exception(f"Worker {pid} failed on a batch: {e}")
            with total_failed.get_lock():
                total_failed.value += len(item) if isinstance(item, list) else 1

    if forwarder is not None:
        forwarder.close()
    logger.info(f"Worker {pid} exiting")
