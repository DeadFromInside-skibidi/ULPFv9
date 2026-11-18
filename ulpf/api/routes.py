"""
ULPF REST API — FastAPI Routes
================================
Exposes the framework over REST (OpenAPI docs at /docs).

* Endpoints are synchronous ``def`` handlers: parsing is CPU-bound, so FastAPI
  runs them in its worker threadpool instead of blocking the event loop.
* The pipeline keeps per-stream parser state, so calls into it are serialised
  with a lock; storage has its own lock.
* Authentication: set ``ULPF_API_KEY`` (admin) or a role keys file to require
  an ``X-API-Key`` header on every endpoint except ``/health``. Each route
  needs a role: ``read`` for queries, ``write`` for ingestion, ``admin`` for
  auto-learning, correlation and listener control (see ``ulpf.api.auth``).
"""
from __future__ import annotations

import csv
import io
import logging
import os
import threading
import time
from typing import Optional

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse, Response

from ulpf.api.auth import require
from ulpf.engine.schema import SCHEMA_DEFINITION
from ulpf.plugin.interface import ULPFPlugin

logger = logging.getLogger(__name__)

MAX_UPLOAD_BYTES = int(os.environ.get("ULPF_MAX_UPLOAD_MB", "512")) * 1024 * 1024
MAX_BATCH_LINES = 100_000


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """Any valid key (ULPF_API_KEY or a role key from the keys file); open when none is configured.

    Kept for callers that only need authentication; every route below declares
    the role it needs instead (a valid key alone is not authorisation).
    """
    from ulpf.api.auth import auth_configured, role_of
    if auth_configured() and role_of(x_api_key) is None:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")


# Every route declares its role: read (queries, inspection), write (ingestion and
# records it creates), admin (learning, correlation rewrites, listener control).
READ = [Depends(require("read"))]
WRITE = [Depends(require("write"))]
ADMIN = [Depends(require("admin"))]

router = APIRouter(prefix="/api/v1")
public_router = APIRouter(prefix="/api/v1")

_plugin: ULPFPlugin | None = None
_plugin_lock = threading.Lock()
_pipeline_lock = threading.Lock()
_started_at = time.time()
# Set by `ulpf run`: ingestion endpoints then journal through the runtime
# (durable, sealed, routed to every output) instead of writing the store directly.
_runtime = None


def attach_runtime(runtime) -> None:
    """Serve the API from a running v9 runtime (shares its store; ingest goes through its journal)."""
    global _plugin, _runtime
    p = ULPFPlugin()
    p.initialize(storage=runtime.database)
    p.start()
    _plugin = p
    _runtime = runtime


def detach_runtime(runtime=None) -> None:
    """Stop serving from ``runtime`` (its API server stopped); later requests use a standalone plugin."""
    global _plugin, _runtime
    if runtime is not None and _runtime is not runtime:
        return
    with _plugin_lock:
        if _runtime is not None and _plugin is not None:
            _plugin.shutdown()          # the plugin wraps the runtime's store; the runtime closes it
            _plugin = None
        _runtime = None


def _runtime_ingest(lines: list[str], source: str = "api") -> dict:
    raws = [l.encode("utf-8") for l in lines if l and l.strip()]
    first = _runtime.ingest("api", source, raws) if raws else None
    return {"accepted": len(raws), "journal_first_seq": first,
            "journal_last_seq": first + len(raws) - 1 if raws else None,
            "note": "accepted into the durable journal; events are processed and routed asynchronously"}


def get_plugin() -> ULPFPlugin:
    """Lazily initialise the shared plugin (first request, or app startup)."""
    global _plugin
    if _plugin is None:
        with _plugin_lock:
            if _plugin is None:
                p = ULPFPlugin()
                p.initialize()
                p.start()
                _plugin = p
    return _plugin


def shutdown_plugin() -> None:
    global _plugin
    _listener_manager.stop()
    with _plugin_lock:
        if _plugin is not None:
            _plugin.shutdown()
            _plugin = None


def _process_lines(lines: list[str], stream: bool = True) -> tuple[list[dict], list[dict], list[dict]]:
    """Run lines through the pipeline + analytics and store them.

    Returns (results, events, anomalies).
    """
    plugin = get_plugin()
    with _pipeline_lock:
        if stream:
            plugin.pipeline.registry.reset_stream_state()
        results = [plugin.pipeline.process_line(l) for l in lines if l and l.strip()]
        events = [r["event"] for r in results if r.get("success")]
        anomalies = plugin.anomaly_detector.analyse_batch(events) if plugin.anomaly_detector and events else []
        if plugin.correlator:
            for e in events:
                plugin.correlator.add_and_correlate(e)
    if events:
        plugin.storage.insert_batch(events)
    if anomalies:
        plugin.storage.store_anomalies_bulk(anomalies)
    return results, events, anomalies


def _summary(results: list[dict], events: list[dict], anomalies: list[dict]) -> dict:
    return {
        "total": len(results),
        "successful": len(events),
        "skipped_headers": sum(1 for r in results if r.get("skipped")),
        "failed": sum(1 for r in results if not r.get("success") and not r.get("skipped")),
        "stored": len(events),
        "anomalies_detected": len(anomalies),
        "format_distribution": _count(e["raw_format"] for e in events),
    }


def _count(items) -> dict:
    out: dict = {}
    for i in items:
        out[i] = out.get(i, 0) + 1
    return out


# ---------------------------------------------------------------------------
# Network listener lifecycle (managed via REST)
# ---------------------------------------------------------------------------

class _ListenerManager:
    def __init__(self):
        self._listener = None
        self._worker_pool = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._config = {"host": "0.0.0.0", "port": 5514, "protocol": "both", "workers": None}
        self._start_time: float | None = None
        self._error: str | None = None
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()

    def start(self, host: str, port: int, protocol: str, workers: int | None) -> dict:
        with self._lock:
            if self.is_running:
                return {"success": False,
                        "error": f"Listener already running on {self._config['host']}:{self._config['port']}"}
            from multiprocessing import Queue as MPQueue
            from ulpf.ingestion.listener import NetworkListener
            from ulpf.ingestion.workers import WorkerPool

            self._config = {"host": host, "port": port, "protocol": protocol, "workers": workers}
            shared_queue = MPQueue(maxsize=2_000)
            pool = WorkerPool(num_workers=workers, input_queue=shared_queue, anomaly_detection=True)
            pool.start(db=get_plugin().storage, is_network=True)
            listener = NetworkListener(shared_queue, host=host, port=port)
            ready = threading.Event()
            self._error = None
            self._listener, self._worker_pool = listener, pool
            self._running = True
            self._start_time = time.time()
            self._thread = threading.Thread(target=self._run, args=(protocol, ready),
                                            daemon=True, name="ulpf-network-listener")
            self._thread.start()
            ready.wait(timeout=5.0)
            if self._error:
                self._running = False
                pool.stop()
                self._listener = self._worker_pool = None
                msg = self._error
                if "10048" in msg or "in use" in msg.lower():
                    msg = f"Port {port} is already in use. Choose a different port."
                elif "10013" in msg or "permission" in msg.lower():
                    msg = f"Permission denied binding to port {port} (ports < 1024 need elevated rights)."
                return {"success": False, "error": msg}
            logger.info(f"Network listener started on {host}:{port} ({protocol})")
            return {"success": True, "message": f"Network listener started on {host}:{port} ({protocol.upper()})",
                    "config": self._config}

    def _run(self, protocol: str, ready: threading.Event) -> None:
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            try:
                loop.run_until_complete(self._listener.start(protocol))
            except OSError as e:
                self._error = str(e)
                return
            finally:
                ready.set()
            while self._running:
                loop.run_until_complete(asyncio.sleep(0.5))
        finally:
            try:
                loop.run_until_complete(self._listener.stop())
            except Exception:
                pass
            loop.close()

    def stop(self) -> dict:
        with self._lock:
            if not self.is_running:
                return {"success": False, "error": "No listener is currently running"}
            self._running = False
            self._thread.join(timeout=5)
            stats = self._listener.stats.to_dict() if self._listener else {}
            metrics = self._worker_pool.stop() if self._worker_pool else {}
            self._listener = self._worker_pool = self._thread = None
            return {"success": True, "message": "Network listener stopped",
                    "final_stats": stats, "worker_metrics": metrics}

    def get_status(self) -> dict:
        if not self.is_running:
            return {"running": False, "config": self._config, "stats": {}}
        return {
            "running": True,
            "config": self._config,
            "uptime_seconds": round(time.time() - self._start_time, 1) if self._start_time else 0,
            "stats": self._listener.stats.to_dict() if self._listener else {},
            "workers": self._worker_pool.get_metrics() if self._worker_pool else {},
        }


_listener_manager = _ListenerManager()


# ---- Health (unauthenticated, for load balancers / container HEALTHCHECK) ----

@public_router.get("/health", tags=["Health"])
def health():
    plugin = get_plugin()
    h = plugin.health()
    status_code = 200 if h.get("status") == "healthy" else 503
    return JSONResponse(h, status_code=status_code)


# ---- Ingestion ----

@router.post("/ingest", tags=["Ingestion"], dependencies=WRITE)
def ingest_line(body: dict):
    """Ingest a single log line: {"raw": "...", "event_id"?: "...", "tags"?: [...]}"""
    raw = body.get("raw", "")
    if not raw:
        return JSONResponse({"error": "Missing 'raw' field"}, 400)
    if _runtime is not None:
        return _runtime_ingest([raw])
    plugin = get_plugin()
    with _pipeline_lock:
        result = plugin.process_event(body)
    return result


@router.post("/ingest/batch", tags=["Ingestion"], dependencies=WRITE)
def ingest_batch(body: dict):
    """Ingest multiple lines: {"lines": ["...", ...]} (max 100k per request)."""
    lines = body.get("lines", [])
    if not lines or not isinstance(lines, list):
        return JSONResponse({"error": "Missing 'lines' list"}, 400)
    if len(lines) > MAX_BATCH_LINES:
        return JSONResponse({"error": f"At most {MAX_BATCH_LINES} lines per request"}, 413)
    if _runtime is not None:
        return _runtime_ingest([str(l) for l in lines])
    results, events, anomalies = _process_lines([str(l) for l in lines])
    out = _summary(results, events, anomalies)
    out["results"] = results[:10]
    return out


@router.post("/ingest/file", tags=["Ingestion"], dependencies=WRITE)
def ingest_file(file: UploadFile = File(...)):
    """Upload and process a log file (streamed in 20k-line batches)."""
    totals = {"total": 0, "successful": 0, "skipped_headers": 0, "failed": 0, "stored": 0,
              "anomalies_detected": 0, "format_distribution": {}}
    size = 0
    pending = b""
    first = True
    t0 = time.perf_counter()
    while True:
        chunk = file.file.read(4 * 1024 * 1024)
        size += len(chunk)
        if size > MAX_UPLOAD_BYTES:
            return JSONResponse({"error": f"Upload exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB"}, 413)
        data = pending + chunk
        if chunk:
            data, _, pending = data.rpartition(b"\n")
        else:
            pending = b""
        lines = data.decode("utf-8", errors="replace").splitlines()
        if _runtime is not None:
            for i in range(0, len(lines), 20_000):
                r = _runtime_ingest(lines[i:i + 20_000], source=f"upload:{file.filename}")
                totals["total"] += r["accepted"]
                totals["successful"] += r["accepted"]
            if not chunk:
                break
            continue
        for i in range(0, len(lines), 20_000):
            results, events, anomalies = _process_lines(lines[i:i + 20_000], stream=first)
            first = False
            s = _summary(results, events, anomalies)
            for k in ("total", "successful", "skipped_headers", "failed", "stored", "anomalies_detected"):
                totals[k] += s[k]
            for f, n in s["format_distribution"].items():
                totals["format_distribution"][f] = totals["format_distribution"].get(f, 0) + n
        if not chunk:
            break
    elapsed = time.perf_counter() - t0
    return {"filename": file.filename, "bytes": size, **totals,
            "elapsed_sec": round(elapsed, 3),
            "events_per_second": round(totals["successful"] / elapsed, 1) if elapsed else 0.0}


# ---- Query ----

@router.get("/events", tags=["Query"], dependencies=READ)
def query_events(
    category: Optional[str] = None,
    action: Optional[str] = None,
    severity_min: Optional[int] = Query(default=None, ge=0, le=10),
    severity_max: Optional[int] = Query(default=None, ge=0, le=10),
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    raw_format: Optional[str] = None,
    timestamp_after: Optional[str] = None,
    timestamp_before: Optional[str] = None,
    q: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    """Query normalised events (newest first). Timestamps are ISO-8601 UTC strings."""
    filters = {k: v for k, v in {
        "category": category, "action": action, "severity_min": severity_min,
        "severity_max": severity_max, "source_ip": source_ip, "destination_ip": destination_ip,
        "raw_format": raw_format, "timestamp_after": timestamp_after,
        "timestamp_before": timestamp_before, "q": q,
    }.items() if v is not None}
    db = get_plugin().storage
    events = db.query(filters, limit, offset)
    return {"count": len(events), "total_matching": db.count_events(filters), "events": events}


@router.get("/events/{event_id}", tags=["Query"], dependencies=READ)
def get_event(event_id: str):
    event = get_plugin().storage.get_event(event_id)
    if not event:
        return JSONResponse({"error": "Event not found"}, 404)
    return event


@router.get("/search", tags=["Query"], dependencies=READ)
def search_events(q: str, limit: int = Query(default=50, ge=1, le=500)):
    """Case-insensitive substring search across raw events, messages and tags."""
    events = get_plugin().storage.search(q, limit)
    return {"query": q, "count": len(events), "events": events}


# ---- Stats & Schema ----

@router.get("/stats", tags=["Stats"], dependencies=READ)
def get_stats():
    plugin = get_plugin()
    return {
        "database": plugin.storage.stats(),
        "pipeline": plugin.pipeline.get_metrics(),
        "anomaly_baseline": plugin.anomaly_detector.get_baseline_report() if plugin.anomaly_detector else {},
        "uptime_seconds": round(time.time() - _started_at, 1),
    }


@router.get("/metrics", tags=["Stats"], response_class=Response, dependencies=READ)
def prometheus_metrics():
    """Prometheus text exposition of pipeline, store and listener counters."""
    plugin = get_plugin()
    m = plugin.pipeline.get_metrics()
    db = plugin.storage.stats()
    lines = [
        "# HELP ulpf_events_processed_total Lines processed by the API pipeline.",
        "# TYPE ulpf_events_processed_total counter",
        f"ulpf_events_processed_total {m['total_events']}",
        "# HELP ulpf_events_failed_total Lines that raised an error in the pipeline.",
        "# TYPE ulpf_events_failed_total counter",
        f"ulpf_events_failed_total {m['failed']}",
        "# HELP ulpf_store_events Events currently in the event store.",
        "# TYPE ulpf_store_events gauge",
        f"ulpf_store_events {db.get('total_events', 0)}",
        "# HELP ulpf_store_events_by_format Stored events per detected format.",
        "# TYPE ulpf_store_events_by_format gauge",
    ]
    lines += [f'ulpf_store_events_by_format{{format="{k}"}} {v}' for k, v in (db.get("by_format") or {}).items()]
    status = _listener_manager.get_status()
    if status.get("running"):
        s, w = status.get("stats", {}), status.get("workers", {})
        lines += [
            "# TYPE ulpf_listener_messages_received_total counter",
            f"ulpf_listener_messages_received_total {s.get('packets_received', 0)}",
            "# TYPE ulpf_listener_messages_dropped_total counter",
            f"ulpf_listener_messages_dropped_total {s.get('messages_dropped', 0)}",
            "# TYPE ulpf_worker_events_persisted_total counter",
            f"ulpf_worker_events_persisted_total {w.get('total_persisted', 0)}",
            "# TYPE ulpf_worker_queue_depth gauge",
            f"ulpf_worker_queue_depth {w.get('input_queue_size', 0)}",
        ]
    if _runtime is not None:
        from ulpf.runtime.metrics import prometheus_lines
        lines += prometheus_lines(_runtime.stats())
    return Response("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


@router.get("/schema", tags=["Schema"], dependencies=READ)
def get_schema():
    """The ULPF unified event schema (field catalogue, severity scale, categories)."""
    return SCHEMA_DEFINITION


@router.get("/parsers", tags=["Parsers"], dependencies=READ)
def list_parsers():
    plugin = get_plugin()
    learned = [s.to_dict() for s in plugin.pipeline.auto_engine.registry.list_parsers()] \
        if plugin.pipeline.auto_engine else []
    return {"parsers": plugin.pipeline.registry.list_parsers(), "learned_parsers": learned}


@router.post("/parsers/test", tags=["Parsers"], dependencies=READ)
def test_parser(body: dict):
    """Parse (without storing) one line or a multi-line batch: {"raw": "..."}"""
    raw = body.get("raw", "")
    plugin = get_plugin()
    with _pipeline_lock:
        lines = [l for l in raw.splitlines() if l.strip()]
        if len(lines) > 1:
            return plugin.pipeline.process_text(raw)
        return plugin.pipeline.process_line(raw)


# ---- Auto-Parser (APG) ----

def _is_known(line: str) -> bool:
    pipeline = get_plugin().pipeline
    parser = pipeline.registry.get_parser_for_format(pipeline._detect(line)["format_name"])
    return parser is not None and parser.parse(line) is not None


@router.post("/auto-learn", tags=["Auto-Parser"], dependencies=ADMIN)
def auto_learn(body: dict):
    """Learn parsers for unknown formats: {"lines": [...], "save": true}.

    Lines already handled by built-in parsers are excluded. Accepted parsers
    are validated, signed, persisted and immediately active in the pipeline.
    """
    lines = body.get("lines", [])
    if not lines:
        return JSONResponse({"error": "Missing 'lines'"}, 400)
    engine = get_plugin().pipeline.auto_engine
    if engine is None:
        return JSONResponse({"error": "Auto-parser disabled (enable_auto_parser=False)"}, 400)
    with _pipeline_lock:
        report = engine.learn([str(l) for l in lines], is_known=_is_known, save=bool(body.get("save", True)))
    for a in report["accepted"]:
        a["spec"] = a["spec"].to_dict()
    return report


@router.get("/auto-learn/configs", tags=["Auto-Parser"], dependencies=READ)
def list_learned():
    engine = get_plugin().pipeline.auto_engine
    return {"configs": [s.to_dict() for s in engine.registry.list_all()] if engine else []}


# ---- Log DNA ----

def _dna():
    from ulpf.intelligence.log_dna import LogDNA
    return LogDNA()


@router.post("/fingerprint", tags=["Log DNA"], dependencies=WRITE)
def fingerprint(body: dict):
    lines = body.get("lines", [])
    if not lines:
        return JSONResponse({"error": "Missing 'lines'"}, 400)
    dna = _dna()
    try:
        fp = dna.fingerprint(lines, body.get("label", ""))
    except ValueError as e:
        return JSONResponse({"error": str(e)}, 400)
    fid = dna.register(fp)
    return {"fingerprint_id": fid, "fingerprint": fp.to_dict()}


@router.post("/fingerprint/match", tags=["Log DNA"], dependencies=READ)
def fingerprint_match(body: dict):
    fid, score = _dna().match(body.get("lines", []))
    return {"matched_id": fid, "similarity": round(score, 4)}


@router.post("/fingerprint/drift", tags=["Log DNA"], dependencies=READ)
def detect_drift(body: dict):
    return _dna().detect_drift(body.get("fingerprint_id", ""), body.get("lines", []))


# ---- Correlation / anomalies ----

@router.post("/correlate", tags=["Correlation"], dependencies=ADMIN)
def correlate(body: dict):
    """Correlate given event IDs, or the most recent N events: {"event_ids"?: [...], "limit"?: 100}"""
    from ulpf.intelligence.correlation import EventCorrelator
    db = get_plugin().storage
    event_ids = body.get("event_ids") or []
    events = db.get_events(event_ids) if event_ids else db.query(limit=min(int(body.get("limit", 100)), 50_000))
    correlator = EventCorrelator(float(body.get("time_window_seconds", 60.0)))
    correlator.add_events(events)
    groups = correlator.correlate()
    for g in groups:
        db.set_correlation([e["event_id"] for e in g.events if e.get("event_id")], g.correlation_id)
    return {"events_analysed": len(events), "correlation_groups": len(groups),
            "groups": correlator.get_results()}


@router.get("/anomalies", tags=["Anomaly"], dependencies=READ)
def get_anomalies(limit: int = Query(default=50, ge=1, le=10_000)):
    plugin = get_plugin()
    live = plugin.anomaly_detector.get_anomalies(limit) if plugin.anomaly_detector else []
    return {
        "anomalies": live or plugin.storage.query_anomalies(limit),
        "baseline": plugin.anomaly_detector.get_baseline_report() if plugin.anomaly_detector else {},
    }


# ---- Forensics ----

def _forensics():
    fb = get_plugin().forensic_builder
    if fb is None:
        raise HTTPException(status_code=400, detail="Forensic intelligence disabled")
    return fb


@router.post("/forensic/chain", tags=["Forensic"], dependencies=WRITE)
def create_evidence_chain(body: dict):
    """Build an evidence chain: {"event_ids": [...]} or {"limit": N} for the latest N events."""
    db = get_plugin().storage
    ids = body.get("event_ids") or []
    events = db.get_events(ids) if ids else db.query(limit=min(int(body.get("limit", 0) or 0), 100_000))
    if not events:
        return JSONResponse({"error": "No valid events"}, 400)
    chain = _forensics().build_from_events(events, body.get("description", "Evidence chain"), body.get("tags", []))
    return {"chain": chain.to_dict()}


@router.post("/forensic/export/{chain_id}", tags=["Forensic"], dependencies=WRITE)
def export_evidence(chain_id: str):
    try:
        return {"message": "Evidence package exported", "filepath": _forensics().export_package(chain_id)}
    except ValueError as e:
        return JSONResponse({"error": str(e)}, 404)


@router.get("/forensic/verify/{chain_id}", tags=["Forensic"], dependencies=READ)
def verify_chain(chain_id: str):
    return _forensics().verify_chain(chain_id)


@router.post("/forensic/verify-package", tags=["Forensic"], dependencies=READ)
def verify_package_upload(file: UploadFile = File(...)):
    """Independently verify an exported evidence package file."""
    import tempfile
    from ulpf.intelligence.forensic import verify_package
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        tmp.write(file.file.read())
        path = tmp.name
    try:
        return verify_package(path)
    except ValueError as e:
        return JSONResponse({"valid": False, "problems": [f"Not a valid package: {e}"]}, 400)
    finally:
        os.unlink(path)


@router.get("/forensic/chains", tags=["Forensic"], dependencies=READ)
def list_chains():
    fb = get_plugin().forensic_builder
    return {"chains": fb.list_chains() if fb else []}


# ---- Export ----

_CSV_FIELDS = ["event_id", "timestamp", "category", "severity", "action", "source_ip", "source_port",
               "destination_ip", "destination_port", "protocol", "raw_format", "message"]


@router.get("/export", tags=["Export"], dependencies=READ)
def export_events(format: str = Query(default="json", pattern="^(json|csv)$"),
                  limit: int = Query(default=1000, ge=1, le=100_000)):
    """Export recent events as JSON or CSV (text/csv attachment)."""
    events = get_plugin().storage.query(limit=limit)
    if format == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS)
        writer.writeheader()
        for e in events:
            src, dst = e.get("source") or {}, e.get("destination") or {}
            writer.writerow({
                "event_id": e.get("event_id"), "timestamp": e.get("timestamp"), "category": e.get("category"),
                "severity": e.get("severity"), "action": e.get("action"),
                "source_ip": src.get("ip"), "source_port": src.get("port"),
                "destination_ip": dst.get("ip"), "destination_port": dst.get("port"),
                "protocol": (e.get("network") or {}).get("protocol"), "raw_format": e.get("raw_format"),
                "message": (e.get("message") or "")[:500],
            })
        return Response(content=buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": 'attachment; filename="ulpf_events.csv"'})
    return {"count": len(events), "events": events}


# ---- Network Listener Control ----

@router.post("/listener/start", tags=["Listener"], dependencies=ADMIN)
def start_listener(body: dict):
    """Start the syslog listener: {"host", "port", "protocol": udp|tcp|both, "workers"}"""
    try:
        port = int(body.get("port", 5514))
    except (TypeError, ValueError):
        return JSONResponse({"success": False, "error": "port must be an integer"}, 400)
    protocol = str(body.get("protocol", "both")).lower()
    if not 1 <= port <= 65535:
        return JSONResponse({"success": False, "error": "Port must be between 1 and 65535"}, 400)
    if protocol not in ("udp", "tcp", "both"):
        return JSONResponse({"success": False, "error": "Protocol must be 'udp', 'tcp', or 'both'"}, 400)
    workers = body.get("workers")
    result = _listener_manager.start(host=str(body.get("host", "0.0.0.0")), port=port, protocol=protocol,
                                     workers=int(workers) if workers else None)
    return result if result.get("success") else JSONResponse(result, 400)


@router.post("/listener/stop", tags=["Listener"], dependencies=ADMIN)
def stop_listener():
    result = _listener_manager.stop()
    return result if result.get("success") else JSONResponse(result, 400)


@router.get("/listener/status", tags=["Listener"], dependencies=READ)
def listener_status():
    return _listener_manager.get_status()
