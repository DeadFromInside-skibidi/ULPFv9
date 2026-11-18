"""
ULPF Plugin Interface
======================
The single entry point for any host system embedding ULPF.

Usage:
    from ulpf.plugin import ULPFPlugin

    plugin = ULPFPlugin()
    plugin.initialize({"storage_backend": "duckdb"})
    plugin.start()

    result = plugin.process_batch([
        {"raw": "<134>Sep 15 12:00:00 fw-01 sshd[1234]: Connection accepted"},
        {"raw": "CEF:0|Vendor|FW|1.0|100|Test|5|src=10.0.0.1 dst=10.0.0.2"},
    ], batch_id="batch-001")

    print(result)  # summary dict, NOT all events
    plugin.shutdown()
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from ulpf.plugin.config import ULPFConfig
from ulpf.plugin.lifecycle import enforce_offline, validate_environment

logger = logging.getLogger("ulpf.plugin")


class ULPFPlugin:
    """
    Universal Log Pre-processing Framework — Plugin Interface.

    The ULPF Engine does not care whether it is running inside your server,
    in Docker, from the CLI, or in a demo. This class is the single entry
    point for any host system.
    """

    name = "ulpf"
    version = "9.0.0"

    def __init__(self):
        self._config: ULPFConfig = ULPFConfig()
        self._pipeline = None
        self._storage = None
        self._anomaly_detector = None
        self._correlator = None
        self._forensic_builder = None
        self._log_dna = None
        self._running: bool = False
        self._start_time: float = 0.0
        self._initialized: bool = False

    def initialize(self, config: dict | None = None, storage=None) -> None:
        """
        Initialize the plugin with configuration.

        Args:
            config: Dict of configuration overrides. See ULPFConfig for keys.
            storage: an already-open store to share (the runtime's); it is
                     not closed on shutdown.
        """
        if config:
            self._config = ULPFConfig.from_dict(config)
        self._config.resolve_paths()

        # Validate environment
        warnings = validate_environment(self._config)
        for w in warnings:
            logger.warning(f"Environment: {w}")

        # Offline enforcement
        enforce_offline(self._config)

        # Configure enrichment with custom config dir
        from ulpf.engine.enricher import configure_enrichment
        configure_enrichment(self._config.config_dir)

        # Initialize storage first: if the store cannot be opened there is no
        # point spinning up the pipeline's learning thread.
        self._owns_storage = storage is None
        if storage is not None:
            self._storage = storage
        else:
            from ulpf.storage import create_storage
            self._storage = create_storage(
                backend=self._config.storage_backend,
                path=self._config.storage_path,
            )

        from ulpf.engine.pipeline import Pipeline
        self._pipeline = Pipeline(
            enable_auto_parser=self._config.enable_auto_parser,
            learned_parsers_dir=self._config.learned_parsers_dir,
        )

        # Initialize intelligence components
        if self._config.enable_anomaly_detection:
            from ulpf.intelligence.anomaly import AnomalyDetector
            self._anomaly_detector = AnomalyDetector()

        if self._config.enable_correlation:
            from ulpf.intelligence.correlation import EventCorrelator
            self._correlator = EventCorrelator()

        if self._config.enable_forensics:
            from ulpf.intelligence.forensic import ForensicBuilder
            self._forensic_builder = ForensicBuilder(
                output_dir=self._config.evidence_dir
            )

        if self._config.enable_log_dna:
            from ulpf.intelligence.log_dna import LogDNA
            self._log_dna = LogDNA()

        self._initialized = True
        logger.info(
            f"ULPF Plugin initialized: backend={self._config.storage_backend}, "
            f"offline={self._config.offline}"
        )

    def start(self) -> None:
        """Start the plugin processing engine."""
        if not self._initialized:
            raise RuntimeError("Plugin not initialized. Call initialize() first.")

        self._running = True
        self._start_time = time.time()
        logger.info("ULPF Plugin started.")

    def process_event(self, raw_event: dict) -> dict:
        """
        Process a single event.

        Args:
            raw_event: {"raw": "<log line>", "source": {"type": "syslog", "ip": "..."}}

        Returns:
            Normalized event dict with all enrichments.
        """
        if not self._running:
            return {"success": False, "error": "Plugin not running"}

        raw_line = raw_event.get("raw", "")
        if not raw_line:
            return {"success": False, "error": "No raw log data"}

        result = self._pipeline.process_line(raw_line, event_id=raw_event.get("event_id"),
                                             source_ip=(raw_event.get("source") or {}).get("ip", ""))

        if result.get("success") and result.get("event"):
            event = result["event"]
            for tag in raw_event.get("tags") or []:
                if tag not in event["tags"]:
                    event["tags"].append(tag)

            anomalies = []
            if self._anomaly_detector:
                anomalies = self._anomaly_detector.analyse_event(event)
                if anomalies:
                    event["extensions"]["anomalies"] = anomalies
            if self._correlator:
                self._correlator.add_and_correlate(event)

            if self._storage:
                self._storage.insert_batch([event])
                if anomalies:
                    self._storage.store_anomalies_bulk(anomalies)

        return result

    def process_batch(
        self,
        events: list[dict],
        batch_id: str = "",
    ) -> dict:
        """
        Process a batch of events. Returns a SUMMARY, not all events.

        Args:
            events: List of {"raw": "<log line>", ...} dicts
            batch_id: Optional batch identifier

        Returns:
            Summary dict: {batch_id, received, processed, failed,
                           processing_time_ms, events_per_second, alerts, ...}
        """
        if not self._running:
            return {"success": False, "error": "Plugin not running"}

        batch_id = batch_id or str(uuid.uuid4())[:12]
        start = time.perf_counter()

        processed_events = []
        successes = 0
        failures = 0
        skipped = 0
        alerts = []
        groups: dict[str, Any] = {}

        for raw_event in events:
            if isinstance(raw_event, dict):
                raw_line = raw_event.get("raw", "")
                event_id = raw_event.get("event_id")
            else:
                raw_line, event_id = str(raw_event), None
            if not raw_line:
                failures += 1
                continue

            result = self._pipeline.process_line(raw_line, event_id=event_id)

            if result.get("success") and result.get("event"):
                event = result["event"]
                processed_events.append(event)
                successes += 1

                if self._anomaly_detector:
                    anomalies = self._anomaly_detector.analyse_event(event)
                    if anomalies:
                        event["extensions"]["anomalies"] = anomalies
                        alerts.extend(anomalies)
                if self._correlator:
                    group = self._correlator.add_and_correlate(event)
                    if group is not None:
                        groups[group.correlation_id] = group
            elif result.get("skipped"):
                skipped += 1
            else:
                failures += 1

        if self._anomaly_detector and processed_events:
            alerts.extend(self._anomaly_detector.analyse_batch_aggregate(processed_events))

        correlation_groups = [g.to_dict() for g in groups.values()]

        stored = 0
        if self._storage and processed_events:
            stored = self._storage.insert_batch(processed_events)
            if alerts:
                self._storage.store_anomalies_bulk(alerts)

        elapsed_ms = (time.perf_counter() - start) * 1000
        eps = successes / max(elapsed_ms / 1000, 0.001)

        return {
            "batch_id": batch_id,
            "received": len(events),
            "processed": successes,
            "stored": stored,
            "skipped_headers": skipped,
            "failed": failures,
            "processing_time_ms": round(elapsed_ms, 2),
            "events_per_second": round(eps, 1),
            "alerts": alerts[:50],  # Cap at 50
            "alert_count": len(alerts),
            "correlation_groups": len(correlation_groups),
            "correlations": correlation_groups[:10],  # Cap at 10
            "format_distribution": self._pipeline.get_metrics().get("format_distribution", {}),
        }

    def query(self, query: dict) -> dict:
        """
        Query stored events.

        Args:
            query: {
                "type": "events" | "stats" | "search" | "anomalies" | "correlations",
                "filters": {...},
                "limit": 100,
                "offset": 0,
            }
        """
        if not self._storage:
            return {"error": "No storage backend configured"}

        query_type = query.get("type", "events")
        limit = query.get("limit", 100)
        offset = query.get("offset", 0)
        filters = query.get("filters", {})

        if query_type == "stats":
            return self._storage.stats()

        elif query_type == "events":
            events = self._storage.query(filters=filters, limit=limit, offset=offset)
            return {"events": events, "count": len(events)}

        elif query_type == "search":
            search_term = query.get("q", "")
            results = self._storage.search(query=search_term, limit=limit)
            return {"results": results, "count": len(results)}

        elif query_type == "anomalies":
            if self._anomaly_detector:
                return {
                    "anomalies": self._anomaly_detector.get_anomalies(limit),
                    "baseline": self._anomaly_detector.get_baseline_report(),
                }
            return {"anomalies": [], "baseline": {}}

        elif query_type == "correlations":
            if self._correlator:
                return {"groups": self._correlator.get_results()}
            return {"groups": []}

        return {"error": f"Unknown query type: {query_type}"}

    def health(self) -> dict:
        """Get plugin health status."""
        from ulpf.plugin.health import health_check
        return health_check(self)

    def metrics(self) -> dict:
        """Get pipeline processing metrics."""
        if self._pipeline:
            return self._pipeline.get_metrics()
        return {}

    def shutdown(self) -> None:
        """Gracefully shut down the plugin."""
        logger.info("ULPF Plugin shutting down...")
        self._running = False

        if self._pipeline:
            self._pipeline.close()

        if self._storage and getattr(self, "_owns_storage", True):
            try:
                self._storage.close()
            except Exception as e:
                logger.error(f"Storage close error: {e}")

        logger.info("ULPF Plugin shut down successfully.")

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def pipeline(self):
        """Direct access to the processing pipeline (for adapters)."""
        return self._pipeline

    @property
    def storage(self):
        """Direct access to the storage backend (for adapters)."""
        return self._storage

    @property
    def anomaly_detector(self):
        """Direct access to the anomaly detector (for adapters)."""
        return self._anomaly_detector

    @property
    def correlator(self):
        """Direct access to the event correlator (for adapters)."""
        return self._correlator

    @property
    def forensic_builder(self):
        """Direct access to the forensic builder (for adapters)."""
        return self._forensic_builder

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def config(self) -> ULPFConfig:
        return self._config
