"""
Processing Pipeline
====================
Orchestrates: Ingest → Detect → Parse → Normalize → Enrich → Store.

The Pipeline is the core of the ULPF engine. It has NO dependency on
FastAPI, GUI, CLI, or any specific storage backend.

Invariants:
  * Every non-blank, non-directive line yields exactly one event — known
    formats via their parser, unknown formats via a learned (APG) parser,
    and anything else via the raw fallback. Nothing is dropped.
  * The SHA-256 of the raw line is computed once at entry and is the value
    stored in ``evidence.raw_hash`` / ``metadata.raw_hash_sha256``.
  * Stream directives (W3C ``#Fields:``) and CSV header rows update parser
    state and are reported as skipped headers, never stored as events.
"""
from __future__ import annotations

import hashlib
import logging
import time
from collections import deque
from typing import Iterator

from ulpf.parsers.base import HEADER_LINE

logger = logging.getLogger(__name__)

# Profiling sampling mask — timing is collected every 4096 events
_PROFILE_MASK = 0x0FFF

_sha256 = hashlib.sha256

# Auto-parser output keys that are handled explicitly (not copied to parsed_fields)
_AUTO_RESERVED = frozenset(("category", "action", "severity", "message", "timestamp",
                            "raw_event", "raw_format", "evidence", "metadata", "_meta"))


class PipelineMetrics:
    """Tracks processing stats."""
    def __init__(self):
        self.total = 0
        self.success = 0
        self.failed = 0
        self.skipped = 0
        self._avg_ms_ewma = 0.0
        self.format_dist: dict[str, int] = {}
        self.category_dist: dict[str, int] = {}
        self.severity_dist: dict[str, int] = {}
        self.parser_usage: dict[str, int] = {}
        self.errors: deque[dict] = deque(maxlen=100)

    def to_dict(self) -> dict:
        return {
            "total_events": self.total,
            "successful": self.success,
            "failed": self.failed,
            "skipped_headers": self.skipped,
            "success_rate": round(self.success / max(self.total, 1) * 100, 2),
            "avg_processing_time_ms": round(self._avg_ms_ewma, 3),
            "format_distribution": dict(self.format_dist),
            "category_distribution": dict(self.category_dist),
            "severity_distribution": dict(self.severity_dist),
            "parser_usage": dict(self.parser_usage),
            "recent_errors": list(self.errors)[-10:],
        }


class Pipeline:
    """The ULPF processing pipeline."""

    def __init__(self, enable_auto_parser: bool = True, learned_parsers_dir: str | None = None,
                 plugin_policy: dict | None = None, apg_engine: str = "classic"):
        from ulpf.parsers.registry import ParserRegistry
        from ulpf.engine.enricher import enrich_event
        from ulpf.engine.detector import detect_format
        from ulpf.engine.normalizer import build_raw_fallback_event

        self.registry = ParserRegistry(plugin_policy)
        self._plugins = self.registry.plugins
        self._detect = detect_format
        self._enrich = enrich_event
        self._raw_fallback = build_raw_fallback_event
        self._w3c = self.registry.get_parser_for_format("w3c")
        self.metrics = PipelineMetrics()
        self._counter: int = 0

        self.auto_engine = None
        if enable_auto_parser:
            if apg_engine == "streaming":
                from ulpf.intelligence.auto_parser.streaming_engine import StreamingAPGEngine as Engine
            else:
                from ulpf.intelligence.auto_parser.engine import AutoParserEngine as Engine
            self.auto_engine = Engine(learned_dir=learned_parsers_dir)
            self.auto_engine.start()

    def close(self) -> None:
        """Stop background learning threads."""
        if self.auto_engine is not None:
            self.auto_engine.stop()

    # ------------------------------------------------------------------
    # Hot path: single event
    # ------------------------------------------------------------------

    def process_line(self, raw_line: str, event_id: str | None = None,
                     timestamp_now: str | None = None, source_ip: str = "",
                     raw_hash: str | None = None) -> dict:
        """Process a single raw log line. Returns a result dict.

        ``raw_hash`` is supplied by the runtime, which hashes the exact bytes
        received when it journals them; otherwise the stripped line is hashed.
        """
        line = raw_line.strip()
        if not line:
            return {"success": False, "skipped": True, "error": "Empty line"}
        if line[0] == "#":
            # W3C/IIS directives (#Fields, #Software …) define the stream schema
            if self._w3c is not None:
                self._w3c.consume_header(line)
            self.metrics.skipped += 1
            return {"success": False, "skipped": True, "header": True, "comment": True,
                    "error": "Directive or comment line"}

        self._counter += 1
        do_profile = (self._counter & _PROFILE_MASK) == 0
        t0 = time.perf_counter() if do_profile else 0.0

        try:
            if raw_hash is None:
                raw_hash = _sha256(line.encode("utf-8", errors="replace")).hexdigest()
            detection = self._detect(line)
            event = None
            # Lookup order: plugins -> built-in parser for the detected format ->
            # learned (APG) parsers -> raw fallback
            for plugin in self._plugins:
                if plugin.can_parse(line):
                    event = plugin.parse(line, raw_hash=raw_hash, event_id=event_id, timestamp_now=timestamp_now)
                    if event is not None:
                        detection = {**detection, "format_name": plugin.parser_id, "plugin": True}
                        break
            parser = None if event is not None else self.registry.get_parser_for_format(detection["format_name"])
            if parser is not None:
                event = parser.parse(line, raw_hash=raw_hash, event_id=event_id, timestamp_now=timestamp_now)
                if event is HEADER_LINE:
                    self.metrics.skipped += 1
                    return {"success": False, "skipped": True, "header": True,
                            "error": "Header row", "detection": detection}

            if event is None and self.auto_engine is not None:
                event = self._try_auto_parse(line, raw_hash, event_id, timestamp_now, source_ip)

            if event is None:
                event = self._raw_fallback(line, raw_hash=raw_hash, event_id=event_id,
                                           timestamp_now=timestamp_now)

            event = self._enrich(event)
            meta = event["metadata"]
            meta["detection_confidence"] = detection["confidence"]
            if do_profile:
                self._record_profile(t0, meta)
            self._update_metrics(event)

            result = {"success": True, "event": event, "detection": detection}
            fmt = event["raw_format"]
            if fmt == "raw_fallback":
                result["raw_fallback"] = True
            elif fmt == "auto_detected":
                result["auto_parsed"] = True
            return result

        except Exception as e:
            logger.debug("Pipeline error on line %.120r", line, exc_info=True)
            self.metrics.total += 1
            self.metrics.failed += 1
            self.metrics.errors.append({"error": f"{type(e).__name__}: {e}", "time": time.time()})
            return {"success": False, "error": str(e)}

    # ------------------------------------------------------------------
    # Batch / stream APIs
    # ------------------------------------------------------------------

    def process_batch(self, lines: list[str]) -> list[dict]:
        """Process multiple log lines in a tight loop."""
        process = self.process_line
        return [process(line) for line in lines if line]

    def iter_file(self, filepath: str, batch_size: int = 5000) -> Iterator[list[dict]]:
        """Stream a file through the pipeline in bounded-memory batches of results."""
        self.registry.reset_stream_state()
        process = self.process_line
        batch: list[dict] = []
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip():
                    batch.append(process(line))
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []
        if batch:
            yield batch

    def process_file(self, filepath: str) -> list[dict]:
        """Process a log file line-by-line through the full pipeline."""
        results: list[dict] = []
        for batch in self.iter_file(filepath):
            results.extend(batch)
        return results

    def process_text(self, text: str) -> list[dict]:
        """Process multi-line text (a paste or upload) as one stream."""
        self.registry.reset_stream_state()
        process = self.process_line
        return [process(line) for line in text.splitlines() if line.strip()]

    def get_metrics(self) -> dict:
        return self.metrics.to_dict()

    def reset_metrics(self):
        self.metrics = PipelineMetrics()
        self._counter = 0

    # ------------------------------------------------------------------
    # Auto-parser (non-blocking)
    # ------------------------------------------------------------------

    def _try_auto_parse(self, raw_line: str, raw_hash: str, event_id: str | None,
                        timestamp_now: str | None, source_ip: str = "") -> dict | None:
        """Parse with a learned (APG) parser and wrap the fields in a unified event.

        Unknown lines are also sampled into the learning plane here.
        """
        try:
            parsed = self.auto_engine.parse(raw_line, source_ip=source_ip)
        except Exception:
            logger.debug("Auto-parser failure", exc_info=True)
            return None
        if not parsed:
            return None

        from ulpf.engine.schema import new_unified_event
        from ulpf.engine.normalizer import (apply_field_mappings, normalize_action,
                                            normalize_severity, normalize_timestamp)

        for side in ("source", "destination"):
            v = parsed.get(f"{side}.ip")
            if isinstance(v, str) and v.count(":") == 1 and "." in v:
                ip, _, port = v.partition(":")
                if port.isdigit():
                    parsed[f"{side}.ip"] = ip
                    parsed.setdefault(f"{side}.port", port)

        event = new_unified_event(event_id=event_id, timestamp=timestamp_now)
        event["raw_event"] = raw_line
        event["raw_format"] = "auto_detected"
        event["category"] = "other"
        event["action"] = normalize_action(parsed.get("action"))
        sev_norm, sev_label = normalize_severity(parsed.get("severity"))
        event["severity"] = sev_norm
        event["severity_label"] = sev_label
        event["message"] = parsed.get("message") or raw_line[:512]
        event["timestamp"], event["timestamp_original"] = normalize_timestamp(parsed.get("timestamp"))

        apply_field_mappings(parsed, event)
        event["parsed_fields"] = {k: v for k, v in parsed.items() if k not in _AUTO_RESERVED}

        meta_in = parsed.get("_meta") or {}
        meta = event["metadata"]
        meta["parser_id"] = meta_in.get("parser_id", "auto_detected")
        meta["parser_name"] = "Auto-Parser (APG)"
        meta["parser_version"] = str(meta_in.get("parser_version", ""))
        meta["parser_confidence"] = meta_in.get("parser_confidence")
        meta["source_fingerprint"] = meta_in.get("source_fingerprint")
        meta["template_id"] = meta_in.get("parser_id")
        family = meta_in.get("source_family", "")
        if family:
            from ulpf.engine.schema import canonical_category
            event["category"] = canonical_category(family.split(".")[-1])
        event["evidence"]["raw_hash"] = raw_hash
        meta["raw_hash_sha256"] = raw_hash
        return event

    # ------------------------------------------------------------------
    # Profiling & metrics
    # ------------------------------------------------------------------

    def _record_profile(self, t0: float, meta: dict) -> None:
        elapsed = (time.perf_counter() - t0) * 1000
        meta["processing_time_ms"] = round(elapsed, 3)
        m = self.metrics
        m._avg_ms_ewma = elapsed if m._avg_ms_ewma == 0.0 else m._avg_ms_ewma * 0.9 + elapsed * 0.1

    def _update_metrics(self, event: dict) -> None:
        m = self.metrics
        m.total += 1
        m.success += 1
        fmt = event["raw_format"] or "unknown"
        m.format_dist[fmt] = m.format_dist.get(fmt, 0) + 1
        cat = event["category"]
        m.category_dist[cat] = m.category_dist.get(cat, 0) + 1
        sev = str(event["severity"])
        m.severity_dist[sev] = m.severity_dist.get(sev, 0) + 1
        pid = event["metadata"]["parser_id"] or "unknown"
        m.parser_usage[pid] = m.parser_usage.get(pid, 0) + 1


def process_line_standalone(raw_line: str) -> dict:
    """
    Module-level function for multiprocessing compatibility.
    Each worker process lazily initializes its own Pipeline instance.
    """
    if not hasattr(process_line_standalone, "_pipeline"):
        process_line_standalone._pipeline = Pipeline()
    return process_line_standalone._pipeline.process_line(raw_line)
