"""
APG 2.0 Streaming Engine
===========================
The industrial-grade, streaming, self-learning parser generation engine.

Replaces the batch-oriented ``AutoParserEngine`` learning loop with a
continuous streaming pipeline:

    StreamingTokenizer → VectorisedClusterer → NativeTemplateMiner
    → ParserCompiler → NativeMatcherSet (hot-swapped)

Design principles:
  1. **No process restart**: learning runs continuously in a background
     thread, ingesting samples from the streaming clusterer.
  2. **4-stage lifecycle**: Sampling → Canary (10k events, >99.5% accuracy,
     <20 µs) → Active → Retired.
  3. **Native dispatch**: the hot path uses Aho-Corasick multi-pattern
     matching from ``native_synthesis.HotSwapRegistry``.
  4. **Streaming drift detection**: per-cluster bitmask distribution
     entropy is checked continuously, triggering re-learning when a
     format drifts beyond threshold.
  5. **Defence mode**: cryptographic signing of parser specs, requiring
     operator approval via ``ulpf parsers approve <id>``.

Thread model:
  - Data-plane threads call ``parse()`` (lock-free via snapshot)
  - One background learning thread processes the streaming clusterer
  - Hot-swap is atomic and lock-free for readers
"""
from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Any, Callable

from ulpf.intelligence.auto_parser.config import AutoParserConfig
from ulpf.intelligence.auto_parser.parser_spec import ParserSpec
from ulpf.intelligence.auto_parser.compiler import ParserCompiler
from ulpf.intelligence.auto_parser.registry import AutoParserRegistry
from ulpf.intelligence.auto_parser.fingerprint import compute_fingerprint, FormatFingerprint
from ulpf.intelligence.auto_parser.quarantine import QuarantineManager
from ulpf.intelligence.auto_parser.sampler import Sampler
from ulpf.intelligence.auto_parser.miners.native import NativeTemplateMiner
from ulpf.intelligence.auto_parser.validator import ParserValidator
from ulpf.intelligence.auto_parser.admission import AdmissionController
from ulpf.intelligence.auto_parser.provenance import ProvenanceManager
from ulpf.intelligence.auto_parser.streaming_tokenizer import StreamingTokenizer, StreamFrame
from ulpf.intelligence.auto_parser.vectorised_clusterer import VectorisedClusterer, StreamCluster
from ulpf.intelligence.auto_parser.native_synthesis import HotSwapRegistry, NativeMatcherSet

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lifecycle Constants
# ---------------------------------------------------------------------------
LIFECYCLE_SAMPLING = "sampling"
LIFECYCLE_CANARY = "canary"
LIFECYCLE_ACTIVE = "active"
LIFECYCLE_RETIRED = "retired"

_CANARY_EVENT_THRESHOLD = 10_000     # events before canary can promote
_CANARY_ACCURACY_THRESHOLD = 0.995   # >99.5% field extraction accuracy
_CANARY_LATENCY_THRESHOLD_US = 20.0  # <20 µs execution time
_DRIFT_ENTROPY_THRESHOLD = 0.5       # entropy score triggering re-learning
_MAX_LEARN_ATTEMPTS = 3
_MIN_AUTO_CLUSTER = 10
_STREAMING_BATCH_SIZE = 100          # check clusterer every N events


class APG2LifecycleManager:
    """
    4-stage lifecycle manager for APG 2.0.

    Sampling → Canary → Active → Retired

    Canary promotion requires:
      - At least 10,000 events processed
      - >99.5% field extraction accuracy
      - <20 µs average execution time
    """

    VALID_STATES = [LIFECYCLE_SAMPLING, LIFECYCLE_CANARY, LIFECYCLE_ACTIVE, LIFECYCLE_RETIRED,
                    "candidate", "validating", "pending_approval", "drifting"]

    def __init__(self) -> None:
        self._canary_stats: dict[str, dict[str, Any]] = {}
        self._timing_samples: dict[str, list[float]] = {}

    def transition(self, spec: ParserSpec, new_state: str) -> None:
        """Transition parser to a new state."""
        if new_state not in self.VALID_STATES:
            raise ValueError(f"Invalid parser state: {new_state}")

        old_state = spec.state
        spec.state = new_state

        if new_state == LIFECYCLE_CANARY and old_state != LIFECYCLE_CANARY:
            self._canary_stats[spec.parser_id] = {
                "start_time": time.time(),
                "events_processed": 0,
                "errors": 0,
                "field_extractions": 0,
                "field_failures": 0,
            }
            self._timing_samples[spec.parser_id] = []

    def record_canary_event(self, parser_id: str, success: bool,
                            parse_time_us: float = 0.0,
                            fields_extracted: int = 0,
                            fields_expected: int = 0) -> None:
        """Record a parsing event for a canary with detailed metrics."""
        stats = self._canary_stats.get(parser_id)
        if stats is None:
            return

        stats["events_processed"] += 1
        if not success:
            stats["errors"] += 1

        if fields_expected > 0:
            stats["field_extractions"] += fields_extracted
            stats["field_failures"] += (fields_expected - fields_extracted)

        # Track timing samples (bounded)
        timings = self._timing_samples.get(parser_id, [])
        if parse_time_us > 0 and len(timings) < 10_000:
            timings.append(parse_time_us)
            self._timing_samples[parser_id] = timings

    def get_canary_stats(self, parser_id: str) -> dict[str, Any] | None:
        """Get tracking stats for a canary with APG 2.0 metrics."""
        if parser_id not in self._canary_stats:
            return None

        stats = self._canary_stats[parser_id].copy()
        stats["duration"] = time.time() - stats["start_time"]

        # Field extraction accuracy
        total_fields = stats["field_extractions"] + stats["field_failures"]
        stats["field_accuracy"] = (
            stats["field_extractions"] / total_fields if total_fields > 0 else 1.0
        )

        # Average parse time
        timings = self._timing_samples.get(parser_id, [])
        stats["avg_parse_time_us"] = (
            sum(timings) / len(timings) if timings else 0.0
        )
        stats["p99_parse_time_us"] = (
            sorted(timings)[int(len(timings) * 0.99)] if len(timings) >= 100 else stats["avg_parse_time_us"]
        )

        return stats

    def can_promote_to_active(self, parser_id: str) -> tuple[bool, str]:
        """
        Check if a canary meets APG 2.0 promotion criteria.

        Requirements:
          - ≥ 10,000 events processed
          - >99.5% field extraction accuracy
          - <20 µs average execution time
        """
        stats = self.get_canary_stats(parser_id)
        if stats is None:
            return False, "No canary stats"

        if stats["events_processed"] < _CANARY_EVENT_THRESHOLD:
            return False, (f"Insufficient events: {stats['events_processed']}"
                          f" < {_CANARY_EVENT_THRESHOLD}")

        if stats["field_accuracy"] < _CANARY_ACCURACY_THRESHOLD:
            return False, (f"Accuracy {stats['field_accuracy']:.4f}"
                          f" < {_CANARY_ACCURACY_THRESHOLD}")

        if stats["avg_parse_time_us"] > _CANARY_LATENCY_THRESHOLD_US:
            return False, (f"Latency {stats['avg_parse_time_us']:.1f}µs"
                          f" > {_CANARY_LATENCY_THRESHOLD_US}µs")

        if stats["errors"] > stats["events_processed"] * 0.005:
            return False, f"Error rate too high: {stats['errors']} errors"

        return True, "Ready for production"

    def cleanup_canary(self, parser_id: str) -> None:
        self._canary_stats.pop(parser_id, None)
        self._timing_samples.pop(parser_id, None)


# ---------------------------------------------------------------------------
# APG 2.0 Streaming Engine
# ---------------------------------------------------------------------------

class StreamingAPGEngine:
    """
    APG 2.0: Industrial-grade streaming parser generation engine.

    Hot path (data plane):
      - ``parse()`` dispatches via Aho-Corasick + hot-swapped matcher set
      - Unknown events are tokenised and fed to the streaming clusterer
      - Lock-free for readers

    Learning plane (background thread):
      - Continuously monitors the vectorised clusterer for ready clusters
      - Mines templates, validates, promotes through 4-stage lifecycle
      - Hot-swaps new parser tables without blocking the data plane

    Drift detection (integrated):
      - Per-cluster bitmask entropy is monitored continuously
      - Drifting formats trigger re-learning automatically
    """

    def __init__(self, config_path: str | None = None,
                 learned_dir: str | None = None):
        self.config = AutoParserConfig(config_path)
        self.profile = self.config.active_profile

        # Core registries
        self.registry = AutoParserRegistry(learned_dir)
        self.provenance = ProvenanceManager()
        self.quarantine = QuarantineManager(self.profile.poisoning)

        # APG 2.0 components
        self.streaming_tokenizer = StreamingTokenizer()
        self.vectorised_clusterer = VectorisedClusterer(
            similarity_threshold=0.80,
            max_clusters=self.profile.max_candidate_templates,
        )
        self.hot_swap_registry = HotSwapRegistry()
        self.lifecycle = APG2LifecycleManager()

        # Legacy components (used for mining and validation)
        self.native_miner = NativeTemplateMiner()
        self.validator = ParserValidator(
            target_max_parse_time_ms=self.profile.promotion.max_parse_time_ms,
            min_accuracy=self.profile.promotion.min_accuracy,
        )
        self.admission = AdmissionController(self.profile)

        # Streaming state
        self._running = False
        self._learning_thread: threading.Thread | None = None
        self._learn_lock = threading.Lock()
        self._pending_clusters: set[str] = set()
        self._attempts: dict[str, int] = {}
        self._events_since_check = 0

        # Defence mode
        self.approval_required = False
        self.max_parsers_per_source: int | None = None
        self._fid_source: dict[str, str] = {}
        self._per_source: dict[str, int] = {}
        self._synced_version = -1

        # Bootstrap: register existing parsers in the hot-swap registry
        self._bootstrap_hot_swap()

    def _bootstrap_hot_swap(self) -> None:
        """Load existing parsers into the hot-swap registry."""
        self._sync_hot_swap()
        for spec in self.registry.list_parsers():
            src = spec.metadata.get("learned_source")
            if src is not None and spec.state != "retired":
                self._per_source[src] = self._per_source.get(src, 0) + 1

    # =========================================================================
    # HOT PATH (DATA PLANE) — Lock-free dispatch
    # =========================================================================

    def parse(self, raw_line: str, source_ip: str = "") -> dict[str, Any] | None:
        """
        Parse a line using the hot-swapped native matcher set.

        1. Aho-Corasick multi-pattern dispatch for candidate filtering
        2. Full regex verification on best candidate
        3. Unknown lines → streaming tokenizer → vectorised clusterer
        """
        # Step 1: Try hot-swap dispatch (lock-free)
        if self.registry.version != self._synced_version:
            self._sync_hot_swap()
        t0 = time.perf_counter()
        parser, parsed = self.hot_swap_registry.current.dispatch_parse(raw_line)
        if parser is not None:
            parse_time_us = (time.perf_counter() - t0) * 1_000_000    # dispatch + extraction

            if parsed is not None:
                self._attach(parsed, parser)
                # Canary telemetry
                if parser.spec.state == LIFECYCLE_CANARY:
                    field_count = len([v for v in parsed.values()
                                      if v is not None and not isinstance(v, dict)])
                    expected = len(parser.spec.fields) if parser.spec.fields else field_count
                    self.lifecycle.record_canary_event(
                        parser.parser_id, True, parse_time_us,
                        fields_extracted=field_count,
                        fields_expected=expected,
                    )
                return parsed

            if parser.spec.state == LIFECYCLE_CANARY:
                self.lifecycle.record_canary_event(parser.parser_id, False)

        # Step 2: Fallback to legacy registry
        if self.registry.has_parsers():
            legacy_parser, parsed = self.registry.get_adaptive_parse(raw_line, source=source_ip)
            if legacy_parser is not None:
                if parsed is not None:
                    self._attach(parsed, legacy_parser)
                    return parsed

        # Step 3: Unknown event → streaming pipeline
        if self._running and self.profile.auto_discovery:
            if (self.quarantine.validate_message_length(raw_line)
                    and self.quarantine.check_and_record_event(source_ip)):
                self._ingest_unknown(raw_line, source_ip)

        return None

    def _sync_hot_swap(self) -> None:
        """Mirror the registry's live anchored parsers: reloads from disk, operator decisions
        and signature checks reach the hot path, and a rejected parser stops parsing at once.
        Generic (anchor-less) parsers stay exact-fingerprint only, as in the registry."""
        version = self.registry.version
        self.hot_swap_registry.replace_all(list(self.registry.adaptive_parsers()))
        self._synced_version = version

    def _attach(self, parsed: dict, parser) -> None:
        """Attach provenance metadata to a parsed event."""
        self.provenance.attach_event_provenance(
            parsed, parser, "", parser.spec.match.fingerprint or "")
        parsed.setdefault("_meta", {})["source_family"] = parser.spec.source_family

    def _ingest_unknown(self, raw_line: str, source_ip: str) -> None:
        """Feed an unknown event into the streaming pipeline."""
        frame = self.streaming_tokenizer.tokenise_event(raw_line)
        if frame is None:
            return

        # Track source mapping
        if len(self._fid_source) > 10_000:
            self._fid_source.clear()
        self._fid_source[frame.fingerprint_hash] = source_ip or ""

        # Add to vectorised clusterer
        cluster = self.vectorised_clusterer.add_frame(frame)

        # Periodically check for ready clusters
        self._events_since_check += 1
        if self._events_since_check >= _STREAMING_BATCH_SIZE:
            self._events_since_check = 0
            self._check_ready_clusters()

    def _check_ready_clusters(self) -> None:
        """Check for clusters ready for learning."""
        ready = self.vectorised_clusterer.get_ready_clusters(
            min_samples=self.profile.min_samples_for_promotion
        )
        for cluster in ready:
            if cluster.cluster_id in self._pending_clusters:
                continue
            if self._attempts.get(cluster.cluster_id, 0) >= _MAX_LEARN_ATTEMPTS:
                continue
            self._pending_clusters.add(cluster.cluster_id)

    # =========================================================================
    # BACKGROUND LEARNING PLANE — Continuous streaming
    # =========================================================================

    def start(self) -> None:
        """Start the streaming learning engine (no process restart needed)."""
        if self._running:
            return
        self._running = True
        self._learning_thread = threading.Thread(
            target=self._learning_loop, name="ulpf-apg2-learner", daemon=True)
        self._learning_thread.start()
        logger.info(f"APG 2.0 Engine started (Profile: {self.profile.name})")

    def stop(self) -> None:
        self._running = False
        if self._learning_thread:
            self._learning_thread.join(timeout=2.0)
            self._learning_thread = None

    def _learning_loop(self) -> None:
        """Continuous learning loop — processes clusters as they become ready."""
        last_drift_check = time.monotonic()
        last_canary_check = time.monotonic()

        while self._running:
            now = time.monotonic()

            # Process pending clusters
            pending = list(self._pending_clusters)
            for cluster_id in pending:
                try:
                    self._process_cluster(cluster_id)
                except Exception as e:
                    logger.error(f"Error processing cluster {cluster_id[:8]}: {e}",
                                 exc_info=True)
                finally:
                    self._pending_clusters.discard(cluster_id)

            # Periodic drift detection
            if now - last_drift_check >= 5.0:
                last_drift_check = now
                try:
                    self._detect_drift()
                except Exception as e:
                    logger.error(f"Drift detection error: {e}", exc_info=True)

            # Periodic canary promotion checks
            if now - last_canary_check >= 2.0:
                last_canary_check = now
                try:
                    self._check_canaries()
                except Exception as e:
                    logger.error(f"Canary check error: {e}", exc_info=True)

            # Periodic registry reload
            try:
                if self.registry.reload_if_changed():
                    self._bootstrap_hot_swap()
            except Exception:
                pass

            # Sleep briefly if nothing to do
            if not self._pending_clusters:
                time.sleep(0.5)

    def _process_cluster(self, cluster_id: str) -> None:
        """Process a ready cluster: mine templates, validate, promote."""
        cluster = self.vectorised_clusterer.get_cluster(cluster_id)
        if cluster is None:
            return

        samples = list(cluster.samples)
        if len(samples) < self.profile.min_samples_for_promotion:
            return

        self._attempts[cluster_id] = self._attempts.get(cluster_id, 0) + 1
        logger.info(f"APG 2.0: Learning cluster {cluster_id[:8]} "
                     f"from {len(samples)} samples")

        # Mine templates
        with self._learn_lock:
            specs = self.native_miner.mine(samples, cluster_id)
            clusters = dict(self.native_miner.last_clusters)

        if not specs:
            logger.debug(f"No templates mined for cluster {cluster_id[:8]}")
            return

        # Select best specs
        from ulpf.intelligence.auto_parser.engine import AutoParserEngine
        chosen, failures = AutoParserEngine._select_specs(
            specs, samples, clusters, self.validator, _MIN_AUTO_CLUSTER)

        for spec, result, _ in failures:
            logger.debug(f"Parser {spec.parser_id} rejected: "
                         f"{'; '.join(result.rejection_reasons)}")

        source = self._fid_source.pop(cluster_id, "")
        cap = self.max_parsers_per_source

        for spec, val_result, _ in chosen:
            if cap is not None and self._per_source.get(source, 0) >= cap:
                logger.warning(f"Source {source!r} at parser cap; "
                               f"not registering {spec.parser_id}")
                break

            can_promote, reason = self.admission.can_promote_to_canary(
                spec, val_result)
            if not can_promote:
                logger.debug(f"Parser {spec.parser_id} rejected: {reason}")
                continue

            # 4-stage lifecycle: start in Sampling → promote to Canary
            state = "pending_approval" if self.approval_required else LIFECYCLE_CANARY
            spec.metadata["learned_from"] = "autonomous_apg2"
            spec.metadata["learned_source"] = source
            spec.metadata["validation_accuracy"] = round(val_result.accuracy, 4)
            spec.metadata["apg_version"] = "2.0"
            spec.metadata["cluster_id"] = cluster_id[:16]

            self.lifecycle.transition(spec, state)
            self.provenance.sign_parser_spec(spec)

            try:
                compiled = ParserCompiler.compile(spec)
                self.registry.register(spec, compiled, save_to_disk=True)
                self.hot_swap_registry.register(spec, compiled)
                self._per_source[source] = self._per_source.get(source, 0) + 1
                self._attempts[cluster_id] = _MAX_LEARN_ATTEMPTS
                logger.info(f"APG 2.0: Learned {spec.parser_id} ({state})")
            except Exception as e:
                logger.error(f"Failed to register {spec.parser_id}: {e}")

        # Clean up cluster
        self.vectorised_clusterer.remove_cluster(cluster_id)

    def _check_canaries(self) -> None:
        """Check canary parsers for promotion to active."""
        for spec in self.registry.list_parsers():
            if spec.state != LIFECYCLE_CANARY:
                continue

            can_promote, reason = self.lifecycle.can_promote_to_active(
                spec.parser_id)

            if can_promote:
                self.lifecycle.transition(spec, LIFECYCLE_ACTIVE)
                self.lifecycle.cleanup_canary(spec.parser_id)
                self.provenance.sign_parser_spec(spec)
                self.registry.register(spec, save_to_disk=True)
                self.hot_swap_registry.register(spec)
                logger.info(f"APG 2.0: Promoted {spec.parser_id} → ACTIVE")

            elif self.lifecycle.get_canary_stats(spec.parser_id):
                stats = self.lifecycle.get_canary_stats(spec.parser_id)
                if stats and stats["duration"] > self.profile.canary_duration_sec * 3:
                    self.lifecycle.transition(spec, LIFECYCLE_RETIRED)
                    self.lifecycle.cleanup_canary(spec.parser_id)
                    self.provenance.sign_parser_spec(spec)
                    self.registry.register(spec, save_to_disk=True)
                    self.hot_swap_registry.unregister(spec.parser_id)
                    logger.warning(f"APG 2.0: Retired canary {spec.parser_id}: {reason}")

    def _detect_drift(self) -> None:
        """
        Streaming drift detection using bitmask entropy.

        Drifting clusters indicate format changes; the affected parser
        is transitioned to 'drifting' and re-learning is triggered.
        """
        drifting = self.vectorised_clusterer.get_drifting_clusters(
            threshold=_DRIFT_ENTROPY_THRESHOLD)

        for cluster in drifting:
            if cluster.cluster_id in self._pending_clusters:
                continue

            logger.info(f"APG 2.0: Drift detected in cluster "
                         f"{cluster.cluster_id[:8]} "
                         f"(entropy={cluster.drift_score:.3f})")

            # Find any parser associated with this cluster
            for spec in self.registry.list_parsers():
                if (spec.metadata.get("cluster_id") == cluster.cluster_id[:16]
                        and spec.state == LIFECYCLE_ACTIVE):
                    self.lifecycle.transition(spec, "drifting")
                    self.provenance.sign_parser_spec(spec)
                    self.registry.register(spec, save_to_disk=True)
                    logger.info(f"APG 2.0: Parser {spec.parser_id} → DRIFTING")

            # Reset cluster for re-learning
            self._attempts.pop(cluster.cluster_id, None)
            self._pending_clusters.add(cluster.cluster_id)

    # =========================================================================
    # OPERATOR INTERFACE
    # =========================================================================

    def approve(self, parser_id: str, operator: str = "") -> ParserSpec:
        """Operator approval of a pending parser (defence mode)."""
        self.registry.reload_if_changed()
        spec = self.registry.get_spec(parser_id)
        if spec is None:
            raise KeyError(f"No learned parser {parser_id!r}")
        if spec.state not in ("pending_approval", LIFECYCLE_CANARY, "candidate"):
            raise ValueError(f"Parser {parser_id} is {spec.state}, not awaiting approval")

        self.lifecycle.transition(spec, LIFECYCLE_ACTIVE)
        spec.metadata["decided_by"] = operator or "operator"
        spec.metadata["decided_at"] = time.time()
        self.provenance.sign_parser_spec(spec)
        self.registry.register(spec, save_to_disk=True)
        self.hot_swap_registry.register(spec)
        return spec

    def reject(self, parser_id: str, operator: str = "") -> ParserSpec:
        """Operator rejection of a pending parser."""
        self.registry.reload_if_changed()
        spec = self.registry.get_spec(parser_id)
        if spec is None:
            raise KeyError(f"No learned parser {parser_id!r}")

        self.lifecycle.transition(spec, LIFECYCLE_RETIRED)
        spec.metadata["decided_by"] = operator or "operator"
        spec.metadata["decided_at"] = time.time()
        self.provenance.sign_parser_spec(spec)
        self.registry.register(spec, save_to_disk=True)
        self.hot_swap_registry.unregister(parser_id)
        return spec

    def learn(self, lines: list[str], is_known: Callable[[str], bool] | None = None,
              save: bool = True, min_group: int = 2, state: str = "active",
              source: str | None = None) -> dict[str, Any]:
        """
        Explicit operator-driven learning (compatible with v1 API).

        Feeds lines through the streaming tokenizer and clusterer, then
        mines and validates — same result, streamed infrastructure.
        """
        clean = [l.strip() for l in lines if l and l.strip() and not l.strip().startswith("#")]
        known = [l for l in clean if is_known and is_known(l)]
        unknown = [l for l in clean if not (is_known and is_known(l))]

        report: dict[str, Any] = {
            "total_lines": len(clean), "known_lines": len(known),
            "unknown_lines": len(unknown), "accepted": [], "rejected": [],
            "covered_lines": 0, "apg_version": "2.0",
        }
        if not unknown:
            report["error"] = ("All lines are already handled by built-in parsers"
                               if clean else "No log lines supplied")
            return report

        # Stream through tokenizer → clusterer
        local_clusterer = VectorisedClusterer()
        for line in unknown:
            frame = self.streaming_tokenizer.tokenise_event(line)
            if frame:
                local_clusterer.add_frame(frame)

        # Group by fingerprint for compatibility with the miner
        groups: dict[str, list[str]] = {}
        for line in unknown:
            groups.setdefault(
                compute_fingerprint(line).fingerprint_id, []).append(line)

        validator = ParserValidator(
            target_max_parse_time_ms=self.profile.promotion.max_parse_time_ms,
            min_accuracy=self.profile.promotion.min_accuracy)

        covered: set[str] = set()
        for fp_id, group in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            if len(group) < min_group:
                report["rejected"].append({
                    "fingerprint": fp_id, "lines": len(group),
                    "reason": f"Need at least {min_group} samples",
                })
                continue

            with self._learn_lock:
                specs = self.native_miner.mine(group, fp_id)
                clusters = dict(self.native_miner.last_clusters)

            if not specs:
                report["rejected"].append({
                    "fingerprint": fp_id, "lines": len(group),
                    "reason": "No stable template could be mined",
                })
                continue

            from ulpf.intelligence.auto_parser.engine import AutoParserEngine
            chosen, failures = AutoParserEngine._select_specs(
                specs, group, clusters, validator, min_group)

            for spec, result, lines_used in failures:
                report["rejected"].append({
                    "fingerprint": fp_id, "lines": len(lines_used),
                    "parser_id": spec.parser_id, "template": spec.template,
                    "reason": "; ".join(result.rejection_reasons),
                })

            for spec, result, lines_used in chosen:
                spec.state = state
                spec.sample_count = len(lines_used)
                spec.metadata["validation_accuracy"] = round(result.accuracy, 4)
                spec.metadata["learned_from"] = "operator"
                spec.metadata["apg_version"] = "2.0"
                if source:
                    spec.metadata["learned_source"] = source

                self.provenance.sign_parser_spec(spec)
                compiled = self.registry.register(spec, save_to_disk=save)
                self.hot_swap_registry.register(spec, compiled)

                import os
                path = None
                if save:
                    path = os.path.join(
                        self.registry.learned_dir, f"{spec.parser_id}.json")

                covered.update(
                    l for l in group if compiled.parse(l) is not None)

                report["accepted"].append({
                    "spec": spec, "parser_id": spec.parser_id,
                    "template": spec.template, "family": spec.source_family,
                    "fingerprint": fp_id, "lines": len(lines_used),
                    "accuracy": round(result.accuracy, 4),
                    "parse_time_ms": round(result.parse_time_ms_avg, 4),
                    "saved_to": path,
                })

        report["covered_lines"] = len(covered)
        report["coverage_pct"] = round(
            len(covered) / len(unknown) * 100, 1) if unknown else 0
        return report

    # =========================================================================
    # DIAGNOSTICS
    # =========================================================================

    def get_stats(self) -> dict[str, Any]:
        """Comprehensive APG 2.0 diagnostics."""
        return {
            "apg_version": "2.0",
            "running": self._running,
            "profile": self.profile.name,
            "streaming_tokenizer": {
                "events_processed": self.streaming_tokenizer.events_processed,
            },
            "vectorised_clusterer": self.vectorised_clusterer.stats,
            "hot_swap_registry": self.hot_swap_registry.get_stats(),
            "registry": {
                "parsers": len(self.registry.list_parsers()),
                "version": self.registry.version,
            },
            "lifecycle": {
                "pending_clusters": len(self._pending_clusters),
                "learn_attempts": dict(self._attempts),
            },
        }
