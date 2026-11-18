"""
AutoParser Engine
===================
The orchestrator connecting the Hot Path (data plane) and the
Learning Plane (background thread).

Data plane  — ``parse()``: anchored learned parsers are tried first (a few
              compiled-regex probes); only lines nothing matches are
              fingerprinted and sampled for learning. Never blocks.
Learning plane — samples per structural fingerprint are mined, validated,
              admitted as *canary* parsers, and promoted to *active* once
              they survive the canary window without errors. Every lifecycle
              change is persisted to the learned-parsers directory.
``learn()`` — explicit, operator-driven learning from sample lines (CLI,
              REST API, desktop Auto-Learn page) with validation.
"""
from __future__ import annotations

import logging
import queue
import threading
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
from ulpf.intelligence.auto_parser.lifecycle import ParserLifecycleManager
from ulpf.intelligence.auto_parser.provenance import ProvenanceManager

logger = logging.getLogger(__name__)

_MAX_LEARN_ATTEMPTS = 3
# Smallest structure inside a shared fingerprint the background learner will
# turn into a parser (the canary window still has to be survived afterwards)
_MIN_AUTO_CLUSTER = 10


class AutoParserEngine:
    """
    Main Orchestrator for the Auto-Parser.
    Separates the blocking learning plane from the non-blocking data plane.
    """

    def __init__(self, config_path: str | None = None, learned_dir: str | None = None):
        self.config = AutoParserConfig(config_path)
        self.profile = self.config.active_profile

        self.registry = AutoParserRegistry(learned_dir)
        self.provenance = ProvenanceManager()

        self.quarantine = QuarantineManager(self.profile.poisoning)
        self.sampler = Sampler(
            max_samples_per_fingerprint=self.profile.poisoning.max_sample_size_per_candidate,
            max_fingerprints=self.profile.max_candidate_templates,
        )
        self.learning_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._pending: set[str] = set()
        self._attempts: dict[str, int] = {}
        self._learn_lock = threading.Lock()

        self.native_miner = NativeTemplateMiner()
        self.validator = ParserValidator(
            target_max_parse_time_ms=self.profile.promotion.max_parse_time_ms,
            min_accuracy=self.profile.promotion.min_accuracy,
        )
        self.admission = AdmissionController(self.profile)
        self.lifecycle = ParserLifecycleManager()

        self._running = False
        self._learning_thread: threading.Thread | None = None
        # Defence mode: autonomously learned parsers wait for operator approval
        self.approval_required = False
        # Cap on autonomously learned parsers per source (None = unlimited); a source
        # at its cap is still parsed by its parsers, it just stops creating new ones.
        self.max_parsers_per_source: int | None = None
        self._fid_source: dict[str, str] = {}
        self._per_source: dict[str, int] = {}
        for spec in self.registry.list_parsers():
            src = spec.metadata.get("learned_source")
            if src is not None and spec.state != "retired":
                self._per_source[src] = self._per_source.get(src, 0) + 1

    # =========================================================================
    # HOT PATH (DATA PLANE)
    # =========================================================================

    def parse(self, raw_line: str, source_ip: str = "") -> dict[str, Any] | None:
        """Parse a line with a learned parser. Returns fields, or None if unknown."""
        registry = self.registry
        if registry.has_parsers():
            parser, parsed = registry.get_adaptive_parse(raw_line, source=source_ip)
            if parser is not None:
                if parsed is not None:
                    self._attach(parsed, parser)
                    return parsed
                if parser.spec.state == "canary":
                    self.lifecycle.record_canary_event(parser.parser_id, False)

        has_generic = registry.has_generic
        admitted = False
        if self._running and self.profile.auto_discovery:
            # Rate-limit (per source) before paying for a fingerprint
            admitted = (self.quarantine.validate_message_length(raw_line)
                        and self.quarantine.check_and_record_event(source_ip))
        if not admitted and not has_generic:
            return None

        fp = compute_fingerprint(raw_line)
        if has_generic:
            parser = registry.get_exact_match(fp.fingerprint_id)
            if parser is not None:
                parsed = parser.parse(raw_line)
                if parsed is not None:
                    self._attach(parsed, parser)
                    return parsed
        if admitted:
            self._sample_unknown(raw_line, fp, source_ip)
        return None

    def _attach(self, parsed: dict, parser) -> None:
        self.provenance.attach_event_provenance(parsed, parser, "", parser.spec.match.fingerprint or "")
        parsed["_meta"]["source_family"] = parser.spec.source_family
        if parser.spec.state == "canary":
            self.lifecycle.record_canary_event(parser.parser_id, True)

    def submit_unknown(self, raw_line: str, fp: FormatFingerprint, source_ip: str) -> None:
        """Submit an unknown event to the learning plane (rate-limited)."""
        if not self.profile.auto_discovery or not self._running:
            return
        if not self.quarantine.validate_message_length(raw_line):
            return
        if not self.quarantine.check_and_record_event(source_ip):
            return
        self._sample_unknown(raw_line, fp, source_ip)

    def _sample_unknown(self, raw_line: str, fp: FormatFingerprint, source_ip: str = "") -> None:
        fid = fp.fingerprint_id
        if self._attempts.get(fid, 0) >= _MAX_LEARN_ATTEMPTS:
            return
        if fid not in self.sampler._reservoirs:
            cap = self.max_parsers_per_source
            if cap is not None and self._per_source.get(source_ip or "", 0) >= cap:
                return
            if not self.quarantine.record_new_cluster(source_ip):
                return
            if len(self._fid_source) > 10_000:
                self._fid_source.clear()
            self._fid_source[fid] = source_ip or ""
        self.sampler.add_sample(fid, raw_line)
        if fid in self._pending:
            return
        res = self.sampler._reservoirs.get(fid)
        if res is None or len(res.samples) < self.profile.min_samples_for_promotion:
            return
        self._pending.add(fid)
        try:
            self.learning_queue.put_nowait(fid)
        except queue.Full:
            self._pending.discard(fid)

    # =========================================================================
    # BACKGROUND LEARNING PLANE
    # =========================================================================

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._learning_thread = threading.Thread(
            target=self._learning_loop, name="ulpf-autoparser-learner", daemon=True)
        self._learning_thread.start()
        logger.info(f"AutoParser Engine started (Profile: {self.profile.name})")

    def stop(self) -> None:
        self._running = False
        if self._learning_thread:
            self._learning_thread.join(timeout=2.0)
            self._learning_thread = None

    def _learning_loop(self) -> None:
        import time
        last_reload = time.monotonic()
        while self._running:
            try:
                fp_id = self.learning_queue.get(timeout=1.0)
            except queue.Empty:
                fp_id = None
            if time.monotonic() - last_reload >= 2.0:
                last_reload = time.monotonic()
                try:
                    if self.registry.reload_if_changed():
                        logger.info("Reloaded learned parsers changed on disk")
                except Exception:
                    logger.debug("Learned-parser reload failed", exc_info=True)
            if fp_id is not None:
                try:
                    self._process_learning_candidate(fp_id)
                except Exception as e:
                    logger.error(f"Error in learning loop: {e}", exc_info=True)
                finally:
                    self._pending.discard(fp_id)
            try:
                self._check_canaries()
            except Exception as e:
                logger.error(f"Error evaluating canaries: {e}", exc_info=True)

    def _process_learning_candidate(self, fp_id: str) -> None:
        samples = self.sampler.get_samples(fp_id)
        if len(samples) < self.profile.min_samples_for_promotion:
            return
        self._attempts[fp_id] = self._attempts.get(fp_id, 0) + 1
        logger.info(f"Learning fingerprint {fp_id} from {len(samples)} samples")

        with self._learn_lock:
            specs = self.native_miner.mine(samples, fp_id)
            clusters = dict(self.native_miner.last_clusters)
        chosen = []
        if specs:
            chosen, failures = self._select_specs(specs, samples, clusters, self.validator,
                                                  _MIN_AUTO_CLUSTER)
            for spec, result, _ in failures:
                logger.debug(f"Parser {spec.parser_id} rejected: {'; '.join(result.rejection_reasons)}")
        source = self._fid_source.pop(fp_id, "")
        cap = self.max_parsers_per_source
        for spec, val_result, _ in chosen:
            if cap is not None and self._per_source.get(source, 0) >= cap:
                logger.warning(f"Source {source!r} reached learning.max_parsers_per_source={cap}; "
                               f"not registering {spec.parser_id}")
                break
            can_promote, reason = self.admission.can_promote_to_canary(spec, val_result)
            if not can_promote:
                logger.debug(f"Parser {spec.parser_id} rejected: {reason}")
                continue
            state = "pending_approval" if self.approval_required else "canary"
            spec.metadata["learned_from"] = "autonomous"
            spec.metadata["learned_source"] = source
            spec.metadata["validation_accuracy"] = round(val_result.accuracy, 4)
            self.lifecycle.transition(spec, state)
            self.provenance.sign_parser_spec(spec)
            try:
                self.registry.register(spec, ParserCompiler.compile(spec), save_to_disk=True)
                self._per_source[source] = self._per_source.get(source, 0) + 1
                self._attempts[fp_id] = _MAX_LEARN_ATTEMPTS
                logger.info(f"Learned {spec.parser_id} ({state}).")
            except Exception as e:
                logger.error(f"Failed to register learned parser {spec.parser_id}: {e}")
        self.sampler.clear_fingerprint(fp_id)

    def _check_canaries(self) -> None:
        for spec in self.registry.list_parsers():
            if spec.state != "canary":
                continue
            stats = self.lifecycle.get_canary_stats(spec.parser_id)
            if not stats:
                # Canary loaded from disk after a restart: restart its observation window
                self.lifecycle.transition(spec, "candidate")
                self.lifecycle.transition(spec, "canary")
                continue
            can_promote, reason = self.admission.can_promote_to_active(
                spec, stats["duration"], stats["events_processed"], stats["errors"])
            if can_promote:
                self.lifecycle.transition(spec, "active")
                self.lifecycle.cleanup_canary(spec.parser_id)
                self._persist_state(spec)
                logger.info(f"Promoted {spec.parser_id} to ACTIVE state.")
            elif stats["duration"] > self.profile.canary_duration_sec * 2:
                self.lifecycle.transition(spec, "retired")
                self.lifecycle.cleanup_canary(spec.parser_id)
                self._persist_state(spec)
                logger.warning(f"Retired canary {spec.parser_id}: {reason}")

    def approve(self, parser_id: str, operator: str = "") -> ParserSpec:
        """Operator approval of a pending parser (defence mode): it becomes active."""
        return self._decide(parser_id, "active", operator)

    def reject(self, parser_id: str, operator: str = "") -> ParserSpec:
        return self._decide(parser_id, "retired", operator)

    def _decide(self, parser_id: str, state: str, operator: str) -> ParserSpec:
        import time as _time
        self.registry.reload_if_changed()
        spec = self.registry.get_spec(parser_id)
        if spec is None:
            raise KeyError(f"no learned parser {parser_id!r}")
        if state == "active" and spec.state not in ("pending_approval", "canary", "candidate"):
            raise ValueError(f"parser {parser_id} is {spec.state}, not awaiting approval")
        self.lifecycle.transition(spec, state)
        spec.metadata["decided_by"] = operator or "operator"
        spec.metadata["decided_at"] = _time.time()
        self.provenance.sign_parser_spec(spec)
        self.registry.register(spec, save_to_disk=True)
        return spec

    def _persist_state(self, spec: ParserSpec) -> None:
        self.provenance.sign_parser_spec(spec)   # the signature covers the state
        self.registry.refresh()
        try:
            self.registry.save_parser(spec)
        except OSError as e:
            logger.warning(f"Could not persist state of {spec.parser_id}: {e}")

    # =========================================================================
    # EXPLICIT (OPERATOR-DRIVEN) LEARNING
    # =========================================================================

    def learn(self, lines: list[str], is_known: Callable[[str], bool] | None = None,
              save: bool = True, min_group: int = 2, state: str = "active",
              source: str | None = None) -> dict[str, Any]:
        """Learn parsers for the unknown formats present in ``lines``.

        Args:
            lines: sample log lines (may mix formats)
            is_known: predicate returning True for lines a built-in parser
                      already handles; those are excluded from learning
            save: persist accepted specs to the learned-parsers directory
            min_group: minimum lines per structural fingerprint to learn from

        Returns a report with accepted specs (validated, state ``active``),
        rejected candidates with reasons, and coverage statistics.
        """
        clean = [l.strip() for l in lines if l and l.strip() and not l.strip().startswith("#")]
        known = [l for l in clean if is_known and is_known(l)]
        unknown = [l for l in clean if not (is_known and is_known(l))]
        report: dict[str, Any] = {
            "total_lines": len(clean), "known_lines": len(known), "unknown_lines": len(unknown),
            "accepted": [], "rejected": [], "covered_lines": 0,
        }
        if not unknown:
            report["error"] = ("All lines are already handled by built-in parsers"
                               if clean else "No log lines supplied")
            return report

        groups: dict[str, list[str]] = {}
        for line in unknown:
            groups.setdefault(compute_fingerprint(line).fingerprint_id, []).append(line)

        validator = ParserValidator(target_max_parse_time_ms=self.profile.promotion.max_parse_time_ms,
                                    min_accuracy=self.profile.promotion.min_accuracy)
        covered: set[str] = set()
        for fp_id, group in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            if len(group) < min_group:
                report["rejected"].append({"fingerprint": fp_id, "lines": len(group),
                                           "reason": f"Need at least {min_group} samples of this structure"})
                continue
            with self._learn_lock:
                specs = self.native_miner.mine(group, fp_id)
                clusters = dict(self.native_miner.last_clusters)
            if not specs:
                report["rejected"].append({"fingerprint": fp_id, "lines": len(group),
                                           "reason": "No stable template could be mined"})
                continue
            chosen, failures = self._select_specs(specs, group, clusters, validator, min_group)
            for spec, result, lines in failures:
                report["rejected"].append({"fingerprint": fp_id, "lines": len(lines),
                                           "parser_id": spec.parser_id, "template": spec.template,
                                           "reason": "; ".join(result.rejection_reasons)})
            for spec, result, lines in chosen:
                spec.state = state
                spec.sample_count = len(lines)
                spec.metadata["validation_accuracy"] = round(result.accuracy, 4)
                spec.metadata["learned_from"] = "operator"
                if source:
                    spec.metadata["learned_source"] = source
                self.provenance.sign_parser_spec(spec)
                compiled = self.registry.register(spec, save_to_disk=save)
                path = None
                if save:
                    import os
                    path = os.path.join(self.registry.learned_dir, f"{spec.parser_id}.json")
                covered.update(l for l in group if compiled.parse(l) is not None)
                report["accepted"].append({
                    "spec": spec, "parser_id": spec.parser_id, "template": spec.template,
                    "family": spec.source_family, "fingerprint": fp_id, "lines": len(lines),
                    "accuracy": round(result.accuracy, 4),
                    "parse_time_ms": round(result.parse_time_ms_avg, 4), "saved_to": path,
                })
        report["covered_lines"] = len(covered)
        report["coverage_pct"] = round(len(covered) / len(unknown) * 100, 1)
        return report

    @staticmethod
    def _select_specs(specs: list[ParserSpec], lines: list[str],
                      clusters: dict[str, tuple[list[str], int]],
                      validator: ParserValidator, min_cluster: int):
        """Choose which mined specs to accept for one fingerprint's lines.

        Normally one template covers every line, and the most accurate spec is
        accepted if it validates against all of them. A fingerprint can also
        be shared by structurally different formats; then each spec is judged
        on the cluster it was mined from, and must parse at least 90% of
        that cluster's share of ``lines``.

        Returns (chosen, failures), each a list of (spec, ValidationResult, lines).
        """
        results = [(spec, validator.validate(spec, lines)) for spec in specs]
        best_spec, best = max(results, key=lambda r: r[1].accuracy)
        if best.passed:
            return [(best_spec, best, lines)], []
        chosen, failures = [], []
        for spec, whole in results:
            samples, count = clusters.get(spec.parser_id, ([], 0))
            matched = round(whole.accuracy * len(lines))
            if count >= len(lines) or count < max(2, min_cluster) or matched < 0.9 * count:
                failures.append((spec, whole, lines))
                continue
            own = validator.validate(spec, samples)
            (chosen if own.passed else failures).append((spec, own, samples))
        return chosen, failures
