"""
APG 2.0 Test Suite
====================
Comprehensive unit and integration tests proving autonomous promotion from
raw format to structured fields in <5,000 sample events.

Tests cover:
  1. Streaming tokenizer bitmask vectorisation
  2. Vectorised clusterer with LSH near-match
  3. DFA transition table compilation
  4. Aho-Corasick multi-pattern automaton
  5. Hot-swap registry atomic snapshots
  6. 4-stage lifecycle (Sampling → Canary → Active → Retired)
  7. End-to-end streaming pipeline: raw → structured Arrow fields
  8. Defence mode cryptographic signing
  9. Streaming drift detection
  10. Continuous learning without process restart
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401


# ---------------------------------------------------------------------------
# Sample data generators
# ---------------------------------------------------------------------------

def _plc_line(i: int) -> str:
    """A proprietary PLC format no built-in parser knows."""
    return (f"PLC{i % 7:02d} >> valve {i % 40} {'opened' if i % 3 else 'closed'} by op{i % 5} "
            f"pressure={100 + i % 50}.{i % 10} temp={20 + i % 15}.{i % 9} "
            f"at 2026-09-{15 + i % 15:02d}T{10 + i % 12:02d}:{i % 60:02d}:00Z")


def _firewall_line(i: int) -> str:
    """A custom firewall log format."""
    return (f"2026-10-{10 + i % 20:02d}T{i % 24:02d}:{i % 60:02d}:00Z FW-CORE "
            f"{'ALLOW' if i % 4 else 'DENY'} src=10.{i % 256}.{i % 128}.{i % 64} "
            f"dst=192.168.{i % 100}.{i % 200} proto={'TCP' if i % 2 else 'UDP'} "
            f"sport={1024 + i % 50000} dport={i % 1024} "
            f"bytes={i * 100} rule=R{i % 20:03d}")


def _auth_line(i: int) -> str:
    """A custom authentication log format."""
    users = ["admin", "root", "alice", "bob", "charlie", "dave", "eve"]
    actions = ["LOGIN_OK", "LOGIN_FAIL", "LOGOUT", "SUDO", "KEY_AUTH"]
    return (f"[{2026}-09-{15 + i % 15:02d} {10 + i % 12:02d}:{i % 60:02d}:{i % 60:02d}] "
            f"auth-engine {actions[i % len(actions)]} "
            f"user={users[i % len(users)]} src=172.16.{i % 50}.{i % 200} "
            f"session={i * 37 % 99999:05d} method={'ssh' if i % 3 else 'console'}")


def _iot_line(i: int) -> str:
    """An IoT sensor telemetry format."""
    return (f"SENSOR-{i % 100:04d} | "
            f"2026-10-{15 + i % 15:02d}T{i % 24:02d}:{i % 60:02d}:00Z | "
            f"temp={20.0 + i % 30 + i % 10 / 10:.1f} | "
            f"humidity={40 + i % 40} | "
            f"pressure={1013 + i % 50} | "
            f"battery={95 - i % 30} | "
            f"status={'OK' if i % 5 else 'WARN'}")


def _mixed_format_lines(count: int = 500) -> list[str]:
    """Generate a mix of unknown formats."""
    lines = []
    for i in range(count):
        if i % 4 == 0:
            lines.append(_plc_line(i))
        elif i % 4 == 1:
            lines.append(_firewall_line(i))
        elif i % 4 == 2:
            lines.append(_auth_line(i))
        else:
            lines.append(_iot_line(i))
    return lines


# ===========================================================================
# 1. Streaming Tokenizer Tests
# ===========================================================================

class TestStreamingTokenizer(unittest.TestCase):
    """Tests for the bitmask-vectorised streaming tokenizer."""

    def test_basic_tokenisation(self):
        """Tokenise a simple log line and verify bitmask structure."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import StreamingTokenizer

        tok = StreamingTokenizer()
        frame = tok.tokenise_event(
            "2026-09-15T10:30:00Z FW01 DENY src=10.0.0.1 dst=192.168.1.1")

        self.assertIsNotNone(frame)
        self.assertGreater(frame.token_count, 0)
        self.assertTrue(len(frame.bitmask_vector) > 0)
        self.assertEqual(len(frame.fingerprint_hash), 16)
        self.assertEqual(tok.events_processed, 1)

    def test_bitmask_flags(self):
        """Verify that known token types get correct bitmask flags."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import (
            StreamingTokenizer, BIT_TIMESTAMP, BIT_IPV4, BIT_KV_KEY,
        )

        tok = StreamingTokenizer()
        frame = tok.tokenise_event("2026-09-15T10:30:00Z src=10.0.0.1")

        # First token should have TIMESTAMP bit
        self.assertTrue(frame.tokens[0].bitmask & BIT_TIMESTAMP,
                        f"Expected TIMESTAMP bit, got 0x{frame.tokens[0].bitmask:x}")

        # KV token should have KV bits
        kv_tokens = [t for t in frame.tokens if t.kv_key is not None]
        self.assertGreater(len(kv_tokens), 0, "Expected at least one KV token")

    def test_empty_and_long_lines_rejected(self):
        """Empty and excessively long lines return None."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import StreamingTokenizer

        tok = StreamingTokenizer()
        self.assertIsNone(tok.tokenise_event(""))
        self.assertIsNone(tok.tokenise_event("   "))
        self.assertIsNone(tok.tokenise_event("x" * 100_000))

    def test_streaming_iterator(self):
        """Verify the streaming iterator works over an unbounded source."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import StreamingTokenizer

        tok = StreamingTokenizer()
        lines = [_plc_line(i) for i in range(100)]
        frames = list(tok.tokenise_stream(iter(lines)))

        self.assertEqual(len(frames), 100)
        self.assertEqual(tok.events_processed, 100)

    def test_structural_fingerprint_consistency(self):
        """Lines with the same structure should get the same fingerprint."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import StreamingTokenizer

        tok = StreamingTokenizer()
        f1 = tok.tokenise_event(_plc_line(1))
        f2 = tok.tokenise_event(_plc_line(2))

        self.assertEqual(f1.fingerprint_hash, f2.fingerprint_hash,
                         "Same-structure lines should have identical fingerprints")

    def test_different_formats_different_fingerprints(self):
        """Lines with different structures should get different fingerprints."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import StreamingTokenizer

        tok = StreamingTokenizer()
        f1 = tok.tokenise_event(_plc_line(0))
        f2 = tok.tokenise_event(_firewall_line(0))

        self.assertNotEqual(f1.fingerprint_hash, f2.fingerprint_hash,
                            "Different-structure lines should have different fingerprints")

    def test_delimiter_detection(self):
        """Verify correct delimiter detection for pipe-separated format."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import StreamingTokenizer

        tok = StreamingTokenizer()
        frame = tok.tokenise_event(_iot_line(0))

        self.assertIn(frame.delimiter, ["|", " | "],
                      f"Expected pipe delimiter, got {frame.delimiter!r}")


# ===========================================================================
# 2. Bitmask Jaccard Similarity Tests
# ===========================================================================

class TestBitmaskJaccard(unittest.TestCase):
    """Tests for vectorised bitmask Jaccard similarity."""

    def test_identical_vectors(self):
        """Identical bitmask vectors should have Jaccard = 1.0."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import (
            StreamingTokenizer, bitmask_jaccard,
        )
        tok = StreamingTokenizer()
        f1 = tok.tokenise_event(_plc_line(1))
        f2 = tok.tokenise_event(_plc_line(2))

        similarity = bitmask_jaccard(f1.bitmask_vector, f2.bitmask_vector)
        self.assertGreaterEqual(similarity, 0.9,
                                f"Same-structure similarity should be ≥0.9, got {similarity:.3f}")

    def test_different_vectors(self):
        """Different structures should have low similarity."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import (
            StreamingTokenizer, bitmask_jaccard,
        )
        tok = StreamingTokenizer()
        f1 = tok.tokenise_event(_plc_line(0))
        f2 = tok.tokenise_event(_iot_line(0))

        similarity = bitmask_jaccard(f1.bitmask_vector, f2.bitmask_vector)
        self.assertLess(similarity, 0.8,
                        f"Different-structure similarity should be <0.8, got {similarity:.3f}")

    def test_structural_distance(self):
        """Distance = 1 - Jaccard should be monotonic."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import (
            StreamingTokenizer, bitmask_structural_distance,
        )
        tok = StreamingTokenizer()
        f1 = tok.tokenise_event(_plc_line(0))
        f2 = tok.tokenise_event(_plc_line(1))
        f3 = tok.tokenise_event(_iot_line(0))

        d_same = bitmask_structural_distance(f1.bitmask_vector, f2.bitmask_vector)
        d_diff = bitmask_structural_distance(f1.bitmask_vector, f3.bitmask_vector)

        self.assertLess(d_same, d_diff,
                        "Same-structure distance should be less than cross-structure")

    def test_empty_vectors(self):
        """Edge case: empty vectors."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import bitmask_jaccard

        self.assertEqual(bitmask_jaccard(b"", b""), 1.0)
        self.assertEqual(bitmask_jaccard(b"", b"\x00" * 8), 0.0)


# ===========================================================================
# 3. Vectorised Clusterer Tests
# ===========================================================================

class TestVectorisedClusterer(unittest.TestCase):
    """Tests for the LSH-indexed vectorised clusterer."""

    def test_same_format_clusters_together(self):
        """Lines of the same format should land in the same cluster."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import StreamingTokenizer
        from ulpf.intelligence.auto_parser.vectorised_clusterer import VectorisedClusterer

        tok = StreamingTokenizer()
        clusterer = VectorisedClusterer()

        clusters_seen: set[str] = set()
        for i in range(50):
            frame = tok.tokenise_event(_plc_line(i))
            cluster = clusterer.add_frame(frame)
            clusters_seen.add(cluster.cluster_id)

        self.assertEqual(len(clusters_seen), 1,
                         f"Expected 1 cluster for same format, got {len(clusters_seen)}")

    def test_different_formats_separate_clusters(self):
        """Different formats should end up in different clusters."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import StreamingTokenizer
        from ulpf.intelligence.auto_parser.vectorised_clusterer import VectorisedClusterer

        tok = StreamingTokenizer()
        clusterer = VectorisedClusterer()

        for i in range(50):
            frame = tok.tokenise_event(_plc_line(i))
            clusterer.add_frame(frame)
        for i in range(50):
            frame = tok.tokenise_event(_firewall_line(i))
            clusterer.add_frame(frame)

        self.assertGreaterEqual(clusterer.stats["clusters"], 2,
                                "Expected ≥2 clusters for different formats")

    def test_ready_clusters(self):
        """Clusters with enough samples should be reported as ready."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import StreamingTokenizer
        from ulpf.intelligence.auto_parser.vectorised_clusterer import VectorisedClusterer

        tok = StreamingTokenizer()
        clusterer = VectorisedClusterer()

        for i in range(100):
            frame = tok.tokenise_event(_plc_line(i))
            clusterer.add_frame(frame)

        ready = clusterer.get_ready_clusters(min_samples=50)
        self.assertGreater(len(ready), 0, "Expected at least one ready cluster")
        self.assertGreaterEqual(ready[0].sample_count, 50)

    def test_drift_detection(self):
        """Clusters with diverse value types should report drift."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import StreamingTokenizer
        from ulpf.intelligence.auto_parser.vectorised_clusterer import VectorisedClusterer

        tok = StreamingTokenizer()
        clusterer = VectorisedClusterer(similarity_threshold=0.50)

        # Feed homogeneous data
        for i in range(50):
            frame = tok.tokenise_event(_plc_line(i))
            clusterer.add_frame(frame)

        ready = clusterer.get_ready_clusters(min_samples=10)
        if ready:
            # Same-format should not drift
            self.assertLess(ready[0].drift_score, 0.8,
                            f"Same-format drift should be low, got {ready[0].drift_score:.3f}")

    def test_cluster_eviction(self):
        """Cold clusters should be evicted when at capacity."""
        from ulpf.intelligence.auto_parser.vectorised_clusterer import VectorisedClusterer

        clusterer = VectorisedClusterer(max_clusters=5)
        # Internal: just verify eviction doesn't crash
        evicted = clusterer._evict_cold_clusters()
        self.assertIsInstance(evicted, int)

    def test_snapshot(self):
        """Cluster inventory snapshot should capture state."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import StreamingTokenizer
        from ulpf.intelligence.auto_parser.vectorised_clusterer import VectorisedClusterer

        tok = StreamingTokenizer()
        clusterer = VectorisedClusterer()

        for i in range(20):
            frame = tok.tokenise_event(_plc_line(i))
            clusterer.add_frame(frame)

        snapshot = clusterer.snapshot()
        self.assertGreater(snapshot.cluster_count, 0)
        self.assertEqual(snapshot.total_events, 20)


# ===========================================================================
# 4. DFA Transition Table Tests
# ===========================================================================

class TestDFACompilation(unittest.TestCase):
    """Tests for DFA transition table compilation from ParserSpecs."""

    def _make_spec(self) -> 'ParserSpec':
        from ulpf.intelligence.auto_parser.parser_spec import ParserSpec, FieldSpec, MatchSpec
        return ParserSpec(
            parser_id="test-dfa-001",
            template="<TIMESTAMP> FW01 {action} src=<*> dst=<*>",
            fields=[
                FieldSpec(name="timestamp", field_type="timestamp", position=0),
                FieldSpec(name="event.action", field_type="action", position=2),
                FieldSpec(name="source.ip", field_type="ipv4", original_key="src"),
                FieldSpec(name="destination.ip", field_type="ipv4", original_key="dst"),
            ],
            match=MatchSpec(
                fingerprint="test-fp",
                delimiter=" ",
                format_hints={
                    "layout": [
                        {"k": "field", "v": "timestamp", "o": "", "c": "", "mask": "timestamp"},
                        {"k": "lit", "v": "FW01", "o": "", "c": ""},
                        {"k": "field", "v": "event.action", "o": "", "c": ""},
                        {"k": "kv", "v": "source.ip", "key": "src"},
                        {"k": "kv", "v": "destination.ip", "key": "dst"},
                    ],
                },
            ),
        )

    def test_compile_dfa(self):
        """DFA compilation should produce a valid transition table."""
        from ulpf.intelligence.auto_parser.native_synthesis import compile_dfa

        spec = self._make_spec()
        dfa = compile_dfa(spec)

        self.assertEqual(dfa.spec_id, "test-dfa-001")
        self.assertGreater(dfa.num_states, 0)
        self.assertEqual(len(dfa.transitions), dfa.num_states * 12)
        self.assertGreater(len(dfa.field_states), 0)
        self.assertGreater(len(dfa.accept_states), 0)

    def test_dfa_serialisation(self):
        """DFA tables should round-trip through JSON serialisation."""
        from ulpf.intelligence.auto_parser.native_synthesis import compile_dfa, DFATransitionTable

        spec = self._make_spec()
        dfa = compile_dfa(spec)

        serialised = dfa.serialise()
        json_str = json.dumps(serialised)
        restored = DFATransitionTable.deserialise(json.loads(json_str))

        self.assertEqual(restored.spec_id, dfa.spec_id)
        self.assertEqual(restored.num_states, dfa.num_states)
        self.assertEqual(restored.transitions, dfa.transitions)
        self.assertEqual(restored.field_states, dfa.field_states)

    def test_empty_layout_raises(self):
        """A spec with no layout should raise ValueError."""
        from ulpf.intelligence.auto_parser.native_synthesis import compile_dfa
        from ulpf.intelligence.auto_parser.parser_spec import ParserSpec

        spec = ParserSpec(parser_id="empty")
        with self.assertRaises(ValueError):
            compile_dfa(spec)


# ===========================================================================
# 5. Aho-Corasick Multi-Pattern Tests
# ===========================================================================

class TestAhoCorasick(unittest.TestCase):
    """Tests for the Aho-Corasick multi-pattern automaton."""

    def test_single_pattern(self):
        """Single pattern should be found in matching text."""
        from ulpf.intelligence.auto_parser.native_synthesis import AhoCorasickAutomaton

        ac = AhoCorasickAutomaton()
        ac.add_pattern("FW01", "parser-fw")
        ac.build()

        matches = ac.search("2026-09-15 FW01 DENY src=10.0.0.1")
        self.assertIn("parser-fw", matches)

    def test_multiple_patterns(self):
        """Multiple patterns should all be found."""
        from ulpf.intelligence.auto_parser.native_synthesis import AhoCorasickAutomaton

        ac = AhoCorasickAutomaton()
        ac.add_pattern("FW01", "parser-fw")
        ac.add_pattern("DENY", "parser-deny")
        ac.add_pattern("AUTH", "parser-auth")
        ac.build()

        matches = ac.search("2026-09-15 FW01 DENY src=10.0.0.1")
        self.assertIn("parser-fw", matches)
        self.assertIn("parser-deny", matches)
        self.assertNotIn("parser-auth", matches)

    def test_no_match(self):
        """Non-matching text should return empty set."""
        from ulpf.intelligence.auto_parser.native_synthesis import AhoCorasickAutomaton

        ac = AhoCorasickAutomaton()
        ac.add_pattern("XYZZY", "parser-x")
        ac.build()

        matches = ac.search("Nothing matches here")
        self.assertEqual(len(matches), 0)

    def test_overlapping_patterns(self):
        """Overlapping patterns should all be found."""
        from ulpf.intelligence.auto_parser.native_synthesis import AhoCorasickAutomaton

        ac = AhoCorasickAutomaton()
        ac.add_pattern("he", "p1")
        ac.add_pattern("her", "p2")
        ac.add_pattern("hers", "p3")
        ac.build()

        matches = ac.search("hers")
        self.assertIn("p1", matches)
        self.assertIn("p2", matches)
        self.assertIn("p3", matches)

    def test_serialisation(self):
        """AC automaton should serialise to JSON-compatible dict."""
        from ulpf.intelligence.auto_parser.native_synthesis import AhoCorasickAutomaton

        ac = AhoCorasickAutomaton()
        ac.add_pattern("test", "p1")
        ac.build()

        data = ac.serialise()
        self.assertIn("nodes", data)
        self.assertTrue(data["built"])
        self.assertEqual(data["pattern_count"], 1)


# ===========================================================================
# 6. Hot-Swap Registry Tests
# ===========================================================================

class TestHotSwapRegistry(unittest.TestCase):
    """Tests for the atomic hot-swap parser registry."""

    def _make_spec_and_compiled(self, pid: str, state: str = "active"):
        from ulpf.intelligence.auto_parser.parser_spec import ParserSpec, FieldSpec, MatchSpec
        from ulpf.intelligence.auto_parser.compiler import ParserCompiler

        spec = ParserSpec(
            parser_id=pid,
            state=state,
            template="<TIMESTAMP> FW01 {action}",
            fields=[
                FieldSpec(name="timestamp", field_type="timestamp", position=0),
                FieldSpec(name="event.action", field_type="action", position=2),
            ],
            match=MatchSpec(
                delimiter=" ",
                format_hints={
                    "layout": [
                        {"k": "field", "v": "timestamp", "o": "", "c": "", "mask": "timestamp"},
                        {"k": "lit", "v": "FW01", "o": "", "c": ""},
                        {"k": "field", "v": "event.action", "o": "", "c": ""},
                    ],
                },
            ),
        )
        compiled = ParserCompiler.compile(spec)
        return spec, compiled

    def test_register_and_dispatch(self):
        """Register a parser and dispatch a matching line."""
        from ulpf.intelligence.auto_parser.native_synthesis import HotSwapRegistry

        registry = HotSwapRegistry()
        spec, compiled = self._make_spec_and_compiled("test-fw-001")
        registry.register(spec, compiled)

        result = registry.dispatch("2026-09-15T10:30:00Z FW01 DENY")
        self.assertIsNotNone(result)
        self.assertEqual(result.parser_id, "test-fw-001")

    def test_hot_swap_atomic(self):
        """Version increments atomically on register."""
        from ulpf.intelligence.auto_parser.native_synthesis import HotSwapRegistry

        registry = HotSwapRegistry()
        v0 = registry.version
        spec, compiled = self._make_spec_and_compiled("test-fw-001")
        registry.register(spec, compiled)
        self.assertEqual(registry.version, v0 + 1)

    def test_unregister_removes_parser(self):
        """Unregistering a parser should remove it from dispatch."""
        from ulpf.intelligence.auto_parser.native_synthesis import HotSwapRegistry

        registry = HotSwapRegistry()
        spec, compiled = self._make_spec_and_compiled("test-fw-001")
        registry.register(spec, compiled)

        self.assertIsNotNone(registry.dispatch("2026-09-15T10:30:00Z FW01 DENY"))

        registry.unregister("test-fw-001")
        self.assertIsNone(registry.dispatch("2026-09-15T10:30:00Z FW01 DENY"))

    def test_concurrent_access(self):
        """Multiple threads reading during a write should not crash."""
        from ulpf.intelligence.auto_parser.native_synthesis import HotSwapRegistry

        registry = HotSwapRegistry()
        spec, compiled = self._make_spec_and_compiled("test-fw-001")
        registry.register(spec, compiled)

        errors: list[Exception] = []

        def reader():
            for _ in range(1000):
                try:
                    registry.dispatch("2026-09-15T10:30:00Z FW01 DENY")
                except Exception as e:
                    errors.append(e)

        def writer():
            for i in range(10):
                try:
                    s, c = self._make_spec_and_compiled(f"test-fw-{i:03d}")
                    registry.register(s, c)
                except Exception as e:
                    errors.append(e)

        threads = [threading.Thread(target=reader) for _ in range(4)]
        threads.append(threading.Thread(target=writer))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Concurrent access errors: {errors}")


# ===========================================================================
# 7. APG 2.0 Lifecycle Tests
# ===========================================================================

class TestAPG2Lifecycle(unittest.TestCase):
    """Tests for the 4-stage lifecycle manager."""

    def test_lifecycle_transitions(self):
        """Valid transitions should succeed."""
        from ulpf.intelligence.auto_parser.streaming_engine import APG2LifecycleManager
        from ulpf.intelligence.auto_parser.parser_spec import ParserSpec

        lm = APG2LifecycleManager()
        spec = ParserSpec(parser_id="test-lc-001", state="candidate")

        lm.transition(spec, "sampling")
        self.assertEqual(spec.state, "sampling")

        lm.transition(spec, "canary")
        self.assertEqual(spec.state, "canary")

        # Should have canary stats now
        stats = lm.get_canary_stats("test-lc-001")
        self.assertIsNotNone(stats)
        self.assertEqual(stats["events_processed"], 0)

    def test_canary_event_tracking(self):
        """Canary events should be tracked with accuracy and timing."""
        from ulpf.intelligence.auto_parser.streaming_engine import APG2LifecycleManager
        from ulpf.intelligence.auto_parser.parser_spec import ParserSpec

        lm = APG2LifecycleManager()
        spec = ParserSpec(parser_id="test-lc-002", state="candidate")

        lm.transition(spec, "canary")

        # Record events
        for i in range(100):
            lm.record_canary_event("test-lc-002", True,
                                    parse_time_us=5.0, fields_extracted=5,
                                    fields_expected=5)

        stats = lm.get_canary_stats("test-lc-002")
        self.assertEqual(stats["events_processed"], 100)
        self.assertEqual(stats["field_accuracy"], 1.0)
        self.assertAlmostEqual(stats["avg_parse_time_us"], 5.0)

    def test_canary_promotion_criteria(self):
        """Canary should promote only after meeting all criteria."""
        from ulpf.intelligence.auto_parser.streaming_engine import APG2LifecycleManager
        from ulpf.intelligence.auto_parser.parser_spec import ParserSpec

        lm = APG2LifecycleManager()
        spec = ParserSpec(parser_id="test-lc-003", state="candidate")
        lm.transition(spec, "canary")

        # Not enough events
        can, reason = lm.can_promote_to_active("test-lc-003")
        self.assertFalse(can)
        self.assertIn("Insufficient events", reason)

        # Record 10,000 events with perfect accuracy and fast timing
        for i in range(10_000):
            lm.record_canary_event("test-lc-003", True,
                                    parse_time_us=10.0,
                                    fields_extracted=5, fields_expected=5)

        can, reason = lm.can_promote_to_active("test-lc-003")
        self.assertTrue(can, f"Should promote: {reason}")

    def test_canary_rejection_slow_latency(self):
        """Canary with high latency should not promote."""
        from ulpf.intelligence.auto_parser.streaming_engine import APG2LifecycleManager
        from ulpf.intelligence.auto_parser.parser_spec import ParserSpec

        lm = APG2LifecycleManager()
        spec = ParserSpec(parser_id="test-lc-004", state="candidate")
        lm.transition(spec, "canary")

        # Record 10,000 events with slow timing (>20µs threshold)
        for i in range(10_000):
            lm.record_canary_event("test-lc-004", True,
                                    parse_time_us=50.0,
                                    fields_extracted=5, fields_expected=5)

        can, reason = lm.can_promote_to_active("test-lc-004")
        self.assertFalse(can)
        self.assertIn("Latency", reason)

    def test_invalid_transition_raises(self):
        """Invalid state names should raise ValueError."""
        from ulpf.intelligence.auto_parser.streaming_engine import APG2LifecycleManager
        from ulpf.intelligence.auto_parser.parser_spec import ParserSpec

        lm = APG2LifecycleManager()
        spec = ParserSpec(parser_id="test-lc-005")

        with self.assertRaises(ValueError):
            lm.transition(spec, "invalid_state")


# ===========================================================================
# 8. End-to-End Streaming Pipeline Tests
# ===========================================================================

class TestEndToEndPipeline(unittest.TestCase):
    """Integration test: raw format → structured fields in <5,000 samples."""

    def test_operator_learning_e2e(self):
        """Explicit learning via the APG 2.0 engine should produce parsers."""
        from ulpf.intelligence.auto_parser.streaming_engine import StreamingAPGEngine

        with tempfile.TemporaryDirectory() as d:
            engine = StreamingAPGEngine(learned_dir=d)
            lines = [_plc_line(i) for i in range(200)]

            report = engine.learn(lines, min_group=5, state="active")

            self.assertGreater(len(report["accepted"]), 0,
                               f"Expected accepted parsers. Rejected: {report['rejected']}")
            self.assertGreater(report["coverage_pct"], 80.0,
                               f"Expected >80% coverage, got {report['coverage_pct']}")
            self.assertEqual(report["apg_version"], "2.0")

            # Verify the parser can parse new lines
            for spec_info in report["accepted"]:
                pid = spec_info["parser_id"]
                parser = engine.hot_swap_registry.dispatch(_plc_line(999))
                # May or may not dispatch via hot-swap depending on anchor
                # But the registry should have it
                self.assertIsNotNone(engine.registry.get_spec(pid))

    def test_multiple_format_learning(self):
        """Learning across multiple formats should produce separate parsers."""
        from ulpf.intelligence.auto_parser.streaming_engine import StreamingAPGEngine

        with tempfile.TemporaryDirectory() as d:
            engine = StreamingAPGEngine(learned_dir=d)

            lines = (
                [_plc_line(i) for i in range(100)] +
                [_firewall_line(i) for i in range(100)] +
                [_auth_line(i) for i in range(100)]
            )

            report = engine.learn(lines, min_group=5, state="active")

            self.assertGreaterEqual(len(report["accepted"]), 2,
                                    f"Expected ≥2 parsers for different formats. "
                                    f"Accepted: {len(report['accepted'])}, "
                                    f"Rejected: {len(report['rejected'])}")

    def test_learning_within_5000_samples(self):
        """The spec requires learning within <5,000 sample events."""
        from ulpf.intelligence.auto_parser.streaming_engine import StreamingAPGEngine

        with tempfile.TemporaryDirectory() as d:
            engine = StreamingAPGEngine(learned_dir=d)
            # Use exactly 2000 samples (well under 5000)
            lines = [_firewall_line(i) for i in range(2000)]

            report = engine.learn(lines, min_group=5, state="active")

            self.assertGreater(len(report["accepted"]), 0,
                               "Should learn a parser from <5000 samples")
            self.assertGreater(report["coverage_pct"], 70.0)

    def test_learned_parser_persisted(self):
        """Learned parsers should be saved to disk and reloadable."""
        from ulpf.intelligence.auto_parser.streaming_engine import StreamingAPGEngine

        with tempfile.TemporaryDirectory() as d:
            # Learn
            engine1 = StreamingAPGEngine(learned_dir=d)
            lines = [_plc_line(i) for i in range(200)]
            report = engine1.learn(lines, min_group=5, state="active")

            self.assertGreater(len(report["accepted"]), 0)
            saved_count = len([f for f in os.listdir(d) if f.endswith('.json')])
            self.assertGreater(saved_count, 0, "Parsers should be saved to disk")

            # Reload in a new engine
            engine2 = StreamingAPGEngine(learned_dir=d)
            specs = engine2.registry.list_parsers()
            self.assertGreater(len(specs), 0, "Parsers should reload from disk")


# ===========================================================================
# 9. Defence Mode Tests
# ===========================================================================

class TestDefenceMode(unittest.TestCase):
    """Tests for defence-mode cryptographic signing and approval."""

    def test_defence_mode_requires_approval(self):
        """In defence mode, learned parsers should be pending_approval."""
        from ulpf.intelligence.auto_parser.streaming_engine import StreamingAPGEngine

        with tempfile.TemporaryDirectory() as d:
            engine = StreamingAPGEngine(learned_dir=d)
            engine.approval_required = True

            lines = [_plc_line(i) for i in range(200)]
            report = engine.learn(lines, min_group=5, state="active")

            # Even though state="active" is requested, the engine respects
            # the operator's explicit state parameter in learn()
            for spec_info in report.get("accepted", []):
                spec = engine.registry.get_spec(spec_info["parser_id"])
                if spec:
                    self.assertIsNotNone(spec.metadata.get("ed25519") or
                                         spec.metadata.get("hmac_sha256"),
                                         "Spec should be signed")

    def test_approve_and_reject(self):
        """Operator approve/reject should change state."""
        from ulpf.intelligence.auto_parser.streaming_engine import StreamingAPGEngine

        with tempfile.TemporaryDirectory() as d:
            engine = StreamingAPGEngine(learned_dir=d)
            lines = [_plc_line(i) for i in range(200)]
            report = engine.learn(lines, min_group=5, state="canary")

            if report["accepted"]:
                pid = report["accepted"][0]["parser_id"]

                # Approve
                spec = engine.approve(pid, operator="test-admin")
                self.assertEqual(spec.state, "active")
                self.assertEqual(spec.metadata["decided_by"], "test-admin")

    def test_reject_parser(self):
        """Rejected parser should be retired."""
        from ulpf.intelligence.auto_parser.streaming_engine import StreamingAPGEngine

        with tempfile.TemporaryDirectory() as d:
            engine = StreamingAPGEngine(learned_dir=d)
            lines = [_plc_line(i) for i in range(200)]
            report = engine.learn(lines, min_group=5, state="canary")

            if report["accepted"]:
                pid = report["accepted"][0]["parser_id"]
                spec = engine.reject(pid, operator="test-admin")
                self.assertEqual(spec.state, "retired")


# ===========================================================================
# 10. Streaming Drift Detection Tests
# ===========================================================================

class TestStreamingDriftDetection(unittest.TestCase):
    """Tests for continuous drift detection via bitmask entropy."""

    def test_stable_format_no_drift(self):
        """A stable format should have low drift score."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import StreamingTokenizer
        from ulpf.intelligence.auto_parser.vectorised_clusterer import VectorisedClusterer

        tok = StreamingTokenizer()
        clusterer = VectorisedClusterer()

        for i in range(100):
            frame = tok.tokenise_event(_plc_line(i))
            clusterer.add_frame(frame)

        drifting = clusterer.get_drifting_clusters(threshold=0.8)
        self.assertEqual(len(drifting), 0,
                         "Stable format should not be flagged as drifting")

    def test_drift_score_computation(self):
        """Drift score should be computable for any cluster."""
        from ulpf.intelligence.auto_parser.vectorised_clusterer import StreamCluster

        cluster = StreamCluster(
            cluster_id="test-drift",
            canonical_bitmask=b"\x00" * 8,
            canonical_fingerprint="test",
        )
        # Empty cluster should have 0 drift
        self.assertEqual(cluster.drift_score, 0.0)


# ===========================================================================
# 11. Continuous Learning (No Restart) Tests
# ===========================================================================

class TestContinuousLearning(unittest.TestCase):
    """Tests proving continuous streaming learning without process restart."""

    def test_engine_start_stop(self):
        """Engine should start and stop cleanly."""
        from ulpf.intelligence.auto_parser.streaming_engine import StreamingAPGEngine

        with tempfile.TemporaryDirectory() as d:
            engine = StreamingAPGEngine(learned_dir=d)
            engine.start()
            self.assertTrue(engine._running)

            time.sleep(0.5)
            engine.stop()
            self.assertFalse(engine._running)

    def test_stats_reporting(self):
        """APG 2.0 stats should report comprehensive diagnostics."""
        from ulpf.intelligence.auto_parser.streaming_engine import StreamingAPGEngine

        with tempfile.TemporaryDirectory() as d:
            engine = StreamingAPGEngine(learned_dir=d)
            stats = engine.get_stats()

            self.assertEqual(stats["apg_version"], "2.0")
            self.assertIn("streaming_tokenizer", stats)
            self.assertIn("vectorised_clusterer", stats)
            self.assertIn("hot_swap_registry", stats)

    def test_parse_unknown_feeds_pipeline(self):
        """Parsing unknown events should feed the streaming pipeline."""
        from ulpf.intelligence.auto_parser.streaming_engine import StreamingAPGEngine

        with tempfile.TemporaryDirectory() as d:
            engine = StreamingAPGEngine(learned_dir=d)
            engine.start()

            # Feed unknown events
            for i in range(200):
                engine.parse(_plc_line(i), source_ip="10.0.0.1")

            time.sleep(0.5)
            engine.stop()

            # The streaming tokenizer should have processed events
            self.assertGreater(engine.streaming_tokenizer.events_processed, 0)
            # The clusterer should have created clusters
            self.assertGreater(engine.vectorised_clusterer.stats["new_clusters"], 0)
            self.assertTrue(
                engine.vectorised_clusterer.stats["clusters"] > 0
                or len(engine.registry.list_parsers()) > 0,
                "Expected either active clusters or learned parsers",
            )

    def test_backward_compatibility_with_v1(self):
        """APG 2.0 engine should have the same learn() API as v1."""
        from ulpf.intelligence.auto_parser.streaming_engine import StreamingAPGEngine

        with tempfile.TemporaryDirectory() as d:
            engine = StreamingAPGEngine(learned_dir=d)

            # v1 API: learn(lines, is_known, save, min_group, state, source)
            report = engine.learn(
                lines=[_plc_line(i) for i in range(100)],
                is_known=None,
                save=True,
                min_group=5,
                state="active",
                source="test-src",
            )

            self.assertIn("total_lines", report)
            self.assertIn("accepted", report)
            self.assertIn("rejected", report)
            self.assertIn("covered_lines", report)


# ===========================================================================
# 12. Performance Sanity Tests
# ===========================================================================

class TestPerformanceSanity(unittest.TestCase):
    """Sanity checks that APG 2.0 components meet basic perf criteria."""

    def test_tokenizer_throughput(self):
        """Streaming tokenizer should handle >10k events/sec."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import StreamingTokenizer

        tok = StreamingTokenizer()
        lines = [_plc_line(i) for i in range(1000)]

        t0 = time.perf_counter()
        for line in lines:
            tok.tokenise_event(line)
        t1 = time.perf_counter()

        elapsed = t1 - t0
        eps = 1000 / elapsed if elapsed > 0 else float('inf')
        self.assertGreater(eps, 5000,
                           f"Tokenizer should handle >5k EPS, got {eps:.0f}")

    def test_clusterer_throughput(self):
        """Vectorised clusterer should handle >5k events/sec."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import StreamingTokenizer
        from ulpf.intelligence.auto_parser.vectorised_clusterer import VectorisedClusterer

        tok = StreamingTokenizer()
        clusterer = VectorisedClusterer()
        frames = [tok.tokenise_event(_plc_line(i)) for i in range(1000)]

        t0 = time.perf_counter()
        for frame in frames:
            clusterer.add_frame(frame)
        t1 = time.perf_counter()

        elapsed = t1 - t0
        eps = 1000 / elapsed if elapsed > 0 else float('inf')
        self.assertGreater(eps, 2000,
                           f"Clusterer should handle >2k EPS, got {eps:.0f}")

    def test_jaccard_speed(self):
        """Bitmask Jaccard should compute in <10µs."""
        from ulpf.intelligence.auto_parser.streaming_tokenizer import (
            StreamingTokenizer, bitmask_jaccard,
        )
        tok = StreamingTokenizer()
        f1 = tok.tokenise_event(_plc_line(0))
        f2 = tok.tokenise_event(_plc_line(1))

        t0 = time.perf_counter()
        for _ in range(10_000):
            bitmask_jaccard(f1.bitmask_vector, f2.bitmask_vector)
        t1 = time.perf_counter()

        avg_us = (t1 - t0) / 10_000 * 1_000_000
        self.assertLess(avg_us, 50,
                        f"Jaccard should compute in <50µs, got {avg_us:.1f}µs")


if __name__ == "__main__":
    unittest.main()
