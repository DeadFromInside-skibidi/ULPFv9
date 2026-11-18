"""Phase 3: O(1) learned-parser dispatch, time-partitioned event store, split-brain-free cluster leases."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401


# ---------------------------------------------------------------------------
# Bug 5: anchor-indexed adaptive matching
# ---------------------------------------------------------------------------

def _mined(lines):
    from ulpf.intelligence.auto_parser.miners.native import NativeTemplateMiner
    return NativeTemplateMiner().mine(lines, "fp")[0]


def _format_lines(k: int, i: int) -> str:
    """Three families of formats (space, pipe and comma delimited), each with a unique literal."""
    if k % 3 == 0:
        return f"SVC{k} login user{i} from 10.0.{i % 250}.1 port {1000 + i} ok"
    if k % 3 == 1:
        return f"PUMP{k}|{i}|2026-01-0{i % 9 + 1}T00:00:00Z|OK"
    return f"2026-01-0{i % 9 + 1}T00:00:00Z,sensor{k},{i}.5,celsius"


_SPEC_CACHE: dict[int, object] = {}


def _registry(n: int):
    from ulpf.intelligence.auto_parser.registry import AutoParserRegistry
    reg = AutoParserRegistry(tempfile.mkdtemp())
    for k in range(n):
        if k not in _SPEC_CACHE:
            spec = _mined([_format_lines(k, i) for i in range(8)])
            spec.parser_id = f"auto_{k:04d}"
            spec.state = "active"
            _SPEC_CACHE[k] = spec
        reg.register(_SPEC_CACHE[k])
    return reg


def _linear(reg, line):
    for p in reg._adaptive:
        if p.pattern.match(line):
            return p
    return None


class TestAnchorIndex(unittest.TestCase):
    def test_same_answers_as_the_linear_scan(self):
        reg = _registry(60)
        self.assertGreater(sum(len(t) for t in reg._index.tables.values()), 50)    # indexed, not scanned
        lines = [_format_lines(k, 1000 + k) for k in range(60)] + [
            "nothing like any format", "SVC3 login", "PUMP4|x", "", "   ", "2026-01-01T00:00:00Z,sensor999,1.5,celsius"]
        for line in lines:
            self.assertIs(reg.get_adaptive_match(line), _linear(reg, line), line)
        self.assertEqual(reg.get_adaptive_match(_format_lines(42, 7)).parser_id, "auto_0042")

    def test_priority_state_then_own_source(self):
        from ulpf.intelligence.auto_parser.compiler import ParserCompiler
        reg = _registry(10)
        lines = [_format_lines(3, i) for i in range(8)]
        twin = _mined(lines)                     # a second parser for the same format
        twin.parser_id, twin.state = "auto_canary", "canary"
        reg.register(twin, ParserCompiler.compile(twin))
        self.assertEqual(reg.get_adaptive_match(lines[0]).parser_id, "auto_0003")   # active beats canary
        a, b = _mined(lines), _mined(lines)
        a.parser_id, b.parser_id = "auto_src_a", "auto_src_b"
        a.state = b.state = "active"
        a.metadata["learned_source"], b.metadata["learned_source"] = "10.0.0.1", "10.0.0.2"
        reg.register(a)
        reg.register(b)
        self.assertEqual(reg.get_adaptive_match(lines[0], source="10.0.0.2").parser_id, "auto_src_b")
        self.assertEqual(reg.get_adaptive_match(lines[0], source="10.0.0.1").parser_id, "auto_src_a")

    def test_lookup_cost_does_not_grow_with_parser_count(self):
        def per_call(reg, lines, fn, rounds=3):
            best = float("inf")
            for _ in range(rounds):
                t0 = time.perf_counter()
                for line in lines:
                    fn(line)
                best = min(best, (time.perf_counter() - t0) / len(lines))
            return best

        timings = {}
        for n in (1, 50, 500):
            reg = _registry(n)
            # a matching line for the newest parser, and a line nothing matches (the worst case)
            lines = [_format_lines(n - 1, 77)] * 1000 + ["kernel: eth0 link up speed 1000 duplex full"] * 1000
            for line in lines[:1] + lines[-1:]:
                self.assertIs(reg.get_adaptive_match(line), _linear(reg, line))
            timings[n] = per_call(reg, lines, reg.get_adaptive_match)
            if n == 500:
                timings["linear500"] = per_call(reg, lines, lambda l: _linear(reg, l))
        floor = max(timings[1], timings[50])
        self.assertLess(timings[500], 3 * floor + 2e-6, timings)
        self.assertLess(timings[500] * 5, timings["linear500"], timings)


# ---------------------------------------------------------------------------
# Bug 4: time-partitioned DuckDB store
# ---------------------------------------------------------------------------

def _ev(i: int) -> dict:
    return {"event_id": f"e{i:05d}", "timestamp": f"2026-01-01T00:{(i * 7) % 60:02d}:{i % 60:02d}+00:00",
            "raw_event": f"line {i}", "raw_format": "raw", "message": f"m{i}", "severity": i % 10,
            "source": {"ip": f"10.0.0.{i % 5}"}, "category": "network" if i % 2 else "auth"}


class _Clock:
    def __init__(self, db, period):
        self.period = period
        db._current_period = lambda: self.period


def _partitioned(d, **kw):
    from ulpf.storage.database import Database
    db = Database(os.path.join(d, "s.duckdb"), partition="daily", **kw)
    return db, _Clock(db, "20260101")


class TestPartitionedStore(unittest.TestCase):
    def _three_days(self, **kw):
        d = tempfile.mkdtemp(prefix="ulpf_parts_")
        db, clock = _partitioned(d, **kw)
        with db._conn_lock:
            db._maybe_rotate()
        for day, rng in (("20260101", range(0, 40)), ("20260102", range(40, 70)), ("20260103", range(70, 100))):
            clock.period = day
            db.store_events_bulk([_ev(i) for i in rng])
        return d, db, clock

    def test_queries_match_a_single_table_store(self):
        from ulpf.storage.database import Database
        d, db, _ = self._three_days()
        flat = Database(os.path.join(d, "flat.duckdb"))
        flat.store_events_bulk([_ev(i) for i in range(100)])
        self.assertGreaterEqual(len([p for p in db.partitions() if p["rows"]]), 3)
        for filters in (None, {"category": "auth"}, {"source_ip": "10.0.0.3", "severity_min": 4}, {"q": "line 7"}):
            self.assertEqual(db.count_events(filters), flat.count_events(filters), filters)
            for order in ("newest", "timestamp"):
                for limit, offset in ((10, 0), (25, 30), (7, 95), (50, 200)):
                    got = [e["event_id"] for e in db.query_events(filters, limit, offset, order_by=order)]
                    want = [e["event_id"] for e in flat.query_events(filters, limit, offset, order_by=order)]
                    self.assertEqual(got, want, (filters, order, limit, offset))
        self.assertEqual(db.get_stats()["total_events"], 100)
        self.assertEqual(db.get_event("e00005")["message"], "m5")
        self.assertEqual(len(db.get_events(["e00001", "e00050", "e00099"])), 3)
        db.close()
        flat.close()

    def test_writes_reach_only_the_active_partition_and_sealed_ones_are_read_only(self):
        d, db, _ = self._three_days()
        hot = [p for p in db.partitions() if p["state"] == "hot"]
        self.assertEqual(len(hot), 1)
        self.assertEqual(hot[0]["period"], "20260103")
        with self.assertRaises(Exception):          # sealed partitions are attached READ_ONLY
            db.conn.execute("UPDATE p_20260101.events SET message = 'x'")
        n = db.execute_on_partitions("UPDATE {events} SET message = 'edited' WHERE event_id = ?", ["e00003"],
                                     probe="event_id = ?", probe_params=["e00003"])
        self.assertEqual(n, 1)
        self.assertEqual(db.get_event("e00003")["message"], "m3")      # normalised_json keeps the original
        self.assertEqual(db.conn.execute("SELECT message FROM events WHERE event_id = 'e00003'").fetchone()[0],
                         "edited")
        db.set_correlation(["e00001", "e00045", "e00090"], "corr-x")
        self.assertEqual(db.count_events({"correlation_id": "corr-x"}), 3)
        db.close()

    def test_segments_are_ingested_once_across_a_rotation(self):
        from ulpf.runtime.sinks.duckdb_sink import encode_parquet
        d = tempfile.mkdtemp()
        db, clock = _partitioned(d)
        seg = os.path.join(d, "L-1-10-10.parquet")
        with open(seg, "wb") as f:
            f.write(encode_parquet([_ev(i) for i in range(10)]))
        self.assertEqual(db.ingest_segments([seg], ["store/L-1-10-10.parquet"]), 10)
        clock.period = "20260102"                     # crash before the buffer deleted the file; next day
        self.assertEqual(db.ingest_segments([seg], ["store/L-1-10-10.parquet"]), 0)
        self.assertEqual(db.count_events(), 10)
        db.close()

    def test_size_roll_and_whole_file_retention(self):
        d = tempfile.mkdtemp()
        db, clock = _partitioned(d, partition_max_mb=0.000001, retention_days=1)
        clock.period = "20200101"
        db.store_events_bulk([_ev(i) for i in range(5)])
        db.store_events_bulk([_ev(i) for i in range(5, 10)])          # the first file is "full"
        names = [p["name"] for p in db.partitions()]
        self.assertIn("20200101_1", names)
        clock.period = time.strftime("%Y%m%d", time.gmtime())
        files_before = set(os.listdir(db.parts_dir))
        db.partition_max_bytes = 0
        out = db.maintain()
        self.assertTrue(out["rotated"])
        self.assertGreaterEqual(out["retired"], 2)
        self.assertEqual(db.count_events(), 0)
        gone = files_before - set(os.listdir(db.parts_dir))
        self.assertTrue(any(f.startswith("events_20200101") for f in gone), gone)
        db.close()

    def test_retired_partitions_can_be_archived(self):
        for fmt, ext in (("duckdb", ".duckdb"), ("parquet", ".parquet")):
            d = tempfile.mkdtemp()
            archive = os.path.join(d, "cold")
            db, clock = _partitioned(d, archive_dir=archive, archive_format=fmt)
            clock.period = "20200101"
            db.store_events_bulk([_ev(i) for i in range(6)])
            clock.period = "20200102"
            db.store_events_bulk([_ev(i) for i in range(6, 8)])
            self.assertGreaterEqual(db.apply_retention(1), 1)
            self.assertIn(f"events_20200101{ext}", os.listdir(archive))
            if fmt == "parquet":
                import pyarrow.parquet as pq
                self.assertEqual(pq.read_table(os.path.join(archive, "events_20200101.parquet")).num_rows, 6)
            self.assertEqual(db.count_events(), 2)
            db.close()

    def test_readers_and_upgrades(self):
        from ulpf.storage.database import Database
        d, db, _ = self._three_days()
        db.close()
        ro = Database(os.path.join(d, "s.duckdb"), read_only=True)        # no option: detected
        self.assertTrue(ro.partitioned)
        self.assertEqual(ro.count_events(), 100)
        self.assertEqual(len(ro.query_events(limit=60)), 60)
        ro.close()
        legacy_dir = tempfile.mkdtemp()
        legacy = Database(os.path.join(legacy_dir, "s.duckdb"))
        legacy.store_events_bulk([_ev(i) for i in range(5)])
        legacy.close()
        up = Database(os.path.join(legacy_dir, "s.duckdb"), partition="hourly")
        up.store_events_bulk([_ev(i) for i in range(100, 103)])
        self.assertEqual([p["name"] for p in up.partitions()][0], "legacy")
        self.assertEqual([e["event_id"] for e in up.query_events(limit=4)], ["e00102", "e00101", "e00100", "e00004"])
        up.close()

    def test_defence_lockdown_still_rotates(self):
        d = tempfile.mkdtemp()
        db, clock = _partitioned(d)
        db.lock_down([d])
        clock.period = "20260202"
        db.store_events_bulk([_ev(1)])
        clock.period = "20260203"
        db.store_events_bulk([_ev(2)])
        self.assertEqual(db.count_events(), 2)
        db.close()


# ---------------------------------------------------------------------------
# Bug 7: cluster leases and fencing
# ---------------------------------------------------------------------------

def _cluster_cfg(shared: str, failover: float = 1.0) -> dict:
    return {"cluster": {"shared_dir": shared, "heartbeat_seconds": 0.1, "failover_seconds": failover,
                        "nodes": []}, "api": {"port": 0}}


class TestClusterLeases(unittest.TestCase):
    def test_liveness_ignores_wall_clocks(self):
        from ulpf.runtime.cluster import PeerView
        now = [100.0]
        view = PeerView(failover_s=5, clock=lambda: now[0])
        skewed = {"node": "b", "epoch": "x", "seq": 1, "ts": time.time() - 3600}   # clock an hour behind
        self.assertTrue(view.observe({"b": skewed})["b"])
        now[0] += 4
        skewed["seq"] = 2
        self.assertTrue(view.observe({"b": skewed})["b"])
        future = {"node": "c", "epoch": "y", "seq": 9, "ts": time.time() + 3600}   # an hour ahead, but stuck
        view.observe({"c": future})
        now[0] += 6
        self.assertFalse(view.observe({"c": future})["c"])
        self.assertFalse(view.observe({"b": {**skewed, "seq": 3, "stopped": True}})["b"])

    def test_a_live_holder_keeps_its_lease_and_handover_increments_the_token(self):
        from ulpf.runtime.cluster import Cluster, FencedError
        shared = tempfile.mkdtemp()
        a, b = Cluster(_cluster_cfg(shared), "a"), Cluster(_cluster_cfg(shared), "b")
        for c in (a, b):
            c.beat()
        for c in (a, b):
            c._alive = c.alive_nodes()
        self.assertEqual(a.acquire("okta"), 1)
        self.assertIsNone(b.acquire("okta"))                 # never taken from a live holder
        a.save_checkpoint("okta:okta", {"value": "cursor-1"}, token=1)
        a.release("okta")
        self.assertEqual(b.acquire("okta"), 2)
        b.save_checkpoint("okta:okta", {"value": "cursor-2"}, token=2)
        with self.assertRaises(FencedError):                 # the old holder cannot move the position back
            a.save_checkpoint("okta:okta", {"value": "stale"}, token=1)
        self.assertEqual(b.load_checkpoint("okta:okta")["value"], "cursor-2")
        self.assertFalse(a.holds("okta"))
        self.assertTrue(b.holds("okta"))

    def test_a_crashed_holder_is_replaced_and_finds_out(self):
        from ulpf.runtime.cluster import Cluster
        shared = tempfile.mkdtemp()
        a, b = Cluster(_cluster_cfg(shared, failover=0.3), "a"), Cluster(_cluster_cfg(shared, failover=0.3), "b")
        a.beat()
        b.beat()
        a._alive, b._alive = a.alive_nodes(), b.alive_nodes()
        self.assertEqual(a.acquire("cloudtrail"), 1)
        # a stops beating (hung or crashed); b keeps beating and sees a's seq stand still
        deadline = time.time() + 5
        while "a" in b._alive and time.time() < deadline:
            time.sleep(0.05)
            b.tick()
        self.assertNotIn("a", b._alive)
        self.assertEqual(b.acquire("cloudtrail"), 2)
        lost = []
        a.on_change = lambda: lost.append(True)
        a.tick()                                            # a comes back: its lease is gone
        self.assertTrue(lost)
        self.assertNotIn("cloudtrail", a.held)

    def test_a_node_cut_off_from_the_share_fences_itself(self):
        from ulpf.runtime.cluster import Cluster
        shared = tempfile.mkdtemp()
        a = Cluster(_cluster_cfg(shared, failover=0.4), "a")
        a.beat()
        self.assertTrue(a.owns("okta"))

        def unreachable(stopped=False):
            raise OSError("share unreachable")

        a.beat = unreachable
        a._last_beat_ok -= 1.0                               # last good write was a second ago
        self.assertTrue(a.tick())
        self.assertTrue(a.fenced)
        self.assertFalse(a.owns("okta"))
        self.assertIsNone(a.acquire("okta"))


if __name__ == "__main__":
    unittest.main()
