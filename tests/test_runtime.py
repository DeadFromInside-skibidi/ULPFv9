"""v9 runtime: config, journal, buffers, routing, views, evidence, audit, end-to-end pipeline."""
from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401

from ulpf.config import ConfigError, describe, load_pipeline_config  # noqa: E402


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def read_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_bytes(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


def count_lines(directory: str) -> int:
    n = 0
    for name in os.listdir(directory):
        with open(os.path.join(directory, name), "rb") as f:
            n += sum(1 for _ in f)
    return n


def wait_for(pred, timeout=60.0, step=0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(step)
    return False


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class TestPipelineConfig(unittest.TestCase):
    def test_unknown_key_reports_line_number(self):
        text = "mode: industry\noutputs:\n  - type: duckdb\n    name: store\n    pth: x\n"
        with self.assertRaises(ConfigError) as cm:
            load_pipeline_config(text=text)
        msg = str(cm.exception)
        self.assertIn("line 5", msg)
        self.assertIn("outputs[0].pth", msg)
        self.assertIn("did you mean 'path'", msg)

    def test_type_and_reference_errors_are_all_reported(self):
        text = ("workers: 2\ninputs:\n  - {type: syslog, name: a, port: notaport}\n"
                "outputs:\n  - {type: duckdb, name: store}\nroutes:\n  - {name: r, to: [nowhere]}\n")
        with self.assertRaises(ConfigError) as cm:
            load_pipeline_config(text=text)
        msg = str(cm.exception)
        self.assertIn("inputs[0].port", msg)
        self.assertIn("no output named 'nowhere'", msg)

    def test_mode_defaults(self):
        d = load_pipeline_config(data={"mode": "defence", "outputs": [{"type": "duckdb", "name": "s"}],
                                       "inputs": []})
        self.assertTrue(d.get("journal.encrypt"))
        self.assertEqual(d.get("journal.sync"), "always")
        self.assertEqual(d.get("journal.retention_days"), 180)
        self.assertTrue(d.get("learning.approval_required"))
        i = load_pipeline_config(data={"outputs": [{"type": "duckdb", "name": "s"}]})
        self.assertFalse(i.get("journal.encrypt"))
        self.assertFalse(i.get("learning.approval_required"))

    def test_defence_rules_and_waivers(self):
        base = {"mode": "defence", "outputs": [{"type": "duckdb", "name": "s"}],
                "inputs": [{"type": "syslog", "name": "udp", "protocol": "udp", "port": 5514},
                           {"type": "okta", "name": "okta", "domain": "x.okta.com", "token_env": "T"}]}
        with self.assertRaises(ConfigError) as cm:
            load_pipeline_config(data=json.loads(json.dumps(base)))
        msg = str(cm.exception)
        self.assertIn("defence.tls_listeners", msg)
        self.assertIn("defence.no_cloud", msg)
        self.assertIn("defence.allowlist", msg)
        waived = dict(base, inputs=base["inputs"][:1], overrides=["defence.tls_listeners"])
        cfg = load_pipeline_config(data=waived)
        self.assertEqual(len(cfg.waived), 1)
        self.assertIn("defence.tls_listeners", describe(cfg)["waived_rules"][0])

    def test_allowlist_permits_named_destinations(self):
        cfg = {"mode": "defence", "airgap": {"allow": ["10.0.0.0/8"]},
               "outputs": [{"type": "duckdb", "name": "s"},
                           {"type": "syslog", "name": "fw", "host": "10.1.2.3", "protocol": "tls"}]}
        report = describe(load_pipeline_config(data=cfg))
        self.assertEqual(report["remote_destinations"], ["fw -> 10.1.2.3"])
        cfg["outputs"][1]["host"] = "203.0.113.9"
        with self.assertRaises(ConfigError):
            load_pipeline_config(data=cfg)

    def test_example_config_is_valid(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "config", "pipeline.example.yaml")
        cfg = load_pipeline_config(path)
        self.assertEqual(cfg.mode, "industry")
        self.assertIn("store", describe(cfg)["outputs"])


# ---------------------------------------------------------------------------
# Journal
# ---------------------------------------------------------------------------

class TestJournal(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _journal(self, **kw):
        from ulpf.runtime.journal import Journal
        return Journal(self.dir, **kw)

    def test_append_read_iterate(self):
        import hashlib
        j = self._journal(sync="always")
        first, digests = j.append("10.0.0.1", "syslog", [b"one", b"two \xff bytes", b"three"])
        self.assertEqual(first, 1)
        self.assertEqual(digests[1], hashlib.sha256(b"two \xff bytes").digest())
        j.append("10.0.0.2", "syslog", [b"four"])
        rec = j.read(2)
        self.assertEqual(rec.raw, b"two \xff bytes")      # exact bytes, not decoded text
        self.assertEqual((rec.source, rec.input), ("10.0.0.1", "syslog"))
        self.assertIsNone(j.read(99))
        self.assertEqual([r.seq for b in j.iter_from(3) for r in b], [3, 4])
        j.close()
        j2 = self._journal()
        self.assertEqual(j2.next_seq, 5)
        self.assertEqual(j2.read(4).raw, b"four")
        j2.close()

    def test_encryption_at_rest(self):
        from ulpf.runtime.journal import Journal, JournalCorruption
        key = os.urandom(32)
        j = self._journal(key=key, sync="always")
        j.append("s", "i", [b"secret password=hunter2"])
        j.close()
        blob = b"".join(read_bytes(os.path.join(self.dir, n))
                        for n in os.listdir(self.dir) if n.endswith(".ulj"))
        self.assertNotIn(b"hunter2", blob)
        self.assertEqual(Journal(self.dir, key=key).read(1).raw, b"secret password=hunter2")
        with self.assertRaises(JournalCorruption):
            Journal(self.dir, read_only=True).read(1)    # no key

    def test_torn_tail_is_truncated_on_recovery(self):
        j = self._journal(sync="always")
        j.append("s", "i", [b"a", b"b"])
        j.append("s", "i", [b"c"])
        seg = os.path.join(self.dir, sorted(n for n in os.listdir(self.dir) if n.endswith(".ulj"))[-1])
        j._fh.close()
        j._fh = None
        with open(seg, "ab") as f:
            f.write(b"ULJB\x01\x00garbage-from-a-crash")
        j2 = self._journal()
        self.assertEqual(j2.next_seq, 4)
        self.assertEqual(j2.read(3).raw, b"c")
        j2.append("s", "i", [b"d"])
        self.assertEqual(j2.read(4).raw, b"d")
        j2.close()

    def test_altered_bytes_are_detected(self):
        from ulpf.runtime.journal import JournalCorruption
        j = self._journal(sync="always")
        j.append("s", "i", [b"original line"])
        j.append("s", "i", [b"a later record"])
        j.set_committed(2)
        j.close()
        seg = os.path.join(self.dir, next(n for n in os.listdir(self.dir) if n.endswith(".ulj")))
        data = bytearray(read_bytes(seg))
        data[data.find(b"original")] = ord("O")
        write_bytes(seg, bytes(data))
        with self.assertRaises(JournalCorruption):
            self._journal(read_only=True)
        with self.assertRaises(JournalCorruption):
            self._journal()          # the writer refuses to "repair" (truncate) evidence

    def test_losing_committed_records_is_detected(self):
        from ulpf.runtime.journal import JournalCorruption
        j = self._journal(sync="always")
        j.append("s", "i", [b"one"])
        j.append("s", "i", [b"two"])
        j.set_committed(2)
        j.close()
        seg = os.path.join(self.dir, next(n for n in os.listdir(self.dir) if n.endswith(".ulj")))
        data = read_bytes(seg)
        write_bytes(seg, data[:len(data) - 5])      # truncate the committed last block
        with self.assertRaises(JournalCorruption):
            self._journal()

    def test_retention_only_removes_committed_segments(self):
        j = self._journal(segment_bytes=200, retention_days=1)
        for n in range(10):
            j.append("s", "i", [b"x" * 100])
        segs = len(j._segments)
        self.assertGreater(segs, 3)
        old = time.time() - 3 * 86400
        for n in os.listdir(self.dir):
            os.utime(os.path.join(self.dir, n), (old, old))
        self.assertEqual(j.sweep(), 0)                 # nothing committed yet
        j.set_committed(5)
        removed = j.sweep()
        self.assertGreater(removed, 0)
        self.assertIsNone(j.read(1))
        self.assertIsNotNone(j.read(10))
        j.close()


# ---------------------------------------------------------------------------
# Buffers, tracker, routing, views
# ---------------------------------------------------------------------------

class TestBufferAndRouting(unittest.TestCase):
    def test_buffer_exactly_once_names_and_watermark(self):
        from ulpf.runtime.buffer import DiskBuffer
        b = DiskBuffer(tempfile.mkdtemp(), 10_000)
        n = b.log_name(1, 10, 10)
        b.write(n, b"x" * 100)
        b.write(n, b"y" * 100)                       # replay: same name, kept once
        self.assertEqual(len(b.segments()), 1)
        self.assertEqual(read_bytes(b.segments()[0].path), b"x" * 100)
        b.write(b.log_name(11, 20, 10), b"z")
        b.write_derived(b"d", 1)
        self.assertEqual([s.to_seq for s in b.ready(10) if s.kind == "L"], [10])
        self.assertEqual(len(b.ready(10)), 2)          # derived segments are always ready
        for s in b.ready(10):
            b.ack(s)
        self.assertEqual([s.from_seq for s in b.segments()], [11])

    def test_buffer_full_block_and_drop_oldest(self):
        from ulpf.runtime.buffer import BufferFull, DiskBuffer
        blk = DiskBuffer(tempfile.mkdtemp(), 250, "block")
        blk.write(blk.log_name(1, 1, 5), b"a" * 200)
        with self.assertRaises(BufferFull):
            blk.write(blk.log_name(2, 2, 5), b"b" * 200, timeout=0.3)
        drop = DiskBuffer(tempfile.mkdtemp(), 250, "drop_oldest")
        drop.write(drop.log_name(1, 1, 7), b"a" * 200)
        dropped = drop.write(drop.log_name(2, 2, 3), b"b" * 200)
        self.assertEqual(dropped, 7)
        self.assertEqual(drop.stats()["dropped_events"], 7)
        self.assertEqual([s.from_seq for s in drop.segments()], [2])

    def test_commit_tracker_out_of_order(self):
        from ulpf.runtime.dispatch import CommitTracker
        t = CommitTracker()
        t.register(1, 10)
        t.register(11, 5)
        t.register(16, 4)
        t.complete(11)
        self.assertEqual(t.committed, 0)
        t.complete(1)
        self.assertEqual(t.committed, 15)
        t.complete(16)
        self.assertEqual(t.committed, 19)

    def test_router(self):
        from ulpf.runtime.router import Router
        r = Router([{"name": "hi", "when": {"severity_gte": 7, "category_in": ["firewall"]}, "to": ["siem"]},
                    {"name": "seals", "when": {"kind_in": ["seal"]}, "to": ["siem", "store"], "final": True},
                    {"name": "all", "when": {"field_exists": ["source.ip"]}, "to": ["store"]}], "store")
        ev = {"event_kind": "log", "severity": 8, "category": "firewall", "source": {"ip": "1.2.3.4"}}
        self.assertEqual(r.targets(ev), ["siem", "store"])
        self.assertEqual(r.targets({"event_kind": "seal"}), ["siem", "store"])
        self.assertEqual(r.targets({"event_kind": "log", "severity": 1}), ["store"])   # default
        self.assertEqual(r.unrouted, 1)
        self.assertEqual(Router([], "").targets({"event_kind": "log"}), [])           # "" drops

    def test_ecs_and_ocsf_views(self):
        from ulpf.engine.pipeline import Pipeline
        from ulpf.engine.views import to_ecs, to_ocsf
        p = Pipeline(enable_auto_parser=False)
        ev = p.process_line("CEF:0|Palo Alto|PAN-OS|10.1|traffic|Connection blocked|8|"
                            "src=10.1.1.5 dst=8.8.8.8 spt=51234 dpt=53 proto=UDP act=blocked suser=alice")["event"]
        ecs = to_ecs(ev)
        self.assertEqual(ecs["source"]["ip"], "10.1.1.5")
        self.assertEqual(ecs["destination"]["port"], 53)
        self.assertEqual(ecs["event"]["outcome"], "failure")
        self.assertEqual(ecs["event"]["original"], ev["raw_event"])
        self.assertEqual(ecs["observer"]["vendor"], "Palo Alto")
        self.assertEqual(ecs["user"]["name"], "alice")
        oc = to_ocsf(ev)
        self.assertEqual(oc["class_uid"], 4001)
        self.assertEqual(oc["activity_id"], 5)            # refused
        self.assertEqual(oc["type_uid"], 400105)
        self.assertEqual(oc["severity_id"], 4)
        self.assertEqual(oc["dst_endpoint"]["ip"], "8.8.8.8")
        self.assertEqual(oc["raw_data"], ev["raw_event"])
        self.assertEqual(oc["metadata"]["uid"], ev["event_id"])


# ---------------------------------------------------------------------------
# Evidence and audit
# ---------------------------------------------------------------------------

class TestEvidenceAndAudit(unittest.TestCase):
    def test_seals_verify_and_detect_tampering(self):
        from ulpf.runtime.evidence import (Sealer, inclusion_proof, leaf, load_seals, verify_proof,
                                           verify_seals)
        from ulpf.runtime.journal import Journal
        d = tempfile.mkdtemp()
        j = Journal(os.path.join(d, "journal"), sync="always")
        key = os.urandom(32)
        sealer = Sealer(os.path.join(d, "evidence", "seals"), "node-t", 50, 3600, key=key)
        j.add_listener(sealer.on_append)
        for i in range(12):
            j.append("src", "in", [f"line {i}-{k}".encode() for k in range(10)])
        while sealer.seal_now("test"):
            pass
        seals_dir = os.path.join(d, "evidence", "seals")
        seals = load_seals(seals_dir)
        self.assertEqual(sum(s["count"] for s in seals), 120)
        self.assertTrue(verify_seals(seals_dir, j, key)["valid"])
        # inclusion proof for record 57
        s = next(s for s in seals if s["first_seq"] <= 57 <= s["last_seq"])
        leaves = [leaf(q, j.read(q).sha256) for q in range(s["first_seq"], s["last_seq"] + 1)]
        proof = inclusion_proof(leaves, 57 - s["first_seq"])
        self.assertTrue(verify_proof(leaves[57 - s["first_seq"]], proof, s["merkle_root"]))
        # edited seal file
        path = os.path.join(seals_dir, sorted(n for n in os.listdir(seals_dir) if n.startswith("seal-"))[1])
        doc = read_json(path)
        doc["count"] += 1
        write_bytes(path, json.dumps(doc).encode())
        res = verify_seals(seals_dir, j, key)
        self.assertFalse(res["valid"])
        self.assertTrue(any("does not match its hash" in p for p in res["problems"]))
        sealer.close()
        j.close()

    def test_audit_log_chain(self):
        from ulpf.runtime.audit import AuditLog, verify_audit_log
        path = os.path.join(tempfile.mkdtemp(), "audit.log")
        log = AuditLog(path)
        for i in range(5):
            log.record("test.action", {"i": i}, actor="tester")
        ok = verify_audit_log(path)
        self.assertTrue(ok["valid"])
        self.assertEqual(ok["entries"], 5)
        lines = read_bytes(path).decode().splitlines()
        e = json.loads(lines[2])
        e["details"]["i"] = 99
        lines[2] = json.dumps(e, sort_keys=True)
        write_bytes(path, ("\n".join(lines) + "\n").encode())
        r = verify_audit_log(path)
        self.assertFalse(r["valid"])
        self.assertEqual(r["broken_at_line"], 3)


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------

LINES = [l for l in read_bytes(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                            "demo_data", "mixed_formats.log")).splitlines()
         if l.strip() and not l.startswith(b"#")]


def runtime_config(data_dir: str, port: int, **extra) -> dict:
    cfg = {
        "workers": 1, "node": {"data_dir": data_dir},
        "inputs": [{"type": "syslog", "name": "tcp", "protocol": "tcp", "host": "127.0.0.1", "port": port}],
        "outputs": [{"type": "duckdb", "name": "store", "path": os.path.join(data_dir, "store.duckdb")},
                    {"type": "file", "name": "archive", "path": os.path.join(data_dir, "archive"), "view": "ocsf"}],
        "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["store", "archive"]},
                   {"name": "derived", "when": {"kind_in": ["seal", "correlation", "anomaly", "drift"]},
                    "to": ["store"]}],
        "evidence": {"seal_every_events": 200, "seal_every_seconds": 1},
        "api": {"enabled": False},
    }
    cfg.update(extra)
    return cfg


class TestRuntimeEndToEnd(unittest.TestCase):
    def test_tcp_to_store_and_archive_with_evidence(self):
        from ulpf.runtime.evidence import verify_seals
        from ulpf.runtime.supervisor import Runtime
        d = tempfile.mkdtemp(prefix="ulpf_rt_")
        port = free_port()
        rt = Runtime(load_pipeline_config(data=runtime_config(d, port))).start()
        n = 1000
        payload = b"\n".join((LINES * 100)[:n]) + b"\n"
        with socket.create_connection(("127.0.0.1", port)) as s:
            s.sendall(payload)
        self.assertTrue(wait_for(lambda: rt.runners["archive"].delivered_events >= n))
        summary = rt.stop()
        self.assertEqual(summary["journal"]["next_seq"], n + 1)
        self.assertEqual(summary["committed_seq"], n)
        from ulpf.storage.database import Database
        db = Database(os.path.join(d, "store.duckdb"), read_only=True)
        kinds = dict(db.conn.execute("SELECT json_extract_string(normalised_json, '$.event_kind'), "
                                     "COUNT(*) FROM events GROUP BY 1").fetchall())
        self.assertEqual(kinds["log"], n)
        self.assertGreaterEqual(kinds.get("seal", 0), n // 200)
        self.assertEqual(count_lines(os.path.join(d, "archive")), n)
        from ulpf.runtime.journal import Journal
        # Seals are Ed25519-signed: a verifier needs only the public key (evidence.pub), no secret
        res = verify_seals(os.path.join(d, "evidence", "seals"),
                           Journal(os.path.join(d, "journal"), read_only=True), None, database=db)
        self.assertTrue(res["valid"], res["problems"][:3])
        self.assertTrue(res["anchor_pinned"])
        self.assertGreaterEqual(res["signatures_checked"], n // 200)
        self.assertFalse(os.path.exists(os.path.join(d, "evidence", "evidence.key")))
        self.assertEqual(res["events_checked"], n)
        db.close()

    def test_uncommitted_journal_is_replayed_exactly_once(self):
        """Crash after journaling, before processing: restart replays; a second restart adds nothing."""
        from ulpf.runtime.journal import Journal
        from ulpf.runtime.supervisor import Runtime
        d = tempfile.mkdtemp(prefix="ulpf_rt_")
        j = Journal(os.path.join(d, "journal"), sync="always")
        hundred = (LINES * 10)[:100]
        for _ in range(3):
            j.append("10.9.9.9", "tcp", hundred)
        j.close()                                   # committed_seq stays 0: nothing processed
        cfg = runtime_config(d, free_port(), evidence={"enabled": False},
                             analytics={"correlation": {"enabled": False}})
        for _ in range(2):
            rt = Runtime(load_pipeline_config(data=cfg)).start()
            wait_for(lambda: rt.persisted_committed >= 300 and not rt.buffers["store"].segments(), 60)
            rt.stop()
        from ulpf.storage.database import Database
        db = Database(os.path.join(d, "store.duckdb"), read_only=True)
        total, distinct = db.conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT event_id) FROM events "
            "WHERE json_extract_string(normalised_json, '$.event_kind') = 'log'").fetchone()
        db.close()
        self.assertEqual((total, distinct), (300, 300))

    def test_failed_input_is_restarted(self):
        from ulpf.runtime.supervisor import Runtime
        d = tempfile.mkdtemp(prefix="ulpf_rt_")
        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        port = blocker.getsockname()[1]
        cfg = runtime_config(d, free_port(), evidence={"enabled": False})
        cfg["inputs"].append({"type": "syslog", "name": "clash", "protocol": "tcp",
                              "host": "127.0.0.1", "port": port})   # port already taken
        rt = Runtime(load_pipeline_config(data=cfg)).start()
        try:
            restarted = wait_for(lambda: rt.inputs["clash"].stats.restarts >= 1, 20)
            if not restarted and rt.inputs["clash"].stats.errors == 0:
                self.skipTest("platform allowed a second bind on the same port")
            self.assertTrue(restarted)
            self.assertIn("Error", rt.inputs["clash"].stats.last_error)
        finally:
            rt.stop()
            blocker.close()


if __name__ == "__main__":
    unittest.main()
