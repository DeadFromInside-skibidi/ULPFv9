"""
Core correctness suite: engine, parsers, storage, intelligence, ingestion, API.

    python -m unittest tests.test_core -v
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import tests._isolation  # noqa: E402,F401

from ulpf.engine.pipeline import Pipeline  # noqa: E402

PIPELINE = Pipeline()


def parse(line: str) -> dict:
    res = PIPELINE.process_line(line)
    assert res["success"], res
    return res["event"]


class TestSchemaAndNormalizer(unittest.TestCase):
    def test_schema_definition_is_complete(self):
        from ulpf.engine.schema import SCHEMA_DEFINITION, new_unified_event
        self.assertGreaterEqual(SCHEMA_DEFINITION["field_count"], 65)
        names = {f["name"] for g in SCHEMA_DEFINITION["groups"] for f in g["fields"]}
        event = new_unified_event()

        def leaves(d, prefix=""):
            for k, v in d.items():
                if isinstance(v, dict) and v and k not in ("parsed_fields", "extensions"):
                    yield from leaves(v, f"{prefix}{k}.")
                else:
                    yield f"{prefix}{k}"
        undocumented = set(leaves(event)) - names
        self.assertEqual(undocumented, set(), "every event field must be documented")

    def test_event_ids_are_unique_uuid4(self):
        import uuid
        from ulpf.engine.schema import new_uuid
        ids = {new_uuid() for _ in range(10000)}
        self.assertEqual(len(ids), 10000)
        self.assertEqual(uuid.UUID(next(iter(ids))).version, 4)

    def test_severity_labels_cover_0_to_10(self):
        from ulpf.engine.normalizer import normalize_severity
        self.assertEqual(normalize_severity("10", "cef"), (10, "critical"))
        self.assertEqual(normalize_severity("7", "cef"), (7, "high"))
        self.assertEqual(normalize_severity("5"), (5, "medium"))
        self.assertEqual(normalize_severity("high"), (7, "high"))
        self.assertEqual(normalize_severity("0", "syslog"), (10, "critical"))   # emergency
        self.assertEqual(normalize_severity("6", "syslog"), (1, "info"))
        self.assertEqual(normalize_severity("7.6"), (8, "high"))
        self.assertEqual(normalize_severity(None), (0, "unknown"))

    def test_timestamps_are_converted_to_utc(self):
        from ulpf.engine.normalizer import normalize_timestamp
        self.assertEqual(normalize_timestamp("2024-08-28T15:45:01+05:30")[0], "2024-08-28T10:15:01+00:00")
        self.assertEqual(normalize_timestamp("2024-08-28T10:15:01Z")[0], "2024-08-28T10:15:01+00:00")
        self.assertEqual(normalize_timestamp("1724840101")[0], "2024-08-28T10:15:01+00:00")
        self.assertEqual(normalize_timestamp("1724840101000")[0], "2024-08-28T10:15:01+00:00")
        self.assertEqual(normalize_timestamp("28/Aug/2024:12:15:01 +0200")[0], "2024-08-28T10:15:01+00:00")
        ts, orig = normalize_timestamp("not a time")
        self.assertEqual(orig, "not a time", "unparseable originals are preserved")

    def test_yearless_syslog_never_lands_in_the_future(self):
        from ulpf.engine.normalizer import normalize_timestamp
        future = datetime.now(timezone.utc) + timedelta(days=40)
        ts, _ = normalize_timestamp(future.strftime("%b %d %H:%M:%S"))
        self.assertLess(datetime.fromisoformat(ts), datetime.now(timezone.utc) + timedelta(days=1))

    def test_compound_vendor_actions(self):
        from ulpf.engine.normalizer import normalize_action
        self.assertEqual(normalize_action("allow-url"), "allowed")
        self.assertEqual(normalize_action("client-rst"), "reset")
        self.assertEqual(normalize_action("Accept"), "allowed")
        self.assertEqual(normalize_action("DENY"), "denied")
        self.assertEqual(normalize_action("timeout"), "disconnected")
        self.assertEqual(normalize_action("weird"), "other")

    def test_raw_hash_is_sha256_of_raw_line(self):
        line = "CEF:0|Vendor|FW|1.0|100|Blocked|5|src=10.0.0.1 dst=10.0.0.2"
        ev = parse(line)
        digest = hashlib.sha256(line.encode()).hexdigest()
        self.assertEqual(ev["evidence"]["raw_hash"], digest)
        self.assertEqual(ev["metadata"]["raw_hash_sha256"], digest)


class TestParsers(unittest.TestCase):
    def test_cef_escaping_and_labels(self):
        ev = parse(r"CEF:0|Acme|Gate\|Pro|2.1|42|Blocked URL|8|src=10.1.1.1 dst=10.2.2.2 "
                   r"request=http://x.test/a?b=1&c=2 msg=user said a\=b cs1=Corp_Web cs1Label=RuleName act=allow-url")
        self.assertEqual(ev["device"]["product"], "Gate|Pro")
        self.assertEqual(ev["parsed_fields"]["request"], "http://x.test/a?b=1&c=2")
        self.assertEqual(ev["parsed_fields"]["msg"], "user said a=b")
        self.assertEqual(ev["parsed_fields"]["RuleName"], "Corp_Web")
        self.assertEqual(ev["rule"]["name"], "Corp_Web")
        self.assertEqual(ev["action"], "allowed")
        self.assertEqual(ev["severity_label"], "high")

    def test_leef2_custom_delimiter(self):
        ev = parse("LEEF:2.0|Lancope|StealthWatch|1.0|41|^|src=10.0.1.8^dst=10.0.0.5^sev=5^srcPort=3245^dstPort=443")
        self.assertEqual(ev["source"]["ip"], "10.0.1.8")
        self.assertEqual(ev["destination"]["port"], 443)
        self.assertEqual(ev["severity"], 5)
        ev = parse("LEEF:2.0|Vendor|Prod|1.0|7|x5E|src=1.1.1.1^dst=2.2.2.2")
        self.assertEqual(ev["destination"]["ip"], "2.2.2.2")

    def test_w3c_fields_directive_is_honoured(self):
        text = ("#Software: TestProxy\n#Fields: date time cs-method s-ip c-ip sc-status\n"
                "2024-08-28 10:15:01 GET 203.0.113.50 192.168.1.100 403\n")
        results = PIPELINE.process_text(text)
        headers = [r for r in results if r.get("skipped")]
        events = [r["event"] for r in results if r.get("success")]
        self.assertEqual(len(headers), 2)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["source"]["ip"], "192.168.1.100")
        self.assertEqual(events[0]["destination"]["ip"], "203.0.113.50")
        self.assertEqual(events[0]["action"], "denied")

    def test_csv_header_is_not_stored_as_event(self):
        text = "timestamp,src_ip,dst_ip,action,severity\n2024-08-28T10:00:00Z,10.0.0.1,10.0.0.2,deny,7\n"
        results = PIPELINE.process_text(text)
        self.assertTrue(results[0].get("header"))
        ev = results[1]["event"]
        self.assertEqual(ev["source"]["ip"], "10.0.0.1")
        self.assertEqual(ev["action"], "denied")
        self.assertEqual(ev["severity"], 7)

    def test_xml_rejects_entities(self):
        res = PIPELINE.process_line('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>')
        self.assertEqual(res["event"]["raw_format"], "raw_fallback")

    def test_windows_event_data_names(self):
        ev = parse("<Event><System><EventID>4625</EventID><Computer>DC01</Computer>"
                   "<TimeCreated SystemTime='2026-09-30T10:00:00Z'/></System><EventData>"
                   "<Data Name='TargetUserName'>bob</Data><Data Name='IpAddress'>10.9.9.9</Data>"
                   "</EventData></Event>")
        self.assertEqual(ev["user"]["name"], "bob")
        self.assertEqual(ev["source"]["ip"], "10.9.9.9")
        self.assertEqual(ev["device"]["hostname"], "DC01")

    def test_ecs_style_json_paths(self):
        ev = parse('{"@timestamp":"2026-01-01T00:00:00Z","source":{"ip":"1.2.3.4","port":5555},'
                   '"destination":{"ip":"5.6.7.8"},"user":{"name":"eve"},"event":{"action":"deny"}}')
        self.assertEqual(ev["source"]["ip"], "1.2.3.4")
        self.assertEqual(ev["source"]["port"], 5555)
        self.assertEqual(ev["user"]["name"], "eve")

    def test_nothing_is_dropped(self):
        ev = parse("totally free text that matches nothing at all 10.0.0.9")
        self.assertEqual(ev["raw_format"], "raw_fallback")
        self.assertEqual(ev["source"]["ip"], "10.0.0.9")


class TestStorage(unittest.TestCase):
    def setUp(self):
        from ulpf.storage.database import Database
        self.db = Database(os.path.join(tempfile.mkdtemp(), "t.duckdb"))

    def tearDown(self):
        self.db.close()

    def test_roundtrip_is_lossless(self):
        ev = parse("CEF:0|V|P|1|1|n|3|src=10.0.0.1 dst=10.0.0.2 spt=1 dpt=2 msg=hello")
        self.assertEqual(self.db.store_events_bulk([ev]), 1)
        self.assertEqual(self.db.get_event(ev["event_id"]), json.loads(json.dumps(ev, default=str)))

    def test_filters_search_count_reset_purge(self):
        events = [parse(f"CEF:0|V|P|1|1|n|{s}|src=10.0.0.{s} dst=10.0.0.99") for s in range(10)]
        events.append(parse("free text no structure"))
        self.db.store_events_bulk(events)
        self.assertEqual(self.db.count_events(), 11)
        self.assertEqual(self.db.count_events({"severity_min": 7}), 3)
        self.assertEqual(len(self.db.search_events("10.0.0.5")), 1)
        self.assertEqual(len(self.db.search_events("FREE TEXT")), 1, "search is case-insensitive")
        self.assertEqual(self.db.query_events(limit=1)[0]["event_id"], events[-1]["event_id"], "newest first")
        self.assertEqual(self.db.purge_raw_fallback(), 1)
        self.assertEqual(self.db.get_stats()["total_events"], 10)
        self.db.reset_database()
        self.assertEqual(self.db.count_events(), 0)
        self.assertEqual(self.db.store_events_bulk(events[:2]), 2, "store usable after reset")

    def test_retention_purge(self):
        old = parse("CEF:0|V|P|1|1|n|3|src=10.0.0.1 rt=2020-01-01T00:00:00Z")
        new = parse("CEF:0|V|P|1|1|n|3|src=10.0.0.2")
        self.db.store_events_bulk([old, new])
        self.assertEqual(self.db.purge_older_than(365, by="timestamp"), 1)
        self.assertEqual(self.db.count_events(), 1)
        self.assertEqual(self.db.purge_older_than(1), 0, "nothing ingested more than a day ago")

    def test_string_ports_do_not_break_bulk_insert(self):
        ev = parse("CEF:0|V|P|1|1|n|3|src=10.0.0.1")
        ev["source"]["port"] = "not-a-port"
        ev["destination"]["port"] = "99999999999"
        self.assertEqual(self.db.store_events_bulk([ev]), 1)

    def test_read_only_store_refuses_writes(self):
        from ulpf.storage.database import Database, DatabaseLockedError
        path = self.db.db_path
        self.db.close()
        ro = Database(path, read_only=True)
        with self.assertRaises(DatabaseLockedError):
            ro.store_events_bulk([parse("x y z")])
        ro.close()
        self.db = Database(path)


class TestForensics(unittest.TestCase):
    def setUp(self):
        from ulpf.intelligence.forensic import ForensicBuilder
        self.dir = tempfile.mkdtemp()
        self.builder = ForensicBuilder(self.dir)
        self.events = [parse(f"CEF:0|V|P|1|1|n|5|src=10.0.0.{i} dst=10.0.0.200") for i in range(7)]

    def test_chain_merkle_and_tamper_detection(self):
        from ulpf.intelligence.forensic import merkle_proof, verify_merkle_proof
        chain = self.builder.build_from_events(self.events, "t")
        self.assertTrue(chain.verify_integrity()["valid"])
        leaves = [i.leaf for i in chain.items]
        self.assertTrue(verify_merkle_proof(leaves[3], merkle_proof(leaves, 3), chain.merkle_root))
        chain.items[2].event["severity"] = 0          # tamper with a normalised field
        self.assertEqual(chain.verify_integrity()["type"], "normalised_hash_mismatch")

    def test_exported_package_verifies_and_detects_edits(self):
        from ulpf.intelligence.forensic import verify_package
        chain = self.builder.build_from_events(self.events, "export")
        path = self.builder.export_package(chain.chain_id)
        self.assertTrue(verify_package(path)["valid"])
        with open(path, encoding="utf-8") as f:
            pkg = json.load(f)
        pkg["raw_events"][1]["raw_event"] += " edited"
        tampered = path.replace(".json", "_t.json")
        with open(tampered, "w", encoding="utf-8") as f:
            json.dump(pkg, f)
        result = verify_package(tampered)
        self.assertFalse(result["valid"])
        self.assertTrue(any("raw event altered" in p for p in result["problems"]))

    def test_chains_and_custody_survive_restart(self):
        from ulpf.intelligence.forensic import ForensicBuilder
        chain = self.builder.build_from_events(self.events, "persist")
        reloaded = ForensicBuilder(self.dir)
        self.assertIn(chain.chain_id, reloaded.chains)
        self.assertTrue(reloaded.verify_chain(chain.chain_id)["valid"])
        self.assertGreaterEqual(len(reloaded.get_custody_log(chain.chain_id)), 2)


class TestCorrelationAndAnomaly(unittest.TestCase):
    def test_related_events_form_one_group(self):
        from ulpf.intelligence.correlation import EventCorrelator
        c = EventCorrelator(60)
        evs = [parse(f"CEF:0|V|IDS|1|1|SCAN nmap probe|4|src=45.33.32.156 dst=10.0.0.{i} "
                     f"rt=2026-01-01T00:00:{i:02d}Z") for i in range(5)]
        evs.append(parse("CEF:0|V|IDS|1|2|ET EXPLOIT SQL Injection|9|src=45.33.32.156 dst=10.0.0.1 "
                         "rt=2026-01-01T00:00:30Z"))
        for e in evs:
            c.add_and_correlate(e)
        groups = c.get_results()
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["event_count"], 6)
        self.assertEqual(groups[0]["kill_chain_stages"][:2], ["reconnaissance", "exploitation"])

    def test_window_separates_and_memory_is_bounded(self):
        from ulpf.intelligence.correlation import EventCorrelator
        c = EventCorrelator(10, max_groups=50)
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(20000):
            ev = {"event_id": str(i), "timestamp": (base + timedelta(seconds=i * 20)).isoformat(),
                  "source": {"ip": f"10.0.{i % 200}.1"}, "destination": {"ip": "10.9.9.9"}, "severity": 1}
            c.add_and_correlate(ev)
        self.assertLessEqual(len(c.groups), 50)
        self.assertLess(len(c._keys), 1000)

    def test_low_entropy_only_for_high_severity_bursts(self):
        from ulpf.intelligence.anomaly import AnomalyDetector
        d = AnomalyDetector()
        routine = [{"severity": 1, "source": {}, "destination": {}} for _ in range(50)]
        self.assertFalse(any(a["type"] == "low_entropy" for a in d.analyse_batch(routine)))
        attack = [{"severity": 9, "source": {}, "destination": {}} for _ in range(50)]
        self.assertTrue(any(a["type"] == "low_entropy" for a in d.analyse_batch(attack)))


class TestAutoParser(unittest.TestCase):
    def test_learned_parser_generalises_to_other_days_and_values(self):
        lines = [f"[2026-09-27 10:00:{i:02d}] [AUTH] [WARN] Login failed for user u{i} from 10.0.0.{i}"
                 for i in range(10)]
        report = PIPELINE.auto_engine.learn(lines, save=True)
        self.assertEqual(len(report["accepted"]), 1, report)
        res = PIPELINE.process_line("[2027-01-05 23:59:59] [AUTH] [ERROR] Login failed for user zed from 172.16.9.9")
        self.assertTrue(res.get("auto_parsed"), res)
        ev = res["event"]
        self.assertEqual(ev["timestamp"], "2027-01-05T23:59:59+00:00")
        self.assertEqual(ev["source"]["ip"], "172.16.9.9")
        self.assertEqual(ev["user"]["name"], "zed")
        self.assertEqual(ev["severity_label"], "high")
        self.assertTrue(os.path.exists(report["accepted"][0]["saved_to"]))

    def test_tampered_spec_is_rejected_on_load(self):
        from ulpf.intelligence.auto_parser.registry import AutoParserRegistry
        lines = [f"PUMP|{i}|2026-01-0{i % 9 + 1}T00:00:00Z|OK" for i in range(6)]
        report = PIPELINE.auto_engine.learn(lines, save=True)
        path = report["accepted"][0]["saved_to"]
        with open(path, encoding="utf-8") as f:
            spec = json.load(f)
        spec["template"] = "tampered"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(spec, f)
        reg = AutoParserRegistry(os.path.dirname(path))
        self.assertIsNone(reg.get_spec(spec["parser_id"]))

    def test_comma_and_kv_delimited_templates_compile(self):
        from ulpf.intelligence.auto_parser.miners.native import NativeTemplateMiner
        from ulpf.intelligence.auto_parser.compiler import ParserCompiler
        rows = [f"SENSOR-{i},2026-02-0{i}T10:00:00Z,{20 + i}.5,celsius" for i in range(1, 6)]
        spec = NativeTemplateMiner().mine(rows, "fp")[0]
        parser = ParserCompiler.compile(spec)
        self.assertIsNotNone(parser.parse("SENSOR-77,2026-03-01T00:00:00Z,19.0,celsius"))

    def test_tab_delimited_values_keep_their_spaces(self):
        from ulpf.intelligence.auto_parser.engine import AutoParserEngine
        msgs = ["Login failed for user", "Session closed", "Policy violation on port 443"]
        lines = [f"2026-09-27 10:00:{i:02d}\tdevice=fw{i}\tuser=u{i}\tsrc=10.0.0.{i}\tmsg={msgs[i % 3]}"
                 for i in range(9)]
        engine = AutoParserEngine(learned_dir=tempfile.mkdtemp())
        self.assertEqual(len(engine.learn(lines, save=False)["accepted"]), 1)
        parsed = engine.parse("2027-01-05 23:59:59\tdevice=fw77\tuser=zed\tsrc=172.16.9.9\t"
                              "msg=Tunnel down, peer unreachable")
        self.assertEqual(parsed["user.name"], "zed")
        self.assertEqual(parsed["source.ip"], "172.16.9.9")
        self.assertEqual(parsed["message"], "Tunnel down, peer unreachable")

    def test_quoted_values_and_keys_survive_into_the_parser(self):
        from ulpf.intelligence.auto_parser.compiler import ParserCompiler
        from ulpf.intelligence.auto_parser.engine import AutoParserEngine
        engine = AutoParserEngine(learned_dir=tempfile.mkdtemp())
        reasons = ["too many attempts", "account locked by policy"]
        lines = [f'2026-09-27T10:00:0{i}Z host=web{i} user="u{i}" src=10.0.0.{i} reason="{reasons[i % 2]}"'
                 for i in range(6)]
        self.assertTrue(engine.learn(lines, save=False)["accepted"])
        parsed = engine.parse('2027-01-01T00:00:00Z host=web9 user="zed" src=10.9.9.9 reason="password expired"')
        self.assertEqual(parsed["user.name"], "zed")
        self.assertEqual(parsed["reason"], "password expired")
        # Literals keep their quote characters, so they still match the raw line
        rows = [f'{{"app":"gw","seq":{i},"user":"u{i}"}}' for i in range(5)]
        parser = ParserCompiler.compile(engine.native_miner.mine(rows, "fp")[0])
        self.assertTrue(all(parser.parse(r) is not None for r in rows), parser.spec.template)

    def test_formats_sharing_a_fingerprint_are_learned_separately(self):
        from ulpf.intelligence.auto_parser.engine import AutoParserEngine
        # Same token count, delimiter and field types: one structural fingerprint
        a = [f"DEBUG: 2026-09-27 10:00:{i:02d} - Process {i} allocated {i * 100} bytes of memory"
             for i in range(10)]
        b = [f"Transaction {i} initiated by u{i} on 2026-09-27 10:00:{i:02d} with status: allow"
             for i in range(10)]
        engine = AutoParserEngine(learned_dir=tempfile.mkdtemp())
        report = engine.learn(a + b, save=False)
        self.assertEqual(len(report["accepted"]), 2, report["rejected"])
        self.assertEqual(report["coverage_pct"], 100.0)


class TestIngestion(unittest.TestCase):
    def test_worker_pool_zero_loss(self):
        from ulpf.ingestion.workers import WorkerPool
        from ulpf.storage.database import Database
        db = Database(os.path.join(tempfile.mkdtemp(), "pool.duckdb"))
        pool = WorkerPool(num_workers=2, batch_size=250)
        pool.start(db=db)
        lines = [f"CEF:0|V|P|1|1|n|3|src=10.0.{i // 250}.{i % 250} dst=10.0.0.1" for i in range(5000)]
        pool.submit_batch(lines)
        metrics = pool.stop()
        self.assertEqual(metrics["total_success"], 5000)
        self.assertEqual(db.count_events(), 5000)
        db.close()

    def test_tcp_octet_counting_guard(self):
        import asyncio
        from queue import Queue
        from ulpf.ingestion.listener import ListenerStats, SyslogTCPProtocol

        async def run():
            q = Queue()
            proto = SyslogTCPProtocol(q, ListenerStats())
            proto._loop = asyncio.get_running_loop()
            # newline-framed line that starts with digits must not be read as an octet length
            proto.data_received(b"1724840101 host app: epoch first\n")
            proto._flush_msg_batch()
            return q.get_nowait()
        self.assertEqual(asyncio.run(run()), ["1724840101 host app: epoch first"])

    def test_forwarder_formats_rfc5424(self):
        from ulpf.ingestion.forwarder import format_rfc5424
        msg = format_rfc5424(parse("CEF:0|V|P|1|1|n|9|src=1.2.3.4 dst=5.6.7.8")).decode()
        self.assertTrue(msg.startswith("<129>1 "))   # local0 (16*8) + crit (1)
        self.assertIn('src="1.2.3.4"', msg)


class TestAPI(unittest.TestCase):
    """Exercises the real ASGI app over HTTP (uvicorn on an ephemeral port)."""

    @classmethod
    def setUpClass(cls):
        try:
            import uvicorn
        except ImportError:
            raise unittest.SkipTest("uvicorn not installed")
        import socket
        import threading
        from ulpf.api.app import create_app
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]
        cls.server = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=cls.port,
                                                   log_level="warning"))
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        deadline = time.time() + 20
        while not cls.server.started and time.time() < deadline:
            time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(timeout=10)

    def request(self, method, path, body=None, headers=None):
        import urllib.error
        import urllib.request
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
                                     headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, resp.headers.get("content-type", ""), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("content-type", ""), e.read()

    def test_health_schema_ingest_query_export(self):
        self.assertEqual(self.request("GET", "/api/v1/health")[0], 200)
        status, _, body = self.request("GET", "/api/v1/schema")
        self.assertGreaterEqual(json.loads(body)["field_count"], 65)
        _, _, body = self.request("POST", "/api/v1/ingest/batch", {"lines": [
            "CEF:0|V|P|1|1|n|8|src=10.0.0.1 dst=10.0.0.2", "#Fields: date time c-ip",
            "2024-01-01 00:00:00 10.0.0.3"]})
        r = json.loads(body)
        self.assertEqual(r["successful"], 2)
        self.assertEqual(r["skipped_headers"], 1)
        _, _, body = self.request("GET", "/api/v1/events?severity_min=8")
        self.assertGreaterEqual(json.loads(body)["count"], 1)
        status, ctype, body = self.request("GET", "/api/v1/export?format=csv&limit=5")
        self.assertEqual(status, 200)
        self.assertTrue(ctype.startswith("text/csv"))
        self.assertTrue(body.startswith(b"event_id,"))
        status, _, body = self.request("GET", "/api/v1/metrics")
        self.assertEqual(status, 200)
        self.assertIn(b"ulpf_store_events ", body)

    def test_auto_learn_endpoint_activates_parser(self):
        lines = [f"ACME-VPN | 2026-05-0{i} 12:00:0{i} | session {i}00 opened for user u{i} from 198.51.100.{i}"
                 for i in range(1, 6)]
        _, _, body = self.request("POST", "/api/v1/auto-learn", {"lines": lines})
        report = json.loads(body)
        self.assertEqual(len(report["accepted"]), 1, report)
        _, _, body = self.request("POST", "/api/v1/parsers/test", {
            "raw": "ACME-VPN | 2026-07-30 08:01:02 | session 999 opened for user zoe from 203.0.113.77"})
        res = json.loads(body)
        self.assertTrue(res.get("auto_parsed"), res)
        self.assertEqual(res["event"]["source"]["ip"], "203.0.113.77")

    def test_listener_start_ingest_stop(self):
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        status, _, body = self.request("POST", "/api/v1/listener/start",
                                       {"host": "127.0.0.1", "port": port, "protocol": "udp", "workers": 2})
        self.assertEqual(status, 200, body)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for i in range(300):
                s.sendto(f"<134>Oct 11 22:14:{i % 60:02d} gw-{i} sshd[1]: Accepted password for u{i} "
                         f"from 10.1.{i // 250}.{i % 250} port 22".encode(), ("127.0.0.1", port))
        deadline = time.time() + 30
        while time.time() < deadline:
            st = json.loads(self.request("GET", "/api/v1/listener/status")[2])
            if st.get("workers", {}).get("total_persisted", 0) >= 300:
                break
            time.sleep(0.5)
        _, _, body = self.request("POST", "/api/v1/listener/stop")
        final = json.loads(body)
        self.assertEqual(final["final_stats"]["messages_queued"], 300)
        self.assertEqual(final["worker_metrics"]["total_persisted"], 300)

    def test_api_key_enforced_when_configured(self):
        os.environ["ULPF_API_KEY"] = "s3cret"
        try:
            self.assertEqual(self.request("GET", "/api/v1/stats")[0], 401)
            self.assertEqual(self.request("GET", "/api/v1/stats", headers={"X-API-Key": "s3cret"})[0], 200)
            self.assertEqual(self.request("GET", "/api/v1/health")[0], 200)
        finally:
            del os.environ["ULPF_API_KEY"]


if __name__ == "__main__":
    unittest.main(verbosity=2)
