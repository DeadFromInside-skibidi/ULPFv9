"""
The five USPs on the live runtime (plan v9 section 2), reduced volume for CI.

U1  APG learns an unseen format from live traffic; defence mode holds it for approval
U2  evidence chain: seals verify, an edited stored event is detected at the right record
U3  one schema at every output; ECS / OCSF views are pure functions (golden files)
U4  offline by default (egress guard records nothing); air-gap mode blocks egress
U5  Log DNA drift within 1,000 lines; a cross-source kill chain is one correlation group

Regenerate golden files with ULPF_UPDATE_GOLDEN=1.
"""
from __future__ import annotations

import glob
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401
from tests.fakes import FakeHTTP  # noqa: E402

from ulpf.config import ConfigError, load_pipeline_config  # noqa: E402

GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden", "views")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_for(pred, timeout=60.0, step=0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(step)
    return False


def send_tcp(port: int, lines: list[str]) -> None:
    with socket.create_connection(("127.0.0.1", port)) as s:
        s.sendall("".join(l + "\n" for l in lines).encode())


def runtime(d: str, cfg: dict):
    from ulpf.runtime.supervisor import Runtime
    base = {"workers": 1, "node": {"data_dir": d}, "api": {"enabled": False},
            "outputs": [{"type": "duckdb", "name": "store", "path": os.path.join(d, "s.duckdb")}],
            "routes": [{"name": "all", "to": ["store"]}], "default_output": ""}
    base.update(cfg)
    return Runtime(load_pipeline_config(data=base)).start()


def q(rt, sql: str, params=None):
    with rt.database._conn_lock:
        return rt.database.conn.execute(sql, params or []).fetchall()


def logs(rt) -> int:
    return q(rt, "SELECT COUNT(*) FROM events WHERE json_extract_string(normalised_json, '$.event_kind') = 'log'")[0][0]


# ---------------------------------------------------------------------------
# U1
# ---------------------------------------------------------------------------

def plc_line(i: int) -> str:
    """A proprietary format no built-in parser knows."""
    return (f"PLC{i % 7:02d} >> valve {i % 40} {'opened' if i % 3 else 'closed'} by op{i % 5} "
            f"at 2026/10/21-10:{(i // 60) % 60:02d}:{i % 60:02d} pressure {1 + (i % 97) / 10:.2f}bar")


class TestU1LiveLearning(unittest.TestCase):
    def test_unseen_format_is_learned_without_restart(self):
        d = tempfile.mkdtemp(prefix="ulpf_u1_")
        port = free_port()
        rt = runtime(d, {"inputs": [{"type": "syslog", "name": "plc", "protocol": "tcp", "host": "127.0.0.1",
                                     "port": port, "framing": "newline"}],
                         "evidence": {"enabled": False}})
        try:
            send_tcp(port, [plc_line(i) for i in range(300)])
            self.assertTrue(wait_for(lambda: glob.glob(os.path.join(rt.learned_dir, "*.json")), 60),
                            "no parser was learned from the live stream")
            time.sleep(2.5)                       # workers pick learned parsers up within 2 s
            send_tcp(port, [plc_line(i) for i in range(300, 1300)])
            self.assertTrue(wait_for(lambda: logs(rt) >= 1300, 60), logs(rt))
            fmt = dict(q(rt, "SELECT raw_format, COUNT(*) FROM events WHERE CAST(json_extract("
                             "normalised_json, '$.evidence.journal_seq') AS BIGINT) > 300 GROUP BY 1"))
            parsed = fmt.get("auto_detected", 0)
            self.assertGreaterEqual(parsed / 1000, 0.99, fmt)
            row = q(rt, "SELECT normalised_json FROM events WHERE raw_format = 'auto_detected' LIMIT 1")[0][0]
            meta = json.loads(row)["metadata"]
            self.assertTrue(meta["parser_id"])
            # the learning plane recorded which source taught it
            with open(glob.glob(os.path.join(rt.learned_dir, "*.json"))[0], encoding="utf-8") as f:
                spec = json.load(f)
            self.assertEqual(spec["metadata"]["learned_source"], "127.0.0.1")
        finally:
            rt.stop()

    def test_defence_mode_holds_learned_parsers_for_approval(self):
        from ulpf.intelligence.auto_parser.engine import AutoParserEngine
        d = tempfile.mkdtemp(prefix="ulpf_u1d_")
        path = os.path.join(d, "plc.log")
        open(path, "w").close()
        rt = runtime(d, {"mode": "defence", "inputs": [{"type": "file", "name": "plc", "paths": [path],
                                                         "start_from": "beginning", "poll_interval_ms": 50}]})
        try:
            with open(path, "a", newline="\n") as f:
                f.writelines(plc_line(i) + "\n" for i in range(300))
            self.assertTrue(wait_for(lambda: glob.glob(os.path.join(rt.learned_dir, "*.json")), 60))
            eng = AutoParserEngine(learned_dir=rt.learned_dir)
            try:
                specs = eng.registry.list_parsers()
                self.assertTrue(specs)
                self.assertTrue(all(s.state == "pending_approval" for s in specs), [s.state for s in specs])
                with open(path, "a", newline="\n") as f:
                    f.writelines(plc_line(i) + "\n" for i in range(300, 400))
                self.assertTrue(wait_for(lambda: logs(rt) >= 400, 60))
                n_auto = q(rt, "SELECT COUNT(*) FROM events WHERE raw_format = 'auto_detected'")[0][0]
                self.assertEqual(n_auto, 0)       # unapproved parsers are never used
                for s in specs:
                    eng.approve(s.parser_id, "test-operator")
            finally:
                eng.stop()
            time.sleep(3.0)
            with open(path, "a", newline="\n") as f:
                f.writelines(plc_line(i) + "\n" for i in range(400, 600))
            self.assertTrue(wait_for(lambda: logs(rt) >= 600, 60))
            n = q(rt, "SELECT COUNT(*) FROM events WHERE raw_format = 'auto_detected' AND CAST(json_extract("
                      "normalised_json, '$.evidence.journal_seq') AS BIGINT) > 400")[0][0]
            self.assertGreaterEqual(n, 198)
        finally:
            rt.stop()

    def test_parser_cap_per_source(self):
        from ulpf.intelligence.auto_parser.engine import AutoParserEngine
        d = tempfile.mkdtemp(prefix="ulpf_u1c_")
        eng = AutoParserEngine(learned_dir=d)
        eng.max_parsers_per_source = 1
        eng.start()
        try:
            for i in range(120):
                eng.parse(plc_line(i), source_ip="10.0.0.9")
            self.assertTrue(wait_for(lambda: len(eng.registry.list_parsers()) >= 1, 30))
            other = [f"HVAC|zone={i % 9}|temp={20 + i % 7}.{i % 10}|fan={'on' if i % 2 else 'off'}|ts=171{i:07d}"
                     for i in range(120)]
            for line in other:
                eng.parse(line, source_ip="10.0.0.9")
            time.sleep(3.0)
            self.assertEqual(len(eng.registry.list_parsers()), 1)
            for line in other:                        # another source may still learn it
                eng.parse(line, source_ip="10.0.0.10")
            self.assertTrue(wait_for(lambda: len(eng.registry.list_parsers()) >= 2, 30))
        finally:
            eng.stop()


# ---------------------------------------------------------------------------
# U2
# ---------------------------------------------------------------------------

class TestU2EvidenceChain(unittest.TestCase):
    def test_seals_verify_and_edits_are_located(self):
        from ulpf.runtime.evidence import verify_seals
        d = tempfile.mkdtemp(prefix="ulpf_u2_")
        port = free_port()
        rt = runtime(d, {"inputs": [{"type": "syslog", "name": "tcp", "protocol": "tcp", "host": "127.0.0.1",
                                     "port": port}],
                         "evidence": {"enabled": True, "seal_every_events": 1000, "seal_every_seconds": 600,
                                      "row_mac": True},
                         "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["store"]},
                                    {"name": "seals", "when": {"kind_in": ["seal"]}, "to": ["seals"]}],
                         "outputs": [{"type": "duckdb", "name": "store", "path": os.path.join(d, "s.duckdb")},
                                     {"type": "file", "name": "seals", "path": os.path.join(d, "seals_out")}]})
        n = 5000
        try:
            send_tcp(port, [f"<134>Oct 11 22:14:15 fw01 app[1]: accepted connection {i} from 10.1.{i % 250}.{i % 200}"
                            for i in range(n)])
            self.assertTrue(wait_for(lambda: logs(rt) >= n, 60), logs(rt))
            rt.sealer.seal_now("test")
            seal_dir = os.path.join(d, "evidence", "seals")
            # Forward security: the host has erased the row keys of committed epochs, so it
            # cannot check (or forge) those rows' MACs...
            self.assertTrue(wait_for(lambda: rt.row_keys.base_epoch >= 4, 20), rt.row_keys.base_epoch)
            res = verify_seals(seal_dir, rt.journal, rt.sealer.key, rt.database)
            self.assertTrue(res["valid"], res["problems"])
            self.assertGreaterEqual(res["row_macs_unchecked"], 4000)
            # ...an off-box verifier holding the escrowed K_0 checks every row
            with open(os.path.join(d, "evidence", "row_key.k0"), "rb") as f:
                k0 = f.read()
            res = verify_seals(seal_dir, rt.journal, None, rt.database, row_key=k0)
            self.assertTrue(res["valid"], res["problems"])
            self.assertEqual(res["row_macs_unchecked"], 0)
            self.assertEqual(res["records_checked"], n)
            self.assertEqual(res["events_checked"], n)
            self.assertGreaterEqual(res["seals"], 5)
            # seals are also emitted as events to an output
            self.assertTrue(wait_for(lambda: rt.runners["seals"].delivered_events >= 5, 20))

            def seq_eid(seq):
                return q(rt, "SELECT event_id FROM events WHERE CAST(json_extract(normalised_json, "
                             "'$.evidence.journal_seq') AS BIGINT) = ?", [seq])[0][0]

            # 1. an analyst-facing column edited, raw_hash left alone -> row MAC catches it
            rt.database.execute_on_partitions("UPDATE {events} SET source_ip = '8.8.8.8' WHERE event_id = ?", [seq_eid(1234)], probe="event_id = ?", probe_params=[seq_eid(1234)])
            # 2. raw_hash rewritten -> differs from the journal
            rt.database.execute_on_partitions("UPDATE {events} SET raw_hash = repeat('0', 64) WHERE event_id = ?", [seq_eid(4321)], probe="event_id = ?", probe_params=[seq_eid(4321)])
            # 3. the MAC itself removed -> the seal says rows carry MACs, so that is an edit too
            rt.database.execute_on_partitions("UPDATE {events} SET row_mac = NULL, message = 'nothing to see' WHERE event_id = ?", [seq_eid(2222)], probe="event_id = ?", probe_params=[seq_eid(2222)])
            res = verify_seals(seal_dir, rt.journal, None, rt.database, row_key=k0)
            self.assertFalse(res["valid"])
            joined = "\n".join(res["problems"])
            self.assertEqual(len(res["problems"]), 3, joined)
            self.assertIn("record 1234 was modified", joined)
            self.assertIn("row MAC mismatch", joined)
            self.assertIn("record 2222 was modified after it was written (row MAC missing)", joined)
            self.assertIn("record 4321 has a raw_hash", joined)
        finally:
            rt.stop()


# ---------------------------------------------------------------------------
# U3
# ---------------------------------------------------------------------------

GOLDEN_LINES = {
    "syslog_sshd": "<34>Oct 11 22:14:15 db01 sshd[4721]: Failed password for root from 45.33.32.156 port 51234 ssh2",
    "rfc5424": '<165>1 2026-10-21T10:00:03Z waf-prod-01 app 101 ID47 [attack severity="high"] '
               "Suspicious beacon from 10.0.2.15 to 91.121.87.10:8080",
    "cef": "CEF:0|Check Point|VPN-1 & FireWall-1|R81.20|Drop|Firewall Rule Drop|8|rt=2026-10-21T10:00:01Z "
           "src=45.33.32.156 dst=10.0.1.50 spt=12345 dpt=4444 proto=TCP act=Drop",
    "leef": "LEEF:2.0|IBM|QRadar|7.5|SecurityAlert|devTime=2026-10-21T10:00:00Z\tsrc=185.220.101.33\t"
            "dst=10.0.1.99\tusrName=jdoe\tsev=7\tmsg=Brute force threshold exceeded",
    "json_suricata": '{"timestamp":"2026-10-21T10:00:04Z","event_type":"alert","src_ip":"177.54.150.200",'
                     '"src_port":53211,"dest_ip":"10.0.0.5","dest_port":53,"proto":"UDP",'
                     '"alert":{"signature":"ET MALWARE DNS Query to C2 Domain","severity":1}}',
    "fortinet_kv": 'date=2026-10-21 time=10:00:04 devname="FGT-EDGE-01" type="traffic" srcip=192.168.1.105 '
                   'srcport=51234 dstip=91.121.87.10 dstport=443 proto=6 action="deny" user="eng01"',
    "windows_xml": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
                   "<Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID>"
                   "<TimeCreated SystemTime='2026-10-21T10:00:05.000Z'/><Computer>DC01</Computer></System>"
                   "<EventData><Data Name='TargetUserName'>administrator</Data>"
                   "<Data Name='IpAddress'>103.224.182.7</Data></EventData></Event>",
}


def golden_event(name: str) -> dict:
    from ulpf.engine.pipeline import Pipeline
    p = Pipeline(enable_auto_parser=False)
    r = p.process_line(GOLDEN_LINES[name], event_id=f"00000000-0000-8000-8000-{len(name):012d}",
                       timestamp_now="2026-10-21T10:00:00+00:00")
    assert r["success"], r
    ev = r["event"]
    ev["metadata"]["detection_confidence"] = round(ev["metadata"]["detection_confidence"] or 0, 2)
    ev["metadata"]["processing_time_ms"] = None
    return ev


class TestU3OneSchemaEveryOutput(unittest.TestCase):
    def test_views_match_golden_files(self):
        from ulpf.engine.views import apply_view
        update = os.environ.get("ULPF_UPDATE_GOLDEN") == "1"
        os.makedirs(GOLDEN, exist_ok=True)
        for name in GOLDEN_LINES:
            ev = golden_event(name)
            for view in ("unified", "ecs", "ocsf", "udm", "asim"):
                got = json.loads(json.dumps(apply_view(json.loads(json.dumps(ev)), view), default=str))
                path = os.path.join(GOLDEN, f"{name}.{view}.json")
                if update:
                    with open(path, "w", encoding="utf-8", newline="\n") as f:
                        json.dump(got, f, indent=2, sort_keys=True, ensure_ascii=False)
                        f.write("\n")
                    continue
                self.assertTrue(os.path.exists(path), f"missing golden file {path} (run with ULPF_UPDATE_GOLDEN=1)")
                with open(path, encoding="utf-8") as f:
                    self.assertEqual(got, json.load(f), f"{name} / {view} differs from {path}")

    def test_views_are_pure(self):
        from ulpf.engine.views import apply_view
        ev = golden_event("cef")
        before = json.dumps(ev, sort_keys=True, default=str)
        a = apply_view(ev, "ecs"), apply_view(ev, "ocsf")
        self.assertEqual(json.dumps(ev, sort_keys=True, default=str), before)
        self.assertEqual(a, (apply_view(ev, "ecs"), apply_view(ev, "ocsf")))

    def test_every_output_receives_the_same_canonical_event(self):
        docs: dict[str, dict] = {}
        lock = threading.Lock()

        def respond(req):
            if req["path"].startswith("/_bulk"):
                lines = [l for l in req["body"].split(b"\n") if l]
                items = []
                with lock:
                    for a, b in zip(lines[0::2], lines[1::2]):
                        docs[json.loads(a)["create"]["_id"]] = json.loads(b)
                        items.append({"create": {"status": 201}})
                return 200, {}, {"errors": False, "items": items}
            return 200, {}, {"version": {"number": "8.11.0"}}

        es = FakeHTTP(respond)
        d = tempfile.mkdtemp(prefix="ulpf_u3_")
        port = free_port()
        os.environ["ULPF_T_ES"] = "k"
        rt = runtime(d, {"inputs": [{"type": "syslog", "name": "tcp", "protocol": "tcp", "host": "127.0.0.1",
                                     "port": port, "framing": "newline"}],
                         "evidence": {"enabled": False}, "analytics": {"anomaly": {"enabled": False},
                                                                        "drift": {"enabled": False},
                                                                        "correlation": {"enabled": False}},
                         "outputs": [{"type": "duckdb", "name": "store", "path": os.path.join(d, "s.duckdb")},
                                     {"type": "elasticsearch", "name": "es", "urls": [es.url], "api_key_env": "ULPF_T_ES",
                                      "view": "unified"},
                                     {"type": "file", "name": "file", "path": os.path.join(d, "out")}],
                         "routes": [{"name": "all", "to": ["store", "es", "file"]}]})
        try:
            lines = [l for l in GOLDEN_LINES.values()]
            send_tcp(port, lines)
            n = len(lines)
            self.assertTrue(wait_for(lambda: all(r.delivered_events >= n for r in rt.runners.values()), 30))
            from ulpf.storage.database import _hydrate
            store = {r[0]: _hydrate(r[1], r[2], r[3]) for r in
                     q(rt, "SELECT event_id, normalised_json, raw_event, parsed_fields FROM events")}
            files = {}
            for p in glob.glob(os.path.join(d, "out", "*.ndjson")):
                with open(p, "rb") as fh:
                    for line in fh:
                        e = json.loads(line)
                        files[e["event_id"]] = e
            self.assertEqual(set(store), set(files))
            self.assertEqual(set(store), set(docs))
            canon = ("event_id", "timestamp", "category", "action", "severity", "raw_format", "raw_event",
                     "message", "source", "destination", "user", "device", "evidence", "metadata")
            for eid, ev in store.items():
                for k in canon:
                    self.assertEqual(json.dumps(ev.get(k), sort_keys=True), json.dumps(files[eid].get(k), sort_keys=True),
                                     f"{k} differs between store and file for {eid}")
                    self.assertEqual(json.dumps(ev.get(k), sort_keys=True), json.dumps(docs[eid].get(k), sort_keys=True),
                                     f"{k} differs between store and Elasticsearch for {eid}")
        finally:
            rt.stop()
            es.close()


# ---------------------------------------------------------------------------
# U4
# ---------------------------------------------------------------------------

class TestU4Offline(unittest.TestCase):
    def test_default_config_contacts_nothing(self):
        from ulpf.config import default_config
        from ulpf.runtime.supervisor import Runtime
        d = tempfile.mkdtemp(prefix="ulpf_u4_")
        cfg = default_config("industry")
        port = free_port()
        cfg["inputs"][0]["port"] = port
        cfg["outputs"][0]["path"] = os.path.join(d, "s.duckdb")
        cfg["node"] = {"data_dir": d}
        cfg["api"] = {"enabled": True, "port": 0}
        cfg["workers"] = 1
        pc = load_pipeline_config(data=cfg)
        from ulpf.config import describe
        self.assertEqual(describe(pc)["remote_destinations"], [])
        rt = Runtime(pc).start()
        try:
            send_tcp(port, [f"<134>Oct 11 22:14:15 fw01 app: line {i} from 45.33.32.{i % 250}" for i in range(500)])
            self.assertTrue(wait_for(lambda: rt.stats()["committed_seq"] >= 500, 60))
            time.sleep(1.0)
            report = rt.egress_report()
            self.assertEqual(report["mode"], "record")
            self.assertEqual(report["destinations"], {}, report)
            self.assertEqual(report["blocked"], {})
        finally:
            rt.stop()

    def test_airgap_mode_blocks_egress_in_process(self):
        from ulpf.platform import get_adapter
        d = tempfile.mkdtemp(prefix="ulpf_u4b_")
        rt = runtime(d, {"mode": "defence", "inputs": [], "airgap": {"allow": ["10.255.255.1"]}})
        try:
            self.assertTrue(rt.egress.enforce)
            with self.assertRaises(PermissionError):
                socket.create_connection(("192.0.2.10", 443), timeout=1)
            with self.assertRaises(PermissionError):
                u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    u.sendto(b"x", ("192.0.2.11", 514))
                finally:
                    u.close()
            report = rt.egress_report()
            self.assertIn("192.0.2.10:443", report["blocked"])
            self.assertIn("192.0.2.11:514", report["blocked"])
            # an allowed address is not blocked by the guard (it simply is not reachable here)
            s = socket.socket()
            s.settimeout(0.2)
            try:
                s.connect(("10.255.255.1", 9))
            except PermissionError:
                self.fail("allowed destination was blocked")
            except OSError:
                pass
            finally:
                s.close()
            get_adapter().is_air_gapped()         # the route probe is not egress
            self.assertNotIn("192.0.2.1:9", rt.egress_report()["blocked"])
        finally:
            rt.stop()
        # after stop the guard no longer applies to this process
        s = socket.socket()
        s.settimeout(0.05)
        try:
            s.connect(("192.0.2.12", 9))
        except PermissionError:
            self.fail("egress guard still active after the runtime stopped")
        except OSError:
            pass
        finally:
            s.close()

    def test_airgap_config_rejects_unlisted_destination(self):
        with self.assertRaises(ConfigError) as cm:
            load_pipeline_config(data={"mode": "defence", "airgap": {"allow": ["10.0.0.5"]},
                                       "outputs": [{"type": "syslog", "name": "siem", "host": "10.0.0.9",
                                                    "port": 6514, "protocol": "tls"}]})
        self.assertIn("defence.allowlist", str(cm.exception))


# ---------------------------------------------------------------------------
# U5
# ---------------------------------------------------------------------------

class TestU5StreamAnalytics(unittest.TestCase):
    def test_stream_correlator_memory_is_bounded(self):
        from datetime import datetime, timedelta, timezone
        from ulpf.runtime.analytics import StreamCorrelator
        emitted = []
        sc = StreamCorrelator("n", window_seconds=10, emit=emitted.extend, max_groups=100, max_group_events=50)
        t0 = datetime(2026, 10, 21, tzinfo=timezone.utc)

        def proj(i, src, dst):
            return {"event_id": f"e{i}", "timestamp": (t0 + timedelta(seconds=i // 50)).isoformat(),
                    "category": "network", "action": "allowed", "severity": 3, "message": "x",
                    "source": {"ip": src}, "destination": {"ip": dst}, "device": {}, "user": {}, "network": {},
                    "threat": {}, "rule": {}}
        for i in range(200_000):
            # one hot server everybody talks to, plus pairs of short-lived peers
            p = proj(i, f"10.{i // 2 % 250}.{i // 500 % 250}.1", "10.0.0.1" if i % 3 == 0 else f"172.16.{i // 2 % 250}.9")
            sc.submit([p])
            if i % 1000 == 0:
                sc.step()
        sc.step(time.time() + 10_000)
        groups = sc.correlator._groups
        self.assertLessEqual(len(groups), 100)
        self.assertTrue(all(len(g.events) <= 50 for g in groups.values()))
        self.assertGreater(sc.evicted, 0)
        self.assertTrue(emitted)                      # closed groups were still reported

    def test_first_seen_ip_alerts_wait_for_a_stable_population(self):
        from ulpf.intelligence.anomaly import AnomalyDetector
        det = AnomalyDetector(new_ip_warmup=2000, new_ip_external_only=True, new_ip_max_novelty=0.01)

        def ev(src, dst="10.0.0.1"):
            return {"severity": 3, "source": {"ip": src}, "destination": {"ip": dst}, "network": {},
                    "category": "network"}
        alerts = []
        # learning a growing network: 300 public peers appear over the first 3,000 events
        for i in range(3000):
            alerts += det.analyse_event(ev(f"45.33.{i % 300 // 250}.{i % 300 % 250 + 1}"))
        # steady state: the same peers, plus internal hosts that never alert
        for i in range(3000):
            alerts += det.analyse_event(ev(f"45.33.{i % 300 // 250}.{i % 300 % 250 + 1}", f"10.1.{i % 50}.1"))
        self.assertEqual([a for a in alerts if a["type"] == "new_ip"], [])
        alerts = det.analyse_event(ev("185.220.101.77"))     # a stranger on a quiet network
        self.assertEqual([a["ip"] for a in alerts if a["type"] == "new_ip"], ["185.220.101.77"])

    def test_drift_and_cross_source_correlation(self):
        d = tempfile.mkdtemp(prefix="ulpf_u5_")
        p_fw, p_auth = free_port(), free_port()
        rt = runtime(d, {"inputs": [{"type": "syslog", "name": "fw", "protocol": "tcp", "host": "127.0.0.1",
                                     "port": p_fw, "framing": "newline"},
                                    {"type": "syslog", "name": "auth", "protocol": "tcp", "host": "127.0.0.1",
                                     "port": p_auth, "framing": "newline"}],
                         "evidence": {"enabled": False},
                         "analytics": {"drift": {"enabled": True, "sample_lines": 200, "min_interval_seconds": 0},
                                       "anomaly": {"enabled": False},
                                       "correlation": {"enabled": True, "window_seconds": 30}}})
        try:
            def drift_events():
                return q(rt, "SELECT message, normalised_json FROM events WHERE "
                             "json_extract_string(normalised_json, '$.event_kind') = 'drift'")

            # --- drift: the vendor renames its JSON fields mid-stream
            before = [json.dumps({"ts": f"2026-10-21T09:{i // 60 % 60:02d}:{i % 60:02d}Z", "src": f"10.0.{i % 9}.1",
                                  "dst": "10.9.9.9", "act": "allow", "bytes": i}) for i in range(600)]
            after = [json.dumps({"ts": f"2026-10-21T09:{i // 60 % 60:02d}:{i % 60:02d}Z", "source_address":
                                 f"10.0.{i % 9}.1", "destination_address": "10.9.9.9", "verdict": "allow",
                                 "octets": i}) for i in range(1000)]
            send_tcp(p_fw, before)
            self.assertTrue(wait_for(lambda: logs(rt) >= 600, 60))
            self.assertEqual(drift_events(), [])           # a stable stream raises nothing
            send_tcp(p_fw, after)
            self.assertTrue(wait_for(lambda: logs(rt) >= 1600, 60))
            self.assertTrue(wait_for(lambda: drift_events(), 10))
            msg, doc = drift_events()[0]
            ext = json.loads(doc)["extensions"]["drift"]
            self.assertEqual(ext["input"], "fw")
            self.assertLess(ext["similarity"], 0.5)
            first_after = 600 + 1
            related = json.loads(doc)["related_events"][0]
            seq = q(rt, "SELECT CAST(json_extract(normalised_json, '$.evidence.journal_seq') AS BIGINT) "
                        "FROM events WHERE event_id = ?", [related])[0][0]
            self.assertLessEqual(seq - first_after, 1000)   # detected within 1,000 lines of the change

            # --- correlation: one attacker, two sources, five kill-chain steps
            atk = "185.220.101.44"
            send_tcp(p_fw, [
                f"CEF:0|Palo Alto|PAN-OS|10.2|scan|Port scan detected|6|rt=2026-10-21T11:00:00Z src={atk} "
                "dst=10.0.1.20 dpt=22 act=alert msg=nmap reconnaissance port scan",
                f"CEF:0|Palo Alto|PAN-OS|10.2|exploit|Exploit attempt|9|rt=2026-10-21T11:00:20Z src={atk} "
                "dst=10.0.1.20 dpt=443 act=alert msg=exploit attempt CVE-2024-3400 command injection"])
            send_tcp(p_auth, [
                f"<38>Oct 21 11:00:05 bastion sshd[901]: Failed password for root from {atk} port 40001 ssh2",
                f"<38>Oct 21 11:00:09 bastion sshd[901]: Failed password for root from {atk} port 40002 ssh2",
                f"<38>Oct 21 11:00:12 bastion sshd[901]: Accepted password for root from {atk} port 40003 ssh2"])
            time.sleep(1.0)
            # unrelated later traffic moves event time past the window, which closes the group
            send_tcp(p_auth, ["<38>Oct 21 11:02:00 web01 cron[77]: job backup finished"])

            def groups():
                rows = q(rt, "SELECT normalised_json FROM events WHERE "
                             "json_extract_string(normalised_json, '$.event_kind') = 'correlation'")
                return [json.loads(r[0]) for r in rows]
            self.assertTrue(wait_for(lambda: any(atk in json.dumps(g) for g in groups()), 30))
            g = [g for g in groups() if atk in json.dumps(g)][-1]
            ext = g["extensions"]["correlation"]
            self.assertEqual(len(ext["event_ids"]), 5)
            inputs = set(q(rt, "SELECT DISTINCT json_extract_string(normalised_json, '$.metadata.input') FROM events "
                               f"WHERE event_id IN ({', '.join('?' for _ in ext['event_ids'])})", ext["event_ids"]))
            self.assertEqual({i[0] for i in inputs}, {"fw", "auth"})
            self.assertTrue(ext["kill_chain_stages"])
            self.assertEqual(sorted(g["related_events"]), sorted(ext["event_ids"]))
        finally:
            rt.stop()


# ---------------------------------------------------------------------------
# Offline GeoIP (MaxMind DB format) - used by enrichment in air-gapped installs
# ---------------------------------------------------------------------------

def _mmdb_encode(v) -> bytes:
    def ctrl(kind, size):
        if size < 29:
            head = bytes([((kind if kind < 8 else 0) << 5) | size])
        elif size < 285:
            head = bytes([((kind if kind < 8 else 0) << 5) | 29])
            ext = bytes([size - 29])
            return head + (bytes([kind - 7]) if kind >= 8 else b"") + ext
        else:
            raise ValueError("too long for the test writer")
        return head + (bytes([kind - 7]) if kind >= 8 else b"")
    if isinstance(v, str):
        b = v.encode()
        return ctrl(2, len(b)) + b
    if isinstance(v, float):
        return ctrl(3, 8) + struct.pack(">d", v)
    if isinstance(v, int):
        b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big") if v else b""
        return ctrl(6, len(b)) + b
    if isinstance(v, dict):
        return ctrl(7, len(v)) + b"".join(_mmdb_encode(k) + _mmdb_encode(x) for k, x in v.items())
    if isinstance(v, list):
        return ctrl(11, len(v)) + b"".join(_mmdb_encode(x) for x in v)
    raise TypeError(type(v))


def write_mmdb(path: str, networks: list[tuple[str, dict]]) -> None:
    """Minimal IPv4 MaxMind DB writer (24-bit records) for tests."""
    import ipaddress
    data, offsets = b"", []
    for _, rec in networks:
        offsets.append(len(data))
        data += _mmdb_encode(rec)
    nodes = [[None, None]]
    for (cidr, _), off in zip(networks, offsets):
        net = ipaddress.ip_network(cidr)
        bits, value, node = net.prefixlen, int(net.network_address), 0
        for i in range(bits):
            b = (value >> (31 - i)) & 1
            if i == bits - 1:
                nodes[node][b] = ("data", off)
            else:
                if not isinstance(nodes[node][b], int):
                    nodes.append([None, None])
                    nodes[node][b] = len(nodes) - 1
                node = nodes[node][b]
    n = len(nodes)

    def rec(x):
        if x is None:
            return n
        if isinstance(x, tuple):
            return n + 16 + x[1]
        return x
    tree = b"".join(rec(l).to_bytes(3, "big") + rec(r).to_bytes(3, "big") for l, r in nodes)
    meta = {"node_count": n, "record_size": 24, "ip_version": 4, "database_type": "ULPF-Test-City",
            "binary_format_major_version": 2, "binary_format_minor_version": 0, "build_epoch": 1760000000,
            "languages": ["en"], "description": {"en": "test"}}
    with open(path, "wb") as f:
        f.write(tree + bytes(16) + data + b"\xab\xcd\xefMaxMind.com" + _mmdb_encode(meta))


class TestOfflineGeoIP(unittest.TestCase):
    def test_mmdb_reader_and_enrichment(self):
        from ulpf.intelligence.mmdb import MMDBReader, geo_from_record
        d = tempfile.mkdtemp(prefix="ulpf_geo_")
        path = os.path.join(d, "Test-City.mmdb")
        nl = {"country": {"iso_code": "NL", "names": {"en": "Netherlands"}},
              "city": {"names": {"en": "Amsterdam"}}, "location": {"latitude": 52.37, "longitude": 4.89},
              "subdivisions": [{"names": {"en": "North Holland"}}]}
        jp = {"country": {"iso_code": "JP", "names": {"en": "Japan"}}, "location": {"latitude": 35.68, "longitude": 139.69}}
        write_mmdb(path, [("81.2.69.0/24", nl), ("133.0.0.0/8", jp)])
        with MMDBReader(path) as r:
            self.assertEqual(r.database_type, "ULPF-Test-City")
            rec, plen = r.lookup("81.2.69.160")
            self.assertEqual(plen, 24)
            self.assertEqual(geo_from_record(rec), {"country": "Netherlands", "cc": "NL", "city": "Amsterdam",
                                                    "region": "North Holland", "lat": 52.37, "lon": 4.89})
            self.assertEqual(geo_from_record(r.lookup("133.11.0.1")[0])["cc"], "JP")
            self.assertIsNone(r.lookup("8.8.8.8")[0])
            self.assertIsNone(r.lookup("::ffff:8.8.4.4")[0])

        from ulpf.engine import enricher
        os.environ["ULPF_GEOIP_DIR"] = d
        try:
            enricher.reset_geoip()
            self.assertEqual(enricher._lookup_geo("81.2.69.160")["city"], "Amsterdam")
            # special-purpose ranges are labelled, never geolocated
            doc = enricher._lookup_geo("203.0.113.9")
            self.assertEqual(doc["cc"], "ZZ")
            self.assertNotIn("lat", doc)
            self.assertEqual(enricher._lookup_geo("100.64.1.1")["cc"], "XX")      # CGNAT
        finally:
            os.environ.pop("ULPF_GEOIP_DIR", None)
            enricher.reset_geoip()


if __name__ == "__main__":
    unittest.main()
