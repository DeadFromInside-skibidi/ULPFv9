"""
Problem-statement source classes and solution items not covered elsewhere
(docs/PROBLEM_STATEMENT_COVERAGE.md): IoT over MQTT, databases, endpoint
security tools, unified visibility (Grafana), AI/ML on the exported dataset.
"""
from __future__ import annotations

import glob
import json
import math
import os
import random
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401
from tests.fakes import FakeMqttBroker  # noqa: E402

from ulpf.config import load_pipeline_config  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def wait_for(pred, timeout=60.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.1)
    return False


def runtime(d, inputs):
    from ulpf.runtime.supervisor import Runtime
    return Runtime(load_pipeline_config(data={
        "workers": 1, "node": {"data_dir": d}, "api": {"enabled": False}, "evidence": {"enabled": False},
        "inputs": inputs, "outputs": [{"type": "duckdb", "name": "store", "path": os.path.join(d, "s.duckdb")}],
        "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["store"]}],
        "default_output": ""})).start()


class TestIoT(unittest.TestCase):
    def test_mqtt_messages_are_acked_only_after_journaling(self):
        broker = FakeMqttBroker()
        d = tempfile.mkdtemp(prefix="ulpf_mqtt_")
        rt = runtime(d, [{"type": "mqtt", "name": "plant", "host": "127.0.0.1", "port": broker.port,
                          "topics": ["plant/+/telemetry"], "qos": 1}])
        try:
            self.assertTrue(broker.subscribed.wait(20), "input did not subscribe")
            n = 50
            for i in range(n):
                payload = json.dumps({"device": f"sensor-{i % 5}", "temp_c": 20 + i % 7, "valve": "open",
                                      "timestamp": "2026-10-21T10:00:00Z", "src_ip": f"10.20.0.{i % 5 + 1}"})
                broker.publish(f"plant/line{i % 3}/telemetry", payload.encode(), qos=1, pid=i + 1)
            self.assertTrue(wait_for(lambda: rt.runners["store"].delivered_events >= n, 30))
            self.assertTrue(wait_for(lambda: len(broker.acked) >= n, 10))
            self.assertEqual(sorted(broker.acked), list(range(1, n + 1)))
            self.assertLessEqual(len(broker.acked), rt.journal.next_seq - 1)   # never acked before journaled
            with rt.database._conn_lock:
                topics = {r[0] for r in rt.database.conn.execute(
                    "SELECT json_extract_string(normalised_json, '$.metadata.ingestion_source') FROM events").fetchall()}
            self.assertEqual(topics, {f"plant/line{k}/telemetry" for k in range(3)})
        finally:
            rt.stop()
            broker.close()


class TestDatabasesAndEndpoints(unittest.TestCase):
    def test_database_audit_logs(self):
        from ulpf.cli_runtime import onboard_source
        from ulpf.engine.pipeline import Pipeline
        p = Pipeline(enable_auto_parser=False)
        # MySQL Enterprise / Percona audit plugin, JSON format
        mysql = json.dumps({"timestamp": "2026-10-21 10:00:01", "id": 0, "class": "connection",
                            "event": "connect", "connection_id": 41, "account": {"user": "app", "host": "web01"},
                            "login": {"user": "app", "os": "", "ip": "10.1.1.20", "proxy": ""},
                            "connection_data": {"connection_type": "ssl", "status": 1045, "db": "billing"},
                            "user": "app", "host_name": "web01", "connection_ip": "10.1.1.20"})
        ev = p.process_line(mysql)["event"]
        self.assertEqual(ev["raw_format"], "json")
        self.assertEqual(ev["user"]["name"], "app")
        self.assertEqual(ev["source"]["ip"], "10.1.1.20")
        self.assertEqual(ev["source"]["hostname"], "web01")
        self.assertEqual(ev["parsed_fields"]["connection_data.db"], "billing")    # nested keys kept, flattened
        # PostgreSQL stderr log: a proprietary layout, onboarded from a sample
        pg = [f"2026-10-21 10:{i // 60 % 60:02d}:{i % 60:02d}.{i % 1000:03d} UTC [{4000 + i % 50}] "
              f"{'app' if i % 3 else 'postgres'}@{'billing' if i % 2 else 'crm'} "
              f"{'LOG' if i % 4 else 'FATAL'}:  connection authorized: user={'app' if i % 3 else 'postgres'} "
              f"database={'billing' if i % 2 else 'crm'} application_name=psql" for i in range(200)]
        rep = onboard_source("postgres", pg, "industry", tempfile.mkdtemp())
        self.assertGreaterEqual(rep["total_coverage_pct"], 99.0, rep)

    def test_edr_telemetry(self):
        from ulpf.engine.pipeline import Pipeline
        line = json.dumps({"event_simpleName": "NetworkConnectIP4", "timestamp": "1760000000123",
                           "ComputerName": "WS-0142", "aid": "8f2c1e0a9b7d", "UserName": "CORP\\alice",
                           "LocalAddressIP4": "10.0.4.17", "LocalPort": "51544",
                           "RemoteAddressIP4": "45.33.32.156", "RemotePort": "443", "Protocol": "6",
                           "ImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\rundll32.exe",
                           "CommandLine": "rundll32.exe C:\\Users\\alice\\AppData\\x.dll,Start"})
        ev = Pipeline(enable_auto_parser=False).process_line(line)["event"]
        self.assertEqual(ev["device"]["hostname"], "WS-0142")
        self.assertEqual(ev["device"]["serial"], "8f2c1e0a9b7d")
        self.assertEqual(ev["user"]["name"], "CORP\\alice")
        self.assertEqual((ev["source"]["ip"], ev["source"]["port"]), ("10.0.4.17", 51544))
        self.assertEqual((ev["destination"]["ip"], ev["destination"]["port"]), ("45.33.32.156", 443))
        self.assertEqual(ev["network"]["protocol"], "TCP")
        self.assertTrue(ev["timestamp"].startswith("2025-10-09T08:53:20.123"))
        self.assertIn("CommandLine", ev["parsed_fields"])
        self.assertIn("ioc_match", ev["tags"])              # 45.33.32.156 is in the bundled IOC feed


class TestSelectiveForwarding(unittest.TestCase):
    def test_raw_forwarding_sends_the_original_bytes(self):
        from ulpf.engine.pipeline import Pipeline
        from ulpf.runtime.sinks import build_sink
        cfg = load_pipeline_config(data={"outputs": [{"type": "syslog", "name": "siem", "host": "127.0.0.1",
                                                     "port": 514, "format": "raw"}]})
        sink = build_sink(cfg.outputs()[0], {"mode": "industry"})
        lines = ["<34>Oct 11 22:14:15 db01 sshd[1]: Failed password for root from 45.33.32.156 port 22 ssh2",
                 'CEF:0|V|P|1|100|café|8|src=10.0.0.1 dst=10.0.0.2',
                 '{"src_ip":"10.0.0.9","action":"deny"}']
        p = Pipeline(enable_auto_parser=False)
        payload = sink.encode([p.process_line(l)["event"] for l in lines])
        self.assertEqual(sink.records(payload), [l.encode() for l in lines])
        overhead = len(payload) - sum(len(l.encode()) for l in lines)
        self.assertLessEqual(overhead, 4 * len(lines))     # only the octet-count prefixes


class TestVisibility(unittest.TestCase):
    def test_grafana_dashboard_queries_ecs_fields_the_outputs_produce(self):
        with open(os.path.join(ROOT, "deploy", "grafana", "ulpf-overview.json"), encoding="utf-8") as f:
            dash = json.load(f)
        fields = set()
        for p in dash["panels"]:
            for t in p["targets"]:
                fields.add(t["timeField"])
                fields |= {b["field"] for b in t.get("bucketAggs", []) if "field" in b}
                import re
                fields |= set(re.findall(r"([a-z@_][\w.@]*):", t["query"])) - {"_exists_"}
                fields |= set(re.findall(r"_exists_:([\w.@]+)", t["query"]))

        produced = set()

        def flatten(d, pre=""):
            for k, v in d.items():
                produced.add(pre + k)
                if isinstance(v, dict):
                    flatten(v, pre + k + ".")
        for path in glob.glob(os.path.join(ROOT, "tests", "golden", "views", "*.ecs.json")):
            with open(path, encoding="utf-8") as f:
                flatten(json.load(f))
        missing = sorted(fields - produced)
        self.assertEqual(missing, [], f"dashboard uses fields no ECS output contains: {missing}")


class TestMachineLearning(unittest.TestCase):
    def test_exported_dataset_trains_a_baseline_model(self):
        import pyarrow.parquet as pq
        from benchmarks.live.common import build_corpus
        from ulpf.engine.pipeline import Pipeline
        from ulpf.main import ml_feature_rows, write_ml_dataset
        p = Pipeline(enable_auto_parser=False)
        with open(build_corpus(4000, seed=9, path=os.path.join(tempfile.mkdtemp(), "c.log")),
                  encoding="utf-8", errors="replace") as f:
            events = [r["event"] for r in (p.process_line(l) for l in f) if r.get("event")]
        out = os.path.join(tempfile.mkdtemp(), "features.parquet")
        write_ml_dataset(ml_feature_rows(events), out, "parquet")
        rows = pq.read_table(out).to_pylist()
        self.assertEqual(len(rows), len(events))

        # Predict "high severity" from features that do not contain the severity itself
        feats = ["dest_port", "source_port", "protocol_number", "category_code", "format_code", "is_threat",
                 "is_blocked", "is_cross_border", "hour_of_day"]
        X = [[float(r[k]) for k in feats] for r in rows]
        y = [r["is_high_severity"] for r in rows]
        cols = list(zip(*X))
        mu = [sum(c) / len(c) for c in cols]
        sd = [max(1e-9, math.sqrt(sum((v - m) ** 2 for v in c) / len(c))) for c, m in zip(cols, mu)]
        X = [[(v - m) / s for v, m, s in zip(x, mu, sd)] for x in X]
        idx = list(range(len(X)))
        random.Random(1).shuffle(idx)
        cut = int(0.8 * len(idx))
        train, test = idx[:cut], idx[cut:]
        w, b = [0.0] * len(feats), 0.0

        def prob(x):
            z = b + sum(wi * xi for wi, xi in zip(w, x))
            return 1 / (1 + math.exp(-max(-30, min(30, z))))
        for _epoch in range(30):                     # logistic regression, plain SGD
            for i in train:
                g = prob(X[i]) - y[i]
                w = [wi - 0.05 * g * xi for wi, xi in zip(w, X[i])]
                b -= 0.05 * g
        acc = sum((prob(X[i]) >= 0.5) == bool(y[i]) for i in test) / len(test)
        majority = max(sum(y[i] for i in test), len(test) - sum(y[i] for i in test)) / len(test)
        self.assertGreater(acc, majority, (acc, majority))   # it learned something real


if __name__ == "__main__":
    unittest.main()
