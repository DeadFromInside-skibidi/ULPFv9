"""Outputs end to end through the runtime, against in-process fake destinations."""
from __future__ import annotations

import datetime
import gzip
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401
from tests.fakes import FakeHTTP, FakeTcpSink, google_credentials  # noqa: E402

from ulpf.config import load_pipeline_config  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def demo_lines(n: int) -> list[bytes]:
    with open(os.path.join(ROOT, "demo_data", "mixed_formats.log"), "rb") as f:
        lines = [l for l in f.read().splitlines() if l.strip() and not l.startswith(b"#")]
    return (lines * (n // len(lines) + 1))[:n]


def wait_for(pred, timeout=60.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.1)
    return False


class Destinations:
    """One fake HTTP server behaving like ES, HEC, Loki, OTLP, Azure, Google and S3."""

    def __init__(self):
        self.es_docs: dict[str, dict] = {}
        self.es_down = threading.Event()
        self.s3: dict[str, bytes] = {}
        self.lock = threading.Lock()
        self.http = FakeHTTP(self.respond)

    def respond(self, req):
        p, body = req["path"], req["body"]
        if p.startswith("/_bulk"):
            if self.es_down.is_set():
                return 503, {}, b'{"error":"unavailable"}'
            lines = [l for l in body.split(b"\n") if l]
            items, errors = [], False
            with self.lock:
                for a, d in zip(lines[0::2], lines[1::2]):
                    _id = json.loads(a)["create"]["_id"]
                    if b"REJECTME" in d:
                        items.append({"create": {"status": 400, "error": {"type": "mapper_parsing_exception"}}})
                        errors = True
                    elif _id in self.es_docs:
                        items.append({"create": {"status": 409}})
                        errors = True
                    else:
                        self.es_docs[_id] = json.loads(d)
                        items.append({"create": {"status": 201}})
            return 200, {"Content-Type": "application/json"}, {"errors": errors, "items": items}
        if p == "/" and req["method"] == "GET":
            return 200, {}, {"version": {"number": "8.11.0"}}
        if p.startswith("/services/collector/event"):
            return 200, {}, {"text": "Success", "code": 0}
        if p.startswith("/loki/api/v1/push") or p.startswith("/dataCollectionRules"):
            return 204, {}, b""
        if p.startswith("/v1/logs") or p.startswith("/v2/unstructuredlogentries"):
            return 200, {}, {}
        if "oauth2" in p or p.startswith("/token"):
            return 200, {}, {"access_token": "test-token", "expires_in": 3600}
        if req["method"] == "PUT":
            with self.lock:
                self.s3[p] = body
            return 200, {}, b""
        return 404, {}, b"{}"

    def count(self, prefix: str, fn) -> int:
        return sum(fn(b) for b in self.http.bodies(prefix))


class TestOutputsEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dest = Destinations()
        cls.syslog = FakeTcpSink()
        cls.dir = tempfile.mkdtemp(prefix="ulpf_out_")
        os.environ.update(ULPF_T_ES="k", ULPF_T_HEC="t", ULPF_T_AZ="s", ULPF_T_S3A="AKIDEXAMPLE",
                          ULPF_T_S3S="secret")
        url = cls.dest.http.url
        creds = google_credentials(url + "/token", cls.dir)
        names = ["store", "es", "hec", "loki", "otlp", "syslog", "file", "lake", "s3", "azure", "chronicle"]
        cfg = {
            "workers": 1, "node": {"data_dir": cls.dir}, "inputs": [], "api": {"enabled": False},
            "evidence": {"enabled": False}, "analytics": {"correlation": {"enabled": False}},
            "outputs": [
                {"type": "duckdb", "name": "store", "path": os.path.join(cls.dir, "s.duckdb")},
                {"type": "elasticsearch", "name": "es", "urls": [url], "api_key_env": "ULPF_T_ES", "view": "ecs",
                 "retry": {"initial_ms": 50, "max_ms": 200}},
                {"type": "splunk_hec", "name": "hec", "url": url, "token_env": "ULPF_T_HEC"},
                {"type": "loki", "name": "loki", "url": url},
                {"type": "otlp", "name": "otlp", "url": url},
                {"type": "syslog", "name": "syslog", "host": "127.0.0.1", "port": cls.syslog.port,
                 "protocol": "tcp", "format": "leef"},
                {"type": "file", "name": "file", "path": os.path.join(cls.dir, "ndjson"), "view": "ocsf"},
                {"type": "parquet", "name": "lake", "path": os.path.join(cls.dir, "lake"), "partition": ["dt"]},
                {"type": "s3", "name": "s3", "bucket": "logs", "endpoint": url, "region": "us-east-1",
                 "access_key_env": "ULPF_T_S3A", "secret_key_env": "ULPF_T_S3S"},
                {"type": "azure_log_analytics", "name": "azure", "endpoint": url, "dcr_immutable_id": "dcr-1",
                 "stream_name": "Custom-ULPF", "tenant_id": "t1", "client_id": "c1",
                 "client_secret_env": "ULPF_T_AZ", "login_endpoint": url},
                {"type": "chronicle", "name": "chronicle", "customer_id": "cust", "credentials_file": creds,
                 "endpoint": url},
            ],
            "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": names}],
            "default_output": "",
        }
        from ulpf.runtime.supervisor import Runtime
        cls.rt = Runtime(load_pipeline_config(data=cfg)).start()
        cls.n = 300
        lines = demo_lines(cls.n - 1) + [b"<134>Oct 11 22:14:15 host app: REJECTME please"]
        cls.rt.ingest("test", "10.1.1.1", lines)
        ok = wait_for(lambda: all(cls.rt.runners[n].delivered_events + cls.rt.runners[n].dead_lettered >= cls.n
                                  for n in names), 90)
        cls.stats = cls.rt.stats()
        cls.summary = cls.rt.stop()
        cls.all_delivered = ok

    @classmethod
    def tearDownClass(cls):
        cls.dest.http.close()
        cls.syslog.close()

    def test_every_output_received_every_event(self):
        self.assertTrue(self.all_delivered, {n: (r["delivered_events"], r["last_error"])
                                             for n, r in self.stats["outputs"].items()})
        n = self.n
        d = self.dest
        self.assertEqual(d.count("/services/collector/event", lambda b: len([l for l in b.split(b"\n") if l])), n)
        self.assertEqual(d.count("/loki/api/v1/push", lambda b: sum(len(s["values"]) for s in json.loads(b)["streams"])), n)
        self.assertEqual(d.count("/v1/logs", lambda b: len(json.loads(b)["resourceLogs"][0]["scopeLogs"][0]["logRecords"])), n)
        self.assertEqual(d.count("/dataCollectionRules", lambda b: len(json.loads(b))), n)
        self.assertEqual(d.count("/v2/unstructuredlogentries", lambda b: len(json.loads(b)["entries"])), n)
        frames = self.syslog.frames()
        self.assertEqual(len(frames), n)
        self.assertIn(b"LEEF:1.0|ULPF|ULPF|9.0|", frames[0])
        with_files = os.path.join(self.dir, "ndjson")
        lines = []
        for f in os.listdir(with_files):
            with open(os.path.join(with_files, f), "rb") as fh:
                lines += [json.loads(line) for line in fh]
        self.assertEqual(len(lines), n)
        self.assertIn("class_uid", lines[0])            # OCSF view

    def test_lake_outputs_are_partitioned_parquet(self):
        import pyarrow.parquet as pq
        import pyarrow.dataset as ds
        lake = os.path.join(self.dir, "lake")
        self.assertTrue(any(d.startswith("dt=") for d in os.listdir(lake)))
        self.assertEqual(ds.dataset(lake, format="parquet", partitioning="hive").count_rows(), self.n)
        rows = sum(pq.read_table(io.BytesIO(b)).num_rows for b in self.dest.s3.values())
        self.assertEqual(rows, self.n)
        self.assertTrue(all(k.startswith("/logs/") and "dt=" in k for k in self.dest.s3))
        put = next(r for r in self.dest.http.requests if r["method"] == "PUT")
        self.assertTrue(put["headers"]["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"))

    def test_elasticsearch_partial_rejection_goes_to_dlq(self):
        self.assertEqual(len(self.dest.es_docs), self.n - 1)
        doc = next(iter(self.dest.es_docs.values()))
        self.assertIn("@timestamp", doc)                # ECS view
        es = self.stats["outputs"]["es"]
        self.assertEqual(es["dead_lettered"], 1)
        dlq = self.rt.dlq.read("es")
        self.assertEqual(len(dlq), 1)
        self.assertIn("REJECTME", dlq[0]["record"])
        self.assertIn("mapper_parsing_exception", dlq[0].get("reason_detail", "") + dlq[0]["reason"])

    def test_store_has_every_event_once(self):
        from ulpf.storage.database import Database
        db = Database(os.path.join(self.dir, "s.duckdb"), read_only=True)
        total, distinct = db.conn.execute("SELECT COUNT(*), COUNT(DISTINCT event_id) FROM events").fetchone()
        db.close()
        self.assertEqual((total, distinct), (self.n, self.n))


class TestOutageRecovery(unittest.TestCase):
    def test_sink_outage_buffers_then_drains_without_loss_or_duplicates(self):
        from ulpf.runtime.supervisor import Runtime
        dest = Destinations()
        dest.es_down.set()
        d = tempfile.mkdtemp(prefix="ulpf_outage_")
        os.environ["ULPF_T_ES"] = "k"
        cfg = {"workers": 1, "node": {"data_dir": d}, "inputs": [], "api": {"enabled": False},
               "evidence": {"enabled": False},
               "outputs": [{"type": "elasticsearch", "name": "es", "urls": [dest.http.url], "api_key_env": "ULPF_T_ES",
                            "retry": {"initial_ms": 50, "max_ms": 300}}],
               "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["es"]}], "default_output": ""}
        rt = Runtime(load_pipeline_config(data=cfg)).start()
        try:
            rt.ingest("t", "10.2.2.2", demo_lines(500))
            self.assertTrue(wait_for(lambda: rt.buffers["es"].stats()["events"] == 500, 30))
            time.sleep(1.5)
            self.assertEqual(len(dest.es_docs), 0)
            self.assertGreater(rt.runners["es"].retries, 0)
            self.assertFalse(rt.runners["es"].healthy)
            dest.es_down.clear()
            self.assertTrue(wait_for(lambda: rt.runners["es"].delivered_events == 500, 30))
            self.assertEqual(len(dest.es_docs), 500)
            self.assertEqual(rt.buffers["es"].stats()["events"], 0)
        finally:
            rt.stop()
            dest.http.close()


class TestSignatures(unittest.TestCase):
    def test_sigv4_matches_aws_published_example(self):
        """AWS SigV4 test suite example (IAM ListUsers, 2015-08-30)."""
        from ulpf.runtime.net import sigv4_headers
        h = sigv4_headers("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", "us-east-1", "iam",
                          "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                          headers={"content-type": "application/x-www-form-urlencoded; charset=utf-8"},
                          now=datetime.datetime(2015, 8, 30, 12, 36, 0, tzinfo=datetime.timezone.utc),
                          content_sha_header=False)
        self.assertTrue(h["authorization"].endswith(
            "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"))

    def test_cef_formatter_escapes(self):
        from ulpf.runtime.sinks.syslog_sink import format_cef
        out = format_cef({"event_type": "a|b", "message": "x=y", "severity": 7, "action": "blocked",
                          "source": {"ip": "1.2.3.4"}, "event_id": "e1"}).decode()
        self.assertTrue(out.startswith("CEF:0|ULPF|ULPF|9.0|a\\|b|x=y|7|"))
        self.assertIn("msg=x\\=y", out)


if __name__ == "__main__":
    unittest.main()
