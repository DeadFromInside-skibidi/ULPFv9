"""
The compiled core's analytics must give what the Python implementations give,
event by event: Sigma hits (``SigmaEngine.match``), route targets
(``Router.targets``), anomalies (``AnomalyDetector.analyse_batch``), format
drift (``DriftMonitor.observe``), and the whole worker with every analytics
stage on (segments, projections, derived events). Skipped when the extension is
not built.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import random
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401

import orjson  # noqa: E402

from tests.test_native_lane import corpus  # noqa: E402
from ulpf.engine.native_lane import load_engine  # noqa: E402

HAVE_ENGINE = load_engine() is not None

# Every modifier, keyword lists, wildcards, null values, value lists, aggregations
RULES = """
title: t1
id: t1
logsource: {product: ulpf}
detection:
  sel:
    message|contains: [failed, denied]
    source.ip|cidr: [10.0.0.0/8, 192.168.0.0/16, fe80::/10]
  condition: sel
---
title: t2
id: t2
logsource: {product: ulpf}
detection:
  sel:
    message|startswith: 'Accepted'
  other:
    raw_event|endswith: 'ssh2'
  condition: sel or other
---
title: t3
id: t3
logsource: {product: ulpf}
detection:
  sel:
    destination.port|gte: 1024
    destination.port|lt: 9000
  low:
    severity|lte: 3
  condition: sel and not low
---
title: t4
id: t4
logsource: {product: ulpf}
detection:
  kw:
    - 'beacon*'
    - '*inval?d user*'
    - 'MIMIKATZ'
  condition: kw
---
title: t5
id: t5
logsource: {product: ulpf}
detection:
  a:
    user.name|re: '^(root|admin)$'
  b:
    device.vendor|cased: 'Fortinet'
  c:
    parsed_fields|exists: false
  d:
    src_port|exists: true
  condition: 1 of a or b or (c and d)
---
title: t6
id: t6
logsource: {product: ulpf}
detection:
  sel:
    CommandLine|base64offset|contains: 'whoami'
  w:
    CommandLine|windash|contains: '-enc'
  condition: sel or w
---
title: t7
id: t7
logsource: {product: ulpf}
detection:
  sel:
    category: [firewall, ids_ips]
    action|all|contains: [b, l]
  n:
    rule.name: null
  condition: sel and not n
---
title: t8
id: t8
logsource: {product: ulpf}
detection:
  sel:
    source.ip|fieldref: destination.ip
  t:
    tags|contains: 'category:'
  condition: sel or t
---
title: t9
id: t9
logsource: {category: authentication}
detection:
  sel:
    action: failed
  timeframe: 5m
  condition: sel | count(user.name) by source.ip, device.hostname > 2
---
title: t10
id: t10
logsource: {product: ulpf}
detection:
  sel:
    network.protocol|re|i: '^t.p$'
    severity: [7, 8, 9]
    EventID: 4625
  bools:
    flag: true
  condition: sel or bools
---
title: t11
id: t11
logsource: {product: zeek}
detection:
  sel:
    dst_port: 53
  condition: sel
"""


def _engine(text: str):
    import yaml
    from ulpf.intelligence.sigma import SigmaEngine, compile_rule
    rules = [compile_rule(d) for d in yaml.safe_load_all(text) if d]
    return SigmaEngine(rules)


def _lane():
    from ulpf.engine.native_lane import NativeLane
    return NativeLane.create()


@unittest.skipUnless(HAVE_ENGINE, "ulpf_core batch engine not built")
class TestNativeAnalytics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lines = corpus()
        rnd = random.Random(5)
        extra = []
        for i in range(400):
            extra.append(json.dumps({"timestamp": "2026-10-21T10:00:00Z", "message": rnd.choice(
                ["login failed", "Access DENIED", "beacon sent", "ok"]), "src_ip": rnd.choice(
                ["10.1.2.3", "192.168.9.9", "8.8.8.8", "fe80::1"]), "dst_ip": rnd.choice(["10.1.2.3", "1.1.1.1"]),
                "dst_port": rnd.choice([22, 53, 1500, 8080, 9001]), "CommandLine": rnd.choice(
                ["powershell -enc d2hvYW1p", "cmd /c " + "dwhoami", "cmd.exe /enc x", "ls"]),
                "flag": rnd.choice([True, False, "TRUE", 1]), "severity": rnd.randrange(0, 11),
                "user": rnd.choice(["root", "Admin", "bob", "ROOT"]), "vendor": rnd.choice(["Fortinet", "fortinet"]),
                "EventID": rnd.choice([4625, "4625", 4624])}))
        cls.lines += extra
        cls.raws = [l.encode() for l in cls.lines]
        cls.digests = [hashlib.sha256(r).digest() for r in cls.raws]

    def _run(self, sigma_ir=None, router_ir=None):
        from ulpf import ulpf_core
        lane = _lane()
        an = ulpf_core.Analytics(sigma_ir, router_ir)
        return lane.run(self.raws, self.digests, 1, "node-t", "tcp", "10.9.8.7", "10.9.8.7", ["site:a"],
                        want_events=True, want_projections=True, analytics=an)

    def test_sigma_hits_match_python(self):
        from ulpf.intelligence.sigma import builtin_engine
        for eng in (builtin_engine(), _engine(RULES)):
            ir = eng.ir()
            self.assertIsNotNone(ir)
            res = self._run(sigma_ir=orjson.dumps(ir).decode())
            undecided = set(res.sigma_undecided)
            hits = 0
            for k, (ev, proj) in enumerate(zip(res.events, res.projections)):
                want = eng.match(ev)
                if k in undecided:
                    self.assertIsNone(proj["sigma"])
                    continue
                self.assertEqual(proj["sigma"], want, self.lines[res.native[k]][:200])
                hits += len(want)
            self.assertGreater(hits, 50)
            self.assertLess(len(undecided), len(res.native) // 20)

    def test_route_targets_match_python(self):
        from ulpf.runtime.router import Router
        rnd = random.Random(7)
        conds = [{"category_in": ["firewall", "ids_ips"]}, {"severity_gte": 7}, {"severity_lte": 3.5},
                 {"raw_format_in": ["cef", "json"]}, {"field_exists": ["user.name"]},
                 {"field_equals": {"network.protocol": "TCP"}}, {"field_equals": {"destination.port": 53.0}},
                 {"field_equals": {"rule.name": None}}, {"kind_in": ["log"]}, {"input_in": ["tcp", "x"]},
                 {"source_in": ["10.9.8.7"]}, {"field_exists": ["threat.cve"]}, {}]
        for trial in range(25):
            routes = [{"name": f"r{i}", "when": dict(rnd.choice(conds)), "to": rnd.sample(["a", "b", "c"], 2),
                       "final": rnd.random() < 0.3} for i in range(rnd.randrange(1, 5))]
            router = Router(routes, rnd.choice([None, "d"]))
            rir, names = router.ir()
            res = self._run(router_ir=orjson.dumps(rir).decode())
            py = Router(routes, router.default)
            for k, ev in enumerate(res.events):
                got = res.targets[k] if res.targets is not None else res.targets_uniform
                self.assertEqual([names[j] for j in got], py.targets(ev), (routes, self.lines[res.native[k]]))
            self.assertEqual(res.unrouted, py.unrouted)

    def test_anomalies_match_python(self):
        from ulpf import ulpf_core
        from ulpf.intelligence.anomaly import AnomalyDetector, NativeAnomalyDetector
        rnd = random.Random(9)
        opts = dict(new_ip_warmup=50, new_ip_external_only=True, new_ip_max_novelty=0.5, baseline_window=40)
        py, nat = AnomalyDetector(**opts), NativeAnomalyDetector(ulpf_core.AnomalyState, **opts)
        res = self._run()
        events = res.events
        for b in range(60):
            batch = []
            for _ in range(rnd.randrange(1, 60)):
                e = json.loads(json.dumps(rnd.choice(events)))
                r = rnd.random()
                if r < 0.1:
                    e["severity"] = rnd.choice([0, 10, 9])
                if r < 0.2:
                    e["network"]["bytes_in"] = rnd.choice([1, 10 ** 6, 2 ** 62, 3.5, True, "12", None])
                    e["network"]["bytes_out"] = rnd.choice([0, 7, 2 ** 63 - 1, -5])
                if r < 0.3:
                    e["source"]["ip"] = f"203.0.113.{rnd.randrange(256)}"
                if r < 0.05:
                    e["destination"]["ip"] = rnd.choice([12, 12.0, True, "", None, "abc"])
                batch.append(e)
            self.assertEqual(nat.analyse_batch(batch), py.analyse_batch(batch), b)
        # native batches: the core reads the events where they are
        py2, nat2 = AnomalyDetector(**opts), NativeAnomalyDetector(ulpf_core.AnomalyState, **opts)
        for i in range(3):
            res = self._run()
            self.assertEqual(nat2.analyse_native(res.batch, []), py2.analyse_batch(res.events), i)

    def test_drift_matches_python(self):
        from ulpf import ulpf_core
        from ulpf.runtime.analytics import DriftMonitor, NativeDriftMonitor
        d = tempfile.mkdtemp(prefix="ulpf_drift_")
        py = DriftMonitor(sample_lines=50, min_interval_seconds=0, data_dir=d)
        nat = NativeDriftMonitor(ulpf_core.DriftState, sample_lines=50, min_interval_seconds=0, data_dir=d)
        from ulpf.runtime.analytics import structure_signature
        events = self._run().events
        by_sig: dict = {}
        for e in events:
            by_sig.setdefault(e["raw_format"], {}).setdefault(structure_signature(e), []).append(e)
        # the format with the most distinct structures: its two largest groups alternate
        fmt = max(by_sig, key=lambda f: len(by_sig[f]))
        groups = sorted(by_sig[fmt].values(), key=len, reverse=True)[:2]
        self.assertEqual(len(groups), 2)
        rnd = random.Random(3)
        fired = 0

        def neutral(evs):
            out = json.loads(json.dumps(evs, default=str))
            for x in out:
                x["timestamp"] = x["metadata"]["ingestion_time"] = "now"
            return out
        for b in range(80):
            # a source whose structure changes every ten batches (and some other traffic)
            g = groups[(b // 10) % 2]
            batch = [json.loads(json.dumps(rnd.choice(g if rnd.random() < 0.9 else events)))
                     for _ in range(rnd.randrange(5, 60))]
            a, n = py.observe("tcp", "src-1", batch), nat.observe("tcp", "src-1", batch)
            self.assertEqual(neutral(n), neutral(a), b)
            fired += len(a)
        self.assertGreater(fired, 2)
        # native batches observed in place
        py2 = DriftMonitor(sample_lines=50, min_interval_seconds=0, data_dir=d)
        nat2 = NativeDriftMonitor(ulpf_core.DriftState, sample_lines=50, min_interval_seconds=0, data_dir=d)
        for i in range(3):
            res = self._run()
            self.assertEqual(neutral(nat2.observe_native("tcp", "s", res.batch, [])),
                             neutral(py2.observe("tcp", "s", res.events)), i)

    def test_worker_outputs_match_the_python_path_with_all_analytics(self):
        """Python vs native worker: every stage on, a field route and a non-DuckDB output."""
        import pyarrow.parquet as pq
        from ulpf.config import load_pipeline_config
        from ulpf.runtime.worker import WorkerState
        out = {}
        for mode in ("python", "native"):
            d = tempfile.mkdtemp(prefix=f"ulpf_an_{mode}_")
            cfg = load_pipeline_config(data={
                "node": {"data_dir": d}, "api": {"enabled": False},
                "inputs": [{"type": "syslog", "name": "tcp", "protocol": "tcp", "host": "127.0.0.1", "port": 1,
                            "tags": ["site:a"]}],
                "outputs": [{"type": "duckdb", "name": "store", "path": os.path.join(d, "s.duckdb")},
                            {"type": "file", "name": "alerts", "path": os.path.join(d, "alerts"), "view": "ocsf"}],
                "routes": [{"name": "hi", "when": {"severity_gte": 7}, "to": ["alerts"]},
                           {"name": "all", "when": {"kind_in": ["log", "anomaly", "drift"]}, "to": ["store"]}],
                "analytics": {"drift": {"sample_lines": 200, "min_interval_seconds": 0}},
            }).data
            cfg.update(_buffer_root=os.path.join(d, "buffers"), _data_dir=d, _learned_dir=os.path.join(d, "learned"))
            ws = WorkerState(cfg, "node-t", 0)
            if mode == "python":
                ws.native = ws.native_analytics = None
                from ulpf.intelligence.anomaly import AnomalyDetector
                from ulpf.runtime.analytics import DriftMonitor
                ws.anomaly = AnomalyDetector(new_ip_warmup=10_000, new_ip_external_only=True, new_ip_max_novelty=0.01)
                ws.drift = DriftMonitor(sample_lines=200, min_interval_seconds=0, data_dir=d)
            else:
                self.assertIsNotNone(ws.native_analytics)
            results = []
            for i in range(0, len(self.raws), 1000):
                r = ws.process("tcp", "10.9.8.7", i + 1, self.raws[i:i + 1000], self.digests[i:i + 1000], time.time())
                self.assertEqual(r["t"], "done", r)
                results.append({k: r[k] for k in ("counts", "written", "derived_summary")} | {"proj": r["proj"]})
            segs = {}
            for sink in ("store", "alerts"):
                rows = []
                for path in sorted(glob.glob(os.path.join(d, "buffers", sink, "*"))):
                    if path.endswith(".parquet"):
                        for row in pq.read_table(path).to_pylist():
                            ev = orjson.loads(row["normalised_json"])
                            ev["metadata"]["ingestion_time"] = "now"
                            ev["metadata"]["processing_time_ms"] = None
                            if ev.get("timestamp_original") is None:     # clock readings (log and derived)
                                ev["timestamp"] = "now"
                            rows.append((row["event_id"], ev, row["parsed_fields"], row["tags"]))
                    else:
                        with open(path, "rb") as f:
                            for line in f.read().splitlines():
                                doc = orjson.loads(line)
                                x = doc["unmapped"]["x_ulpf"]["event"]
                                x["metadata"]["ingestion_time"] = "now"
                                x["metadata"]["processing_time_ms"] = None
                                doc.pop("metadata", None)
                                if x.get("timestamp_original") is None:
                                    x["timestamp"] = "now"
                                    doc.pop("time", None)
                                rows.append(doc)
                segs[sink] = rows
            out[mode] = (results, segs)
            ws.close()
        py_res, py_segs = out["python"]
        nat_res, nat_segs = out["native"]
        for a, b in zip(py_res, nat_res):
            self.assertEqual(a["written"], b["written"])
            self.assertEqual(a["derived_summary"], b["derived_summary"])
            self.assertEqual(len(a["proj"]), len(b["proj"]))
            for pa, pb in zip(a["proj"], b["proj"]):
                self.assertEqual(pa.get("sigma"), pb.get("sigma"), pa)
                self.assertEqual(pa["event_id"], pb["event_id"])
        for sink in ("store", "alerts"):
            self.assertEqual(len(py_segs[sink]), len(nat_segs[sink]), sink)
            self.assertGreater(len(py_segs[sink]), 10, sink)
            for a, b in zip(py_segs[sink], nat_segs[sink]):
                self.assertEqual(a, b, sink)


if __name__ == "__main__":
    unittest.main()
