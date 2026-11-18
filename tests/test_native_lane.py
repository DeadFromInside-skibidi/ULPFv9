"""
The compiled batch engine (native lane) must produce what the Python pipeline
produces, record by record: the same event (values and key order) and the same
store row. Skipped when the extension is not built with the batch engine.

Fields that legitimately differ: the "now" values of an event without a source
timestamp (the core reads the clock once per batch) and the sampled
``metadata.processing_time_ms``.
"""
from __future__ import annotations

import glob
import os
import random
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401

import hashlib  # noqa: E402

import orjson  # noqa: E402

from ulpf.engine.native_lane import load_engine  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HAVE_ENGINE = load_engine() is not None

EDGE = [
    "<34>Oct 11 22:14:15 db01 sshd[4721]: Failed password for root from 45.33.32.156 port 51234 ssh2",
    "<34>Oct  1 02:04:05 db01 sshd[4721]: Accepted publickey for invalid user bob from 10.1.1.1 port 22 ssh2",
    '<165>1 2026-10-21T10:00:03Z waf-prod-01 app 101 ID47 [attack severity="high"][x@1 k="v\\"q"] Suspicious '
    "beacon from 10.0.2.15 to 91.121.87.10:8080",
    "<165>1 2026-10-21T10:00:03.123456+05:30 host - - - - message without sd",
    "<165>1 - host app - - - no timestamp",
    "<13>Oct 11 22:14:15 fw01 %ASA-4-106023: Deny tcp src outside:10.1.1.1/1234 dst inside:10.2.2.2/80",
    "Oct 11 22:14:15 router1 %LINK-3-UPDOWN: Interface Gi0/1, changed state to down",
    "Oct 11 22:14:15 host kernel: 10.0.0.1(1234) -> 10.0.0.2(80) dropped port=99",
    "CEF:0|Check Point|VPN-1 & FireWall-1|R81.20|Drop|Firewall Rule Drop|8|rt=2026-10-21T10:00:01Z "
    "src=45.33.32.156 dst=10.0.1.50 spt=12345 dpt=4444 proto=TCP act=Drop",
    "<134>Oct 21 10:00:00 gw CEF:0|Vendor|Prod|1.0|100|Login failed for x|Very-High|suser=bob duser=alice "
    "msg=bad password here cs1Label=policy cs1=strict",
    "CEF:0|A\\|B|P|1|sig|name|3|msg=a\\=b c\\\\d rt=1760000000123 cat=web",
    "CEF:0|V|P|1|2|allow|7.5|rt=Oct 21 2026 10:00:00 in=100 out=50 request=http://x/y",
    "CEF:0|V|P|1|2|n",
    "LEEF:2.0|IBM|QRadar|7.5|SecurityAlert|devTime=2026-10-21T10:00:00Z\tsrc=185.220.101.33\t"
    "dst=10.0.1.99\tusrName=jdoe\tsev=7\tmsg=Brute force threshold exceeded",
    "LEEF:2.0|V|P|1|42|^|src=1.2.3.4^dst=5.6.7.8^cat=ids attack^sev=high",
    "LEEF:1.0|V|P|1|42|src=1.2.3.4 dst=5.6.7.8 devTime=1760000000",
    'date=2026-10-21 time=10:00:04 devname="FGT-EDGE-01" type="traffic" srcip=192.168.1.105 '
    'srcport=51234 dstip=91.121.87.10 dstport=443 proto=6 action="deny" user="eng01"',
    "level=error a=1 b=2 c=3:d=4,e=5;f=6 msg=disk full on /var",
    'k1="unterminated v1 k2=x k3=y k4=z',
    '{"timestamp":"2026-10-21T10:00:04Z","event_type":"alert","src_ip":"177.54.150.200",'
    '"src_port":53211,"dest_ip":"10.0.0.5","dest_port":53,"proto":"UDP",'
    '"alert":{"signature":"ET MALWARE DNS Query","severity":1}}',
    '{"ts":1760000000.5,"severity":7.6,"bytes_in":"12","bytes_out":30,"source":"edr","user":{"name":"x"}}',
    '{"time":"Oct 21 2026 10:00:00","level":"warn","items":[{"a":1},{"b":2}],"tags":["x","y"],'
    '"vendor":"","observer":{"vendor":"Acme"},"flag":true,"n":null,"big":1e16}',
    '{"message":"no timestamp here","severity":"critical","src":"10.0.0.1","dst_port":"8080.0"}',
    '{"timestamp":"2026-10-21T10:00:00.1Z","severity":"inf"}',           # delegated (Python decides)
    '{"a": NaN}',                                                         # delegated
    "plain text that is nothing in particular",                           # delegated (raw fallback)
    "a,b,c,d,e",                                                          # delegated (CSV)
    "#Fields: date time c-ip",                                            # delegated (W3C directive)
    "   ",                                                                # delegated (skipped)
    "<Event><System><EventID>4625</EventID></System></Event>",            # delegated (XML)
    "café latte=1 b=2 c=3",                                         # delegated (non-ASCII)
]


def corpus() -> list[str]:
    lines = list(EDGE)
    for path in sorted(glob.glob(os.path.join(ROOT, "demo_data", "*.log"))):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines += [l.rstrip("\n") for l in f if l.strip()]
    sys.path.insert(0, ROOT)
    from benchmarks.generator import DeterministicGenerator
    g = DeterministicGenerator(seed=7)
    gens = [g.gen_syslog3164, g.gen_syslog5424, g.gen_cef, g.gen_leef, g.gen_json, g.gen_kv, g.gen_csv, g.gen_xml]
    rnd = random.Random(11)
    lines += [rnd.choice(gens)() for _ in range(10000)]
    return lines


def _neutral(ev: dict) -> dict:
    ev = orjson.loads(orjson.dumps(ev))
    meta = ev["metadata"]
    meta["ingestion_time"] = "now"
    meta["processing_time_ms"] = None
    if ev.get("timestamp_original") is None:
        ev["timestamp"] = "now"
    return ev


def _worker(d: str, row_mac: bool = False):
    from ulpf.config import load_pipeline_config
    from ulpf.runtime.keys import RowKeyChain
    from ulpf.runtime.worker import WorkerState
    cfg = load_pipeline_config(data={
        "node": {"data_dir": d}, "api": {"enabled": False},
        "inputs": [{"type": "syslog", "name": "tcp", "protocol": "tcp", "host": "127.0.0.1", "port": 1,
                    "tags": ["site:a"]}],
        "outputs": [{"type": "duckdb", "name": "store", "path": os.path.join(d, "s.duckdb")}],
        "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["store"]}],
    }).data
    cfg.update(_buffer_root=os.path.join(d, "buffers"), _data_dir=d, _learned_dir=os.path.join(d, "learned"))
    if row_mac:
        cfg["_row_ratchet"] = RowKeyChain(0, b"k" * 32, 50).snapshot()
    return WorkerState(cfg, "node-t", 0)


@unittest.skipUnless(HAVE_ENGINE, "ulpf_core batch engine not built")
class TestNativeLane(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lines = corpus()
        cls.dir = tempfile.mkdtemp(prefix="ulpf_lane_")
        cls.ws = _worker(cls.dir, row_mac=True)
        cls.lane = cls.ws.native
        cls.raws = [l.encode("utf-8") for l in cls.lines]
        cls.digests = [hashlib.sha256(r).digest() for r in cls.raws]

    def _reference(self, i: int, seq: int, source: str = "10.9.8.7"):
        counts = {"skipped": 0, "failed": 0, "raw_fallback": 0, "auto_parsed": 0}
        return self.ws._python_event("tcp", source, source, source, ["site:a"], None, seq, self.raws[i],
                                     self.digests[i], counts)

    def test_events_and_rows_match_the_python_pipeline(self):
        from ulpf.storage.database import EVENT_COLUMNS, event_to_row, row_mac
        first = 1000
        res = self.lane.run(self.raws, self.digests, first, "node-t", "tcp", "10.9.8.7", "10.9.8.7", ["site:a"],
                            row_key=self.ws.row_keys, want_events=True, want_projections=True)
        self.assertEqual(sorted(res.native + res.delegated), list(range(len(self.raws))))
        ratio = len(res.native) / len(self.raws)
        self.assertGreater(ratio, 0.6, ratio)
        rows = res.table.to_pylist()
        i_mac = EVENT_COLUMNS.index("row_mac")
        mismatches = []
        for k, i in enumerate(res.native):
            ref = self._reference(i, first + i)
            self.assertIsNotNone(ref, self.lines[i])
            a, b = _neutral(res.events[k]), _neutral(ref)
            if orjson.dumps(a) != orjson.dumps(b):
                mismatches.append((self.lines[i], a, b))
                continue
            got = rows[k]
            want = dict(zip(EVENT_COLUMNS, event_to_row(ref)))
            for col in EVENT_COLUMNS:
                if col in ("normalised_json", "row_mac"):
                    continue
                g, w = got[col], want[col]
                if col in ("parsed_fields", "tags"):
                    g, w = orjson.loads(g), orjson.loads(w)
                if col == "timestamp" and ref.get("timestamp_original") is None:
                    continue
                if g != w:
                    mismatches.append((self.lines[i], col, g, w))
            norm = _neutral({**orjson.loads(got["normalised_json"]), "raw_event": None, "parsed_fields": None})
            ref_norm = _neutral({**orjson.loads(want["normalised_json"]), "raw_event": None, "parsed_fields": None})
            if norm != ref_norm:
                mismatches.append((self.lines[i], "normalised_json"))
            # the core's MAC verifies with the Python implementation over the stored values
            values = tuple(got[c] for c in EVENT_COLUMNS)
            key = self.ws.row_keys.key_for_seq(first + i)
            self.assertEqual(values[i_mac], row_mac(key, values), self.lines[i])
            self.assertEqual(res.projections[k]["event_id"], ref["event_id"])
        self.assertEqual(mismatches[:3], [], f"{len(mismatches)} mismatching records")

    def test_delegated_records_are_the_ones_python_must_decide(self):
        res = self.lane.run(self.raws[:len(EDGE)], self.digests[:len(EDGE)], 1, "node-t", "tcp", "s", "", [],
                            want_events=True)
        delegated = {self.lines[i] for i in res.delegated}
        for line in ('{"timestamp":"2026-10-21T10:00:00.1Z","severity":"inf"}', '{"a": NaN}',
                     "plain text that is nothing in particular", "a,b,c,d,e", "#Fields: date time c-ip", "   ",
                     "café latte=1 b=2 c=3", "CEF:0|V|P|1|2|n"):
            self.assertIn(line, delegated)
        self.assertIn(EDGE[0], {self.lines[i] for i in res.native})

    def test_worker_columnar_and_hybrid_lanes_store_the_same_rows(self):
        """The whole worker: native columnar, native hybrid and pure Python produce the same store rows."""
        import pyarrow.parquet as pq
        from ulpf.storage.database import EVENT_COLUMNS
        out = {}
        for mode in ("python", "hybrid", "columnar"):
            d = tempfile.mkdtemp(prefix=f"ulpf_lane_{mode}_")
            ws = _worker(d)
            if mode == "python":
                ws.native = None
            if mode == "columnar":
                ws.anomaly = ws.drift = None
            else:
                ws.drift = None          # drift samples by wall clock: keep the runs comparable
            n = 2000
            res = ws.process("tcp", "10.9.8.7", 1, self.raws[:n], self.digests[:n], time.time())
            self.assertEqual(res["t"], "done", res)
            files = glob.glob(os.path.join(d, "buffers", "store", "*.parquet"))
            self.assertEqual(len(files), 1)
            # derived anomaly events exist only where anomaly detection runs: compare the log events
            rows = [r for r in pq.read_table(files[0]).to_pylist()
                    if orjson.loads(r["normalised_json"]).get("event_kind") == "log"]
            out[mode] = [{c: r[c] for c in EVENT_COLUMNS if c not in ("normalised_json", "row_mac")}
                         for r in rows]
            for r, full in zip(out[mode], rows):
                r["tags"] = orjson.loads(r["tags"])
                r["parsed_fields"] = orjson.loads(r["parsed_fields"])
                ev = orjson.loads(full["normalised_json"])
                if ev.get("timestamp_original") is None:
                    r["timestamp"] = "now"
            if mode != "python":
                self.assertGreater(res["counts"]["native"], n // 2)
            ws.close()
        self.assertEqual(len(out["python"]), len(out["columnar"]))
        for a, b, c in zip(out["python"], out["hybrid"], out["columnar"]):
            self.assertEqual(a, b)
            self.assertEqual(a, c)

    def test_native_timestamps_agree_with_python(self):
        from ulpf import ulpf_core
        from ulpf.engine.normalizer import _parse_ts
        rnd = random.Random(3)
        samples = []
        for _ in range(4000):
            sec = rnd.randrange(946684800, 4102444800)
            frac = rnd.choice(["", ".5", ".123", ".999999", ".0000001", "." + str(rnd.randrange(10**6)).zfill(6)])
            samples.append(f"{sec}{frac}")
            samples.append(f"{sec * 1000 + rnd.randrange(1000)}{frac}")
            t = time.gmtime(sec)
            samples.append(time.strftime("%Y-%m-%dT%H:%M:%S", t) + rnd.choice(["Z", "+05:30", "-08:00", ".123Z", ".123456"]))
            samples.append(time.strftime("%b %d %Y %H:%M:%S", t) + rnd.choice(["", ".5", ".25"]))
        for s in samples:
            got = ulpf_core.parse_ts_native(s)
            if got is not None:
                self.assertEqual(got, _parse_ts(s), s)


if __name__ == "__main__":
    unittest.main()
