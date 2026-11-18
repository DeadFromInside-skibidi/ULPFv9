"""
Lakehouse: hot ring → Delta cold tier → compaction → federated queries.

Every count is checked against the generated events: nothing lost, nothing counted twice
across the hot/cold boundary, after compaction, or after a crash between commit and ring mark.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
import random
import shutil
import sys
import tempfile
import time
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401
from tests.fakes import FakeHTTP  # noqa: E402

try:
    from ulpf import ulpf_core
    HAVE = hasattr(ulpf_core, "HotRing")
except ImportError:
    HAVE = False

T0 = _dt.datetime(2026, 10, 25, 8, 0, tzinfo=_dt.timezone.utc)
KEY_ENV = "ULPF_T_LAKE_KEY"


def events(n: int, seed: int = 1, tenants=("acme", "globex"), hours: int = 3, start: int = 0):
    rnd = random.Random(seed)
    out = []
    for i in range(start, start + n):
        ts = T0 + _dt.timedelta(seconds=(i * 3600 * hours) // max(n + start, 1))
        out.append({
            "event_id": f"e{i}", "timestamp": ts.isoformat().replace("+00:00", "Z"), "category": "network",
            "severity": i % 11, "source": {"ip": f"10.{i % 7}.{i % 13}.{i % 251}", "port": 1024 + i % 5000},
            "destination": {"ip": f"192.168.{i % 3}.{i % 17}", "port": 443}, "user": {"name": f"user{i % 50}"},
            "metadata": {"input": tenants[i % len(tenants)]}, "evidence": {"journal_seq": i, "raw_hash": "h"},
            "raw_event": f"line {i} " + "x" * rnd.randrange(50, 300),
            "parsed_fields": {"sha256": hashlib.sha256(str(i).encode()).hexdigest()} if i % 5 == 0 else {}})
    return out


def lake_opts(root: str, encrypted: bool = False, **extra) -> dict:
    o = {"type": "lakehouse", "name": "lake", "storage": {"type": "local", "path": os.path.join(root, "table")},
         "hot": {"path": os.path.join(root, "hot", "ring"), "capacity_mb": 64},
         "tenant_by_input": {"acme": "acme", "globex": "globex"},
         "compaction": {"enabled": False, "min_mb": 128, "max_mb": 512}, "flush_seconds": 3600}
    if encrypted:
        o["encryption"] = {"key_env": KEY_ENV}
    o.update(extra)
    return o


@unittest.skipUnless(HAVE, "ulpf_core hot tier not built")
class TestLakehouse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ[KEY_ENV] = base64.b64encode(os.urandom(32)).decode()

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="ulpf_lake_")
        self.addCleanup(shutil.rmtree, self.root, True)

    def _sink(self, opts):
        from ulpf.runtime.buffer import Segment
        from ulpf.runtime.sinks.lakehouse import LakehouseSink
        s = LakehouseSink("lake", opts, {"data_dir": self.root})
        s.open()
        self.addCleanup(s.close)
        seg = iter(range(10**6))

        def put(evs):
            n = next(seg)
            s.deliver(s.encode(evs), Segment(f"L-{n}-{n}-{len(evs)}", "", "L", n, n, len(evs), 0))
        return s, put

    def _count(self, svc, **kw):
        t, st = svc.query.run("SELECT count(*) AS n FROM events", **kw)
        return t.column("n")[0].as_py(), st

    def test_hot_cold_federation_exact_counts_and_pruning(self):
        s, put = self._sink(lake_opts(self.root))
        svc = s.service
        evs = events(6000)
        for i in range(0, 4000, 500):
            put(evs[i:i + 500])
        svc.flush_once()                                     # 4000 cold
        for i in range(4000, 6000, 500):
            put(evs[i:i + 500])                              # 2000 hot
        n, st = self._count(svc)
        self.assertEqual((n, st["hot_rows"]), (6000, 2000))
        self.assertEqual(self._count(svc, tenant="acme")[0], 3000)
        start = T0 + _dt.timedelta(hours=1)
        end = T0 + _dt.timedelta(hours=1, minutes=59, seconds=59)
        want = sum(1 for e in evs if e["metadata"]["input"] == "acme"
                   and start <= _dt.datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")) <= end)
        n, st = self._count(svc, tenant="acme", start=start, end=end)
        self.assertEqual(n, want)
        self.assertLess(st["files_after_partitions"], st["files_total"])
        # bloom pruning: an IP that is nowhere skips every cold file; one that exists is found
        n, st = self._count(svc, eq={"source_ip": "172.31.1.1"})
        self.assertEqual((n, st["files_scanned"]), (0, 0))
        ip = evs[123]["source"]["ip"]
        n, st = self._count(svc, eq={"source_ip": ip})
        self.assertEqual(n, sum(1 for e in evs if e["source"]["ip"] == ip))
        self.assertLess(st["files_scanned"], st["files_after_stats"] + 1)
        sha = evs[100]["parsed_fields"]["sha256"]
        self.assertEqual(self._count(svc, eq={"hash_sha256": sha})[0], 1)
        # redelivering a segment that is still in the ring stores nothing new
        from ulpf.runtime.buffer import Segment
        s.deliver(s.encode(evs[4000:4500]), Segment("L-8-8-500", "", "L", 8, 8, 500, 0))
        self.assertEqual(self._count(svc)[0], 6000)
        svc.flush_once()
        self.assertEqual(self._count(svc)[0], 6000)
        # zonemaps and page index are in the files
        import pyarrow.parquet as pq
        a = next(iter(svc.table.snapshot().files.values()))
        md = pq.ParquetFile(os.path.join(self.root, "table", *a["path"].split("/"))).metadata
        self.assertTrue(md.row_group(0).column(DATA_TS).statistics.has_min_max)
        self.assertIn("ZSTD", md.row_group(0).column(0).compression)

    def test_encrypted_tier_mac_chain_and_key_required(self):
        s, put = self._sink(lake_opts(self.root, encrypted=True))
        svc = s.service
        evs = events(3000, seed=2)
        for i in range(0, 3000, 300):
            put(evs[i:i + 300])
            if i % 900 == 0:
                svc.flush_once()
        svc.flush_once()
        self.assertEqual(self._count(svc)[0], 3000)
        ip = evs[7]["source"]["ip"]
        self.assertEqual(self._count(svc, eq={"source_ip": ip})[0], sum(1 for e in evs if e["source"]["ip"] == ip))
        snap = svc.table.snapshot()
        for a in snap.files.values():
            with open(os.path.join(self.root, "table", *a["path"].split("/")), "rb") as f:
                f.seek(-4, 2)
                self.assertEqual(f.read(), b"PARE")            # encrypted footer
            side = open(os.path.join(self.root, "table", *a["tags"]["ulpf.bloom"].split("/")), "rb").read()
            self.assertNotIn(b"ULPFBLM1", side)              # sealed sidecar
        self.assertGreaterEqual(svc.table.verify()["commits"], 2)
        # without the key: no plan over encrypted files
        from ulpf.lake.delta import DeltaTable, TamperedLog
        from ulpf.lake.query import LakeQuery
        with self.assertRaises(PermissionError):
            LakeQuery(DeltaTable(svc.store)).run("SELECT count(*) FROM events")
        # an edited commit breaks the chain
        log = os.path.join(self.root, "table", "_delta_log", f"{snap.version:020d}.json")
        body = open(log, "rb").read()
        with open(log, "wb") as f:
            f.write(body.replace(b'"dataChange":true', b'"dataChange":false', 1))
        with self.assertRaises(TamperedLog):
            DeltaTable(svc.store, svc.key).verify()

    def test_compaction_preserves_rows_and_merges_files(self):
        s, put = self._sink(lake_opts(self.root))
        svc = s.service
        evs = events(5000, seed=3, tenants=("acme",), hours=1)
        for i in range(0, 5000, 250):
            put(evs[i:i + 250])
            svc.flush_once()
        before = len(svc.table.snapshot().files)
        self.assertEqual(before, 20)
        replaced = svc.compact_once(force=True)
        snap = svc.table.snapshot()
        self.assertEqual((replaced, len(snap.files)), (20, 1))
        self.assertEqual(self._count(svc)[0], 5000)
        t, _ = svc.query.run("SELECT count(DISTINCT event_id) AS n, sum(journal_seq) AS s FROM events")
        self.assertEqual(t.to_pylist()[0], {"n": 5000, "s": sum(range(5000))})
        self.assertFalse(json.loads(next(iter(snap.files.values()))["stats"]) is None)
        # vacuum deletes the replaced files once past the retention window
        svc.vacuum_hours = 0
        time.sleep(0.01)
        self.assertEqual(svc.vacuum_once(), 20)
        self.assertEqual(self._count(svc)[0], 5000)

    def test_crash_between_commit_and_ring_mark_does_not_duplicate(self):
        from ulpf.lake.service import LakeService
        opts = lake_opts(self.root)
        s, put = self._sink(opts)
        svc = s.service
        put(events(1000, seed=4))
        ring_flushed_before = svc.hot.ring.flushed
        svc.hot.mark_flushed = lambda pos: None              # crash: the ring is never marked
        svc.flush_once()
        self.assertEqual(svc.hot.ring.flushed, ring_flushed_before)
        svc.query.hot = None
        s.service = None                                     # abandon without the final flush
        svc._stop.set()
        svc2 = LakeService("lake", opts, self.root).start()
        self.addCleanup(svc2.stop)
        self.assertEqual(svc2.hot.ring.flushed, svc2.hot.ring.head)    # restored from the txn
        self.assertEqual(self._count(svc2)[0], 1000)
        self.assertEqual(svc2.flush_once(), 0)

    def test_checkpoint_replay_matches_log(self):
        from ulpf.lake.delta import DeltaTable
        s, put = self._sink(lake_opts(self.root))
        svc = s.service
        for k in range(12):
            put(events(100, seed=k, start=k * 100))
            svc.flush_once()
        self.assertTrue(svc.store.exists("_delta_log/_last_checkpoint"))
        fresh = DeltaTable(svc.store).snapshot()
        live = svc.table.snapshot()
        self.assertEqual((fresh.version, set(fresh.files), fresh.txns), (live.version, set(live.files), live.txns))

    def test_s3_store_conditional_commits_and_streamed_upload(self):
        from ulpf.lake.store import Exists, S3Store
        objects = {}

        def s3(req):
            key = urllib.parse.unquote(req["path"].split("?")[0][len("/bkt/"):])
            if req["method"] == "PUT":
                h = req["headers"]
                if hashlib.sha256(req["body"]).hexdigest() != h.get("x-amz-content-sha256") or \
                        "AWS4-HMAC-SHA256" not in h.get("authorization", ""):
                    return 403, {}, b"bad signature"
                if h.get("if-none-match") == "*" and key in objects:
                    return 412, {}, b""
                objects[key] = req["body"]
                return 200, {}, b""
            if req["method"] == "HEAD":
                return (200 if key in objects else 404), {}, b""
            if req["method"] == "DELETE":
                objects.pop(key, None)
                return 204, {}, b""
            if "list-type=2" in req["path"]:
                q = urllib.parse.parse_qs(req["path"].split("?", 1)[1])
                pre = q.get("prefix", [""])[0]
                items = "".join(f"<Contents><Key>{k}</Key><Size>{len(v)}</Size></Contents>"
                                for k, v in sorted(objects.items()) if k.startswith(pre))
                return 200, {}, f"<ListBucketResult><IsTruncated>false</IsTruncated>{items}</ListBucketResult>".encode()
            return (200, {}, objects[key]) if key in objects else (404, {}, b"")

        fake = FakeHTTP(s3)
        self.addCleanup(fake.close)
        st = S3Store("bkt", "lake", "us-east-1", "AK", "SK", endpoint=fake.url, path_style=True)
        st.put_if_absent("_delta_log/00000000000000000000.json", b"{}")
        with self.assertRaises(Exists):
            st.put_if_absent("_delta_log/00000000000000000000.json", b"{}")
        p = os.path.join(self.root, "big.bin")
        with open(p, "wb") as f:
            f.write(os.urandom(3 << 20))
        st.put_file("tenant_id=a/date=2026-10-25/hour=08/x.parquet", p)
        out = os.path.join(self.root, "back.bin")
        st.get_file("tenant_id=a/date=2026-10-25/hour=08/x.parquet", out)
        self.assertEqual(open(out, "rb").read(), open(p, "rb").read())
        self.assertEqual([k for k, _ in st.list("_delta_log")], ["_delta_log/00000000000000000000.json"])
        # a whole table on the fake S3: flush, query through the download cache
        from ulpf.lake.service import LakeService
        import ulpf.lake.service as service_mod
        orig = service_mod.open_store
        service_mod.open_store = lambda o: st
        try:
            svc = LakeService("s3lake", lake_opts(self.root), self.root).start()
        finally:
            service_mod.open_store = orig
        self.addCleanup(svc.stop)
        from ulpf.lake.schema import SCHEMA
        import pyarrow as pa
        from ulpf.lake import schema
        rows = schema.rows(events(500, seed=9), lambda e: "acme")
        svc.hot.append(pa.Table.from_pylist(rows, schema=SCHEMA), "seg-1")
        svc.flush_once()
        svc.query.hot = None
        self.assertEqual(self._count(svc)[0], 500)
        self.assertTrue(any(k.endswith(".zstd.parquet") for k in objects))

    def test_flight_query_with_token(self):
        import pyarrow.flight as fl
        os.environ["ULPF_T_FLIGHT"] = "flight-secret"
        port = _free_port()
        s, put = self._sink(lake_opts(self.root, flight={"enabled": True, "port": port, "token_env": "ULPF_T_FLIGHT"}))
        put(events(800, seed=5))
        client = fl.FlightClient(f"grpc+tcp://127.0.0.1:{port}")
        ticket = fl.Ticket(json.dumps({"sql": "SELECT count(*) AS n FROM events", "tenant": "globex"}).encode())
        opts = fl.FlightCallOptions(headers=[(b"authorization", b"Bearer flight-secret")])
        self.assertEqual(client.do_get(ticket, opts).read_all().column("n")[0].as_py(), 400)
        with self.assertRaises(fl.FlightUnauthenticatedError):
            client.do_get(ticket, fl.FlightCallOptions(headers=[(b"authorization", b"Bearer nope")])).read_all()
        s.service.flush_once()
        self.assertEqual(len(list(client.list_flights(options=opts))), 6)

    def test_cli_status_query_verify(self):
        import subprocess
        s, put = self._sink(lake_opts(self.root, encrypted=True))
        put(events(400, seed=6))
        s.service.flush_once()
        cfg = os.path.join(self.root, "pipeline.json")
        with open(cfg, "w") as f:
            json.dump({"node": {"data_dir": self.root}, "inputs": [], "outputs": [lake_opts(self.root, encrypted=True)]}, f)
        run = lambda *a: subprocess.run([sys.executable, "-m", "ulpf.main", "lake", *a, "--config", cfg],
                                        capture_output=True, text=True, timeout=120, env=os.environ)
        r = run("query", "--tenant", "acme")
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        self.assertEqual(json.loads(r.stdout.strip().splitlines()[-1]), {"events": 200})
        r = run("verify")
        self.assertIn("VALID", r.stdout, r.stderr[-800:])
        self.assertEqual(json.loads(run("status").stdout)["files"], 6)      # 2 tenants x 3 hours

    def test_config_and_defence_rules(self):
        from ulpf.config import load_pipeline_config
        from ulpf.config.schema import ConfigError
        base = {"inputs": [], "outputs": [lake_opts(self.root)]}
        load_pipeline_config(data=base)
        with self.assertRaises(ConfigError) as e:
            load_pipeline_config(data={**base, "mode": "defence"})
        self.assertIn("lake_encryption", str(e.exception))
        remote = lake_opts(self.root)
        remote["storage"] = {"type": "minio", "bucket": "b", "endpoint": "http://10.0.0.5:9000"}
        with self.assertRaises(ConfigError) as e:
            load_pipeline_config(data={"mode": "defence", "inputs": [], "outputs": [remote]})
        self.assertIn("tls_outputs", str(e.exception))


DATA_TS = 2      # "timestamp" column index in DATA_SCHEMA


def _free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@unittest.skipUnless(HAVE, "ulpf_core hot tier not built")
class TestLakehouseRuntime(unittest.TestCase):
    def test_runtime_ingest_to_lake(self):
        import socket
        from tests.test_inputs import free_port, start_runtime, wait_for
        d = tempfile.mkdtemp(prefix="ulpf_lakert_")
        port = free_port()
        o = lake_opts(d)
        o["tenant_by_input"] = {"tcp": "acme"}
        rt = start_runtime(d, [{"type": "syslog", "name": "tcp", "protocol": "tcp", "host": "127.0.0.1", "port": port}],
                           outputs=[o], routes=[{"name": "all", "when": {"kind_in": ["log"]}, "to": ["lake"]}])
        try:
            with socket.create_connection(("127.0.0.1", port)) as c:
                c.sendall(b"".join(b"<134>Oct 25 08:%02d:00 fw01 app: conn src=10.0.0.%d dst=8.8.8.8\n" % (i % 60, i % 200)
                                   for i in range(300)))
            from ulpf.lake import service
            self.assertTrue(wait_for(lambda: service.get("lake") is not None
                                     and service.get("lake").query.run("SELECT count(*) n FROM events")[0]
                                     .column("n")[0].as_py() == 300, 30))
            svc = service.get("lake")
            svc.flush_once()
            n = svc.query.run("SELECT count(*) n FROM events", tenant="acme")[0].column("n")[0].as_py()
            self.assertEqual(n, 300)
        finally:
            rt.stop()


if __name__ == "__main__":
    unittest.main()
