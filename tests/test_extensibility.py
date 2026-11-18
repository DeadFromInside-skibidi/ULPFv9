"""Phase E2: source onboarding, parser plugins, schema versioning, raw traceability, ML export."""
from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
import tempfile
import textwrap
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401

from ulpf.config import load_pipeline_config  # noqa: E402


def plc_line(i: int) -> str:
    return (f"PLC{i % 7:02d} >> valve {i % 40} {'opened' if i % 3 else 'closed'} by op{i % 5} "
            f"at 2026/10/21-10:{(i // 60) % 60:02d}:{i % 60:02d} pressure {1 + (i % 97) / 10:.2f}bar")


CONFIG = """\
# Plant pipeline
mode: industry
inputs:
  # existing edge listener
  - type: syslog
    name: edge
    protocol: tcp
    host: 127.0.0.1
    port: 5514
outputs:
  - type: duckdb
    name: store
routes:
  - name: all
    to: [store]
"""


class TestSourceOnboarding(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ulpf_onboard_")
        self.sample = os.path.join(self.dir, "plc.log")
        with open(self.sample, "w", newline="\n") as f:
            f.writelines(plc_line(i) + "\n" for i in range(200))

    def test_onboard_learns_a_validated_parser_in_one_command(self):
        from ulpf.cli_runtime import onboard_source
        with open(self.sample) as f:
            rep = onboard_source("plc-line-3", f.readlines(), "industry", os.path.join(self.dir, "learned"))
        self.assertEqual(rep["lines"], 200)
        self.assertEqual(rep["builtin_coverage_pct"], 0.0)
        self.assertEqual(len(rep["learned"]), 1, rep)
        self.assertGreaterEqual(rep["total_coverage_pct"], 99.0)
        self.assertGreaterEqual(rep["learned"][0]["accuracy"], 0.99)
        self.assertEqual(rep["learned"][0]["state"], "active")
        self.assertLess(rep["elapsed_seconds"], 60)
        # the saved parser is used by a fresh pipeline
        from ulpf.engine.pipeline import Pipeline
        p = Pipeline(enable_auto_parser=True, learned_parsers_dir=os.path.join(self.dir, "learned"))
        try:
            r = p.process_line(plc_line(5000))
            self.assertTrue(r.get("auto_parsed"), r["event"]["raw_format"])
        finally:
            p.close()

    def test_defence_onboarding_waits_for_approval(self):
        from ulpf.cli_runtime import onboard_source
        from ulpf.intelligence.auto_parser.engine import AutoParserEngine
        learned = os.path.join(self.dir, "learned_d")
        with open(self.sample) as f:
            rep = onboard_source("plc", f.readlines(), "defence", learned)
        self.assertEqual(rep["learned"][0]["state"], "pending_approval")
        eng = AutoParserEngine(learned_dir=learned)
        try:
            spec = eng.registry.list_parsers()[0]
            self.assertEqual(spec.state, "pending_approval")
            self.assertEqual(spec.metadata["learned_source"], "plc")
            self.assertTrue(eng.provenance.verify_parser_spec(spec))
        finally:
            eng.stop()

    def test_cli_writes_the_input_into_the_config(self):
        from ulpf.main import main
        cfg_path = os.path.join(self.dir, "pipeline.yaml")
        with open(cfg_path, "w", newline="\n") as f:
            f.write(CONFIG)
        rc = main(["source", "onboard", "--name", "plc", "--sample", self.sample, "--config", cfg_path,
                   "--write-config", "--path", "/var/log/plc/*.log", "--data-dir", self.dir])
        self.assertEqual(rc, 0)
        with open(cfg_path) as f:
            text = f.read()
        self.assertIn("# existing edge listener", text)      # comments survive
        cfg = load_pipeline_config(cfg_path)
        names = [i["name"] for i in cfg["inputs"]]
        self.assertEqual(names, ["plc", "edge"])
        plc = cfg["inputs"][0]
        self.assertEqual(plc["paths"], ["/var/log/plc/*.log"])
        self.assertEqual(plc["start_from"], "end")


# ---------------------------------------------------------------------------

PLUGIN_SRC = '''
from ulpf.parsers.base import BaseParser
from ulpf.engine.normalizer import build_normalized_event


class AcmePlcParser(BaseParser):
    parser_id = "acme_plc"
    parser_name = "ACME PLC (plugin)"
    supported_formats = ["acme_plc"]
    version = "1.0.0"

    def can_parse(self, raw_line):
        return raw_line.startswith("PLC") and " >> valve " in raw_line

    def parse(self, raw_line, **kwargs):
        unit, rest = raw_line.split(" >> ", 1)
        words = rest.split()
        fields = {"unit": unit, "valve": words[1], "state": words[2], "operator": words[4]}
        return build_normalized_event(**kwargs, raw_line=raw_line, raw_format="acme_plc",
                                      parsed_fields=fields, parser_id=self.parser_id,
                                      parser_name=self.parser_name, parser_version=self.version,
                                      category="system", event_type="valve_" + words[2],
                                      device_vendor="ACME", device_product="PLC", message=rest)
'''


def install_fake_plugin(root: str) -> str:
    pkg = os.path.join(root, "acme_ulpf")
    info = os.path.join(root, "acme_ulpf-1.0.0.dist-info")
    os.makedirs(pkg)
    os.makedirs(info)
    with open(os.path.join(pkg, "__init__.py"), "w") as f:
        f.write(textwrap.dedent(PLUGIN_SRC))
    with open(os.path.join(info, "METADATA"), "w") as f:
        f.write("Metadata-Version: 2.1\nName: acme-ulpf\nVersion: 1.0.0\n")
    with open(os.path.join(info, "entry_points.txt"), "w") as f:
        f.write("[ulpf.parsers]\nacme_plc = acme_ulpf:AcmePlcParser\n")
    with open(os.path.join(info, "RECORD"), "w") as f:
        f.write("acme_ulpf/__init__.py,,\nacme_ulpf-1.0.0.dist-info/METADATA,,\n"
                "acme_ulpf-1.0.0.dist-info/entry_points.txt,,\nacme_ulpf-1.0.0.dist-info/RECORD,,\n")
    return root


class TestParserPlugins(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.site = install_fake_plugin(tempfile.mkdtemp(prefix="ulpf_site_"))
        sys.path.insert(0, cls.site)

    @classmethod
    def tearDownClass(cls):
        sys.path.remove(cls.site)
        sys.modules.pop("acme_ulpf", None)

    def test_plugin_is_discovered_and_used_before_builtins(self):
        from ulpf.engine.pipeline import Pipeline
        from ulpf.parsers.plugins import discover
        infos = [i for i in discover() if i.name == "acme_plc"]
        self.assertEqual(len(infos), 1)
        self.assertTrue(infos[0].loaded, infos[0].error)
        self.assertEqual(len(infos[0].sha256), 64)
        p = Pipeline(enable_auto_parser=False)
        r = p.process_line(plc_line(3))
        self.assertEqual(r["event"]["raw_format"], "acme_plc")
        self.assertEqual(r["event"]["parsed_fields"]["operator"], "op3")
        self.assertEqual(r["event"]["metadata"]["parser_id"], "acme_plc")
        # other formats still go to the built-in parsers
        self.assertEqual(p.process_line("<34>Oct 11 22:14:15 h app: x")["event"]["raw_format"], "syslog")

    def test_defence_loads_only_allow_listed_hashes(self):
        from ulpf.engine.pipeline import Pipeline
        from ulpf.parsers.plugins import discover, policy_from_config
        sha = next(i for i in discover() if i.name == "acme_plc").sha256
        denied = policy_from_config({"mode": "defence"})
        info = next(i for i in discover(denied) if i.name == "acme_plc")
        self.assertFalse(info.loaded)
        self.assertIn("plugins.allow", info.error)
        self.assertNotEqual(Pipeline(enable_auto_parser=False, plugin_policy=denied)
                            .process_line(plc_line(1))["event"]["raw_format"], "acme_plc")
        allowed = policy_from_config({"mode": "defence", "plugins": {"allow": [sha]}})
        self.assertEqual(Pipeline(enable_auto_parser=False, plugin_policy=allowed)
                         .process_line(plc_line(1))["event"]["raw_format"], "acme_plc")
        # a modified package no longer matches its allow-listed hash
        with open(os.path.join(self.site, "acme_ulpf", "__init__.py"), "a") as f:
            f.write("\n# tampered\n")
        try:
            info = next(i for i in discover(allowed) if i.name == "acme_plc")
            self.assertFalse(info.loaded)
        finally:
            path = os.path.join(self.site, "acme_ulpf", "__init__.py")
            with open(path) as f:
                src = f.read().replace("\n# tampered\n", "")
            with open(path, "w") as f:
                f.write(src)

    def test_config_accepts_plugin_policy(self):
        cfg = load_pipeline_config(data={"plugins": {"allow": ["ab" * 32]}, "outputs": [{"type": "duckdb", "name": "s"}]})
        self.assertEqual(cfg["plugins"]["allow"], ["ab" * 32])


# ---------------------------------------------------------------------------

class TestSchemaRegistry(unittest.TestCase):
    def test_registry_matches_live_catalogue(self):
        from ulpf.engine import schema_registry as reg
        from ulpf.engine.schema import SCHEMA_VERSION
        self.assertIn(SCHEMA_VERSION, reg.versions())
        self.assertEqual(reg.load(SCHEMA_VERSION), reg.current(),
                         "the schema catalogue changed: bump SCHEMA_VERSION and add a registry file")

    def test_minor_versions_are_additive(self):
        from ulpf.engine import schema_registry as reg
        vs = reg.versions()
        for a, b in zip(vs, vs[1:]):
            d = reg.diff(reg.load(a), reg.load(b))
            self.assertTrue(d["compatible"], d)

    def test_diff_detects_removed_and_retyped_fields(self):
        from ulpf.engine import schema_registry as reg
        cur = reg.current()
        broken = {"version": "1.2.0", "fields": dict(cur["fields"])}
        del broken["fields"]["source.ip"]
        broken["fields"]["severity"] = "string"
        d = reg.diff(cur, broken)
        self.assertEqual(d["removed"], ["source.ip"])
        self.assertEqual(d["type_changed"][0]["field"], "severity")
        self.assertFalse(d["compatible"])
        self.assertTrue(reg.diff(cur, {**broken, "version": "2.0.0"})["compatible"])

    def test_cli_diff_exit_codes(self):
        from ulpf.main import main
        from ulpf.engine import schema_registry as reg
        self.assertEqual(main(["schema", "diff", "1.0.0", "1.1.0"]), 0)
        d = tempfile.mkdtemp()
        old = os.path.join(d, "old.json")
        reg.export(old)
        new = os.path.join(d, "new.json")
        doc = reg.current()
        doc["fields"].pop("destination.port")
        with open(new, "w") as f:
            json.dump(doc, f)
        self.assertEqual(main(["schema", "diff", old, new]), 1)

    def test_every_event_carries_its_schema_version(self):
        from ulpf.engine.pipeline import Pipeline
        from ulpf.engine.schema import SCHEMA_VERSION
        r = Pipeline(enable_auto_parser=False).process_line("<34>Oct 11 22:14:15 h app: x")
        self.assertEqual(r["event"]["metadata"]["schema_version"], SCHEMA_VERSION)


# ---------------------------------------------------------------------------

class TestRawTraceability(unittest.TestCase):
    def test_raw_bytes_match_for_every_event(self):
        from ulpf.runtime.supervisor import Runtime
        d = tempfile.mkdtemp(prefix="ulpf_raw_")
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        rt = Runtime(load_pipeline_config(data={
            "workers": 1, "node": {"data_dir": d}, "api": {"enabled": False}, "evidence": {"enabled": False},
            "inputs": [{"type": "syslog", "name": "tcp", "protocol": "tcp", "host": "127.0.0.1", "port": port,
                        "framing": "newline"}],
            "outputs": [{"type": "duckdb", "name": "store", "path": os.path.join(d, "s.duckdb")}],
            "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["store"]}],
            "default_output": ""})).start()
        lines = []
        for i in range(100):
            lines += [f"<134>Oct 11 22:14:15 fw{i} app: tést ünïcode {i} \t tab",
                      f"CEF:0|V|P|1|{i}|n|5|src=10.0.0.{i % 250} msg=café {i}",
                      json.dumps({"i": i, "msg": "q\"uote", "emoji": "✓"}, ensure_ascii=False),
                      plc_line(i)]
        try:
            with socket.create_connection(("127.0.0.1", port)) as c:
                c.sendall("".join(l + "\r\n" if i % 2 else l + "\n" for i, l in enumerate(lines)).encode("utf-8"))
            deadline = time.time() + 60
            while time.time() < deadline and rt.runners["store"].delivered_events < len(lines):
                time.sleep(0.1)
            with rt.database._conn_lock:
                rows = rt.database.conn.execute(
                    "SELECT raw_hash, CAST(json_extract(normalised_json, '$.evidence.journal_seq') AS BIGINT) "
                    "FROM events").fetchall()
            self.assertEqual(len(rows), len(lines))
            matched = 0
            for raw_hash, seq in rows:
                rec = rt.journal.read(seq)
                if rec.sha256_hex == raw_hash and hashlib.sha256(rec.raw).hexdigest() == raw_hash:
                    matched += 1
            self.assertEqual(matched, len(lines))          # 100 % byte-identical
            originals = {l.encode("utf-8") for l in lines}
            self.assertEqual({rt.journal.read(seq).raw for _, seq in rows}, originals)
        finally:
            rt.stop()


# ---------------------------------------------------------------------------

class TestUpgrade(unittest.TestCase):
    def test_pre_v9_parquet_shards_still_ingest(self):
        import pyarrow.parquet as pq
        from ulpf.engine.pipeline import Pipeline
        from ulpf.storage.database import EVENT_COLUMNS, Database, event_to_row, rows_to_arrow
        d = tempfile.mkdtemp()
        ev = Pipeline(enable_auto_parser=False).process_line("<34>Oct 11 22:14:15 h app: old shard")["event"]
        table = rows_to_arrow([event_to_row(ev)])
        old = table.drop_columns(["row_mac"])              # what 8.x workers wrote
        path = os.path.join(d, "old.parquet")
        pq.write_table(old, path)
        db = Database(os.path.join(d, "s.duckdb"))
        try:
            self.assertEqual(db.ingest_parquet([path]), 1)
            row = db.conn.execute(f"SELECT {', '.join(EVENT_COLUMNS)} FROM events").fetchone()
            self.assertIsNone(row[EVENT_COLUMNS.index("row_mac")])
            self.assertEqual(row[0], ev["event_id"])
        finally:
            db.close()


class TestEventIds(unittest.TestCase):
    def test_fast_event_id_equals_the_uuid_construction(self):
        import random
        import uuid
        from ulpf.runtime.ids import event_id

        def reference(node, seq, ordinal=0):
            h = bytearray(hashlib.sha256(f"{node}:{seq}:{ordinal}".encode()).digest()[:16])
            h[6] = (h[6] & 0x0F) | 0x80
            h[8] = (h[8] & 0x3F) | 0x80
            return str(uuid.UUID(bytes=bytes(h)))
        rnd = random.Random(7)
        for _ in range(5000):
            node, seq, o = f"node-{rnd.getrandbits(48):012x}", rnd.getrandbits(40), rnd.randint(0, 9)
            self.assertEqual(event_id(node, seq, o), reference(node, seq, o))
        u = uuid.UUID(event_id("n", 1))
        self.assertEqual((u.version, u.variant), (8, uuid.RFC_4122))


class TestMlExport(unittest.TestCase):
    def test_parquet_and_csv_with_column_card(self):
        import pyarrow.parquet as pq
        from ulpf.engine.pipeline import Pipeline
        from ulpf.main import ML_COLUMNS, ml_feature_rows, write_ml_dataset
        p = Pipeline(enable_auto_parser=False)
        events = [p.process_line(l)["event"] for l in (
            "CEF:0|Check Point|FW|1|Drop|d|8|rt=2026-10-21T10:00:01Z src=45.33.32.156 dst=10.0.1.50 spt=1 dpt=4444 "
            "proto=TCP act=Drop",
            "<34>Oct 11 22:14:15 db01 sshd[1]: Failed password for root from 45.33.32.156 port 22 ssh2")]
        rows = ml_feature_rows(events)
        d = tempfile.mkdtemp()
        out = os.path.join(d, "f.parquet")
        card = write_ml_dataset(rows, out, "parquet")
        t = pq.read_table(out)
        self.assertEqual(t.num_rows, 2)
        self.assertEqual(t.column_names, [c[0] for c in ML_COLUMNS])
        self.assertEqual(str(t.schema.field("severity").type), "int8")
        self.assertTrue(str(t.schema.field("timestamp").type).startswith("timestamp"))
        self.assertEqual(t.schema.field("is_threat").metadata[b"kind"], b"flag")
        self.assertEqual(t.column("dest_port").to_pylist()[0], 4444)
        with open(card) as f:
            doc = json.load(f)
        kinds = {c["name"]: c["kind"] for c in doc["columns"]}
        self.assertEqual(kinds["timestamp"], "timestamp")
        self.assertEqual(kinds["severity"], "numeric")
        self.assertEqual(kinds["category"], "categorical")
        csv_out = os.path.join(d, "f.csv")
        write_ml_dataset(rows, csv_out, "csv")
        with open(csv_out) as f:
            self.assertEqual(f.readline().strip().split(","), [c[0] for c in ML_COLUMNS])


if __name__ == "__main__":
    unittest.main()
