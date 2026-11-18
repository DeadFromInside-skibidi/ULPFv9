"""Phase G: API roles over TLS, config reload, API keys, multi-node failover."""
from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401
from tests.fakes import self_signed_cert  # noqa: E402

from ulpf.config import load_pipeline_config  # noqa: E402


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_for(pred, timeout=60.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.1)
    return False


def write_yaml(path: str, doc: dict) -> None:
    import yaml
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(doc, f, sort_keys=False)


class TestApiRolesAndReload(unittest.TestCase):
    def test_roles_over_tls_and_reload(self):
        from ulpf.api.auth import new_key
        from ulpf.runtime.supervisor import Runtime
        d = tempfile.mkdtemp(prefix="ulpf_ops_")
        cert, key = self_signed_cert(d)
        keys = os.path.join(d, "keys.json")
        k_read, k_write, k_admin = (new_key(keys, n, r) for n, r in
                                    (("dash", "read"), ("shipper", "write"), ("ops", "admin")))
        port = free_port()
        cfg_path = os.path.join(d, "pipeline.yaml")
        doc = {"workers": 1, "node": {"data_dir": d},
               "api": {"enabled": True, "port": 0, "keys_file": keys, "tls": {"cert": cert, "key": key}},
               "evidence": {"enabled": False},
               "inputs": [{"type": "syslog", "name": "tcp", "protocol": "tcp", "host": "127.0.0.1", "port": port},
                          {"type": "http", "name": "http"}],
               "outputs": [{"type": "duckdb", "name": "store", "path": os.path.join(d, "s.duckdb")}],
               "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["store"]}], "default_output": ""}
        write_yaml(cfg_path, doc)
        rt = Runtime(load_pipeline_config(cfg_path)).start()
        ctx = ssl.create_default_context(cafile=cert)
        base = rt.api_server.url
        self.assertTrue(base.startswith("https://"))

        def call(path, key=None, method="GET", body=None):
            req = urllib.request.Request(base + path, method=method, data=body,
                                         headers={"X-API-Key": key} if key else {})
            try:
                with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
                    return r.status, json.loads(r.read() or b"{}")
            except urllib.error.HTTPError as e:
                return e.code, {}

        try:
            self.assertEqual(call("/api/v1/runtime/status")[0], 401)
            self.assertEqual(call("/api/v1/runtime/status", k_read)[0], 200)
            self.assertEqual(call("/api/v1/ingest/stream/s1", k_read, "POST", b"line one")[0], 401)
            self.assertEqual(call("/api/v1/ingest/stream/s1", k_write, "POST", b"line one\nline two")[1]["accepted"], 2)
            self.assertEqual(call("/api/v1/runtime/reload", k_write, "POST", b"")[0], 403)

            # an invalid edit is rejected and the running config keeps working
            with open(cfg_path, "a", encoding="utf-8") as f:
                f.write("bogus_option: 1\n")
            st, res = call("/api/v1/runtime/reload", k_admin, "POST", b"")
            self.assertEqual(st, 200)
            self.assertFalse(res["reloaded"])
            self.assertTrue(any("bogus_option" in e for e in res["errors"]))
            with socket.create_connection(("127.0.0.1", port)) as s:
                s.sendall(b"<134>Oct 11 22:14:15 h app: still running\n")
            self.assertTrue(wait_for(lambda: rt.runners["store"].delivered_events >= 3, 30))

            # a valid edit (new output + route) rebuilds the stage without losing data
            doc["outputs"].append({"type": "file", "name": "copy", "path": os.path.join(d, "copy")})
            doc["routes"].append({"name": "all-copy", "to": ["copy"]})
            write_yaml(cfg_path, doc)
            st, res = call("/api/v1/runtime/reload", k_admin, "POST", b"")
            self.assertTrue(res["reloaded"], res)
            self.assertTrue(res["stage_rebuilt"])
            with socket.create_connection(("127.0.0.1", port)) as s:
                s.sendall(b"<134>Oct 11 22:14:15 h app: after reload\n")
            self.assertTrue(wait_for(lambda: rt.runners["copy"].delivered_events >= 1, 30))
            with rt.database._conn_lock:
                n = rt.database.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            self.assertEqual(n, 4)
        finally:
            rt.stop()
            os.environ.pop("ULPF_API_KEYS_FILE", None)

    def test_apikey_cli(self):
        import io
        from contextlib import redirect_stdout
        from ulpf.api.auth import role_of
        from ulpf.main import main
        d = tempfile.mkdtemp()
        keys = os.path.join(d, "keys.json")
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(main(["apikey", "new", "--name", "siem", "--role", "write", "--keys-file", keys,
                                   "--data-dir", d]), 0)
        key = buf.getvalue().strip().splitlines()[-1]
        os.environ["ULPF_API_KEYS_FILE"] = keys
        try:
            self.assertEqual(role_of(key), "write")
            self.assertIsNone(role_of(key + "x"))
        finally:
            os.environ.pop("ULPF_API_KEYS_FILE")
        with open(keys) as f:
            self.assertNotIn(key, f.read())          # only the digest is stored


class TestCluster(unittest.TestCase):
    def test_rendezvous_hashing_moves_only_the_dead_nodes_inputs(self):
        from ulpf.runtime.cluster import owner
        nodes = ["n1", "n2", "n3", "n4"]
        keys = [f"input-{i}" for i in range(400)]
        before = {k: owner(k, nodes) for k in keys}
        counts = {n: list(before.values()).count(n) for n in nodes}
        self.assertTrue(all(60 < c < 140 for c in counts.values()), counts)
        after = {k: owner(k, ["n1", "n2", "n4"]) for k in keys}
        moved = [k for k in keys if before[k] != after[k]]
        self.assertTrue(all(before[k] == "n3" for k in moved))
        self.assertEqual(len(moved), counts["n3"])

    def test_two_nodes_fail_over_a_shared_file_input_without_loss(self):
        from ulpf.runtime.cluster import status
        from ulpf.runtime.supervisor import Runtime
        shared = tempfile.mkdtemp(prefix="ulpf_shared_")
        logs = os.path.join(shared, "logs")
        os.makedirs(logs)
        path = os.path.join(logs, "app.log")
        with open(path, "w", newline="\n") as f:
            f.writelines(f"<134>Oct 11 22:14:15 h app: line {i}\n" for i in range(300))
        nodes = [{"id": "node-a", "address": "http://127.0.0.1:1"}, {"id": "node-b", "address": "http://127.0.0.1:2"}]

        def make(node_id):
            d = tempfile.mkdtemp(prefix=f"ulpf_{node_id}_")
            return load_pipeline_config(data={
                "workers": 1, "node": {"id": node_id, "data_dir": d}, "api": {"enabled": False},
                "evidence": {"enabled": False},
                "cluster": {"enabled": True, "nodes": nodes, "shared_dir": shared,
                            "heartbeat_seconds": 0.3, "failover_seconds": 1.5},
                "inputs": [{"type": "file", "name": "shared-app", "paths": [path], "start_from": "beginning",
                            "poll_interval_ms": 50, "placement": "one"}],
                "outputs": [{"type": "duckdb", "name": "store", "path": os.path.join(d, "s.duckdb")}],
                "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["store"]}],
                "default_output": ""})

        a, b = Runtime(make("node-a")).start(), Runtime(make("node-b")).start()
        try:
            def stored(rt):
                with rt.database._conn_lock:
                    return [r[0] for r in rt.database.conn.execute("SELECT raw_event FROM events").fetchall()]
            self.assertTrue(wait_for(lambda: len(stored(a)) + len(stored(b)) >= 300, 30))
            time.sleep(1.0)
            st = status(make("node-a").data)
            self.assertEqual(set(st["alive"]), {"node-a", "node-b"})
            first = st["assignments"]["shared-app"]
            self.assertIn(first, ("node-a", "node-b"))
            owner_rt, other = (a, b) if first == "node-a" else (b, a)
            self.assertIn("shared-app", owner_rt.inputs)
            self.assertNotIn("shared-app", other.inputs)       # exactly one node runs it
            owner_rt.stop()
            with open(path, "a", newline="\n") as f:
                f.writelines(f"<134>Oct 11 22:14:15 h app: line {i}\n" for i in range(300, 500))
            self.assertTrue(wait_for(lambda: "shared-app" in other.inputs, 15), "no takeover")
            self.assertTrue(wait_for(lambda: len(stored(other)) >= 200, 30))
            time.sleep(1.0)
            from ulpf.storage.database import Database
            first_db = Database(owner_rt.cfg["outputs"][0]["path"], read_only=True)
            try:
                rows = [r[0] for r in first_db.conn.execute("SELECT raw_event FROM events").fetchall()]
            finally:
                first_db.close()
            everything = rows + stored(other)
            self.assertEqual(len(everything), 500)             # nothing lost
            self.assertEqual(len(set(everything)), 500)        # nothing twice (graceful hand-over)
        finally:
            for rt in (a, b):
                try:
                    rt.stop()
                except Exception:
                    pass

    def test_config_requires_a_shared_dir(self):
        from ulpf.config import ConfigError
        with self.assertRaises(ConfigError) as cm:
            load_pipeline_config(data={"cluster": {"enabled": True}, "outputs": [{"type": "duckdb", "name": "s"}]})
        self.assertIn("cluster.shared_dir", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
