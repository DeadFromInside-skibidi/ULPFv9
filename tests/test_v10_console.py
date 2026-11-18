"""v10 web console: static SPA, RBAC/multi-tenancy, console APIs, SOAR/copilot routes, WebSocket stream."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import tempfile
import threading
import time
import types
import unittest
import urllib.error
import urllib.request


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Console(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import uvicorn
        from fastapi import FastAPI
        from ulpf.console.server import mount_console
        from ulpf.soar.service import SoarService
        from ulpf.storage.database import Database
        cls.d = tempfile.mkdtemp()
        keys = [{"name": "acme-analyst", "role": "analyst", "tenants": ["acme"], "sha256": hashlib.sha256(b"k-acme").hexdigest()},
                {"name": "globex-auditor", "role": "auditor", "tenants": ["globex"], "sha256": hashlib.sha256(b"k-glob").hexdigest()},
                {"name": "lead", "role": "admin", "tenants": ["*"], "sha256": hashlib.sha256(b"k-lead").hexdigest()}]
        kf = os.path.join(cls.d, "keys.json")
        with open(kf, "w", encoding="utf-8") as f:
            json.dump(keys, f)
        cls._env = os.environ.get("ULPF_API_KEYS_FILE")
        os.environ["ULPF_API_KEYS_FILE"] = kf
        db = Database(os.path.join(cls.d, "s.duckdb"))
        db.store_events([{"event_id": f"e{i}", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
                          "category": "authentication", "action": "failed" if i % 2 else "success", "severity": 5,
                          "user": {"name": "alice"}, "source": {"ip": "10.0.0.5"},
                          "destination": {"ip": "10.0.0.9", "port": 22}, "raw_event": "x", "raw_format": "syslog",
                          "evidence": {"raw_hash": "00"}} for i in range(6)])
        soar = SoarService(cls.d, {})
        rt = types.SimpleNamespace(soar=soar, copilot=None, database=db, data_dir=cls.d, node="n1", journal=None,
                                   buffers={}, cluster=None, correlator=None,
                                   cfg=types.SimpleNamespace(data={"compliance": {}}),
                                   stats=lambda: {"mode": "industry", "uptime_seconds": 1, "inputs": {}, "outputs": {}})
        cls.rt, cls.db, cls.soar = rt, db, soar
        app = FastAPI()
        mount_console(app, rt)
        cls.port = _free_port()
        cls.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=cls.port, log_level="error"))
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        end = time.time() + 15
        while not cls.server.started and time.time() < end:
            time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(5)
        cls.soar.close()
        cls.db.close()
        if cls._env is None:
            os.environ.pop("ULPF_API_KEYS_FILE", None)
        else:
            os.environ["ULPF_API_KEYS_FILE"] = cls._env
        shutil.rmtree(cls.d, ignore_errors=True)

    def call(self, path, key=None, tenant=None, method="GET", body=None):
        h = {"Content-Type": "application/json"}
        if key:
            h["X-API-Key"] = key
        if tenant:
            h["X-ULPF-Tenant"] = tenant
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method, headers=h,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                ct = r.headers.get("Content-Type", "")
                data = r.read()
                return r.status, (json.loads(data) if "json" in ct else data), {k.lower(): v for k, v in r.headers.items()}
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}"), dict(e.headers)

    def test_static_spa_with_csp(self):
        st, body, hdr = self.call("/console/")
        self.assertEqual(st, 200)
        self.assertIn(b"ULPF SOC Console", body)
        self.assertIn("script-src 'self'", hdr["content-security-policy"])
        st, body, _ = self.call("/console/app.js")
        self.assertIn(b"textContent", body)
        st, _, _ = self.call("/console/../../setup.py")
        self.assertEqual(st, 200)                              # traversal falls back to index.html

    def test_rbac_and_tenant_isolation(self):
        self.assertEqual(self.call("/api/v1/console/me")[0], 401)
        st, me, _ = self.call("/api/v1/console/me", "k-acme")
        self.assertEqual((me["role"], me["tenant"]), ("analyst", "acme"))
        self.assertEqual(self.call("/api/v1/console/me", "k-acme", "globex")[0], 403)
        st, c, _ = self.call("/api/v1/soar/cases", "k-acme", method="POST", body={"title": "acme case", "severity": "high"})
        self.assertEqual(st, 200, c)
        self.assertEqual(self.call("/api/v1/soar/cases", "k-glob", method="POST", body={"title": "x"})[0], 403)  # auditor
        st, lst, _ = self.call("/api/v1/soar/cases", "k-glob")
        self.assertEqual(lst["cases"], [])                     # globex sees none of acme's cases
        st, lst, _ = self.call("/api/v1/soar/cases", "k-lead", "acme")
        self.assertEqual(len(lst["cases"]), 1)

    def test_console_endpoints(self):
        st, o, _ = self.call("/api/v1/console/overview", "k-lead")
        self.assertEqual(st, 200)
        self.assertIn("metrics", o)
        st, a, _ = self.call("/api/v1/console/attack", "k-lead")
        self.assertTrue(any(t["name"] == "Credential Access" for t in a["tactics"]))
        st, g, _ = self.call("/api/v1/console/graph?hours=24", "k-lead")
        self.assertTrue(any(e["kind"] == "auth" and e["count"] == 6 for e in g["edges"]), g)
        st, f, _ = self.call("/api/v1/console/flows?hours=24", "k-lead")
        self.assertTrue(f["flows"])
        st, q, _ = self.call("/api/v1/copilot/nl2query", "k-acme", method="POST",
                             body={"question": "top 5 users with failed logins today", "language": "kql"})
        self.assertTrue(q["valid"], q)
        st, pb, _ = self.call("/api/v1/soar/playbooks", "k-lead")
        self.assertGreaterEqual(len(pb["playbooks"]), 4)

    def test_websocket_stream_with_ticket(self):
        from websockets.sync.client import connect
        st, t, _ = self.call("/api/v1/console/ws-ticket", "k-acme", method="POST")
        with connect(f"ws://127.0.0.1:{self.port}/api/v1/console/stream?ticket={t['ticket']}&tenant=acme",
                     open_timeout=5) as ws:
            self.soar.cases.create("acme", "live case", "critical")
            seen = set()
            end = time.time() + 6
            while time.time() < end and not {"metrics", "case"} <= seen:
                seen.add(json.loads(ws.recv(timeout=3))["type"])
            self.assertIn("metrics", seen)
            self.assertIn("case", seen)
        from websockets.exceptions import InvalidStatus, ConnectionClosed
        with self.assertRaises((InvalidStatus, ConnectionClosed, OSError)):     # tickets are single-use
            with connect(f"ws://127.0.0.1:{self.port}/api/v1/console/stream?ticket={t['ticket']}", open_timeout=5) as ws:
                ws.recv(timeout=3)


if __name__ == "__main__":
    unittest.main()
