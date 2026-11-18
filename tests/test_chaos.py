"""
Phase H chaos tests: each must lose zero events (or count its drops exactly).

    kill -9 during file ingest        restart: no line missing, none twice
    sink outage                       buffer drains after recovery, no loss, no duplicates
    sink buffer full, when_full=block ingest stalls (back-pressure), nothing lost
    sink buffer full, drop_oldest     delivered + counted drops == sent
    TCP input partition               a retrying client's lines are all accepted after recovery
    DLQ growth                        bounded by dlq.max_mb, evictions reported

The outage lasts ULPF_CHAOS_OUTAGE_S seconds (default 15; the plan's full run is 600).
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401
from tests.fakes import FakeHTTP  # noqa: E402

from ulpf.config import load_pipeline_config  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTAGE_S = float(os.environ.get("ULPF_CHAOS_OUTAGE_S", "15"))


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


class FakeES:
    """Bulk endpoint that can be taken down; idempotent on _id like Elasticsearch."""

    def __init__(self, reject_all: bool = False):
        self.docs: dict[str, dict] = {}
        self.down = threading.Event()
        self.reject_all = reject_all
        self.lock = threading.Lock()
        self.http = FakeHTTP(self.respond)

    def respond(self, req):
        if not req["path"].startswith("/_bulk"):
            return 200, {}, {"version": {"number": "8.11.0"}}
        if self.down.is_set():
            return 503, {}, b'{"error":"unavailable"}'
        lines = [l for l in req["body"].split(b"\n") if l]
        items, errors = [], False
        with self.lock:
            for a, d in zip(lines[0::2], lines[1::2]):
                _id = json.loads(a)["create"]["_id"]
                if self.reject_all:
                    items.append({"create": {"status": 400, "error": {"type": "mapper_parsing_exception"}}})
                    errors = True
                elif _id in self.docs:
                    items.append({"create": {"status": 409}})
                    errors = True
                else:
                    self.docs[_id] = json.loads(d)
                    items.append({"create": {"status": 201}})
        return 200, {}, {"errors": errors, "items": items}


def es_runtime(d: str, es: FakeES, port: int, buffer: dict | None = None, dlq: dict | None = None):
    from ulpf.runtime.supervisor import Runtime
    os.environ["ULPF_T_ES"] = "k"
    cfg = {"workers": 2, "node": {"data_dir": d}, "api": {"enabled": False}, "evidence": {"enabled": False},
           "analytics": {"anomaly": {"enabled": False}, "drift": {"enabled": False},
                         "correlation": {"enabled": False}},
           "inputs": [{"type": "syslog", "name": "tcp", "protocol": "tcp", "host": "127.0.0.1", "port": port}],
           "outputs": [{"type": "elasticsearch", "name": "es", "urls": [es.http.url], "api_key_env": "ULPF_T_ES",
                        "retry": {"initial_ms": 50, "max_ms": 500}, "buffer": buffer or {"max_mb": 512}}],
           "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["es"]}], "default_output": ""}
    if dlq:
        cfg["dlq"] = dlq
    return Runtime(load_pipeline_config(data=cfg)).start()


def send_lines(port: int, lines: list[str]) -> None:
    with socket.create_connection(("127.0.0.1", port)) as s:
        s.sendall("".join(l + "\n" for l in lines).encode())


def lines_for(n: int, tag: str = "x") -> list[str]:
    return [f"<134>Oct 11 22:14:15 fw{i % 7} app[1]: {tag} event {i} from 10.0.{i % 250}.{i % 200} "
            f"port {1024 + i % 60000} payload {'p' * (i % 80)}" for i in range(n)]


class TestSinkFailures(unittest.TestCase):
    def test_sink_outage_drains_without_loss(self):
        es = FakeES()
        es.down.set()
        d, port = tempfile.mkdtemp(prefix="ulpf_chaos_out_"), free_port()
        rt = es_runtime(d, es, port)
        n = 20_000
        try:
            t0 = time.time()
            send_lines(port, lines_for(n))
            self.assertTrue(wait_for(lambda: rt.stats()["committed_seq"] >= n, 60))
            time.sleep(max(0.0, OUTAGE_S - (time.time() - t0)))
            self.assertEqual(len(es.docs), 0)
            self.assertGreater(rt.runners["es"].retries, 0)
            es.down.clear()
            self.assertTrue(wait_for(lambda: rt.runners["es"].delivered_events >= n, 120))
            time.sleep(1.0)
            self.assertEqual(len(es.docs), n)
            self.assertEqual(rt.runners["es"].dead_lettered, 0)
        finally:
            rt.stop()
            es.http.close()

    def _full_buffer(self, when_full: str):
        es = FakeES()
        es.down.set()
        d, port = tempfile.mkdtemp(prefix=f"ulpf_chaos_{when_full}_"), free_port()
        rt = es_runtime(d, es, port, buffer={"max_mb": 1, "when_full": when_full})
        n = 30_000
        sender = threading.Thread(target=send_lines, args=(port, lines_for(n, when_full)), daemon=True)
        try:
            sender.start()
            time.sleep(6.0)
            stalled_at = rt.stats()["committed_seq"]
            return rt, es, sender, n, stalled_at
        except Exception:
            rt.stop()
            es.http.close()
            raise

    def test_buffer_full_block_stalls_ingest_without_loss(self):
        rt, es, sender, n, stalled_at = self._full_buffer("block")
        try:
            self.assertLess(stalled_at, n)             # back-pressure reached the input
            buf = rt.runners["es"].buffer.stats()
            # bounded: under the cap, or one segment that is larger than the cap on its own
            self.assertTrue(buf["bytes"] <= 1.05 * 2**20 or buf["segments"] == 1, buf)
            es.down.clear()
            sender.join(120)
            self.assertTrue(wait_for(lambda: rt.runners["es"].delivered_events >= n, 180))
            time.sleep(1.0)
            self.assertEqual(len(es.docs), n)
            self.assertEqual(rt.dispatcher.stats()["dropped"].get("es", 0), 0)
        finally:
            rt.stop()
            es.http.close()

    def test_buffer_full_drop_oldest_counts_exactly(self):
        rt, es, sender, n, _ = self._full_buffer("drop_oldest")
        try:
            sender.join(120)
            self.assertTrue(wait_for(lambda: rt.stats()["committed_seq"] >= n, 120))   # never blocks
            es.down.clear()

            def settled():
                dropped = rt.dispatcher.stats()["dropped"].get("es", 0)
                return dropped > 0 and len(es.docs) + dropped == n
            self.assertTrue(wait_for(settled, 120),
                            (len(es.docs), rt.dispatcher.stats()["dropped"]))
        finally:
            rt.stop()
            es.http.close()

    def test_dlq_stays_bounded(self):
        es = FakeES(reject_all=True)
        d, port = tempfile.mkdtemp(prefix="ulpf_chaos_dlq_"), free_port()
        rt = es_runtime(d, es, port, dlq={"max_mb": 1, "retention_days": 7})
        n = 20_000
        try:
            send_lines(port, lines_for(n, "reject"))
            self.assertTrue(wait_for(lambda: rt.runners["es"].dead_lettered >= n, 120),
                            rt.runners["es"].dead_lettered)
            st = rt.dlq.stats()
            self.assertEqual(st["events_written"], n)
            self.assertLessEqual(st["bytes"], 1.25 * 2**20 + 1, st)   # cap + one rotated file
            self.assertGreater(st["evicted_files"], 0)
        finally:
            rt.stop()
            es.http.close()


class TestInputFailures(unittest.TestCase):
    def test_tcp_partition_retrying_client_loses_nothing(self):
        from ulpf.runtime.supervisor import Runtime
        d, port = tempfile.mkdtemp(prefix="ulpf_chaos_tcp_"), free_port()
        rt = Runtime(load_pipeline_config(data={
            "workers": 1, "node": {"data_dir": d}, "api": {"enabled": False}, "evidence": {"enabled": False},
            "inputs": [{"type": "syslog", "name": "tcp", "protocol": "tcp", "host": "127.0.0.1", "port": port}],
            "outputs": [{"type": "duckdb", "name": "store", "path": os.path.join(d, "s.duckdb")}],
            "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["store"]}],
            "default_output": ""})).start()
        lines = lines_for(3000, "partition")
        conn_of: dict[int, int] = {}       # line index -> connection number it was written to
        cut: set[int] = set()              # connections that failed

        def client():
            i, sock, conn = 0, None, 0
            while i < len(lines):
                try:
                    if sock is None:
                        sock = socket.create_connection(("127.0.0.1", port), timeout=2)
                        conn += 1
                    sock.sendall((lines[i] + "\n").encode())
                    conn_of[i] = conn
                    i += 1
                    if i % 50 == 0:
                        time.sleep(0.05)
                except OSError:
                    cut.add(conn)
                    sock = None
                    time.sleep(0.2)
            sock.close()

        try:
            opts = rt.inputs["tcp"].opts
            t = threading.Thread(target=client, daemon=True)
            t.start()
            time.sleep(0.5)
            rt._stop_input("tcp")                      # partition: listener gone
            time.sleep(2.0)
            rt._start_input(opts)                      # recovery
            t.join(120)
            self.assertTrue(wait_for(lambda: rt.runners["store"].delivered_events >= 1, 30))
            time.sleep(2.0)
            with rt.database._conn_lock:
                stored = {r[0] for r in rt.database.conn.execute("SELECT raw_event FROM events").fetchall()}
            # Every line written to a connection that stayed up is stored. Lines written into the
            # connection the partition cut can die in the kernel buffers: that is TCP, not ULPF,
            # and is why senders that need guarantees use RELP-style acks or the HTTP input.
            self.assertTrue(cut, "the partition did not break the client's connection")
            self.assertTrue(any(c not in cut for c in conn_of.values()), "no line sent after recovery")
            stored = {s.strip() for s in stored}      # raw_event is whitespace-stripped
            missing = [i for i, l in enumerate(lines) if l.strip() not in stored]
            self.assertTrue(all(conn_of[i] in cut for i in missing),
                            [i for i in missing if conn_of[i] not in cut][:5])
            after = [i for i, c in conn_of.items() if c > max(cut)]
            self.assertTrue(all(lines[i].strip() in stored for i in after))
        finally:
            rt.stop()


def _kill_tree(pid: int) -> None:
    import psutil
    p = psutil.Process(pid)
    for c in p.children(recursive=True):
        c.kill()
    p.kill()


class TestProcessCrash(unittest.TestCase):
    def test_kill_9_during_file_ingest_then_restart(self):
        import yaml
        d = tempfile.mkdtemp(prefix="ulpf_chaos_kill_")
        log = os.path.join(d, "app.log")
        open(log, "w").close()
        db = os.path.join(d, "s.duckdb")
        cfg = os.path.join(d, "pipeline.yaml")
        with open(cfg, "w") as f:
            yaml.safe_dump({"workers": 2, "node": {"data_dir": os.path.join(d, "node")}, "api": {"enabled": False},
                            "journal": {"sync": "always"},
                            "inputs": [{"type": "file", "name": "app", "paths": [log], "start_from": "beginning",
                                        "poll_interval_ms": 50}],
                            "outputs": [{"type": "duckdb", "name": "store", "path": db}],
                            "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["store"]}],
                            "default_output": ""}, f)
        n = 6000
        lines = lines_for(n, "crash")
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0

        def start():
            return subprocess.Popen([sys.executable, "-m", "ulpf.main", "run", "--config", cfg, "--no-api"],
                                    cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    creationflags=flags)

        p = start()
        with open(log, "a", newline="\n") as f:
            for i, l in enumerate(lines[:4000]):
                f.write(l + "\n")
                if i % 500 == 0:
                    f.flush()
                    time.sleep(0.4)
        time.sleep(1.0)
        _kill_tree(p.pid)                              # kill -9: no shutdown code runs
        p.wait(30)
        with open(log, "a", newline="\n") as f:
            f.writelines(l + "\n" for l in lines[4000:])
        p = start()
        try:
            time.sleep(25.0)
        finally:
            if sys.platform == "win32":
                p.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                p.send_signal(signal.SIGTERM)
            try:
                p.wait(90)
            except subprocess.TimeoutExpired:
                _kill_tree(p.pid)
                self.fail("runtime did not stop on the shutdown signal")
        from ulpf.storage.database import Database
        store = Database(db, read_only=True)
        try:
            rows = [r[0] for r in store.conn.execute("SELECT raw_event FROM events").fetchall()]
        finally:
            store.close()
        self.assertEqual(len(set(rows)), n, f"{n - len(set(rows))} line(s) missing")
        self.assertEqual(len(rows), n, f"{len(rows) - n} duplicate(s)")


if __name__ == "__main__":
    unittest.main()
