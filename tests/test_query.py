"""
KQL / SPL2 / HQL: parsed, compiled and executed over real Arrow event batches; every result is
checked against the answer computed in Python from the same events. Also: syntax errors with
line and column, the workload governor (fair share, deadlines, memory), the live tail on the
ingest path, and queries over the event store and a lakehouse in a running runtime.
"""
from __future__ import annotations

import collections
import datetime as dt
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401

from ulpf.query import QuerySyntaxError, parse  # noqa: E402
from ulpf.query.engine import Governor, QueryEngine, QueryError, Timeout  # noqa: E402

T0 = dt.datetime(2026, 11, 5, 8, 0, tzinfo=dt.timezone.utc)
USERS = ["alice", "bob", "carol", "dave"]


def make_events(n=600):
    out = []
    for i in range(n):
        ts = T0 + dt.timedelta(seconds=i * 30)
        out.append({
            "event_id": f"e{i}", "timestamp": ts.isoformat().replace("+00:00", "Z"),
            "category": "authentication" if i % 2 else "network",
            "action": "login_failed" if i % 3 == 0 else "allowed", "severity": i % 11,
            "source": {"ip": f"10.0.{i % 3}.{i % 7}", "port": 1024 + i}, "destination": {"ip": "192.0.2.10", "port": 443},
            "user": {"name": USERS[i % 4]}, "device": {"hostname": f"host{i % 5}"},
            "network": {"bytes_in": i * 3, "protocol": "tcp"},
            "message": f"session {i} closed by admin" if i % 10 == 0 else f"session {i} ok",
            "raw_event": f"<34>Nov  5 host{i % 5} sshd[{100 + i}]: Failed password for {USERS[i % 4]} "
                         f"from 10.0.{i % 3}.{i % 7} port {1024 + i}",
            "parsed_fields": {"EventID": 4625 if i % 3 == 0 else 4624}})
    return out


EVENTS = make_events()


def table_of(events):
    from ulpf.storage.database import event_to_row, rows_to_arrow
    return rows_to_arrow([event_to_row(e) for e in events])


def ts(e):
    return dt.datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))


def hour(e):
    t = ts(e)
    return t.replace(minute=0, second=0).isoformat().replace("+00:00", "Z")


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table = table_of(EVENTS)
        cls.eng = QueryEngine()

    def q(self, dialect, text, **kw):
        return self.eng.run(dialect, text, table=self.table, max_rows=100_000, **kw)

    def rows(self, dialect, text, keys=None):
        r = self.q(dialect, text)
        return [tuple(x[k] for k in (keys or [c["name"] for c in r["columns"]])) for x in r["rows"]]


class TestSyntaxErrors(unittest.TestCase):
    def err(self, dialect, text):
        with self.assertRaises(QuerySyntaxError) as cm:
            parse(dialect, text)
        return cm.exception

    def test_positions(self):
        e = self.err("kql", "events\n| where severity >\n| take 3")
        self.assertEqual((e.line, e.column), (3, 1))
        e = self.err("kql", "events | summarize count() by\n   user.name, | take 1")
        self.assertEqual((e.line, e.column), (2, 15))
        e = self.err("kql", "events | where name == 'unterminated")
        self.assertEqual((e.line, e.column, e.message), (1, 24, "unterminated string"))
        e = self.err("kql", "events | frobnicate x")
        self.assertEqual((e.line, e.column), (1, 10))
        self.assertIn("unknown query operator", e.message)
        e = self.err("spl", "from events where x = 1\n| stats count( BY user")
        self.assertEqual((e.line, e.column), (2, 19))     # 'user' where ')' belongs
        e = self.err("spl", "| rex field=_raw \"no groups here\"")
        self.assertIn("named group", e.message)
        e = self.err("hql", "groupBy([user.name], function=frob())")
        self.assertEqual(e.line, 1)
        e = self.err("hql", "a=1 | regex(/(?<x>\\d+/")
        self.assertEqual((e.line, e.column), (1, 23))           # the call's missing ')'
        e = self.err("hql", "a=1 | regex(/(?<x>\\d+/)")
        self.assertEqual((e.line, e.column), (1, 13))           # the malformed pattern itself
        self.assertIn("invalid regular expression", e.message)
        self.assertIn("^", e.snippet)

    def test_hostile_input_is_a_syntax_error(self):
        eng = QueryEngine()
        t = table_of(EVENTS[:5])
        for d, q in [("kql", "events | where " + "(" * 500 + "1" + ")" * 500), ("kql", "events | where " + "not " * 20000 + "true"),
                     ("kql", "events | where " + " and ".join(["severity > 1"] * 5000)),
                     ("hql", "! " * 20000 + "a=1"), ("spl", "search " + "NOT " * 20000 + "x"), ("kql", "x" * 70000)]:
            with self.assertRaises(QuerySyntaxError, msg=q[:40]):
                eng.run(d, q, table=t)

    def test_semantic_errors_have_positions(self):
        eng = QueryEngine()
        t = table_of(EVENTS[:5])
        with self.assertRaises(QuerySyntaxError) as cm:
            eng.run("kql", "events\n| extend x = nosuchfn(severity)", table=t)
        self.assertEqual((cm.exception.line, cm.exception.column), (2, 14))
        with self.assertRaises(QuerySyntaxError) as cm:
            eng.run("kql", "events | where count() > 1", table=t)
        self.assertIn("aggregation", cm.exception.message)


class TestKql(Base):
    def test_summarize_by_user(self):
        want = collections.Counter(e["user"]["name"] for e in EVENTS if e["action"] == "login_failed")
        got = self.rows("kql", "events | where action == 'login_failed' | summarize count() by user.name | sort by count_ desc")
        self.assertEqual(dict(got), dict(want))
        self.assertEqual([c for _, c in got], sorted(want.values(), reverse=True))

    def test_bin_hour_and_time_filter(self):
        cut = T0 + dt.timedelta(hours=1, minutes=30)
        want = collections.Counter((hour(e), e["user"]["name"]) for e in EVENTS if ts(e) > cut)
        got = self.rows("kql", "SecurityEvent | where TimeGenerated > datetime(2026-11-05 09:30) "
                               "| summarize n = count() by bin(TimeGenerated, 1h), user.name")
        self.assertEqual({(a, b): n for a, b, n in got}, dict(want))

    def test_extend_project_string_ops(self):
        want = [(e["event_id"], e["network"]["bytes_in"] * 2) for e in EVENTS
                if "ADMIN" in e["message"].upper() and e["network"]["bytes_in"] > 600]
        got = self.rows("kql", "events | extend b = toint(network.bytes_in) * 2 | where message contains 'ADMIN' "
                               "and b > 1200 | project event_id, b | sort by b asc")
        self.assertEqual(got, sorted(want, key=lambda x: x[1]))
        n = self.rows("kql", "events | where message has 'admin' and message !has 'adm' | count")
        self.assertEqual(n, [(sum(1 for e in EVENTS if "admin" in e["message"]),)])
        n = self.rows("kql", "events | where user.name in~ ('ALICE', 'Bob') and severity between (3 .. 5) | count")
        self.assertEqual(n[0][0], sum(1 for e in EVENTS if e["user"]["name"] in ("alice", "bob") and 3 <= e["severity"] <= 5))
        n = self.rows("kql", "events | where raw_event matches regex @'port 10[0-9]{2}\\b' | count")
        self.assertEqual(n[0][0], sum(1 for e in EVENTS if 1000 <= e["source"]["port"] <= 1099))

    def test_dcount_top_distinct(self):
        got = self.rows("kql", "events | summarize ips = dcount(source.ip), mx = max(severity) by user.name | top 2 by ips desc")
        want = {u: len({e["source"]["ip"] for e in EVENTS if e["user"]["name"] == u}) for u in USERS}
        self.assertEqual(len(got), 2)
        for u, ips, mx in got:
            self.assertEqual(ips, want[u])
        self.assertEqual(sorted(r[0] for r in self.rows("kql", "events | distinct device.hostname")),
                         sorted({e["device"]["hostname"] for e in EVENTS}))

    def test_join_kinds(self):
        hi = collections.Counter(e["user"]["name"] for e in EVENTS if e["severity"] >= 9)
        fails = collections.Counter(e["user"]["name"] for e in EVENTS if e["action"] == "login_failed")
        got = self.rows("kql", "events | where action == 'login_failed' | summarize fails = count() by user.name "
                               "| join kind=inner (events | where severity >= 9 | summarize hi = count() by user.name) on user.name")
        self.assertEqual({u: (f, h) for u, f, h in got}, {u: (fails[u], hi[u]) for u in fails if u in hi})
        got = self.rows("kql", "events | summarize by user.name | join kind=leftanti (events | where user.name == 'bob' "
                               "| summarize by user.name) on user.name")
        self.assertEqual(sorted(r[0] for r in got), ["alice", "carol", "dave"])

    def test_make_series_and_mv_expand(self):
        got = self.rows("kql", "events | where user.name == 'alice' | make-series n = count() default = 0 on timestamp "
                               "from datetime(2026-11-05 08:00) to datetime(2026-11-05 14:00) step 1h")
        want = [sum(1 for e in EVENTS if e["user"]["name"] == "alice" and ts(e).hour == h) for h in range(8, 14)]
        self.assertEqual(got[0][0], want)
        self.assertEqual(got[0][1][0], "2026-11-05T08:00:00Z")
        got = self.rows("kql", "events | extend w = split(message, ' ') | mv-expand w | summarize c = count() by tostring(w) "
                               "| where w in ('session', 'admin')")
        self.assertEqual(dict(got), {"session": len(EVENTS), "admin": sum(1 for e in EVENTS if "admin" in e["message"])})


class TestSpl(Base):
    def test_stats_by(self):
        want = {u: (sum(1 for e in EVENTS if e["user"]["name"] == u and e["action"] == "login_failed"),
                    len({e["source"]["ip"] for e in EVENTS if e["user"]["name"] == u and e["action"] == "login_failed"}))
                for u in USERS}
        got = self.rows("spl", 'from events where action = "login_failed" | stats count() AS n, dc(src) AS ips BY user | sort -n')
        self.assertEqual({u: (n, ips) for u, n, ips in got}, want)

    def test_search_rex_dedup_lookup(self):
        got = self.rows("spl", 'search sshd user=car* | rex field=_raw "from (?<srcip>\\d+\\.\\d+\\.\\d+\\.\\d+) port '
                               '(?<p>\\d+)" | stats count BY srcip')
        want = collections.Counter(e["source"]["ip"] for e in EVENTS if e["user"]["name"] == "carol")
        self.assertEqual(dict(got), dict(want))
        got = self.rows("spl", "| eval sev2 = severity * 2 | where sev2 > 15 | dedup user | table user, sev2")
        self.assertEqual(sorted(r[0] for r in got), sorted(USERS))
        newest = {}
        for e in sorted(EVENTS, key=ts, reverse=True):
            if e["severity"] * 2 > 15:
                newest.setdefault(e["user"]["name"], e["severity"] * 2)
        self.assertEqual(dict(got), newest)
        d = tempfile.mkdtemp(prefix="ulpf_lookup_")
        with open(os.path.join(d, "assets.csv"), "w", encoding="utf-8") as f:
            f.write("hostname,owner,tier\nhost0,ops,gold\nhost1,dev,silver\nhost1,dup,ignored\n")
        eng = QueryEngine(lookup_dir=d)
        r = eng.run("spl", "| lookup assets hostname AS host OUTPUT owner, tier AS t | stats count BY owner, t",
                    table=self.table)
        got = {(x["owner"], x["t"]): x["count"] for x in r["rows"]}
        hosts = collections.Counter(e["device"]["hostname"] for e in EVENTS)
        self.assertEqual(got[("ops", "gold")], hosts["host0"])
        self.assertEqual(got[("dev", "silver")], hosts["host1"])       # first row of a duplicate key wins
        self.assertEqual(got[(None, None)], len(EVENTS) - hosts["host0"] - hosts["host1"])

    def test_timechart_and_top(self):
        got = self.rows("spl", "| timechart span=1h count() BY category")
        want = collections.Counter((hour(e), e["category"]) for e in EVENTS)
        self.assertEqual({(a, b): c for a, b, c in got}, dict(want))
        got = self.rows("spl", "| top 2 host")
        want = collections.Counter(e["device"]["hostname"] for e in EVENTS).most_common()
        self.assertEqual([c for _, c in got], [c for _, c in want[:2]])


class TestHql(Base):
    def test_groupby_functions(self):
        got = self.rows("hql", "action=login_failed | groupBy([user.name], function=[count(), max(severity), "
                               "avg(severity, as=avgsev)]) | sort(_count, order=desc)")
        for u, cnt, mx, avg in got:
            sev = [e["severity"] for e in EVENTS if e["user"]["name"] == u and e["action"] == "login_failed"]
            self.assertEqual((cnt, mx), (len(sev), max(sev)))
            self.assertAlmostEqual(avg, sum(sev) / len(sev))

    def test_regex_extraction_and_filters(self):
        got = self.rows("hql", '/Failed password for (?<who>\\w+) from/ | groupBy(who)')
        self.assertEqual(dict(got), dict(collections.Counter(e["user"]["name"] for e in EVENTS)))
        n = self.rows("hql", "source.ip=10.0.1.* user.name!=bob severity>5 | count()")
        self.assertEqual(n[0][0], sum(1 for e in EVENTS if e["source"]["ip"].startswith("10.0.1.")
                                       and e["user"]["name"] != "bob" and e["severity"] > 5))
        n = self.rows("hql", 'user.name=/^(alice|dave)$/ or "closed by admin" | count()')
        self.assertEqual(n[0][0], sum(1 for e in EVENTS if e["user"]["name"] in ("alice", "dave")
                                       or "closed by admin" in e["raw_event"] or "closed by admin" in e["message"]
                                       and False))
        got = self.rows("hql", "in(user.name, values=[alice, bob]) | x := severity * 10 | table([user.name, x], limit=3)")
        self.assertEqual(len(got), 3)

    def test_bucket(self):
        got = self.rows("hql", "bucket(span=1h, function=count())")
        want = collections.Counter(hour(e) for e in EVENTS)
        self.assertEqual(dict(got), dict(want))


class TestCrossDialect(Base):
    def test_same_question_same_answer(self):
        kql = self.rows("kql", "events | where severity >= 5 and category == 'authentication' "
                               "| summarize n = count() by user.name | sort by user.name asc")
        spl = self.rows("spl", 'from events where severity >= 5 AND category = "authentication" '
                               "| stats count() AS n BY user | sort user")
        hql = self.rows("hql", "severity>=5 category=authentication | groupBy([user.name]) | sort(user.name, order=asc)")
        self.assertEqual(kql, spl)
        self.assertEqual(kql, hql)
        self.assertEqual(sum(n for _, n in kql), sum(1 for e in EVENTS if e["severity"] >= 5 and e["category"] == "authentication"))


class TestGovernor(unittest.TestCase):
    def test_fair_share_round_robin(self):
        g = Governor(max_concurrent=1, per_user=1, memory_mb=1024, query_memory_mb=64, timeout_s=10)
        order = []
        first = g.acquire("heavy", time.monotonic() + 10)
        lock = threading.Lock()

        def ask(user, k):
            t = g.acquire(user, time.monotonic() + 10)
            with lock:
                order.append((user, k))
            time.sleep(0.02)
            g.release(t)

        threads = [threading.Thread(target=ask, args=("heavy", k)) for k in range(4)]
        for th in threads:
            th.start()
            time.sleep(0.02)
        light = threading.Thread(target=ask, args=("light", 0))
        light.start()
        time.sleep(0.05)
        g.release(first)
        for th in threads + [light]:
            th.join(10)
        self.assertIn(("light", 0), order[:2])           # not behind the heavy user's whole queue
        self.assertEqual(len(order), 5)

    def test_queue_full_and_wait_deadline(self):
        g = Governor(max_concurrent=1, per_user=1, memory_mb=1024, query_memory_mb=64, max_queue=1, timeout_s=10)
        held = g.acquire("a", time.monotonic() + 5)
        with self.assertRaises(Timeout):
            g.acquire("b", time.monotonic() + 0.2)
        g.release(held)
        self.assertEqual(g.snapshot()["timeouts"], 1)

    def test_query_deadline_interrupts(self):
        big = table_of(make_events(4000))
        eng = QueryEngine(governor=Governor(timeout_s=1.0))
        t0 = time.monotonic()
        with self.assertRaises(Timeout):
            eng.run("kql", "events | join kind=inner (events | join kind=inner (events) on category) on category "
                           "| summarize count()", table=big, timeout_s=1.0)
        self.assertLess(time.monotonic() - t0, 5)

    def test_memory_limit(self):
        big = table_of(make_events(30000))
        eng = QueryEngine(governor=Governor(memory_mb=64, query_memory_mb=32))
        with self.assertRaises(QueryError) as cm:
            eng.run("kql", "events | join kind=inner (events) on category | summarize make_list(raw_event)", table=big)
        self.assertIn("memory", str(cm.exception).lower())


class TestRuntimeQueryAndLive(unittest.TestCase):
    def test_store_query_and_live_tail(self):
        from tests.test_inputs import free_port, start_runtime, wait_for
        d = tempfile.mkdtemp(prefix="ulpf_qrt_")
        port = free_port()
        rt = start_runtime(d, [{"type": "syslog", "name": "tcp", "protocol": "tcp", "host": "127.0.0.1", "port": port}])
        try:
            self.assertTrue(wait_for(lambda: rt.live is not None, 10))
            with self.assertRaises(Exception):
                rt.live.open("ana", "kql", "events | summarize count()")       # not row-level
            tail = rt.live.open("ana", "kql", "events | where raw_event contains 'Failed' and source.ip == '10.9.9.9' "
                                              "| project timestamp, source.ip, message")
            time.sleep(0.5)                                                   # lease reaches the workers
            lines = [b"<38>Nov  5 08:00:%02d gw sshd[1]: Failed password for root from 10.9.9.9 port 22 ssh2\n" % i
                     for i in range(5)]
            lines += [b"<38>Nov  5 08:01:%02d gw sshd[1]: Accepted password for bob from 10.1.1.1 port 22 ssh2\n" % i
                      for i in range(5)]
            sent = time.monotonic()
            with socket.create_connection(("127.0.0.1", port)) as c:
                c.sendall(b"".join(lines))
            got, first_at = [], None
            while time.monotonic() - sent < 10 and len(got) < 5:
                r = rt.live.poll(tail["id"], "ana", 100, 1.0)
                if r["rows"] and first_at is None:
                    first_at = time.monotonic()
                got += r["rows"]
            self.assertEqual(len(got), 5)
            self.assertTrue(all(x["source.ip"] == "10.9.9.9" for x in got))
            self.assertLess(first_at - sent, 1.0, "live tail latency")
            with self.assertRaises(Exception):
                rt.live.poll(tail["id"], "mallory", 10, 0)                    # other analysts cannot read it
            rt.live.close(tail["id"], "ana")
            # the same events, historically, from the store
            self.assertTrue(wait_for(lambda: rt.query_engine.run("kql", "events | count")["rows"][0]["Count"] == 10, 30))
            r = rt.query_engine.run("spl", 'search "Failed password" | stats count BY src', user="ana")
            self.assertEqual(r["rows"], [{"src": "10.9.9.9", "count": 5}])
            r = rt.query_engine.run("hql", "source.ip=10.1.1.1 | count()", user="ana")
            self.assertEqual(r["rows"][0]["_count"], 5)
        finally:
            rt.stop()

    def test_http_api(self):
        import json
        import urllib.error
        import urllib.request
        from ulpf.api.auth import new_key
        from tests.test_inputs import free_port, start_runtime, wait_for
        d = tempfile.mkdtemp(prefix="ulpf_qapi_")
        keys = os.path.join(d, "keys.json")
        ana, bob = new_key(keys, "ana", "read"), new_key(keys, "bob", "read")
        old = os.environ.get("ULPF_API_KEYS_FILE")
        os.environ["ULPF_API_KEYS_FILE"] = keys
        self.addCleanup(lambda: os.environ.pop("ULPF_API_KEYS_FILE") if old is None
                        else os.environ.__setitem__("ULPF_API_KEYS_FILE", old))
        port = free_port()
        rt = start_runtime(d, [{"type": "syslog", "name": "tcp", "protocol": "tcp", "host": "127.0.0.1", "port": port}],
                           api=True)
        base = rt.api_server.url

        def call(method, path, body=None, key=ana):
            req = urllib.request.Request(base + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json", **({"X-API-Key": key} if key else {})})
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    return r.status, json.loads(r.read() or b"null")
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read() or b"null")

        try:
            self.assertEqual(call("POST", "/api/v1/query", {"dialect": "kql", "query": "events | count"}, key=None)[0], 401)
            st, body = call("POST", "/api/v1/query/validate", {"dialect": "kql", "query": "events\n| where x =="})
            self.assertEqual((st, body["line"], body["column"]), (400, 2, 13))     # the missing operand
            st, tail = call("POST", "/api/v1/live", {"dialect": "spl", "query": 'search "Failed password" | table src, message'})
            self.assertEqual(st, 201)
            self.assertEqual(call("GET", f"/api/v1/live/{tail['id']}", key=bob)[0], 404)   # bob cannot read ana's tail
            time.sleep(0.5)
            with socket.create_connection(("127.0.0.1", port)) as c:
                c.sendall(b"".join(b"<38>Nov  5 08:00:%02d gw sshd[1]: Failed password for root from 10.7.7.%d port 22\n"
                                   % (i, i) for i in range(3)))
            got = []
            deadline = time.monotonic() + 10
            while len(got) < 3 and time.monotonic() < deadline:
                got += call("GET", f"/api/v1/live/{tail['id']}?wait=1")[1]["rows"]
            self.assertEqual(sorted(r["src"] for r in got), ["10.7.7.0", "10.7.7.1", "10.7.7.2"])
            self.assertEqual(call("DELETE", f"/api/v1/live/{tail['id']}")[0], 200)
            self.assertTrue(wait_for(lambda: call("POST", "/api/v1/query", {"dialect": "hql", "query": "count()"})[1]
                                     .get("rows", [{}])[0].get("_count") == 3, 30))
            st, body = call("POST", "/api/v1/query", {"dialect": "kql", "query": "events | summarize n = count() by source.ip "
                                                                               "| sort by source.ip asc"}, key=bob)
            self.assertEqual((st, [r["n"] for r in body["rows"]]), (200, [1, 1, 1]))
            st, gov = call("GET", "/api/v1/query/governor")
            self.assertGreaterEqual(gov["completed"], 2)
        finally:
            rt.stop()

    def test_lakehouse_source(self):
        import base64
        from tests.test_lakehouse import HAVE, lake_opts
        if not HAVE:
            self.skipTest("ulpf_core hot tier not built")
        from ulpf.lake import schema
        from ulpf.lake.service import LakeService, get
        import pyarrow as pa
        d = tempfile.mkdtemp(prefix="ulpf_qlake_")
        os.environ["ULPF_T_QLAKE"] = base64.b64encode(os.urandom(32)).decode()
        svc = LakeService("qlake", lake_opts(d, encrypted=False), d).start()
        try:
            rows = schema.rows(EVENTS, lambda e: "acme")
            svc.hot.append(pa.Table.from_pylist(rows[:300], schema=schema.SCHEMA), "s1")
            svc.flush_once()
            svc.hot.append(pa.Table.from_pylist(rows[300:], schema=schema.SCHEMA), "s2")   # 300 hot, 300 cold
            eng = QueryEngine(lakes=get)
            r = eng.run("kql", "events | summarize n = count() by user.name", source="lake:qlake")
            self.assertEqual({x["user.name"]: x["n"] for x in r["rows"]},
                             dict(collections.Counter(e["user"]["name"] for e in EVENTS)))
            r = eng.run("spl", "| stats count BY tenant_id", source="lake:qlake")
            self.assertEqual(r["rows"], [{"tenant_id": "acme", "count": len(EVENTS)}])
        finally:
            svc.stop()


if __name__ == "__main__":
    unittest.main()
