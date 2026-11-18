"""
Sigma correlation rules (event_count, value_count, temporal, temporal_ordered), their hits in
the compiled core, risk-based alerting (decay, thresholds, tactics, suppression, persistence),
and a runtime that turns ingested lines into correlation detections, YARA-L detections and a
Notable Incident.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import socket
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401

from ulpf.intelligence.risk import RiskEngine, RiskEvent  # noqa: E402
from ulpf.intelligence.sigma import SigmaEngine, load_rules  # noqa: E402

T0 = dt.datetime(2026, 11, 5, 8, 0, tzinfo=dt.timezone.utc)

RULES = """
title: Failed logon
id: 11111111-0000-0000-0000-000000000001
name: failed_logon
status: test
logsource: {product: ulpf, category: authentication}
detection:
  selection: {action: failure}
  condition: selection
level: low
tags: [attack.credential_access, attack.t1110]
---
title: Successful logon
id: 11111111-0000-0000-0000-000000000002
name: ok_logon
logsource: {product: ulpf, category: authentication}
detection:
  selection: {action: success}
  condition: selection
level: low
---
title: New service installed
id: 11111111-0000-0000-0000-000000000003
name: new_service
logsource: {product: ulpf, category: system}
detection:
  selection: {action: service_installed}
  condition: selection
level: medium
tags: [attack.persistence]
---
title: Brute force (5 failures for one user in 5 minutes)
id: 22222222-0000-0000-0000-000000000001
correlation:
  type: event_count
  rules: [failed_logon]
  group-by: [user.name]
  timespan: 5m
  condition: {gte: 5}
level: high
tags: [attack.credential_access]
---
title: Password spray (one source, 3 users)
id: 22222222-0000-0000-0000-000000000002
correlation:
  type: value_count
  rules: [failed_logon]
  group-by: [source.ip]
  timespan: 10m
  condition: {field: user.name, gte: 3}
level: high
---
title: Logon then service on the same host
id: 22222222-0000-0000-0000-000000000003
correlation:
  type: temporal_ordered
  rules: [ok_logon, new_service]
  group-by: [host]
  aliases:
    host: {ok_logon: device.hostname, new_service: device.hostname}
  timespan: 10m
level: critical
generate: true
"""


def ev(i, action, category, user="alice", ip="10.0.0.5", host="ws1", minutes=0.0):
    return {"event_id": f"e{i}", "event_kind": "log", "category": category, "action": action,
            "timestamp": (T0 + dt.timedelta(minutes=minutes)).isoformat(), "source": {"ip": ip},
            "user": {"name": user}, "device": {"hostname": host}, "raw_event": f"x {action}", "message": "",
            "parsed_fields": {}}


def engine():
    d = tempfile.mkdtemp(prefix="ulpf_corr_")
    with open(os.path.join(d, "rules.yml"), "w", encoding="utf-8") as f:
        f.write(RULES)
    rules, corrs, errors = load_rules([d], builtin=False, with_correlations=True)
    assert not errors, errors
    return SigmaEngine(rules, correlations=corrs), d


def run(eng, events):
    out = []
    for e in events:
        out += eng.detect(e, dt.datetime.fromisoformat(e["timestamp"]))
    return out


class TestSigmaCorrelations(unittest.TestCase):
    def test_event_count_fires_once_and_suppresses_base(self):
        eng, _ = engine()
        evs = [ev(i, "failure", "authentication", minutes=i * 0.5) for i in range(7)]
        evs += [ev(10 + i, "failure", "authentication", user="bob", minutes=i * 2) for i in range(5)]   # 8 min span
        d = run(eng, evs)
        brute = [x for x in d if x.rule.title.startswith("Brute force")]
        self.assertEqual([(x.key, x.count) for x in brute], [("alice", 5)])
        self.assertFalse(any(x.rule.title == "Failed logon" for x in d))       # generate: false

    def test_value_count(self):
        eng, _ = engine()
        evs = [ev(i, "failure", "authentication", user=f"u{i % 4}", ip="203.0.113.9", minutes=i) for i in range(4)]
        spray = [x for x in run(eng, evs) if x.rule.title.startswith("Password spray")]
        self.assertEqual([(x.key, x.count) for x in spray], [("203.0.113.9", 3)])

    def test_temporal_ordered_and_generate(self):
        eng, _ = engine()
        d = run(eng, [ev(1, "success", "authentication", host="ws1"), ev(2, "service_installed", "system", host="ws1",
                                                                          minutes=3),
                      ev(3, "service_installed", "system", host="ws2"), ev(4, "success", "authentication", host="ws2",
                                                                            minutes=3),
                      ev(5, "success", "authentication", host="ws3"), ev(6, "service_installed", "system", host="ws3",
                                                                          minutes=30)])
        seq = [x for x in d if x.rule.title.startswith("Logon then service")]
        self.assertEqual([x.key for x in seq], ["ws1"])
        self.assertTrue(any(x.rule.title == "Successful logon" for x in d))     # generate: true keeps base alerts

    def test_bad_correlations_are_rejected(self):
        d = tempfile.mkdtemp(prefix="ulpf_corr_bad_")
        with open(os.path.join(d, "r.yml"), "w", encoding="utf-8") as f:
            f.write("title: x\nid: a\ncorrelation: {type: event_count, rules: [nope], timespan: 5m, condition: {gte: 2}}\n"
                    "---\ntitle: y\nid: b\ncorrelation: {type: weird, rules: [x], timespan: 5m}\n")
        rules, corrs, errors = load_rules([d], builtin=False, with_correlations=True)
        self.assertEqual(corrs, [])
        self.assertTrue(any("unknown rule" in e for e in errors), errors)
        self.assertTrue(any("unknown correlation type" in e for e in errors), errors)

    def test_core_hits_carry_the_same_correlation_values(self):
        try:
            from ulpf import ulpf_core
        except ImportError:
            self.skipTest("ulpf_core not built")
        import orjson
        eng, _ = engine()
        an = ulpf_core.Analytics(orjson.dumps(eng.ir()).decode(), None)
        for e in [ev(1, "failure", "authentication"), ev(2, "success", "authentication", host="h9"),
                  ev(3, "service_installed", "system", host="h9")]:
            got = json.loads(an.sigma_match_json(orjson.dumps(e).decode()))
            self.assertEqual(got, json.loads(json.dumps(eng.match(e))))
            self.assertTrue(all(len(h) == 4 for h in got))


class TestRisk(unittest.TestCase):
    def test_half_life_decay(self):
        rk = RiskEngine(half_life_days=7, dynamic=False)
        rk.add([RiskEvent("user", "alice", 40, 0.0, "r1")])
        self.assertAlmostEqual(rk.score("user", "alice", 7 * 86400), 20.0)
        self.assertAlmostEqual(rk.score("user", "alice", 14 * 86400), 10.0)
        rk.add([RiskEvent("user", "alice", 30, 7 * 86400, "r2")])
        self.assertAlmostEqual(rk.score("user", "alice", 7 * 86400), 50.0)
        rk.add([RiskEvent("user", "alice", 20, 0.0, "late")])                 # late events arrive decayed
        self.assertAlmostEqual(rk.score("user", "alice", 7 * 86400), 60.0)

    def test_threshold_suppression_and_regrowth(self):
        rk = RiskEngine(dynamic=False, thresholds={"host": 100}, suppress_hours=24, renotify_growth=0.5)
        n = rk.add([RiskEvent("host", "ws1", 50, t, f"r{t}") for t in (0, 60, 120)])
        self.assertEqual(len(n), 1)
        self.assertEqual((n[0]["entity"], n[0]["score"] >= 100), ("ws1", True))
        self.assertEqual(rk.add([RiskEvent("host", "ws1", 10, 180, "r")]), [])              # suppressed
        self.assertEqual(len(rk.add([RiskEvent("host", "ws1", 80, 240, "big")])), 1)         # grew by half

    def test_tactic_diversity_and_dynamic_threshold(self):
        rk = RiskEngine(dynamic=False, tactic_threshold=3)
        n = rk.add([RiskEvent("user", "eve", 5, t, f"r{t}", (tac,)) for t, tac in
                    ((0, "discovery"), (10, "lateral_movement"), (20, "exfiltration"))])
        self.assertEqual(len(n), 1)
        self.assertIn("3 ATT&CK tactics", n[0]["reasons"][0])
        dyn = RiskEngine(dynamic=True, min_entities=20, dynamic_sigma=3, thresholds={"ip": 50})
        dyn.add([RiskEvent("ip", f"10.0.0.{i}", 60 + (i % 5), 0.0, "noisy") for i in range(40)])
        self.assertGreater(dyn.threshold("ip", 0.0), 60)                      # the noise floor is not notable
        self.assertEqual(dyn.add([RiskEvent("ip", "10.0.0.1", 1, 1.0, "x")]), [])
        self.assertEqual(len(dyn.add([RiskEvent("ip", "192.0.2.7", 300, 2.0, "x")])), 1)

    def test_persistence(self):
        rk = RiskEngine(dynamic=False)
        rk.add([RiskEvent("domain", "evil.example", 70, 100.0, "r", ("command_and_control",))])
        p = os.path.join(tempfile.mkdtemp(), "risk", "state.json")
        rk.save(p)
        rk2 = RiskEngine(dynamic=False)
        self.assertEqual(rk2.load(p), 1)
        self.assertAlmostEqual(rk2.score("domain", "evil.example", 100.0), 70.0)


YARAL = r'''
rule ssh_brute_force_then_login {
  meta:
    severity = "HIGH"
    tactic = "credential_access"
  events:
    $f.metadata.event_type = "USER_LOGIN"
    $f.security_result.action = "FAIL"
    $f.target.user.userid = $user
    $s.metadata.event_type = "USER_LOGIN"
    $s.security_result.action = "ALLOW"
    $s.target.user.userid = $user
    $f.metadata.event_timestamp.seconds <= $s.metadata.event_timestamp.seconds
  match:
    $user over 30m
  outcome:
    $risk_score = max(90)
  condition:
    #f >= 3 and $s
}
'''


class TestRuntimeDetections(unittest.TestCase):
    def test_correlation_yaral_and_notable_from_ingest(self):
        from tests.test_inputs import free_port, start_runtime, stored, wait_for
        d = tempfile.mkdtemp(prefix="ulpf_det_")
        rules = os.path.join(d, "sigma")
        os.makedirs(rules)
        with open(os.path.join(rules, "ssh.yml"), "w", encoding="utf-8") as f:
            f.write("""title: SSH failed password
id: 33333333-0000-0000-0000-000000000001
name: ssh_fail
logsource: {product: linux, service: sshd}
detection:
  keywords: ['Failed password']
  condition: keywords
level: medium
tags: [attack.credential_access, attack.t1110.001]
---
title: SSH brute force
id: 33333333-0000-0000-0000-000000000002
correlation:
  type: event_count
  rules: [ssh_fail]
  group-by: [source.ip]
  timespan: 10m
  condition: {gte: 4}
level: high
""")
        yl = os.path.join(d, "brute.yaral")
        with open(yl, "w", encoding="utf-8") as f:
            f.write(YARAL)
        port = free_port()
        rt = start_runtime(d, [{"type": "syslog", "name": "tcp", "protocol": "tcp", "host": "127.0.0.1", "port": port}],
                           default_output="store",
                           analytics={"correlation": {"enabled": True}, "anomaly": {"enabled": False},
                                      "drift": {"enabled": False},
                                      "sigma": {"rules": [rules], "builtin": False},
                                      "yaral": {"rules": [yl]},
                                      "risk": {"thresholds": {"user": 80, "ip": 80}, "dynamic": False}})
        try:
            # recent timestamps: risk decays with a 7-day half-life from the event time
            t0 = dt.datetime.now() - dt.timedelta(minutes=5)

            def stamp(sec):
                t = t0 + dt.timedelta(seconds=sec)
                return f"{t:%b} {t.day:2d} {t:%H:%M:%S}".encode()
            lines = [b"<38>" + stamp(i) + b" gw sshd[1]: Failed password for root from 10.66.6.6 port 22 ssh2\n"
                     for i in range(5)]
            lines += [b"<38>" + stamp(60) + b" gw sshd[1]: Accepted password for root from 10.66.6.6 port 22 ssh2\n"]
            with socket.create_connection(("127.0.0.1", port)) as c:
                c.sendall(b"".join(lines))

            def kinds():
                return dict(stored(rt, "SELECT json_extract_string(normalised_json, '$.event_kind') k, count(*) "
                                       "FROM events GROUP BY k"))
            self.assertTrue(wait_for(lambda: {"detection", "notable"} <= set(kinds()), 40), kinds())
            msgs = [m for (m,) in stored(rt, "SELECT message FROM events WHERE "
                                             "json_extract_string(normalised_json, '$.event_kind') IN ('detection','notable')")]
            self.assertTrue(any(m.startswith("Sigma: SSH brute force") for m in msgs), msgs)
            self.assertTrue(any(m.startswith("YARA-L: ssh_brute_force_then_login (root)") for m in msgs), msgs)
            self.assertTrue(any(m.startswith("Notable: user root") for m in msgs), msgs)
            self.assertFalse(any(m.startswith("Sigma: SSH failed password") for m in msgs))   # suppressed base rule
            ent = rt.correlator.risk.entity("user", "root")
            self.assertGreaterEqual(ent["score"], 80)
        finally:
            rt.stop()
        self.assertTrue(os.path.exists(os.path.join(d, "risk", "state.json")))


if __name__ == "__main__":
    unittest.main()
