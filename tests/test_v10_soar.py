"""v10 SOAR: cases, safe expressions, DAG playbooks, HITL, connectors, audit chain."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import unittest


class FakeTransport:
    def __init__(self, fail_first: int = 0):
        self.sent = []
        self.fail_first = fail_first

    def send(self, req):
        from ulpf.soar.connectors import ConnectorError
        self.sent.append(req)
        if self.fail_first > 0:
            self.fail_first -= 1
            raise ConnectorError("simulated outage")
        if req.url.endswith("/oauth2/token") or "oauth2/v2.0/token" in req.url:
            return 200, b'{"access_token": "tok", "expires_in": 3600}'
        if req.url.endswith("/security/user/authenticate"):
            return 200, b'{"data": {"token": "jwt"}}'
        if req.url.endswith("/web_api/login"):
            return 200, b'{"sid": "s1"}'
        return 200, b'{"ok": true}'


ENV = {"PANOS_KEY": "k", "FW_TOKEN": "t", "CP_USER": "u", "CP_PASS": "p", "ASA_USER": "u", "ASA_PASS": "p",
       "WZ_USER": "u", "WZ_PASS": "p", "MDE": "s", "CS": "s", "OKTA": "t", "ENTRA": "s", "AWS_AK": "AKIA",
       "AWS_SK": "secretvalue"}


def _wait(fn, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.02)
    raise AssertionError("timed out")


def _final(svc, rid):
    def f():
        r = svc.engine.get_run("default", rid)
        return r if r["status"] in ("succeeded", "failed") else None
    return _wait(f)


class Expressions(unittest.TestCase):
    def test_eval_and_templates(self):
        from ulpf.soar.expr import evaluate, render
        ctx = {"inputs": {"ip": "10.1.2.3", "hosts": ["a", "b"], "n": 3}, "steps": {"x": {"output": {"score": 80}}}}
        self.assertTrue(evaluate("steps.x.output.score >= 70 and len(inputs.hosts) == 2", ctx))
        self.assertTrue(evaluate("cidr_contains('10.0.0.0/8', inputs.ip)", ctx))
        self.assertFalse(evaluate("inputs.missing.deep == 3", ctx))
        self.assertEqual(render("{{ inputs.hosts }}", ctx), ["a", "b"])
        self.assertEqual(render("ip={{ inputs.ip }}", ctx), "ip=10.1.2.3")

    def test_hostile_expressions_rejected(self):
        from ulpf.soar.expr import ExprError, evaluate
        for bad in ("__import__('os').system('x')", "().__class__", "[x for x in inputs]", "lambda: 1",
                    "'a' * 10000000", "open('f')", "inputs.__class__.__bases__"):
            with self.subTest(bad=bad):
                try:
                    v = evaluate(bad, {"inputs": {}})
                except ExprError:
                    continue
                self.assertIsNone(v)          # attribute access on dicts only: never reaches Python objects


class Cases(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        from ulpf.soar.cases import CaseStore
        self.cs = CaseStore(self.d)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_lifecycle_sla_tenancy_and_locker(self):
        from ulpf.soar.cases import CaseError, NotFound
        c = self.cs.create("acme", "Brute force", "critical", actor="ana", first_event_at=time.time() - 120)
        self.assertEqual(c["state"], "new")
        self.assertAlmostEqual(c["mttd_seconds"], 120, delta=5)
        with self.assertRaises(NotFound):
            self.cs.get("globex", c["id"])                       # tenant isolation
        with self.assertRaises(CaseError):
            self.cs.transition("acme", c["id"], "eradication", "ana")   # illegal jump
        for st in ("triaged", "investigating", "containment", "eradication", "closed", "post_incident"):
            c = self.cs.transition("acme", c["id"], st, "ana")
        self.assertIsNotNone(c["mttr_seconds"])
        self.assertIsNotNone(c["time_to_contain_seconds"])
        a = self.cs.add_artifact("acme", c["id"], "pcap", b"\xd4\xc3\xb2\xa1" + b"x" * 100, "ana", "cap.pcap")
        self.assertEqual(self.cs.read_artifact("acme", a["id"], "bob")[:4], b"\xd4\xc3\xb2\xa1")
        self.assertEqual([x["action"] for x in self.cs.artifact("acme", a["id"])["custody"]], ["collected", "accessed"])
        blob = self.cs._blob_path(a["sha256"])
        os.chmod(blob, 0o666)
        with open(blob, "ab") as f:
            f.write(b"tamper")
        self.assertFalse(self.cs.verify_artifact("acme", a["id"])["intact"])
        kinds = [t["kind"] for t in self.cs.timeline("acme", c["id"])]
        self.assertIn("artifact", kinds)
        from ulpf.runtime.audit import verify_audit_log
        self.assertTrue(verify_audit_log(self.cs.audit.path)["valid"])

    def test_sla_breach(self):
        c = self.cs.create("t", "x", "critical", detected_at=time.time() - 3600)
        self.assertIn("triage", c["sla"]["breached"])


class Connectors(unittest.TestCase):
    def test_every_connector_plans_valid_requests(self):
        from ulpf.soar import connectors as cn
        cfgs = [
            ({"type": "panos", "url": "https://fw", "api_key_env": "PANOS_KEY"}, "block_ip", {"ip": "203.0.113.9"}),
            ({"type": "panos", "url": "https://fw", "api_key_env": "PANOS_KEY"}, "block_domain",
             {"domain": "evil.example.com"}),
            ({"type": "fortios", "url": "https://fg", "api_token_env": "FW_TOKEN"}, "block_ip",
             {"ip": "198.51.100.0/24"}),
            ({"type": "checkpoint", "url": "https://cp", "user_env": "CP_USER", "password_env": "CP_PASS"},
             "block_ip", {"ip": "203.0.113.9"}),
            ({"type": "cisco_asa", "url": "https://asa", "user_env": "ASA_USER", "password_env": "ASA_PASS"},
             "block_ip", {"ip": "203.0.113.9"}),
            ({"type": "nftables"}, "block_ip", {"ip": "2001:db8::1"}),
            ({"type": "iptables"}, "block_ip", {"ip": "203.0.113.9"}),
            ({"type": "wazuh", "url": "https://wz", "user_env": "WZ_USER", "password_env": "WZ_PASS"},
             "isolate_host", {"agent_id": "001"}),
            ({"type": "defender", "tenant_id": "t1", "client_id": "c", "client_secret_env": "MDE"},
             "isolate_host", {"machine_id": "abc123"}),
            ({"type": "crowdstrike", "client_id": "c", "client_secret_env": "CS"}, "isolate_host",
             {"device_id": "d1"}),
            ({"type": "active_directory"}, "disable_user", {"user": "jdoe"}),
            ({"type": "okta", "url": "https://corp.okta.com", "api_token_env": "OKTA"}, "disable_user",
             {"user": "jdoe@corp.com"}),
            ({"type": "entra", "tenant_id": "t1", "client_id": "c", "client_secret_env": "ENTRA"},
             "revoke_sessions", {"user": "jdoe@corp.com"}),
            ({"type": "aws_iam", "access_key_env": "AWS_AK", "secret_key_env": "AWS_SK"}, "disable_user",
             {"user": "ci-bot"}),
        ]
        for cfg, action, params in cfgs:
            with self.subTest(t=cfg["type"]):
                ft = FakeTransport()
                c = cn.build({"name": cfg["type"], **cfg}, ft, ENV)
                sim = c.execute(action, params, dry_run=True)
                self.assertEqual(sim["status"], "simulated")
                self.assertEqual(ft.sent, [])                      # dry run sends nothing
                self.assertNotIn("secretvalue", json.dumps(sim))
                if c.inverse(action):
                    self.assertIn(c.inverse(action), c.actions)
                if cfg["type"] in ("nftables", "iptables", "active_directory"):
                    continue
                res = c.execute(action, params)
                self.assertEqual(res["status"], "done")
                self.assertTrue(ft.sent)

    def test_injection_rejected(self):
        from ulpf.soar import connectors as cn
        c = cn.build({"type": "iptables", "name": "h"}, FakeTransport(), ENV)
        for bad in ("1.2.3.4; rm -rf /", "1.2.3.4 -j ACCEPT", "$(id)"):
            with self.assertRaises(cn.ConnectorError):
                c.plan("block_ip", {"ip": bad})
        ad = cn.build({"type": "active_directory", "name": "ad"}, FakeTransport(), ENV)
        with self.assertRaises(cn.ConnectorError):
            ad.plan("disable_user", {"user": "x'; Remove-Item C:/ -Recurse; '"})


class Playbooks(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        from ulpf.soar.service import SoarService
        self.ft = FakeTransport()
        self.svc = SoarService(self.d, {"connectors": [
            {"name": "perimeter-fw", "type": "panos", "url": "https://fw", "api_key_env": "PANOS_KEY"},
            {"name": "corp-ad", "type": "okta", "url": "https://o", "api_token_env": "OKTA"},
            {"name": "edr", "type": "crowdstrike", "client_id": "c", "client_secret_env": "CS"}]},
            transport=self.ft, env=dict(ENV))
        self.assertEqual(self.svc.playbook_errors, [])

    def tearDown(self):
        self.svc.close()
        shutil.rmtree(self.d, ignore_errors=True)

    def test_validation_errors(self):
        from ulpf.soar.playbook import PlaybookError, validate
        with self.assertRaises(PlaybookError):
            validate({"id": "x", "steps": [{"id": "a", "action": "util.echo", "needs": ["b"]},
                                           {"id": "b", "action": "util.echo", "needs": ["a"]}]})
        with self.assertRaises(PlaybookError):
            validate({"id": "x", "steps": [{"id": "a", "connector": "fw", "action": "block_ip", "approval": False}]})

    def test_brute_force_playbook_hitl_branch_rollback(self):
        case = self.svc.cases.create("default", "BF", "high")
        run = self.svc.engine.start("contain-external-brute-force", "default", {"ip": "203.0.113.50"}, "ana",
                                    case["id"], wait=True)
        self.assertEqual(run["status"], "waiting_approval")
        self.assertEqual(run["state"]["steps"]["internal_note"]["status"], "skipped")
        self.assertEqual(self.ft.sent, [])                    # nothing destructive before approval
        appr = self.svc.engine.approvals("default")
        self.assertEqual(len(appr), 1)
        with self.assertRaises(PermissionError):              # four-eyes
            self.svc.engine.decide("default", appr[0]["id"], "ana", True)
        self.svc.engine.decide("default", appr[0]["id"], "lead", True, "confirmed external", actor_roles={"admin"})
        run = _final(self.svc, run["id"])
        self.assertEqual(run["status"], "succeeded", run["state"])
        self.assertTrue(any(b"register" in (r.body or b"") for r in self.ft.sent))
        self.assertEqual(len(run["state"]["containment"]), 1)
        c = self.svc.cases.get("default", case["id"])
        self.assertIsNotNone(c["contained_at"])
        self.assertEqual(c["state"], "triaged")
        rb = self.svc.engine.rollback("default", run["id"], "lead")
        self.assertEqual(rb["rolled_back"][0]["action"], "unblock_ip")
        self.assertTrue(any(b"unregister" in (r.body or b"") for r in self.ft.sent))
        from ulpf.runtime.audit import verify_audit_log
        self.assertTrue(verify_audit_log(self.svc.audit.path)["valid"])
        with open(self.svc.audit.path, encoding="utf-8") as f:
            actions = [json.loads(line)["action"] for line in f]
        self.assertIn("soar.command", actions)
        self.assertIn("soar.approval_decided", actions)

    def test_internal_source_not_blocked_and_dry_run(self):
        case = self.svc.cases.create("default", "BF internal", "high")
        run = self.svc.engine.start("contain-external-brute-force", "default", {"ip": "10.9.9.9"}, "ana",
                                    case["id"], wait=True)
        self.assertEqual(run["status"], "succeeded", run["state"])
        self.assertEqual(run["state"]["steps"]["block_source"]["status"], "skipped")
        dry = self.svc.engine.start("contain-external-brute-force", "default", {"ip": "198.51.100.7"}, "ana",
                                    case["id"], dry_run=True, wait=True)
        self.assertEqual(dry["status"], "succeeded", dry["state"])
        self.assertEqual(dry["state"]["steps"]["block_source"]["output"]["status"], "simulated")
        self.assertEqual(self.ft.sent, [])

    def test_foreach_parallel_subplaybook_and_retries(self):
        self.svc.engine.register({"id": "multi", "steps": [
            {"id": "a", "action": "util.echo", "with": {"v": 1}},
            {"id": "b", "action": "util.echo", "with": {"v": 2}},
            {"id": "gate", "type": "approval", "needs": ["a", "b"]},
            {"id": "each", "type": "foreach", "needs": ["gate"], "approval": False, "items": "{{ inputs.hosts }}",
             "do": {"connector": "edr", "action": "isolate_host", "with": {"device_id": "{{ item }}"}},
             "retries": 2, "retry_delay": 0.01},
            {"id": "sub", "type": "playbook", "playbook": "notify-soc", "needs": ["each"],
             "with": {"message": "isolated {{ len(steps.each.output) }}"}}]})
        case = self.svc.cases.create("default", "multi", "critical")
        self.ft.fail_first = 1                       # one transient failure, recovered by a retry
        run = self.svc.engine.start("multi", "default", {"hosts": ["h1", "h2", "h3"]}, "ana", case["id"], wait=True)
        self.assertEqual(run["status"], "waiting_approval")
        aid = self.svc.engine.approvals("default")[0]["id"]
        self.svc.engine.decide("default", aid, "lead", True, actor_roles={"admin"})
        run = _final(self.svc, run["id"])
        self.assertEqual(run["status"], "succeeded", run["state"]["errors"])
        self.assertEqual(len(run["state"]["steps"]["each"]["output"]), 3)
        self.assertEqual(len(run["state"]["containment"]), 3)
        notes = [t for t in self.svc.cases.timeline("default", case["id"]) if t["kind"] == "note"]
        self.assertTrue(any("isolated 3" in n["detail"]["text"] for n in notes))

    def test_auto_case_from_detection(self):
        det = {"rule_id": "r-bf", "title": "Password spray", "level": "high", "techniques": ["T1110.003"],
               "key": "203.0.113.77", "count": 30, "event_id": "e1", "entities": {"ip": "203.0.113.77"}}
        cases = self.svc.on_detections([det])
        again = self.svc.on_detections([det])          # idempotent within the hour
        self.assertEqual(cases[0]["id"], again[0]["id"])
        runs = _wait(lambda: self.svc.engine.list_runs("default", case_id=cases[0]["id"]))
        self.assertEqual(runs[0]["playbook"], "contain-external-brute-force")


if __name__ == "__main__":
    unittest.main()
