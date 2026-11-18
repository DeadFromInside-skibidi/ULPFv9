"""
YARA-L 2.0: rules parsed, evaluated per event in the "workers" (UDM view of real pipeline
events), joined in the "host" correlator: multi-event joins with ordering, counts, negation,
sliding windows, regex backreferences, outcomes; syntax errors with line and column.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401

from ulpf.intelligence.yaral import (YaraLCorrelator, YaraLEngine, YaraLError,  # noqa: E402
                                     parse_rules)

BRUTE = r'''
rule brute_force_then_success {
  meta:
    severity = "HIGH"
    risk = 80
  events:
    $fail.metadata.event_type = "USER_LOGIN"
    $fail.security_result.action = "FAIL"
    $fail.target.user.userid = $user
    $ok.metadata.event_type = "USER_LOGIN"
    $ok.security_result.action = "ALLOW"
    $ok.target.user.userid = $user
    $fail.metadata.event_timestamp.seconds < $ok.metadata.event_timestamp.seconds
  match:
    $user over 15m
  outcome:
    $risk_score = max(80)
    $sources = array_distinct($fail.principal.ip)
    $failures = count($fail.metadata.product_log_id)
  condition:
    #fail >= 3 and $ok
}
'''

NO_MFA = r'''
rule login_without_mfa {
  events:
    $login.metadata.event_type = "USER_LOGIN"
    $login.security_result.action = "ALLOW"
    $login.target.user.userid = $user
    $mfa.metadata.description = /mfa (approved|verified)/ nocase
    $user = re.capture($mfa.metadata.description, `for (\w+)`)
  match:
    $user over 1h
  condition:
    $login and !$mfa
}
'''

SLIDE = r'''
rule fail_after_login {
  events:
    $login.security_result.action = "ALLOW"
    $login.target.user.userid = $user
    $fail.security_result.action = "FAIL"
    $fail.target.user.userid = $user
  match:
    $user over 10m after $login
  condition:
    $login and #fail >= 2
}
'''

BACKREF = r'''
rule doubled_letter_user {
  events:
    $e.metadata.event_type = "USER_LOGIN"
    re.regex($e.target.user.userid, `^(\w)\1`)
    not net.ip_in_range_cidr($e.principal.ip, "192.168.0.0/16")
  condition:
    $e
}
'''


def events(lines):
    from ulpf.engine.pipeline import Pipeline
    p = Pipeline(enable_auto_parser=False)
    return [p.process_line(x)["event"] for x in lines]


def fail(t, user, ip="10.9.9.9"):
    return f"<38>Nov  5 {t} gw sshd[1]: Failed password for {user} from {ip} port 22 ssh2"


def ok(t, user, ip="10.1.1.1"):
    return f"<38>Nov  5 {t} gw sshd[1]: Accepted password for {user} from {ip} port 22 ssh2"


def mfa(t, user):
    return f"<38>Nov  5 {t} gw duo: MFA approved for {user}"


def run(rule_text, lines):
    rules = parse_rules(rule_text)
    host = YaraLCorrelator(rules)
    eng = YaraLEngine(rules)
    out = []
    for e in events(lines):                     # one batch per event: order matters, like ingest
        out += host.submit(eng.extract([e]))
    out += host.tick(10**12)
    return out


class TestYaraL(unittest.TestCase):
    def test_multi_event_join_with_order_and_count(self):
        lines = [fail(f"08:00:0{i}", "alice", f"10.9.9.{i}") for i in range(4)] + [ok("08:01:00", "alice")]
        lines += [fail("08:00:00", "bob"), ok("08:00:30", "bob")]           # bob: one failure only
        lines += [ok("08:02:00", "carol")] + [fail(f"08:03:0{i}", "carol") for i in range(4)]   # success first
        d = run(BRUTE, lines)
        self.assertEqual([x.key for x in d], [("alice",)])
        x = d[0].to_dict()
        self.assertEqual(x["counts"], {"fail": 4, "ok": 1})
        self.assertEqual(x["outcome"]["risk_score"], 80)
        self.assertEqual(x["outcome"]["sources"], ["10.9.9.0", "10.9.9.1", "10.9.9.2", "10.9.9.3"])
        self.assertEqual(x["outcome"]["failures"], 4)
        self.assertEqual(len(x["events"]), 5)

    def test_negation_decided_when_window_closes(self):
        d = run(NO_MFA, [ok("08:00:00", "alice"), mfa("08:00:20", "alice"), ok("08:05:00", "bob"),
                         fail("09:30:00", "zed")])
        self.assertEqual([x.key for x in d], [("bob",)])

    def test_sliding_window_after_pivot(self):
        d = run(SLIDE, [ok("08:00:00", "alice"), fail("08:03:00", "alice"), fail("08:09:00", "alice"),
                        ok("08:00:00", "bob"), fail("08:03:00", "bob"), fail("08:12:00", "bob")])
        self.assertEqual([x.key for x in d], [("alice",)])

    def test_regex_backreference_and_cidr(self):
        d = run(BACKREF, [ok("08:00:00", "aaron"), ok("08:00:01", "bob"), ok("08:00:02", "eel", "192.168.1.5")])
        self.assertEqual(len(d), 1)
        self.assertEqual(d[0].counts["e"], 1)

    def test_syntax_errors(self):
        with self.assertRaises(YaraLError) as cm:
            parse_rules("rule x {\n  events:\n    $e.metadata.event_type = \n  condition:\n    $e\n}")
        self.assertEqual((cm.exception.line, cm.exception.column), (3, 30))   # the missing value
        with self.assertRaises(YaraLError) as cm:
            parse_rules('rule x {\n events:\n  re.regex($e.a, `(a+)+$`)\n condition:\n  $e\n}')
        self.assertIn("nested quantifiers", str(cm.exception))
        with self.assertRaises(YaraLError) as cm:
            parse_rules('rule x {\n events:\n  $e.a = "1"\n match:\n  $u over 5m\n condition:\n  $e\n}')
        self.assertIn("match variable $u", str(cm.exception))
        with self.assertRaises(YaraLError) as cm:
            parse_rules('rule x {\n events:\n  $e.a = "1"\n condition:\n  #e\n}')
        self.assertIn("comparison", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
