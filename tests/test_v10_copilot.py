"""v10 copilot: offline backends, compiler-validated NL->query, grounded triage."""
from __future__ import annotations

import unittest


class FakeModel:
    name = "fake"
    device = "cpu"
    n_ctx = 2048

    def __init__(self, reply):
        self.reply = reply
        self.prompts = []

    def count_tokens(self, text):
        return max(1, len(text) // 4)

    def generate(self, system, prompt, max_tokens=512, grammar_json=False):
        self.prompts.append(prompt)
        return self.reply


class NlToQuery(unittest.TestCase):
    CASES = [
        "top 10 source ips with failed logins in the last 24 hours",
        "how many high severity detections today",
        "failed ssh logins for user alice by hour over the past 7 days",
        "show 50 firewall denies to 10.0.0.5",
        "count of logins by user in the last 3 days",
        "distinct users with successful logins last week",
        "powershell events on host web01",
    ]

    def test_grammar_output_compiles_in_every_dialect(self):
        from ulpf.copilot.nl2query import translate
        for q in self.CASES:
            for lang in ("kql", "spl", "hql"):
                with self.subTest(q=q, lang=lang):
                    res = translate(q, lang)
                    self.assertTrue(res["valid"], (res["query"], res["rejected"]))

    def test_intent_details(self):
        from ulpf.copilot.nl2query import translate
        r = translate("top 10 source ips with failed logins in the last 24 hours", "kql")
        self.assertIn("ago(24h)", r["query"])
        self.assertIn('action == "failed"', r["query"])
        self.assertIn("top 10 by count_", r["query"])
        r = translate("failed logins in the last 2 days", "spl")
        self.assertIsNotNone(r["start"])

    def test_invalid_model_answer_replaced_by_grammar(self):
        from ulpf.copilot.nl2query import translate
        bad = FakeModel('{"query": "events | frobnicate everything", "explanation": "x"}')
        r = translate("failed logins last 24 hours", "kql", bad)
        self.assertTrue(r["valid"])
        self.assertEqual(r["origin"], "grammar")
        self.assertEqual(r["rejected"][0]["origin"], "model")
        good = FakeModel('{"query": "events | where action == \\"failed\\" | count", "explanation": "x"}')
        self.assertEqual(translate("failed logins", "kql", good)["origin"], "model")


class Triage(unittest.TestCase):
    EVENTS = [
        {"event_id": f"e{i}", "timestamp": f"2026-03-01T10:00:{i:02d}Z", "message": "Failed password for root",
         "action": "failed", "source": {"ip": "203.0.113.9"}, "destination": {"ip": "10.0.0.5"},
         "device": {"hostname": "bastion01"}} for i in range(10)
    ] + [
        {"event_id": "e20", "timestamp": "2026-03-01T10:01:00Z", "message": "Accepted password for root",
         "action": "success", "source": {"ip": "203.0.113.9"}, "destination": {"ip": "10.0.0.5"},
         "user": {"name": "root"}, "device": {"hostname": "bastion01"}},
        {"event_id": "e21", "timestamp": "2026-03-01T10:05:00Z", "message": "ssh root@10.0.0.7 session opened",
         "action": "success", "source": {"ip": "10.0.0.5"}, "destination": {"ip": "10.0.0.7"}, "protocol": "ssh"},
        {"event_id": "e22", "timestamp": "2026-03-01T10:09:00Z", "message": "rclone upload to remote 198.51.100.4",
         "action": "allowed", "source": {"ip": "10.0.0.7"}, "destination": {"ip": "198.51.100.4"}},
    ]

    def test_narrative_is_grounded(self):
        from ulpf.copilot.triage import investigate
        r = investigate({"id": "CASE-1", "mitre": ["T1110"]}, self.EVENTS,
                        [{"rule_id": "x", "title": "SSH brute force", "techniques": ["T1110.001"], "event_id": "e9"}])
        self.assertEqual(r["verdict"], "true_positive")
        self.assertTrue(r["credential_access"])
        self.assertTrue(r["initial_access"])
        self.assertTrue(r["lateral_movement"])
        self.assertTrue(r["exfiltration"])
        self.assertIn("203.0.113.9", r["affected_assets"]["external_ips"])
        self.assertIn("compromised or weak credentials", r["root_cause"])
        self.assertTrue(any(x["recommendation"] == "contain-external-brute-force" for x in r["recommendations"]))
        self.assertEqual(r["attack"][0]["tactic"], "Credential Access")

    def test_model_hallucination_rejected(self):
        from ulpf.copilot.triage import investigate
        liar = FakeModel('{"summary": "Attack from 192.0.2.66 using T1059.001", "root_cause": "phishing"}')
        r = investigate(None, self.EVENTS, [], liar)
        self.assertIn("model_rejected", r)
        self.assertEqual(r["generated_by"], "rules")
        honest = FakeModel('{"summary": "Brute force from 203.0.113.9 led to root access.", '
                           '"root_cause": "weak root password"}')
        r = investigate(None, self.EVENTS, [], honest)
        self.assertEqual(r["generated_by"], "fake")

    def test_budget_and_offline_loader(self):
        from ulpf.copilot.inference import Budget, ModelError, _check_local, load_backend
        b = load_backend({"backends": ["llama_cpp", "rules"], "model_path": "C:/nope/model.gguf"})
        self.assertEqual(b.name, "rules")
        with self.assertRaises(ModelError):
            _check_local("https://huggingface.co/x/y.gguf", None)
        m = FakeModel("")
        m.n_ctx = 1000
        body, info = Budget(m, reserve_output=200).fit("H", [(0, "Facts", ["f" * 400]),
                                                            (1, "Events", ["e" * 400] * 20)])
        self.assertLessEqual(info["tokens"], 800)
        self.assertGreater(info["items_dropped"], 0)
        self.assertIn("f" * 400, body)


if __name__ == "__main__":
    unittest.main()
