"""
Threat Intelligence Platform: indicator normalisation, STIX 2.1 / MISP / OTX parsing, TAXII paging,
confidence decay, the compiled matcher against its Python twin, enrichment in both lanes, defence mode.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import tempfile
import time
import unittest

import orjson

from ulpf.intelligence.tip import runtime as tip_runtime
from ulpf.intelligence.tip.feeds import parse_misp, parse_otx
from ulpf.intelligence.tip.indicators import Indicator, normalize
from ulpf.intelligence.tip.matcher import PyMatcher, read_snapshot, tokens, write_snapshot
from ulpf.intelligence.tip.service import FeedRefused, TipService, builtin_indicators
from ulpf.intelligence.tip.stix import TaxiiClient, parse_bundle, pattern_indicators
from ulpf.intelligence.tip.store import TipStore, effective

try:
    from ulpf import ulpf_core
    HAVE_CORE = hasattr(ulpf_core, "IocMatcher")
except ImportError:
    ulpf_core = None
    HAVE_CORE = False

SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
BUNDLE = {
    "type": "bundle", "id": "bundle--1",
    "objects": [
        {"type": "indicator", "id": "indicator--a", "spec_version": "2.1", "pattern_type": "stix",
         "pattern": "[domain-name:value = 'c2.evil.example'] OR [ipv4-addr:value = '203.0.113.66']",
         "confidence": 85, "indicator_types": ["malicious-activity"], "valid_from": "2026-11-01T00:00:00Z",
         "modified": "2026-11-05T00:00:00Z",
         "kill_chain_phases": [{"kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                "phase_name": "command-and-control"}]},
        {"type": "indicator", "id": "indicator--b", "spec_version": "2.1", "pattern_type": "stix",
         "pattern": f"[file:hashes.'SHA-256' = '{SHA.upper()}']", "confidence": 90,
         "valid_from": "2026-11-01T00:00:00Z"},
        {"type": "indicator", "id": "indicator--c", "pattern_type": "stix", "revoked": True,
         "pattern": "[url:value = 'http://old.example/x']", "valid_from": "2026-01-01T00:00:00Z"},
        {"type": "indicator", "id": "indicator--d", "pattern_type": "sigma", "pattern": "title: x"},
        {"type": "malware", "id": "malware--m", "name": "EvilRAT", "is_family": True},
        {"type": "campaign", "id": "campaign--k", "name": "Operation Night"},
        {"type": "intrusion-set", "id": "intrusion-set--i", "name": "APT-Example"},
        {"type": "identity", "id": "identity--v", "name": "Energy sector", "identity_class": "class"},
        {"type": "relationship", "id": "relationship--1", "relationship_type": "indicates",
         "source_ref": "indicator--a", "target_ref": "malware--m"},
        {"type": "relationship", "id": "relationship--2", "relationship_type": "indicates",
         "source_ref": "indicator--a", "target_ref": "campaign--k"},
        {"type": "relationship", "id": "relationship--3", "relationship_type": "attributed-to",
         "source_ref": "campaign--k", "target_ref": "intrusion-set--i"},
        {"type": "relationship", "id": "relationship--4", "relationship_type": "targets",
         "source_ref": "campaign--k", "target_ref": "identity--v"},
    ]}


def rows_of(inds, source="t", flags=0):
    return [(k, v, i.confidence, i.category, i.threat_actor, i.campaign, i.kill_chain_phase, i.stix_id,
             source, i.flags or flags)
            for i in inds for k, v in [normalize(i.kind, i.value)]]


class TestIndicators(unittest.TestCase):
    def test_normalisation(self):
        n = normalize
        self.assertEqual(n("auto", "203.0.113.5"), ("ip", "203.0.113.5"))
        self.assertEqual(n("auto", "::ffff:203.0.113.5"), ("ip", "203.0.113.5"))
        self.assertEqual(n("auto", "198.51.100.7/24"), ("cidr", "198.51.100.0/24"))
        self.assertEqual(n("auto", "10.0.0.1/32"), ("ip", "10.0.0.1"))
        self.assertEqual(n("domain", "*.Evil.COM."), ("domain_wildcard", "evil.com"))
        self.assertIsNone(n("domain", "*.com"))
        self.assertEqual(n("url", "HTTPS://Evil.com:443/a?B=1#frag"), ("url", "https://evil.com/a?B=1"))
        self.assertEqual(n("url", "hxxp://bad.example"), ("url", "http://bad.example/"))
        self.assertEqual(n("hash", SHA.upper()), ("sha256", SHA))
        self.assertIsNone(n("md5", SHA))
        self.assertEqual(n("email", "Bad.Guy@Phish.Example"), ("email", "bad.guy@phish.example"))
        self.assertEqual(n("registry", "HKLM/Software/Evil"), ("registry", "hklm\\software\\evil"))
        self.assertIsNone(n("mutex", "ab"))
        self.assertIsNone(n("auto", "x" * 3000))
        self.assertIsNone(n("domain", "bad_dömain.com"))

    def test_tokens(self):
        t = tokens(f"GET http://1.2.3.4:8080/x from bob@corp.example sha={SHA} host=a.b.example 10.1.2.3 dead")
        kinds = [c[0] for c in t]
        self.assertEqual(kinds, ["url", "ip", "email", "domain", "hash", "domain", "ip"])


class TestFeeds(unittest.TestCase):
    def test_stix_bundle(self):
        inds, stats = parse_bundle(BUNDLE, "stix:test")
        self.assertEqual(stats["revoked"], ["indicator--c"])
        self.assertEqual(stats["patterns_skipped"], 1)
        by = {(i.kind, i.value): i for i in inds}
        dom = by[("domain", "c2.evil.example")]
        self.assertEqual((dom.threat_actor, dom.campaign, dom.kill_chain_phase, dom.confidence),
                         ("APT-Example", "Operation Night", "command-and-control", 0.85))
        self.assertEqual(dom.diamond, {"adversary": "APT-Example", "capability": "EvilRAT",
                                       "infrastructure": "c2.evil.example", "victim": "Energy sector"})
        self.assertIn(("sha256", SHA.upper()), by)
        self.assertEqual(dom.first_seen, 1793491200.0)

    def test_patterns(self):
        p = pattern_indicators
        self.assertEqual(p("[ipv4-addr:value='1.2.3.4']"), [("ip", "1.2.3.4")])
        self.assertEqual(p("[file:hashes.'SHA-256' = 'aa'] AND [file:hashes.MD5='bb']"),
                         [("sha256", "aa"), ("md5", "bb")])
        self.assertEqual(p("[domain-name:value LIKE '%.evil.com'] OR [ipv4-addr:value ISSUBSET '10.0.0.0/8']"),
                         [("domain_wildcard", "evil.com"), ("cidr", "10.0.0.0/8")])
        self.assertEqual(p("[ipv4-addr:value != '1.1.1.1']"), [])
        self.assertEqual(p("[ipv4-addr:value NOT = '1.1.1.1']"), [])
        self.assertEqual(p("[mutex:name = 'Global\\\\Evil'] WITHIN 5 SECONDS"), [("mutex", "Global\\Evil")])
        with self.assertRaises(ValueError):
            p("[" + "x" * 9000 + "]")
        p("[" * 5000 + "a:b = 'c'")                    # no recursion, no blow-up

    def test_misp_and_otx(self):
        misp = {"response": [{"Event": {
            "info": "Phishing wave", "threat_level_id": "1", "timestamp": "1762000000", "date": "2026-11-01",
            "Tag": [{"name": 'misp-galaxy:threat-actor="APT-X"'}, {"name": "kill-chain:Delivery"}],
            "Attribute": [
                {"type": "email-src", "value": "boss@phish.example", "to_ids": True, "uuid": "u1"},
                {"type": "ip-dst|port", "value": "198.51.100.9|443", "to_ids": True},
                {"type": "filename|md5", "value": "a.exe|" + "a" * 32, "to_ids": True},
                {"type": "comment", "value": "x", "to_ids": False},
                {"type": "domain", "value": "context.example", "to_ids": False}],
            "Object": [{"Attribute": [{"type": "mutex", "value": "EvilMutex", "to_ids": True}]}]}}]}
        inds, stats = parse_misp(misp)
        self.assertEqual(sorted((i.kind, i.value) for i in inds),
                         [("email", "boss@phish.example"), ("ip", "198.51.100.9"), ("md5", "a" * 32),
                          ("mutex", "EvilMutex")])
        self.assertTrue(all(i.threat_actor == "APT-X" and i.campaign == "Phishing wave" and i.confidence == 0.9
                            and i.kill_chain_phase == "Delivery" for i in inds))
        otx = {"results": [{"name": "Pulse", "adversary": "Group Y", "modified": "2026-11-02T00:00:00",
                            "tags": ["kill-chain:exploitation"],
                            "indicators": [{"id": 1, "type": "IPv4", "indicator": "192.0.2.10"},
                                           {"id": 2, "type": "hostname", "indicator": "x.bad.example"},
                                           {"id": 3, "type": "YARA", "indicator": "rule"},
                                           {"id": 4, "type": "URL", "indicator": "http://bad.example/p",
                                            "is_active": 0}]}]}
        inds, stats = parse_otx(otx)
        self.assertEqual([(i.kind, i.value, i.threat_actor, i.kill_chain_phase) for i in inds],
                         [("ip", "192.0.2.10", "Group Y", "exploitation"),
                          ("domain", "x.bad.example", "Group Y", "exploitation")])
        self.assertEqual(stats["skipped"], 2)

    def test_taxii_pages_from_cursor(self):
        calls = []
        pages = [({"more": True, "next": "p2", "objects": BUNDLE["objects"][:2]},
                  {"X-TAXII-Date-Added-Last": "2026-11-05T00:00:00.000Z"}),
                 ({"more": False, "objects": BUNDLE["objects"][2:]},
                  {"X-TAXII-Date-Added-Last": "2026-11-06T00:00:00.000Z"})]

        def get(url, headers, **_kw):
            calls.append(url)
            self.assertEqual(headers["Accept"], "application/taxii+json;version=2.1")
            body, h = pages[len(calls) - 1]
            return 200, h, json.dumps(body).encode()

        objs, cursor = TaxiiClient({"url": "https://taxii.example/api1/collections/c1"}, get).pull(
            "2026-11-01T00:00:00Z")
        self.assertEqual(len(objs), len(BUNDLE["objects"]))
        self.assertEqual(cursor, "2026-11-06T00:00:00.000Z")
        self.assertIn("added_after=2026-11-01T00%3A00%3A00Z", calls[0])
        self.assertIn("next=p2", calls[1])


class TestStoreAndDecay(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ulpf_tip_")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_half_life_and_resighting(self):
        self.assertAlmostEqual(effective(0.8, 0, 10, 10), 0.4)
        self.assertEqual(effective(0.8, 0, 0, 1e9), 0.8)
        st = TipStore(os.path.join(self.dir, "tip.db"), {"ip": 1, "domain": 0})
        t0 = 1_800_000_000.0
        st.upsert([Indicator("ip", "192.0.2.1", 0.8, last_seen=t0),
                   Indicator("domain", "bad.example", 0.9, last_seen=t0, valid_until=t0 + 86400),
                   Indicator("ip", "not an ip", 0.9)], "feed", now=t0)
        self.assertEqual(st.count(), 2)
        active = lambda now: {r[1]: r[2] for r in st.active(0.2, now)}
        self.assertEqual(active(t0), {"192.0.2.1": 0.8, "bad.example": 0.9})
        self.assertEqual(active(t0 + 86400), {"192.0.2.1": 0.4, "bad.example": 0.9})
        self.assertEqual(active(t0 + 3 * 86400), {})              # decayed below 0.2; domain expired
        st.sight("ip", "192.0.2.1", now=t0 + 3 * 86400)
        self.assertEqual(active(t0 + 3 * 86400), {"192.0.2.1": 0.8})
        # a feed publishing it again resets last_seen, first_seen stays
        st.upsert([Indicator("ip", "192.0.2.1", 0.7, first_seen=t0 + 5 * 86400, last_seen=t0 + 5 * 86400)],
                  "feed", now=t0 + 5 * 86400)
        row = st.lookup("192.0.2.1", now=t0 + 5 * 86400)[0]
        self.assertEqual((row["first_seen"], row["last_seen"], row["effective_confidence"]),
                         (t0, t0 + 5 * 86400, 0.7))
        self.assertEqual(st.purge(0.2, now=t0 + 400 * 86400), 2)
        st.close()

    def test_bounded_and_builtin(self):
        st = TipStore(os.path.join(self.dir, "tip.db"), max_indicators=3)
        res = st.upsert([Indicator("ip", f"192.0.2.{i}", 0.5) for i in range(10)], "f")
        self.assertEqual((res["added"], res["rejected"]), (3, 7))
        st.close()
        b = builtin_indicators()
        self.assertTrue(b and all(i.kind == "ip" and i.flags == 1 for i in b))


class TestMatcher(unittest.TestCase):
    ROWS = [("ip", "203.0.113.9"), ("cidr", "198.51.100.0/24"), ("cidr", "2001:db8::/32"), ("domain", "evil.example"),
            ("domain_wildcard", "bad.test"), ("url", "http://x.example/a?b=1"), ("sha256", SHA),
            ("md5", "d41d8cd98f00b204e9800998ecf8427e"), ("email", "spy@phish.example"),
            ("mutex", "Global\\EvilMutex"), ("registry", "hklm\\software\\evil")]

    def snap(self, extra=()):
        rows = [(k, v, 0.9, "malware", "APT", "", "c2", f"id-{i}", "t", 0) for i, (k, v) in enumerate(self.ROWS)]
        rows += list(extra)
        return write_snapshot(rows)

    def matchers(self, data):
        ms = [PyMatcher()]
        if HAVE_CORE:
            ms.append(ulpf_core.IocMatcher())
        for m in ms:
            m.load_bytes(data)
        return ms

    def test_each_kind(self):
        cases = [
            (("203.0.113.9", None, None), ("ip", "203.0.113.9")),
            ((None, "198.51.100.200", None), ("cidr", "198.51.100.200")),
            ((None, "2001:db8:1::5", None), ("cidr", "2001:db8:1::5")),
            ((None, None, "dns query a.b.Bad.Test. resolved"), ("domain_wildcard", "a.b.bad.test")),
            ((None, None, "query bad.test"), None),
            ((None, None, "GET HTTP://X.example:80/a?b=1 200"), ("url", "http://x.example/a?b=1")),
            ((None, None, "GET http://evil.example/zzz 200"), ("domain", "evil.example")),
            ((None, None, f"hash={SHA.upper()}"), ("sha256", SHA)),
            ((None, None, "md5:D41D8CD98F00B204E9800998ECF8427E"), ("md5", "d41d8cd98f00b204e9800998ecf8427e")),
            ((None, None, "From: <Spy@Phish.Example>"), ("email", "spy@phish.example")),
            ((None, None, "Mutant GLOBAL\\EVILMUTEX created"), ("mutex", "GLOBAL\\EVILMUTEX")),
            ((None, None, "TargetObject: HKEY_LOCAL_MACHINE\\SOFTWARE\\Evil\\Run"),
             ("registry", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Evil")),
            ((None, None, json.dumps({"EventID": 13, "TargetObject": "HKLM\\Software\\Evil\\Run"})),
             ("registry", "HKLM\\\\Software\\\\Evil")),                      # JSON-escaped backslashes
            ((None, None, json.dumps({"mutex": "Global\\EvilMutex"})), ("mutex", "Global\\\\EvilMutex")),
            ((None, None, "Global/EvilMutex hklm/software/evil no backslash"), None),
            (("10.0.0.1", "10.0.0.2", "clean example.com 1.2.3.4 " + "ab" * 10), None),
        ]
        for m in self.matchers(self.snap()):
            for args, want in cases:
                got = m.match_event(*args)
                self.assertEqual(got[:2] if got else None, want, (type(m).__name__, args))
            hit = m.match_event("203.0.113.9")
            self.assertEqual(hit[2:], ("malware", 0.9, "id-0", "t", "APT", "", "c2"))

    def test_fields_only_ip_not_matched_in_text(self):
        data = self.snap([("ip", "192.0.2.77", 0.5, "Scanner", "", "", "", "", "builtin", 1)])
        for m in self.matchers(data):
            self.assertEqual(m.match_event("192.0.2.77")[:2], ("ip", "192.0.2.77"))
            self.assertIsNone(m.match_event(None, None, "connection from 192.0.2.77"))

    def test_malformed_snapshots_are_rejected(self):
        good = self.snap()
        bad = [b"", b"ULPFIOC1", good[:-3], b"XXXXXXXX" + good[8:], good[:8] + b"\xff\xff\xff\xff" + good[12:]]
        for m in self.matchers(good):
            for b in bad:
                with self.assertRaises(ValueError):
                    m.load_bytes(b)
            self.assertEqual(m.match_event("203.0.113.9")[0], "ip")          # the old set stays loaded
        rng = random.Random(3)
        for _ in range(300):                                                  # fuzz: never a crash
            b = bytearray(good)
            for _ in range(4):
                b[rng.randrange(len(b))] = rng.randrange(256)
            for m in self.matchers(good):
                try:
                    m.load_bytes(bytes(b))
                except ValueError:
                    pass

    @unittest.skipUnless(HAVE_CORE, "ulpf_core not built")
    def test_core_equals_python_on_random_events(self):
        rng = random.Random(7)
        words = ["evil.example", "a.bad.test", "bad.test", "x.example", "http://x.example/a?b=1",
                 "https://evil.example/p", "spy@phish.example", "SPY@phish.example.", SHA, SHA.upper()[:40],
                 "d41d8cd98f00b204e9800998ecf8427e", "198.51.100.4", "203.0.113.9", "8.8.8.8", "[::1]", "::ffff:1.2.3.4",
                 "Global\\EvilMutex", "hkcu\\software\\evil", "HKLM\\Software\\Evil\\x", "hxxp://evil.example",
                 "user=bob", "café", "ok.", "(evil.example)", "'x.example'", "a@b", "http://[2001:db8::1]:8080/",
                 "ftp://203.0.113.9/", "1.2.3", "999.1.1.1", "e.g.", "example.com:443", "%2Fevil.example",
                 "mailto:spy@phish.example", "-", " ", "\t", "日本.example", "http://localhost/x",
                 "HTTP://User:pw@Evil.Example:80/p#frag", "https://evil.example?q=1", "https://evil.example.:443",
                 "hxxps://X.Example/a?b=1", "http://x.example/a?b=1#z", "ftp://a@b@c.example/", "http://[::1]",
                 "SHA256=" + SHA, "MD5=D41D8CD98F00B204E9800998ECF8427E", "Hashes=SHA1=" + SHA[:40].upper(),
                 "x" * 40, SHA + "0", "file:" + SHA, "a" * 31 + "@" + "b" * 40 + ".example", "http:/x://evil.example/",
                 "very.long." * 30 + "example", "spy@" + "q" * 70 + ".example", "localhost:8080/a"]
        extra = [("ip", f"192.0.2.{i}", 0.3 + i / 1000, "c", "", "", "", f"e{i}", "s", i % 2) for i in range(200)]
        extra.append(("url", "http://localhost/x", 0.5, "c", "", "", "", "", "s", 0))
        extra.append(("url", "https://evil.example/?q=1", 0.5, "c", "", "", "", "", "s", 0))
        extra.append(("sha1", SHA[:40], 0.5, "c", "", "", "", "", "s", 0))
        ms = self.matchers(self.snap(extra))
        words += [f"192.0.2.{i}" for i in range(0, 256, 7)]
        seps = [" ", " ", " ", "", "\"", "=", ",", "/", "\n", "|"]
        for _ in range(20000):
            text = "".join(rng.choice(words) + rng.choice(seps) for _ in range(rng.randint(0, 8)))
            if rng.random() < 0.1:
                text = " " * rng.randint(0, 40) + text      # shift tokens across the 32-byte probe grid
            src = rng.choice([None, "", "192.0.2.3", "10.0.0.1", " 203.0.113.9 ", "bad"])
            dst = rng.choice([None, "198.51.100.1", "2001:db8::9", "::ffff:198.51.100.1"])
            self.assertEqual(ms[0].match_event(src, dst, text), ms[1].match_event(src, dst, text), (src, dst, text))
        self.assertEqual(ms[0].stats()["indicators"], ms[1].stats()["indicators"])


class TestEnrichment(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ulpf_tip_")
        self.snap = os.path.join(self.dir, "intel", "matcher.snap")

    def tearDown(self):
        tip_runtime.configure(None)
        shutil.rmtree(self.dir, ignore_errors=True)

    def _event(self, line):
        from ulpf.engine.pipeline import Pipeline
        return Pipeline().process_line(line)["event"]

    def test_python_enricher(self):
        inds, _ = parse_bundle(BUNDLE, "stix:test")
        write_snapshot(rows_of(inds, "stix:test") + rows_of(builtin_indicators(), "builtin", 1), self.snap)
        line = '<134>Nov 11 10:00:00 fw01 app: conn src=10.0.0.5 dst=10.0.0.9 query=c2.evil.example'
        before = self._event(line)
        self.assertNotIn("intel", before["threat"])
        tip_runtime.configure(self.snap)
        ev = self._event(line)
        self.assertEqual((ev["threat"]["ioc_type"], ev["threat"]["ioc_value"]), ("domain", "c2.evil.example"))
        self.assertEqual(ev["threat"]["intel"], {"id": "indicator--a", "source": "stix:test",
                                                 "threat_actor": "APT-Example", "campaign": "Operation Night",
                                                 "kill_chain_phase": "command-and-control"})
        self.assertIn("ioc_match", ev["tags"])
        self.assertIn("threat:malicious-activity", ev["tags"])
        tip_runtime.configure(None)
        self.assertNotIn("ioc_match", self._event(line)["tags"])

    def test_native_lane_matches_python_with_intel(self):
        try:
            from tests.test_native_lane import HAVE_ENGINE, _neutral, _worker, corpus
        except ImportError:
            self.skipTest("native lane tests unavailable")
        if not HAVE_ENGINE or not HAVE_CORE:
            self.skipTest("ulpf_core batch engine not built")
        lines = corpus()[:4000]
        rng = random.Random(5)
        cands = sorted({c[1] if c[0] != "ip" else str(c[1]) for l in lines for c in tokens(l)
                        if c[0] in ("domain", "url", "email", "ip")})
        chosen = rng.sample(cands, min(len(cands), max(10, len(cands) // 3)))
        rows = []
        for i, v in enumerate(chosen):
            kv = normalize("auto", v)
            if kv:
                rows.append((*kv, round(0.3 + (i % 70) / 100, 2), f"Cat {i % 5}", "Actor" if i % 2 else "",
                             "", "", f"id{i}", "t", 0))
        rows += rows_of(builtin_indicators(), "builtin", 1)
        rows.append(("cidr", "10.0.0.0/8", 0.4, "Internal", "", "", "", "", "t", 0))
        write_snapshot(rows, self.snap)
        ws = _worker(self.dir, row_mac=False)
        self.assertIsNotNone(tip_runtime.active())
        raws = [l.encode("utf-8") for l in lines]
        digests = [hashlib.sha256(r).digest() for r in raws]
        res = ws.native.run(raws, digests, 1, "node-t", "tcp", "10.9.8.7", "10.9.8.7", ["site:a"],
                            want_events=True)
        hits = mism = 0
        for k, i in enumerate(res.native):
            counts = {"skipped": 0, "failed": 0, "raw_fallback": 0, "auto_parsed": 0}
            ref = ws._python_event("tcp", "10.9.8.7", "10.9.8.7", "10.9.8.7", ["site:a"], None, 1 + i, raws[i],
                                   digests[i], counts)
            a, b = _neutral(res.events[k]), _neutral(ref)
            hits += "intel" in b["threat"]
            if orjson.dumps(a) != orjson.dumps(b):
                mism += 1
                if mism == 1:
                    first = (lines[i], a["threat"], b["threat"], a["tags"], b["tags"])
        self.assertEqual(mism, 0, first if mism else None)
        self.assertGreater(hits, 100)


class TestService(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ulpf_tip_")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_defence_mode_refuses_network_feeds(self):
        feed = {"name": "x", "type": "taxii", "url": "https://taxii.example/api/collections/c/"}
        with self.assertRaises(FeedRefused):
            TipService(self.dir, {"feeds": [feed]}, mode="defence")
        TipService(self.dir, {"feeds": [feed]}, mode="defence", airgap_allow=["taxii.example"]).stop()
        TipService(self.dir, {"feeds": [feed]}, mode="industry").stop()
        with self.assertRaises(ValueError):
            TipService(self.dir, {"feeds": [{**feed, "url": "http://taxii.example/"}]}).stop()

    def test_file_feed_sync_build_and_retire(self):
        path = os.path.join(self.dir, "bundle.json")
        with open(path, "w") as f:
            json.dump(BUNDLE, f)
        seen = []
        svc = TipService(self.dir, {"feeds": [{"name": "local", "type": "stix_file", "path": path}]},
                         mode="defence", on_snapshot=seen.append)
        svc.step()
        self.assertEqual(len(seen), 1)
        rows = read_snapshot(open(seen[0], "rb").read())
        vals = {r[2] for r in rows}
        self.assertTrue({"c2.evil.example", "203.0.113.66", SHA} <= vals, vals)
        svc.step()
        self.assertEqual(len(seen), 1)                    # unchanged file: no rebuild
        b2 = {**BUNDLE, "objects": [o for o in BUNDLE["objects"] if o["id"] != "indicator--b"]}
        with open(path, "w") as f:
            json.dump(b2, f)
        os.utime(path, (time.time() + 5, time.time() + 5))
        svc.step()
        self.assertEqual(len(seen), 2)
        self.assertNotIn(SHA, {r[2] for r in read_snapshot(open(seen[1], "rb").read())})
        svc.stop()

    def test_cli_import_and_lookup(self):
        import contextlib
        import io
        from ulpf.main import main
        path = os.path.join(self.dir, "b.json")
        with open(path, "w") as f:
            json.dump(BUNDLE, f)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = main(["intel", "import-stix", "--file", path, "--data-dir", self.dir])
        self.assertEqual(rc, 0, out.getvalue())
        self.assertEqual(json.loads(out.getvalue())["added"], 3)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = main(["intel", "lookup", "C2.Evil.Example", "--data-dir", self.dir])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out.getvalue())[0]["threat_actor"], "APT-Example")
        self.assertTrue(os.path.isfile(os.path.join(self.dir, "intel", "matcher.snap")))


if __name__ == "__main__":
    unittest.main()
