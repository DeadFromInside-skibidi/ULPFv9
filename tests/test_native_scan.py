"""
The compiled core's hand-written matchers (native/ulpf_core/src/scan.rs) must give
what Python's ``re`` gives for the parsers' own patterns, on the text the core
handles (printable ASCII and tab). Generated inputs are dense in the characters
the patterns care about (delimiters, digits, brackets, escapes), plus mutations
of real lines. Skipped when the extension is not built.
"""
from __future__ import annotations

import glob
import os
import random
import string
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401

from ulpf.engine.native_lane import load_engine  # noqa: E402

HAVE_ENGINE = load_engine() is not None
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TOKENS = ["<", ">", "1", "13", "165", "999", "1234", "Oct", "Octo", " ", "  ", "\t", "11", "1", "22:14:15", "2:14:15",
          ":", "::", "[", "]", "\\", '"', "=", "-", "host", "app", "sshd", "123", ".", "for ", "invalid user ",
          " from ", " port ", "port", "PT", "Pt", "pt=", "port:", "%ASA-4-106023", "%LINK-3-UPDOWN", "%x-9-Y", "(",
          ")", "10.0.0.1", "1.2.3.4567", "256.1.2.3", "01.2.3.4", "a", "_", "ID47", "x@1", "%", "A", "7", "0", "-",
          "2026-10-21T10:00:03Z", "k=v", 'k="v"', 'k="a\\"b"', "[x@1 k=\"v\"]", "a.b-c", "fe80::1", "abc", "Z",
          "10.0.0.1(1234)", "1.2.3.4(", "(80)", "Oct 11 22:14:15 "]
ALPHABET = string.ascii_letters + string.digits + " \t" + string.punctuation


def soup(rnd: random.Random) -> str:
    return "".join(rnd.choice(TOKENS) for _ in range(rnd.randrange(1, 26)))


def mutate(rnd: random.Random, line: str) -> str:
    chars = list(line)
    for _ in range(rnd.randrange(0, 4)):
        op = rnd.randrange(3)
        pos = rnd.randrange(len(chars) + 1)
        if op == 0 and chars:
            del chars[min(pos, len(chars) - 1)]
        elif op == 1:
            chars.insert(pos, rnd.choice(ALPHABET))
        elif chars:
            chars[min(pos, len(chars) - 1)] = rnd.choice(ALPHABET)
    return "".join(chars)


def real_lines() -> list[str]:
    out = []
    for path in sorted(glob.glob(os.path.join(ROOT, "demo_data", "*.log"))):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            out += [l.rstrip("\n") for l in f if l.strip()]
    sys.path.insert(0, ROOT)
    from benchmarks.generator import DeterministicGenerator
    g = DeterministicGenerator(seed=5)
    out += [f() for f in (g.gen_syslog3164, g.gen_syslog5424, g.gen_cef, g.gen_leef, g.gen_kv) for _ in range(400)]
    # plain syslog (no PRI) and Cisco "addr(port)" pairs
    out += [l.split(">", 1)[1] for l in out if l.startswith("<") and ">" in l[:6]]
    out += [f"Oct {d} 22:14:{d:02d} fw{d} %ASA-{d % 8}-302013: Built tcp 10.0.{d}.1({1000 + d}) to "
            f"192.168.{d}.9({d * 7}) for x" for d in range(1, 60)]
    return [l for l in out if all(c == "\t" or " " <= c <= "~" for c in l)]


@unittest.skipUnless(HAVE_ENGINE, "ulpf_core batch engine not built")
class TestNativeScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rnd = random.Random(20261025)
        lines = real_lines()
        samples = [soup(rnd) for _ in range(60_000)] + lines
        samples += [mutate(rnd, rnd.choice(lines)) for _ in range(60_000)]
        # keep the core's domain: printable ASCII and tab
        cls.samples = [s for s in samples if all(c == "\t" or " " <= c <= "~" for c in s)]

    def _check(self, name, expect):
        from ulpf import ulpf_core
        bad = []
        for s in self.samples:
            got, want = ulpf_core._scan_probe(name, s), expect(s)
            if got != want:
                bad.append((s, got, want))
        self.assertEqual(bad[:3], [], f"{len(bad)} of {len(self.samples)} differ for {name}")

    def test_syslog_headers(self):
        from ulpf.parsers import syslog_parser as sp
        groups = lambda rx: lambda s: (list(m.groups()) if (m := rx.match(s)) else None)  # noqa: E731
        self._check("rfc5424", groups(sp._RFC5424))
        self._check("rfc3164", groups(sp._RFC3164))
        self._check("plain", groups(sp._PLAIN))

    def test_syslog_fields(self):
        from ulpf.parsers import syslog_parser as sp
        self._check("ip", sp._IP.findall)
        self._check("port", sp._PORT.findall)
        self._check("cisco_pair", sp._CISCO_PAIR.findall)
        self._check("ssh", lambda s: m.groups() if (m := sp._SSH.search(s)) else None)
        self._check("cisco_mnemonic", lambda s: m.group(1) if (m := sp._CISCO_MNEMONIC.search(s)) else None)
        self._check("sd_param", lambda s: [m.groups() for m in sp._SD_PARAM.finditer(s)])

    def test_cef_extension_split(self):
        from ulpf.parsers import cef_parser as cp
        self._check("ext_split", lambda s: [(m.start(), m.end(), m.group(1)) for m in cp._EXT_SPLIT.finditer(s)])


if __name__ == "__main__":
    unittest.main()
