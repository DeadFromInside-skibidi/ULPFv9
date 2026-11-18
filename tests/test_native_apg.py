"""
Learned-parser (APG) dispatch in ``ulpf_core``: one Rust RegexSet pass picks the parser and
captures its fields. The Python index (``AnchorIndex.match`` + ``CompiledParser.parse``) is the
reference: same parser and same fields for every line and source, including lines the core
leaves to Python (non-ASCII, control characters). Also: the streaming engine in the pipeline,
operator decisions reaching its hot path, and autonomous learning in under 5,000 events.
"""
from __future__ import annotations

import copy
import dataclasses
import os
import random
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401
from tests.test_apg2 import _auth_line, _firewall_line, _iot_line, _plc_line  # noqa: E402

try:
    from ulpf import ulpf_core
    HAVE = hasattr(ulpf_core, "ApgSet")
except ImportError:
    HAVE = False

GENS = (_plc_line, _firewall_line, _auth_line, _iot_line)
SOURCES = ("", "10.0.0.1", "10.0.0.2")


def _syslog_line(i: int) -> str:
    return f"<13>Oct 11 22:14:{i % 60:02d} host{i % 3} sshd[{i}]: Accepted password for u{i % 9} from 10.0.0.{i % 255}"


def _learn_all(d: str):
    from ulpf.intelligence.auto_parser.engine import AutoParserEngine
    eng = AutoParserEngine(learned_dir=d)
    for k, gen in enumerate(GENS):
        rep = eng.learn([gen(i) for i in range(800)], min_group=5, state="active", source=SOURCES[k % 3])
        assert rep["accepted"], gen.__name__
    return eng


def _mutate(rnd: random.Random, line: str) -> str:
    k = rnd.randrange(9)
    if k == 0:
        return line
    if k == 1:
        i = rnd.randrange(len(line))
        return line[:i] + rnd.choice(" =|[]\"x9.:-\t") + line[i + 1:]
    if k == 2:
        return line[:rnd.randrange(1, len(line))]
    if k == 3:
        return line + rnd.choice([" extra", "  ", " k=v", "|", "\n", "\t"])
    if k == 4:
        i = rnd.randrange(len(line))
        return line[:i] + rnd.choice(["é", "\x1c", "\x1f", " ", "٣"]) + line[i:]
    if k == 5:
        return "  " + line
    if k == 6:
        return line.replace(" ", "  ", rnd.randrange(1, 3))
    if k == 7:
        return line.replace("=", '="a b" ', 1)
    return _syslog_line(rnd.randrange(1000))


def _corpus(n: int, seed: int = 7) -> list[str]:
    rnd = random.Random(seed)
    return [_mutate(rnd, rnd.choice(GENS)(rnd.randrange(100_000))) for _ in range(n)]


@unittest.skipUnless(HAVE, "ulpf_core APG matcher not built")
class TestDispatchEquivalence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="ulpf_napg_")
        cls.eng = _learn_all(cls.dir)
        cls.lines = _corpus(12_000)

    def _compare(self, idx, lines):
        native = 0
        for n, line in enumerate(lines):
            src = SOURCES[n % 3]
            p = idx.match(line, src)
            want = (p.parser_id, p.parse(line)) if p is not None else (None, None)
            q, fields = idx.match_parse(line, src)
            self.assertEqual(((q.parser_id if q else None), fields), want, repr(line))
            hit = idx.native.first_match(line, src)
            native += hit is None or hit[0] >= 0
        return native

    def test_registry_index_matches_python(self):
        idx = self.eng.registry._index
        self.assertIsNotNone(idx.native)
        self.assertEqual(idx.native.failed, [])
        native = self._compare(idx, self.lines)
        parsed = sum(1 for n, l in enumerate(self.lines) if idx.match(l, SOURCES[n % 3]) is not None)
        self.assertGreater(parsed, 3000)
        self.assertGreater(native / len(self.lines), 0.75)     # the rest: non-ASCII / control chars

    def test_priority_and_source_ties(self):
        """Random states and learned sources over the same parsers: the winner rules agree."""
        from ulpf.intelligence.auto_parser.registry import AnchorIndex
        rnd = random.Random(3)
        base = list(self.eng.registry.adaptive_parsers())
        for _ in range(6):
            ps = []
            for p in base * 2:                      # duplicates: ties broken by state, source, order
                c = copy.copy(p)
                c.spec = copy.deepcopy(p.spec)
                c.spec.state = rnd.choice(["active", "canary", "candidate"])
                c.spec.metadata["learned_source"] = rnd.choice(SOURCES)
                ps.append(c)
            rnd.shuffle(ps)
            self._compare(AnchorIndex(tuple(ps)), self.lines[:3000])

    def test_hot_swap_set_matches_python(self):
        from ulpf.intelligence.auto_parser.native_synthesis import HotSwapRegistry
        hs = HotSwapRegistry()
        hs.replace_all(list(self.eng.registry.adaptive_parsers()))
        cur = hs.current
        self.assertIsNotNone(cur.native)
        py = dataclasses.replace(cur, native=None)
        for line in self.lines[:6000]:
            p, f = cur.dispatch_parse(line)
            q, g = py.dispatch_parse(line)
            self.assertEqual((p and p.parser_id, f), (q and q.parser_id, g), repr(line))

    def test_kv_scanner_matches_python_re(self):
        """The hand-written ``_KV_ANY`` scanner (the lookahead is not expressible in Rust regex)."""
        from ulpf.intelligence.auto_parser.compiler import _KV_ANY
        rnd = random.Random(11)
        alphabet = 'ab_.-=" \t,;|\\x1'
        samples = ["".join(rnd.choice(alphabet) for _ in range(rnd.randrange(0, 40))) for _ in range(30_000)]
        samples += [l for l in self.lines if l.isascii() and l.isprintable()][:3000]
        for s in samples:
            self.assertEqual(ulpf_core._scan_probe("kv_any", s), _KV_ANY.findall(s), repr(s))

    def test_bad_pattern_falls_back(self):
        s = ulpf_core.ApgSet(["^a(?P<g0>b)$", "^(?<=x)$", None], [0, 1, 2], ["", "", ""])
        self.assertEqual(s.failed, [1, 2])
        self.assertEqual(s.first_match("ab", ""), (0, ["b"]))
        self.assertEqual(s.first_match("zz", ""), (-1, []))       # a failed parser might match
        m = ulpf_core.ApgMatcher()
        self.assertEqual(m.publish(s), 1)
        self.assertEqual(m.current().first_match("ab", ""), (0, ["b"]))


@unittest.skipUnless(HAVE, "ulpf_core APG matcher not built")
class TestStreamingEngine(unittest.TestCase):
    def test_operator_decision_reaches_hot_path(self):
        """A parser rejected by another process (the control plane) stops parsing after reload."""
        from ulpf.intelligence.auto_parser.engine import AutoParserEngine
        from ulpf.intelligence.auto_parser.streaming_engine import StreamingAPGEngine
        with tempfile.TemporaryDirectory() as d:
            rep = AutoParserEngine(learned_dir=d).learn([_auth_line(i) for i in range(600)], min_group=5,
                                                        state="canary")
            worker = StreamingAPGEngine(learned_dir=d)
            line = _auth_line(12345)
            self.assertIsNotNone(worker.parse(line))
            for a in rep["accepted"]:
                AutoParserEngine(learned_dir=d).reject(a["parser_id"], "op")
            time.sleep(0.05)                        # mtime resolution
            worker.registry.reload_if_changed()
            self.assertIsNone(worker.parse(line))

    def test_pipeline_selects_streaming_engine(self):
        from ulpf.engine.pipeline import Pipeline
        from ulpf.intelligence.auto_parser.streaming_engine import StreamingAPGEngine
        with tempfile.TemporaryDirectory() as d:
            _learn_all(d)
            p = Pipeline(learned_parsers_dir=d, apg_engine="streaming")
            try:
                self.assertIsInstance(p.auto_engine, StreamingAPGEngine)
                r = p.process_line(_plc_line(77))     # the only format no built-in parser claims
                self.assertEqual(r["event"]["raw_format"], "auto_detected")
                self.assertEqual(r["event"]["metadata"]["parser_name"], "Auto-Parser (APG)")
            finally:
                p.close()

    def test_autonomous_learning_under_5000_events(self):
        """Unknown lines through parse() with learning running: parsed by a learned canary
        well before 5,000 events."""
        from ulpf.intelligence.auto_parser.streaming_engine import StreamingAPGEngine
        with tempfile.TemporaryDirectory() as d:
            eng = StreamingAPGEngine(learned_dir=d)
            eng.start()
            try:
                first = None
                for i in range(5000):
                    if eng.parse(_firewall_line(i), source_ip="10.9.9.9") is not None:
                        first = i
                        break
                    if i % 250 == 249:
                        time.sleep(0.2)             # let the learning thread run
            finally:
                eng.stop()
            self.assertIsNotNone(first, "no learned parser within 5,000 events")
            self.assertLess(first, 5000)
            states = {s.state for s in eng.registry.list_parsers()}
            self.assertIn("canary", states)

    def test_throughput(self):
        """Parse rate of learned formats, native against Python dispatch (printed; native must win)."""
        from ulpf.intelligence.auto_parser.streaming_engine import StreamingAPGEngine
        with tempfile.TemporaryDirectory() as d:
            _learn_all(d)
            lines = [GENS[i % 4](i) for i in range(20_000)]
            rates = {}
            for mode in ("1", "0"):
                os.environ["ULPF_NATIVE_APG"] = mode
                try:
                    eng = StreamingAPGEngine(learned_dir=d)
                finally:
                    os.environ.pop("ULPF_NATIVE_APG", None)
                parse = eng.parse
                t0 = time.perf_counter()
                ok = sum(1 for l in lines if parse(l) is not None)
                rates[mode] = len(lines) / (time.perf_counter() - t0)
                self.assertEqual(ok, len(lines))
            print(f"\nAPG parse: native {rates['1']:,.0f} ev/s, python {rates['0']:,.0f} ev/s")
            self.assertGreater(rates["1"], rates["0"])


if __name__ == "__main__":
    unittest.main()
