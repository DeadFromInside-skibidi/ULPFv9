"""
The compiled core (native/ulpf_core) must produce exactly what the Python
reference produces: same values, same key order, for every corpus line.
Skipped when the extension is not built.
"""
from __future__ import annotations

import glob
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401

import orjson  # noqa: E402

from ulpf.engine import normalizer  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with mock.patch.dict(os.environ, {"ULPF_NATIVE": "1"}):
    HAVE_NATIVE = normalizer._load_native() is not None

EDGE_LINES = [
    # timestamps: native shapes and shapes that must be delegated
    '{"timestamp":"2026-10-21T10:00:00.123Z","src_ip":"10.0.0.1","severity":"high"}',
    '{"timestamp":"2026-10-21T10:00:00.123456+05:30","src_ip":"10.0.0.1","severity":3}',
    '{"timestamp":"2026-10-21 23:59:59-08:00","action":"Accept (NAT)","proto":"6"}',
    '{"timestamp":"2026-10-21","action":"client-rst","proto":"tcp"}',
    '{"timestamp":"2026-10-21T10:00:00.1Z","action":"ALLOW-URL"}',
    '{"timestamp":"1760000000","severity":"9","bytes_in":"12","bytes_out":30}',
    '{"timestamp":"1760000000123","severity":"-inf"}',
    '{"timestamp":"1760000000.5","severity":"nan"}',
    '{"timestamp":"21/Oct/2026:10:00:00 +0000","severity":"very-high","direction":"Ingress"}',
    '{"timestamp":"Feb 29 10:00:00","severity":"critical "}',
    '{"timestamp":"2024-02-30T10:00:00Z","severity":7.6}',
    '{"timestamp":"not a time","severity":"  "}',
    '{"timestamp":"   ","severity":""}',
    '{"ts":"2026-10-21T10:00:00Z","user":"","duser":"bob","suser":"alice","src_port":"0080"}',
    '{"src_port":"1_000","dst_port":"8.0","sentbyte":"x","rcvdbyte":"99999999999999999999"}',
    '{"proto":"099","protocol_number":3,"direction":"sideways"}',
    '{"proto":"  ","src":"N/A","dst":"null","message":"m"}',
    '{"source.ip":"1.2.3.4","Destination.Port":"443","x.y.src":"5.6.7.8","SRC-IP":"9.9.9.9"}',
    '{"nested":{"a":1},"list":[1,2],"bool":true,"float":1.5,"src_ip":"10.0.0.9"}',
    '{"timestamp":"2026-10-21T10:00:00Z","msg":"café","user":"üser","action":"ÄLLOW"}',
    '{"Timestamp":"2026-10-21T10:00:00Z","SrcIP":"10.1.1.1","Act":"deny"}',
    "<34>Oct  1 22:14:15 h app: x",
    "<34>Oct 11 22:14:15 h sshd[1]: Failed password for invalid user admin from 10.0.0.5 port 22 ssh2",
    "<165>1 2026-10-21T10:00:03.000Z host app 1 ID [sd a=\"1\"] msg with ✓",
    "CEF:0|V|P|1|100|n|Very-High|src=10.0.0.1 dst=10.0.0.2 spt=1 dpt=2 proto=17 act=blocked rt=Oct 21 2026 10:00:00",
    "CEF:0|V|P|1|100|n|5|src=10.0.0.1 in=10 out=20 cs1Label=foo cs1=bar end=1760000000000",
    "LEEF:2.0|IBM|QRadar|7|ev|^|src=1.1.1.1^dst=2.2.2.2^sev=4^devTime=2026-10-21 10:00:00",
    "date=2026-10-21 time=10:00:04 devname=FGT type=traffic srcip=1.1.1.1 dstip=2.2.2.2 sentbyte=1 rcvdbyte=2",
]


def corpus_lines() -> list[str]:
    lines = list(EDGE_LINES)
    for path in sorted(glob.glob(os.path.join(ROOT, "demo_data", "*.log"))):
        with open(path, encoding="utf-8", errors="replace") as f:
            lines += [l.rstrip("\n") for l in f if l.strip()]
    from benchmarks.live.common import build_corpus
    path = build_corpus(20000, seed=3, path=os.path.join(tempfile.mkdtemp(), "c.log"))
    with open(path, encoding="utf-8", errors="replace") as f:
        lines += [l.rstrip("\n") for l in f if l.strip()]
    return lines


def run(lines: list[str], native: bool) -> list[bytes]:
    from ulpf.engine.pipeline import Pipeline
    assert normalizer.set_native(native) == native
    p = Pipeline(enable_auto_parser=False)
    out = []
    with mock.patch("time.time", return_value=1761040800.0):
        for i, line in enumerate(lines):
            r = p.process_line(line, event_id=f"id-{i}")
            ev = r.get("event")
            if ev is not None:
                ev["metadata"]["processing_time_ms"] = None   # sampled timing
            out.append(orjson.dumps(r, default=str))
    return out


@unittest.skipUnless(HAVE_NATIVE, "ulpf_core extension not built")
class TestNativeEquivalence(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        normalizer.set_native(False)       # the default

    def test_identical_output_on_the_corpus(self):
        lines = corpus_lines()
        fast, ref = run(lines, True), run(lines, False)
        diffs = [(lines[i], a, b) for i, (a, b) in enumerate(zip(fast, ref)) if a != b]
        self.assertEqual(len(lines), len(fast))
        if diffs:
            line, a, b = diffs[0]
            self.fail(f"{len(diffs)} of {len(lines)} lines differ; first: {line!r}\nnative: {a[:1500]!r}\n"
                      f"python: {b[:1500]!r}")

    def test_timestamp_parser_matches_python(self):
        from hypothesis import given, settings, strategies as st
        from ulpf import ulpf_core

        digits = st.integers(min_value=0, max_value=99)

        @st.composite
        def iso(draw):
            y = draw(st.integers(1, 9999))
            s = (f"{y:04d}-{draw(st.integers(0, 13)):02d}-{draw(st.integers(0, 32)):02d}"
                 f"{draw(st.sampled_from(['T', ' ', 'x', '']))}"
                 f"{draw(digits):02d}:{draw(digits):02d}:{draw(digits):02d}")
            s += draw(st.sampled_from(["", ".1", ".123", ".123456", ".1234567"]))
            s += draw(st.sampled_from(["", "Z", "z", "+05:30", "-08:00", "+0530", "+24:00", "-00:59"]))
            return s

        @st.composite
        def bsd(draw):
            return (f"{draw(st.sampled_from(['Jan', 'Feb', 'Oct', 'Dec', 'Foo']))} "
                    f"{draw(st.sampled_from(['', ' ']))}{draw(st.integers(0, 32))}"
                    f" {draw(digits):02d}:{draw(digits):02d}:{draw(digits):02d}")[:15].ljust(15)

        @settings(max_examples=3000, deadline=None)
        @given(st.one_of(iso(), bsd(), st.integers(0, 9_999_999_999).map(str), st.text(max_size=30)))
        def check(ts):
            fast = ulpf_core.parse_ts_fast(ts)
            if fast is not None:     # None = native declines and Python decides
                self.assertEqual(fast, normalizer._parse_ts.__wrapped__(ts), ts)
        check()


@unittest.skipUnless(HAVE_NATIVE, "ulpf_core extension not built")
class TestNativeSwitch(unittest.TestCase):
    def test_opt_in_only(self):
        with mock.patch.dict(os.environ, {"ULPF_NATIVE": "0"}):
            self.assertIsNone(normalizer._load_native())
        self.assertFalse(normalizer.NATIVE)          # off by default


if __name__ == "__main__":
    unittest.main()
