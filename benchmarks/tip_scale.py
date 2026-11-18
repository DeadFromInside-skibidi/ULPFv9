"""
Threat-intelligence matching at scale: 2,000,000 active indicators of every kind (IPs, CIDRs, domains,
*.wildcards, URLs, MD5 / SHA-256, e-mail senders, mutexes, registry keys) against event streams.

Reports: snapshot build and load time, matcher memory, the per-event cost of ``IocMatcher.match_event``
(text + both IPs; mixed formats and a URL / hash-heavy corpus), and the per-event overhead the matcher
adds to the native lane (same batch, intel off vs on).

    python -m benchmarks.tip_scale [--indicators 2000000] [--events 100000] [--repeat 5]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import statistics
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def indicator_rows(n: int, seed: int = 1):
    """Synthetic indicators (TEST-NET / reserved names so nothing real is implied)."""
    rnd = random.Random(seed)
    mix = (("ip", 0.40), ("cidr", 0.02), ("domain", 0.25), ("domain_wildcard", 0.03), ("url", 0.12),
           ("sha256", 0.08), ("md5", 0.05), ("email", 0.04), ("mutex", 0.004), ("registry", 0.004))
    rows = []
    for kind, share in mix:
        for i in range(int(n * share)):
            if kind == "ip":
                v = f"{rnd.randrange(1, 224)}.{rnd.randrange(256)}.{rnd.randrange(256)}.{rnd.randrange(1, 255)}"
            elif kind == "cidr":
                v = f"{rnd.randrange(1, 224)}.{rnd.randrange(256)}.{rnd.randrange(256)}.0/24"
            elif kind == "domain":
                v = f"h{i:x}{rnd.randrange(1 << 20):x}.bad{i % 997}.example"
            elif kind == "domain_wildcard":
                v = f"w{i:x}.wild{i % 31}.test"
            elif kind == "url":
                v = f"http://u{i:x}.bad.example/p/{rnd.randrange(1 << 30):x}"
            elif kind == "sha256":
                v = f"{rnd.getrandbits(256):064x}"
            elif kind == "md5":
                v = f"{rnd.getrandbits(128):032x}"
            elif kind == "email":
                v = f"s{i:x}@phish{i % 101}.example"
            elif kind == "mutex":
                v = f"Global\\Mtx_{i:x}_{rnd.randrange(1 << 24):x}"
            else:
                v = f"hklm\\software\\bad{i:x}\\run{rnd.randrange(1 << 16):x}"
            rows.append((kind, v, 0.5 + (i % 50) / 100, "Malware", "", "", "", f"id{i}", "bench", 0))
    while len(rows) < n:
        rows.append(("ip", f"198.18.{len(rows) % 256}.{len(rows) % 251}", 0.5, "Malware", "", "", "", "", "bench", 0))
    return rows


def corpora(n: int, rows):
    from benchmarks.generator import DeterministicGenerator
    g = DeterministicGenerator(seed=7)
    gens = [g.gen_syslog3164, g.gen_syslog5424, g.gen_cef, g.gen_leef, g.gen_json, g.gen_kv, g.gen_csv, g.gen_xml]
    rnd = random.Random(3)
    mixed = [rnd.choice(gens)() for _ in range(n)]
    hits = [r[1] for r in rows[:: max(1, len(rows) // 5000)] if r[0] in ("url", "sha256", "domain", "email")]
    heavy = []
    for i in range(n):
        h = rnd.choice(hits) if i % 100 == 0 else f"https://cdn{i % 500}.example.net/a/{i:x}.js"
        heavy.append(f'{{"ts":"2026-11-11T10:00:00Z","src_ip":"10.1.{i % 256}.{i % 200}","dst_ip":"93.184.{i % 256}.1",'
                     f'"url":"{h}","file_hash":"{(i * 7919) % (1 << 64):064x}","user":"u{i % 300}@corp.example",'
                     f'"process":"C:\\\\Windows\\\\System32\\\\svc{i % 9}.exe","msg":"GET {h} 200"}}')
    return {"mixed": mixed, "url_hash_heavy": heavy}


def rss_mb() -> float | None:
    try:
        import psutil
        return psutil.Process().memory_info().rss / 2**20
    except ImportError:
        return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--indicators", type=int, default=2_000_000)
    ap.add_argument("--events", type=int, default=100_000)
    ap.add_argument("--repeat", type=int, default=5)
    ap.add_argument("--out", help="write the JSON result here")
    a = ap.parse_args(argv)

    from ulpf import ulpf_core
    from ulpf.intelligence.tip import runtime as tip_runtime
    from ulpf.intelligence.tip.matcher import write_snapshot

    res: dict = {"indicators": a.indicators, "events": a.events}
    t = time.perf_counter()
    rows = indicator_rows(a.indicators)
    res["generate_s"] = round(time.perf_counter() - t, 2)
    d = tempfile.mkdtemp(prefix="ulpf_tipbench_")
    snap = os.path.join(d, "intel", "matcher.snap")
    t = time.perf_counter()
    write_snapshot(rows, snap)
    res["snapshot_write_s"] = round(time.perf_counter() - t, 2)
    res["snapshot_mb"] = round(os.path.getsize(snap) / 2**20, 1)
    rss0 = rss_mb()
    m = ulpf_core.IocMatcher()
    t = time.perf_counter()
    m.load(snap)
    res["load_s"] = round(time.perf_counter() - t, 2)
    st = m.stats()
    res["matcher"] = st
    rss1 = rss_mb()
    if rss0 is not None:
        res["load_rss_delta_mb"] = round(rss1 - rss0, 1)

    corp = corpora(a.events, rows)
    res["match_event_ns"] = {}
    for name, lines in corp.items():
        best = None
        for _ in range(a.repeat):
            t = time.perf_counter_ns()
            hits = m.count_matches(lines)
            el = (time.perf_counter_ns() - t) / len(lines)
            best = el if best is None or el < best else best
        res["match_event_ns"][name] = {"ns_per_event": round(best, 1), "hit_rate": round(hits / len(lines), 4),
                                       "avg_line_bytes": round(sum(map(len, lines)) / len(lines), 1)}

    # overhead inside the native lane: the same batch with the matcher off and on
    from benchmarks.native_lane import worker
    ws = worker(d)
    lane = ws.native
    res["lane_overhead_ns"] = {}
    for name, lines in corp.items():
        raws = [l.encode() for l in lines]
        tip_runtime.configure(None)
        first = lane.run(raws, [hashlib.sha256(r).digest() for r in raws], 1, "n", "tcp", "10.9.8.7", "10.9.8.7", [])
        # native records only: delegated ones run the Python pipeline (tens of us each) and drown the
        # difference in noise; their matcher call is the same compiled function
        raws = [raws[i] for i in first.native]
        digs = [hashlib.sha256(r).digest() for r in raws]
        diffs, offs = [], []
        for _ in range(a.repeat * 2):                  # interleaved off / on rounds, paired differences
            per = {}
            for label, path in (("off", None), ("on", snap)):
                tip_runtime.configure(path)
                t = time.perf_counter_ns()
                lane.run(raws, digs, 1, "n", "tcp", "10.9.8.7", "10.9.8.7", [])
                per[label] = (time.perf_counter_ns() - t) / len(raws)
            diffs.append(per["on"] - per["off"])
            offs.append(per["off"])
        res["lane_overhead_ns"][name] = {"native_records": len(raws), "off_ns": round(statistics.median(offs), 1),
                                         "overhead_ns_median": round(statistics.median(diffs), 1),
                                         "overhead_ns_p25_p75": [round(x, 1) for x in
                                                                 statistics.quantiles(diffs, n=4)[::2]]}
    tip_runtime.configure(None)
    out = json.dumps(res, indent=2)
    print(out)
    if a.out:
        with open(a.out, "w") as f:
            f.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
