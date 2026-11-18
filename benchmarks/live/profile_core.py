"""Profile the per-line hot path (detect → parse → normalise → enrich) in one process.

    python -m benchmarks.live.profile_core --events 50000

Writes the top functions by own time and per-format cost to benchmarks/results/live/.
"""
from __future__ import annotations

import argparse
import cProfile
import io
import os
import pstats
import tempfile
import time

from benchmarks.live.common import build_corpus, hardware, save_result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=50_000)
    ap.add_argument("--top", type=int, default=30)
    args = ap.parse_args()
    os.environ.setdefault("ULPF_DATA_DIR", tempfile.mkdtemp(prefix="ulpf_prof_"))
    from ulpf.engine.pipeline import Pipeline

    with open(build_corpus(args.events, seed=11), encoding="utf-8") as f:
        lines = [l.rstrip("\n") for l in f]
    pipeline = Pipeline()
    for l in lines[:2000]:  # warm caches the same way a running worker would be
        pipeline.process_line(l)

    by_fmt: dict[str, list[float]] = {}
    t0 = time.perf_counter()
    for l in lines:
        s = time.perf_counter()
        r = pipeline.process_line(l)
        fmt = r["event"]["raw_format"] if r.get("success") else "failed"
        by_fmt.setdefault(fmt, []).append(time.perf_counter() - s)
    plain = time.perf_counter() - t0

    prof = cProfile.Profile()
    prof.enable()
    for l in lines:
        pipeline.process_line(l)
    prof.disable()
    pipeline.close()

    buf = io.StringIO()
    stats = pstats.Stats(prof, stream=buf).sort_stats("tottime")
    stats.print_stats(args.top)
    top = []
    for (file, line, fn), (cc, nc, tt, ct, _) in sorted(stats.stats.items(), key=lambda kv: -kv[1][2])[:args.top]:
        top.append({"function": f"{os.path.basename(file)}:{line}:{fn}", "calls": nc,
                    "own_s": round(tt, 4), "cumulative_s": round(ct, 4)})
    total_own = sum(v[2] for v in stats.stats.values())
    result = {
        "events": len(lines),
        "events_per_second_single_core": round(len(lines) / plain, 1),
        "us_per_event": round(plain / len(lines) * 1e6, 2),
        "per_format_us": {k: {"count": len(v), "mean_us": round(sum(v) / len(v) * 1e6, 1)}
                          for k, v in sorted(by_fmt.items())},
        "profiled_total_own_s": round(total_own, 3),
        "top_functions": top,
        "hardware": hardware(),
    }
    result["result_file"] = save_result("profile_core", result)
    print(f"{result['events_per_second_single_core']:,} events/s single core "
          f"({result['us_per_event']} us/event)")
    for k, v in result["per_format_us"].items():
        print(f"  {k:14s} n={v['count']:6d}  {v['mean_us']:7.1f} us")
    print("\nTop functions by own time:")
    for t in top[:20]:
        print(f"  {t['own_s']:8.3f}s  {t['own_s'] / total_own:6.1%}  {t['function']}")
    print(f"\n{result['result_file']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
