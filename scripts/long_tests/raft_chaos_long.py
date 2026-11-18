"""Long Jepsen-style Raft run: many seeds, long partitions schedules, invariant checks on every tick.

    python -m scripts.long_tests.raft_chaos_long --seeds 500 --rounds 400 --nodes 5
Exit status 0 when every invariant held for every seed.
"""
from __future__ import annotations

import argparse
import sys
import time
import unittest

sys.path.insert(0, ".")
from tests.test_v10_cluster import RaftSafety  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=500)
    ap.add_argument("--start", type=int, default=1000)
    args = ap.parse_args()
    t = RaftSafety()
    t0 = time.time()
    failures = []
    for seed in range(args.start, args.start + args.seeds):
        try:
            t._chaos(seed)
        except AssertionError as e:
            failures.append((seed, str(e)[:300]))
            print(f"seed {seed}: FAILED {e}", flush=True)
        if seed % 25 == 0:
            print(f"{seed - args.start + 1}/{args.seeds} seeds, {len(failures)} failures, {time.time() - t0:.0f}s",
                  flush=True)
    print(f"done: {args.seeds} seeds, {len(failures)} failures in {time.time() - t0:.0f}s")
    return 1 if failures else 0


if __name__ == "__main__":
    unittest.TestCase.maxDiff = None
    sys.exit(main())
