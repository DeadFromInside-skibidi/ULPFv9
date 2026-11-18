"""
Single-core throughput of the worker hot path: Python pipeline vs the compiled
batch engine (native lane), on the same records, in one process.

    python -m benchmarks.native_lane [--events 60000] [--batch 2000]

Rows written per mode, all through WorkerState.process (detect, parse,
normalise, enrich, analytics, route, encode the DuckDB segment, write it to
the buffer):

  python_*      Python pipeline (the reference)
  native_*      compiled core; with the native analytics (Sigma, routes,
                anomaly state, drift signatures) no event dicts are built for
                its records
  engine only   Engine.parse + finish (no analytics, no segment encode, no
                Python-path records)

"full" = the defaults of a production config: anomaly detection, format drift,
the bundled Sigma rules and cross-source correlation projections. "none" =
all of them off. Results print as JSON.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("ULPF_DATA_DIR", tempfile.mkdtemp(prefix="ulpf_bench_"))


def corpus(n: int, native_only: bool) -> list[bytes]:
    from benchmarks.generator import DeterministicGenerator
    g = DeterministicGenerator(seed=42)
    gens = [g.gen_syslog3164, g.gen_syslog5424, g.gen_cef, g.gen_leef, g.gen_json, g.gen_kv]
    if not native_only:
        gens += [g.gen_csv, g.gen_xml]
    rnd = random.Random(1)
    return [rnd.choice(gens)().encode() for _ in range(n)]


def worker(d: str):
    from ulpf.config import load_pipeline_config
    from ulpf.runtime.worker import WorkerState
    cfg = load_pipeline_config(data={
        "node": {"data_dir": d}, "api": {"enabled": False},
        "inputs": [{"type": "syslog", "name": "tcp", "protocol": "tcp", "host": "127.0.0.1", "port": 1}],
        "outputs": [{"type": "duckdb", "name": "store", "path": os.path.join(d, "s.duckdb"),
                     "buffer": {"max_mb": 100000}}],
        "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["store"]}],
    }).data
    cfg.update(_buffer_root=os.path.join(d, "buffers"), _data_dir=d, _learned_dir=os.path.join(d, "learned"))
    return WorkerState(cfg, "node-b", 0)


def run_worker(raws, digests, batch: int, native: bool, analytics: bool) -> float:
    ws = worker(tempfile.mkdtemp(prefix="ulpf_bench_"))
    if not native:
        ws.native = None
        ws.native_analytics = None
    if not analytics:
        ws.anomaly = ws.drift = ws.sigma = None
        ws._correlate = False
        if native:
            ws.native_analytics = ws._native_analytics()
    t0 = time.perf_counter()
    for i in range(0, len(raws), batch):
        r = ws.process("tcp", "10.9.8.7", i + 1, raws[i:i + batch], digests[i:i + batch], time.time())
        assert r["t"] == "done", r
    dt = time.perf_counter() - t0
    ws.close()
    return len(raws) / dt


def run_engine(raws, digests, batch: int) -> float:
    from ulpf.engine.native_lane import NativeLane
    lane = NativeLane.create()
    t0 = time.perf_counter()
    for i in range(0, len(raws), batch):
        lane.run(raws[i:i + batch], digests[i:i + batch], i + 1, "node-b", "tcp", "10.9.8.7", "10.9.8.7", [])
    return len(raws) / (time.perf_counter() - t0)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=60000)
    ap.add_argument("--batch", type=int, default=2000)
    args = ap.parse_args(argv)
    from ulpf.engine.native_lane import load_engine
    if load_engine() is None:
        print("ulpf_core batch engine not built (scripts/build_native.ps1 | .sh)", file=sys.stderr)
        return 2
    out = {"python": platform.python_version(), "platform": platform.platform(), "cpu": platform.processor(),
           "events": args.events, "batch": args.batch, "results": {}}
    for corpus_name, native_only in (("native_formats", True), ("mixed_with_csv_xml", False)):
        raws = corpus(args.events, native_only)
        digests = [hashlib.sha256(r).digest() for r in raws]
        res = {}
        for analytics in (True, False):
            tag = "full" if analytics else "none"
            res[f"python_{tag}"] = run_worker(raws, digests, args.batch, False, analytics)
            res[f"native_{tag}"] = run_worker(raws, digests, args.batch, True, analytics)
        res["engine_only"] = run_engine(raws, digests, args.batch)
        out["results"][corpus_name] = {k: round(v) for k, v in res.items()}
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
