"""
Soak test: the live runtime at a fixed offered rate for a long time.

    python -m benchmarks.soak --minutes 60 --rate 5000 [--workers N] [--proto tcp]

Every 10 s it records persisted events, the host's and the workers' resident
memory, the journal and buffer state. At the end it reports loss and memory
growth after warm-up (the first 10 % of the run). Results go to
benchmarks/results/soak/soak_<timestamp>.json.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def keep_awake(on: bool) -> None:
    """Windows: stop the machine sleeping while this process runs (no system setting changes)."""
    if sys.platform != "win32":
        return
    import ctypes
    ES_CONTINUOUS, ES_SYSTEM_REQUIRED = 0x80000000, 0x00000001
    ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | (ES_SYSTEM_REQUIRED if on else 0))


def rss_mb(pid: int, exclude: set[int]) -> tuple[float, float]:
    import psutil
    p = psutil.Process(pid)
    host = p.memory_info().rss / 2**20
    kids = sum(c.memory_info().rss for c in p.children(recursive=True) if c.pid not in exclude) / 2**20
    return round(host, 1), round(kids, 1)


def main() -> int:
    from benchmarks.live.common import build_corpus, hardware
    from ulpf.config import load_pipeline_config
    from ulpf.runtime.supervisor import Runtime

    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=60.0)
    ap.add_argument("--rate", type=float, default=5000.0)
    ap.add_argument("--workers", type=int, default=0, help="0 = auto")
    ap.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--output", choices=["duckdb", "file"], default="duckdb",
                    help="file: NDJSON output instead of the store (isolates store memory)")
    args = ap.parse_args()

    corpus = build_corpus(100_000, seed=42)
    total = int(args.rate * args.minutes * 60)
    repeat = max(1, -(-total // 100_000))
    d = args.data_dir or tempfile.mkdtemp(prefix="ulpf_soak_")
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    cfg = load_pipeline_config(data={
        "mode": "industry", "workers": args.workers or "auto", "node": {"data_dir": d},
        "inputs": [{"type": "syslog", "name": "in", "protocol": args.proto, "host": "127.0.0.1", "port": port}],
        "outputs": [{"type": "duckdb", "name": "store", "path": os.path.join(d, "soak.duckdb")}
                    if args.output == "duckdb" else
                    {"type": "file", "name": "store", "path": os.path.join(d, "out"), "rotate_mb": 256}],
        "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["store"]}],
        "default_output": "", "api": {"enabled": False},
        "journal": {"retention_days": 1}})
    keep_awake(True)
    rt = Runtime(cfg).start()
    sender = subprocess.Popen([sys.executable, "-m", "benchmarks.live.sender", "--file", corpus, "--proto",
                               args.proto, "--port", str(port), "--rate", str(args.rate), "--repeat",
                               str(repeat), "--limit", str(total)], cwd=ROOT, stdout=subprocess.PIPE)
    t0 = time.time()
    samples = []
    end = t0 + args.minutes * 60 + 120          # the sender stops itself after `total` lines
    try:
        while time.time() < end and sender.poll() is None:
            time.sleep(10)
            host, kids = rss_mb(os.getpid(), {sender.pid})
            st = rt.stats()
            try:
                with rt.database._conn_lock:
                    duck = rt.database.conn.execute(
                        "SELECT sum(memory_usage_bytes) FROM duckdb_memory()").fetchone()[0] / 2**20
            except Exception:
                duck = None
            corr = rt.correlator.correlator if rt.correlator else None
            samples.append({"t": round(time.time() - t0, 1), "persisted": st["outputs"]["store"]["delivered_events"],
                            "received": st["inputs"]["in"]["received"], "rss_host_mb": host,
                            "rss_workers_mb": kids, "duckdb_mb": round(duck, 1) if duck is not None else None,
                            "py_blocks": sys.getallocatedblocks(),
                            "correlation_groups": len(corr._groups) if corr else None,
                            "correlation_keys": len(corr._keys) if corr else None,
                            "correlation_backlog": sum(len(b) for b in list(rt.correlator._queue)) if corr else None,
                            "journal_segments": st["journal"].get("segments"),
                            "buffer_segments": st["outputs"]["store"]["buffer"]["segments"]})
            print(json.dumps(samples[-1]), flush=True)
        sender.terminate() if sender.poll() is None else None
        sent_line = sender.communicate(timeout=60)[0].decode().strip().splitlines()
        sent = json.loads(sent_line[-1])["sent"] if sent_line else None
    finally:
        received = rt.stats()["inputs"]["in"]["received"]
        drain_start = time.time()
        while rt.stats()["outputs"]["store"]["delivered_events"] < received and time.time() - drain_start < 300:
            time.sleep(1)
        summary = rt.stop(timeout=120)
        keep_awake(False)
    persisted = summary["outputs"]["store"]["delivered_events"]
    warm = [s for s in samples if s["t"] >= 0.1 * args.minutes * 60] or samples
    growth = None
    if len(warm) >= 2:
        # The store's page cache (DuckDB, capped by memory_limit and emptied at each WAL
        # checkpoint) is reported separately: the leak signal is the runtime's own memory.
        def runtime_mb(s):
            return s["rss_host_mb"] - (s.get("duckdb_mb") or 0)
        a, b = warm[0], warm[-1]
        half = warm[len(warm) // 2:]
        growth = {"host_runtime_mb": round(runtime_mb(b) - runtime_mb(a), 1),
                  "host_runtime_max_mb": round(max(runtime_mb(s) for s in warm), 1),
                  "workers_mb": round(b["rss_workers_mb"] - a["rss_workers_mb"], 1),
                  "workers_second_half_mb": round(half[-1]["rss_workers_mb"] - half[0]["rss_workers_mb"], 1),
                  "duckdb_max_mb": max((s.get("duckdb_mb") or 0) for s in warm),
                  "py_blocks_first_last": [warm[0].get("py_blocks"), warm[-1].get("py_blocks")],
                  "max_sample_gap_s": max(b2["t"] - a2["t"] for a2, b2 in zip(samples, samples[1:])),
                  "host_rss_max_mb": max(s["rss_host_mb"] for s in warm)}
    result = {"minutes": args.minutes, "offered_rate": args.rate, "proto": args.proto,
              "workers": summary["pipeline"].get("workers"), "sent": sent, "received": received,
              "persisted": persisted, "loss": (sent - persisted) if sent is not None else None,
              "memory_growth_after_warmup": growth, "samples": samples, "hardware": hardware()}
    out_dir = os.path.join(ROOT, "benchmarks", "results", "soak")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"soak_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    print(json.dumps({k: v for k, v in result.items() if k not in ("samples",)}, indent=2))
    print("result file:", path)
    return 0 if result["loss"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
