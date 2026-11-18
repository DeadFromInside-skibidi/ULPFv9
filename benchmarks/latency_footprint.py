"""
End-to-end latency at load, storage footprint, and SIEM forwarding share.

    python -m benchmarks.latency_footprint [--rates 2000,5000,10000] [--events 60000]

Latency is receipt -> committed in the DuckDB store, per event: the journal's
receive time of each record (taken when the input accepted it) against the
wall-clock time the store transaction holding its segment committed. Both are
measured in this process, so there is no clock skew.

Footprint (one unpaced run of the 200k-line mixed corpus): raw corpus bytes,
journal bytes (the lossless raw archive, uncompressed), DuckDB store file after
CHECKPOINT, and the Parquet lake. Forwarding share: events with severity >= 7
plus derived analytics events (correlation, drift, anomaly) as a fraction of all
log events: what a "forward only what matters" route would send to a SIEM.

The corpus is ULPF's synthetic mixed-format generator (9 formats), not
customer data; real ratios depend on the log mix. Results go to
benchmarks/results/latency/.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def dir_bytes(path: str) -> int:
    total = 0
    for root, _d, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def pct(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = min(len(s) - 1, max(0, int(round(p / 100 * (len(s) - 1)))))
    return s[k]


def make_runtime(d: str, port: int, outputs: list[dict], route_all: bool = False):
    from ulpf.config import load_pipeline_config
    from ulpf.runtime.supervisor import Runtime
    routes = [{"name": "all", "to": [o["name"] for o in outputs]}] if route_all else \
        [{"name": "logs", "when": {"kind_in": ["log"]}, "to": [o["name"] for o in outputs]}]
    return Runtime(load_pipeline_config(data={
        "workers": "auto", "node": {"data_dir": d}, "api": {"enabled": False},
        "inputs": [{"type": "syslog", "name": "in", "protocol": "tcp", "host": "127.0.0.1", "port": port}],
        "outputs": outputs, "routes": routes, "default_output": ""})).start()


def latency_run(rate: float, events: int, corpus: str) -> dict:
    from ulpf.runtime.buffer import parse_name
    from ulpf.runtime.sinks.duckdb_sink import DuckDBSink
    commits: list[tuple[float, int, int]] = []       # (commit time, first seq, last seq)
    original = DuckDBSink.deliver_many

    def timed(self, segs, read):
        original(self, segs, read)
        t = time.time()
        for s in segs:
            meta = parse_name(s.name)
            if meta and meta[0] == "L":
                commits.append((t, meta[1], meta[2]))
    DuckDBSink.deliver_many = timed
    d = tempfile.mkdtemp(prefix="ulpf_lat_")
    port = free_port()
    rt = make_runtime(d, port, [{"type": "duckdb", "name": "store", "path": os.path.join(d, "s.duckdb")}])
    try:
        subprocess.run([sys.executable, "-m", "benchmarks.live.sender", "--file", corpus, "--port", str(port),
                        "--rate", str(rate), "--limit", str(events)], cwd=ROOT, capture_output=True, check=True)
        deadline = time.time() + 300
        while time.time() < deadline and rt.runners["store"].delivered_events < events:
            time.sleep(0.2)
        lat = []
        for t, first, last in commits:
            for seq in range(first, last + 1, max(1, (last - first + 1) // 50)):   # ~50 samples per segment
                rec = rt.journal.read(seq)
                if rec is not None:
                    lat.append((t - rec.recv_ts) * 1000.0)
        return {"offered_eps": rate, "events": events, "persisted": rt.runners["store"].delivered_events,
                "samples": len(lat), "p50_ms": round(pct(lat, 50), 1), "p90_ms": round(pct(lat, 90), 1),
                "p95_ms": round(pct(lat, 95), 1), "p99_ms": round(pct(lat, 99), 1),
                "max_ms": round(max(lat), 1) if lat else None}
    finally:
        rt.stop()
        DuckDBSink.deliver_many = original


def footprint_run(corpus: str) -> dict:
    d = tempfile.mkdtemp(prefix="ulpf_fp_")
    port = free_port()
    with open(corpus, "rb") as f:
        raw = f.read()
    n = raw.count(b"\n")
    rt = make_runtime(d, port, [{"type": "duckdb", "name": "store", "path": os.path.join(d, "s.duckdb")},
                                {"type": "parquet", "name": "lake", "path": os.path.join(d, "lake")}],
                      route_all=True)
    try:
        subprocess.run([sys.executable, "-m", "benchmarks.live.sender", "--file", corpus, "--port", str(port)],
                       cwd=ROOT, capture_output=True, check=True)
        deadline = time.time() + 600
        while time.time() < deadline and (rt.runners["store"].delivered_events < n or
                                          rt.runners["lake"].delivered_events < n):
            time.sleep(0.5)
        time.sleep(3)
        with rt.database._conn_lock:
            q = rt.database.conn.execute
            logs = q("SELECT count(*) FROM events WHERE json_extract_string(normalised_json,'$.event_kind')='log'").fetchone()[0]
            sev7 = q("SELECT count(*) FROM events WHERE json_extract_string(normalised_json,'$.event_kind')='log' "
                     "AND severity >= 7").fetchone()[0]
            derived = dict(q("SELECT json_extract_string(normalised_json,'$.event_kind') k, count(*) FROM events "
                             "WHERE k <> 'log' GROUP BY 1").fetchall())
            q("CHECKPOINT")
    finally:
        rt.stop()
    analytics = sum(v for k, v in derived.items() if k in ("correlation", "drift", "anomaly"))
    jb, db, lb = dir_bytes(os.path.join(d, "journal")), os.path.getsize(os.path.join(d, "s.duckdb")), \
        dir_bytes(os.path.join(d, "lake"))
    return {"events": n, "raw_bytes": len(raw), "journal_bytes": jb, "duckdb_bytes": db, "parquet_lake_bytes": lb,
            "duckdb_vs_raw": round(db / len(raw), 3), "parquet_vs_raw": round(lb / len(raw), 3),
            "journal_vs_raw": round(jb / len(raw), 3),
            "log_events": logs, "severity_gte_7": sev7, "derived_events": derived,
            "forward_share_pct": round(100 * (sev7 + analytics) / max(logs, 1), 2)}


def main() -> int:
    from benchmarks.live.common import build_corpus, hardware
    ap = argparse.ArgumentParser()
    ap.add_argument("--rates", default="2000,5000,10000")
    ap.add_argument("--events", type=int, default=60_000)
    args = ap.parse_args()
    corpus = build_corpus(200_000, seed=42)
    lat = [latency_run(float(r), args.events, corpus) for r in args.rates.split(",")]
    for r in lat:
        print(json.dumps(r))
    fp = footprint_run(corpus)
    print(json.dumps(fp))
    out = os.path.join(ROOT, "benchmarks", "results", "latency")
    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, f"latency_footprint_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"latency_at_load": lat, "footprint": fp, "hardware": hardware(),
                   "corpus": "synthetic 9-format mix (benchmarks/live/common.build_corpus, seed 42)"}, f, indent=2)
    print("result file:", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
