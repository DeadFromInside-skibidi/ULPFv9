"""
Lakehouse throughput and memory: worker encode, hot append, flush to the encrypted Delta tier,
compaction, and pruned queries. Peak RSS is sampled throughout (target: host < 512 MB).

    python -m benchmarks.lakehouse [--events 2000000] [--plain]

2.5 billion events a day is 28,935 events/s sustained.
"""
from __future__ import annotations

import argparse
import base64
import datetime as _dt
import json
import os
import shutil
import tempfile
import threading
import time

import psutil

TARGET_EPS = 2_500_000_000 / 86_400


class _Peak:
    def __init__(self):
        self.proc = psutil.Process()
        self.peak = 0
        self._stop = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while not self._stop.wait(0.05):
            self.peak = max(self.peak, self.proc.memory_info().rss)

    def mb(self) -> float:
        self.peak = max(self.peak, self.proc.memory_info().rss)
        return round(self.peak / 2**20, 1)


def _events(n: int, start: int, t0: _dt.datetime) -> list[dict]:
    out = []
    for i in range(start, start + n):
        ts = t0 + _dt.timedelta(milliseconds=i * 20)
        out.append({"event_id": f"{i:016x}", "timestamp": ts.isoformat().replace("+00:00", "Z"),
                    "category": "network", "action": "allowed" if i % 3 else "blocked", "severity": i % 11,
                    "raw_format": "cef", "message": f"connection {i}",
                    "source": {"ip": f"10.{i % 31}.{i % 251}.{i % 241}", "port": 1024 + i % 60000},
                    "destination": {"ip": f"172.16.{i % 17}.{i % 199}", "port": 443},
                    "network": {"protocol": "tcp", "bytes_in": i % 9000, "bytes_out": i % 4000},
                    "user": {"name": f"user{i % 5000}"}, "device": {"vendor": "Palo Alto", "product": "PAN-OS",
                                                                     "hostname": f"fw{i % 8}"},
                    "metadata": {"input": f"t{i % 4}", "ingestion_source": "10.0.0.1"},
                    "evidence": {"journal_seq": i, "raw_hash": f"{i:064x}", "node_id": "n1"},
                    "raw_event": f"CEF:0|Palo Alto|PAN-OS|10.1|end|TRAFFIC|3|src=10.{i % 31}.{i % 251}.{i % 241} "
                                 f"dst=172.16.{i % 17}.{i % 199} spt={1024 + i % 60000} dpt=443 suser=user{i % 5000} "
                                 f"act={'allowed' if i % 3 else 'blocked'} in={i % 9000} out={i % 4000}",
                    "parsed_fields": {"sha256": f"{(i * 2654435761) % 2**64:064x}"} if i % 50 == 0 else {}})
    return out


def run(n_events: int, encrypted: bool, batch: int = 5000) -> dict:
    from ulpf.lake.service import LakeService
    from ulpf.runtime.sinks.lakehouse import LakehouseSink
    from ulpf.lake import hot as hotmod
    root = tempfile.mkdtemp(prefix="ulpf_lakebench_")
    os.environ["ULPF_BENCH_LAKE_KEY"] = base64.b64encode(os.urandom(32)).decode()
    opts = {"type": "lakehouse", "name": "bench", "storage": {"type": "local", "path": os.path.join(root, "table")},
            "hot": {"capacity_mb": 1024}, "tenant_by_input": {f"t{k}": f"tenant{k}" for k in range(4)},
            "flush_seconds": 3600, "flush_mb": 64,
            "compaction": {"enabled": False, "min_mb": 128, "max_mb": 512}}
    if encrypted:
        opts["encryption"] = {"key_env": "ULPF_BENCH_LAKE_KEY"}
    peak = _Peak()
    sink = LakehouseSink("bench", opts, {"data_dir": root})
    t0 = _dt.datetime(2026, 10, 25, 0, 0, tzinfo=_dt.timezone.utc)
    res = {"events": n_events, "encrypted": encrypted, "target_eps": round(TARGET_EPS)}
    # worker side: encode (one process; workers scale it across cores)
    payloads, enc_s = [], 0.0
    sample = _events(batch, 0, t0)
    t = time.perf_counter()
    for _ in range(5):
        sink.encode(sample)
    res["worker_encode_eps"] = round(5 * batch / (time.perf_counter() - t))
    svc = LakeService("bench", opts, root)               # daemons off: each stage timed alone
    from ulpf.lake import hot as _h
    appended = flush_s = append_s = 0.0
    rows_total = 0
    for start in range(0, n_events, batch):
        evs = _events(min(batch, n_events - start), start, t0)
        te = time.perf_counter()
        payload = sink.encode(evs)
        enc_s += time.perf_counter() - te
        ta = time.perf_counter()
        rows = len(evs)
        while not svc.hot.append_framed(payload, f"seg-{start}"):
            tf = time.perf_counter()
            svc.flush_once()
            flush_s += time.perf_counter() - tf
            ta += time.perf_counter() - tf
        if (start // batch) % 32 == 31:
            svc.hot.sync()                                   # the sink syncs once per 32 segments
        append_s += time.perf_counter() - ta
        rows_total += rows
        if svc.hot.ring.head - svc.hot.ring.flushed >= svc.flush_bytes:
            tf = time.perf_counter()
            svc.flush_once()
            flush_s += time.perf_counter() - tf
    tf = time.perf_counter()
    svc.flush_once()
    flush_s += time.perf_counter() - tf
    res["hot_append_eps"] = round(rows_total / append_s)
    res["flush_eps"] = round(rows_total / flush_s)
    res["ingest_host_eps_serial"] = round(rows_total / (append_s + flush_s))
    # in the runtime the sink thread appends while the flusher thread writes: the slower stage bounds it
    res["ingest_host_eps_pipelined"] = min(res["hot_append_eps"], res["flush_eps"])
    snap = svc.table.snapshot()
    res["files_before_compaction"] = len(snap.files)
    res["bytes_before_compaction"] = sum(a["size"] for a in snap.files.values())
    res["peak_rss_mb_ingest"] = peak.mb()
    tc = time.perf_counter()
    svc.compact_once(force=True)
    res["compaction_eps"] = round(rows_total / (time.perf_counter() - tc))
    snap = svc.table.snapshot()
    res["files_after_compaction"] = len(snap.files)
    res["file_mb_after"] = sorted(round(a["size"] / 2**20, 1) for a in snap.files.values())[-5:]
    res["peak_rss_mb_compaction"] = peak.mb()
    q = svc.query
    tq = time.perf_counter()
    t_all, st = q.run("SELECT count(*) AS n FROM events")
    res["query_count_all"] = {"rows": t_all.column("n")[0].as_py(), "ms": round((time.perf_counter() - tq) * 1000),
                              "files_scanned": st["files_scanned"]}
    i = n_events // 3
    ip = f"10.{i % 31}.{i % 251}.{i % 241}"
    tq = time.perf_counter()
    t_ip, st = q.run("SELECT count(*) AS n FROM events", eq={"source_ip": ip})
    res["query_ip_lookup"] = {"rows": t_ip.column("n")[0].as_py(), "ms": round((time.perf_counter() - tq) * 1000),
                              "files_scanned": st["files_scanned"], "files_total": st["files_total"]}
    tq = time.perf_counter()
    t_absent, st = q.run("SELECT count(*) AS n FROM events", eq={"source_ip": "192.0.2.77"})
    res["query_absent_ip"] = {"rows": t_absent.column("n")[0].as_py(), "ms": round((time.perf_counter() - tq) * 1000),
                              "files_scanned": st["files_scanned"]}
    lo = t0 + _dt.timedelta(minutes=30)
    tq = time.perf_counter()
    t_rng, st = q.run("SELECT count(*) AS n FROM events", tenant="tenant1", start=lo, end=lo + _dt.timedelta(minutes=30))
    res["query_tenant_30min"] = {"rows": t_rng.column("n")[0].as_py(), "ms": round((time.perf_counter() - tq) * 1000),
                                 "files_scanned": st["files_scanned"]}
    res["peak_rss_mb"] = peak.mb()
    res["worker_encode_eps_in_run"] = round(rows_total / enc_s)
    res["host_headroom_x"] = round(res["ingest_host_eps_pipelined"] / TARGET_EPS, 2)
    shutil.rmtree(root, ignore_errors=True)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=2_000_000)
    ap.add_argument("--plain", action="store_true")
    a = ap.parse_args()
    res = run(a.events, not a.plain)
    print(json.dumps(res, indent=1))
    out = os.path.join(os.path.dirname(__file__), "results",
                       f"lakehouse_{time.strftime('%Y%m%d_%H%M%S')}.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(res, f, indent=1)


if __name__ == "__main__":
    main()
