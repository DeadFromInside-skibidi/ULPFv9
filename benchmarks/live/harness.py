"""Live-path benchmark: generator process → socket → ingest pipeline → store.

    python -m benchmarks.live.harness --target legacy --proto tcp --events 200000 --workers 3
    python -m benchmarks.live.harness --target runtime --proto tcp --events 200000

Reports offered/sent, received, parsed and persisted counts, loss attributed
to each stage, sustained persisted throughput and drain lag (time from the
last line sent until the last event was persisted). Results go to
benchmarks/results/live/ together with the hardware record.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

from benchmarks.live.common import PROJECT_ROOT, build_corpus, hardware, save_result


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start_sender(corpus: str, proto: str, port: int, rate: float) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "benchmarks.live.sender", "--file", corpus, "--proto", proto,
         "--port", str(port), "--rate", str(rate)],
        cwd=PROJECT_ROOT, stdout=subprocess.PIPE, text=True)


class _Target:
    """Interface: start(port), counters() -> dict, stop() -> dict."""


class LegacyTarget(_Target):
    """8.2 path: asyncio NetworkListener → shared queue → WorkerPool → DuckDB."""

    def __init__(self, proto: str, workers: int):
        self.proto, self.workers = proto, workers

    def start(self, port: int) -> None:
        import asyncio
        from multiprocessing import Queue as MPQueue
        from ulpf.ingestion.listener import NetworkListener
        from ulpf.ingestion.workers import WorkerPool
        from ulpf.storage import create_storage

        self.db = create_storage()
        q = MPQueue(maxsize=2000)
        self.pool = WorkerPool(num_workers=self.workers, input_queue=q, batch_size=2000,
                               anomaly_detection=True)
        self.pool.start(db=self.db, is_network=True)
        self.listener = NetworkListener(q, host="127.0.0.1", port=port)
        self.loop = asyncio.new_event_loop()
        ready = threading.Event()

        def run():
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self.listener.start(self.proto))
            ready.set()
            self.loop.run_forever()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        ready.wait(10)

    def counters(self) -> dict:
        s = self.listener.stats
        return {"received": s.packets_received, "queue_dropped": s.messages_dropped,
                "parsed": self.pool.total_success.value, "failed": self.pool.total_failed.value,
                "persisted": self.pool.total_persisted}

    def stop(self) -> dict:
        import asyncio
        asyncio.run_coroutine_threadsafe(self.listener.stop(), self.loop).result(10)
        self.loop.call_soon_threadsafe(self.loop.stop)
        metrics = self.pool.stop()
        final = self.counters()
        final["persisted"] = metrics.get("total_persisted", final["persisted"])
        self.db.close()
        return final


def make_target(name: str, proto: str, workers: int, config: str | None):
    if name == "legacy":
        return LegacyTarget(proto, workers)
    if name == "runtime":
        from benchmarks.live.runtime_target import RuntimeTarget
        return RuntimeTarget(proto, workers, config)
    raise ValueError(name)


def run(target_name: str = "legacy", proto: str = "tcp", events: int = 100_000, workers: int | None = None,
        rate: float = 0.0, warmup: int = 2000, idle_timeout: float = 5.0, config: str | None = None) -> dict:
    workers = workers or max(1, (os.cpu_count() or 2) - 1)
    os.environ["ULPF_DATA_DIR"] = tempfile.mkdtemp(prefix="ulpf_live_")
    os.environ.pop("ULPF_DB_PATH", None)
    corpus = build_corpus(events)
    warm = build_corpus(warmup, seed=7)

    target = make_target(target_name, proto, workers, config)
    port = _free_port()
    target.start(port)

    # Warm-up: workers import modules and build pipelines on their first batch
    w = _start_sender(warm, "tcp" if proto == "tcp" else proto, port, 0)
    w.wait(120)
    deadline = time.monotonic() + 60
    while target.counters()["persisted"] < warmup * 0.95 and time.monotonic() < deadline:
        time.sleep(0.1)
    base = target.counters()

    t_send = time.perf_counter()
    sender = _start_sender(corpus, proto, port, rate)
    series: list[tuple[float, int]] = []
    last_value, last_change = -1, time.perf_counter()
    sent_info = None
    while True:
        time.sleep(0.25)
        now = time.perf_counter()
        persisted = target.counters()["persisted"] - base["persisted"]
        series.append((round(now - t_send, 3), persisted))
        if persisted != last_value:
            last_value, last_change = persisted, now
        if sent_info is None and sender.poll() is not None:
            sent_info = json.loads(sender.stdout.read().strip().splitlines()[-1])
        if sent_info and (persisted >= sent_info["sent"] or now - last_change > idle_timeout):
            break
    final = target.stop()
    counts = {k: final[k] - base.get(k, 0) for k in final}
    sent = sent_info["sent"]
    t_last = max((t for t, v in series if v == last_value), default=0.0)
    first_t = next((t for t, v in series if v > 0), 0.0)
    result = {
        "target": target_name, "proto": proto, "workers": workers, "offered_rate": rate or "unpaced",
        "events": events, "sent": sent, "send_seconds": sent_info["seconds"],
        "send_rate": sent_info["rate"], **counts,
        "loss": {
            "network": max(0, sent - counts["received"]),
            "queue": counts.get("queue_dropped", 0),
            "processing": max(0, counts["received"] - counts.get("queue_dropped", 0) - counts["parsed"]),
            "storage": max(0, counts["parsed"] - counts["persisted"]),
            "total": max(0, sent - counts["persisted"]),
        },
        "persisted_eps": round(counts["persisted"] / max(t_last, 1e-9), 1),
        "drain_lag_seconds": round(max(0.0, t_last - sent_info["seconds"]), 3),
        "first_persist_seconds": first_t,
        "series": series[::4],
        "hardware": hardware(),
    }
    result["result_file"] = save_result(f"{target_name}_{proto}", result)
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", choices=["legacy", "runtime"], default="legacy")
    ap.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    ap.add_argument("--events", type=int, default=100_000)
    ap.add_argument("--workers", type=int, default=None)
    ap.add_argument("--rate", type=float, default=0.0)
    ap.add_argument("--config", default=None)
    args = ap.parse_args()
    r = run(args.target, args.proto, args.events, args.workers, args.rate, config=args.config)
    keys = ("target", "proto", "workers", "sent", "received", "parsed", "persisted",
            "persisted_eps", "drain_lag_seconds", "loss", "result_file")
    print(json.dumps({k: r[k] for k in keys if k in r}, indent=2))
    return 0 if r["loss"]["total"] == 0 or args.proto == "udp" else 1


if __name__ == "__main__":
    raise SystemExit(main())
