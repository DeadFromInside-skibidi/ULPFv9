"""Live-benchmark target for the v9 runtime (journal → workers → buffers → DuckDB)."""
from __future__ import annotations

import os

from ulpf.config import load_pipeline_config


class RuntimeTarget:
    def __init__(self, proto: str, workers: int, config: str | None = None):
        self.proto, self.workers, self.config = proto, workers, config

    def start(self, port: int) -> None:
        from ulpf.runtime.supervisor import Runtime
        if self.config:
            cfg = load_pipeline_config(self.config)
            cfg.data["inputs"][0]["port"] = port
        else:
            cfg = load_pipeline_config(data={
                "mode": "industry", "workers": self.workers,
                "inputs": [{"type": "syslog", "name": "in", "protocol": self.proto,
                            "host": "127.0.0.1", "port": port}],
                "outputs": [{"type": "duckdb", "name": "store"}],
                # Only log events count as "persisted"; derived events are not routed
                "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["store"]}],
                "default_output": "",
                "api": {"enabled": False},
            })
            # ULPF_BENCH_DISABLE=correlation,anomaly,drift,evidence (or "all") isolates costs
            off = os.environ.get("ULPF_BENCH_DISABLE", "")
            off = {"correlation", "anomaly", "drift", "evidence"} if off == "all" else set(filter(None, off.split(",")))
            for k in off & {"correlation", "anomaly", "drift"}:
                cfg.data["analytics"][k]["enabled"] = False
            if "evidence" in off:
                cfg.data["evidence"]["enabled"] = False
        self.rt = Runtime(cfg).start()

    def counters(self) -> dict:
        rt = self.rt
        inp = next(iter(rt.inputs.values())).stats
        c = rt.dispatcher.counts
        return {"received": inp.received, "queue_dropped": inp.dropped_overflow,
                "parsed": c.get("events", 0), "failed": c.get("failed", 0),
                "persisted": rt.runners["store"].delivered_events}

    def stop(self) -> dict:
        final = self.counters()
        summary = self.rt.stop()
        final["persisted"] = summary["outputs"]["store"]["delivered_events"]
        return final
