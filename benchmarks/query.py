"""
Query latency: typical KQL / SPL2 / HQL hunts over an in-memory batch of store-format events,
plus the live-tail filter cost per ingest batch.

    python -m benchmarks.query [--events 500000]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import statistics
import time

QUERIES = [
    ("kql", "events | where action == 'login_failed' | summarize count() by user.name | top 10 by count_"),
    ("kql", "events | where TimeGenerated > datetime(2026-11-05 10:00) | summarize n = count() by bin(TimeGenerated, 1h), category"),
    ("kql", "events | where source.ip startswith '10.1.' and severity >= 7 | project timestamp, source.ip, message | take 100"),
    ("kql", "events | where raw_event has 'root' | summarize dcount(source.ip) by device.hostname"),
    ("spl", 'from events where action = "login_failed" | stats count() AS n, dc(src) AS ips BY user | sort -n | head 10'),
    ("spl", "search sshd root | timechart span=1h count() BY category"),
    ("hql", "action=login_failed | groupBy([user.name], function=[count(), max(severity)]) | sort(_count, limit=10)"),
    ("hql", "/from (?<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)/ | groupBy(ip, limit=10)"),
]


def _events(n: int) -> list[dict]:
    t0 = _dt.datetime(2026, 11, 5, 8, tzinfo=_dt.timezone.utc)
    users = [f"user{k}" for k in range(500)]
    out = []
    for i in range(n):
        u = users[i % 500]
        ip = f"10.{i % 4}.{i % 251}.{i % 241}"
        out.append({"event_id": f"{i:x}", "timestamp": (t0 + _dt.timedelta(milliseconds=i * 40)).isoformat()
                    .replace("+00:00", "Z"), "category": ("authentication", "network", "process")[i % 3],
                    "action": "login_failed" if i % 5 == 0 else "allowed", "severity": i % 11,
                    "source": {"ip": ip}, "destination": {"ip": "192.0.2.1"}, "user": {"name": u},
                    "device": {"hostname": f"host{i % 40}"}, "message": f"session {i}",
                    "raw_event": f"<34>Nov  5 host{i % 40} sshd[{i}]: Failed password for {u if i % 7 else 'root'} "
                                 f"from {ip} port {1024 + i % 50000} ssh2"})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=500_000)
    a = ap.parse_args()
    from ulpf.query.engine import QueryEngine
    from ulpf.query.live import LiveFilters, compile_live
    from ulpf.storage.database import event_to_row, rows_to_arrow
    t = time.perf_counter()
    table = rows_to_arrow([event_to_row(e) for e in _events(a.events)])
    res = {"events": a.events, "build_s": round(time.perf_counter() - t, 1), "cpus": os.cpu_count(), "queries": []}
    eng = QueryEngine()
    for d, q in QUERIES:
        times, rows = [], 0
        for _ in range(3):
            r = eng.run(d, q, table=table, max_rows=1000)
            times.append(r["elapsed_ms"])
            rows = len(r["rows"])
        res["queries"].append({"dialect": d, "query": q, "median_ms": statistics.median(times), "rows": rows})
    # live tail: 4 tails over 1,000-event ingest batches
    batch = table.slice(0, 1000)
    lf = LiveFilters()
    lf.set([{"id": f"t{k}", "sql": compile_live("kql", f"events | where raw_event contains 'user{k}' "
                                                         f"and severity > 5 | project timestamp, source.ip")}
            for k in range(4)], 60)
    lf.run(batch)
    t = time.perf_counter()
    for _ in range(50):
        lf.run(batch)
    res["live_4_tails_ms_per_1000_event_batch"] = round((time.perf_counter() - t) / 50 * 1000, 2)
    print(json.dumps(res, indent=1))
    out = os.path.join(os.path.dirname(__file__), "results", f"query_{time.strftime('%Y%m%d_%H%M%S')}.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(res, f, indent=1)


if __name__ == "__main__":
    main()
