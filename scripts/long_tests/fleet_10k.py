"""Fleet control plane at scale: N simulated forwarders enroll and heartbeat over HTTP; measures coordinator CPU.

    python -m scripts.long_tests.fleet_10k --agents 10000 --minutes 10 --interval 30
Target: < 2 % of one core on the coordinator (process CPU time / wall time), no failed heartbeats.
Run the load generator on a different machine for realistic numbers: --server http://coordinator:8000 --no-server
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import sys
import tempfile
import threading
import time


def serve(port: int, data_dir: str):
    import uvicorn
    from fastapi import FastAPI
    from ulpf.fleet.api import build_router
    from ulpf.fleet.control import FleetControl
    fc = FleetControl(data_dir)
    app = FastAPI()
    app.include_router(build_router(fc))
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", backlog=4096,
                                        limit_concurrency=20000))
    threading.Thread(target=srv.run, daemon=True).start()
    while not srv.started:
        time.sleep(0.05)
    return fc, srv


async def agent(i, base, token, interval, end, stats, session_sem):
    import urllib.request
    loop = asyncio.get_running_loop()

    def post(path, body, headers):
        req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", **headers})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    aid = f"agent-{i:05d}"
    async with session_sem:
        enr = await loop.run_in_executor(None, post, "/api/v1/fleet/enroll", {"token": token(), "agent_id": aid}, {})
    hdr = {"X-Agent-Id": aid, "X-Agent-Token": enr["agent_token"]}
    await asyncio.sleep(random.uniform(0, interval))
    while time.time() < end:
        try:
            async with session_sem:
                await loop.run_in_executor(None, post, "/api/v1/fleet/heartbeat",
                                           {"eps": random.randint(10, 500), "buffer_fill": random.random() * 0.3}, hdr)
            stats["ok"] += 1
        except Exception:
            stats["fail"] += 1
        await asyncio.sleep(interval * random.uniform(0.8, 1.2))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--agents", type=int, default=10000)
    ap.add_argument("--minutes", type=float, default=10)
    ap.add_argument("--interval", type=float, default=30)
    ap.add_argument("--port", type=int, default=18080)
    args = ap.parse_args()
    import psutil
    d = tempfile.mkdtemp()
    fc, srv = serve(args.port, d)
    base = f"http://127.0.0.1:{args.port}"
    tokens = [fc.create_enrollment_token("load", 3600) for _ in range(args.agents)]
    it = iter(tokens)
    proc = psutil.Process(os.getpid())
    stats = {"ok": 0, "fail": 0}
    end = time.time() + args.minutes * 60

    async def run():
        sem = asyncio.Semaphore(256)
        await asyncio.gather(*(agent(i, base, lambda: next(it), args.interval, end, stats, sem)
                               for i in range(args.agents)))
    # measure the coordinator only during steady state (after enrollment)
    t = threading.Thread(target=lambda: asyncio.run(run()), daemon=True)
    t.start()
    time.sleep(min(120, args.minutes * 30))
    c0, w0 = proc.cpu_times(), time.time()
    t.join()
    c1, w1 = proc.cpu_times(), time.time()
    cpu = ((c1.user + c1.system) - (c0.user + c0.system)) / max(1e-6, w1 - w0)
    print(json.dumps({"agents": args.agents, "heartbeats_ok": stats["ok"], "heartbeats_failed": stats["fail"],
                      "process_cpu_fraction_incl_load_generator": round(cpu, 4),
                      "note": "includes the in-process load generator; run it remotely for the coordinator alone",
                      "summary": fc.summary()}, indent=2, default=str))
    srv.should_exit = True
    return 0 if stats["fail"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
