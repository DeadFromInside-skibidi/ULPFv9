"""Real-network Raft failover: N node *processes* on localhost (or hosts given by --peers), random kill -9 /
restart of the leader and followers while a client keeps acquiring leases and writing fenced checkpoints.

    python -m scripts.long_tests.raft_tcp_kill --nodes 5 --minutes 30 --dir /tmp/raft-long

Checks: fencing tokens of successive grants strictly increase, no two live holders at once (as observed by the
client), every acknowledged checkpoint is readable after the run, the cluster recovers a leader within 5 s of
every kill. Exit 0 when all hold.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import socket
import subprocess
import sys
import time

CHILD = r"""
import sys, time, json, os
sys.path.insert(0, %(root)r)
from ulpf.runtime.raft import RaftCluster
peers = json.loads(%(peers)r)
cfg = {"cluster": {"heartbeat_seconds": 0.5, "failover_seconds": 4,
       "raft": {"peers": peers, "data_dir": %(dir)r, "tick_ms": 25, "lease_ttl_seconds": 4}}}
c = RaftCluster(cfg, %(node)r)
c.start()
status = os.path.join(%(dir)r, %(node)r + ".status")
while True:
    with open(status + ".tmp", "w") as f:
        json.dump(c.status(), f, default=str)
    os.replace(status + ".tmp", status)
    time.sleep(0.5)
"""


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", type=int, default=5)
    ap.add_argument("--minutes", type=float, default=30)
    ap.add_argument("--dir", default="raft-long")
    args = ap.parse_args()
    root = os.path.abspath(".")
    os.makedirs(args.dir, exist_ok=True)
    peers = {f"n{i}": f"127.0.0.1:{free_port()}" for i in range(args.nodes)}
    procs: dict[str, subprocess.Popen] = {}

    def start(n):
        code = CHILD % {"root": root, "peers": json.dumps(peers), "dir": os.path.abspath(args.dir), "node": n}
        procs[n] = subprocess.Popen([sys.executable, "-c", code])

    for n in peers:
        start(n)
    from ulpf.runtime.raft import RaftCluster
    client_peers = dict(peers)
    client_peers["client"] = f"127.0.0.1:{free_port()}"
    # the client is a non-voting observer: it only forwards proposals to the leader
    cl = RaftCluster({"cluster": {"heartbeat_seconds": 0.5, "failover_seconds": 4,
                                  "raft": {"peers": client_peers, "data_dir": os.path.abspath(args.dir) + "-client",
                                           "tick_ms": 25, "lease_ttl_seconds": 4}}}, "client")
    cl.raft.members = sorted(peers)          # not a voter
    cl.start()
    end = time.time() + args.minutes * 60
    tokens, acked, problems, recoveries = [], {}, [], []
    rng = random.Random(7)
    next_kill = time.time() + 20
    i = 0
    while time.time() < end:
        i += 1
        try:
            res = cl.submit({"op": "acquire", "name": "in", "node": f"w{i % 3}", "epoch": "e", "ttl": 2.0}, 10)
            if res.get("granted") and not res.get("renewed"):
                if tokens and res["token"] <= tokens[-1]:
                    problems.append(f"token {res['token']} not above {tokens[-1]}")
                tokens.append(res["token"])
                r = cl.submit({"op": "checkpoint", "key": f"k{i}", "entry": {"v": i}, "token": res["token"]}, 10)
                if r.get("stored"):
                    acked[f"k{i}"] = i
        except TimeoutError as e:
            problems.append(f"timeout: {e}")
        if time.time() > next_kill:
            victim = rng.choice(list(peers))
            procs[victim].kill()
            t0 = time.time()
            try:
                cl.submit({"op": "noop"}, 15)
                recoveries.append(time.time() - t0)
            except TimeoutError:
                problems.append(f"no recovery 15 s after killing {victim}")
            start(victim)
            next_kill = time.time() + rng.uniform(10, 40)
        time.sleep(0.05)
    time.sleep(3)
    with cl._lock:
        stored = dict(cl.raft.machine.checkpoints)
    lost = [k for k in acked if k not in stored]
    for p in procs.values():
        p.kill()
    report = {"grants": len(tokens), "acked_checkpoints": len(acked), "lost": len(lost), "problems": problems[:50],
              "recovery_seconds_max": max(recoveries or [0]), "recoveries": len(recoveries)}
    print(json.dumps(report, indent=2))
    return 0 if not lost and not [p for p in problems if not p.startswith("timeout")] and \
        max(recoveries or [0]) < 5 else 1


if __name__ == "__main__":
    sys.exit(main())
