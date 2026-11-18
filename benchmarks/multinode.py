"""
Aggregate throughput of N independent ULPF nodes (separate processes, each its
own journal, workers and store), compared with one node.

    python -m benchmarks.multinode --nodes 2 --workers 3 --events 200000

Each node receives events/N lines over its own TCP input, unpaced. The rate is
total persisted events / time from the first byte sent until the last node has
stored its share. All nodes run on this machine, so they share its cores: on
one host this measures the overhead of the multi-process layout, and the
scaling ratio is bounded by the host's core count. On separate hosts, nodes
share nothing on the data path. Results: benchmarks/results/multinode/.
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
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_node(idx: int, workers: int, base: str) -> dict:
    import yaml
    d = os.path.join(base, f"node{idx}")
    os.makedirs(d, exist_ok=True)
    port, api = free_port(), free_port()
    cfg = os.path.join(d, "pipeline.yaml")
    with open(cfg, "w") as f:
        yaml.safe_dump({"workers": workers, "node": {"id": f"bench-{idx}", "data_dir": d},
                        "api": {"enabled": True, "port": api},
                        "inputs": [{"type": "syslog", "name": "in", "protocol": "tcp", "host": "127.0.0.1", "port": port}],
                        "outputs": [{"type": "duckdb", "name": "store", "path": os.path.join(d, "s.duckdb")}],
                        "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["store"]}],
                        "default_output": ""}, f)
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    proc = subprocess.Popen([sys.executable, "-m", "ulpf.main", "run", "--config", cfg], cwd=ROOT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
    return {"proc": proc, "port": port, "api": api, "dir": d}


def persisted(node: dict) -> int:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{node['api']}/api/v1/runtime/status", timeout=5) as r:
            return json.loads(r.read())["outputs"]["store"]["delivered_events"]
    except Exception:
        return -1


def stop(node: dict) -> None:
    p = node["proc"]
    try:
        if sys.platform == "win32":
            import signal
            p.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            p.terminate()
        p.wait(120)
    except Exception:
        import psutil
        for c in psutil.Process(p.pid).children(recursive=True):
            c.kill()
        p.kill()


def run(n_nodes: int, workers: int, events: int, corpus: str) -> dict:
    base = tempfile.mkdtemp(prefix=f"ulpf_multinode_{n_nodes}_")
    nodes = [start_node(i, workers, base) for i in range(n_nodes)]
    try:
        deadline = time.time() + 120
        while time.time() < deadline and not all(persisted(n) >= 0 for n in nodes):
            time.sleep(0.5)
        share = events // n_nodes
        with open(corpus, "rb") as f:
            lines = [l.rstrip(b"\r\n") for l in f if l.strip()][:share * n_nodes]
        t0 = time.perf_counter()

        def send(node, chunk):
            with socket.create_connection(("127.0.0.1", node["port"])) as s:
                for i in range(0, len(chunk), 2000):
                    s.sendall(b"\n".join(chunk[i:i + 2000]) + b"\n")
        threads = [threading.Thread(target=send, args=(n, lines[i * share:(i + 1) * share])) for i, n in enumerate(nodes)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        done = {}
        while len(done) < n_nodes and time.perf_counter() - t0 < 900:
            for i, n in enumerate(nodes):
                if i not in done and persisted(n) >= share:
                    done[i] = time.perf_counter() - t0
            time.sleep(0.2)
        elapsed = max(done.values()) if len(done) == n_nodes else None
        total = sum(max(0, persisted(n)) for n in nodes)
        return {"nodes": n_nodes, "workers_per_node": workers, "events": share * n_nodes, "persisted": total,
                "loss": share * n_nodes - total, "seconds": round(elapsed, 2) if elapsed else None,
                "aggregate_eps": round(total / elapsed, 1) if elapsed else None,
                "per_node_seconds": {f"node{i}": round(s, 2) for i, s in sorted(done.items())}}
    finally:
        for n in nodes:
            stop(n)


def main() -> int:
    from benchmarks.live.common import build_corpus, hardware
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", type=int, default=2)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--events", type=int, default=200_000)
    args = ap.parse_args()
    corpus = build_corpus(args.events, seed=42)
    single = run(1, args.workers, args.events, corpus)
    multi = run(args.nodes, args.workers, args.events, corpus)
    ratio = round(multi["aggregate_eps"] / single["aggregate_eps"], 2) if single["aggregate_eps"] and multi["aggregate_eps"] else None
    doc = {"single": single, "multi": multi, "scaling_ratio": ratio, "hardware": hardware(),
           "note": "all nodes on one host: the ratio is bounded by the host's cores"}
    out_dir = os.path.join(ROOT, "benchmarks", "results", "multinode")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"multinode_{args.nodes}x{args.workers}_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    print(json.dumps({k: v for k, v in doc.items() if k != "hardware"}, indent=2))
    print("result file:", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
