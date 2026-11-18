"""
Competitive benchmark: the same corpus over TCP into ULPF, Vector, Logstash and
Fluent Bit, each writing JSON lines to a file, on the same machine.

    python -m benchmarks.competitive.run [--events 200000] [--tools ulpf,vector,logstash,fluent-bit]

A tool that is not installed (not on PATH) is reported as "not installed",
never estimated. For each tool: events written, wall time from the first byte
sent until the output stops growing, events/s, peak RSS and CPU seconds of the
tool's process tree, and loss (sent - written). Results go to
benchmarks/results/competitive/.

What is compared is not identical work. ULPF detects the format of every line,
normalises it to the unified schema, enriches it, journals and hashes it, and
runs the analytics. The other tools run a syslog parse and write JSON. The
report states this next to the numbers.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port: int, timeout: float = 120) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.5)
    return False


def count_lines(path: str) -> int:
    n = 0
    for root, _d, files in os.walk(path) if os.path.isdir(path) else [(os.path.dirname(path), [], [os.path.basename(path)])]:
        for f in files:
            try:
                with open(os.path.join(root, f), "rb") as fh:
                    n += sum(chunk.count(b"\n") for chunk in iter(lambda: fh.read(1 << 20), b""))
            except OSError:
                pass
    return n


def tree_usage(pid: int) -> tuple[float, float]:
    import psutil
    try:
        p = psutil.Process(pid)
        procs = [p] + p.children(recursive=True)
        rss = sum(x.memory_info().rss for x in procs) / 2**20
        cpu = sum(sum(x.cpu_times()[:2]) for x in procs)
        return rss, cpu
    except psutil.Error:
        return 0.0, 0.0


def command(tool: str, port: int, out: str, work: str) -> tuple[list[str], dict, str] | None:
    env = dict(os.environ, PORT=str(port), OUT=out, DATA_DIR=work, OUT_DIR=os.path.dirname(out),
               OUT_FILE=os.path.basename(out))
    if tool == "ulpf":
        cfg = os.path.join(work, "ulpf.yaml")
        import yaml
        with open(cfg, "w") as f:
            yaml.safe_dump({"workers": "auto", "node": {"data_dir": work}, "api": {"enabled": False},
                            "inputs": [{"type": "syslog", "name": "in", "protocol": "tcp", "host": "127.0.0.1",
                                        "port": port}],
                            "outputs": [{"type": "file", "name": "out", "path": out}],
                            "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["out"]}],
                            "default_output": ""}, f)
        return [sys.executable, "-m", "ulpf.main", "run", "--config", cfg, "--no-api"], env, out
    exe = {"vector": "vector", "logstash": "logstash", "fluent-bit": "fluent-bit"}[tool]
    path = shutil.which(exe) or (shutil.which("fluentbit") if tool == "fluent-bit" else None)
    if not path:
        return None
    if tool == "vector":
        return [path, "--config", os.path.join(HERE, "vector.toml")], env, out
    if tool == "logstash":
        return [path, "-f", os.path.join(HERE, "logstash.conf"), "--path.data", work], env, out
    return [path, "-c", os.path.join(HERE, "fluent-bit.conf")], env, out


def run_tool(tool: str, corpus: str, events: int) -> dict:
    work = tempfile.mkdtemp(prefix=f"bench_{tool}_")
    port = free_port()
    out = os.path.join(work, "out") if tool == "ulpf" else os.path.join(work, "out.json")
    spec = command(tool, port, out, work)
    if spec is None:
        return {"tool": tool, "status": "not installed"}
    cmd, env, out_path = spec
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            creationflags=flags)
    try:
        if not wait_port(port):
            return {"tool": tool, "status": "did not open its port"}
        t0 = time.perf_counter()
        sender = subprocess.run([sys.executable, "-m", "benchmarks.live.sender", "--file", corpus, "--port",
                                 str(port), "--limit", str(events)], cwd=ROOT, capture_output=True, text=True)
        sent = json.loads(sender.stdout.strip().splitlines()[-1])["sent"]
        peak_rss, last, stable_since = 0.0, -1, time.perf_counter()
        while time.perf_counter() - stable_since < 5 and time.perf_counter() - t0 < 900:
            rss, _ = tree_usage(proc.pid)
            peak_rss = max(peak_rss, rss)
            n = count_lines(out_path)
            if n != last:
                last, stable_since = n, time.perf_counter()
            if n >= sent:
                break
            time.sleep(0.5)
        elapsed = (stable_since if last < sent else time.perf_counter()) - t0
        _, cpu = tree_usage(proc.pid)
        written = count_lines(out_path)
        return {"tool": tool, "status": "ok", "sent": sent, "written": written, "loss": sent - written,
                "seconds": round(elapsed, 2), "events_per_second": round(written / elapsed, 1),
                "peak_rss_mb": round(peak_rss, 1), "cpu_seconds": round(cpu, 1)}
    finally:
        try:
            if sys.platform == "win32":
                import signal
                proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                proc.terminate()
            proc.wait(60)
        except Exception:
            import psutil
            for c in psutil.Process(proc.pid).children(recursive=True):
                c.kill()
            proc.kill()


def main() -> int:
    from benchmarks.live.common import build_corpus, hardware
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=200_000)
    ap.add_argument("--tools", default="ulpf,vector,logstash,fluent-bit")
    args = ap.parse_args()
    corpus = build_corpus(args.events, seed=42)
    results = [run_tool(t.strip(), corpus, args.events) for t in args.tools.split(",") if t.strip()]
    doc = {"events": args.events, "corpus": os.path.basename(corpus), "results": results,
           "note": "ULPF normalises, enriches, journals, hashes and analyses every event; the other tools "
                   "parse syslog and write JSON. Not identical work.",
           "hardware": hardware()}
    out_dir = os.path.join(ROOT, "benchmarks", "results", "competitive")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"competitive_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    for r in results:
        print(json.dumps(r))
    print("result file:", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
