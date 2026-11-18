"""Load generator for live benchmarks. Runs as its own process so it never
competes with the system under test for the GIL.

    python -m benchmarks.live.sender --file corpus.log --proto tcp --port 5514 [--rate 20000]

Prints one JSON line on completion: {"sent": N, "seconds": S, "rate": R}.
--rate 0 sends as fast as the socket accepts (TCP applies backpressure).
"""
from __future__ import annotations

import argparse
import json
import socket
import time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    ap.add_argument("--rate", type=float, default=0.0, help="lines/s, 0 = unpaced")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--limit", type=int, default=0, help="send at most N lines (0 = all)")
    args = ap.parse_args()

    with open(args.file, "rb") as f:
        lines = [l.rstrip(b"\r\n") for l in f if l.strip()]
    lines = lines * args.repeat
    if args.limit:
        lines = lines[:args.limit]
    slice_s = 0.01
    per_slice = max(1, int(args.rate * slice_s)) if args.rate > 0 else 2000

    sent = 0
    t0 = time.perf_counter()
    if args.proto == "tcp":
        sock = socket.create_connection((args.host, args.port))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        for i in range(0, len(lines), per_slice):
            chunk = lines[i:i + per_slice]
            sock.sendall(b"\n".join(chunk) + b"\n")
            sent += len(chunk)
            if args.rate > 0:
                due = t0 + sent / args.rate
                delay = due - time.perf_counter()
                if delay > 0:
                    time.sleep(delay)
        sock.shutdown(socket.SHUT_WR)
        sock.close()
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        addr = (args.host, args.port)
        for i in range(0, len(lines), per_slice):
            for line in lines[i:i + per_slice]:
                sock.sendto(line, addr)
            sent += min(per_slice, len(lines) - i)
            if args.rate > 0:
                delay = t0 + sent / args.rate - time.perf_counter()
                if delay > 0:
                    time.sleep(delay)
        sock.close()
    secs = time.perf_counter() - t0
    print(json.dumps({"sent": sent, "seconds": round(secs, 3), "rate": round(sent / max(secs, 1e-9), 1)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
