"""Signed MAVLink v2 telemetry at line rate into a running ULPF UDP input, with spoofed commands mixed in.

    # pipeline: syslog input, protocol udp, port 14550, telemetry: mavlink,
    #           mavlink: {keys: {"*": "env:MAV_KEY"}}  and  MAV_KEY=<64 hex> in the runtime's environment
    MAV_KEY=<64 hex> python -m scripts.long_tests.mavlink_flood --port 14550 --rate 20000 --seconds 600 --spoof 0.001

Afterwards query the store: every spoofed COMMAND_LONG must be stored with auth=rejected, none of the genuine
frames, and the runtime's drop counters must stay at 0 (or report exactly what was shed).
"""
from __future__ import annotations

import argparse
import os
import socket
import sys
import time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=14550)
    ap.add_argument("--rate", type=int, default=20000)
    ap.add_argument("--seconds", type=float, default=600)
    ap.add_argument("--spoof", type=float, default=0.001, help="share of frames that are forged commands")
    a = ap.parse_args()
    from ulpf.runtime.telemetry import mavlink_frame, sign_mavlink
    key = bytes.fromhex(os.environ["MAV_KEY"])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = spoofed = 0
    t_end = time.time() + a.seconds
    seq = 0
    last_ts = 0
    every = int(1 / a.spoof) if a.spoof else 0
    while time.time() < t_end:
        t0 = time.time()
        for _ in range(a.rate // 100):
            seq = (seq + 1) % 256
            if every and sent % every == 0:
                f = sign_mavlink(mavlink_frame(76, (0, 0, 0, 0, 0, 0, 0, 400, 1, 1, 0), seq=seq), b"\x00" * 32)
                spoofed += 1
            else:
                ts = max(int((time.time() - 1420070400) * 100_000), last_ts + 1)   # strictly increasing per stream
                last_ts = ts
                f = sign_mavlink(mavlink_frame(33, (sent, 0, 0, 0, 0, 0, 0, 0, 0), seq=seq), key, link_id=1,
                                 timestamp=ts)
            s.sendto(f, (a.host, a.port))
            sent += 1
        time.sleep(max(0.0, 0.01 - (time.time() - t0)))
    print(f"sent {sent} frames ({spoofed} spoofed commands) in {a.seconds:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
