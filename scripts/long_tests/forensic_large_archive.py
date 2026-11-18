"""Forensic verifier on a large archive: build a sealed journal of --gb gigabytes, flip one random bit,
check that both verifiers (Python and compiled Rust) report the exact byte offset, bit and sequence number.

    python -m scripts.long_tests.forensic_large_archive --gb 100 --dir D:/ulpf-forensic-100g
"""
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import time


def build(d: str, gb: float) -> None:
    from ulpf.runtime.evidence import Sealer
    from ulpf.runtime.journal import Journal
    j = Journal(os.path.join(d, "journal"), segment_bytes=256 * 2**20, sync="interval")
    s = Sealer(os.path.join(d, "evidence", "seals"), "n1", 10000, 3600)
    j.add_listener(s.on_append)
    line = (b"<134>1 2026-01-01T00:00:00Z fw01 kernel - - - SRC=203.0.113.%d DST=10.0.0.%d PROTO=TCP "
            b"SPT=%d DPT=443 ACTION=ALLOW " + b"x" * 300)
    target = gb * 2**30
    t0 = time.time()
    n = 0
    while j.stats()["bytes_written"] < target:
        j.append("fw01", "syslog", [line % (n % 250, i % 250, 1024 + i) for i in range(2000)])
        n += 1
        if n % 500 == 0:
            print(f"{j.stats()['bytes_written'] / 2**30:.1f} GiB, {time.time() - t0:.0f}s", flush=True)
    while s.seal_now():
        pass
    s.close()
    j.close()


def flip(d: str) -> tuple[str, int, int]:
    jd = os.path.join(d, "journal")
    segs = sorted(n for n in os.listdir(jd) if n.endswith(".ulj"))
    seg = random.choice(segs[:-1] or segs)
    p = os.path.join(jd, seg)
    size = os.path.getsize(p)
    off = random.randint(4096, size - 4096)
    bit = random.randint(0, 7)
    with open(p, "r+b") as f:
        f.seek(off)
        b = f.read(1)[0]
        f.seek(off)
        f.write(bytes([b ^ (1 << bit)]))
    return seg, off, bit


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gb", type=float, default=100)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--skip-build", action="store_true")
    a = ap.parse_args()
    if not a.skip_build:
        build(a.dir, a.gb)
    seg, off, bit = flip(a.dir)
    print(f"flipped {seg} offset {off} bit {bit}")
    args = ["journal", "--journal", os.path.join(a.dir, "journal"), "--seals", os.path.join(a.dir, "evidence", "seals"),
            "--pubkey", os.path.join(a.dir, "evidence", "evidence.pub"), "--json"]
    ok = True
    exe = os.path.join("native", "ulpf_forensic", "target", "release",
                       "ulpf-forensic-verify.exe" if os.name == "nt" else "ulpf-forensic-verify")
    for name, cmd in (("rust", [exe] + args), ("python", [sys.executable, "-m", "ulpf.forensic_verify"] + args)):
        if name == "rust" and not os.path.exists(exe):
            print("rust verifier not built: cargo build --release in native/ulpf_forensic")
            continue
        t0 = time.time()
        out = subprocess.run(cmd, capture_output=True, text=True)
        res = json.loads(out.stdout)
        hit = [p for p in res["problems"] if p.get("segment") == seg and p.get("offset") == off and p.get("bit") == bit]
        print(f"{name}: {time.time() - t0:.0f}s, valid={res['valid']}, exact hit={bool(hit)} "
              f"{hit[0] if hit else res['problems'][:3]}")
        ok &= bool(hit) and not res["valid"]
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
