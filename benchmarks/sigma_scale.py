"""
Ingest throughput of a worker (native lane, analytics on) as the Sigma rule set grows: none,
the bundled rules, and 1,000 / all rules of the official SigmaHQ pack
(``tests/data/sigmahq``). Two corpora: mixed non-Windows formats, and Sysmon-style JSON whose
events pass the Windows logsource guards (the expensive case).

    python -m benchmarks.sigma_scale [--events 40000] [--repeat 3]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import statistics
import sys
import tempfile
import time


def sysmon_corpus(n: int) -> list[bytes]:
    rnd = random.Random(7)
    images = ["C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Windows\\explorer.exe",
              "C:\\Windows\\System32\\svchost.exe", "C:\\Users\\bob\\AppData\\Local\\Temp\\setup.exe"]
    cmds = ["cmd.exe /c dir", "powershell.exe -NoProfile -Command Get-Process", "chrome.exe --type=renderer",
            "svchost.exe -k netsvcs -p", "setup.exe /quiet", "cmd.exe /c whoami /all", "explorer.exe"]
    out = []
    for i in range(n):
        out.append(json.dumps({
            "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": f"ws{i % 50}",
            "UtcTime": f"2026-11-05 10:{i % 60:02d}:{i % 60:02d}.000", "Image": rnd.choice(images),
            "CommandLine": rnd.choice(cmds), "ParentImage": rnd.choice(images), "User": f"CORP\\user{i % 30}",
            "IntegrityLevel": "Medium", "Hashes": f"SHA256={i:064x}", "ProcessId": 1000 + i}).encode())
    return out


def worker_with(rules):
    from benchmarks.native_lane import worker
    from ulpf.intelligence.sigma import SigmaEngine
    ws = worker(tempfile.mkdtemp(prefix="ulpf_sigbench_"))
    ws.anomaly = ws.drift = None
    if rules is None:
        ws.sigma = None
    else:
        ws.sigma = SigmaEngine(rules)
        ws._correlate = True
    ws.native_analytics = ws._native_analytics()
    return ws


def eps(ws, raws, digests, batch=2000) -> float:
    t0 = time.perf_counter()
    for i in range(0, len(raws), batch):
        r = ws.process("tcp", "10.9.8.7", i + 1, raws[i:i + batch], digests[i:i + batch], time.time())
        assert r["t"] == "done", r
    return len(raws) / (time.perf_counter() - t0)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=40000)
    ap.add_argument("--repeat", type=int, default=3)
    a = ap.parse_args(argv)
    from benchmarks.native_lane import corpus
    from tests.test_sigma_pack import unpack
    from ulpf.intelligence.sigma import load_rules
    pack, errors = load_rules([unpack()], builtin=False)
    builtin, _ = load_rules([], builtin=True)
    # "empty": Sigma on (projections, correlation) with no rules; the rules' own cost is measured against it
    sets = {"none": None, "empty": [], "builtin": builtin, "sigmahq_1000": pack[:1000], "sigmahq_all": pack}
    res = {"events": a.events, "sigmahq_rules": len(pack), "load_errors": len(errors), "results": {}}
    for cname, raws in (("mixed_formats", corpus(a.events, True)), ("sysmon_json", sysmon_corpus(a.events))):
        digests = [hashlib.sha256(r).digest() for r in raws]
        row = {}
        for name, rules in sets.items():
            ws = worker_with(rules)
            native = ws.native_analytics is not None
            eps(ws, raws[:2000], digests[:2000])                      # warm-up
            row[name] = {"eps": round(statistics.median(eps(ws, raws, digests) for _ in range(a.repeat))),
                         "native_analytics": native}
            ws.close()
        base = row["empty"]["eps"]
        for name in row:
            row[name]["vs_empty_pct"] = round((row[name]["eps"] / base - 1) * 100, 1)
        res["results"][cname] = row
    print(json.dumps(res, indent=1))
    out = os.path.join(os.path.dirname(__file__), "results", f"sigma_scale_{time.strftime('%Y%m%d_%H%M%S')}.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(res, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
