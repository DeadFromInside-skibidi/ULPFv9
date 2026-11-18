"""Copilot with a real local model: NL->query validity/accuracy and latency, triage grounding.

    pip install "ulpf[copilot]"                   # llama-cpp-python (CPU) or a CUDA/Metal/Vulkan build
    python -m scripts.long_tests.copilot_model_eval --model D:/models/Llama-3.1-8B-Instruct-Q4_K_M.gguf [--gpu-layers -1]

Reports, per dialect: share of questions whose model answer compiled (origin=model), share that needed the
grammar fallback, p50/p95 latency; and for triage, how often the model's narrative was rejected for
mentioning indicators that are not in the evidence. Runs fully offline.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time

QUESTIONS = [
    "top 10 source ips with failed logins in the last 24 hours", "how many critical detections today",
    "failed ssh logins for user root by hour over the past 7 days", "show 100 firewall denies to 10.0.0.5",
    "distinct users with successful logins last week", "powershell events on host web01 in the last 3 days",
    "count of events by category in the last hour", "top 5 destination ports blocked yesterday",
    "malware events per day this week", "privileged account logins from external ips in the last 30 days",
    "dns events for host dc01 today", "high severity events by source ip in the last 12 hours",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--gpu-layers", type=int, default=-1)
    ap.add_argument("--ctx", type=int, default=8192)
    a = ap.parse_args()
    from ulpf.copilot.inference import load_backend
    from ulpf.copilot.nl2query import translate
    from ulpf.copilot.triage import investigate
    b = load_backend({"model_path": a.model, "n_gpu_layers": a.gpu_layers, "n_ctx": a.ctx})
    print(json.dumps(b.info()))
    if b.name == "rules":
        print("model did not load:", getattr(b, "errors", []))
        return 1
    report = {}
    for lang in ("kql", "spl", "hql"):
        lat, model_ok, valid = [], 0, 0
        for q in QUESTIONS:
            t0 = time.time()
            r = translate(q, lang, b)
            lat.append(time.time() - t0)
            model_ok += r["origin"] == "model"
            valid += r["valid"]
        report[lang] = {"valid": valid / len(QUESTIONS), "model_answer_compiled": model_ok / len(QUESTIONS),
                        "p50_s": statistics.median(lat), "p95_s": sorted(lat)[int(0.95 * len(lat)) - 1]}
    from tests.test_v10_copilot import Triage
    rejected = 0
    for _ in range(5):
        r = investigate({"id": "C"}, Triage.EVENTS, [], b)
        rejected += "model_rejected" in r
    report["triage_model_rejections"] = f"{rejected}/5"
    print(json.dumps(report, indent=2))
    return 0 if all(report[k]["valid"] == 1.0 for k in ("kql", "spl", "hql")) else 1


if __name__ == "__main__":
    sys.exit(main())
