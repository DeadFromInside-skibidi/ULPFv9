"""Shared helpers for live benchmarks: corpus, hardware record, result files."""
from __future__ import annotations

import json
import os
import platform
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

RESULTS_DIR = os.path.join(PROJECT_ROOT, "benchmarks", "results", "live")


def build_corpus(count: int, seed: int = 42, path: str | None = None) -> str:
    """Write ``count`` mixed-format lines (9 formats, varied values) to a file; return its path."""
    sys.path.insert(0, os.path.join(PROJECT_ROOT, "tests", "scripts"))
    from generate_flood_logs import generate_logs  # noqa: E402

    path = path or os.path.join(RESULTS_DIR, f"corpus_{count}_{seed}.log")
    if os.path.exists(path):
        return path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = [l.replace("\n", " ").strip() for l in generate_logs(count, "mixed", seed)]
    lines = [l for l in lines if l and not l.startswith("#")]
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, path)
    return path


def hardware() -> dict:
    info = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpus": os.cpu_count(),
    }
    try:
        import psutil
        info["physical_cpus"] = psutil.cpu_count(logical=False)
        info["ram_gb"] = round(psutil.virtual_memory().total / 2**30, 1)
    except ImportError:
        pass
    if sys.platform == "win32":
        try:
            import subprocess
            out = subprocess.run(["powershell", "-NoProfile", "-Command",
                                  "(Get-CimInstance Win32_Processor).Name"],
                                 capture_output=True, text=True, timeout=20).stdout.strip()
            if out:
                info["cpu_model"] = out
        except Exception:
            pass
    for mod in ("duckdb", "pyarrow", "orjson"):
        try:
            info[f"{mod}_version"] = __import__(mod).__version__
        except Exception:
            pass
    return info


def save_result(name: str, result: dict) -> str:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    path = os.path.join(RESULTS_DIR, f"{name}_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    return path
