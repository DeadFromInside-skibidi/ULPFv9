"""
ULPF Enterprise-Grade Benchmark Harness
========================================
Runs the full benchmark lifecycle with real network I/O (loopback sockets),
real process-level memory measurement and an embedded Loghub sample.
Every number in the report is measured during the run.

Phases:
  [1] Warm-up: imports, regex compilation and allocator warm-up (discarded).
  [2] Steady-State Soak: sustained 5k EPS offered load with EPS, CPU, RSS,
      queue depth and disk monitoring. Detects memory leaks, queue growth,
      worker failures and performance degradation.
  [3] Live UDP Network Benchmark: asyncio listener + real UDP datagrams at
      10k, 50k, 100k and 150k EPS offered. Separates network loss from
      application loss.
  [4] Live TCP Concurrency Benchmark: 1, 4, 16 and 64 concurrent clients,
      plus disconnect, reconnect and listener-restart resilience.
  [5] Multi-Worker Scalability: 1, 2, 4 and 8 worker processes: throughput,
      per-worker RSS, CPU and batch latency percentiles.
  [6] Process-Level Memory Validation: idle RSS, worker baseline RSS and peak
      RSS under load, attributed per worker PID.
  [7] Data Integrity & Security: SHA-256 provenance, event ID uniqueness, raw
      event preservation, timestamp normalisation, storage consistency,
      all-format parsing, air-gap mode and forensic chain integrity.
  [8] Loghub Accuracy: parsing, template and grouping accuracy on 32
      embedded sample lines from 14 Loghub systems, plus a downstream Drain
      comparison (raw vs ULPF-preprocessed input).
  [9] Feature Overhead: wall-clock cost of file processing, Log DNA,
      auto-parser learning and correlation through the CLI.

Workers default to (CPU cores - 1). CLI phases run against an isolated data
directory inside the run folder, so the user's event store is never touched.

Results saved to: benchmarks/results/enterprise/run_<timestamp>/

    python -m benchmarks.enterprise
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

RESULTS_DIR = os.path.join(PROJECT_ROOT, "benchmarks", "results", "enterprise")
DEMO_FILE = os.path.join(PROJECT_ROOT, "demo_data", "mixed_formats.log")
PYTHON_EXE = sys.executable
# More workers than cores only measures context switching
WORKERS = max(1, (os.cpu_count() or 2) - 1)


def print_box(text: str):
    print("\n" + "=" * 105)
    print(text)
    print("=" * 105)


def run_cli_command(cmd: list, desc: str, show_output: bool = False) -> dict:
    """Run a CLI subprocess and return timing + output."""
    print(f"\n  [*] {desc}")
    print(f"      CMD: {' '.join(cmd)}")
    start = time.perf_counter()
    try:
        res = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=600)
        elapsed = time.perf_counter() - start
        if show_output:
            for line in res.stdout.strip().split("\n")[:30]:
                print(f"      {line}")
        print(f"      Completed in {elapsed:.2f}s")
        return {"success": True, "time": elapsed, "output": res.stdout}
    except subprocess.CalledProcessError as e:
        elapsed = time.perf_counter() - start
        print(f"      [!] FAILED ({elapsed:.2f}s): {e.stderr[:200]}")
        return {"success": False, "time": elapsed, "output": e.stderr}
    except subprocess.TimeoutExpired:
        print(f"      [!] TIMED OUT after 600s")
        return {"success": False, "time": 600.0, "output": "timeout"}


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(RESULTS_DIR, f"run_{timestamp}")
    os.makedirs(run_dir, exist_ok=True)
    # Isolate every store, spool and learned parser this run creates
    # (inherited by the CLI subprocesses)
    os.environ["ULPF_DATA_DIR"] = os.path.join(run_dir, "data")
    os.environ.pop("ULPF_DB_PATH", None)

    print_box("  ULPF ENTERPRISE-GRADE BENCHMARK HARNESS — FULL INDUSTRY LIFECYCLE  ")
    print(textwrap.dedent(f"""
    Timestamp       : {timestamp}
    Python          : {PYTHON_EXE}
    Workers         : {WORKERS} (CPU cores - 1)
    Results Dir     : {run_dir}
    Demo Data       : {DEMO_FILE}

    Executing Lifecycle Phases:
      [1] Warm-up
      [2] Steady-State Soak Test (EPS, CPU, RSS, Queue, Leak Detection)
      [3] Live UDP Network Benchmark (Real Socket I/O, 10k–150k EPS offered)
      [4] Live TCP Concurrency Benchmark (1–64 Clients, Resilience)
      [5] Multi-Worker Scalability (1–8 Workers, Throughput & Latency)
      [6] Process-Level Memory Validation (Per-Worker PID Attribution)
      [7] Data Integrity & Security Validation (SHA-256, Air-Gap)
      [8] Loghub Accuracy (14 systems, PA/FTA/GA, downstream Drain)
      [9] Feature Overhead (Process, DNA, Auto-Parser, Correlation)
    """).strip())

    all_results = {}
    phase_status = {}

    # =====================================================================
    # PHASE 1: WARM-UP
    # =====================================================================
    print_box("  PHASE 1: WARM-UP")
    result = run_cli_command(
        [PYTHON_EXE, "-m", "ulpf.main", "benchmark", "--events", "10000"],
        "Warm-up run: 10,000 events through the full pipeline. Metrics discarded."
    )
    phase_status["phase_1_warmup"] = result["success"]

    # =====================================================================
    # PHASE 2: STEADY-STATE SOAK TEST
    # =====================================================================
    print_box("  PHASE 2: STEADY-STATE SOAK TEST (Memory Leak & Degradation Detection)")
    try:
        from benchmarks.soak import run_soak_test
        soak_result = run_soak_test(
            duration_sec=60.0,
            target_eps=5000,
            sample_interval_sec=1.0,
            workers=WORKERS,
            batch_size=1000,
            results_dir=run_dir,
        )
        all_results["soak_test"] = soak_result.get("summary", {})
        phase_status["phase_2_soak"] = soak_result.get("summary", {}).get("overall_health") == "HEALTHY"
    except Exception as e:
        print(f"  [!] Soak test failed: {e}")
        phase_status["phase_2_soak"] = False

    # =====================================================================
    # PHASE 3: LIVE UDP NETWORK BENCHMARK (Real Socket I/O)
    # =====================================================================
    print_box("  PHASE 3: LIVE UDP NETWORK BENCHMARK (Real Asyncio Listener + OS Sockets)")
    try:
        from benchmarks.live_network import run_live_udp_benchmark
        udp_result = run_live_udp_benchmark(
            rates=[10000, 50000, 100000, 150000],
            events_per_rate=10000,
            host="127.0.0.1",
            port=5514,
            workers=WORKERS,
            batch_size=1000,
            results_dir=run_dir,
        )
        all_results["live_udp"] = udp_result.get("udp_results", [])
        # Pass if no rate had >5% total loss
        max_loss = max((r.get("total_loss_pct", 100) for r in udp_result.get("udp_results", [{}])), default=100)
        phase_status["phase_3_live_udp"] = max_loss < 5.0
    except Exception as e:
        print(f"  [!] Live UDP benchmark failed: {e}")
        phase_status["phase_3_live_udp"] = False

    # =====================================================================
    # PHASE 4: LIVE TCP CONCURRENCY BENCHMARK (Real Socket I/O + Resilience)
    # =====================================================================
    print_box("  PHASE 4: LIVE TCP CONCURRENCY BENCHMARK (1–64 Clients + Resilience)")
    try:
        from benchmarks.live_network import run_live_tcp_benchmark
        tcp_result = run_live_tcp_benchmark(
            client_counts=[1, 4, 16, 64],
            events_per_client=2000,
            host="127.0.0.1",
            port=5515,
            workers=WORKERS,
            batch_size=1000,
            results_dir=run_dir,
        )
        all_results["live_tcp"] = tcp_result.get("tcp_results", [])
        all_results["tcp_resilience_passed"] = tcp_result.get("resilience_passed", False)
        phase_status["phase_4_live_tcp"] = tcp_result.get("resilience_passed", False)
    except Exception as e:
        print(f"  [!] Live TCP benchmark failed: {e}")
        phase_status["phase_4_live_tcp"] = False

    # =====================================================================
    # PHASE 5: MULTI-WORKER SCALABILITY
    # =====================================================================
    print_box("  PHASE 5: MULTI-WORKER SCALABILITY (1–8 Workers, Throughput & Latency)")
    try:
        from benchmarks.multiworker import run_worker_benchmark
        mw_result = run_worker_benchmark(
            worker_counts=[1, 2, 4, 8],
            events_per_run=50000,
            results_dir=run_dir,
        )
        all_results["multiworker"] = mw_result.get("configurations", [])
        phase_status["phase_5_multiworker"] = True
    except Exception as e:
        print(f"  [!] Multi-worker benchmark failed: {e}")
        phase_status["phase_5_multiworker"] = False

    # =====================================================================
    # PHASE 6: PROCESS-LEVEL MEMORY VALIDATION
    # =====================================================================
    print_box("  PHASE 6: PROCESS-LEVEL MEMORY VALIDATION (Per-Worker PID Attribution)")
    try:
        from benchmarks.soak import run_memory_validation
        mem_result = run_memory_validation(
            workers=WORKERS,
            batch_size=2000,
            test_events=20000,
            results_dir=run_dir,
        )
        all_results["memory_validation"] = mem_result
        phase_status["phase_6_memory"] = mem_result.get("claim_pass", False)
    except Exception as e:
        print(f"  [!] Memory validation failed: {e}")
        phase_status["phase_6_memory"] = False

    # =====================================================================
    # PHASE 7: DATA INTEGRITY & SECURITY VALIDATION
    # =====================================================================
    print_box("  PHASE 7: DATA INTEGRITY & SECURITY VALIDATION")
    try:
        from benchmarks.integrity import IntegrityValidator
        iv = IntegrityValidator(results_dir=run_dir)
        integrity_result = iv.run_all()
        all_results["integrity"] = integrity_result
        phase_status["phase_7_integrity"] = integrity_result.get("failed", 1) == 0
    except Exception as e:
        print(f"  [!] Integrity validation failed: {e}")
        phase_status["phase_7_integrity"] = False

    # =====================================================================
    # PHASE 8: LOGHUB ACADEMIC ACCURACY (14 Enterprise Datasets)
    # =====================================================================
    print_box("  PHASE 8: LOGHUB ACADEMIC ACCURACY (14 Enterprise & HPC Datasets)")
    try:
        from benchmarks.loghub_eval import run_loghub_evaluation
        loghub_result = run_loghub_evaluation(results_dir=run_dir)
        all_results["loghub"] = loghub_result
        pa = loghub_result.get("overall_parsing_accuracy_pct", 0)
        phase_status["phase_8_loghub"] = pa >= 90.0
        print(f"\n  Overall Parsing Accuracy: {pa:.1f}%")
    except Exception as e:
        print(f"  [!] Loghub evaluation failed: {e}")
        phase_status["phase_8_loghub"] = False

    # =====================================================================
    # PHASE 9: INTELLIGENT FEATURE OVERHEAD
    # =====================================================================
    print_box("  PHASE 9: FEATURE OVERHEAD (Process, DNA, Auto-Parser, Correlation)")
    feature_timings = {}
    feature_ok = []

    # Populate the isolated store first so correlation has events to work on
    for key, cmd, desc in (
        ("process_sec", ["process", "--files", DEMO_FILE], "File processing into the isolated store..."),
        ("fingerprint_sec", ["fingerprint", "--file", DEMO_FILE], "Log DNA fingerprinting..."),
        ("auto_parser_sec", ["learn", "--file", DEMO_FILE, "--all-lines"], "Auto-parser learning..."),
        ("correlation_sec", ["correlate", "--limit", "500"], "MITRE ATT&CK event correlation..."),
    ):
        r = run_cli_command([PYTHON_EXE, "-m", "ulpf.main", *cmd], desc)
        feature_timings[key] = round(r["time"], 3)
        feature_ok.append(r["success"])

    all_results["feature_overhead"] = feature_timings
    phase_status["phase_9_features"] = all(feature_ok) and all(v < 30.0 for v in feature_timings.values())

    # =====================================================================
    # FINAL REPORT
    # =====================================================================
    print_box("  ENTERPRISE BENCHMARK REPORT  ")

    passed = sum(1 for v in phase_status.values() if v)
    total = len(phase_status)
    overall = "PASS" if passed == total else f"PARTIAL ({passed}/{total})"

    print(f"\n  {'Phase':<50} {'Status':>10}")
    print(f"  {'─' * 50} {'─' * 10}")
    for phase, status in phase_status.items():
        label = phase.replace("_", " ").title()
        icon = "  PASS" if status else "  FAIL"
        print(f"  {label:<50} {icon:>10}")

    print(f"\n  {'─' * 62}")
    print(f"  {'OVERALL':.<50} {overall:>12}")

    # Soak summary
    soak = all_results.get("soak_test", {})
    if soak:
        print(f"\n  Soak Test:")
        print(f"    Avg EPS          : {soak.get('avg_eps', 'N/A'):>10,}")
        print(f"    Peak RSS         : {soak.get('peak_rss_mb', 'N/A'):>10} MB")
        print(f"    Memory Leak      : {'NONE' if not soak.get('memory_leak_detected') else 'DETECTED'}")
        print(f"    Worker Failures  : {'NONE' if not soak.get('worker_failure_detected') else 'DETECTED'}")
        print(f"    Degradation      : {'NONE' if not soak.get('performance_degradation') else 'DETECTED'}")

    # Memory summary
    mem = all_results.get("memory_validation", {})
    if mem:
        print(f"\n  Memory:")
        print(f"    Peak App RSS     : {mem.get('total_peak_app_rss_mb', 'N/A')} MB")
        print(f"    Avg per Worker   : {mem.get('avg_peak_per_worker_mb', 'N/A')} MB")

    # Loghub summary
    loghub = all_results.get("loghub", {})
    if loghub:
        print(f"\n  Loghub Accuracy:")
        print(f"    Parsing Accuracy : {loghub.get('overall_parsing_accuracy_pct', 'N/A')}%")

    # Feature overhead
    feat = all_results.get("feature_overhead", {})
    if feat:
        print(f"\n  Feature Overhead:")
        for k, v in feat.items():
            print(f"    {k:<20}: {v}s")

    print(f"\n  Results saved to: {run_dir}")

    # Save full JSON report
    report = {
        "timestamp": timestamp,
        "python": PYTHON_EXE,
        "results_dir": run_dir,
        "phase_status": phase_status,
        "overall": overall,
        "results": {},
    }
    # Serialize only JSON-safe parts
    for key, val in all_results.items():
        try:
            json.dumps(val)
            report["results"][key] = val
        except (TypeError, ValueError):
            report["results"][key] = str(val)

    report_path = os.path.join(run_dir, "enterprise_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"  Full report: {report_path}")
    print("=" * 105)

    return 0 if overall == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
