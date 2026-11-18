"""
ULPF Benchmark Suite
========================
Reproducible performance, reliability, and integrity validation.

Modes:
  Mode A (Engine): Raw pipeline throughput — no GUI, no listener, no storage I/O.
  Mode B (Live):   Full product stack — listener → pipeline → storage → GUI notification.

Every measurement is written to CSV/JSON files in the results directory.
"""
from __future__ import annotations

import csv
import gc
import json
import multiprocessing
import os
import platform
import statistics
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from benchmarks.generator import DeterministicGenerator


class HardwareProfile:
    """Capture and report hardware/OS information for the benchmark environment."""

    @staticmethod
    def collect() -> dict:
        info = {
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "cpu_count_logical": multiprocessing.cpu_count(),
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
        }

        # RAM
        try:
            import psutil
            mem = psutil.virtual_memory()
            info["ram_total_gb"] = round(mem.total / (1024 ** 3), 2)
            info["ram_available_gb"] = round(mem.available / (1024 ** 3), 2)
        except ImportError:
            info["ram_total_gb"] = "psutil_not_installed"

        # CPU brand (Windows WMI)
        if platform.system() == "Windows":
            try:
                import subprocess
                result = subprocess.run(
                    ["wmic", "cpu", "get", "name"],
                    capture_output=True, text=True, timeout=5
                )
                lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip() and l.strip() != "Name"]
                if lines:
                    info["cpu_brand"] = lines[0]
            except Exception:
                pass

        return info


class LatencyTracker:
    """Collects per-event latency samples for percentile computation."""

    def __init__(self):
        self.samples: List[float] = []

    def record(self, latency_ms: float):
        self.samples.append(latency_ms)

    def percentile(self, p: float) -> float:
        if not self.samples:
            return 0.0
        sorted_s = sorted(self.samples)
        idx = int(len(sorted_s) * p / 100.0)
        idx = min(idx, len(sorted_s) - 1)
        return sorted_s[idx]

    def summary(self) -> dict:
        if not self.samples:
            return {"count": 0}
        sorted_s = sorted(self.samples)
        return {
            "count": len(sorted_s),
            "min_ms": round(sorted_s[0], 4),
            "max_ms": round(sorted_s[-1], 4),
            "mean_ms": round(statistics.mean(sorted_s), 4),
            "median_ms": round(statistics.median(sorted_s), 4),
            "stdev_ms": round(statistics.stdev(sorted_s), 4) if len(sorted_s) > 1 else 0.0,
            "p50_ms": round(self.percentile(50), 4),
            "p90_ms": round(self.percentile(90), 4),
            "p95_ms": round(self.percentile(95), 4),
            "p99_ms": round(self.percentile(99), 4),
            "p999_ms": round(self.percentile(99.9), 4),
        }


class MemoryTracker:
    """Track memory usage during benchmark execution."""

    def __init__(self):
        self._snapshots: List[dict] = []
        self._baseline: float = 0.0

    def snapshot(self, label: str = "") -> dict:
        try:
            import psutil
            proc = psutil.Process(os.getpid())
            mem = proc.memory_info()
            main_rss = mem.rss / (1024 * 1024)
            children = proc.children(recursive=True)
            worker_rss = sum(c.memory_info().rss for c in children if c.is_running()) / (1024 * 1024)
            total_rss = main_rss + worker_rss
            snap = {
                "label": label,
                "rss_mb": round(total_rss, 2),
                "main_rss_mb": round(main_rss, 2),
                "worker_rss_mb": round(worker_rss, 2),
                "vms_mb": round(mem.vms / (1024 * 1024), 2),
                "timestamp": time.time(),
            }
        except ImportError:
            # Fallback: try platform-specific methods
            rss_mb = 0.0
            vms_mb = 0.0
            try:
                if sys.platform == "win32":
                    # Windows: use ctypes to query process memory
                    import ctypes
                    import ctypes.wintypes
                    class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                        _fields_ = [
                            ("cb", ctypes.wintypes.DWORD),
                            ("PageFaultCount", ctypes.wintypes.DWORD),
                            ("PeakWorkingSetSize", ctypes.c_size_t),
                            ("WorkingSetSize", ctypes.c_size_t),
                            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                            ("PagefileUsage", ctypes.c_size_t),
                            ("PeakPagefileUsage", ctypes.c_size_t),
                        ]
                    counters = PROCESS_MEMORY_COUNTERS()
                    counters.cb = ctypes.sizeof(counters)
                    handle = ctypes.windll.kernel32.GetCurrentProcess()
                    if ctypes.windll.psapi.GetProcessMemoryInfo(
                        handle, ctypes.byref(counters), ctypes.sizeof(counters)
                    ):
                        rss_mb = round(counters.WorkingSetSize / (1024 * 1024), 2)
                        vms_mb = round(counters.PagefileUsage / (1024 * 1024), 2)
                else:
                    import resource
                    usage = resource.getrusage(resource.RUSAGE_SELF)
                    rss_mb = round(usage.ru_maxrss / 1024, 2)
            except Exception:
                pass
            snap = {
                "label": label,
                "rss_mb": rss_mb,
                "vms_mb": vms_mb,
                "timestamp": time.time(),
            }
        except Exception:
            snap = {
                "label": label,
                "rss_mb": 0,
                "vms_mb": 0,
                "timestamp": time.time(),
            }
        self._snapshots.append(snap)
        return snap

    def set_baseline(self):
        snap = self.snapshot("baseline")
        self._baseline = snap["rss_mb"]

    def delta_mb(self) -> float:
        if not self._snapshots:
            return 0.0
        return self._snapshots[-1]["rss_mb"] - self._baseline

    def get_snapshots(self) -> List[dict]:
        return list(self._snapshots)


class BenchmarkRunner:
    """
    Core benchmark orchestrator.

    Supports:
      - Mode A (Engine): Isolated pipeline throughput measurement
      - Mode B (Live): Full-stack product measurement
      - Database write/read benchmarks
      - Memory profiling
      - Latency percentile tracking
    """

    def __init__(self, num_events: int = 10000, seed: int = 42,
                 results_dir: str | None = None):
        self.num_events = num_events
        self.seed = seed
        self.generator = DeterministicGenerator(seed=seed)
        self.results_dir = results_dir or os.path.join(
            PROJECT_ROOT, "benchmarks", "results",
            datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        )
        os.makedirs(self.results_dir, exist_ok=True)
        self.hardware = HardwareProfile.collect()
        self.memory = MemoryTracker()

    def get_hardware_info(self) -> dict:
        return self.hardware

    # ------------------------------------------------------------------
    # Mode A: Engine-only pipeline benchmark
    # ------------------------------------------------------------------

    def run_pipeline_benchmark(self, num_workers: int = None,
                                warmup_events: int = 1000) -> dict:
        """
        Mode A: Measure raw pipeline throughput.

        Process events through Pipeline.process_line() without any
        network listener, storage I/O, or GUI overhead.
        """
        if num_workers is None:
            import os
            num_workers = os.cpu_count() or 4

        print(f"\n  [Mode A] Engine Pipeline Benchmark")
        print(f"  {'-' * 50}")
        print(f"  Events     : {self.num_events:,}")
        print(f"  Workers    : {num_workers}")
        print(f"  Warmup     : {warmup_events:,}")

        self.memory.set_baseline()

        # Generate deterministic dataset
        print(f"  Generating synthetic dataset (seed={self.seed})...")
        t_gen = time.perf_counter()
        lines = self.generator.generate(self.num_events)
        gen_time = time.perf_counter() - t_gen
        print(f"  Generated {len(lines):,} lines in {gen_time:.2f}s")

        self.memory.snapshot("after_generation")

        # Initialize pipeline
        from ulpf.engine.pipeline import Pipeline
        pipeline = Pipeline()

        # Warmup phase (excluded from measurement)
        print(f"  Warming up ({warmup_events:,} events)...")
        warmup_lines = lines[:warmup_events]
        for line in warmup_lines:
            pipeline.process_line(line)
        pipeline.reset_metrics()

        self.memory.snapshot("after_warmup")

        # Force GC before measurement
        gc.collect()
        gc.disable()

        # Main measurement
        print(f"  Running benchmark...")
        latency = LatencyTracker()
        successes = 0
        failures = 0
        format_counts: Dict[str, int] = {}

        if num_workers > 1:
            from concurrent.futures import ProcessPoolExecutor, as_completed
            from ulpf.ingestion.workers import _benchmark_process_batch

            chunk_size = max(500, len(lines) // (num_workers * 4))
            batches = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]

            t_start = time.perf_counter()
            with ProcessPoolExecutor(max_workers=num_workers) as executor:
                futures = [executor.submit(_benchmark_process_batch, b) for b in batches]
                for f in as_completed(futures):
                    s, fail, ms, fmts = f.result()
                    successes += s
                    failures += fail
                    batch_total = max(s + fail, 1)
                    latency.record(ms / batch_total)
                    for k, v in fmts.items():
                        format_counts[k] = format_counts.get(k, 0) + v
            t_end = time.perf_counter()
        else:
            t_start = time.perf_counter()
            chunk_size = 2000
            batches = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
            
            for batch in batches:
                t_batch = time.perf_counter()
                results = pipeline.process_batch(batch)
                elapsed_ms = (time.perf_counter() - t_batch) * 1000
                latency.record(elapsed_ms / len(batch))
                
                if hasattr(results, "num_rows"):
                    successes += results.num_rows
                    format_counts["duckdb_vectorized"] = format_counts.get("duckdb_vectorized", 0) + results.num_rows
                else:
                    for result in results:
                        if result.get("success"):
                            successes += 1
                            event = result.get("event", {})
                            fmt = event.get("raw_format", "unknown")
                            format_counts[fmt] = format_counts.get(fmt, 0) + 1
                        elif not result.get("skipped"):
                            failures += 1
            t_end = time.perf_counter()

        gc.enable()

        total_time_sec = t_end - t_start
        eps = self.num_events / max(total_time_sec, 0.0001)

        snap = self.memory.snapshot("after_benchmark")
        total_rss = snap.get("rss_mb", 0.0)
        main_rss = snap.get("main_rss_mb", 0.0)
        worker_rss = snap.get("worker_rss_mb", 0.0)

        result = {
            "mode": "A_engine",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "events_total": self.num_events,
            "events_success": successes,
            "events_failed": failures,
            # Header/comment lines (W3C #Fields, CSV header rows) are skipped by design
            "events_skipped_headers": self.num_events - successes - failures,
            "success_rate_pct": round(successes / max(successes + failures, 1) * 100, 2),
            "total_time_sec": round(total_time_sec, 4),
            "events_per_second": round(eps, 1),
            "generation_time_sec": round(gen_time, 3),
            "warmup_events": warmup_events,
            "workers": num_workers,
            "seed": self.seed,
            "latency": latency.summary(),
            "format_distribution": format_counts,
            "memory": {
                "baseline_rss_mb": self.memory._baseline,
                "total_rss_mb": total_rss,
                "main_rss_mb": main_rss,
                "worker_rss_mb": worker_rss,
                "peak_delta_mb": self.memory.delta_mb(),
                "snapshots": self.memory.get_snapshots(),
            },
            "hardware": self.hardware,
        }

        # Print results
        print(f"\n  -- Results ------------------------------------------")
        print(f"  Total Time     : {total_time_sec:.3f}s")
        print(f"  Throughput     : {eps:,.0f} EPS")
        print(f"  Success Rate   : {result['success_rate_pct']}%  "
              f"({result['events_skipped_headers']:,} header/comment lines skipped)")
        print(f"  P50 Latency    : {latency.percentile(50):.3f} ms")
        print(f"  P95 Latency    : {latency.percentile(95):.3f} ms")
        print(f"  P99 Latency    : {latency.percentile(99):.3f} ms")
        print(f"  Total Process RSS: {total_rss:.1f} MB (Main: {main_rss:.1f} MB, Workers: {worker_rss:.1f} MB)")
        print(f"  Memory Delta   : {self.memory.delta_mb():.1f} MB")

        # Save raw results
        self._save_result("pipeline_benchmark", result)
        self._save_latency_csv("pipeline_latency", latency.samples)

        return result

    # ------------------------------------------------------------------
    # Mode B: Full-stack live benchmark
    # ------------------------------------------------------------------

    def run_live_benchmark(self, host: str = "127.0.0.1", port: int = 5514,
                           proto: str = "udp", batch_size: int = 100,
                           settle_time: float = 5.0) -> dict:
        """
        Mode B: Full-stack benchmark — send data via network to ULPF listener.

        This measures the complete product pipeline:
        Network → Listener → Pipeline → Storage → GUI callback

        Requires a running ULPF listener (GUI desktop or CLI listen).
        """
        import socket

        print(f"\n  [Mode B] Live Full-Stack Benchmark")
        print(f"  {'-' * 50}")
        print(f"  Target       : {host}:{port} ({proto.upper()})")
        print(f"  Events       : {self.num_events:,}")
        print(f"  Batch Size   : {batch_size}")

        # Generate dataset
        print(f"  Generating dataset...")
        lines = self.generator.generate(self.num_events)

        # Send data
        print(f"  Sending {len(lines):,} events via {proto.upper()}...")
        sent = 0
        send_errors = 0
        t_start = time.perf_counter()

        if proto.lower() == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for line in lines:
                try:
                    sock.sendto(line.encode("utf-8"), (host, port))
                    sent += 1
                except Exception:
                    send_errors += 1
            sock.close()
        else:
            # TCP — send in batches with newline delimiters
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host, port))
                batch = []
                for line in lines:
                    batch.append(line)
                    if len(batch) >= batch_size:
                        payload = "\n".join(batch) + "\n"
                        sock.sendall(payload.encode("utf-8"))
                        sent += len(batch)
                        batch = []
                if batch:
                    payload = "\n".join(batch) + "\n"
                    sock.sendall(payload.encode("utf-8"))
                    sent += len(batch)
                sock.close()
            except Exception as e:
                print(f"  [!] TCP connection failed: {e}")
                return {"mode": "B_live", "error": str(e)}

        t_send_end = time.perf_counter()
        send_time = t_send_end - t_start
        send_eps = sent / max(send_time, 0.0001)

        print(f"  Sent {sent:,} events in {send_time:.2f}s ({send_eps:,.0f} send EPS)")
        print(f"  Waiting {settle_time}s for listener to flush...")
        time.sleep(settle_time)

        result = {
            "mode": "B_live",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": f"{host}:{port}",
            "protocol": proto.upper(),
            "events_sent": sent,
            "send_errors": send_errors,
            "send_time_sec": round(send_time, 4),
            "send_eps": round(send_eps, 1),
            "settle_time_sec": settle_time,
            "seed": self.seed,
            "hardware": self.hardware,
        }

        self._save_result("live_benchmark", result)
        return result

    # ------------------------------------------------------------------
    # Database benchmark
    # ------------------------------------------------------------------

    def run_database_benchmark(self) -> dict:
        """
        Measure DuckDB storage write and read performance.
        """
        import tempfile

        print(f"\n  [DB] Database Benchmark")
        print(f"  {'-' * 50}")

        from ulpf.engine.pipeline import Pipeline
        from ulpf.storage.database import Database

        # Use temp database to avoid polluting real data
        tmp_db = os.path.join(tempfile.gettempdir(), f"ulpf_bench_{os.getpid()}.duckdb")
        db = Database(db_path=tmp_db)
        pipeline = Pipeline()

        # Generate and process events
        print(f"  Processing {self.num_events:,} events through pipeline...")
        lines = self.generator.generate(self.num_events)
        events = []
        for line in lines:
            result = pipeline.process_line(line)
            if result.get("success") and result.get("event"):
                events.append(result["event"])

        print(f"  Got {len(events):,} parsed events")

        # Write benchmark
        gc.collect()
        print(f"  Writing to DuckDB...")
        t_write_start = time.perf_counter()
        stored = db.store_events_bulk(events)
        t_write_end = time.perf_counter()
        write_time = t_write_end - t_write_start
        write_eps = stored / max(write_time, 0.0001)

        # Read benchmark
        print(f"  Reading from DuckDB...")
        t_read_start = time.perf_counter()
        read_events = db.query(limit=min(len(events), 10000))
        t_read_end = time.perf_counter()
        read_time = t_read_end - t_read_start
        read_eps = len(read_events) / max(read_time, 0.0001)

        # Stats query
        t_stats_start = time.perf_counter()
        stats = db.stats()
        t_stats_end = time.perf_counter()
        stats_time = t_stats_end - t_stats_start

        # Cleanup
        db.close()
        try:
            os.remove(tmp_db)
        except Exception:
            pass

        db_size_mb = 0
        if os.path.exists(tmp_db):
            db_size_mb = round(os.path.getsize(tmp_db) / (1024 * 1024), 2)

        result = {
            "events_processed": len(events),
            "events_stored": stored,
            "write_time_sec": round(write_time, 4),
            "write_eps": round(write_eps, 1),
            "events_read": len(read_events),
            "read_time_sec": round(read_time, 4),
            "read_eps": round(read_eps, 1),
            "stats_query_time_sec": round(stats_time, 4),
            "db_size_mb": db_size_mb,
            "stats": stats,
        }

        print(f"\n  -- DB Results ----------------------------------------")
        print(f"  Write          : {stored:,} events in {write_time:.3f}s ({write_eps:,.0f} EPS)")
        print(f"  Read           : {len(read_events):,} events in {read_time:.3f}s ({read_eps:,.0f} EPS)")
        print(f"  Stats Query    : {stats_time:.3f}s")

        self._save_result("database_benchmark", result)
        return result

    # ------------------------------------------------------------------
    # Scalability sweep
    # ------------------------------------------------------------------

    def run_scalability_sweep(self, event_counts: List[int] | None = None) -> dict:
        """
        Run pipeline benchmark at multiple event counts to measure scalability.
        """
        if event_counts is None:
            event_counts = [1000, 5000, 10000, 50000, 100000]

        print(f"\n  [Scalability] Sweep across {len(event_counts)} sizes")
        print(f"  {'-' * 50}")

        results = []
        for count in event_counts:
            print(f"\n  --- {count:,} events ---")
            runner = BenchmarkRunner(num_events=count, seed=self.seed,
                                     results_dir=self.results_dir)
            try:
                r = runner.run_pipeline_benchmark(warmup_events=min(count // 10, 1000))
                results.append({
                    "events": count,
                    "eps": r["events_per_second"],
                    "total_time_sec": r["total_time_sec"],
                    "p50_ms": r["latency"]["p50_ms"],
                    "p95_ms": r["latency"]["p95_ms"],
                    "p99_ms": r["latency"]["p99_ms"],
                    "success_rate": r["success_rate_pct"],
                    "memory_delta_mb": r["memory"]["peak_delta_mb"],
                })
            except Exception as e:
                print(f"  [!] Error at {count:,}: {e}")
                results.append({"events": count, "error": str(e)})

        # Save scalability CSV
        csv_path = os.path.join(self.results_dir, "scalability_sweep.csv")
        if results:
            keys = results[0].keys()
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(keys))
                writer.writeheader()
                for r in results:
                    writer.writerow(r)

        sweep_result = {
            "sweep_sizes": event_counts,
            "results": results,
            "csv_path": csv_path,
        }
        self._save_result("scalability_sweep", sweep_result)
        return sweep_result

    # ------------------------------------------------------------------
    # Format-isolated benchmarks
    # ------------------------------------------------------------------

    def run_format_benchmarks(self, events_per_format: int = 10000) -> dict:
        """
        Benchmark each log format independently to identify bottlenecks.
        """
        formats = ["syslog3164", "syslog5424", "cef", "leef", "json",
                    "xml", "csv", "kv", "w3c"]

        print(f"\n  [Format] Per-format benchmark ({events_per_format:,} events each)")
        print(f"  {'-' * 50}")

        from ulpf.engine.pipeline import Pipeline

        results = []
        for fmt in formats:
            pipeline = Pipeline()
            gen = DeterministicGenerator(seed=self.seed)
            lines = gen.generate(events_per_format, format_filter=fmt)

            # Warmup
            for line in lines[:100]:
                pipeline.process_line(line)
            pipeline.reset_metrics()

            gc.collect()
            latency = LatencyTracker()
            successes = 0

            t0 = time.perf_counter()
            for line in lines:
                te = time.perf_counter()
                r = pipeline.process_line(line)
                latency.record((time.perf_counter() - te) * 1000)
                if r.get("success"):
                    successes += 1
            elapsed = time.perf_counter() - t0
            eps = events_per_format / max(elapsed, 0.0001)

            fmt_result = {
                "format": fmt,
                "events": events_per_format,
                "eps": round(eps, 1),
                "total_time_sec": round(elapsed, 4),
                "success_rate_pct": round(successes / events_per_format * 100, 2),
                "p50_ms": round(latency.percentile(50), 4),
                "p95_ms": round(latency.percentile(95), 4),
                "p99_ms": round(latency.percentile(99), 4),
            }
            results.append(fmt_result)
            print(f"  {fmt:12s} : {eps:>10,.0f} EPS | P95={latency.percentile(95):.3f}ms | "
                  f"success={fmt_result['success_rate_pct']}%")

        # Save CSV
        csv_path = os.path.join(self.results_dir, "format_benchmark.csv")
        if results:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
                writer.writeheader()
                writer.writerows(results)

        summary = {"formats": results, "csv_path": csv_path}
        self._save_result("format_benchmark", summary)
        return summary

    # ------------------------------------------------------------------
    # Claim validation
    # ------------------------------------------------------------------

    def validate_claims(self, pipeline_result: dict) -> dict:
        """
        Compare actual measurements against ULPF's published claims.
        """
        claims = {
            "eps_target": 154000,
            "p95_target_ms": 50.0,
            "p99_target_ms": 85.0,
            "memory_per_worker_mb": 10.0,
        }

        actual_eps = pipeline_result.get("events_per_second", 0)
        actual_p95 = pipeline_result.get("latency", {}).get("p95_ms", 0)
        actual_p99 = pipeline_result.get("latency", {}).get("p99_ms", 0)
        workers = pipeline_result.get("workers", 1)
        worker_rss = pipeline_result.get("memory", {}).get("worker_rss_mb", 0)
        total_rss = pipeline_result.get("memory", {}).get("total_rss_mb", 0)
        actual_mem = (worker_rss / workers) if (workers > 1 and worker_rss > 0) else (total_rss / max(workers, 1))

        validation = {
            "eps": {
                "claim": f"{claims['eps_target']:,}+ EPS",
                "measured": round(actual_eps, 1),
                "pass": actual_eps >= claims["eps_target"],
                "delta_pct": round((actual_eps - claims["eps_target"]) / claims["eps_target"] * 100, 1),
            },
            "p95_latency": {
                "claim": f"< {claims['p95_target_ms']} ms",
                "measured": round(actual_p95, 4),
                "pass": actual_p95 < claims["p95_target_ms"],
            },
            "p99_latency": {
                "claim": f"< {claims['p99_target_ms']} ms",
                "measured": round(actual_p99, 4),
                "pass": actual_p99 < claims["p99_target_ms"],
            },
            "memory_per_worker": {
                "claim": f"< {claims['memory_per_worker_mb']} MB per worker",
                "measured": round(actual_mem, 2),
                "pass": actual_mem < claims["memory_per_worker_mb"],
            },
        }

        overall_pass = all(v["pass"] for v in validation.values())
        validation["overall_pass"] = overall_pass

        print(f"\n  -- Claim Validation ----------------------------------")
        for key, v in validation.items():
            if key == "overall_pass":
                continue
            status = "[PASS]" if v["pass"] else "[FAIL]"
            print(f"  {key:20s} : {v['measured']} (claim: {v['claim']}) -> {status}")
        print(f"  {'-' * 48}")
        print(f"  OVERALL: {'[PASS] ALL CLAIMS VALIDATED' if overall_pass else '[FAIL] SOME CLAIMS FAILED'}")

        self._save_result("claim_validation", validation)
        return validation

    # ------------------------------------------------------------------
    # Full suite
    # ------------------------------------------------------------------

    def run_full_suite(self, comprehensive: bool = True, soak_duration: float = 30.0) -> dict:
        """Run all benchmarks in sequence and produce complete results."""
        print(f"\n{'=' * 60}")
        print(f"  ULPF BENCHMARK VALIDATION LABORATORY — COMPREHENSIVE SUITE")
        print(f"{'=' * 60}")

        hw = self.get_hardware_info()
        print(f"  Platform : {hw.get('platform', 'Unknown')}")
        print(f"  CPU      : {hw.get('cpu_brand', hw.get('processor', 'Unknown'))}")
        print(f"  Cores    : {hw.get('cpu_count_logical', '?')}")
        print(f"  RAM      : {hw.get('ram_total_gb', '?')} GB")
        print(f"  Python   : {hw.get('python_version', '?')}")
        print(f"  Events   : {self.num_events:,}")
        print(f"  Results  : {self.results_dir}")

        all_results = {
            "benchmark_version": "2.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hardware": hw,
            "seed": self.seed,
            "events": self.num_events,
        }

        if comprehensive:
            # 1. Multi-Worker Scalability
            try:
                print(f"\n{'=' * 60}")
                print(f"  [1/10] MULTI-WORKER SCALABILITY BENCHMARK (Section 2)")
                print(f"{'=' * 60}")
                from benchmarks.multiworker import run_worker_benchmark
                all_results["worker_scalability"] = run_worker_benchmark(
                    worker_counts=[1, 2, 4, 8, 12, 16],
                    events_per_run=min(self.num_events, 20000),
                    seed=self.seed,
                    results_dir=self.results_dir,
                )
            except Exception as e:
                print(f"  [!] Multi-worker benchmark error: {e}")
                traceback.print_exc()

            # 2. Offered Rate 154K Claim
            try:
                print(f"\n{'=' * 60}")
                print(f"  [2/10] OFFERED RATE 154K CLAIM TEST (Section 3)")
                print(f"{'=' * 60}")
                from benchmarks.claim_154k import run_offered_rate_benchmark
                all_results["offered_rates"] = run_offered_rate_benchmark(
                    rates=[100000, 125000, 150000, 154000, 175000, 200000],
                    measure_events=min(self.num_events, 20000),
                    workers=8,
                    seed=self.seed,
                    results_dir=self.results_dir,
                )
            except Exception as e:
                print(f"  [!] Offered rate benchmark error: {e}")
                traceback.print_exc()

            # 3. Repeatability
            try:
                print(f"\n{'=' * 60}")
                print(f"  [3/10] REPEATABILITY BENCHMARK (Section 4)")
                print(f"{'=' * 60}")
                from benchmarks.claim_154k import run_repeatability_benchmark
                all_results["repeatability"] = run_repeatability_benchmark(
                    runs=3,
                    events_per_run=min(self.num_events, 20000),
                    workers=8,
                    seed=self.seed,
                    results_dir=self.results_dir,
                )
            except Exception as e:
                print(f"  [!] Repeatability benchmark error: {e}")
                traceback.print_exc()

            # 4. Latency Under Load
            try:
                print(f"\n{'=' * 60}")
                print(f"  [4/10] LATENCY AT LOAD BENCHMARK (Section 5)")
                print(f"{'=' * 60}")
                from benchmarks.claim_154k import run_latency_at_load_benchmark
                all_results["latency_at_load"] = run_latency_at_load_benchmark(
                    load_levels=[10000, 50000, 100000, 125000, 150000, 154000, 175000],
                    events_per_level=min(self.num_events, 10000),
                    workers=8,
                    seed=self.seed,
                    results_dir=self.results_dir,
                )
            except Exception as e:
                print(f"  [!] Latency at load error: {e}")
                traceback.print_exc()

            # 5. Burst Ingestion
            try:
                print(f"\n{'=' * 60}")
                print(f"  [5/10] BURST INGESTION BENCHMARK (Section 9)")
                print(f"{'=' * 60}")
                from benchmarks.claim_154k import run_burst_benchmark
                all_results["burst_test"] = run_burst_benchmark(
                    baseline_eps=50000,
                    burst_rates=[100000, 150000, 200000, 300000],
                    workers=8,
                    seed=self.seed,
                    results_dir=self.results_dir,
                )
            except Exception as e:
                print(f"  [!] Burst test error: {e}")
                traceback.print_exc()

            # 6. Live UDP
            try:
                print(f"\n{'=' * 60}")
                print(f"  [6/10] LIVE UDP BENCHMARK (Section 7)")
                print(f"{'=' * 60}")
                from benchmarks.live_network import run_live_udp_benchmark
                all_results["live_udp"] = run_live_udp_benchmark(
                    rates=[10000, 50000, 100000, 150000, 154000, 200000],
                    events_per_rate=5000,
                    workers=8,
                    seed=self.seed,
                    results_dir=self.results_dir,
                )
            except Exception as e:
                print(f"  [!] Live UDP error: {e}")
                traceback.print_exc()

            # 7. Live TCP
            try:
                print(f"\n{'=' * 60}")
                print(f"  [7/10] LIVE TCP BENCHMARK & CONCURRENCY (Section 8)")
                print(f"{'=' * 60}")
                from benchmarks.live_network import run_live_tcp_benchmark
                all_results["live_tcp"] = run_live_tcp_benchmark(
                    client_counts=[1, 4, 16, 64],
                    events_per_client=1000,
                    workers=8,
                    seed=self.seed,
                    results_dir=self.results_dir,
                )
            except Exception as e:
                print(f"  [!] Live TCP error: {e}")
                traceback.print_exc()

            # 8. Memory Validation
            try:
                print(f"\n{'=' * 60}")
                print(f"  [8/10] PROCESS-LEVEL MEMORY VALIDATION (Section 10)")
                print(f"{'=' * 60}")
                from benchmarks.soak import run_memory_validation
                all_results["memory_validation"] = run_memory_validation(
                    workers=4,
                    test_events=10000,
                    results_dir=self.results_dir,
                )
            except Exception as e:
                print(f"  [!] Memory validation error: {e}")
                traceback.print_exc()

            # 9. Soak Test
            try:
                print(f"\n{'=' * 60}")
                print(f"  [9/10] SOAK TEST BENCHMARK (Section 11)")
                print(f"{'=' * 60}")
                from benchmarks.soak import run_soak_test
                all_results["soak_test"] = run_soak_test(
                    duration_sec=soak_duration,
                    target_eps=5000,
                    workers=8,
                    results_dir=self.results_dir,
                )
            except Exception as e:
                print(f"  [!] Soak test error: {e}")
                traceback.print_exc()

            # 10. Comprehensive Integrity Suite (Sections 12-17)
            try:
                print(f"\n{'=' * 60}")
                print(f"  [10/10] INTEGRITY, SECURITY, DRIFT & AIR-GAP SUITE (Sections 12-17)")
                print(f"{'=' * 60}")
                from benchmarks.integrity_suite import IntegritySuiteRunner
                integ_runner = IntegritySuiteRunner(results_dir=self.results_dir)
                all_results["integrity"] = integ_runner.run_all()
            except Exception as e:
                print(f"  [!] Integrity suite error: {e}")
                traceback.print_exc()

        # Isolated Pipeline, Database, Formats
        try:
            pipeline_result = self.run_pipeline_benchmark(num_workers=8)
            all_results["pipeline"] = pipeline_result
        except Exception as e:
            print(f"  [!] Pipeline benchmark failed: {e}")
            traceback.print_exc()
            all_results["pipeline"] = {"error": str(e)}
            pipeline_result = {}

        try:
            db_result = self.run_database_benchmark()
            all_results["database"] = db_result
        except Exception as e:
            print(f"  [!] Database benchmark failed: {e}")
            all_results["database"] = {"error": str(e)}

        try:
            format_result = self.run_format_benchmarks(
                events_per_format=min(self.num_events, 5000)
            )
            all_results["formats"] = format_result
        except Exception as e:
            print(f"  [!] Format benchmark failed: {e}")
            all_results["formats"] = {"error": str(e)}

        # Claim validation
        if pipeline_result and "error" not in pipeline_result:
            try:
                validation = self.validate_claims(pipeline_result)
                all_results["claim_validation"] = validation
            except Exception as e:
                all_results["claim_validation"] = {"error": str(e)}

        # Save master full_suite results.json
        self._save_result("full_suite", all_results)

        # Generate automated graphs and reports
        try:
            from benchmarks.graphs import generate_graphs
            from benchmarks.report import generate_all_reports

            print(f"\n{'=' * 60}")
            print(f"  GENERATING AUTOMATED GRAPHS (Section 18)")
            print(f"{'=' * 60}")
            graphs = generate_graphs(self.results_dir)
            all_results["graphs"] = graphs

            print(f"\n{'=' * 60}")
            print(f"  GENERATING COMPREHENSIVE REPORTS (Sections 19-20)")
            print(f"{'=' * 60}")
            reports = generate_all_reports(self.results_dir)
            all_results["reports"] = reports
            for fmt, path in reports.items():
                print(f"  [OK] {fmt.upper():10s}: {path}")
        except Exception as e:
            print(f"  [!] Error generating graphs/reports: {e}")
            traceback.print_exc()

        print(f"\n{'=' * 60}")
        print(f"  BENCHMARK COMPLETE")
        print(f"  Results directory: {self.results_dir}")
        print(f"{'=' * 60}\n")

        return all_results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _save_result(self, name: str, data: dict):
        filepath = os.path.join(self.results_dir, f"{name}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def _save_latency_csv(self, name: str, samples: List[float]):
        filepath = os.path.join(self.results_dir, f"{name}.csv")
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["event_index", "latency_ms"])
            for i, s in enumerate(samples):
                writer.writerow([i, round(s, 6)])
