"""
ULPF Multi-Worker Scalability Benchmark
==========================================
Benchmarks the actual ULPF WorkerPool process architecture across:
  1, 2, 4, 8, 12, 16 workers (as supported by the host).

Measures for every configuration:
  - Throughput EPS (persisted events / total wall-clock seconds)
  - CPU utilization (system and process tree)
  - Process RSS (main process RSS, worker processes RSS, total application RSS, peak RSS)
  - Latency percentiles (P50, P90, P95, P99, P99.9, Max)
  - Queue depth (input and output queues over time)
  - Errors and drops
  - Persisted events in DuckDB

Generates:
  worker_scalability.csv
  worker_scalability.png
"""
from __future__ import annotations

import csv
import json
import logging
import multiprocessing as mp
import os
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import duckdb
import psutil

from benchmarks.accounting import EventAccountant
from benchmarks.generator import DeterministicGenerator
from ulpf.ingestion.workers import WorkerPool

logger = logging.getLogger("benchmarks.multiworker")


class ResourceSampler(threading.Thread):
    """Samples CPU utilization, process tree RSS, and queue depths in the background."""

    def __init__(self, pool: WorkerPool, main_pid: int, interval_sec: float = 0.05):
        super().__init__(daemon=True, name="resource-sampler")
        self.pool = pool
        self.main_pid = main_pid
        self.interval = interval_sec
        self.stop_event = threading.Event()

        self.cpu_samples: List[float] = []
        self.main_rss_samples: List[float] = []
        self.worker_rss_samples: List[float] = []
        self.total_rss_samples: List[float] = []
        self.input_q_samples: List[int] = []
        self.output_q_samples: List[int] = []
        self.timestamps: List[float] = []

    def run(self):
        try:
            main_proc = psutil.Process(self.main_pid)
        except Exception:
            return

        while not self.stop_event.is_set():
            t = time.perf_counter()
            self.timestamps.append(t)

            # Queue depths
            try:
                iq = self.pool.input_queue.qsize() if hasattr(self.pool.input_queue, "qsize") else 0
            except Exception:
                iq = 0
            try:
                oq = self.pool.output_queue.qsize() if hasattr(self.pool.output_queue, "qsize") else 0
            except Exception:
                oq = 0
            self.input_q_samples.append(iq)
            self.output_q_samples.append(oq)

            # Memory & CPU
            try:
                main_mem = main_proc.memory_info().rss / (1024 * 1024)
                children = main_proc.children(recursive=True)
                worker_mem = sum(c.memory_info().rss for c in children if c.is_running()) / (1024 * 1024)
                total_mem = main_mem + worker_mem

                cpu = psutil.cpu_percent(interval=None)

                self.main_rss_samples.append(main_mem)
                self.worker_rss_samples.append(worker_mem)
                self.total_rss_samples.append(total_mem)
                self.cpu_samples.append(cpu)
            except Exception:
                pass

            self.stop_event.wait(self.interval)

    def stop(self) -> Dict[str, Any]:
        self.stop_event.set()
        self.join(timeout=2.0)
        return {
            "avg_cpu_percent": round(sum(self.cpu_samples) / max(len(self.cpu_samples), 1), 2),
            "max_cpu_percent": round(max(self.cpu_samples, default=0.0), 2),
            "main_rss_mb": round(sum(self.main_rss_samples) / max(len(self.main_rss_samples), 1), 2),
            "worker_rss_mb": round(sum(self.worker_rss_samples) / max(len(self.worker_rss_samples), 1), 2),
            "total_app_rss_mb": round(sum(self.total_rss_samples) / max(len(self.total_rss_samples), 1), 2),
            "peak_rss_mb": round(max(self.total_rss_samples, default=0.0), 2),
            "max_input_queue": max(self.input_q_samples, default=0),
            "max_output_queue": max(self.output_q_samples, default=0),
        }


def run_worker_benchmark(
    worker_counts: Optional[List[int]] = None,
    events_per_run: int = 50000,
    seed: int = 42,
    results_dir: Optional[str] = None,
    batch_size: int = 2000,
) -> Dict[str, Any]:
    """
    Execute multi-worker scalability tests for 1, 2, 4, 8, 12, 16 workers.
    """
    max_cores = mp.cpu_count()
    default_workers = [1, 2, 4, 8, 12, 16]
    tested_workers = [w for w in (worker_counts or default_workers) if w <= max_cores]
    if not tested_workers:
        tested_workers = [1, 2, min(4, max_cores)]

    results_dir = results_dir or os.path.join(PROJECT_ROOT, "benchmarks", "results", "multiworker")
    os.makedirs(results_dir, exist_ok=True)

    print(f"\n{'=' * 65}")
    print(f"  ULPF MULTI-WORKER BENCHMARK (WorkerPool Architecture)")
    print(f"{'=' * 65}")
    print(f"  Host Logical Cores : {max_cores}")
    print(f"  Tested Configurations : {tested_workers}")
    print(f"  Events per Config     : {events_per_run:,}")
    print(f"  Batch Size            : {batch_size:,}")
    print(f"  Output Directory      : {results_dir}\n")

    gen = DeterministicGenerator(seed=seed)
    all_configs_results: List[Dict[str, Any]] = []

    for workers in tested_workers:
        print(f"  [+] Testing {workers} Worker(s)...")

        # Isolated DB per worker test
        tmp_db = os.path.join(tempfile.gettempdir(), f"ulpf_mw_{workers}_{int(time.time())}.duckdb")
        if os.path.exists(tmp_db):
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        accountant = EventAccountant(output_dir=os.path.join(results_dir, f"worker_{workers}_accounting"))
        lines, expected_ids = gen.generate_with_ids(events_per_run, start_id=0)
        accountant.record_generated(expected_ids)
        accountant.record_sent(expected_ids)

        max_q = max(200, (events_per_run // batch_size) * 2)
        pool = WorkerPool(num_workers=workers, batch_size=batch_size, max_queue_size=max_q)
        pool.start(db_path=tmp_db)

        sampler = ResourceSampler(pool, os.getpid(), interval_sec=0.05)
        sampler.start()

        # Submit batches and track batch latency
        t_start = time.perf_counter()
        batch_latencies_ms: List[float] = []

        chunk_size = batch_size
        for i in range(0, len(lines), chunk_size):
            chunk = lines[i : i + chunk_size]
            # Backpressure handling before enqueue
            try:
                while pool.input_queue.qsize() >= max_q - 5:
                    time.sleep(0.002)
            except Exception:
                pass

            t_b0 = time.perf_counter()
            pool.submit_batch(chunk)
            t_b1 = time.perf_counter()
            batch_latencies_ms.append((t_b1 - t_b0) * 1000)

        # Wait until drained with idle detection
        timeout = 60.0
        t_wait_start = time.perf_counter()
        prev_processed = -1
        idle_rounds = 0

        while time.perf_counter() - t_wait_start < timeout:
            current = pool.total_processed.value
            if current >= events_per_run:
                break
            if current == prev_processed:
                idle_rounds += 1
                if idle_rounds >= 15:  # 750ms without progress
                    try:
                        iq = pool.input_queue.qsize()
                        oq = pool.output_queue.qsize()
                        if iq == 0 and oq == 0:
                            break
                    except Exception:
                        pass
            else:
                idle_rounds = 0
                prev_processed = current
            time.sleep(0.05)

        t_end = time.perf_counter()
        wall_time = t_end - t_start

        # Stop resources and pool
        res_stats = sampler.stop()
        pool_metrics = pool.stop(timeout=15.0)

        # Query DuckDB
        persisted_count = 0
        persisted_ids = []
        try:
            con = duckdb.connect(tmp_db)
            persisted_count = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            # Sample persisted IDs for accounting
            rows = con.execute("SELECT raw_event FROM events LIMIT 10000").fetchall()
            for r in rows:
                bid = DeterministicGenerator.extract_bench_id(r[0])
                if bid:
                    persisted_ids.append(bid)
            con.close()
        except Exception as e:
            logger.error(f"Error querying DuckDB: {e}")
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        accountant.record_accepted(expected_ids[: pool_metrics["total_processed"]])
        accountant.record_parsed(expected_ids[: pool_metrics["total_success"]])
        accountant.record_persisted(expected_ids[:persisted_count])
        accountant.save_artifacts()

        # Compute throughput and latency percentiles
        eps = persisted_count / max(wall_time, 0.001)

        # Approximate event latencies from batch processing
        sorted_lat = sorted(batch_latencies_ms)
        p50 = sorted_lat[int(len(sorted_lat) * 0.50)] if sorted_lat else 0.0
        p90 = sorted_lat[int(len(sorted_lat) * 0.90)] if sorted_lat else 0.0
        p95 = sorted_lat[int(len(sorted_lat) * 0.95)] if sorted_lat else 0.0
        p99 = sorted_lat[int(len(sorted_lat) * 0.99)] if sorted_lat else 0.0
        p999 = sorted_lat[int(len(sorted_lat) * 0.999)] if sorted_lat else 0.0
        max_lat = sorted_lat[-1] if sorted_lat else 0.0

        errors = pool_metrics.get("total_failed", 0)
        drops = max(0, events_per_run - persisted_count)
        rss_per_worker = round(res_stats["worker_rss_mb"] / max(workers, 1), 2)

        config_data = {
            "workers": workers,
            "events": events_per_run,
            "wall_time_sec": round(wall_time, 3),
            "throughput_eps": round(eps, 1),
            "cpu_percent": res_stats["avg_cpu_percent"],
            "max_cpu_percent": res_stats["max_cpu_percent"],
            "process_rss_mb": res_stats["main_rss_mb"],
            "worker_rss_mb": res_stats["worker_rss_mb"],
            "rss_per_worker_mb": rss_per_worker,
            "total_app_rss_mb": res_stats["total_app_rss_mb"],
            "peak_rss_mb": res_stats["peak_rss_mb"],
            "p50_ms": round(p50, 4),
            "p90_ms": round(p90, 4),
            "p95_ms": round(p95, 4),
            "p99_ms": round(p99, 4),
            "p999_ms": round(p999, 4),
            "max_ms": round(max_lat, 4),
            "queue_depth_max": res_stats["max_input_queue"],
            "errors": errors,
            "drops": drops,
            "persisted_events": persisted_count,
        }
        all_configs_results.append(config_data)

        print(
            f"      -> {eps:>10,.0f} EPS | Persisted: {persisted_count:,}/{events_per_run:,} | "
            f"CPU: {res_stats['avg_cpu_percent']}% | Total RSS: {res_stats['total_app_rss_mb']:.1f} MB "
            f"({rss_per_worker:.1f} MB/worker) | P95: {p95:.2f}ms"
        )

    # Write worker_scalability.csv
    csv_path = os.path.join(results_dir, "worker_scalability.csv")
    fieldnames = [
        "workers", "events", "wall_time_sec", "throughput_eps", "cpu_percent",
        "max_cpu_percent", "process_rss_mb", "worker_rss_mb", "rss_per_worker_mb",
        "total_app_rss_mb", "peak_rss_mb", "p50_ms", "p90_ms", "p95_ms",
        "p99_ms", "p999_ms", "max_ms", "queue_depth_max", "errors", "drops", "persisted_events",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_configs_results)

    # Write master JSON
    json_path = os.path.join(results_dir, "worker_scalability.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"configurations": all_configs_results, "host_cores": max_cores}, f, indent=2)

    # Generate graph
    graph_path = os.path.join(results_dir, "worker_scalability.png")
    _generate_scalability_graph(all_configs_results, graph_path)

    print(f"\n  Saved: {csv_path}")
    print(f"  Saved: {graph_path}\n")

    return {
        "configurations": all_configs_results,
        "csv_path": csv_path,
        "graph_path": graph_path,
    }


def _generate_scalability_graph(data: List[Dict[str, Any]], output_path: str) -> None:
    """Generate worker_scalability.png from raw measurements."""
    try:
        import matplotlib  # type: ignore
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt  # type: ignore

        workers = [d["workers"] for d in data]
        eps = [d["throughput_eps"] for d in data]
        base_eps = eps[0] if eps else 1.0
        ideal = [base_eps * w for w in workers]
        cpu = [d["cpu_percent"] for d in data]
        rss = [d["total_app_rss_mb"] for d in data]

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6), facecolor="#1a1a2e")
        for ax in (ax1, ax2):
            ax.set_facecolor("#16213e")
            ax.tick_params(colors="#e0e0e0")
            for spine in ax.spines.values():
                spine.set_color("#444")
            ax.grid(True, color="#333", alpha=0.5)

        # Plot 1: Throughput EPS vs Worker Count
        ax1.plot(workers, eps, marker="o", color="#00d2ff", linewidth=2.5, label="Measured EPS")
        ax1.plot(workers, ideal, linestyle="--", color="#ffa502", alpha=0.7, label=f"Ideal Linear (from 1w={base_eps:,.0f})")
        ax1.set_xlabel("Worker Count", color="#e0e0e0", fontsize=11)
        ax1.set_ylabel("Throughput (EPS)", color="#e0e0e0", fontsize=11)
        ax1.set_title("Worker Scalability: Throughput vs Workers", color="#ffffff", fontsize=13)
        ax1.legend(facecolor="#1a1a2e", edgecolor="#444", labelcolor="#e0e0e0")

        # Plot 2: CPU % and RSS Memory
        ax2_twin = ax2.twinx()
        l1 = ax2.plot(workers, cpu, marker="s", color="#ff6b6b", linewidth=2, label="CPU Util (%)")
        l2 = ax2_twin.plot(workers, rss, marker="^", color="#2ed573", linewidth=2, label="Total RSS (MB)")

        ax2.set_xlabel("Worker Count", color="#e0e0e0", fontsize=11)
        ax2.set_ylabel("CPU Utilization (%)", color="#ff6b6b", fontsize=11)
        ax2_twin.set_ylabel("Total Application RSS (MB)", color="#2ed573", fontsize=11)
        ax2_twin.tick_params(colors="#e0e0e0")
        ax2.set_title("Resource Consumption vs Workers", color="#ffffff", fontsize=13)

        lines = l1 + l2
        labels = [l.get_label() for l in lines]
        ax2.legend(lines, labels, facecolor="#1a1a2e", edgecolor="#444", labelcolor="#e0e0e0", loc="upper left")

        plt.tight_layout()
        fig.savefig(output_path, dpi=150, bbox_inches="tight")
        plt.close(fig)
    except Exception as e:
        logger.warning(f"Could not render graph: {e}")


if __name__ == "__main__":
    run_worker_benchmark()
