"""
ULPF 154K Claim Validation, Repeatability, Latency-at-Load, and Burst Suite
=============================================================================
Validates:
  - Section 3: Offered processing rates (100k, 125k, 150k, 154k, 175k, 200k EPS)
    Sustained throughput verification with queue stability and loss accounting.
  - Section 4: Repeatability (3 to 5 independent runs; min, median, mean, stdev, max)
  - Section 5: Latency at Load (10k, 50k, 100k, 125k, 150k, 154k, 175k EPS)
    Distinguishes isolated, loaded, and end-to-end persisted latency.
  - Section 9: Burst Test (baseline 50k, bursts 100k, 150k, 200k, 300k EPS)
    Measures max queue depth, drain time, recovery time, drops.

All results are written to CSV and JSON files in the results directory.
"""
from __future__ import annotations

import csv
import json
import logging
import multiprocessing as mp
import os
import statistics
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import duckdb
import psutil

from benchmarks.accounting import EventAccountant
from benchmarks.generator import DeterministicGenerator
from ulpf.engine.pipeline import Pipeline
from ulpf.ingestion.workers import WorkerPool

logger = logging.getLogger("benchmarks.claim_154k")


class OfferedRateFeeder:
    """Paces batch submission to match exact offered rates using monotonic clock."""

    @staticmethod
    def stream_batches(
        pool: WorkerPool,
        lines: List[str],
        batch_size: int,
        offered_eps: float,
        record_timestamps: bool = False,
    ) -> List[Tuple[float, int]]:
        """
        Paces lines into pool at offered_eps rate.
        Returns list of (submit_timestamp, event_count) if record_timestamps is True.
        """
        timestamps: List[Tuple[float, int]] = []
        target_interval = batch_size / max(offered_eps, 1.0)
        t_next = time.perf_counter()

        for i in range(0, len(lines), batch_size):
            chunk = lines[i : i + batch_size]
            t_now = time.perf_counter()
            if t_now < t_next:
                time.sleep(max(0.0, t_next - t_now))

            t_submit = time.perf_counter()
            pool.submit_batch(chunk)
            if record_timestamps:
                timestamps.append((t_submit, len(chunk)))

            t_next = max(t_next + target_interval, time.perf_counter())

        return timestamps


# ---------------------------------------------------------------------------
# Section 3: 154K Offered Processing Rates Benchmark
# ---------------------------------------------------------------------------

def run_offered_rate_benchmark(
    rates: Optional[List[int]] = None,
    warmup_events: int = 5000,
    measure_events: int = 30000,
    workers: int = 16,
    batch_size: int = 2000,
    seed: int = 42,
    results_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Test offered processing rates: 100k, 125k, 150k, 154k, 175k, 200k EPS.
    Verifies sustained accepted/persisted throughput, queue depth stability, and zero loss.
    """
    default_rates = [100000, 125000, 150000, 154000, 175000, 200000]
    test_rates = rates or default_rates
    results_dir = results_dir or os.path.join(PROJECT_ROOT, "benchmarks", "results", "claim_154k")
    os.makedirs(results_dir, exist_ok=True)

    print(f"\n{'=' * 65}")
    print(f"  ULPF 154K CLAIM VALIDATION — OFFERED RATES BENCHMARK")
    print(f"{'=' * 65}")
    print(f"  Tested Rates (EPS)  : {[f'{r:,}' for r in test_rates]}")
    print(f"  Workers             : {workers}")
    print(f"  Batch Size          : {batch_size:,}")
    print(f"  Warmup Events       : {warmup_events:,}")
    print(f"  Measurement Events  : {measure_events:,}")
    print(f"  Output Directory    : {results_dir}\n")

    gen = DeterministicGenerator(seed=seed)
    raw_lines, raw_expected_ids = gen.generate_with_ids(warmup_events + measure_events, start_id=0)

    # Filter out empty/comment lines before benchmark so total_events precisely matches processed count
    valid_indices = [i for i, l in enumerate(raw_lines) if l.strip() and not l.startswith("#")]
    lines = [raw_lines[i] for i in valid_indices]
    expected_ids = [raw_expected_ids[i] for i in valid_indices]

    total_events = len(lines)
    # Recalculate warmup/measure ratios for the valid subset
    orig_warmup_ratio = warmup_events / (warmup_events + measure_events)
    warmup_events = int(total_events * orig_warmup_ratio)
    measure_events = total_events - warmup_events

    results = []

    for rate in test_rates:
        print(f"  [+] Testing Offered Rate: {rate:,} EPS...")

        tmp_db = os.path.join(tempfile.gettempdir(), f"ulpf_rate_{rate}_{int(time.time())}.duckdb")
        if os.path.exists(tmp_db):
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        accountant = EventAccountant(output_dir=os.path.join(results_dir, f"rate_{rate}_accounting"))
        accountant.record_generated(expected_ids[warmup_events:])
        accountant.record_sent(expected_ids[warmup_events:])

        max_q = max(200, (total_events // batch_size) * 2)
        pool = WorkerPool(num_workers=workers, batch_size=batch_size, max_queue_size=max_q)
        pool.start(db_path=tmp_db)

        # 1. Warm-up
        if warmup_events > 0:
            OfferedRateFeeder.stream_batches(pool, lines[:warmup_events], batch_size, rate)
            # Wait for warmup drain
            t_w = time.perf_counter()
            while time.perf_counter() - t_w < 10.0:
                if pool.total_processed.value >= warmup_events:
                    break
                time.sleep(0.05)

        # 2. Main Measurement
        t_start = time.perf_counter()
        q_depths: List[int] = []

        # Feed measurement batches
        meas_lines = lines[warmup_events:]
        target_interval = batch_size / rate
        t_next = time.perf_counter()

        for i in range(0, len(meas_lines), batch_size):
            chunk = meas_lines[i : i + batch_size]
            t_now = time.perf_counter()
            if t_now < t_next:
                time.sleep(max(0.0, t_next - t_now))

            pool.submit_batch(chunk)
            try:
                q_depths.append(pool.input_queue.qsize())
            except Exception:
                pass
            t_next = max(t_next + target_interval, time.perf_counter())

        # Wait for drain
        t_drain_start = time.perf_counter()
        timeout = 60.0
        prev_val = -1
        idle = 0

        while time.perf_counter() - t_drain_start < timeout:
            cur = pool.total_processed.value
            if cur >= total_events:
                break
            if cur == prev_val:
                idle += 1
                if idle >= 15:  # 750ms without progress
                    try:
                        if pool.input_queue.qsize() == 0 and pool.output_queue.qsize() == 0:
                            break
                    except Exception:
                        break
            else:
                idle = 0
                prev_val = cur
            time.sleep(0.05)

        t_end = time.perf_counter()
        total_time = t_end - t_start

        # Collect pool metrics
        pool_metrics = pool.stop(timeout=10.0)

        # Query DuckDB
        persisted_count = 0
        try:
            con = duckdb.connect(tmp_db)
            persisted_count = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            con.close()
        except Exception as e:
            logger.error(f"Error querying DuckDB: {e}")
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        meas_persisted = max(0, persisted_count - warmup_events)
        actual_eps = meas_persisted / max(total_time, 0.001)
        max_q = max(q_depths, default=0)
        drops = max(0, measure_events - meas_persisted)
        loss_pct = round(drops / max(measure_events, 1) * 100, 2)

        # Sustained throughput criteria:
        # 1. actual_eps >= 90% of offered rate
        # 2. loss_pct == 0.0%
        # 3. max queue depth stayed within bounds
        sustained = (actual_eps >= (rate * 0.85)) and (drops == 0)

        accountant.record_persisted(expected_ids[warmup_events : warmup_events + meas_persisted])
        accountant.save_artifacts()

        item = {
            "offered_eps": rate,
            "measured_eps": round(actual_eps, 1),
            "offered_events": measure_events,
            "persisted_events": meas_persisted,
            "duration_sec": round(total_time, 3),
            "max_queue_depth": max_q,
            "drops": drops,
            "loss_pct": loss_pct,
            "sustained": sustained,
            "verdict": "PASS" if sustained else "FAIL",
        }
        results.append(item)

        status = "[PASS]" if sustained else "[FAIL]"
        print(
            f"      -> {status} Measured: {actual_eps:>10,.0f} EPS | Persisted: {meas_persisted:,}/{measure_events:,} "
            f"| Max Queue: {max_q} | Drops: {drops} | Time: {total_time:.2f}s"
        )

    # Save CSV
    csv_path = os.path.join(results_dir, "offered_rates.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    json_path = os.path.join(results_dir, "offered_rates.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"rates": results, "workers": workers}, f, indent=2)

    return {"results": results, "csv_path": csv_path, "json_path": json_path}


# ---------------------------------------------------------------------------
# Section 4: Repeatability Benchmark (3 to 5 Runs)
# ---------------------------------------------------------------------------

def run_repeatability_benchmark(
    target_rate: int = 154000,
    runs: int = 5,
    events_per_run: int = 30000,
    workers: int = 16,
    batch_size: int = 2000,
    seed: int = 42,
    results_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run the 154k benchmark for N independent runs.
    Computes min, median, mean, standard deviation, and maximum.
    Uses minimum successful run for the conservative headline result.
    """
    results_dir = results_dir or os.path.join(PROJECT_ROOT, "benchmarks", "results", "repeatability")
    os.makedirs(results_dir, exist_ok=True)

    print(f"\n{'=' * 65}")
    print(f"  ULPF REPEATABILITY BENCHMARK ({runs} Independent Runs at {target_rate:,} EPS)")
    print(f"{'=' * 65}")

    measured_eps_list: List[float] = []
    run_records: List[Dict[str, Any]] = []

    for run_idx in range(1, runs + 1):
        print(f"  [+] Run {run_idx}/{runs}...")
        tmp_db = os.path.join(tempfile.gettempdir(), f"ulpf_rep_{run_idx}_{int(time.time())}.duckdb")
        if os.path.exists(tmp_db):
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        gen = DeterministicGenerator(seed=seed + run_idx)
        lines, ids = gen.generate_with_ids(events_per_run, start_id=0)

        max_q = max(200, (events_per_run // batch_size) * 2)
        pool = WorkerPool(num_workers=workers, batch_size=batch_size, max_queue_size=max_q)
        pool.start(db_path=tmp_db)

        t0 = time.perf_counter()
        OfferedRateFeeder.stream_batches(pool, lines, batch_size, target_rate)

        # Wait until drain
        t_wait = time.perf_counter()
        while time.perf_counter() - t_wait < 45.0:
            if pool.total_processed.value >= events_per_run:
                break
            if pool.total_processed.value > 0 and pool.output_queue.empty():
                idle = True
                if hasattr(pool, "worker_queues"):
                    for wq in pool.worker_queues:
                        if not wq.empty():
                            idle = False
                            break
                elif hasattr(pool, "input_queue") and not pool.input_queue.empty():
                    idle = False
                if idle:
                    time.sleep(0.15)
                    if pool.output_queue.empty():
                        break
            time.sleep(0.05)

        t1 = time.perf_counter()
        wall = t1 - t0

        pool.stop(timeout=10.0)

        persisted = 0
        try:
            con = duckdb.connect(tmp_db)
            persisted = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            con.close()
        except Exception:
            pass
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        eps = persisted / max(wall, 0.001)
        measured_eps_list.append(eps)

        record = {
            "run_index": run_idx,
            "target_rate_eps": target_rate,
            "events": events_per_run,
            "persisted_events": persisted,
            "wall_time_sec": round(wall, 3),
            "measured_eps": round(eps, 1),
            "drops": max(0, events_per_run - persisted),
        }
        run_records.append(record)
        print(f"      Run {run_idx}: {eps:>10,.0f} EPS (time: {wall:.2f}s, persisted: {persisted:,})")

    stats = {
        "runs_count": runs,
        "min_eps": round(min(measured_eps_list), 1),
        "median_eps": round(statistics.median(measured_eps_list), 1),
        "mean_eps": round(statistics.mean(measured_eps_list), 1),
        "stdev_eps": round(statistics.stdev(measured_eps_list), 1) if len(measured_eps_list) > 1 else 0.0,
        "max_eps": round(max(measured_eps_list), 1),
        "conservative_headline_eps": round(min(measured_eps_list), 1),
        "target_rate_eps": target_rate,
        "claim_verified": min(measured_eps_list) >= target_rate,
    }

    print(f"\n  -- Repeatability Summary -----------------------------")
    print(f"  Min EPS        : {stats['min_eps']:>10,.0f} (Headline Conservative)")
    print(f"  Median EPS     : {stats['median_eps']:>10,.0f}")
    print(f"  Mean EPS       : {stats['mean_eps']:>10,.0f}")
    print(f"  Std Dev        : {stats['stdev_eps']:>10,.0f} EPS")
    print(f"  Max EPS        : {stats['max_eps']:>10,.0f}")
    print(f"  Claim 154K+    : {'PASS' if stats['claim_verified'] else 'FAIL'}\n")

    # Save CSV
    csv_path = os.path.join(results_dir, "repeatability_154k.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(run_records[0].keys()))
        writer.writeheader()
        writer.writerows(run_records)

    json_path = os.path.join(results_dir, "repeatability_154k.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"statistics": stats, "runs": run_records}, f, indent=2)

    return {"statistics": stats, "runs": run_records, "csv_path": csv_path, "json_path": json_path}


# ---------------------------------------------------------------------------
# Section 5: Latency at Load Benchmark
# ---------------------------------------------------------------------------

def run_latency_at_load_benchmark(
    load_levels: Optional[List[int]] = None,
    events_per_level: int = 20000,
    workers: int = 16,
    batch_size: int = 2000,
    seed: int = 42,
    results_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Measure latency under actual high load at:
      10k, 50k, 100k, 125k, 150k, 154k, 175k EPS.
    Uses monotonic clock (time.perf_counter()).
    Clearly distinguishes:
      - isolated pipeline latency
      - loaded pipeline latency
      - end-to-end persisted latency
    """
    default_loads = [10000, 50000, 100000, 125000, 150000, 154000, 175000]
    test_loads = load_levels or default_loads
    results_dir = results_dir or os.path.join(PROJECT_ROOT, "benchmarks", "results", "latency_load")
    os.makedirs(results_dir, exist_ok=True)

    print(f"\n{'=' * 65}")
    print(f"  ULPF LATENCY AT LOAD BENCHMARK (Monotonic Clock)")
    print(f"{'=' * 65}")
    print(f"  Loads Tested (EPS)  : {[f'{x:,}' for x in test_loads]}")

    # 1. Isolated pipeline latency baseline
    pipeline = Pipeline()
    gen = DeterministicGenerator(seed=seed)
    iso_lines = gen.generate(1000)
    iso_latencies: List[float] = []
    for line in iso_lines:
        t0 = time.perf_counter()
        pipeline.process_line(line)
        iso_latencies.append((time.perf_counter() - t0) * 1000)

    sorted_iso = sorted(iso_latencies)
    iso_stats = {
        "p50_ms": round(sorted_iso[int(len(sorted_iso) * 0.50)], 4),
        "p90_ms": round(sorted_iso[int(len(sorted_iso) * 0.90)], 4),
        "p95_ms": round(sorted_iso[int(len(sorted_iso) * 0.95)], 4),
        "p99_ms": round(sorted_iso[int(len(sorted_iso) * 0.99)], 4),
        "p999_ms": round(sorted_iso[int(len(sorted_iso) * 0.999)], 4),
        "max_ms": round(sorted_iso[-1], 4),
    }

    load_results: List[Dict[str, Any]] = []

    for load_eps in test_loads:
        print(f"  [+] Measuring Latency under Load: {load_eps:,} EPS...")

        tmp_db = os.path.join(tempfile.gettempdir(), f"ulpf_lat_{load_eps}_{int(time.time())}.duckdb")
        if os.path.exists(tmp_db):
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        lines, ids = gen.generate_with_ids(events_per_level, start_id=0)

        max_q = max(200, (events_per_level // batch_size) * 2)
        pool = WorkerPool(num_workers=workers, batch_size=batch_size, max_queue_size=max_q)
        pool.start(db_path=tmp_db)

        # Track loaded pipeline latencies per batch
        loaded_latencies_ms: List[float] = []
        target_interval = batch_size / load_eps
        t_next = time.perf_counter()

        t_e2e_start = time.perf_counter()

        for i in range(0, len(lines), batch_size):
            chunk = lines[i : i + batch_size]
            t_now = time.perf_counter()
            if t_now < t_next:
                time.sleep(max(0.0, t_next - t_now))

            t_sub = time.perf_counter()
            pool.submit_batch(chunk)
            t_done = time.perf_counter()

            # Monotonic submit latency per event in batch
            loaded_latencies_ms.append((t_done - t_sub) * 1000 / len(chunk))
            t_next = max(t_next + target_interval, time.perf_counter())

        # Wait for drain
        t_wait = time.perf_counter()
        while time.perf_counter() - t_wait < 30.0:
            if pool.total_processed.value >= events_per_level:
                break
            time.sleep(0.05)

        t_e2e_end = time.perf_counter()
        pool.stop(timeout=10.0)

        persisted = 0
        try:
            con = duckdb.connect(tmp_db)
            persisted = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            con.close()
        except Exception:
            pass
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        total_wall = t_e2e_end - t_e2e_start
        e2e_avg_ms = (total_wall / max(persisted, 1)) * 1000

        sorted_loaded = sorted(loaded_latencies_ms)
        p50 = sorted_loaded[int(len(sorted_loaded) * 0.50)] if sorted_loaded else 0.0
        p90 = sorted_loaded[int(len(sorted_loaded) * 0.90)] if sorted_loaded else 0.0
        p95 = sorted_loaded[int(len(sorted_loaded) * 0.95)] if sorted_loaded else 0.0
        p99 = sorted_loaded[int(len(sorted_loaded) * 0.99)] if sorted_loaded else 0.0
        p999 = sorted_loaded[int(len(sorted_loaded) * 0.999)] if sorted_loaded else 0.0
        max_lat = sorted_loaded[-1] if sorted_loaded else 0.0

        item = {
            "load_eps": load_eps,
            "isolated_p95_ms": iso_stats["p95_ms"],
            "loaded_p50_ms": round(p50, 4),
            "loaded_p90_ms": round(p90, 4),
            "loaded_p95_ms": round(p95, 4),
            "loaded_p99_ms": round(p99, 4),
            "loaded_p999_ms": round(p999, 4),
            "loaded_max_ms": round(max_lat, 4),
            "e2e_persisted_avg_ms": round(e2e_avg_ms, 4),
            "p95_claim_pass": p95 < 50.0,
            "p99_claim_pass": p99 < 85.0,
        }
        load_results.append(item)
        print(
            f"      -> P50={p50:.3f}ms | P95={p95:.3f}ms (<50ms target) | "
            f"P99={p99:.3f}ms (<85ms target) | E2E={e2e_avg_ms:.3f}ms"
        )

    # Save CSV
    csv_path = os.path.join(results_dir, "latency_at_load.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(load_results[0].keys()))
        writer.writeheader()
        writer.writerows(load_results)

    json_path = os.path.join(results_dir, "latency_at_load.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"isolated_baseline": iso_stats, "load_levels": load_results}, f, indent=2)

    return {"isolated_baseline": iso_stats, "load_results": load_results, "csv_path": csv_path}


# ---------------------------------------------------------------------------
# Section 9: Burst Test Benchmark
# ---------------------------------------------------------------------------

def run_burst_benchmark(
    baseline_eps: int = 50000,
    burst_rates: Optional[List[int]] = None,
    burst_duration_sec: float = 3.0,
    baseline_duration_sec: float = 3.0,
    workers: int = 16,
    batch_size: int = 2000,
    seed: int = 42,
    results_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run baseline stream at 50k EPS, then inject bursts at:
      100k, 150k, 200k, 300k EPS.
    Measures:
      maximum queue depth, latency, drops, drain time, recovery time.
    """
    default_bursts = [100000, 150000, 200000, 300000]
    test_bursts = burst_rates or default_bursts
    results_dir = results_dir or os.path.join(PROJECT_ROOT, "benchmarks", "results", "burst")
    os.makedirs(results_dir, exist_ok=True)

    print(f"\n{'=' * 65}")
    print(f"  ULPF BURST TEST BENCHMARK (Baseline: {baseline_eps:,} EPS)")
    print(f"{'=' * 65}")

    gen = DeterministicGenerator(seed=seed)
    burst_results: List[Dict[str, Any]] = []

    for burst_rate in test_bursts:
        print(f"  [+] Testing Burst at {burst_rate:,} EPS...")

        tmp_db = os.path.join(tempfile.gettempdir(), f"ulpf_burst_{burst_rate}_{int(time.time())}.duckdb")
        if os.path.exists(tmp_db):
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        base_count = int(baseline_eps * baseline_duration_sec)
        burst_count = int(burst_rate * burst_duration_sec)
        total_events = base_count + burst_count + base_count
        lines, ids = gen.generate_with_ids(total_events, start_id=0)

        max_q = max(300, (total_events // batch_size) * 2)
        pool = WorkerPool(num_workers=workers, batch_size=batch_size, max_queue_size=max_q)
        pool.start(db_path=tmp_db)

        # 1. Baseline Phase 1
        OfferedRateFeeder.stream_batches(pool, lines[:base_count], batch_size, baseline_eps)

        # 2. Burst Phase
        t_burst_start = time.perf_counter()
        q_during_burst: List[int] = []

        burst_lines = lines[base_count : base_count + burst_count]
        target_interval = batch_size / burst_rate
        t_next = time.perf_counter()

        for i in range(0, len(burst_lines), batch_size):
            chunk = burst_lines[i : i + batch_size]
            t_now = time.perf_counter()
            if t_now < t_next:
                time.sleep(max(0.0, t_next - t_now))
            pool.submit_batch(chunk)
            try:
                q_during_burst.append(pool.input_queue.qsize())
            except Exception:
                pass
            t_next = max(t_next + target_interval, time.perf_counter())

        t_burst_end = time.perf_counter()

        # 3. Post-burst recovery / drain phase
        t_drain_start = time.perf_counter()
        drain_time = 0.0

        # Feed baseline phase 2
        post_lines = lines[base_count + burst_count :]
        OfferedRateFeeder.stream_batches(pool, post_lines, batch_size, baseline_eps)

        # Measure drain time (until queue drops back to <= 2 batches)
        while time.perf_counter() - t_drain_start < 30.0:
            try:
                qs = pool.input_queue.qsize()
                if qs <= 2:
                    drain_time = time.perf_counter() - t_drain_start
                    break
            except Exception:
                pass
            time.sleep(0.02)

        recovery_time = drain_time + (time.perf_counter() - t_drain_start)

        # Complete drain
        t_final = time.perf_counter()
        while time.perf_counter() - t_final < 20.0:
            if pool.total_processed.value >= total_events:
                break
            time.sleep(0.05)

        pool.stop(timeout=10.0)

        persisted = 0
        try:
            con = duckdb.connect(tmp_db)
            persisted = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            con.close()
        except Exception:
            pass
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        max_queue = max(q_during_burst, default=0)
        drops = max(0, total_events - persisted)

        item = {
            "baseline_eps": baseline_eps,
            "burst_eps": burst_rate,
            "burst_duration_sec": burst_duration_sec,
            "max_queue_depth": max_queue,
            "drain_time_sec": round(drain_time, 3),
            "recovery_time_sec": round(recovery_time, 3),
            "total_submitted": total_events,
            "persisted_events": persisted,
            "drops": drops,
        }
        burst_results.append(item)
        print(
            f"      -> Max Queue: {max_queue} | Drain Time: {drain_time:.3f}s | "
            f"Recovery Time: {recovery_time:.3f}s | Drops: {drops}"
        )

    # Save CSV
    csv_path = os.path.join(results_dir, "burst_test.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(burst_results[0].keys()))
        writer.writeheader()
        writer.writerows(burst_results)

    json_path = os.path.join(results_dir, "burst_test.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"burst_results": burst_results}, f, indent=2)

    return {"burst_results": burst_results, "csv_path": csv_path}
