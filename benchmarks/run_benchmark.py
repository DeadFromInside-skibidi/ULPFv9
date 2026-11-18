#!/usr/bin/env python3
"""
ULPF Benchmark Laboratory — CLI Runner
==========================================

Usage:
    python benchmarks/run_benchmark.py                          # Full comprehensive laboratory
    python benchmarks/run_benchmark.py --mode multiworker       # Multi-worker scalability (1, 2, 4, 8, 12, 16)
    python benchmarks/run_benchmark.py --mode claim154k         # 154k offered rates benchmark
    python benchmarks/run_benchmark.py --mode repeatability     # 154k repeatability benchmark (3-5 runs)
    python benchmarks/run_benchmark.py --mode latency           # Latency percentiles under load
    python benchmarks/run_benchmark.py --mode burst             # Burst test & recovery
    python benchmarks/run_benchmark.py --mode live_udp          # Live UDP benchmark
    python benchmarks/run_benchmark.py --mode live_tcp          # Live TCP concurrency benchmark
    python benchmarks/run_benchmark.py --mode memory            # Process-level RSS validation
    python benchmarks/run_benchmark.py --mode soak              # Soak stability test
    python benchmarks/run_benchmark.py --mode integrity         # Sections 12-17 Security & Integrity suite
    python benchmarks/run_benchmark.py --mode pipeline          # Isolated pipeline only
    python benchmarks/run_benchmark.py --mode full              # Full comprehensive suite
    python benchmarks/run_benchmark.py --report results_dir     # Generate reports from existing results
    python benchmarks/run_benchmark.py --graphs results_dir     # Generate graphs from existing results
"""
from __future__ import annotations

import argparse
import os
import sys

# Ensure project root is on path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def main():
    parser = argparse.ArgumentParser(
        prog="ulpf-benchmark",
        description="ULPF Benchmark Validation Laboratory — Reproducible Performance & Integrity",
    )
    parser.add_argument(
        "--events", "-n", type=int, default=10000,
        help="Number of synthetic events to generate (default: 10000)"
    )
    parser.add_argument(
        "--mode", "-m",
        choices=[
            "pipeline", "database", "formats", "scalability", "multiworker",
            "claim154k", "repeatability", "latency", "burst",
            "live", "live_udp", "live_tcp", "memory", "soak", "integrity", "full"
        ],
        default="full",
        help="Benchmark mode to run (default: full)"
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducibility (default: 42)"
    )
    parser.add_argument(
        "--workers", "-w", type=int, default=8,
        help="Number of worker processes for pipeline / tests (default: 8)"
    )
    parser.add_argument(
        "--worker-counts", nargs="+", type=int, default=[1, 2, 4, 8, 12, 16],
        help="Worker counts for multiworker scalability test"
    )
    parser.add_argument(
        "--runs", type=int, default=5,
        help="Number of independent runs for repeatability test (default: 5)"
    )
    parser.add_argument(
        "--rates", nargs="+", type=int,
        default=[100000, 125000, 150000, 154000, 175000, 200000],
        help="Offered rates in EPS for 154k claim test"
    )
    parser.add_argument(
        "--soak-duration", type=float, default=30.0,
        help="Duration in seconds for soak test (default: 30.0; up to 21600 for 6 hours)"
    )
    parser.add_argument(
        "--output-dir", "-o",
        help="Output directory for results (default: benchmarks/results/<timestamp>)"
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Target host for live benchmark (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", "-p", type=int, default=5514,
        help="Target port for live benchmark (default: 5514)"
    )
    parser.add_argument(
        "--proto", choices=["udp", "tcp"], default="udp",
        help="Protocol for live benchmark (default: udp)"
    )
    parser.add_argument(
        "--sweep-sizes", nargs="+", type=int,
        default=[1000, 5000, 10000, 50000, 100000],
        help="Event counts for scalability sweep"
    )
    parser.add_argument(
        "--report", metavar="RESULTS_DIR",
        help="Generate markdown, HTML, DOCX, and PDF reports from existing results directory"
    )
    parser.add_argument(
        "--graphs", metavar="RESULTS_DIR",
        help="Generate graphs from existing results directory"
    )
    parser.add_argument(
        "--no-graphs", action="store_true",
        help="Skip graph generation after benchmark"
    )

    args = parser.parse_args()

    # Report-only mode
    if args.report:
        from benchmarks.report import generate_all_reports
        reports = generate_all_reports(args.report)
        print("Reports generated:")
        for fmt, path in reports.items():
            print(f"  {fmt.upper():8s}: {path}")
        return

    # Graph-only mode
    if args.graphs:
        from benchmarks.graphs import generate_graphs
        generated = generate_graphs(args.graphs)
        print(f"Generated {len(generated)} graph(s)")
        return

    # Run benchmark
    from benchmarks.suite import BenchmarkRunner

    runner = BenchmarkRunner(
        num_events=args.events,
        seed=args.seed,
        results_dir=args.output_dir,
    )

    if args.mode == "pipeline":
        result = runner.run_pipeline_benchmark(num_workers=args.workers)
        runner.validate_claims(result)

    elif args.mode == "database":
        runner.run_database_benchmark()

    elif args.mode == "formats":
        runner.run_format_benchmarks(events_per_format=args.events)

    elif args.mode == "scalability":
        runner.run_scalability_sweep(event_counts=args.sweep_sizes)

    elif args.mode == "multiworker":
        from benchmarks.multiworker import run_worker_benchmark
        run_worker_benchmark(
            worker_counts=args.worker_counts,
            events_per_run=args.events,
            seed=args.seed,
            results_dir=runner.results_dir,
        )

    elif args.mode == "claim154k":
        from benchmarks.claim_154k import run_offered_rate_benchmark
        run_offered_rate_benchmark(
            rates=args.rates,
            measure_events=args.events,
            workers=args.workers,
            seed=args.seed,
            results_dir=runner.results_dir,
        )

    elif args.mode == "repeatability":
        from benchmarks.claim_154k import run_repeatability_benchmark
        run_repeatability_benchmark(
            target_rate=154000,
            runs=args.runs,
            events_per_run=args.events,
            workers=args.workers,
            seed=args.seed,
            results_dir=runner.results_dir,
        )

    elif args.mode == "latency":
        from benchmarks.claim_154k import run_latency_at_load_benchmark
        run_latency_at_load_benchmark(
            events_per_level=min(args.events, 10000),
            workers=args.workers,
            seed=args.seed,
            results_dir=runner.results_dir,
        )

    elif args.mode == "burst":
        from benchmarks.claim_154k import run_burst_benchmark
        run_burst_benchmark(
            baseline_eps=50000,
            burst_rates=[100000, 150000, 200000, 300000],
            workers=args.workers,
            seed=args.seed,
            results_dir=runner.results_dir,
        )

    elif args.mode == "live":
        runner.run_live_benchmark(
            host=args.host, port=args.port, proto=args.proto
        )

    elif args.mode == "live_udp":
        from benchmarks.live_network import run_live_udp_benchmark
        run_live_udp_benchmark(
            host=args.host,
            port=args.port,
            workers=args.workers,
            seed=args.seed,
            results_dir=runner.results_dir,
        )

    elif args.mode == "live_tcp":
        from benchmarks.live_network import run_live_tcp_benchmark
        run_live_tcp_benchmark(
            host=args.host,
            port=args.port,
            workers=args.workers,
            seed=args.seed,
            results_dir=runner.results_dir,
        )

    elif args.mode == "memory":
        from benchmarks.soak import run_memory_validation
        run_memory_validation(
            workers=args.workers,
            test_events=args.events,
            results_dir=runner.results_dir,
        )

    elif args.mode == "soak":
        from benchmarks.soak import run_soak_test
        run_soak_test(
            duration_sec=args.soak_duration,
            target_eps=5000,
            workers=args.workers,
            results_dir=runner.results_dir,
        )

    elif args.mode == "integrity":
        from benchmarks.integrity_suite import IntegritySuiteRunner
        runner_integ = IntegritySuiteRunner(results_dir=runner.results_dir)
        runner_integ.run_all()

    elif args.mode == "full":
        runner.run_full_suite(comprehensive=True, soak_duration=args.soak_duration)

    # Generate graphs and reports
    if not args.no_graphs:
        try:
            from benchmarks.graphs import generate_graphs
            print("\n  Generating graphs...")
            graphs = generate_graphs(runner.results_dir)
            if graphs:
                print(f"  Generated {len(graphs)} graph(s)")
        except Exception as e:
            print(f"  [INFO] Graph generation skipped: {e}")

    try:
        from benchmarks.report import generate_all_reports
        reports = generate_all_reports(runner.results_dir)
        print("  Reports generated:")
        for fmt, path in reports.items():
            print(f"    {fmt.upper():8s}: {path}")
    except Exception as e:
        print(f"  [INFO] Report generation skipped: {e}")


if __name__ == "__main__":
    main()
