"""
ULPF Benchmark Graph Generator — Section 18 Automated Graphs
==============================================================
Generates all 17 automated performance graphs strictly from raw CSV/JSON measurements:
  1. throughput vs worker count (worker_scalability.png)
  2. throughput vs CPU (throughput_vs_cpu.png)
  3. throughput vs RSS (throughput_vs_rss.png)
  4. throughput vs latency (throughput_vs_latency.png)
  5. offered vs persisted EPS (offered_vs_persisted.png)
  6. P50/P90/P95/P99 latency under load (latency_percentiles_load.png)
  7. queue depth over time (queue_depth_time.png)
  8. memory over time (memory_over_time.png)
  9. CPU over time (cpu_over_time.png)
  10. UDP sent/received/persisted (udp_live_loss.png)
  11. TCP throughput vs clients (tcp_clients_throughput.png)
  12. burst/recovery (burst_recovery.png)
  13. soak test dashboard (soak_test.png)
  14. event accounting waterfall (event_accounting.png)
  15. database growth (database_growth.png)
  16. APG performance (apg_performance.png)
  17. drift detection (drift_detection.png)

Every graph is produced ONLY from actual measurement data files. No data is fabricated.
"""
from __future__ import annotations

import csv
import json
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger("benchmarks.graphs")


def _load_json(filepath: str) -> Optional[dict]:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _load_csv(filepath: str) -> List[Dict[str, Any]]:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return list(csv.DictReader(f))
    except Exception:
        return []


try:
    import matplotlib  # type: ignore
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt  # type: ignore
    HAS_MATPLOTLIB = True
except Exception:
    plt = None  # type: ignore
    HAS_MATPLOTLIB = False


def _try_matplotlib():
    """Return matplotlib.pyplot and availability boolean safely."""
    global plt, HAS_MATPLOTLIB
    if HAS_MATPLOTLIB and plt is not None:
        return plt, True
    try:
        import matplotlib  # type: ignore
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt  # type: ignore
        HAS_MATPLOTLIB = True
        return plt, True
    except Exception:
        return None, False


def _apply_theme(plt):
    plt.rcParams.update({
        "figure.facecolor": "#1a1a2e",
        "axes.facecolor": "#16213e",
        "axes.edgecolor": "#444444",
        "axes.labelcolor": "#e0e0e0",
        "xtick.color": "#e0e0e0",
        "ytick.color": "#e0e0e0",
        "text.color": "#e0e0e0",
        "font.size": 10,
        "axes.titlesize": 12,
        "axes.grid": True,
        "grid.color": "#333333",
        "grid.alpha": 0.5,
    })


def generate_graphs(results_dir: str) -> List[str]:
    """
    Generate all automated graphs from measurement files in results_dir.
    Searches both results_dir and its subdirectories.
    """
    plt, has_mpl = _try_matplotlib()
    generated = []

    if not has_mpl:
        logger.warning("matplotlib not installed — skipping graph generation.")
        return generated

    _apply_theme(plt)

    # Find file helper (check current dir and subdirs)
    def _find_file(filename: str) -> Optional[str]:
        p = os.path.join(results_dir, filename)
        if os.path.exists(p):
            return p
        for root, _, files in os.walk(results_dir):
            if filename in files:
                return os.path.join(root, filename)
        return None

    # ------------------------------------------------------------------
    # 1. worker_scalability.png (Throughput vs Worker Count)
    # 2. throughput_vs_cpu.png
    # 3. throughput_vs_rss.png
    # 4. throughput_vs_latency.png
    # ------------------------------------------------------------------
    ws_csv = _find_file("worker_scalability.csv")
    if ws_csv:
        rows = _load_csv(ws_csv)
        if rows:
            try:
                workers = [int(r["workers"]) for r in rows]
                eps = [float(r["throughput_eps"]) for r in rows]
                cpu = [float(r.get("cpu_percent", 0)) for r in rows]
                rss = [float(r.get("total_app_rss_mb", 0)) for r in rows]
                p95 = [float(r.get("p95_ms", 0)) for r in rows]
                p99 = [float(r.get("p99_ms", 0)) for r in rows]

                # 1. worker_scalability.png
                fig, ax = plt.subplots(figsize=(9, 5))
                base_eps = eps[0] if eps else 1.0
                ideal = [base_eps * w for w in workers]
                ax.plot(workers, eps, marker="o", color="#00d2ff", linewidth=2.5, label="Measured Throughput (EPS)")
                ax.plot(workers, ideal, linestyle="--", color="#ffa502", alpha=0.8, label=f"Ideal Linear (from 1w={base_eps:,.0f})")
                ax.set_xlabel("Worker Count")
                ax.set_ylabel("Throughput (EPS)")
                ax.set_title("Throughput vs Worker Count (ULPF WorkerPool)")
                ax.legend(facecolor="#1a1a2e", edgecolor="#444")
                out = os.path.join(results_dir, "worker_scalability.png")
                fig.savefig(out, dpi=150, bbox_inches="tight")
                plt.close(fig)
                generated.append(out)

                # 2. throughput_vs_cpu.png
                fig, ax = plt.subplots(figsize=(9, 5))
                ax.scatter(cpu, eps, color="#ff6b6b", s=70, zorder=3)
                ax.plot(cpu, eps, color="#ff6b6b", linestyle=":", alpha=0.7)
                for w, c, e in zip(workers, cpu, eps):
                    ax.annotate(f"{w}w", (c, e), textcoords="offset points", xytext=(0, 7), ha="center", color="#ffa502")
                ax.set_xlabel("CPU Utilization (%)")
                ax.set_ylabel("Throughput (EPS)")
                ax.set_title("Throughput vs CPU Utilization")
                out = os.path.join(results_dir, "throughput_vs_cpu.png")
                fig.savefig(out, dpi=150, bbox_inches="tight")
                plt.close(fig)
                generated.append(out)

                # 3. throughput_vs_rss.png
                fig, ax = plt.subplots(figsize=(9, 5))
                ax.plot(rss, eps, marker="^", color="#2ed573", linewidth=2)
                for w, r, e in zip(workers, rss, eps):
                    ax.annotate(f"{w}w ({r:.0f}MB)", (r, e), textcoords="offset points", xytext=(0, 7), ha="center", color="#00d2ff")
                ax.set_xlabel("Total Application RSS (MB)")
                ax.set_ylabel("Throughput (EPS)")
                ax.set_title("Throughput vs Process RSS Memory")
                out = os.path.join(results_dir, "throughput_vs_rss.png")
                fig.savefig(out, dpi=150, bbox_inches="tight")
                plt.close(fig)
                generated.append(out)

                # 4. throughput_vs_latency.png
                fig, ax = plt.subplots(figsize=(9, 5))
                ax.plot(eps, p95, marker="o", color="#ffa502", label="P95 Latency (ms)")
                ax.plot(eps, p99, marker="s", color="#ff4757", label="P99 Latency (ms)")
                ax.axhline(50.0, color="#2ed573", linestyle="--", alpha=0.6, label="P95 Target (50ms)")
                ax.axhline(85.0, color="#1e90ff", linestyle="--", alpha=0.6, label="P99 Target (85ms)")
                ax.set_xlabel("Throughput (EPS)")
                ax.set_ylabel("Latency (ms)")
                ax.set_title("Throughput vs Latency (P95 & P99)")
                ax.legend(facecolor="#1a1a2e", edgecolor="#444")
                out = os.path.join(results_dir, "throughput_vs_latency.png")
                fig.savefig(out, dpi=150, bbox_inches="tight")
                plt.close(fig)
                generated.append(out)
            except Exception as e:
                logger.error(f"Error rendering worker graphs: {e}")

    # ------------------------------------------------------------------
    # 5. offered_vs_persisted.png (Offered EPS vs Persisted EPS)
    # ------------------------------------------------------------------
    offered_csv = _find_file("offered_rates.csv")
    if offered_csv:
        rows = _load_csv(offered_csv)
        if rows:
            try:
                offered = [float(r["offered_eps"]) for r in rows]
                measured = [float(r["measured_eps"]) for r in rows]
                fig, ax = plt.subplots(figsize=(9, 5))
                ax.plot(offered, offered, linestyle="--", color="#a4b0be", label="Offered Rate (Ideal 1:1)")
                ax.plot(offered, measured, marker="o", color="#00d2ff", linewidth=2.5, label="Measured Persisted EPS")
                ax.set_xlabel("Offered Rate (EPS)")
                ax.set_ylabel("Persisted / Accepted Throughput (EPS)")
                ax.set_title("Offered vs Persisted Throughput (154K Claim Test)")
                ax.legend(facecolor="#1a1a2e", edgecolor="#444")
                out = os.path.join(results_dir, "offered_vs_persisted.png")
                fig.savefig(out, dpi=150, bbox_inches="tight")
                plt.close(fig)
                generated.append(out)
            except Exception as e:
                logger.error(f"Error rendering offered_vs_persisted: {e}")

    # ------------------------------------------------------------------
    # 6. latency_percentiles_load.png (P50/P90/P95/P99 latency under load)
    # ------------------------------------------------------------------
    lat_load_csv = _find_file("latency_at_load.csv")
    if lat_load_csv:
        rows = _load_csv(lat_load_csv)
        if rows:
            try:
                loads = [float(r["load_eps"]) for r in rows]
                p50 = [float(r["loaded_p50_ms"]) for r in rows]
                p90 = [float(r["loaded_p90_ms"]) for r in rows]
                p95 = [float(r["loaded_p95_ms"]) for r in rows]
                p99 = [float(r["loaded_p99_ms"]) for r in rows]

                fig, ax = plt.subplots(figsize=(10, 5))
                ax.plot(loads, p50, marker="o", color="#2ed573", label="P50 Latency")
                ax.plot(loads, p90, marker="^", color="#1e90ff", label="P90 Latency")
                ax.plot(loads, p95, marker="s", color="#ffa502", label="P95 Latency")
                ax.plot(loads, p99, marker="d", color="#ff4757", label="P99 Latency")
                ax.axhline(50.0, color="#ff7f50", linestyle="--", label="P95 Threshold (50ms)")
                ax.axhline(85.0, color="#ff4757", linestyle="--", label="P99 Threshold (85ms)")
                ax.set_xlabel("Offered Load (EPS)")
                ax.set_ylabel("Latency (ms)")
                ax.set_title("Latency Percentiles Under High Load")
                ax.legend(facecolor="#1a1a2e", edgecolor="#444")
                out = os.path.join(results_dir, "latency_percentiles_load.png")
                fig.savefig(out, dpi=150, bbox_inches="tight")
                plt.close(fig)
                generated.append(out)
            except Exception as e:
                logger.error(f"Error rendering latency_percentiles_load: {e}")

    # ------------------------------------------------------------------
    # 7. queue_depth_time.png
    # 8. memory_over_time.png
    # 9. cpu_over_time.png
    # 13. soak_test.png (Dashboard)
    # 15. database_growth.png
    # ------------------------------------------------------------------
    soak_csv = _find_file("soak_metrics.csv")
    if soak_csv:
        rows = _load_csv(soak_csv)
        if rows:
            try:
                times = [float(r["elapsed_sec"]) for r in rows]
                q_depth = [int(r.get("queue_depth", 0)) for r in rows]
                total_rss = [float(r.get("total_rss_mb", 0)) for r in rows]
                main_rss = [float(r.get("main_rss_mb", 0)) for r in rows]
                worker_rss = [float(r.get("worker_rss_mb", 0)) for r in rows]
                cpu_t = [float(r.get("cpu_percent", 0)) for r in rows]
                eps_t = [float(r.get("eps", 0)) for r in rows]
                db_size = [float(r.get("db_size_mb", 0)) for r in rows]

                # 7. queue_depth_time.png
                fig, ax = plt.subplots(figsize=(9, 4.5))
                ax.plot(times, q_depth, color="#00d2ff", linewidth=2)
                ax.fill_between(times, q_depth, color="#00d2ff", alpha=0.2)
                ax.set_xlabel("Elapsed Time (s)")
                ax.set_ylabel("Queue Depth (Batches)")
                ax.set_title("Queue Depth Over Time")
                out = os.path.join(results_dir, "queue_depth_time.png")
                fig.savefig(out, dpi=150, bbox_inches="tight")
                plt.close(fig)
                generated.append(out)

                # 8. memory_over_time.png
                fig, ax = plt.subplots(figsize=(9, 4.5))
                ax.plot(times, total_rss, label="Total App RSS", color="#2ed573", linewidth=2)
                ax.plot(times, worker_rss, label="Workers RSS", color="#1e90ff", linestyle="--")
                ax.plot(times, main_rss, label="Main Process RSS", color="#a4b0be", linestyle=":")
                ax.set_xlabel("Elapsed Time (s)")
                ax.set_ylabel("Memory RSS (MB)")
                ax.set_title("Process Memory RSS Over Time (Leak Analysis)")
                ax.legend(facecolor="#1a1a2e", edgecolor="#444")
                out = os.path.join(results_dir, "memory_over_time.png")
                fig.savefig(out, dpi=150, bbox_inches="tight")
                plt.close(fig)
                generated.append(out)

                # 9. cpu_over_time.png
                fig, ax = plt.subplots(figsize=(9, 4.5))
                ax.plot(times, cpu_t, color="#ff6b6b", linewidth=2)
                ax.fill_between(times, cpu_t, color="#ff6b6b", alpha=0.15)
                ax.set_xlabel("Elapsed Time (s)")
                ax.set_ylabel("CPU Utilization (%)")
                ax.set_title("CPU Utilization Over Time")
                out = os.path.join(results_dir, "cpu_over_time.png")
                fig.savefig(out, dpi=150, bbox_inches="tight")
                plt.close(fig)
                generated.append(out)

                # 15. database_growth.png
                fig, ax = plt.subplots(figsize=(9, 4.5))
                ax.plot(times, db_size, color="#ffa502", linewidth=2.5)
                ax.set_xlabel("Elapsed Time (s)")
                ax.set_ylabel("DuckDB Size (MB)")
                ax.set_title("Database Size Growth Over Ingestion")
                out = os.path.join(results_dir, "database_growth.png")
                fig.savefig(out, dpi=150, bbox_inches="tight")
                plt.close(fig)
                generated.append(out)

                # 13. soak_test.png (4-Panel Dashboard)
                fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 8))
                ax1.plot(times, eps_t, color="#00d2ff")
                ax1.set_title("Ingestion EPS")
                ax1.set_ylabel("EPS")
                ax2.plot(times, cpu_t, color="#ff6b6b")
                ax2.set_title("CPU Utilization (%)")
                ax2.set_ylabel("%")
                ax3.plot(times, total_rss, color="#2ed573")
                ax3.set_title("Application RSS (MB)")
                ax3.set_ylabel("MB")
                ax4.plot(times, q_depth, color="#ffa502")
                ax4.set_title("Queue Depth")
                ax4.set_ylabel("Batches")
                plt.tight_layout()
                out = os.path.join(results_dir, "soak_test.png")
                fig.savefig(out, dpi=150, bbox_inches="tight")
                plt.close(fig)
                generated.append(out)
            except Exception as e:
                logger.error(f"Error rendering soak graphs: {e}")

    # ------------------------------------------------------------------
    # 10. udp_live_loss.png (UDP sent/received/persisted)
    # ------------------------------------------------------------------
    udp_csv = _find_file("live_udp_results.csv")
    if udp_csv:
        rows = _load_csv(udp_csv)
        if rows:
            try:
                rates = [r["target_eps"] for r in rows]
                sent = [int(r["sent"]) for r in rows]
                recv = [int(r["received"]) for r in rows]
                persisted = [int(r["persisted"]) for r in rows]

                fig, ax = plt.subplots(figsize=(10, 5))
                x = list(range(len(rates)))
                width = 0.25
                ax.bar([i - width for i in x], sent, width=width, color="#00d2ff", label="Sent Datagrams")
                ax.bar(x, recv, width=width, color="#2ed573", label="Listener Received")
                ax.bar([i + width for i in x], persisted, width=width, color="#ffa502", label="DuckDB Persisted")
                ax.set_xticks(x)
                ax.set_xticklabels([f"{int(r):,} EPS" for r in rates])
                ax.set_ylabel("Event Count")
                ax.set_title("Live UDP Ingestion: Sent vs Received vs Persisted (Loss Breakdown)")
                ax.legend(facecolor="#1a1a2e", edgecolor="#444")
                out = os.path.join(results_dir, "udp_live_loss.png")
                fig.savefig(out, dpi=150, bbox_inches="tight")
                plt.close(fig)
                generated.append(out)
            except Exception as e:
                logger.error(f"Error rendering udp_live_loss: {e}")

    # ------------------------------------------------------------------
    # 11. tcp_clients_throughput.png (TCP throughput vs clients)
    # ------------------------------------------------------------------
    tcp_csv = _find_file("live_tcp_results.csv")
    if tcp_csv:
        rows = _load_csv(tcp_csv)
        if rows:
            try:
                clients = [int(r["clients"]) for r in rows]
                th = [float(r["throughput_eps"]) for r in rows]
                p95 = [float(r["p95_client_latency_ms"]) for r in rows]

                fig, ax1 = plt.subplots(figsize=(9, 5))
                ax2 = ax1.twinx()
                ax1.plot(clients, th, marker="o", color="#00d2ff", linewidth=2.5, label="Throughput (EPS)")
                ax2.plot(clients, p95, marker="s", color="#ff6b6b", linewidth=2, label="P95 Client Latency (ms)")
                ax1.set_xlabel("Concurrent TCP Clients")
                ax1.set_ylabel("Throughput (EPS)", color="#00d2ff")
                ax2.set_ylabel("P95 Latency (ms)", color="#ff6b6b")
                ax1.set_title("TCP Live Listener: Throughput vs Concurrent Clients")
                out = os.path.join(results_dir, "tcp_clients_throughput.png")
                fig.savefig(out, dpi=150, bbox_inches="tight")
                plt.close(fig)
                generated.append(out)
            except Exception as e:
                logger.error(f"Error rendering tcp_clients_throughput: {e}")

    # ------------------------------------------------------------------
    # 12. burst_recovery.png (Burst / Recovery)
    # ------------------------------------------------------------------
    burst_csv = _find_file("burst_test.csv")
    if burst_csv:
        rows = _load_csv(burst_csv)
        if rows:
            try:
                bursts = [f"{int(r['burst_eps']):,} EPS" for r in rows]
                max_q = [int(r["max_queue_depth"]) for r in rows]
                drain_t = [float(r["drain_time_sec"]) for r in rows]

                fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
                ax1.bar(bursts, max_q, color="#ff4757")
                ax1.set_title("Max Queue Depth During Burst")
                ax1.set_ylabel("Queue Depth (Batches)")
                ax2.bar(bursts, drain_t, color="#ffa502")
                ax2.set_title("Queue Drain Time After Burst")
                ax2.set_ylabel("Drain Time (seconds)")
                plt.tight_layout()
                out = os.path.join(results_dir, "burst_recovery.png")
                fig.savefig(out, dpi=150, bbox_inches="tight")
                plt.close(fig)
                generated.append(out)
            except Exception as e:
                logger.error(f"Error rendering burst_recovery: {e}")

    # ------------------------------------------------------------------
    # 14. event_accounting.png (Event Accounting Waterfall)
    # ------------------------------------------------------------------
    acct_csv = _find_file("event_accounting.csv")
    if acct_csv:
        rows = _load_csv(acct_csv)
        if rows:
            try:
                stages = [r["stage"] for r in rows if r["stage"] in ("generated", "sent", "received", "accepted", "parsed", "normalized", "persisted")]
                counts = [int(r["event_count"]) for r in rows if r["stage"] in ("generated", "sent", "received", "accepted", "parsed", "normalized", "persisted")]

                fig, ax = plt.subplots(figsize=(10, 5))
                bars = ax.bar(stages, counts, color="#00d2ff")
                for b in bars:
                    yval = b.get_height()
                    ax.annotate(f"{yval:,}", (b.get_x() + b.get_width() / 2, yval), xytext=(0, 4), textcoords="offset points", ha="center")
                ax.set_title("Event Accounting: End-to-End Delivery Waterfall")
                ax.set_ylabel("Events")
                out = os.path.join(results_dir, "event_accounting.png")
                fig.savefig(out, dpi=150, bbox_inches="tight")
                plt.close(fig)
                generated.append(out)
            except Exception as e:
                logger.error(f"Error rendering event_accounting: {e}")

    # ------------------------------------------------------------------
    # 16. apg_performance.png & 17. drift_detection.png
    # ------------------------------------------------------------------
    integ_json = _find_file("integrity_suite_results.json")
    if integ_json:
        data = _load_json(integ_json)
        if data and "tests" in data:
            # APG graph
            apg_t = next((t for t in data["tests"] if "APG" in t["test"]), None)
            if apg_t:
                try:
                    fields = apg_t["details"].get("fields_inferred", [])
                    fig, ax = plt.subplots(figsize=(8, 4))
                    ax.barh(fields, [1] * len(fields), color="#2ed573")
                    ax.set_title(f"APG Inferred Fields (Mined in {apg_t['details'].get('generation_time_sec', 0)}s)")
                    ax.set_xlabel("Inference Status (1=Inferred)")
                    out = os.path.join(results_dir, "apg_performance.png")
                    fig.savefig(out, dpi=150, bbox_inches="tight")
                    plt.close(fig)
                    generated.append(out)
                except Exception as e:
                    logger.error(f"Error rendering apg_performance: {e}")

            # Drift graph
            drift_t = next((t for t in data["tests"] if "Drift" in t["test"]), None)
            if drift_t and "results" in drift_t["details"]:
                try:
                    fmts = [r["format"] for r in drift_t["details"]["results"]]
                    lats = [float(r["detection_latency_ms"]) for r in drift_t["details"]["results"]]
                    fig, ax = plt.subplots(figsize=(8, 4.5))
                    ax.bar(fmts, lats, color="#ffa502")
                    ax.set_ylabel("Detection Latency (ms)")
                    ax.set_title("Format Drift Detection Latency across Log Formats")
                    out = os.path.join(results_dir, "drift_detection.png")
                    fig.savefig(out, dpi=150, bbox_inches="tight")
                    plt.close(fig)
                    generated.append(out)
                except Exception as e:
                    logger.error(f"Error rendering drift_detection: {e}")

    # ------------------------------------------------------------------
    # Pipeline Latency Distribution Histogram (if available)
    # ------------------------------------------------------------------
    lat_csv = _find_file("pipeline_latency.csv")
    if lat_csv:
        rows = _load_csv(lat_csv)
        if rows:
            try:
                latencies = [float(r["latency_ms"]) for r in rows if r.get("latency_ms")]
                if latencies:
                    fig, ax = plt.subplots(figsize=(9, 4.5))
                    cap = sorted(latencies)[int(len(latencies) * 0.999)]
                    filtered = [l for l in latencies if l <= cap]
                    ax.hist(filtered, bins=100, color="#00d2ff", edgecolor="#0a1128", alpha=0.85)
                    ax.set_xlabel("Latency (ms)")
                    ax.set_ylabel("Frequency")
                    ax.set_title(f"Pipeline Latency Distribution (n={len(latencies):,})")
                    out = os.path.join(results_dir, "latency_histogram.png")
                    fig.savefig(out, dpi=150, bbox_inches="tight")
                    plt.close(fig)
                    generated.append(out)
            except Exception as e:
                logger.error(f"Error rendering latency_histogram: {e}")

    # ------------------------------------------------------------------
    # Loghub & Downstream Parser Visualizations
    # ------------------------------------------------------------------
    loghub_json = _find_file("loghub_benchmark.json")
    if loghub_json:
        lh_data = _load_json(loghub_json)
        if lh_data:
            # 18. loghub_accuracy.png
            try:
                per_sys = lh_data.get("per_system_results", [])
                if per_sys:
                    systems = [ps["system"] for ps in per_sys]
                    pa_scores = [float(ps["parsing_accuracy_pct"]) for ps in per_sys]
                    fta_scores = [float(ps["template_f1"]) * 100 for ps in per_sys]

                    fig, ax = plt.subplots(figsize=(11, 5))
                    x = range(len(systems))
                    w = 0.38
                    ax.bar([i - w/2 for i in x], pa_scores, width=w, color="#00d2ff", label="Parsing Accuracy (PA %)")
                    ax.bar([i + w/2 for i in x], fta_scores, width=w, color="#2ed573", label="Template F1 (FTA %)")
                    ax.set_xticks(list(x))
                    ax.set_xticklabels(systems, rotation=35, ha="right", fontsize=9)
                    ax.set_ylabel("Accuracy (%)")
                    ax.set_ylim(0, 110)
                    ax.set_title("Loghub 2.0 Multi-System Preprocessing Accuracy (14+ Sources)")
                    ax.legend(facecolor="#1a1a2e", edgecolor="#444")
                    out = os.path.join(results_dir, "loghub_accuracy.png")
                    fig.savefig(out, dpi=150, bbox_inches="tight")
                    plt.close(fig)
                    generated.append(out)
            except Exception as e:
                logger.error(f"Error rendering loghub_accuracy: {e}")

            # 19. drain_speedup.png
            try:
                dd = lh_data.get("downstream_drain", {})
                if dd:
                    raw_eps = float(dd.get("raw_eps", 0))
                    pre_eps = float(dd.get("preprocessed_eps", 0))
                    fig, ax = plt.subplots(figsize=(7, 4.5))
                    bars = ax.bar(["Raw Logs", "ULPF Preprocessed"], [raw_eps, pre_eps], color=["#ff4757", "#2ed573"], width=0.45)
                    ax.set_ylabel("Drain Throughput (EPS)")
                    ax.set_title(f"Downstream Drain Parser Acceleration (+{dd.get('speedup_pct', 0)}% Speedup)")
                    for b in bars:
                        h = b.get_height()
                        ax.annotate(f"{h:,.0f} EPS", (b.get_x() + b.get_width() / 2, h), textcoords="offset points", xytext=(0, 6), ha="center", color="#ffffff", fontweight="bold")
                    out = os.path.join(results_dir, "drain_speedup.png")
                    fig.savefig(out, dpi=150, bbox_inches="tight")
                    plt.close(fig)
                    generated.append(out)
            except Exception as e:
                logger.error(f"Error rendering drain_speedup: {e}")

    print(f"  Generated {len(generated)} automated graph(s) in {results_dir}")
    return generated
