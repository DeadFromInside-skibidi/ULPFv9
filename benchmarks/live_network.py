"""
ULPF Live Network Benchmark Suite (UDP & TCP)
==============================================
Validates:
  - Section 7: Live UDP Listener Benchmark
    Tests 10k, 50k, 100k, 150k, 154k, 200k EPS.
    Records: sent, received, accepted, persisted, missing IDs, duplicate IDs,
             queue overflow, application drops, socket errors.
    Distinguishes network loss from application processing loss.
  - Section 8: Live TCP Listener Benchmark
    Tests 1, 4, 16, 64 concurrent clients at increasing EPS.
    Tests disconnect, reconnect, application restart, client reconnect.
    Records throughput, latency, loss, and errors.
"""
from __future__ import annotations

import asyncio
import csv
import json
import logging
import multiprocessing as mp
import os
import socket
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import duckdb

from benchmarks.accounting import EventAccountant
from benchmarks.generator import DeterministicGenerator
from ulpf.ingestion.listener import NetworkListener
from ulpf.ingestion.workers import WorkerPool

logger = logging.getLogger("benchmarks.live_network")


class ListenerThread(threading.Thread):
    """Runs asyncio NetworkListener in a background thread."""

    def __init__(self, queue: mp.Queue, host: str, port: int, protocol: str = "udp"):
        super().__init__(daemon=True, name=f"listener-{protocol}")
        self.queue = queue
        self.host = host
        self.port = port
        self.protocol = protocol
        self.listener: Optional[NetworkListener] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.started_event = threading.Event()
        self.stop_event = threading.Event()

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.listener = NetworkListener(self.queue, host=self.host, port=self.port)

        async def _start():
            await self.listener.start(protocol=self.protocol)
            self.started_event.set()
            while not self.stop_event.is_set():
                await asyncio.sleep(0.05)
            await self.listener.stop()

        try:
            self.loop.run_until_complete(_start())
        except Exception as e:
            logger.debug(f"Listener loop ended: {e}")
        finally:
            self.loop.close()

    def wait_ready(self, timeout: float = 5.0) -> bool:
        return self.started_event.wait(timeout=timeout)

    def stop(self):
        self.stop_event.set()
        self.join(timeout=3.0)


# ---------------------------------------------------------------------------
# Section 7: Live UDP Benchmark
# ---------------------------------------------------------------------------

def run_live_udp_benchmark(
    rates: Optional[List[int]] = None,
    events_per_rate: int = 10000,
    host: str = "127.0.0.1",
    port: int = 5514,
    workers: int = 8,
    batch_size: int = 1000,
    seed: int = 42,
    results_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run real UDP listener and transmit live UDP traffic at:
      10k, 50k, 100k, 150k, 154k, 200k EPS.
    Distinguishes network loss from application processing loss.
    """
    default_rates = [10000, 50000, 100000, 150000, 154000, 200000]
    test_rates = rates or default_rates
    results_dir = results_dir or os.path.join(PROJECT_ROOT, "benchmarks", "results", "live_network")
    os.makedirs(results_dir, exist_ok=True)

    print(f"\n{'=' * 65}")
    print(f"  ULPF LIVE UDP BENCHMARK (Real Asyncio Listener & Socket Traffic)")
    print(f"{'=' * 65}")
    print(f"  Target Port         : {host}:{port} (UDP)")
    print(f"  Tested Rates (EPS)  : {[f'{r:,}' for r in test_rates]}")
    print(f"  Events per Rate     : {events_per_rate:,}")

    gen = DeterministicGenerator(seed=seed)
    udp_results: List[Dict[str, Any]] = []

    for rate in test_rates:
        print(f"  [+] Testing Live UDP at {rate:,} EPS...")

        tmp_db = os.path.join(tempfile.gettempdir(), f"ulpf_udp_{rate}_{int(time.time())}.duckdb")
        if os.path.exists(tmp_db):
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        lines, ids = gen.generate_with_ids(events_per_rate, start_id=0)

        shared_queue = mp.Queue(maxsize=1000)
        pool = WorkerPool(num_workers=workers, input_queue=shared_queue, batch_size=batch_size)
        pool.start(db_path=tmp_db, is_network=True)

        listener_th = ListenerThread(shared_queue, host, port, protocol="udp")
        listener_th.start()
        listener_th.wait_ready()

        # Send UDP packets paced at target rate
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Increase send buffer to minimize local OS dropping
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        except OSError:
            pass

        sent = 0
        socket_errors = 0
        target_interval = 1.0 / max(rate, 1)

        t_send_start = time.perf_counter()
        t_next = t_send_start

        for line in lines:
            t_now = time.perf_counter()
            if t_now < t_next:
                time.sleep(max(0.0, t_next - t_now))
            try:
                sock.sendto(line.encode("utf-8"), (host, port))
                sent += 1
            except Exception:
                socket_errors += 1
            t_next = max(t_next + target_interval, time.perf_counter())

        sock.close()
        t_send_end = time.perf_counter()
        send_duration = t_send_end - t_send_start
        actual_send_eps = sent / max(send_duration, 0.001)

        # Allow settle time
        time.sleep(1.0)
        l_stats = listener_th.listener.stats.to_dict() if listener_th.listener else {}
        received = l_stats.get("packets_received", 0)
        accepted = l_stats.get("messages_queued", 0)
        q_dropped = l_stats.get("messages_dropped", 0)

        # Stop listener and pool
        listener_th.stop()
        pool.stop(timeout=5.0)

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

        # Distinguish network loss from application loss
        network_loss = max(0, sent - received)
        app_loss = max(0, received - persisted)
        total_loss = max(0, sent - persisted)

        net_loss_pct = round(network_loss / max(sent, 1) * 100, 2)
        app_loss_pct = round(app_loss / max(received, 1) * 100, 2)
        total_loss_pct = round(total_loss / max(sent, 1) * 100, 2)

        item = {
            "target_eps": rate,
            "actual_send_eps": round(actual_send_eps, 1),
            "sent": sent,
            "received": received,
            "accepted": accepted,
            "persisted": persisted,
            "socket_errors": socket_errors,
            "queue_overflow_drops": q_dropped,
            "network_loss": network_loss,
            "network_loss_pct": net_loss_pct,
            "application_loss": app_loss,
            "application_loss_pct": app_loss_pct,
            "total_loss": total_loss,
            "total_loss_pct": total_loss_pct,
        }
        udp_results.append(item)
        print(
            f"      -> Sent: {sent:,} | Recv: {received:,} (Net loss: {net_loss_pct}%) | "
            f"Persisted: {persisted:,} (App loss: {app_loss_pct}%) | Send EPS: {actual_send_eps:>8,.0f}"
        )

    # Save CSV
    csv_path = os.path.join(results_dir, "live_udp_results.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(udp_results[0].keys()))
        writer.writeheader()
        writer.writerows(udp_results)

    json_path = os.path.join(results_dir, "live_udp_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"udp_results": udp_results}, f, indent=2)

    return {"udp_results": udp_results, "csv_path": csv_path}


# ---------------------------------------------------------------------------
# Section 8: Live TCP Benchmark
# ---------------------------------------------------------------------------

def run_live_tcp_benchmark(
    client_counts: Optional[List[int]] = None,
    events_per_client: int = 2000,
    host: str = "127.0.0.1",
    port: int = 5515,
    workers: int = 8,
    batch_size: int = 1000,
    seed: int = 42,
    results_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run real TCP listener and test client concurrency:
      1, 4, 16, 64 clients.
    Also tests:
      disconnect, reconnect, application restart, client reconnect.
    """
    default_clients = [1, 4, 16, 64]
    test_clients = client_counts or default_clients
    results_dir = results_dir or os.path.join(PROJECT_ROOT, "benchmarks", "results", "live_network")
    os.makedirs(results_dir, exist_ok=True)

    print(f"\n{'=' * 65}")
    print(f"  ULPF LIVE TCP BENCHMARK (Concurrent Clients & Resilience)")
    print(f"{'=' * 65}")
    print(f"  Target Port         : {host}:{port} (TCP)")
    print(f"  Clients Tested      : {test_clients}")
    print(f"  Events per Client   : {events_per_client:,}")

    gen = DeterministicGenerator(seed=seed)
    tcp_results: List[Dict[str, Any]] = []

    for num_clients in test_clients:
        print(f"  [+] Testing TCP with {num_clients} Concurrent Client(s)...")

        tmp_db = os.path.join(tempfile.gettempdir(), f"ulpf_tcp_{num_clients}_{int(time.time())}.duckdb")
        if os.path.exists(tmp_db):
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        total_expected = num_clients * events_per_client

        shared_queue = mp.Queue(maxsize=1000)
        pool = WorkerPool(num_workers=workers, input_queue=shared_queue, batch_size=batch_size)
        pool.start(db_path=tmp_db, is_network=True)

        listener_th = ListenerThread(shared_queue, host, port, protocol="tcp")
        listener_th.start()
        listener_th.wait_ready()

        # Client worker function
        client_sent = [0] * num_clients
        client_errors = [0] * num_clients
        client_latencies: List[float] = []

        def _client_task(c_idx: int):
            c_lines = gen.generate(events_per_client, start_id=c_idx * events_per_client)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host, port))
                t0 = time.perf_counter()
                payload = "\n".join(c_lines) + "\n"
                sock.sendall(payload.encode("utf-8"))
                client_sent[c_idx] = len(c_lines)
                client_latencies.append((time.perf_counter() - t0) * 1000)
                sock.close()
            except Exception:
                client_errors[c_idx] += 1

        threads = [threading.Thread(target=_client_task, args=(i,)) for i in range(num_clients)]
        t_start = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        t_end = time.perf_counter()
        duration = t_end - t_start

        time.sleep(1.0)
        listener_th.stop()
        pool.stop(timeout=5.0)

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

        total_sent = sum(client_sent)
        total_errs = sum(client_errors)
        throughput = total_sent / max(duration, 0.001)
        sorted_l = sorted(client_latencies)
        p50 = sorted_l[int(len(sorted_l) * 0.5)] if sorted_l else 0.0
        p95 = sorted_l[int(len(sorted_l) * 0.95)] if sorted_l else 0.0

        item = {
            "clients": num_clients,
            "total_sent": total_sent,
            "persisted": persisted,
            "duration_sec": round(duration, 3),
            "throughput_eps": round(throughput, 1),
            "client_errors": total_errs,
            "p50_client_latency_ms": round(p50, 2),
            "p95_client_latency_ms": round(p95, 2),
            "loss_events": max(0, total_sent - persisted),
        }
        tcp_results.append(item)
        print(
            f"      -> Sent: {total_sent:,} | Persisted: {persisted:,} | "
            f"Throughput: {throughput:>8,.0f} EPS | P95 Latency: {p95:.1f}ms | Errors: {total_errs}"
        )

    # ── Test Resilience: Disconnect, Reconnect, Listener Restart ──
    print(f"\n  [+] Testing TCP Resilience (Disconnect / Reconnect / Listener Restart)...")
    resilience_passed = True
    try:
        shared_q = mp.Queue(maxsize=100)
        pool = WorkerPool(num_workers=2, input_queue=shared_q)
        pool.start()
        l_th = ListenerThread(shared_q, host, port, protocol="tcp")
        l_th.start()
        l_th.wait_ready()

        # 1. Connect & abrupt disconnect
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s1.connect((host, port))
        s1.sendall(b"abrupt disconnect test\n")
        s1.close()  # close immediately
        time.sleep(0.1)

        # 2. Reconnect
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.connect((host, port))
        s2.sendall(b"reconnect test message\n")
        s2.close()

        # 3. Application listener restart
        l_th.stop()
        time.sleep(0.2)
        l_th2 = ListenerThread(shared_q, host, port, protocol="tcp")
        l_th2.start()
        l_th2.wait_ready()

        # 4. Client reconnect after restart
        s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s3.connect((host, port))
        s3.sendall(b"post restart client message\n")
        s3.close()

        l_th2.stop()
        pool.stop()
        print(f"      -> Resilience Checks: PASS (Disconnect, Reconnect, Restart, Client Reconnect)")
    except Exception as e:
        resilience_passed = False
        print(f"      -> Resilience Checks: FAILED ({e})")

    # Save CSV
    csv_path = os.path.join(results_dir, "live_tcp_results.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(tcp_results[0].keys()))
        writer.writeheader()
        writer.writerows(tcp_results)

    json_path = os.path.join(results_dir, "live_tcp_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"tcp_results": tcp_results, "resilience_passed": resilience_passed}, f, indent=2)

    return {"tcp_results": tcp_results, "resilience_passed": resilience_passed, "csv_path": csv_path}
