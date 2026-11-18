# ULPF Enterprise Benchmark — Technical Specification

> **Harness:** [`benchmarks/enterprise.py`](benchmarks/enterprise.py) (`python -m benchmarks.enterprise`)
> **Benchmark modules:** [`benchmarks/`](benchmarks/)
> **Results:** `benchmarks/results/enterprise/run_<timestamp>/` (git-ignored)

---

## Overview

The enterprise benchmark is a 9-phase harness covering throughput, memory, network I/O, scalability, correctness, parsing accuracy and feature overhead. Each phase calls the real ULPF components (worker pool, asyncio listener, DuckDB store, CLI) over real loopback sockets and real OS processes. Every number in the report is measured during the run; none is hardcoded.

Two rules keep the results honest and the machine safe:

- **Workers default to (CPU cores − 1).** Oversubscribing the CPU only measures context switching.
- **Isolated state.** The harness points `ULPF_DATA_DIR` at `run_<timestamp>/data`, so no phase reads or writes the operator's real event store, spool or learned parsers.

---

## Phase 1: Warm-up

**Module:** `python -m ulpf.main benchmark --events 10000`
**Purpose:** imports, regex compilation, DuckDB initialisation and allocator warm-up happen once, before any measurement. **Phase 1 metrics are discarded.**

---

## Phase 2: Steady-state soak test

**Module:** [`benchmarks/soak.py`](benchmarks/soak.py) → `run_soak_test()`
**Load:** 60 s at a 5,000 EPS offered rate, cores − 1 workers, 1,000-line batches, worker queue bound 500
**Sampling:** every 1.0 s

| Metric | How it is measured | Why it matters |
| :--- | :--- | :--- |
| **Interval EPS** | `(processed_now − processed_last) / Δt` | Throughput must stay stable over time |
| **CPU %** | `psutil.cpu_percent()` system-wide | CPU-bound vs I/O-bound |
| **Main / worker / total RSS (MB)** | `psutil.Process(...).memory_info().rss` for the host and each child | What an SRE sees in monitoring |
| **Input queue depth** | `pool.input_queue.qsize()` | Backpressure must keep queues bounded |
| **Database size, free disk** | `os.path.getsize`, `shutil.disk_usage` | Disk consumption rate |
| **Active workers** | live child processes via `psutil` | Detects crashes or deadlocks |
| **Errors** | `pool.total_failed` (shared counter) | Parse failures |

After the run, four checks decide the status (`HEALTHY` or `ANOMALIES_DETECTED`):

1. **Memory leak:** average worker RSS in the second half exceeds the first half by more than 250 MB (summed over all workers).
2. **Unbounded queue growth:** the queue reached 95% of its bound.
3. **Worker failure:** fewer live workers than started in any sample after the first two seconds.
4. **Degradation:** second-half EPS below 75% of first-half EPS.

**Output:** `soak_metrics.csv`, `soak_summary.json`

---

## Phase 3: Live UDP network benchmark

**Module:** [`benchmarks/live_network.py`](benchmarks/live_network.py) → `run_live_udp_benchmark()`
**Offered rates:** 10,000 / 50,000 / 100,000 / 150,000 EPS, 10,000 events each

For each rate the benchmark:

1. Creates a fresh DuckDB store in the temp directory.
2. Starts a `WorkerPool` (cores − 1 workers) fed by a shared `multiprocessing.Queue(maxsize=1000)`.
3. Starts the asyncio `NetworkListener` on `127.0.0.1:5514` in a background thread.
4. Sends every line as a UDP datagram from a socket with a 4 MB send buffer, paced to the target rate with `time.sleep`.
5. Waits 1 s for the pipeline to drain, then reads listener counters and the persisted count from DuckDB.
6. Attributes loss:
   - **Network loss** = sent − received (dropped by the kernel when the receive buffer overflowed)
   - **Application loss** = received − persisted (dropped by a full queue or failed to parse/store)
   - **Total loss** = sent − persisted

UDP has no flow control. At high offered rates the kernel drops datagrams by design, the same way a congested production link does, and the benchmark reports that loss rather than hiding it. **Pass:** total loss below 5% at every rate. Use TCP when you cannot accept loss.

**Output:** `live_udp_results.csv`, `live_udp_results.json`

---

## Phase 4: Live TCP concurrency benchmark

**Module:** [`benchmarks/live_network.py`](benchmarks/live_network.py) → `run_live_tcp_benchmark()`
**Clients:** 1, 4, 16 and 64 simultaneous connections, 2,000 events each, listener on `127.0.0.1:5515`

Each client thread connects, sends its lines newline-delimited with one `sendall()`, records the send latency and closes. The phase reports sent vs persisted events, wall-clock throughput, P50/P95 client latency, connection errors and loss.

It then runs four resilience scenarios:

1. **Abrupt disconnect:** the client closes without a graceful shutdown; the listener must survive `ConnectionResetError`.
2. **Reconnect:** a new client connects to the same listener.
3. **Listener restart:** the listener is stopped and started again on the same port (`SO_REUSEADDR`).
4. **Reconnect after restart:** a client connects to the restarted listener.

**Pass:** all four resilience steps complete without an unhandled exception.

**Output:** `live_tcp_results.csv`, `live_tcp_results.json`

---

## Phase 5: Multi-worker scalability

**Module:** [`benchmarks/multiworker.py`](benchmarks/multiworker.py) → `run_worker_benchmark()`
**Worker counts:** 1, 2, 4, 8, with 50,000 events per configuration

For each worker count the benchmark creates a fresh store, starts the pool and a `ResourceSampler` thread (every 50 ms: system CPU, host RSS, every child's RSS, input/output queue depth). It submits batches while measuring per-batch enqueue latency (which includes backpressure waits), and waits until the queues have been empty with no progress for 750 ms. Finally it reads the persisted count from DuckDB.

| Metric | Description |
| :--- | :--- |
| `throughput_eps` | persisted events / wall time (end to end) |
| `cpu_percent`, `max_cpu_percent` | average and peak CPU |
| `process_rss_mb`, `worker_rss_mb`, `rss_per_worker_mb`, `total_app_rss_mb`, `peak_rss_mb` | memory attribution |
| `p50_ms` … `p999_ms`, `max_ms` | batch enqueue latency percentiles |
| `queue_depth_max`, `errors`, `drops`, `persisted_events` | backpressure and correctness |

With `matplotlib` installed it also draws `worker_scalability.png`: throughput against ideal linear scaling, and CPU/RSS against worker count. Expect scaling to flatten at the number of physical cores.

**Output:** `worker_scalability.csv`, `worker_scalability.json`, `worker_scalability.png`

---

## Phase 6: Process-level memory validation

**Module:** [`benchmarks/soak.py`](benchmarks/soak.py) → `run_memory_validation()`
**Workers:** cores − 1, with 20,000 test events

1. **Idle RSS:** host process with all modules imported, before workers start.
2. **Worker baseline:** each worker's RSS 500 ms after start (interpreter + imported modules: DuckDB, PyArrow, parsers).
3. **Peak under load:** RSS of the host and of each worker PID, sampled every 50 ms while 20,000 events are processed.

The phase compares the average peak per worker with a **125 MB** budget and reports a hard `PASS`/`FAIL` with the measured value. Most of a worker's footprint is the Python runtime plus PyArrow and DuckDB, so the old "< 10 MB per worker" claim is not achievable in Python and is no longer made.

**Output:** `memory_validation.json`

---

## Phase 7: Data integrity & security validation

**Module:** [`benchmarks/integrity.py`](benchmarks/integrity.py) → `IntegrityValidator.run_all()`

| Test | What is verified |
| :--- | :--- |
| 7.1 Provenance hashing | every event's `evidence.raw_hash` equals the SHA-256 of its raw line |
| 7.2 Event ID uniqueness | 500 events, zero duplicate `event_id`s |
| 7.3 Raw event preservation | every parsed event keeps the original line in `raw_event` |
| 7.4 Timestamp normalisation | every `timestamp` is ISO 8601 (from BSD syslog, CEF epoch, ISO JSON, …) |
| 7.5 Storage consistency | stored count = read-back count = expected count |
| 7.6 All formats parseable | ≥ 5 of 10 synthetic lines parse for each of syslog 3164/5424, CEF, LEEF, JSON, XML, CSV, KV, W3C |
| 7.7 Air-gap mode | a `ULPFPlugin(offline=True)` processes events |
| 7.8 Forensic chain integrity | an evidence chain over mixed events verifies |

**Pass:** all 8 tests pass. For the deeper suite (byte-exact raw preservation, tamper detection, crash recovery, drift detection) run `python -m benchmarks.integrity_suite`.

**Output:** `integrity_validation.json`

---

## Phase 8: Loghub parsing accuracy

**Module:** [`benchmarks/loghub_eval.py`](benchmarks/loghub_eval.py) → `run_loghub_evaluation()`

Loghub (CUHK) is a widely used academic collection of real system logs with ground-truth templates. The harness embeds a **small sample: 32 annotated lines from 14 Loghub systems** (HDFS, BGL, Spark, Zookeeper, Linux, Windows, OpenStack, Apache, Thunderbird, OpenSSH, Android, Proxifier, HealthApp, Mac). It does not download or replay the full Loghub corpora, so treat the result as a smoke test of template extraction, not as a leaderboard score.

Metrics:

1. **Parsing accuracy (PA):** ULPF's extracted message, with variables masked (IPs, numbers, paths, UUIDs → `<*>`), compared with the ground-truth template.
2. **Template accuracy (precision / recall / F1)** of the extracted templates.
3. **Grouping accuracy (GA):** lines of the same event type end up in the same group.
4. **Size reduction:** raw bytes vs structured event bytes.

**Downstream Drain comparison:** a compact implementation of the Drain algorithm (in the same module) parses the raw lines and the ULPF-preprocessed messages 50 times each, and the phase reports Drain's throughput on both.

**Pass:** overall parsing accuracy ≥ 90%.

**Output:** `loghub_benchmark.csv`, `loghub_benchmark.json`

---

## Phase 9: Feature overhead

Wall-clock time of four CLI operations against the isolated data directory, in order:

1. `process --files demo_data/mixed_formats.log`: parse, normalise and store, which also gives Phase 9's later steps events to work on.
2. `fingerprint --file …`: Log DNA structural fingerprint.
3. `learn --file … --all-lines`: Auto-Parser Generator mining, validation and signing.
4. `correlate --limit 500`: entity correlation and kill-chain mapping over the stored events.

**Pass:** every command exits successfully in under 30 s.

---

## Final report

The harness prints one status per phase and an overall verdict (`PASS`, or `PARTIAL (n/9)`), then summaries of soak, memory, Loghub and feature timings. Statuses depend on the hardware: a 2-core laptop may legitimately fail the 150k EPS UDP rate. The full machine-readable report is `enterprise_report.json` in the run directory.

## Running the benchmark

```bash
python -m benchmarks.enterprise
```

It takes about 5–10 minutes and needs `psutil` (always installed) and optionally `matplotlib` for graphs. The exit code is `0` only when every phase passes.
