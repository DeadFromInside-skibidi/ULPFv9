# ULPF v9 — Implementation Status

Tracks progress against [IMPLEMENTATION_PLAN_V9.md](IMPLEMENTATION_PLAN_V9.md). Every number here comes from a result file under `benchmarks/results/`.

## Decisions recorded

- **USPs confirmed** by the project owner: U1 autonomous format learning, U2 tamper-evident evidence chain, U3 unified schema, U4 offline / air-gap operation, U5 stream analytics (Log DNA drift and correlation).
- **Two operating modes approved**: `defence` and `industry` (plan section 3a).
- **Toolchain:** Rust installed into the user profile with `rustup` (rustc 1.99.1). The plan named the MSVC Build Tools, but they need administrator rights. The GNU host toolchain (`x86_64-pc-windows-gnu`) ships its own linker and needs no admin install, and PyO3 supports it via `generate-import-lib`. Plan section F is therefore unblocked without the MSVC tools.
- **Python packages added** to the project environment for the plan: `cryptography`, `py-spy`, `hypothesis`, `paho-mqtt`, `python-pptx`, `pypdf`, `protobuf`.

## Phase A — Measure and decide (done)

**Hardware:** Intel Core i5-8279U (4 cores / 8 threads, 2.4 GHz laptop part), 15.8 GB RAM, Windows 10, Python 3.11.

**Baseline suites:** core 39/39, platform 14/14, GUI 14/14, audit 6/6 — all OK.

**Hot-path profile** (`python -m benchmarks.live.profile_core --events 50000`; `benchmarks/results/live/profile_core_*.json`):

| Measure | Value |
|---|---|
| Single-core full pipeline | 12,644 events/s (79.1 µs/event) |
| Per format (µs/event) | csv 58, w3c 58, leef 61, syslog 73, cef 82, json 84, kv 84, xml 138 |
| Top own-time functions | `apply_field_mappings` 6.3%, `enrich_event` 6.1%, `process_line` 5.2%, `new_unified_event` 4.4%, `build_normalized_event` 4.3%, SHA-256 3.6%, XML `_find_tag` 3.5%, `detect_format` 2.7% |

**Finding:** the profile is flat. No single function exceeds 7% of own time; the cost is Python object construction across detect → parse → normalise → enrich. A compiled tokenizer or detector alone would not move throughput meaningfully. Phase F will therefore move the **whole built-in-format path** (detect, parse, normalise, enrich to a columnar row) into the compiled core, with the Python pipeline as the reference and fallback (APG-learned formats, plugins).

**Live baseline, 8.2 path** (`python -m benchmarks.live.harness --target legacy …`; listener → shared queue → 3 worker processes → DuckDB):

| Run | Sent | Persisted | Loss | Persisted events/s | Drain lag |
|---|---|---|---|---|---|
| TCP, unpaced, 200k mixed lines (9 formats) | 200,000 | 200,000 | 0 | 17,246 | 11.0 s |
| UDP, 15,000/s offered, 100k lines | 100,000 | 100,000 | 0 | 12,849* | 1.1 s |

\* UDP throughput is bounded by the offered rate (100k lines over ~6.7 s); it is not a ceiling.

## Architecture for phases B–E

- **Input journal (host).** Every accepted line is appended to a segmented on-disk journal with source, receive time, a monotonically increasing sequence number and its SHA-256, before the input acknowledges it. The journal is the input WAL (durability), the raw archive (requirement a), the index for raw retrieval (requirement d) and the feed for evidence seals (U2). In defence mode its segments are encrypted (AES-256-GCM).
- **Source-affinity workers.** A dispatcher sends each source to a fixed worker process, so per-source state (W3C headers, multiline, drift) stays consistent. Workers run the pipeline, evaluate routes, and write sink-encoded segments into each sink's disk buffer.
- **Exactly-once into buffers.** Segment names carry the journal sequence range, and event IDs are derived from (node, sequence). Replay after a crash rewrites the same names and IDs, so buffers never receive duplicates and idempotent sinks (Elasticsearch `_id`, DuckDB) stay duplicate-free.
- **Sink senders (host).** One thread per sink reads its buffer in order, delivers with retry and jitter, sends permanent failures to the dead-letter queue, and applies the `when_full` policy.
- **Commit watermark.** The journal's committed sequence advances once every sink segment for a range exists, which bounds replay after a crash.

## Phases B–E2 — Runtime, connectors, USPs live, extensibility (done)

**Test suites** (all on this machine, `python -m unittest tests.<module>`):

| Suite | Tests | Covers |
|---|---|---|
| `test_core`, `test_platform_and_listener`, `test_service_and_gui`, `test_audit_fixes` | 39 + 14 + 14 + 6 | 8.x baseline, unchanged and passing |
| `test_runtime` | 22 | config (line numbers, modes, waivers), journal (encryption, torn tail, tamper, retention), buffers, router, views, seals, audit log, TCP → store exactly-once, crash replay, input restart |
| `test_outputs` | 7 | all 11 output types against local fakes with exact counts; Elasticsearch outage with no loss or duplicates; partial rejection to the DLQ with reasons; SigV4 test vector; CEF escaping |
| `test_inputs` | 8 | file tail (rotation, copy-truncate, multiline stack traces, restart exactly-once), container decoders (Docker, CRI, journald), HTTP and OTLP (JSON and protobuf, gzip, auth), syslog TLS (octet-counted and newline), NetFlow v5/v9, SNMP v2c trap and inform ack, SNMPv3 authPriv (wrong key rejected), live Windows event channel, CloudTrail SQS+S3, Pub/Sub, Okta, Entra ID (paging, cursors, acks only after journaling), defence-mode cloud ban |
| `test_usp` | 13 | U1–U5 on the live runtime (below), offline MaxMind-format GeoIP |
| `test_extensibility` | 13 | source onboarding, parser plugins, schema registry, raw traceability, ML export |

Not exercised here: MQTT, Kafka and Event Hubs inputs/outputs need a broker or SDK that is not installed; their code paths are covered by config validation only.

**USP acceptance (plan section 2), reduced volume:**

| USP | Test | Result |
|---|---|---|
| U1 | 1,300 lines of an unseen PLC format over TCP | parser learned from the first 300 lines without restart; ≥ 99 % of the next 1,000 parsed by it (`auto_detected`) |
| U1 | same in defence mode | parser held as `pending_approval`, used by 0 events until approved, then ≥ 99 % |
| U1 | `learning.max_parsers_per_source` | second format from a capped source not learned; another source still learns it |
| U2 | 5,000 events, seals every 1,000 | all seals verify against journal and store; an edited `source_ip` (row MAC), a nulled MAC and a rewritten `raw_hash` are each reported at the exact record |
| U3 | 7 formats × unified/ECS/OCSF | golden files in `tests/golden/views/`; views are pure; store, Elasticsearch and file outputs receive identical canonical fields |
| U4 | default config, 500 events | egress guard recorded no outbound destination in host or workers |
| U4 | defence mode | in-process `connect`/`sendto` to a non-allow-listed address raises `PermissionError` before any packet; route probe exempt; guard released on stop; config rejects an unlisted output |
| U5 | vendor renames JSON fields after 600 lines | one `drift` event, raised within 1,000 lines of the change; stable stream raises none |
| U5 | 5-step kill chain across two inputs | one correlation group of exactly 5 events with kill-chain stages, emitted when event time passes the window |

**Live throughput after the new features** (same harness as Phase A: `runtime` target, TCP, 200k mixed lines, 3 workers; `benchmarks/results/live/runtime_tcp_20261021_*.json`):

| Configuration | Persisted events/s | Loss |
|---|---|---|
| Industry defaults (journal, evidence seals, drift, anomaly, correlation, egress guard) | 15,042 | 0 |
| Industry + `evidence.row_mac: true` (defence default) | 12,533 | 0 |
| Evidence disabled | 14,853 | 0 |
| Single-core pipeline (`profile_core`) | 11,945 | — |

The per-row MAC (keyed BLAKE2b over every stored column) costs ~17 %, so it is on by default only in defence mode. Variation between identical runs on this laptop is about ±5 %.

**Defects found and fixed while building the tests** (each has a regression test):

- UDP listeners on Windows stopped after an ICMP port-unreachable (`WSAECONNRESET`); NetFlow, SNMP and syslog UDP now disable it.
- An omitted optional config section with a required key (e.g. `multiline`) failed validation, which broke every file input without multiline.
- Learned parsers were stored in a global directory instead of the node's data directory; `learning.max_parsers_per_source` was accepted but not enforced.
- Store verification compared only `raw_hash`, so edits to other columns went unnoticed (now the row MAC).
- GeoIP: documentation ranges were given United States coordinates by the bundled table, and a re-imported table kept deleted prefixes. Special-purpose ranges are now labelled, never located; real GeoLite2/GeoIP2/DB-IP `.mmdb` files are read offline when present.
- First-seen-IP anomalies fired for every new address after 50 events (87 alerts for 400 benign lines); live streams now alert only for public IPs once the population is stable. The `anomaly_type` field of anomaly events was always empty.
- sshd authentication lines did not yield `user.name` or `source.port`.
- Cloud inputs and token fetches leaked HTTP connections.

## Phase F — Performance core (done; result: Python stays the default path)

**Profile of the live runtime** (py-spy across host and workers, 200k TCP lines, 3 workers): the 3 workers were saturated, while the host used about half of one core. Time per event inside a worker was about 200 µs:

| Worker share | Function |
|---|---|
| 47 % | `process_line` (detect, parse, normalise, enrich) |
| 25 % | DuckDB segment encode (`event_to_row` 14 %, of which JSON 8 %; Arrow 4 %; Parquet 5 %) |
| 6.5 % | `event_id` (UUID object construction) |
| 5 % | anomaly detection |

**What was built.** `native/ulpf_core` is a Rust (PyO3, stable ABI) drop-in for `build_normalized_event`, the normalisation core every parser ends in. It handles only inputs whose Python semantics it reproduces exactly, and calls the Python function for everything else. `tests/test_native.py` runs every demo file, the edge cases and a 20,000-line generated corpus through both paths and requires identical output, key order included; it also runs 3,000 Hypothesis timestamp cases. The build needs neither maturin nor Python headers: `scripts/build_native.ps1` / `.sh` links `python3.dll` with the GNU toolchain.

**Measured result.** The native builder takes 18.6 µs per event and the Python one 16.4 µs. Pipeline throughput is unchanged (13.0k against 13.1k events/s on a single core). Building nested Python dicts through the C API costs as much as the Python dict literals it replaces, and every downstream stage (plugins, analytics, views, sinks) consumes those dicts. A real speed-up would need a fully columnar path (parse straight to Arrow), so this is not a multiplier claim. The core is therefore **opt-in** (`ULPF_NATIVE=1`) and kept under the equivalence tests.

**What did help:**

| Change | Effect |
|---|---|
| `event_id` formatted directly (same IDs, equivalence-tested) | 5.6 µs instead of ~13 µs per event |
| orjson without `OPT_NON_STR_KEYS` unless needed | ~4 µs per event less JSON work |
| Scaling workers (the runtime is shared-nothing between workers) | 3 workers 15,042 ev/s → 6 workers **27,460 ev/s**, 0 loss (`runtime_tcp_20261021_222655.json`) |

The bug found by the equivalence corpus: integer fields above 2⁶³ (e.g. `rcvdbyte=99999999999999999999`) reached the encoder, which cannot serialise them, so the whole batch failed. They are now dropped from the unified field and kept in `parsed_fields` and `raw_event`.

## Phase G — Control plane and operations (done)

`tests/test_operations.py` (5 tests):

| Item | Result |
|---|---|
| API roles over TLS | read / write / admin keys created with `ulpf apikey new` (only SHA-256 digests stored); 401 without a key, 403 for an insufficient role, ingest with write, reload with admin |
| Reload | an invalid edit is rejected with the error list while the running pipeline keeps ingesting; a valid edit (new output and route) rebuilds the stage with no loss |
| Multi-node | rendezvous hashing over live nodes, so only the dead node's inputs move; two runtimes sharing a directory run a `placement: one` file input on exactly one node; after the owner stops, the other node takes over within the failover time and resumes from the shared checkpoint: 500 of 500 lines stored, none twice |
| Service files | `deploy/systemd/ulpf.service` (hardened, `systemctl reload` = SIGHUP); NSSM steps in `docs/INSTALLATION.md` |
| Docker | the image now runs the live pipeline (`config/pipeline.docker.yaml`); ports 8000, 5514/tcp+udp, 6514. Docker is not installed on this machine, so `docker compose up` was not run. The container command, run locally, served `/api/v1/health` (200) and journaled a syslog line |

A defect found by the failover test: during shutdown, the cluster callback could restart an input after the journal had closed. Shutdown now blocks restarts and take-overs.

## Phase H — Verification, chaos, soak, documentation (done)

**Chaos tests** (`tests/test_chaos.py`, 6 tests; the outage lasts `ULPF_CHAOS_OUTAGE_S` seconds, 15 in CI, 600 for the full plan run):

| Failure | Result |
|---|---|
| kill -9 of the whole process tree during file ingest, then restart | 6,000 of 6,000 lines stored, none twice |
| Elasticsearch down while 20,000 events arrive | nothing delivered during the outage, all 20,000 after, no duplicates, nothing dead-lettered |
| Buffer full, `block` | ingest stalls (back-pressure reaches the input), then 30,000 of 30,000 delivered |
| Buffer full, `drop_oldest` | delivered + counted drops = 30,000 exactly |
| TCP input partition | every line written to a connection that survived is stored; only lines in the cut connection's kernel buffer can be lost (TCP behaviour) |
| Permanently rejecting sink | 20,000 events in the DLQ, which stays within `dlq.max_mb` plus one rotation file, with evictions reported |

**Defects these tests and the soak found, all fixed with regression tests:**

- `block` mode deadlocked when later batches filled the buffer, because they could not drain before an earlier one. A segment larger than the whole buffer could never be written.
- A batch interrupted by shutdown was sent to the DLQ even though the journal replays it; it is now reported as aborted.
- The DLQ overshot its cap by a whole rotation file.
- Shutdown races: journal reads after close; input restarts and cluster take-overs during stop; buffer statistics racing segment deletion, which crashed `/api/v1/runtime/status` under load.
- Pre-9.0 Parquet spool shards could not be ingested after the schema gained a column, and were retried forever.
- The DuckDB memory cap (fixed 4 GB) and WAL checkpoint (fixed 1 GB) did not fit small machines; both now scale with RAM.
- Log DNA batch drift: reordered tokens went undetected, and JSON with optional keys raised false alarms. Integrity-suite section 15 now passes with 0 false positives and 0 false negatives.
- ML export timestamps could not be read on Windows (no time-zone database); they now use a fixed UTC offset.

**Final throughput on the final code** (idle machine, 2026-10-22):

| Configuration | Persisted events/s | Loss | Result file |
|---|---|---|---|
| 3 workers, industry defaults | 17,034 | 0 | `live/runtime_tcp_20261022_024708.json` |
| 6 workers, industry defaults | 26,952 | 0 | `live/runtime_tcp_20261022_024737.json` |
| 3 workers, `evidence.row_mac: true` | 15,030 (−12 %) | 0 | `live/runtime_tcp_20261022_024758.json` |
| 1 node × 3 workers / 2 nodes × 3 workers, same 4-core host | 16,927 / 20,934 (×1.24) | 0 / 0 | `multinode/multinode_2x3_20261022_024851.json` |

The 2-node ratio is bounded by this host: 8 workers and 2 host processes share 4 physical cores. It shows the multi-process layout costs nothing extra, not how separate machines scale; that needs two hosts.

**Soak.** A first one-hour run (5,000 events/s) was invalidated because the laptop went to sleep after 16 minutes (Kernel-Power events 42/107, 02:01–02:42). Until then it ran at exactly 5,000/s with no backlog. After resume it caught up at about 14,000/s received, but persisted only about 7,000–9,000/s at 6.7 million stored rows. The store's ingest rate at large table sizes is therefore the limit to watch. `benchmarks/soak.py` now holds off system sleep and records Python's allocated blocks, to separate a leak from allocator or DuckDB growth.

| Soak run (5,000 events/s offered, 7 workers, TCP, DuckDB store) | Sent / persisted | Loss | Memory | Result file |
|---|---|---|---|---|
| 60 min, before the correlator fix | 18,000,000 / 18,000,000 | 0 | workers flat; host outside DuckDB +1.1 GB | `soak/soak_20261022_232711.json` |
| 60 min, after the correlator fix | 18,000,000 / 18,000,000 | 0 | workers flat (530–600 MB); host outside DuckDB median 430 → 1,790 MB per 10-minute window | `soak/soak_20261023_012358.json` |
| 9 min, file output instead of DuckDB | 2,700,000 / 2,700,000 | 0 | host flat at 70–77 MB, workers flat | `soak/soak_20261023_013352.json` |
| 9 min, DuckDB with allocator flushing | 2,700,000 / 2,700,000 | 0 | host outside DuckDB 194 → 549 MB (previously 650–850 MB at the same point) | `soak/soak_20261023_014340.json` |

The soak found a real leak, now fixed. Streaming correlation kept every group after its window closed (up to 5,000 groups × 10,000 events); `tracemalloc` traced 410 MB of retained projections in 150 s. Closed groups are now emitted and evicted, and open groups are capped. The file-output run shows the runtime itself (journal, seals, dispatch, analytics) is memory-flat.

The remaining host growth belongs to the embedded DuckDB store. Its native memory grows with the number of stored rows, beyond what `duckdb_memory()` reports and beyond `memory_limit`. Allocator flushing (`allocator_background_threads`, `allocator_flush_threshold`) reduces it but does not stop it. Guidance (docs/INSTALLATION.md): for sustained high volume, keep the DuckDB store for a retention window (`ulpf purge` / journal retention) and send bulk data to the Parquet lake or a SIEM output. Those outputs keep the host flat, as the file-output run shows.

**Competitive benchmark.** `benchmarks/competitive/` holds the configurations (Vector, Logstash, Fluent Bit) and the runner. None of these tools is installed on this machine, so no comparison is published.

**Final regression (2026-10-23, after every fix above):** 153 tests in 13 suites pass: core 39, platform 14, GUI 14, audit 6, runtime 22, outputs 7, inputs 8, USP 14, extensibility 15, operations 5, coverage 5, native 3, chaos 6. The integrity suite passes 6/6 sections and the APG evaluation passes.

## Phase I — Submission deliverables (done)

| Deliverable | Where | Check |
|---|---|---|
| Source code | this repository; `.gitignore` excludes the bundled interpreter, runtime state, build outputs and corpus files | Clean copy of the tracked files (360 files, 4.9 MB) passes 134 tests in 10 suites (core, platform, audit, runtime, USP, extensibility, inputs, outputs, operations, coverage); the wheel builds as 9.0.0 with the schema registry |
| README with setup | `README.md`, `docs/INSTALLATION.md`, `docs/AIR_GAPPED_DEPLOYMENT_GUIDE.md` | the five-minute run's commands were executed (container command, health, ingest) |
| Architecture document | `docs/ARCHITECTURE_DOCUMENT.pdf` (built by `docs/architecture_document/build.py`) | 2 pages, checked by the build |
| Presentation | `docs/PRESENTATION.pptx` and `.pdf` (`docs/presentation/build.py`) | 5 slides, checked by the build |
| Coverage report | `docs/PROBLEM_STATEMENT_COVERAGE.md` | every row names its test; open items listed |

**New capabilities added in phases B–G:** cluster mode (`ulpf cluster status`, `/api/v1/cluster/*`), `ulpf apikey new`, `ulpf reload`, egress guard (`ulpf.runtime.egress`), keyed row MACs, MaxMind DB reader (`ulpf.intelligence.mmdb`), parser plugin entry points with package-hash allow-list (`ulpf plugins list`), schema registry and `ulpf schema diff`, `ulpf source onboard`, Parquet ML export with a column card.

## Phase 7 — Compiled ingestion kernel and standard views (done; 100k EPS/core not reached)

The native lane (`ulpf_core`) now carries Sigma, routing, anomaly and drift, exports batches through the Arrow C Data Interface, and runs the network listeners on Tokio (`engine: auto`). Views: OCSF 1.3.0, Chronicle UDM and ASIM, validated against bundled catalogues and round-tripped.

| Mode (20k events, one Haswell core) | ev/s |
|---|---|
| Python worker, analytics on | 4.2k |
| Native lane, analytics on | 23.4k |
| Native lane, analytics off | 37.6k |
| Engine only | 55.1k |

Open items are under "Phase 7" in `docs/DEFERRED_WORK.md`.

## Phase 8 — Lakehouse (done)

Output type `lakehouse`:
- **Hot tier:** an mmap ring of Arrow batches.
- **Cold tier:** a Delta table, encrypted with AES-256-GCM, on local disk, S3, MinIO, Ceph or Azure.
- **Daemons:** flusher, compactor, retention and vacuum.
- **Queries:** sandboxed DuckDB federation and Arrow Flight.

Encrypted, 2M events, one core:

| Stage | ev/s |
|---|---|
| Worker encode (per process) | 23k |
| Hot append | 383k |
| Flush to Delta | 71k |
| Compaction | 90k |

Peak RSS 412 MB. Open items are under "Phase 8" in `docs/DEFERRED_WORK.md`.

## Phase 9 — Query languages and live tail (done)

KQL, SPL2 and LogScale HQL each have a parser and a shared logical plan, compiled to DuckDB SQL over the event store, the lakehouse, or Arrow batches. Errors report line and column. A workload governor provides fair share, memory caps and deadlines. Live tails run as row-level filters in the workers on every ingest batch.

Latency: 15–438 ms on 500k events, 8 CPUs, 2 threads per query. Open items are under "Phase 9" in `docs/DEFERRED_WORK.md`.

## Phase 10 — Detection engineering (done; the throughput target is not met)

- **Sigma:** the official SigmaHQ pack compiles and runs unmodified: 3,302 of 3,302 rules; 94.2% fire on their own test events; Rust and Python agree exactly. A compiled Aho-Corasick prefilter and logsource guards keep the cost low.
- **Sigma correlation rules** are supported.
- **YARA-L 2.0:** multi-event joins, hop and sliding windows, negation, outcomes.
- **Risk-based alerting:** decaying entity risk and Notable Incidents.
- **Throughput:** 1,000 SigmaHQ rules cost 17–21% of worker throughput, against the <5% target. Details under "Phase 10" in `docs/DEFERRED_WORK.md`.

## Phase 11 — UEBA, identity graph and asset context (done)

- **Identities:** identifiers of AD, UPN, Kerberos, LDAP, AWS IAM / STS and Linux resolve to one actor.
- **Assets:** a time-ranged asset CMDB and zones.
- **Detectors:** eight behaviour detectors and k-means++ peer groups, on the host; detections feed risk-based alerting.

## Phase 12 — Threat intelligence platform (done; <1 µs met for typical logs, not for URL-heavy events)

- **Indicators:** IPs, CIDRs, domains and wildcards, URLs, hashes, e-mail senders, mutexes and registry keys, with actor, campaign, kill-chain and Diamond Model metadata.
- **Feeds:** STIX 2.1 and TAXII 2.1 (with a cursor), MISP and OTX. Network feeds are off in defence mode unless allow-listed.
- **Decay:** per-kind half-life confidence decay.
- **Matcher:** a compiled Cuckoo-filter, Aho-Corasick and CIDR matcher, in both lanes.
- **Throughput:** with 2,000,000 indicators, matching costs 0.57 µs per typical event and 1.9 µs per URL / hash-dense event. Details under "Phase 12" in `docs/DEFERRED_WORK.md`.
