# ULPF v9 Implementation Plan

Written for: Claude Opus 5.5, implementing the work in this repository. The project owner reviews each phase before the next one starts.

---

## 0. Ground rules

1. **Read before changing.** Read `README.md`, `docs/ARCHITECTURE.md`, `CHANGELOG.md` and this plan. Then run the baseline suites (section 9) and record the results before any edit.
2. **Measure, don't assert.** No throughput, latency or loss figure goes into code, docs or the changelog unless it was produced by a script in `benchmarks/` on recorded hardware. Figures from the 8.2.0 docs are *historical* and must be re-measured in Phase A.
3. **Keep the suites green after every phase.** Every feature ships with tests in the same change.
4. **Privacy.** Never send the project owner's email address or any personal data to an external service, in a request, URL, log or payload. No telemetry, ever.
5. **Compatibility.** Existing CLI commands and REST routes keep working. Removals need a deprecation note in `CHANGELOG.md` first.
6. **Platforms.** Windows 10/11 is a primary platform, Linux is the server platform. Both must pass CI. macOS must at least import and run the CLI.
7. **Secrets.** No keys, certificates or passwords in the repository. Config references them by path or environment variable.
8. **Scope discipline.** Each phase must leave the product in a working, shippable state. If a phase is blocked (for example, no compiler toolchain), mark it blocked in `docs/STATUS.md` and continue with the next unblocked phase. Do not fake completion.
9. **Destructive actions.** Ask the project owner before deleting data, rewriting git history, or installing system-wide tools (for example Rust via rustup). Installing into the project's own environment is fine.

---

## 1. Baseline (8.2.0, as shipped)

| Area | State |
|---|---|
| Inputs | UDP and TCP syslog listener (RFC 6587 octet framing), file processing (CLI and desktop), paste, REST upload |
| Parsing | 8 built-in parsers plus learned parsers (APG) and a raw fallback. Every line yields exactly one event. |
| Normalisation | 93-field schema, UTC timestamps, 0–10 severity, 160 field aliases plus ECS dotted paths |
| Enrichment | Offline GeoIP and IOC feeds in `config/`, reloaded on change |
| Storage | DuckDB single writer, Parquet spool, grouped commits |
| Analysis | Streaming correlation with kill-chain mapping, anomaly detection (z-score, entropy), Log DNA fingerprints and drift |
| Evidence | SHA-256 per event at entry, hash chains, Merkle root with inclusion proofs, custody log, verifiable packages |
| Outputs | RFC 5424 syslog forwarder (UDP or TCP), JSON/CSV/ML export, REST API |
| Interfaces | CLI, FastAPI REST API (optional API key, Prometheus `/metrics`), TUI, PySide6 desktop app |
| Packaging | Dockerfile, docker-compose, offline wheel bundle script, PyInstaller spec |
| Tests | 73 passing (core 39, platform 14, GUI 14, audit 6) plus `qt_app --verify` |

**Gaps versus production log pipelines:**

- No durable input checkpoints. A crash can lose or duplicate lines from file or socket sources.
- No disk buffer or retry for outputs. A downstream outage drops data or blocks the process.
- No dead-letter queue for failed events.
- Only one output type is real: the SIEM forwarder. No Elasticsearch, Splunk HEC, Kafka, object storage, Loki or OTLP.
- No file tailing with rotation handling, no multiline joining, no HTTP or OTLP ingest, no TLS syslog.
- No declarative pipeline configuration. Pipelines are implicit in code and CLI flags.
- Hot path is pure Python. Per-core throughput is well below compiled collectors (Vector, Fluent Bit).

---

## 2. The five differentiators (USPs)

These must be present in the **live** pipeline, not only in the batch CLI. **Confirmed by the project owner. Do not change this list without written approval.**

| # | USP | What "live" means | Live acceptance test |
|---|---|---|---|
| U1 | **Autonomous format learning (APG)** | Unknown lines arriving on any input are sampled, mined, validated and promoted (canary → active) without restart, and the pipeline uses them | Stream a never-seen format over TCP; the first N lines produce raw fallback, after which ≥ 99% of lines are parsed by a learned parser and no restart occurs |
| U2 | **Tamper-evident evidence chain** | Every event is hashed at input. Chains are sealed continuously per time window or event count. The seal (Merkle root) is also emitted to outputs. | Ingest 100k events, seal, alter one stored row, verify fails at the right event; verify passes on untouched data |
| U3 | **Unified normalised schema** | Every output receives the same schema, with optional ECS and OCSF mappings applied at the output stage | Same input produces identical canonical fields at Elasticsearch, Kafka and file sinks (golden-file test) |
| U4 | **Offline / air-gap operation** | Zero outbound connections unless a destination is explicitly configured; air-gap mode refuses any destination not on an allow-list; all enrichment data is local | Run the full pipeline with network interfaces disabled (or sockets intercepted); with the default config, no outbound socket is opened; with air-gap mode, a non-allow-listed sink fails at config validation |
| U5 | **Stream analytics: Log DNA drift and correlation** | Drift and correlation run on the live stream. Drift alerts and correlation groups are emitted as events to outputs. | Replay a source whose delimiter changes mid-stream; a drift event is emitted within 1,000 lines; a 5-event kill-chain sequence across two sources is emitted as one correlation group |

**Conflict to resolve in design:** U4 (no outbound traffic) and general-purpose outputs (sending to other servers) pull against each other. The resolution is: outbound traffic is always opt-in, every destination is declared in the config, air-gap mode enforces an allow-list, and the startup report lists every open destination.

---

## 3. Target architecture (v9)

```
 INPUTS                                   CONTROL PLANE
 syslog UDP / TCP / TLS (RFC 5425)        pipeline YAML  ──► validator (ulpf config check)
 HTTP ingest (NDJSON / JSON)              REST API (auth roles, /metrics, /health)
 OTLP logs (HTTP protobuf / JSON)         CLI  ·  TUI  ·  desktop app
 file tail (rotation, multiline)          hot reload of pipeline config
 Kafka consumer (optional extra)
 journald (Linux) · EVTX (Windows)
        │  each input: durable checkpoint (WAL)
        ▼
 bounded queues ──► DECODE/FRAME ──► CORE (hot path)
                                     tokenise · detect · fingerprint · parse dispatch · normalise
                                     compiled core (Rust, PyO3) with Python reference fallback
                                     learned parsers (APG) run here, behind the validation gate
        ▼
 ENRICH (GeoIP, IOC, private/CGNAT) ──► EVIDENCE STAMP (SHA-256 at entry, rolling seal)  [U2]
        ▼
 ANALYSE (streaming): correlation · anomaly · Log DNA drift  [U5]  → derived events
        ▼
 ROUTER (conditions: source, severity, category, field exists)
        ▼
 OUTPUT SINKS, each with batching · retry with jitter · disk buffer · dead-letter queue
   DuckDB/Parquet store (canonical)  ·  Elasticsearch / OpenSearch bulk
   Splunk HEC  ·  Kafka producer  ·  S3-compatible or local Parquet with rotation
   Loki  ·  OTLP logs  ·  syslog UDP / TCP / TLS  ·  file (NDJSON)
   Each sink may emit ECS or OCSF view of the schema  [U3]

 DURABILITY
   input WAL: offsets for files, sequence numbers for sockets/HTTP where the peer supports it
   sink buffer: segmented on disk, size-bounded, when_full = block | drop_oldest (counted)
   DLQ: failed events with reason, source, raw hash, retry count

 SECURITY
   TLS on every network listener and sink where the peer supports it
   API keys with roles (read, write, admin); per-input allow-lists by source address
   air-gap mode: destinations must appear in the allow-list
```

---

## 3a. Operating modes

ULPF runs in one of two modes, chosen with `mode:` in the pipeline config or `--mode`. One codebase serves both. The mode sets defaults and enforces the stricter rules marked below. Any override of a mode default is logged and listed in the startup report. Mode rules are checked by `ulpf config check`, so an invalid combination fails validation.

| Behaviour | `defence` (air-gapped, classified or regulated) | `industry` (enterprise and cloud) |
|---|---|---|
| Outbound destinations | Allow-list only, enforced at startup and per send | Any destination declared in config |
| Startup network check | Refuses to start if a default route to the internet exists, unless `airgap.allow_route: true` is set and logged | Reports network reachability only |
| Cloud pull connectors (CloudTrail, Event Hubs, Pub/Sub, Okta/Entra) | Disabled | Enabled, opt-in per source |
| Cloud SIEM sinks (Sentinel, Chronicle) | Disabled | Enabled, opt-in per sink |
| Autonomous learning (APG) | Learned parsers enter quarantine and stay inactive until an operator runs `ulpf parsers approve <id>` | Learn and promote automatically (canary → active) |
| Learned or plugin parser integrity | Specs signed, plugin packages must match an allow-listed hash | Specs signed |
| Evidence seals | Mandatory. Every 1,000 events or 60 s, whichever comes first, signed with the installation key | Enabled by default. Every 10,000 events or 5 min |
| Raw event retention | Mandatory raw archive, encrypted at rest (AES-256-GCM), default retention 180 days | Raw archive optional, default 30 days |
| Config and parser changes | Signed, recorded in a hash-chained audit log | Recorded in the audit log |
| Operator actions (login, approve, purge, export) | Hash-chained audit log, exported on schedule | Audit log |
| TLS | Required on every network listener and sink | Recommended, configurable |
| API bind and auth | `127.0.0.1` by default, mutual TLS required for remote access | `127.0.0.1` by default, API key or role key for remote access |

Notes:
- The 180-day retention default is a reference point taken from the project's earlier benchmark document. **Opus must verify the current CERT-In direction text and the applicable sector rules before citing them in any deliverable.**
- Encryption at rest uses AES-256-GCM through the `cryptography` package. The project makes no FIPS 140-3 validation claim; the documentation must say so.

## 3b. Problem statement coverage

The project owner's problem statement is the acceptance contract for this plan. Each item below needs an implementing phase and an acceptance test. Opus maintains `docs/PROBLEM_STATEMENT_COVERAGE.md` as tests land. An item is marked covered only when a test passes or a demonstrated artefact exists, and the file names that test or artefact.

**Background and scope items**

| Requirement | Current state | Implementing phase | Acceptance |
|---|---|---|---|
| Logs from network devices | Syslog, CEF, LEEF, KV present. NetFlow/IPFIX and SNMP traps missing. | C (items 13–14), existing parsers | One integration test per format, exact event counts |
| Logs from servers and operating systems | Syslog, EVTX (Windows, extra), journald (Linux, extra) | C | Integration test per OS source |
| Applications | File tail, multiline, JSON, XML, CSV | C | Rotation and multiline tests |
| Databases | Missing as a class. Audit files and syslog routes exist once file tail is done. | C (item 15) | Test with a sample database audit file and a syslog feed |
| Cloud services | Missing. Pull connectors are needed. | C (items 16–17), industry mode only | Test against recorded API responses, with the connector failing closed in defence mode |
| Containers | Missing. Container and Kubernetes logs are file or journald sources with metadata. | C (item 18) | Test that container labels are attached to every event |
| Endpoint security tools | Covered through HTTP ingest and Kafka. No vendor-specific connectors. | C (items 4, 6) plus E2 onboarding | Onboarding test with an EDR JSON sample |
| Identity and access management | EVTX, syslog, and Okta or Entra pull (industry mode) | C (item 17) | Test with recorded Okta and EVTX samples |
| IoT devices | Missing. MQTT input needed. | C (item 19) | Test with an MQTT publisher in CI |
| Hardware and other platforms | Syslog and file. Covered by onboarding. | E2 | Onboarding test |
| Formats: Syslog, JSON, XML, CSV, CEF, LEEF, proprietary | All present. Proprietary coverage comes from APG. | Existing, E (U1) | Golden tests; APG evaluation |
| Current and future sources (universal, extensible) | Plugin interface missing. Schema extension not versioned. | E2 items 2–3 | Plugin install test; schema diff test |
| Billions of events per day | Single node today. Sizing in the plan is not yet demonstrated. | G (item 6), H (item 3) | 2-node measurement and sizing guide |
| Vendor-agnostic | Unified schema and views | E (U3) | Golden files for unified, ECS and OCSF views |
| Big Data and Data Lake integration | Parquet export exists. S3-compatible sink missing. | D (item 4) | Parquet written to S3-compatible test server and read back |
| AI and ML analytics | `export-ml` CSV exists | D (item 4), E2 item 5 | Parquet dataset loads and trains a baseline model in a test |

**Expected solutions a–k**

| Item | Requirement | Current state | Implementing phase | Acceptance |
|---|---|---|---|---|
| a | Preserve complete raw data without loss | SHA-256 and raw field kept. No archive. | B (item 4), E (U2), E2 item 4 | Integrity suite: byte-identical raw recovered for every event in a test set |
| b | Extract source-specific attributes | 8 parsers, APG, 160 aliases. Unmapped attributes dropped. | E2 item 3 (`x-` namespace) | Golden test: no unmapped attribute lost |
| c | Normalise into a common taxonomy | 93-field schema and categories | Existing, E (U3) | Golden tests |
| d | Traceability between normalised and raw events | `event_id` and `raw_hash`, no retrieval endpoint | E2 item 4, E (U2) | Round-trip test: raw endpoint returns the original bytes |
| e | Plug-and-play onboarding of new sources | APG exists, no single command | E2 items 1–2 | `ulpf source onboard` on a 200-line unknown sample |
| f | Unified visibility | Desktop overview, REST, no dashboard | D (item 1), H (item 5) | Grafana dashboard JSON validates and its queries run against the Elasticsearch sink in CI |
| g | Efficient SIEM and data-lake integration | Syslog only | D (items 1–3, 4, 6, 10) | Per-sink tests, including QRadar via LEEF syslog |
| h | AI and ML-ready analytics | Export only | D (item 4), E2 item 5 | Test as above |
| i | Reduced parser development effort | Not measured | E2, H | Report the measured time from sample to active parser, with the dataset |
| j | Deployable in an air-gapped network | Offline bundle exists | Mode `defence`, E (U4), I | Socket-intercept test with default config and defence mode |
| k | Packaged in a container | Dockerfile and compose exist | G (item 5) | `docker compose up` health check in CI |

**Sizing for "billions of events per day"**

One billion events per day is about 11,600 events per second on average. Plan for 50,000 events per second sustained across the cluster, which gives at least three times peak headroom. The per-node figure is set only after the Phase H measurement; do not state it earlier.

**Current gaps** (every item not yet present in the code): cloud pull connectors, container and Kubernetes collection, IoT and MQTT input, NetFlow/IPFIX and SNMP traps, database audit ingestion, raw retrieval endpoint, multi-node scale-out, source onboarding command, schema versioning and extension namespace, S3-compatible sink, Sentinel and Chronicle adapters, Grafana dashboard, and the submission documents.

## 4. Phases

Each phase lists goal, tasks, files and acceptance. Phase order matters: A and B must come first, E must come before the benchmarks in F are published.

### Phase A — Measure and decide (1–2 days)

**Goal:** a reproducible baseline on the target hardware, and confirmed USPs.

Tasks:
1. Create `benchmarks/live/` with a harness that runs the **live path** end to end: generator (syslog, CEF, JSON, KV mix from `demo_data/`) → listener → pipeline → store, reporting offered rate, accepted, parsed, persisted, lost (by stage) and latency P50/P95/P99.
2. Record hardware: CPU model, physical and logical cores, RAM, OS, Python and dependency versions. Save it next to every result as JSON.
3. Profile the hot path with `py-spy` (or `cProfile` if py-spy is unavailable) and store the flame graph or top-function table under `benchmarks/results/`.
4. Write `docs/STATUS.md` with the baseline table, the profile summary, and the list of blocked items (for example, "no C/Rust toolchain on this machine").
5. Record in `docs/STATUS.md` that the five USPs in section 2 are confirmed by the project owner, and that the two operating modes in section 3a are approved.

**Acceptance:** `benchmarks/live/` runs green; `docs/STATUS.md` contains measured baseline numbers with hardware; USPs confirmed.

### Phase B — Runtime, durability and configuration (3–4 days)

**Goal:** a supervised runtime with checkpoints, buffers and a declarative config.

Tasks:
1. **Pipeline config.** `ulpf/config/pipeline.py`: a YAML schema (add `PyYAML` to dependencies) with typed validation. Sections: `mode` (`defence` or `industry`, section 3a), `inputs`, `stages`, `outputs`, `routes`, `airgap`, `buffers`, `dlq`, `api`, `audit`, `retention`. Provide `ulpf config check <file>` (validate, print the open-destination list) and a default `config/pipeline.example.yaml`.
2. **Runtime supervisor.** `ulpf/runtime/supervisor.py`: starts inputs, stages and sinks as tasks or processes; wires bounded queues with explicit backpressure; restarts failed input adapters with exponential backoff; reports per-stage counters.
3. **Input WAL.** `ulpf/runtime/wal.py`: per-input checkpoint file written atomically (temp file, fsync, rename). Files: offset and inode. Sockets and HTTP: sequence numbers when the peer supplies them; otherwise at-most-once is documented for that input.
4. **Sink buffer.** `ulpf/runtime/buffer.py`: append-only segments on disk, fixed segment size, total size cap, `when_full: block | drop_oldest`, with drop counts exported as metrics. Reads are acknowledged by segment.
5. **Dead-letter queue.** `ulpf/runtime/dlq.py`: NDJSON segments containing the raw line, source, reason, first-seen time and retry count. Configurable retention.
6. **Retry policy.** Shared helper: exponential backoff with jitter, max attempts, per-error classification (retriable vs. permanent).
7. **Metrics.** Per-stage counters and gauges exposed on `/metrics` (Prometheus names prefixed `ulpf_`).

Files: `ulpf/config/`, `ulpf/runtime/`, `tests/test_runtime.py`, `tests/test_config.py`, `config/pipeline.example.yaml`.

**Acceptance:** configs with an unknown key or a bad type fail `ulpf config check` with a line-numbered message; the supervisor restarts a killed input; WAL survives kill -9 with no duplicate or missing line for file input (tested); sink buffer survives a restart.

### Phase C — Inputs (4–6 days)

**Goal:** the sources a real deployment has.

Tasks, in priority order:
1. **Syslog TLS (RFC 5425)** on the existing listener: certificate, key and optional client-CA paths from config.
2. **File tail**: inode-aware, handles truncation and rotation, persists checkpoints (WAL from B), supports glob patterns and `start_from: beginning|end`.
3. **Multiline joining**: start-pattern based (for stack traces, Java, Windows multi-line events), with max-lines and timeout.
4. **HTTP ingest**: `POST /api/v1/ingest/{source}` accepting NDJSON or a JSON array, gzip bodies, per-source API keys, size limits, and a 429 response when queues are full (backpressure to the client).
5. **OTLP logs receiver**: HTTP protobuf and JSON (`/v1/logs`). Map OTLP `LogRecord` to the unified schema. gRPC is optional and must be behind an extra.
6. **Kafka consumer** (optional extra `ulpf[kafka]`): consumer groups, manual commit after the sink acknowledges (at-least-once).
7. **journald** (Linux, optional extra) and **EVTX** (Windows, optional extra `python-evtx`): both as inputs with checkpoints.
8. **Container and Kubernetes logs**: file or journald sources that attach container, pod, namespace and image labels from the runtime metadata. Labels become `x-container.*` fields.
9. **Database audit ingestion**: file tail and syslog routes with a documented setup for common audit outputs (Oracle, SQL Server, PostgreSQL, MySQL). Native database-protocol connectors are out of scope.
10. **MQTT** (IoT, optional extra `ulpf[mqtt]`): subscribe with TLS and client certificates, QoS 1 with checkpoints by message identifier.
11. **Cloud pull connectors** (industry mode only, each opt-in): AWS CloudTrail through S3 and SQS notifications, Azure Event Hubs, Google Pub/Sub. Each has a recorded-response test and fails closed in defence mode.
12. **Identity pull connectors** (industry mode only): Okta System Log and Microsoft Entra ID audit logs over REST with cursor checkpoints.
13. **NetFlow v9 and IPFIX collector** (UDP): template handling per exporter, flow records mapped to network fields, template cache persisted.
14. **SNMP trap receiver** (UDP): SNMPv2c and v3 with configured credentials, trap OID mapped to category.
15. **Source-class integration tests**: one test per class above, using a recorded or generated sample, asserting exact event counts.

Each input: rate limit per source, max line length, connection limit, and a self-test in `ulpf config check`.

**Acceptance:** each input has an integration test that feeds a known corpus and asserts exact event counts; file tail survives rotation in a test; OTLP test uses an official sample payload; HTTP returns 429 under a saturated queue.

### Phase D — Outputs (4–6 days)

**Goal:** the sinks a real deployment has. Each sink implements one interface: `open()`, `write_batch(events)`, `flush()`, `health()`, `close()`. Buffering, retries and the DLQ are shared runtime code, not per-sink code.

Tasks, in priority order:
1. **Elasticsearch / OpenSearch bulk**: batch by size and time, index naming with date pattern, ECS view option, partial-failure handling (per-item status, failed items to DLQ).
2. **Splunk HEC**: token auth, `sourcetype` and `index` from routing, batch limits from HEC defaults, ack mode when enabled.
3. **Kafka producer** (extra): keyed by source for ordering, `acks=all`, compression, idempotent producer.
4. **S3-compatible / local Parquet**: rotation by size or time, Hive-style partitioning (`dt=`, `source=`), written atomically (temp key, then rename or complete multipart).
5. **Loki**: push API with stream labels from routing.
6. **OTLP logs exporter**.
7. **Syslog** (existing forwarder, reworked onto the sink interface): UDP, TCP, TLS.
8. **File (NDJSON)** sink with rotation.
9. **DuckDB store** stays the canonical local store. It becomes a sink like the others, so the same routing applies.
10. **Cloud SIEM adapters** (industry mode only, opt-in): Azure Log Analytics HTTP Data Collector and Google Security Operations (Chronicle) ingestion API. Each uses the same sink interface and allow-list.
11. **Grafana dashboard template** ships with the Elasticsearch sink (used by item f in section 3b).

Routing: `routes` in config select sinks by condition (source, severity, category, field present). Each event goes to every matching sink. Events matching no route go to the default sink and are counted.

**Acceptance:** each sink has a test against a local fake server (in-process HTTP server for ES, HEC, Loki and OTLP; a Kafka test broker is optional and skipped in CI when absent); a sink outage of 10 minutes in a test loses zero events once the sink returns (buffer drains); a permanently rejected event lands in the DLQ with a reason.

### Phase E — USP integration in the live path (4–5 days)

**Goal:** U1–U5 work on live traffic, not only in batch commands. **Do this before the Phase F benchmarks are published.**

Per USP:

**U1 — APG live.**
- Learned parsers are applied in the core stage, after built-in parsers and before the raw fallback. Keep the existing lookup order and document it.
- Autonomous learning consumes unknown lines from every input, with per-source rate limits (existing quarantine logic) and a cap on learned parsers per source.
- Every learned parser is observable: state, hit count, error count, and a `ulpf parsers list` command.
- Canary errors demote a parser to retired automatically (existing lifecycle logic) and emit an event.

**U2 — Evidence chain live.**
- The SHA-256 of the raw line is computed at input, before any parsing, and carried on the event.
- A rolling seal is written per window (configurable by count or time). Each seal records the chain head, event range, Merkle root and the previous seal's hash. Seals are written to a local evidence directory and emitted as events to the `evidence` sink.
- Add `ulpf evidence verify --from <seal> --to <seal>` to recompute from stored events.
- Stored events cannot be silently changed: the store records a per-row checksum, verified on read in verify mode.

**U3 — Unified schema at every sink.**
- Canonical event is produced once. Sinks request a view: `unified` (default), `ecs`, or `ocsf`. Views are pure functions with golden-file tests.
- The unified schema version is written into every event and every seal.

**U4 — Offline by default.**
- Default config has no outbound destinations. Startup prints a report: open listeners, open sinks, network reachability by interface.
- `airgap: true` in config makes any sink whose host is not in `airgap.allow` a validation error.
- The integrity suite (`benchmarks/integrity_suite.py`) gains a test that runs the live pipeline with default config and asserts no outbound socket.

**U5 — Stream analytics live.**
- Log DNA drift runs per source on a sliding sample; on drift, emit a `drift` event with the changed fields (existing `detect_drift` output).
- Correlation runs on the stream with the existing bounded-memory design; emit a `correlation` event per group when the window closes.
- Anomaly detection emits `anomaly` events.
- Derived events carry the `correlation_id` or `source_event_ids` so analysts can trace them.

**Acceptance:** the five live acceptance tests in section 2 pass in CI (they may run with a reduced volume in CI and full volume in `benchmarks/live`).

### Phase E2 — Source onboarding, extensibility and raw traceability (3–4 days)

**Goal:** a new source goes live in minutes without custom code, the schema can grow without breaking consumers, and every normalised event can be traced back to its exact original bytes.

Tasks:
1. **`ulpf source onboard --name <source> --sample <file> [--mode defence|industry]`**: runs the sample through detection, measures parse coverage, runs APG, validates the result, and writes a source entry into the pipeline config. In defence mode the learned parser is placed in quarantine until approved. The command prints coverage, the template, and the elapsed time (used for item i in section 3b).
2. **Parser plugin interface**: entry-point group `ulpf.parsers`, so third parties can publish parsers as installable packages. In defence mode a plugin loads only if its package hash is on the allow-list.
3. **Schema versioning and extension**: `schema_version` written into every event and seal. Minor versions are additive only. Unmapped source attributes are kept under `x-<vendor>.<field>`, so no data is dropped. The schema registry lives in `ulpf/engine/schema_registry/`, and `ulpf schema diff <old> <new>` flags incompatible changes.
4. **Raw retrieval**: `GET /api/v1/events/{event_id}/raw` and `ulpf raw get <event_id>` return the byte-identical original line, read from the raw archive, and verify it against `raw_hash`.
5. **ML-ready feature export**: `export-ml` writes Parquet as well as CSV. The dataset documents each column's type and whether it is numeric, categorical or a timestamp.
6. **Source catalogue**: `docs/SOURCES.md` lists each supported source class, its formats, and its status (built-in, APG-learned, or plugin).

**Acceptance:** onboarding a new format from a 200-line sample completes in one command and yields a validated parser; a plugin package installs through its entry point and is used; schema diff detects a removed field; raw retrieval returns bytes whose hash matches for 100% of a test set.

### Phase F — Performance core (6–10 days; toolchain install permitted)

**Goal:** a compiled hot path, and an honest published comparison.

Permission granted by the project owner: install the Rust toolchain (`rustup`, stable channel, into the user profile) and the Microsoft C++ Build Tools on Windows (needed for the MSVC linker). If an install needs administrator rights or fails, stop, record the blocker in `docs/STATUS.md`, and continue with F4–F5 on the Python path.

Tasks:
1. **Profile-guided choice.** Using Phase A's profile, confirm the hot functions (expected: tokeniser, detector, fingerprint, normaliser field mapping, JSON decode). Only these move.
2. **`ulpf_core` crate** (Rust, PyO3 via maturin, under `native/ulpf_core/`): batch API `process_batch(lines: list[bytes]) -> columnar result` returning Arrow arrays. Python reference implementation stays in `ulpf/engine/`.
3. **Equivalence tests.** Golden corpus (every demo file plus synthetic cases) must produce identical output from the Rust and Python paths. Property tests (hypothesis) for tokeniser and fingerprint. A failing equivalence blocks the merge.
4. **Fallback.** If the extension fails to import, the Python path runs and a warning is logged once. CI runs both paths.
5. **Transport.** Workers send Arrow IPC to the writer instead of Parquet shards for in-memory handoff; keep Parquet spool for crash recovery only.
6. **Listener scaling.** One socket per worker with `SO_REUSEPORT` on Linux; a single socket plus the existing dispatcher on Windows.

**Acceptance:** equivalence tests green; profile shows the expected hot-path reduction; measured throughput recorded with hardware. **Do not write a multiplier or target number into the docs until it is measured.**

### Phase G — Control plane, security and operations (3–4 days)

Tasks:
1. **API auth:** keys with roles (`read`, `write`, `admin`). Existing single `ULPF_API_KEY` remains as an alias for an admin key.
2. **TLS** for the REST API (`--tls-cert`, `--tls-key`).
3. **Config hot reload:** `ulpf reload` or `SIGHUP` on Linux. Reload validates first and applies only if valid; sinks are restarted gracefully.
4. **Service files:** systemd unit example in `deploy/systemd/`, Windows service instructions (NSSM) in `docs/INSTALLATION.md`.
5. **Docker:** update the image and compose file for the new ports (TLS syslog, HTTP ingest, OTLP) and the config volume.
6. **Multi-node ingest** (required for the billions-per-day scope): ingest nodes are independent. Each source is assigned to one node by a stable hash of its identifier, so parser state and checkpoints stay on one node. A static node list in config comes first; discovery is optional. `ulpf cluster status` shows nodes, heartbeats and source assignments. When a node stops heartbeating, its sources move to the next node on the hash ring and resume from the shared checkpoint store. The checkpoint store is a shared directory or object store; the choice is documented in `docs/MULTI_NODE.md`. The API can fan queries out to all store nodes and merge the results. `docs/MULTI_NODE.md` includes the sizing guide.

**Acceptance:** auth tests for each role; reload with an invalid config is rejected and the running config is unchanged; `docker compose up` passes the health check with the example config.

### Phase H — Verification, chaos and documentation (3–4 days)

Tasks:
1. **End-to-end CI job**: start the runtime with the example config, feed each input, assert each output received the right count and schema view. Runs on Linux and Windows.
2. **Chaos tests** (each must lose zero events, or document the exact loss):
   - kill -9 during file ingest: no missing or duplicated lines after restart;
   - sink down for 10 minutes: buffer drains, zero loss;
   - disk full in the sink buffer: `block` stalls ingest without loss, `drop_oldest` drops and counts exactly;
   - network partition on TCP input: client retries are accepted after recovery;
   - DLQ growth: bounded and reported.
3. **Soak test**: 1 hour at a fixed rate on the target hardware; memory must not grow more than a stated bound; results saved to `benchmarks/results/`. Then a 2-node run with the same workload: record the aggregate rate and the scaling ratio. The per-node figure in the sizing guide comes only from this measurement.
4. **Competitive benchmark** (`benchmarks/competitive/`): same corpus, same sink (file and DuckDB), same hardware, versus Vector and Logstash (and Fluent Bit if installed). Each tool's configuration file is committed. Report: events/s, CPU, memory, loss under TCP, and loss under UDP at the same offered rate. Publish the raw numbers and the commands. Report any case where ULPF is slower.
5. **Docs:** update `README.md`, `docs/ARCHITECTURE.md`, `docs/CLI_REFERENCE.md`, `docs/INSTALLATION.md`, `CHANGELOG.md` (version 9.0.0). Every number in docs must cite its result file.

**Acceptance:** all chaos tests pass or document their loss precisely; soak result saved; competitive results published with raw data; docs cross-checked against the code with no stale references (grep for removed commands and paths).

---

### Phase I — Submission deliverables (2 days)

**Goal:** the four items the problem statement asks for, checked against their limits.

Tasks:
1. **Source code link.** Public GitHub repository. Confirm that no runtime data, secrets, `python311/`, or caches are committed. Test a clean clone: `pip install -e .[api,gui]` followed by the baseline suites in section 9.
2. **README with setup instructions.** Covers Windows, Linux, Docker, the offline bundle for air-gapped hosts, a five-minute first run, and the verification commands. Opus follows the README verbatim on a clean environment and fixes any step that fails.
3. **Architecture document, two pages maximum.** Source in `docs/architecture_document/`, exported to `docs/ARCHITECTURE_DOCUMENT.pdf`. Covers components, data flow, the unified schema, the five USPs, the two modes, deployment, and sizing. Check the page count programmatically and fail if it exceeds two.
4. **Technical presentation, five slides maximum.** Built as `docs/PRESENTATION.pptx` (python-pptx, added as an optional extra) and exported to PDF. Covers the problem, the architecture, the live demonstration results, the measured benchmarks, and the coverage matrix. Check the slide count programmatically and fail if it exceeds five.
5. **Coverage report.** `docs/PROBLEM_STATEMENT_COVERAGE.md`, generated from section 3b, with the test or artefact that proves each row.

**Acceptance:** the clean-clone test passes; the README steps succeed verbatim; the architecture PDF has exactly two pages or fewer; the presentation has five slides or fewer; every row of section 3b is marked covered with evidence, or the report states the open gap.

## 5. Where ULPF should be better (and how to prove it)

Positioning rule: ULPF is not faster than Vector per core in Python. It must be better on the things those tools do not do well, and each claim needs a test.

| Claim | Proof |
|---|---|
| Learns unknown formats from live traffic without custom grok or config | U1 live test; `ulpf parsers list` shows learned parsers and their accuracy |
| Provides tamper-evident evidence chains out of the box | U2 verify test; `ulpf evidence verify` |
| One schema across all outputs, with ECS and OCSF views | U3 golden-file tests |
| Verifiably offline by default | U4 socket-intercept test; startup network report |
| Streaming drift and correlation on the same pipeline | U5 live tests |
| Same behaviour on Windows and Linux, with a desktop console | CI on both; `qt_app --verify` |
| Fully inspectable pipeline in one YAML file | `ulpf config check` output |

Where ULPF is slower, say so in the competitive report. Do not claim parity without the raw data.

---

## 6. Risks and decisions

| Risk | Mitigation |
|---|---|
| Python throughput ceiling | Phase F compiled core, measured; if not met, state the measured ceiling and recommend an external collector in front (`deploy/vector.toml`) |
| Scope too large | Phases are ordered so each one ships; B and C are the minimum for production use |
| U4 (offline) conflicts with outputs | Opt-in destinations, allow-list in air-gap mode, startup report of open destinations |
| Learned parsers in live path could misparse | Existing validation gate (≥ 90% accuracy, < 1 ms/line), canary window, automatic retirement, signed specs |
| Sink outages causing memory growth | Disk buffer with a hard cap; `when_full` policy; metrics for buffer fill |
| Windows-specific behaviour (file locks, rename semantics) | Tests on Windows in CI; atomic write helpers already exist and are reused |
| Dependency growth | Optional extras for Kafka, EVTX, journald, gRPC, S3 |
| No compiler on the current machine | Phase F blocked until the owner approves toolchain install; the rest of the plan does not depend on it |

---

## 7. Deliverables checklist

- [ ] `docs/STATUS.md` with baseline, profile, confirmed USPs and blocked items
- [ ] `ulpf/config/`, `ulpf/runtime/`, `config/pipeline.example.yaml`, `ulpf config check`
- [ ] Inputs: syslog TLS, file tail, multiline, HTTP ingest, OTLP, (Kafka, journald, EVTX as extras)
- [ ] Outputs: Elasticsearch/OpenSearch, Splunk HEC, Kafka, Parquet/S3, Loki, OTLP, syslog, NDJSON, DuckDB as a sink
- [ ] Routing with conditions; default sink; unrouted counter
- [ ] USP U1–U5 live tests passing in CI
- [ ] Evidence seals written to disk and to the `evidence` sink; `ulpf evidence verify`
- [ ] `native/ulpf_core/` with equivalence tests (if toolchain available)
- [ ] API roles, TLS, reload, systemd unit, updated Docker assets
- [ ] Chaos tests, soak result, competitive benchmark with raw data
- [ ] Docs and CHANGELOG 9.0.0, every number cited to a result file
- [ ] Operating modes `defence` and `industry` enforced by config validation and tests
- [ ] Source classes in section 3b (network devices, OS, applications, databases, cloud, containers, endpoint, identity, IoT) each with an integration test
- [ ] Raw retrieval endpoint and CLI, byte-identical round trip
- [ ] `ulpf source onboard`, parser plugin interface, schema versioning and `x-` extension namespace
- [ ] Multi-node ingest with `ulpf cluster status`, 2-node measurement, sizing guide
- [ ] Grafana dashboard template tested against the Elasticsearch sink
- [ ] `docs/PROBLEM_STATEMENT_COVERAGE.md` complete with evidence
- [ ] SIH deliverables: clean-clone test, README verified, architecture PDF at most 2 pages, presentation at most 5 slides
- [ ] Test suites green on Windows and Linux

---

## 8. Reporting back

After each phase, Opus writes a short entry in `docs/STATUS.md`:

1. what was built, with file paths;
2. tests added and their results (exact command and counts);
3. measured numbers, with the result file path and hardware;
4. what is blocked, and why;
5. any decision that changes the plan.

Do not start the next phase until the current phase's acceptance criteria are met or the project owner has accepted the gap in writing.

---

## 9. Baseline commands

```powershell
python -m unittest tests.test_core -v
python tests\test_platform_and_listener.py
python tests\test_service_and_gui.py          # QT_QPA_PLATFORM=offscreen on headless hosts
python tests\test_audit_fixes.py
python -m ulpf.gui.qt_app --verify
python -m benchmarks.apg_eval
python -m benchmarks.integrity_suite
```

Run each through `Start-Process` with output redirection on Windows if the console hangs, as done in this project's earlier sessions.

---

## 10. Start here (instructions for Opus 5.5)

1. Read sections 0–3b of this plan in full, then `README.md`, `docs/ARCHITECTURE.md` and `CHANGELOG.md`.
2. Run the baseline commands in section 9 and record the results in `docs/STATUS.md`.
3. Complete Phase A. Record the hardware and the measured baseline. Do not write any target number yet.
4. Continue phase by phase in the order given in section 4 (A, B, C, D, E, E2, F, G, H, I). Write a `docs/STATUS.md` entry after each phase, as section 8 describes, then continue without waiting for approval unless a phase's acceptance criteria are not met.
5. Stop and report to the project owner only in these cases: an install needs administrator rights, a change would alter a confirmed USP or the two-mode design, a requirement in section 3b cannot be met, or a documented number cannot be measured.
6. The Rust toolchain install is permitted. Use the user-profile `rustup` route and the Microsoft C++ Build Tools, as section F describes.
