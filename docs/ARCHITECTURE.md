# ULPF Architecture (v9)

The two-page summary for the submission is [ARCHITECTURE_DOCUMENT.pdf](ARCHITECTURE_DOCUMENT.pdf). This file is the engineering reference.

## 1. Processes and data flow

```
                     ┌───────────────────────────── host process ─────────────────────────────┐
 inputs (threads) ──▶│ Journal.append  (sequence, SHA-256, CRC, optional AES-256-GCM, fsync policy) │
                     │      │ listeners: CommitTracker · Sealer (Merkle windows, chained, HMAC)     │
                     │      ▼                                                                     │
                     │ Dispatcher ── bounded queue per worker (= back-pressure to the inputs) ──┐ │
                     │      ▲  results: counts, projections, derived events                     │ │
                     │      │                                                                   │ │
                     │ StreamCorrelator (cross-source)   AuditLog   API server   egress guard   │ │
                     │ SinkRunner thread per output: deliver segments ≤ persisted watermark      │ │
                     └──────────────────────────────────────────────────────────────────────────┼─┘
                                                                                                   ▼
                     ┌──────────────────────── worker process × N ────────────────────────────────┐
                     │ decode (container/journald) → detect → plugin | built-in | learned | raw    │
                     │ → unified event (event_id = UUIDv8(node, seq), evidence.journal_seq)        │
                     │ → enrich → anomaly + drift (derived events) → routes → encode per output    │
                     │ → DiskBuffer segment L-<from>-<to>-<n> (atomic rename)       egress guard   │
                     └─────────────────────────────────────────────────────────────────────────────┘
```

**Delivery guarantee.** A record is journaled before anything else happens to it. Segment names carry the journal range, and event IDs derive from (node, sequence), so replaying after a crash rewrites the same names and IDs. The commit loop flushes the journal and then persists the watermark; senders deliver only segments at or below the persisted watermark. As a result, every delivered event can be recovered from the journal and is never sent twice by the node. Idempotent outputs (DuckDB through its segment ledger, Elasticsearch `_id`) stay duplicate-free across replays. Input checkpoints (file offsets, cloud cursors) are persisted only once the records they cover are durable.

**Back-pressure.** Worker queues are bounded. When they are full, `ingest()` blocks: TCP, file, HTTP (429) and pull inputs slow down, while UDP counts what it cannot accept. Output buffers are bounded per output. With `block`, a full buffer stalls its workers without loss (a writer that is earlier in journal order than everything buffered never waits for it, which avoids an ordering deadlock). With `drop_oldest`, the oldest segments are dropped and counted.

## 2. Components

| Module | Role |
|---|---|
| `ulpf/config` | Pipeline schema, component catalogue, mode defaults and rules, line-numbered validation |
| `ulpf/runtime/supervisor.py` | `Runtime`: start, replay, reload, stop, input supervision, cluster placement, stats |
| `ulpf/runtime/journal.py` | Segmented append log, encryption, torn-tail repair, retention, read-only mode |
| `ulpf/runtime/dispatch.py` | Worker processes, source affinity, restart and resubmit, commit tracking |
| `ulpf/runtime/worker.py` | The pipeline per batch, analytics, routing, encoding |
| `ulpf/runtime/buffer.py`, `sinks/` | Disk buffers, 12 output connectors, retry/back-off, DLQ |
| `ulpf/runtime/inputs/` | 15 input connectors and their decoders |
| `ulpf/runtime/evidence.py` | Leaves, Merkle roots, seals, inclusion proofs, `verify_seals` (journal + store + row MAC) |
| `ulpf/runtime/egress.py` | Audit-hook egress guard: record or enforce |
| `ulpf/runtime/cluster.py` | Heartbeats, rendezvous placement, shared checkpoints, fan-out queries |
| `ulpf/runtime/analytics.py` | Derived events, drift monitor, stream correlator |
| `ulpf/engine` | Detector, parsers' shared normaliser, unified schema, schema registry, ECS/OCSF views, enricher |
| `ulpf/parsers` | Built-in parsers, plugin loader with package-hash allow-list |
| `ulpf/intelligence` | APG (auto_parser), correlation, anomaly, Log DNA, MaxMind DB reader, intel DB |
| `ulpf/storage` | DuckDB store: typed Arrow/Parquet ingest, segment ledger, row MAC column |
| `native/ulpf_core` | Optional Rust normalisation core (opt-in; equivalence-tested) |

## 3. Unified schema

The schema has 100 fields in 1.1.0 (`ulpf/engine/schema.py`, registry in `ulpf/engine/schema_registry/`). Every event carries `metadata.schema_version`. Minor versions are additive only; `ulpf schema diff` and the test suite enforce this. Source attributes without a unified field stay in `parsed_fields`, and vendor extensions use `extensions.x-<vendor>`. Views are pure functions applied per output: `unified`, `ecs` and `ocsf` (`ulpf/engine/views.py`, golden files in `tests/golden/views/`).

## 4. Security model

- **Modes**: `defence` enforces TLS listeners and outputs, an encrypted journal, the egress allow-list, a ban on cloud connectors, operator approval of learned parsers, row MACs, plugin hash allow-listing, and mTLS for a non-loopback API. Each rule can be waived only by name in `overrides:`, and waivers are printed and audited.
- **Keys**: the journal key (AES-256-GCM), the evidence key (seal HMAC, row MAC) and the parser-signing key live in the data directory with owner-only permissions. API keys are stored as SHA-256 digests.
- **Audit log**: hash-chained JSON lines for start, stop, reload, approvals, onboarding, key creation, evidence verification and cluster rebalancing (`ulpf audit verify`).

## 5. Store

DuckDB holds one `events` table; heavy JSON columns are read only for the requested page. Segment ingest is transactional, with a ledger of ingested segment names that makes it exactly-once. The buffer pool is capped at 25 % of RAM (at most 4 GB) and the WAL checkpoint at a quarter of that. A single process writes the store; others open it read-only.

## 6. Compliance with the problem statement

See [PROBLEM_STATEMENT_COVERAGE.md](PROBLEM_STATEMENT_COVERAGE.md) for every requirement, the artefact that implements it, and the test that proves it.
