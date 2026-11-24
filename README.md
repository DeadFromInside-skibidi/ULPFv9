# ULPF — Universal Log Pre-processing Framework

> **SIH problem statement 26156.** ULPF converts any perimeter-device log into a standardised, lossless, analytics-ready representation, offline.
> **v10.0** adds SOAR, a forensic locker with HSM/TPM keys, Raft clustering, tactical-edge enforcement, a compliance matrix, an offline copilot and a web console (see [New in 10.0](#new-in-100)). The core is a live pipeline (inputs → durable journal → worker processes → outputs). It learns unknown formats from live traffic, seals every record into a tamper-evident chain, normalises to one schema with ECS and OCSF views, is verifiably offline by default, and runs drift, anomaly and correlation analytics on the stream. It has two operating modes: **defence** and **industry**.

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://python.org)
[![Storage](https://img.shields.io/badge/Storage-DuckDB-yellow.svg)](https://duckdb.org)
[![CI](https://img.shields.io/badge/CI-Linux%20%7C%20Windows-brightgreen.svg)](.github/workflows/ci.yml)

---

## Run the live SIEM on your machine

```bash
# Windows (bundled Python):   START_SIEM.bat
# Linux / macOS:              pip install -e ".[api]" && scripts/start_siem.sh
# Docker:                     docker compose up
```

Then open the **Web UI** at **http://127.0.0.1:8000/** (or the live SOC console at **http://127.0.0.1:8000/console/**) and point devices at it: syslog UDP/TCP **5514**, HTTP
`POST /api/v1/ingest/stream/<source>`, OTLP `/v1/logs`. No devices yet? `python scripts/log_sender.py`
sends realistic traffic. The Enterprise Web UI gives you full operational control across 10 specialized views:
Overview telemetry, Ingestion Engine, Columnar Log Explorer, Correlation, Log DNA, Statistical Anomalies,
Cryptographic Forensics, OCSF Schema, Universal Parsers, and Auto-Learn JIT. The live SOC console streams
cockpit metrics, Live Tail (KQL/SPL2/HQL), detections, and cases.

For full speed, install the prebuilt wheel with native core from the [v10.0.0 Release](https://github.com/DeadFromInside-skibidi/ULPFv9/releases/tag/v10.0.0) (`pip install <whl>`), run `START_SIEM.bat` (which automatically fetches the prebuilt native core if missing), or build it locally (`scripts/build_native.ps1` / `.sh`): the workers then use the Rust batch engine and Sigma IR automatically. The launch config is [config/pipeline.live.yaml](config/pipeline.live.yaml).

## New in 10.0

| Area | What you get | Start here |
|---|---|---|
| **SOAR & cases** | Incident lifecycle with SLA timers (MTTD/MTTR), evidence locker with chain of custody, DAG playbooks (branches, loops, parallel steps, sub-playbooks, retries), human-in-the-loop approvals with a four-eyes rule, dry runs, rollback, 13 bi-directional connectors (PAN-OS, FortiOS, Check Point, Cisco ASA, nftables, iptables, Wazuh, Defender, CrowdStrike, AD, Okta, Entra ID, AWS IAM) | `soar: {enabled: true}` · `ulpf soar playbooks` |
| **Forensic locker** | PKCS#11 HSM / YubiKey and TPM 2.0 key providers, encrypted one-time keys at rest, compiled Ed25519 + Merkle (`ulpf_core`), correlation no longer invalidates row MACs, air-gapped `ulpf-forensic-verify` (Python + Rust) that names the exact byte, bit and sequence of a tampered record | `ulpf forensic-kit ./kit` |
| **Cluster & fleet** | Embedded Raft (pre-vote, check-quorum, fencing-token leases, mTLS) replacing the shared directory, rendezvous ingest mesh, fleet control plane with enrollment, client certificates, signed configs and edge back-pressure | `cluster: {backend: raft}` · `ulpf fleet agent` |
| **Tactical edge** | MAVLink v2 signature authentication with replay protection, CCSDS PUS-A/PUS-C, hard memory ceilings (Job Objects / cgroup v2), kernel egress via eBPF or WFP | `limits: {hard_memory_mb: 512}` · `ulpf airgap os-policy --format ebpf\|wfp` |
| **Compliance matrix** | CERT-In (20 incident types, 6-hour report, NTP, 180 days), RBI CSF, SEBI CSCRF, SOC 2, ISO 27001:2022, PCI DSS v4.0 Req 10, sealed evidence bundles with PDF reports | `ulpf matrix run` · `ulpf certin report --case ID` |
| **Offline copilot** | Air-gapped GGUF / ONNX (DirectML, CUDA, CPU) inference, compiler-validated NL→KQL/SPL2/HQL, evidence-grounded triage narratives that refuse invented indicators | `ulpf copilot ask "top 10 sources with failed logins today"` |
| **Web console** | Multi-tenant RBAC, live SOC cockpit, query workbench, ATT&CK heat map, identity graph and flows, case board, playbook editor, compliance and fleet views; no CDN, strict CSP | `ulpf console` → `http://127.0.0.1:8000/console/` |

Release verification: the short suites run in CI (`tests/test_v10_*.py`); the long and hardware runs are in
[docs/LONG_TESTS.md](docs/LONG_TESTS.md). Full notes: [CHANGELOG.md](CHANGELOG.md).

## What it does

```
 syslog UDP/TCP/TLS · files · HTTP · OTLP · journald · Windows events · NetFlow · SNMP traps · MQTT · Kafka
 CloudTrail · Pub/Sub · Okta · Entra ID · Event Hubs
        │
        ▼
 JOURNAL  every record durable, SHA-256 hashed, sequence-numbered (AES-256-GCM in defence mode)
        │                      └─▶ EVIDENCE SEALS  rolling Merkle roots, chained and HMAC'd  [U2]
        ▼
 WORKERS  detect → plugin / 8 built-in parsers / learned parsers [U1] / raw fallback
          → unified schema [U3] → enrichment → drift + anomaly [U5] → routes
        │                                       host: cross-source correlation [U5]
        ▼
 BUFFERS  per output, on disk, exactly once (named by journal range)
        ▼
 OUTPUTS  DuckDB store · file · Parquet lake · S3 · Elasticsearch/OpenSearch · Splunk HEC · Kafka · Loki
          · OTLP · syslog (RFC 5424 / CEF / LEEF) · Azure Monitor · Chronicle      (unified | ECS | OCSF view each)
```

Egress guard [U4]: in every process, each outbound connection is recorded. In air-gap or defence mode, any connection not on the allow-list is blocked.

| Capability | How |
|---|---|
| **Lossless** | Every received byte is journaled before acknowledgement. `GET /api/v1/events/{id}/raw` and `ulpf raw get` return the exact original bytes, verified against SHA-256. |
| **No loss under failure** | A replayable journal, a persisted commit watermark, disk buffers per output, retries with back-off, and a dead-letter queue with reasons. Kill -9, sink outages, full buffers and input partitions are covered by `tests/test_chaos.py`. |
| **Any format** | 8 built-in parsers (CEF, LEEF, syslog 3164/5424, JSON, XML / Windows Event, key-value, CSV, W3C/IIS/CLF), plus container decoders. Unknown formats are learned (APG), and vendor plugins install through `ulpf.parsers` entry points. |
| **One schema** | A 100-field unified schema, versioned (1.1.0) with a registry and `ulpf schema diff`. ECS and OCSF views at any output. Nothing from the source is dropped (`parsed_fields`). |
| **Onboard a source in one command** | `ulpf source onboard --name plc --sample plc.log --config pipeline.yaml --write-config` |
| **Scale out** | Workers scale with cores. Shared-nothing nodes form a cluster with rendezvous-hashed placement, failover and fan-out queries ([docs/MULTI_NODE.md](docs/MULTI_NODE.md)). |
| **Operate** | Validated configs with line numbers, hot reload, API roles (read/write/admin) over TLS or mTLS, a hash-chained audit log, Prometheus metrics, a systemd unit, NSSM, and Docker. |

## Two modes

| | `industry` | `defence` |
|---|---|---|
| Learned parsers | active automatically (canary → active) | held as `pending_approval` until `ulpf parsers approve` |
| Journal | plain, `fsync` every 200 ms | AES-256-GCM, `fsync` per write |
| Outbound traffic | recorded and reported | allow-list enforced in process (`PermissionError`) and at config validation |
| Cloud connectors | allowed | refused |
| Listeners and outputs | TCP or TLS | TLS required |
| Stored rows | raw hash checked against the journal | every column MAC'd (keyed BLAKE2b) and verified |
| Parser plugins | installed plugins load | only allow-listed package hashes load |

A rule can be waived only by naming it in `overrides:`. Every waiver is printed at start-up and recorded in the audit log.

## The five USPs and their proof

| USP | Test (`tests/test_usp.py`, live runtime) |
|---|---|
| **U1 Autonomous format learning** | An unseen PLC format over TCP is learned from 300 lines without a restart; ≥ 99 % of the next 1,000 lines are parsed by the learned parser. In defence mode the parser waits for approval, and 0 events use it until then. |
| **U2 Tamper-evident evidence chain** | 5,000 events sealed in windows of 1,000. All seals verify against the journal and the store. An edited column, a nulled MAC and a rewritten hash are each reported at the exact record. |
| **U3 Unified schema everywhere** | Golden files for 7 formats × unified/ECS/OCSF. The store, Elasticsearch and file outputs receive identical canonical fields. |
| **U4 Offline by default** | The default config contacts nothing: the egress guard covers host and workers. In defence mode a socket to an unlisted address fails before any packet leaves. |
| **U5 Stream analytics** | A vendor field rename produces one drift event within 1,000 lines. A 5-step kill chain across two inputs becomes one correlation group. |

## Measured performance

All figures come from one Intel Core i5-8279U **laptop** (4 cores / 8 threads, Windows 10, Python 3.11). The traffic is 200,000 mixed lines of 9 formats over TCP into the DuckDB store, with journal, seals and all analytics on. Each figure has a result file in [`benchmarks/results/`](benchmarks/results/), and [docs/STATUS.md](docs/STATUS.md) lists the commands.

| Configuration | Persisted events/s | Loss |
|---|---|---|
| 3 workers, industry defaults | 17,034 | 0 |
| 6 workers, industry defaults | 26,952 | 0 |
| 3 workers + per-row MACs (defence default) | 15,030 | 0 |
| Single core, parse → normalise → enrich only | ≈ 12,500 | — |

Throughput grows with cores (1.6× from 3 to 6 workers on this 4-core laptop), and nodes add up. The soak result (memory over an hour) and the 2-node figure are in STATUS. ULPF does much more per event than a forwarder: it journals, hashes, normalises to a full schema, enriches and analyses every event. `benchmarks/competitive/` runs the same corpus through Vector, Logstash and Fluent Bit wherever those are installed.

---

## Five-minute first run

```bash
git clone <repo-url> ulpf && cd ulpf
python -m venv .venv && . .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[api]"
ulpf config check config/pipeline.example.yaml        # shows what it listens on and connects to
ulpf run                                              # built-in default: syslog TCP 127.0.0.1:5514 → local store
```

In a second terminal:

```bash
printf '<34>Oct 11 22:14:15 bastion sshd[901]: Failed password for root from 45.33.32.156 port 40001 ssh2\n' \
  | nc 127.0.0.1 5514                                 # or: python scripts/log_sender.py --file demo_data/mixed_formats.log --proto tcp --port 5514
curl -s localhost:8000/api/v1/events?limit=1          # the normalised event
curl -s localhost:8000/api/v1/runtime/status          # inputs, journal, outputs, egress, evidence
ulpf evidence list && ulpf evidence verify --check-store
```

Other entry points share the same engine and store: `ulpf process --files "demo_data/*.log"` (batch), `ulpf serve` (API only), `ulpf desktop` (PySide6 console), `ulpf tui`.

Installation for Windows, Linux (systemd), Docker, Windows service (NSSM) and air-gapped hosts is in [docs/INSTALLATION.md](docs/INSTALLATION.md) and [docs/AIR_GAPPED_DEPLOYMENT_GUIDE.md](docs/AIR_GAPPED_DEPLOYMENT_GUIDE.md).

## Commands

| Command | Purpose |
|---|---|
| `ulpf run [--config F] [--mode defence]` | The live pipeline |
| `ulpf config check\|show\|example` | Validate a config (all errors, with line numbers) and show listeners and destinations |
| `ulpf reload` / `systemctl reload ulpf` | Apply an edited config; an invalid file is rejected and nothing changes |
| `ulpf source onboard --name N --sample F` | Learn a new source from a sample and add it to the config |
| `ulpf parsers list\|approve\|reject` | Learned parsers; defence-mode approval |
| `ulpf plugins list` | Installed parser plugins and their package hashes |
| `ulpf evidence verify\|list\|prove` | Seals against journal and store; Merkle inclusion proof for one record |
| `ulpf raw get --event-id ID` | Original bytes of an event |
| `ulpf schema diff A B` | Schema compatibility (minor versions additive only) |
| `ulpf cluster status` | Nodes, heartbeats, input placement |
| `ulpf apikey new --role read\|write\|admin` | API keys (only digests stored) |
| `ulpf audit verify` / `ulpf dlq list` | Audit chain check; dead-lettered events with reasons |
| `ulpf export-ml -o features.parquet` | ML feature matrix (Parquet or CSV) with a column card |

The full reference is in [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md), and the API is self-documenting at `/docs`.

## Testing

```bash
python -m unittest tests.test_core tests.test_platform_and_listener tests.test_service_and_gui tests.test_audit_fixes
python -m unittest tests.test_runtime tests.test_inputs tests.test_outputs        # runtime and connectors
python -m unittest tests.test_usp tests.test_extensibility tests.test_operations  # USPs, onboarding, ops
python -m unittest tests.test_coverage                                            # MQTT, DB, EDR, Grafana, ML
python -m unittest tests.test_chaos                                               # failure injection
python -m benchmarks.integrity_suite && python -m benchmarks.apg_eval
python -m benchmarks.live.harness --target runtime --events 200000                # throughput, loss
```

Tests use temporary data directories and fake services on 127.0.0.1; they never touch your store or the network.

## Repository layout

```
ulpf/
  config/        pipeline schema, components, mode rules
  runtime/       supervisor, journal, dispatch, workers, buffers, sinks/, inputs/, evidence, egress guard,
                 cluster, audit, API server
  engine/        detector, pipeline, normaliser, schema + schema_registry/, views (ECS, OCSF), enricher
  parsers/       built-in parsers, plugin loader
  intelligence/  APG (auto_parser/), correlation, anomaly, Log DNA, MaxMind DB reader, intel DB
  storage/       DuckDB store          api/  FastAPI app      gui/  desktop     tui/  terminal UI
native/ulpf_core Rust drop-in for the normalisation core (optional, equivalence-tested; docs/STATUS.md)
benchmarks/      live harness, soak, competitive, integrity suite, APG evaluation
tests/           unit, integration, USP, chaos suites; golden view files
config/          example and Docker pipelines, GeoIP/IOC sample data
deploy/          systemd unit, Vector edge example        docs/  guides, architecture, status
```

License: MIT. Changes are listed in [CHANGELOG.md](CHANGELOG.md).
