# Problem-statement coverage (SIH 26156)

Each row names the artefact that implements the requirement and the test or measurement that proves it. "Open" marks what is not proven on this machine, with the reason.

## Source classes

| Source class | Implementation | Proof | Status |
|---|---|---|---|
| Network devices (firewalls, routers, switches, IDS/IPS) | syslog UDP/TCP/TLS input; CEF, LEEF, syslog, KV parsers; NetFlow v5/v9; SNMP traps v1/v2c/v3 | `test_inputs` (TLS framing, NetFlow, SNMPv3 authPriv, inform ack), `test_runtime`, `test_usp` | covered |
| Servers and operating systems | syslog, journald input, Windows event channels (`evtx`), XML parser for Windows Event | `test_inputs` (live System channel, journald decoder) | covered |
| Applications | file tail (rotation, copy-truncate, multiline, exactly-once restart), HTTP and OTLP ingest, JSON/XML/CSV parsers | `test_inputs`, `test_chaos` (kill -9 during file ingest) | covered |
| Databases | file or syslog input; JSON audit (MySQL Enterprise/Percona); proprietary layouts (PostgreSQL) via onboarding; database field aliases | `test_coverage.TestDatabasesAndEndpoints.test_database_audit_logs` | covered |
| Cloud services | CloudTrail (SQS+S3, SigV4), Pub/Sub, Okta, Entra ID, Event Hubs; refused in defence mode | `test_inputs` against recorded-shape fake APIs; defence ban tested | covered (Event Hubs: config only, SDK not installed) |
| Containers | Docker JSON and CRI decoders with pod/namespace/container labels; journald | `test_inputs.test_container_decoders` | covered |
| Endpoint security tools | HTTP/OTLP/Kafka/file ingest; EDR field aliases (CrowdStrike, Defender, SentinelOne, Elastic) | `test_coverage.test_edr_telemetry` | covered |
| Identity and access management | Windows Security events, syslog (sshd user and port), Okta and Entra pull | `test_inputs` (Okta paging, Entra sign-ins), golden `syslog_sshd` | covered |
| IoT devices | MQTT input (QoS 1, ack only after journaling) | `test_coverage.TestIoT` (paho client against an in-test MQTT 3.1.1 broker) | covered |
| Hardware and other platforms | syslog, file, SNMP; any layout through onboarding or plugins | `test_extensibility` (onboarding, plugins) | covered |
| Formats: syslog, JSON, XML, CSV, CEF, LEEF, proprietary | 8 built-in parsers; APG for proprietary formats | golden files (`tests/golden/views`), `test_usp` U1, `benchmarks/apg_eval` | covered |
| Current and future sources | plugin entry points (`ulpf.parsers`), schema registry with additive minor versions, `x-<vendor>` extension namespace | `test_extensibility` (plugin install, hash allow-list, schema diff) | covered |
| Billions of events per day | workers scale with cores; multi-node cluster | `runtime_tcp_20261022_024737.json` (6 workers: 26,952 events/s ≈ 2.3 billion/day on one laptop); `multinode_2x3_*.json`; soak in STATUS; `test_operations` (failover) | covered on laptop hardware; server sizing to be measured on the target hardware |
| Vendor-agnostic | unified schema + ECS and OCSF views per output | `test_usp` U3 | covered |
| Big Data and data lakes | Parquet lake (partitioned), S3-compatible output | `test_outputs` (Parquet partitions, S3 SigV4 against a fake) | covered |
| AI and ML analytics | `export-ml` Parquet/CSV with a column card; anomaly, drift and correlation events | `test_extensibility.TestMlExport`, `test_coverage.TestMachineLearning` (a baseline model trained on the export beats the majority class) | covered |

## Expected solutions a–k

| Item | Requirement | Implementation | Proof |
|---|---|---|---|
| a | Preserve complete raw data without loss | journal before acknowledgement; raw bytes kept per record; replay after a crash | `test_extensibility.TestRawTraceability` (100 % of a mixed Unicode set byte-identical); integrity suite section 13; `test_chaos` |
| b | Extract source-specific attributes | parsers + APG; every attribute without a unified field stays in `parsed_fields` (nested keys flattened) | `test_coverage` (nested MySQL audit keys kept); golden files |
| c | Normalise into a common taxonomy | unified schema 1.1.0 (100 fields), 12 categories, 0–10 severity, ISO-8601 UTC | golden files; `test_extensibility.TestSchemaRegistry` |
| d | Traceability between normalised and raw events | `evidence.journal_seq`, `raw_hash`; `GET /api/v1/events/{id}/raw`, `ulpf raw get`; Merkle inclusion proofs | `test_inputs` (raw endpoint `matches_event`), `test_usp` U2 |
| e | Plug-and-play onboarding of new sources | `ulpf source onboard` writes a validated input into the config; plugins | `test_extensibility.TestSourceOnboarding`; measured: 200-line sample → active parser in 0.15 s, 100 % coverage, 100 % accuracy |
| f | Unified visibility | REST API, desktop console, terminal UI, Grafana dashboard (`deploy/grafana/ulpf-overview.json`) over the ECS view | `test_coverage.TestVisibility` (every dashboard field exists in ECS output) |
| g | Efficient SIEM and data-lake integration | Elasticsearch/OpenSearch, Splunk HEC, QRadar (LEEF syslog), Sentinel (Azure Logs Ingestion), Chronicle, Kafka, Loki, OTLP, S3, Parquet | `test_outputs` (every type except Kafka against local fakes, exact counts) |
| h | AI and ML-ready analytics | ML export, derived analytics events | as for AI/ML above |
| i | Reduced parser development effort | APG and onboarding replace hand-written grok/regex | measured above (item e); `benchmarks/apg_eval` (7 unseen formats, 100 % coverage) |
| j | Deployable in an air-gapped network | defence mode, in-process egress guard, offline bundle, offline GeoIP | `test_usp` U4; integrity suite section 17 |
| k | Packaged in a container | Dockerfile + compose run the live pipeline with a health check | CI job `docker`; locally, the container command served `/api/v1/health` and journaled a line (Docker is not installed on the development machine) |

## Open items

- **Kafka input and output, Event Hubs input**: implemented and validated by config only. A broker or SDK is not available here.
- **Competitive comparison**: `benchmarks/competitive/` holds the configurations and the runner, but Vector, Logstash and Fluent Bit are not installed on the development machine, so no comparison numbers are published.
- **Server-class sizing**: every throughput figure comes from a 4-core laptop. Measure on the target hardware with `benchmarks/live/harness.py` before committing to per-node capacity.
