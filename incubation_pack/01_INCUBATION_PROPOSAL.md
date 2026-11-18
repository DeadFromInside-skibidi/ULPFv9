# ULPF — Incubation Proposal

**Universal Log Pre-processing Framework: a sovereign, self-learning log pipeline that cuts SIEM ingest and keeps tamper-evident evidence on Indian soil**

Prepared for: Amity Innovation Incubator · DSCI Centre of Excellence (Noida) · iDEX DISC · MeitY TIDE 2.0 / SAMRIDH
Version 9.0.0 of the software · October 2026

> **Evidence policy.** Every technical claim here points to a file in the repository (`ulpf/…`, `config/…`, `tests/…`) or to a measurement under `benchmarks/results/`. Market and regulatory figures cite their published source. Where an analyst or vendor figure is our only source, the text says so. Where we have not measured something, we say that instead of estimating it. All throughput figures come from one developer laptop (Intel Core i5-8279U, 4 cores, 16 GB RAM, Windows 10, Python 3.11), not from server hardware.

---

## 1. Executive summary

**What ULPF is.** ULPF is a log pre-processing pipeline. It sits between an organisation's devices (firewalls, servers, applications, cloud services, OT equipment) and wherever their logs end up: a SIEM, a data lake, or an analyst's console. It accepts logs from 15 input types. Each received line is written to a durable, hash-verified journal before anything else happens, and that journal is the lossless raw archive. Each line is then turned into one 100-field unified event (ECS and OCSF views on request) and delivered to 12 output types, with no loss under failure.

**Mission.** To make complete, verifiable log retention affordable and sovereign for Indian organisations that today cannot afford to send everything to a commercial SIEM, cannot send data abroad, or cannot write parsers for every device they own.

**Unique value proposition.** Commercial SIEMs, open-source stacks and telemetry pipelines each cover part of this. As far as we can determine from public documentation (section 2 of the market report), none combines the following in one offline package:

1. **Unknown formats learned from live traffic** without hand-written regex or Grok. In defence mode, an operator must approve each learned parser before it is used.
2. **A tamper-evident evidence chain** for every record: per-record SHA-256, chained Merkle seals and keyed row checksums, with per-record proofs.
3. **Verifiable offline operation**: an in-process guard that blocks any network connection not on an allow-list.
4. **Raw-preserving selective forwarding**: keep everything locally, send only what matters upstream, byte for byte.

### Dual-wedge positioning

| Wedge | Customer | Pain | What ULPF does |
|---|---|---|---|
| **A. "SIEM diet"** | Mid-market enterprises, NBFCs, fintechs and co-operative banks already paying per-GB SIEM fees | Ingest-priced SIEMs bill every verbose firewall, WAF and proxy line | Normalise and keep 100 % locally, and forward only selected events in their raw form. For an example 100 GB/day customer, the modelled net saving is **₹77 L–₹1.20 Cr per year against a ₹3.6 L licence** (section 4.4) |
| **B. Sovereign log vault** | Defence, DRDO labs, PSUs, industrial OT, BFSI data centres | Air-gapped networks, CERT-In 180-day retention, evidence that must survive legal scrutiny | `defence` mode: encrypted journal, TLS everywhere, in-process egress allow-list, operator-approved parsers, Merkle-sealed evidence, offline install bundle |

---

## 2. The problem

### 2.1 The per-GB SIEM tax

The dominant commercial SIEMs price by ingested volume:

- **Microsoft Sentinel** bills analytics logs per GB ingested. Third-party guides report about **$4.30/GB** pay-as-you-go in East US, and about $2.96/GB at the 100 GB/day commitment tier, which Microsoft says saves up to 52 %. Microsoft labels its own figures as estimates that vary by region and agreement ([Microsoft](https://www.microsoft.com/en-us/security/pricing/microsoft-sentinel), [UnderDefense](https://underdefense.com/industry-pricings/microsoft-sentinel-pricing/), [Charbel Nemnom](https://charbelnemnom.com/microsoft-sentinel-sizing-and-pricing/)).
- **Splunk** offers ingest-based and workload (compute) pricing, does not publish per-GB prices, and says the per-GB rate falls by more than 50 % between 1 and 100 GB/day ([Splunk FAQ](https://www.splunk.com/en_us/products/pricing/faqs/enterprise-and-cloud.html)). Third-party estimates range from about $1,500–1,800 per GB/day per year at small volumes down to $100–200 at 500+ GB/day ([Ogma](https://ogma.in/blog/the-complete-guide-to-splunk-licensing-in-2026-ingest-vs-workload-pricing-explained)). These are estimates, not quotes.
- **Google Security Operations (Chronicle)** uses a commitment-based ingestion model, with 12 months' retention by default and extended retention billed on ingested volume ([Google Cloud docs](https://docs.cloud.google.com/chronicle/docs/onboard/understand-billing)).

Market evidence that reducing ingest is worth paying for: Cribl, the leading security data pipeline vendor, is estimated at about **$305 M ARR in 2025** ([Sacra](https://sacra.com/c/cribl/), an estimate). Practitioners report 20–40 % volume reductions with it ([PeerSpot](https://www.peerspot.com/products/cribl-reviews), [AWS Marketplace reviews](https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-gwiqiktubqhhk)).

### 2.2 The parser bottleneck

Every new device or firmware version needs a parser: Grok in Logstash, regex in Cribl or Wazuh decoders. When a vendor renames a field, the parser keeps "working" while the normalised fields silently go empty. We found **no reliable published statistic** for the share of SIEM onboarding time spent on parsers, so we do not quote one. In its place, we measured what ULPF removes from that effort:

- **Onboarding:** `ulpf source onboard` turned a 200-line sample of an unseen PLC format into a validated, active parser in **0.15 s**, with **100 % coverage** and **100 % field accuracy**. It then wrote the input into the pipeline config (`tests/test_extensibility.py`, docs/STATUS.md).
- **Learning on live traffic:** an unseen format sent over TCP was learned from the first 300 lines without a restart. **≥ 99 %** of the next 1,000 lines were parsed by the learned parser (`tests/test_usp.py::TestU1LiveLearning`).
- **Integrity suite, section 16:** **7 of 7** unknown formats learned, with 100 % coverage and 100 % field accuracy on unseen lines, in 11.7–28.5 ms of learning each (`benchmarks/results/integrity/integrity_suite_results.json`).

### 2.3 Sovereign compliance mandates

| Instrument | What it requires | ULPF feature |
|---|---|---|
| **CERT-In Directions, 28 April 2022** (IT Act s.70B(6); in force 27 June 2022) | Report specified incidents **within 6 hours**. **Keep ICT system logs for 180 days** within Indian jurisdiction ([Linklaters](https://www.linklaters.com/insights/blogs/digilinks/2022/may/india-new-and-onerous-cyber-security-framework-and-breach-reporting-obligations), [PSA Legal](https://psalegal.com/new-cert-in-directions-overview-and-implications/)) | `journal.retention_days` (180 by default in defence mode) on local disk; streaming correlation and drift events within seconds; end-to-end latency p99 under 1 s (section 4.2) |
| **DPDP Act 2023 and DPDP Rules 2025** (notified November 2025) | Penalty of up to **₹250 crore** for failing to take reasonable security safeguards; ₹200 crore for breach-notification failures. The full compliance deadline is reported as 13 May 2027 ([PIB](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2025/nov/doc20251117695301.pdf), [EY](https://www.ey.com/content/dam/ey-unified-site/ey-com/en-in/alerts-hub/2025/11/digital-data-protection-act-rules-notified-by-meity.pdf), [Mondaq](https://www.mondaq.com/from-draft-to-reality-key-changes-in-indias-dpdp-rules-2025/1775140)) | Hash-chained audit log; journal encryption (AES-256-GCM); role-based API keys; evidence verification |
| **Bharatiya Sakshya Adhiniyam 2023, s.63** | Electronic evidence needs a certificate that **states the record's hash value** (two parts: the producing party and an expert). The Supreme Court upheld s.63(4) in 2026, as reported by [LiveLaw](https://www.livelaw.in/amp/top-stories/supreme-court-rejects-challenge-to-s634-bsa-mandating-hash-value-disclosure-for-electronic-evidence-535950) and [SCC Online](https://www.scconline.com/blog/?p=389747) | SHA-256 per record at receipt; `ulpf raw get` returns the original bytes with their hash; `ulpf evidence prove` gives a Merkle inclusion proof |

**What we do not claim.** ULPF produces the hash values and proofs that a s.63 certificate needs. It does not make evidence admissible: certification and expert sign-off are legal acts. The forensic module says so in its own output (`"Engineering verification only; does not claim legal admissibility."`).

---

## 3. The ULPF solution, mapped to the code

### 3.1 Architecture as implemented

```
 15 inputs: syslog UDP/TCP/TLS · file tail · HTTP · OTLP · journald · Windows events · NetFlow v5/v9
            SNMP traps v1/v2c/v3 · MQTT · Kafka · CloudTrail · Pub/Sub · Okta · Entra ID · Event Hubs
        │                                                    ulpf/runtime/inputs/
        ▼
 JOURNAL  sequence number + SHA-256 per record · CRC blocks · torn-tail repair · AES-256-GCM (defence)
        │  ulpf/runtime/journal.py                          └─▶ EVIDENCE SEALER: Merkle root per window,
        │                                                       chained + HMAC, emitted as events
        ▼                                                       ulpf/runtime/evidence.py
 WORKERS (N processes)  ulpf/runtime/worker.py
   detect (constant-time prefix checks → regex fallback)    ulpf/engine/detector.py
   → plugin parsers → 8 built-in parsers → learned (APG) parsers → raw fallback (never drops a line)
   → 100-field unified schema 1.1.0, 180 vendor field aliases   ulpf/engine/schema.py, normalizer.py
   → enrichment (GeoIP .mmdb / IOC feed, offline)             ulpf/engine/enricher.py
   → drift + anomaly events → routes                          ulpf/runtime/analytics.py
        ▼
 DISK BUFFER per output (exactly once, bounded, retry, dead-letter queue)   ulpf/runtime/buffer.py
        ▼
 12 outputs: DuckDB store · file · Parquet lake · S3 · Elasticsearch/OpenSearch · Splunk HEC · Kafka · Loki
             · OTLP · syslog (RFC 5424 / CEF / LEEF / raw) · Azure Monitor · Chronicle  (unified | ECS | OCSF)

 Host: cross-source correlation (7 kill-chain stages) · API (read/write/admin, TLS/mTLS) · audit chain
       · egress guard in every process · cluster heartbeats + placement      ulpf/runtime/supervisor.py
```

### 3.2 The five core innovations

| # | Innovation | Where it is implemented | What exactly it does |
|---|---|---|---|
| 1 | **Autonomous Parser Generator (APG)** | `ulpf/intelligence/auto_parser/` (tokenizer, masker, clusterer, classifier, type_inference, semantic_mapper, compiler, `miners/native.py`), `admission.py`, `lifecycle.py`, `provenance.py`, `config/auto_parser.json` | Mines templates from unknown lines and validates them. Learned parsers are signed (HMAC-SHA256 per installation) and promoted through candidate → canary → active, with per-source rate limits and anti-poisoning quarantine. There are three profiles: `soc` (promotion after 50 samples, 60 s canary), `industrial` (200 samples, 300 s canary, no auto-promotion) and `defense` (500 samples, 600 s canary, minimum accuracy 0.98, signed, offline-only, full tamper-evident audit). In the runtime's defence mode, parsers wait for `ulpf parsers approve` |
| 2 | **Log DNA and live drift monitoring** | `ulpf/intelligence/log_dna.py`, `ulpf/runtime/analytics.py` (DriftMonitor) | Builds a fingerprint per source from Shannon entropy, character distribution, delimiter, mined field types and a structural shape distribution. The live monitor raises a `drift` event when a source's structure changes. Integrity-suite section 15: **5 of 5 drift types detected, 0 false positives, 0 false negatives**, average detection latency 233 ms |
| 3 | **Columnar lakehouse storage** | `ulpf/storage/database.py`, `ulpf/runtime/sinks/duckdb_sink.py`, `lake.py` | Workers encode Arrow tables into Parquet segments. The host ingests them into DuckDB in one transaction, with a segment ledger that makes ingest exactly-once. Queries materialise late (`WHERE rowid IN (…)`). A partitioned Parquet lake serves long retention |
| 4 | **Correlation and anomaly engine** | `ulpf/intelligence/correlation.py`, `anomaly.py`, `ulpf/runtime/analytics.py` | Entity-bucketed sliding-window correlation across sources, mapped to 7 kill-chain stages (reconnaissance through exfiltration). Rolling z-score anomalies (severity, bytes, volume), low-entropy detection, and first-seen public IPs once a baseline is established. Results are delivered as events. *Limitation:* the stage names follow the Lockheed Martin kill chain; MITRE ATT&CK technique or tactic IDs are **not** mapped yet (roadmap Q1) |
| 5 | **Cryptographic chain of custody** | `ulpf/runtime/evidence.py`, `ulpf/intelligence/forensic.py`, `ulpf/runtime/audit.py` | SHA-256 per raw record. Rolling Merkle seals, chained and HMAC'd. Inclusion proofs (`ulpf evidence prove`). Keyed BLAKE2b row checksums on stored events. Exportable forensic packages that verify offline. Integrity-suite section 14: **all 6 manipulation types detected** (modified, deleted, inserted and reordered records, altered hash, altered timestamp) |

Two further capabilities underpin both wedges:

- **Defence mode and egress guard** (`ulpf/config/pipeline.py`, `ulpf/runtime/egress.py`). An audit-hook guard runs in every process. In defence mode, a socket to an address not on the allow-list fails with `PermissionError` before any packet is sent (`tests/test_usp.py::TestU4Offline`). Integrity-suite section 17: 0 external network or DNS connections across a full lifecycle.
- **Raw selective forwarding** (`ulpf/runtime/sinks/syslog_sink.py`, `format: raw`). Selected events go upstream as the original bytes, plus about 3 bytes of framing each (`tests/test_coverage.py::TestSelectiveForwarding`).

Interfaces: `ulpf` CLI (`ulpf/main.py`, `ulpf/cli_runtime.py`), REST API (`ulpf/api/routes.py`, `ulpf/runtime/api_server.py`), terminal UI (`ulpf/tui/tui_app.py`), and a PySide6 desktop console with **14 pages** (`ulpf/gui/pages/`). Deployment: Docker (`Dockerfile`, `docker-compose.yml`), systemd (`deploy/systemd/ulpf.service`), Windows service via NSSM, offline bundle (`scripts/package_offline.sh`).

---

## 4. Empirical proof

All figures below are reproducible with the command or test named. "Laptop" means the Intel i5-8279U (4 cores) machine.

### 4.1 Throughput and reliability (v9 runtime, TCP, 9-format corpus, journal + seals + analytics on)

| Configuration | Persisted events/s | Loss | Result file |
|---|---|---|---|
| 3 workers | 17,034 | 0 | `benchmarks/results/live/runtime_tcp_20261022_024708.json` |
| 6 workers | 26,952 (≈ 2.3 billion/day) | 0 | `…/runtime_tcp_20261022_024737.json` |
| 3 workers + row checksums (defence default) | 15,030 | 0 | `…/runtime_tcp_20261022_024758.json` |
| 2 nodes × 3 workers, same 4-core laptop | 20,934 (1.24× one node) | 0 | `benchmarks/results/multinode/multinode_2x3_20261022_024851.json` |
| Single core, parse + normalise + enrich only | ≈ 12,500 | — | `benchmarks/results/live/profile_core_*.json` |
| **1-hour soak at 5,000 events/s** | 18,000,000 of 18,000,000 | **0** | `benchmarks/results/soak/soak_20261023_012358.json` |

Failure-injection tests (`tests/test_chaos.py`): kill -9 then restart (6,000 of 6,000 lines, none twice); a sink outage (20,000 of 20,000, no duplicates); full buffers in `block` mode (no loss) and `drop_oldest` mode (drops counted exactly); a TCP partition; the DLQ bound. A two-node failover handed over 500 of 500 lines with none twice (`tests/test_operations.py`).

**On the 8.x "154k EPS" claim.** An earlier version's harness claimed 154,000 EPS. Our own archived results (`benchmarks/results.zip`, `validation_run_final/offered_rates.csv`) mark every offered rate from 100k to 200k EPS as **FAIL**, with 7k–29k EPS measured on only 10,000 events. We do not use that claim.

### 4.2 End-to-end latency at load (receipt → committed in the store)

`python -m benchmarks.latency_footprint`; `benchmarks/results/latency/latency_footprint_20261023_023101.json`. Latency runs from the input accepting a line to the store transaction holding it committing, both measured in one process.

| Offered load | Persisted | p50 | p90 | p95 | p99 | max |
|---|---|---|---|---|---|---|
| 2,000 events/s | 60,000 / 60,000 | 304 ms | 418 ms | 455 ms | 536 ms | 625 ms |
| 5,000 events/s | 60,000 / 60,000 | 341 ms | 485 ms | 525 ms | 592 ms | 672 ms |
| 10,000 events/s | 60,000 / 60,000 | 551 ms | 726 ms | 763 ms | 919 ms | 919 ms |

Latency is dominated by deliberate batching: the journal block, the 100 ms commit watermark, and up to 128 segments per store transaction. That is well inside the 6-hour CERT-In reporting window. It is not a sub-millisecond streaming engine, and we do not claim one.

### 4.3 Memory (real OS process memory)

| Measurement | Value | Source |
|---|---|---|
| Pipeline without the embedded store (file output), 9 min at 5,000 events/s | host **70–77 MB**, flat; 7 workers ≈ 300 MB in total (≈ 43 MB each) | `benchmarks/results/soak/soak_20261023_013352.json` |
| With the DuckDB store, 1 hour at 5,000 events/s | workers flat at 530–600 MB in total; host memory outside DuckDB's buffer pool grew from 430 to 1,790 MB, and the host peaked at 6.2 GB | `…/soak_20261023_012358.json` |
| 8.x per-worker measurement (historical) | 24 MB baseline, 84 MB peak per worker, 190 MB idle main process | `benchmarks/results.zip → validation_run_final/memory_validation.json` |

**Trade-off we disclose.** The embedded DuckDB store's native memory grows with the number of stored rows, beyond its configured cap. For sustained high volume, we recommend keeping the store for a retention window and sending bulk data to the Parquet lake or a SIEM; those paths keep the process memory-flat (docs/INSTALLATION.md, "Sizing the local store"). A "sub-500 MB appliance" is accurate only for the pipeline without the embedded store.

### 4.4 What a customer stores and forwards (measured bytes per event)

`benchmarks/results/latency/encoded_size_20261023_023215.json` and `latency_footprint_20261023_023101.json`, on the same synthetic corpus (183 bytes per raw line on average):

| Representation | Size against the raw line |
|---|---|
| Raw journal (lossless archive, 180-day retention) | 1.36× |
| Parquet lake (full unified schema) | 2.0× |
| DuckDB store (full schema, raw text and parsed fields, queryable) | 7.5× |
| Forwarded as **raw** (`format: raw`) | **1.02×** |
| Forwarded as CEF / LEEF syslog | 2.55× / 2.46× |
| Forwarded as OCSF / ECS / unified JSON | 9.1× / 10.5× / 14.3× |

**This shapes the product.** Normalisation adds information, so it adds bytes. The SIEM saving comes from forwarding **fewer events at their raw size**, not from compressing them. Forwarding 10 % of events as ECS JSON would cost *more* than forwarding everything raw. The worked ROI (Deliverable 3, section 2) therefore uses raw forwarding.

### 4.5 Integrity, security and air-gap (`python -m benchmarks.integrity_suite`, 6 of 6 sections pass)

| Section | Result |
|---|---|
| 12 Crash and recovery | store reopened with 417,530 events retained; ingestion resumed; port collision and malformed input handled |
| 13 Raw-byte integrity | 484 of 484 events byte-identical to their source, 0 mismatches |
| 14 Forensic tamper detection | 6 of 6 manipulation types detected; the original verifies |
| 15 Format drift | 5 of 5 drift types detected, 0 false positives, 0 false negatives, average 233 ms |
| 16 APG | 7 of 7 unknown formats learned, 100 % coverage, 100 % field accuracy; autonomous learning after 233 lines |
| 17 Air-gap | 0 external network or DNS connections during a full lifecycle |

The test suite: **159 tests in 13 suites** pass (`python -m unittest discover -s tests`, 286 s on the laptop, 23 October 2026).

### 4.6 What we have not proven yet

| Gap | Status |
|---|---|
| Academic parsing accuracy (Loghub-2k: PA, GA, FTA) | **Not evaluated.** `benchmarks/loghub_eval.py` embeds a 31-line smoke subset of 14 systems, not the 2,000-line labelled sets. Running the full benchmark is milestone Q1-3 |
| Head-to-head against Vector, Logstash and Fluent Bit | Configurations and runner committed (`benchmarks/competitive/`); not run, because the tools are not installed on our machine. Milestone Q1-4 |
| Server-class sizing | All figures come from a laptop. Milestone Q1-5 |
| Kafka and Event Hubs connectors | Config-validated only; no broker or SDK in our test environment |

---

## 5. The ask and the 12-month roadmap

### 5.1 Why an incubator

| Need | What we ask |
|---|---|
| **Enterprise sales** | Mentors who have sold to CISOs of NBFCs, banks and PSUs; help structuring paid pilots and security questionnaires |
| **Channel** | Introductions to CERT-In empanelled audit organisations (231 nationally, [PIB, January 2026](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)) and MSSPs, to pilot the white-label programme |
| **Defence access** | Guidance on iDEX DISC challenges (grants up to ₹1.5 crore, milestone-based, [iDEX](https://idex.gov.in//disc-category/43)) and PSU tender requirements |
| **Grant funding** | MeitY TIDE 2.0 (up to ₹7 lakh prototype grant via incubators, [IIT Hyderabad TIDE page](https://itic.iith.ac.in/meity-tide.html)); SAMRIDH (matching support of up to ₹40 lakh, [Razorpay Rize summary](https://razorpay.com/rize/blogs/samridh-programme)) |
| **Infrastructure** | A server-class test bed (≥ 16 cores) and lab access to real firewall and OT log sources, for sizing and the Loghub and competitive runs |

**Use of a seed grant** (indicative, ₹40 L): server test bed and storage (₹6 L); certification readiness for ISO/IEC 27001 of the company's own development process and a third-party penetration test of ULPF (₹10 L); one systems engineer for the Rust/columnar hot path and ATT&CK mapping (₹14 L); design-partner pilots and travel within NCR (₹5 L); legal: licensing, contracts, trademark (₹5 L).

### 5.2 Milestones

| Quarter | Engineering | Validation | Traction |
|---|---|---|---|
| **Q1** | Sigma rule import (detections from the public Sigma corpus); MITRE ATT&CK technique IDs on correlation events | Q1-3: full Loghub-2k evaluation (PA, GA, FTA) published with the harness. Q1-4: competitive run against Vector, Logstash and Fluent Bit on the same corpus. Q1-5: sizing on a ≥ 16-core server | 3 design-partner pilots (target: 1 NBFC, 1 co-operative bank, 1 MSSP) under the 30-day pilot structure (Deliverable 3, section 4.4) |
| **Q2** | Ed25519 signatures for parsers and seals (asymmetric, so a third party can verify without our key); store memory fix (bounded-memory store mode or rotation of DuckDB files per day) | Third-party penetration test; Kafka and Event Hubs tests against real brokers | First 2 paid Pro nodes; first MSSP partner signed |
| **Q3** | Columnar fast path for the built-in formats (parse straight to Arrow; our measured Rust attempt at the dict level gave no speed-up, docs/STATUS.md Phase F); TPM-backed key storage in the sovereign edition | Soak of 24 hours at production rates on the server test bed | iDEX DISC or PSU proof-of-concept; 5 Pro nodes |
| **Q4** | Management console for many nodes (cluster view, fleet upgrades) | ISO/IEC 27001 readiness assessment | ARR target ₹55 L (Deliverable 3, section 3); 2 MSSP partners with 5 client nodes each |

---

## 6. Team and IP

- **Team.** [Founder names and roles to be completed by the applicants.]
- **IP.** Original code in this repository: 27,455 lines of Python under `ulpf/`, plus a Rust crate under `native/`, with 4,807 lines of tests. The licence is currently MIT (`pyproject.toml`). The open-core split in Deliverable 3 requires relicensing the Pro and Sovereign components before commercial release; this is a legal task for the incubation period.

---

### Sources

Regulatory and market figures: [Mordor Intelligence, India cybersecurity market](https://www.mordorintelligence.com/industry-reports/india-cybersecurity-market) · [Linklaters on the CERT-In directions](https://www.linklaters.com/insights/blogs/digilinks/2022/may/india-new-and-onerous-cyber-security-framework-and-breach-reporting-obligations) · [PSA Legal](https://psalegal.com/new-cert-in-directions-overview-and-implications/) · [PIB, DPDP Rules 2025](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2025/nov/doc20251117695301.pdf) · [EY on the DPDP Rules](https://www.ey.com/content/dam/ey-unified-site/ey-com/en-in/alerts-hub/2025/11/digital-data-protection-act-rules-notified-by-meity.pdf) · [Mondaq on the DPDP penalties](https://www.mondaq.com/from-draft-to-reality-key-changes-in-indias-dpdp-rules-2025/1775140) · [LiveLaw on BSA s.63(4)](https://www.livelaw.in/amp/top-stories/supreme-court-rejects-challenge-to-s634-bsa-mandating-hash-value-disclosure-for-electronic-evidence-535950) · [SCC Online](https://www.scconline.com/blog/?p=389747) · [Microsoft Sentinel pricing](https://www.microsoft.com/en-us/security/pricing/microsoft-sentinel) · [UnderDefense on Sentinel pricing](https://underdefense.com/industry-pricings/microsoft-sentinel-pricing/) · [Splunk pricing FAQ](https://www.splunk.com/en_us/products/pricing/faqs/enterprise-and-cloud.html) · [Ogma on Splunk licensing](https://ogma.in/blog/the-complete-guide-to-splunk-licensing-in-2026-ingest-vs-workload-pricing-explained) · [Google SecOps billing](https://docs.cloud.google.com/chronicle/docs/onboard/understand-billing) · [Sacra on Cribl](https://sacra.com/c/cribl/) · [PIB, CERT-In empanelment](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf) · [iDEX DISC](https://idex.gov.in//disc-category/43) · [IIT Hyderabad on TIDE 2.0](https://itic.iith.ac.in/meity-tide.html) · [Razorpay Rize on SAMRIDH](https://razorpay.com/rize/blogs/samridh-programme)
