# ULPF — Market Research, Competitor Strategy and Gap Analysis

October 2026. Analyst market figures differ widely depending on how each firm defines the market. Each figure below names its source, and figures from different firms are not combined. Bottom-up numbers are computed in `incubation_pack/model.py`, with every assumption labelled.

---

## 1. Market sizing

### 1.1 Global

| Market | Size | Growth | Source |
|---|---|---|---|
| SIEM | $10.78 B (2025) → $19.13 B (2030) | 12.16 % CAGR | [Expert Insights](https://expertinsights.com/security-operations/siem-market-overview-key-stats-and-insights) |
| SIEM (different scope) | $8.39 B (2026) → $13.67 B (2031) | 10.3 % CAGR | [MarketsandMarkets](https://www.marketsandmarkets.com/Market-Reports/siem-market-1904.html) |
| "Modern SIEM" | $7.13 B (2024) → $13.55 B (2029) | 13.7 % CAGR; cloud SIEM 17.5 %, on-premise 3.4 % | Frost & Sullivan, via [press release](https://www.securityworldmarket.com/uk/News/Business-News/modern-siem-market-to-1355-billion-by-2029) |
| Telemetry and security data pipelines | No reliable size found. Gartner lists "telemetry pipelines" as a market ([Gartner Peer Insights](https://www.gartner.com/reviews/market/telemetry-pipelines)) | Cribl ARR estimated at about $305 M in 2025 ([Sacra](https://sacra.com/c/cribl/)) | Consolidation: SentinelOne acquired Observo AI (Sept 2025); Palo Alto Networks acquired Chronosphere (Nov 2025) ([CB Insights](https://www.cbinsights.com/compare/cribl-vs-observoai)) |

**Direction of travel.** Buyers are separating *collection, normalisation and retention* (cheap, local or object storage, Parquet-style) from *detection and search* (expensive, per-GB). The three pipeline acquisitions in 2024–25 show platform vendors paying to own that first layer. ULPF competes in it, with an evidence and offline focus that the acquired products do not have.

### 1.2 India

| Figure | Value | Source |
|---|---|---|
| India cybersecurity market | **$6.56 B (2026) → $15.06 B (2031), 18.07 % CAGR** | [Mordor Intelligence](https://www.mordorintelligence.com/industry-reports/india-cybersecurity-market) |
| Largest end-user segment | **BFSI, 23.88 % of 2025 revenue** | Mordor Intelligence (single source; no independent confirmation found) |
| Fastest-growing buyer size | **SMEs, 19.74 % CAGR**; large enterprises were 69.72 % of 2025 spend | Mordor Intelligence |
| Alternative estimate | $8.58 B (2025) → $16.86 B (2030), 14.5 % CAGR | [MarketsandMarkets](https://www.marketsandmarkets.com/PressReleases/india-cybersecurity.asp) |

*Not used:* a "~$6 B domestic cybersecurity product revenue" figure. We could not find a primary source for it.

### 1.3 Bottom-up TAM / SAM / SOM for ULPF in India

From `incubation_pack/model.py`. Prices are ULPF list prices (Deliverable 3).

| Segment | Entities | Source of the count | Nodes × price | TAM | SAM share (basis) | SAM |
|---|---|---|---|---|---|---|
| NBFCs registered with RBI | 9,291 | [RBI list, 31-Dec-2024](https://website.rbi.org.in/documents/87730/39016390/ListofNBFCsandARCsregisteredwiththeRBI.pdf) | 1 × ₹3.6 L | ₹334.5 Cr | 10 % (*assumption*: those with in-house IT and a SIEM) | ₹33.4 Cr |
| Urban co-operative banks | 1,457 | [RBI Annual Report, via Business Standard](https://www.business-standard.com/amp/industry/banking/ucbs-decline-to-1457-in-fy25-125122901022_1.html) | 1 × ₹3.6 L | ₹52.5 Cr | 42.5 % (Tier 2–4; 57.5 % are Tier 1, RBI) | ₹22.3 Cr |
| CERT-In empanelled audit organisations, as a channel | 231 | [PIB, January 2026](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf) | 20 client nodes × ₹2.52 L (70 % of list) | ₹116.4 Cr | 20 % (*assumption*: those running managed SOC or log services) | ₹23.3 Cr |
| Defence, PSU and critical-infrastructure sites | 300 | *assumption*: no public count found | 1 × ₹15 L | ₹45.0 Cr | 30 % (*assumption*: reachable through iDEX or PSU tenders) | ₹13.5 Cr |
| **Total** | | | | **₹548 Cr (≈ $62 M)** | | **₹92.5 Cr (≈ $10.5 M)** |

**SOM.** The year-3 plan in Deliverable 3 reaches ₹8.9 Cr ARR, which is **9.6 % of SAM**. That is an ambitious share for year 3, and it depends on the MSSP channel working (64 % of year-3 ARR). If the channel underperforms, a direct-sales-only path gives about ₹3.2 Cr by year 3.

**Caveat.** The "4,500 regulated entities" in our original brief could not be sourced. The real counts are 9,291 NBFCs and 1,457 UCBs, most of which are small, so the SAM shares above are deliberately conservative.

---

## 2. Competitor matrix

| | Pricing (public information) | Storage engine | Go-to-market | Where they beat ULPF today | Where ULPF beats them |
|---|---|---|---|---|---|
| **Splunk Enterprise Security (Cisco)** | Ingest or workload (SVC) pricing; no public price list; per-GB rate falls >50 % from 1 to 100 GB/day ([Splunk](https://www.splunk.com/en_us/products/pricing/faqs/enterprise-and-cloud.html)); third-party estimates $100–1,800 per GB/day per year ([Ogma](https://ogma.in/blog/the-complete-guide-to-splunk-licensing-in-2026-ingest-vs-workload-pricing-explained)) | Proprietary indexers | Enterprise direct sales and partners | Detection content, search language, apps ecosystem, proven multi-PB scale, certifications | Flat per-node price; learns parsers without hand-written extraction rules; verifiable offline mode; tamper-evident seals; can sit in front of Splunk and forward raw lines selectively |
| **IBM QRadar** | On-premise continues. QRadar SaaS was sold to Palo Alto Networks (closed 31 Aug 2024), with end of sale/life from 14 Apr 2025 and migration to Cortex XSIAM ([Palo Alto Networks](https://paloaltonetworks.com/cyberpedia/ibm-qradar-acquired-by-palo-alto-networks)) | Proprietary (Ariel) | Large enterprise and government | Mature on-premise deployments in Indian BFSI and government; offence/rule library | A modern, open pipeline for QRadar shops; ULPF already emits LEEF for QRadar (`format: leef`) and raw syslog; offline-first |
| **Microsoft Sentinel** | ~$4.30/GB pay-as-you-go (third-party, East US); commitment tiers up to 52 % cheaper ([Microsoft](https://www.microsoft.com/en-us/security/pricing/microsoft-sentinel), [UnderDefense](https://underdefense.com/industry-pricings/microsoft-sentinel-pricing/)) | Azure Log Analytics | Azure and M365 bundles | Native M365/Entra/Defender integration, analytics rules, cloud scale | Air-gapped operation; data stays on premises; ULPF ships an Azure Monitor Logs Ingestion output to send only selected events |
| **Google SecOps (Chronicle)** | Commitment-based ingestion credits; 12 months' retention by default; extended retention billed on volume ([Google Cloud](https://docs.cloud.google.com/chronicle/docs/onboard/understand-billing)) | Google infrastructure (UDM) | Google Cloud enterprise | Petabyte search, threat intelligence, long retention | Sovereign, offline deployment; ULPF has a Chronicle output for selected events |
| **Elastic Security (ELK)** | Free and open-source tiers; paid subscriptions | Elasticsearch (Lucene, JVM) | Open-source bottom-up plus enterprise | Search UX, Kibana, detection rules, community | Lower hardware floor: Elastic recommends 64 GB as the "sweet spot" per node, warns below 8 GB is counter-productive, and heap is usually half the RAM ([Elastic guide](https://www.elastic.co/guide/en/elasticsearch/guide/current/hardware.html)). ULPF's pipeline ran at 70–77 MB host memory plus about 43 MB per worker without the embedded store |
| **Wazuh** | Free and open source | Wazuh indexer (OpenSearch); recommended 16 GB RAM and 8 cores per node (32 GB in the 5.0 beta) ([Wazuh docs](https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/index.html)) | Open-source community, Wazuh cloud | **Endpoint agent (HIDS, FIM, SCA)**, compliance dashboards, large community | Learned parsers instead of hand-written decoders; tamper-evident evidence; exactly-once delivery to any SIEM; offline enforcement |
| **Cribl Stream** | Free up to 1 TB/day (one worker group); paid tiers priced per GB ingested ([Cribl](https://cribl.io/pricing)); a third party reports about $0.27–0.32 per GB in Cloud credits ([Motadata](https://www.motadata.com/blog/cribl-pricing)) | Pipeline (no store); Cribl Lake/Search separate | Enterprise, strong partner channel | Mature routing UI, very large connector catalogue, proven at TB/day, funded and staffed | Learns parsers automatically; built-in tamper-evident evidence chain and raw journal; air-gap enforcement; per-node flat price; Indian sovereign focus |
| **Vector (Datadog)** | Open source (MPL-2.0); Datadog Observability Pipelines is the commercial version | Pipeline (Rust) | Developer-led | **Much higher per-core throughput** (Rust); VRL transform language | Normalised security schema with ECS and OCSF views, learned parsers, evidence chain, analytics. We have not measured against Vector yet (milestone Q1-4) |
| **DNIF HyperCloud** (India) | No public price list ([Capterra](https://www.capterra.in/software/178977/dnif)) | Proprietary cloud | Indian channel (TechnoBind, M.Tech) | A full SIEM + SOAR + UEBA product with Indian customers | A pipeline that can feed DNIF; air-gapped operation; evidence chain; open core |
| **Vehere** (India) | Not public | Not public | Network detection and response; Redington distribution in India ([CXOToday](https://cxotoday.com/media-coverage/vehere-partners-with-redington-to-expand-ai-powered-cybersecurity-capabilities-in-india/)) | Network-traffic analytics; established government relationships | Different layer (logs, not packets). ULPF ingests NetFlow, so the two are complementary |

---

## 3. Five market gaps ULPF addresses

| Gap | Status quo | ULPF evidence |
|---|---|---|
| **1. Parser synthesis without hand-written rules** | Grok (Logstash), regex functions (Cribl), XML decoders (Wazuh) are written by hand per format | APG learned 7 of 7 unknown formats with 100 % coverage (integrity suite, section 16); live learning without a restart (`tests/test_usp.py`); one-command onboarding in 0.15 s |
| **2. A small-footprint pipeline** | Search clusters sized at 16–64 GB per node | Pipeline without the embedded store: host 70–77 MB plus about 43 MB per worker (`soak_20261023_013352.json`). *Qualification:* the embedded DuckDB store grows with stored rows (the 1-hour soak host peaked at 6.2 GB). The small-footprint claim applies to the pipeline, not to "SIEM in 500 MB" |
| **3. Verifiable air-gapped operation** | Cloud SIEMs need connectivity; on-premise tools are not tested for egress | `defence` mode and the in-process egress guard; integrity suite section 17 (0 external connections); `tests/test_usp.py::TestU4Offline` (an unlisted socket fails before sending). The `defense` APG profile sets `offline_only: true` |
| **4. A built-in cryptographic chain of evidence** | Rows in indexes or databases can be edited without trace | SHA-256 per record; chained Merkle seals; keyed row checksums; 6 of 6 tamper types detected; inclusion proofs. Supports BSA s.63 hash certificates (not admissibility itself) |
| **5. Flat per-node pricing** | Per-GB ingest pricing | ₹3.6 L per node per year. One laptop-class node measured 26,952 events/s; at a 60 % planning margin, it covers a 100 GB/day customer (6,321 events/s on average) |

---

## 4. Honest self-assessment

| What competitors have that ULPF lacks | Effect | Plan |
|---|---|---|
| Endpoint agent (EDR, file integrity monitoring), as in Wazuh | ULPF cannot collect host telemetry itself; it ingests from agents (syslog, journald, Windows events, EDR JSON over HTTP) | Not planned in year 1: we integrate with existing agents rather than build one |
| Detection content (Sigma, analytics rules) | Correlation uses kill-chain heuristics, not a rule library | Q1: Sigma rule import; Q1: ATT&CK technique IDs on correlation events |
| MITRE ATT&CK mapping | Stage names follow the Lockheed Martin kill chain (`STAGE_ORDER` in `correlation.py`), and no technique IDs are mapped | Q1 |
| Store at scale | DuckDB has a single writer per file, and its native memory grows with stored rows (1-hour soak, docs/STATUS.md) | Q2: daily store rotation or bounded-memory store mode; in the meantime, route bulk data to the Parquet lake or SIEM |
| Asymmetric signatures and hardware keys | Learned-parser and seal signatures are HMAC (symmetric) with a per-installation key (`provenance.py`, `evidence.py`), so a third party cannot verify them without the key | Q2: Ed25519; Q3: TPM-backed keys (sovereign edition) |
| Certifications (SOC 2, ISO/IEC 27001, Common Criteria) | Procurement blockers in BFSI and defence | Q2: third-party penetration test; Q4: ISO/IEC 27001 readiness. Common Criteria only once a defence customer requires it |
| Per-core throughput of a Rust pipeline | Python core at ≈ 12,500 events/s per core; our Rust port of the normaliser was not faster (18.6 vs 16.4 µs/event, docs/STATUS.md Phase F) | Q3: a columnar fast path (parse straight to Arrow). Until then, scale with workers and nodes (1.6× from 3 to 6 workers on 4 cores) |
| Proven scale, references | Laptop benchmarks only; no production customers yet | Q1: server sizing; design-partner pilots |
| Published accuracy on Loghub-2k | Not evaluated | Q1-3 |
| Threat-intel and GeoIP data | Bundled feeds are demo-sized (6 IOCs, 7 GeoIP prefixes). MaxMind-format `.mmdb` files are supported (`ulpf/intelligence/mmdb.py`) | Ship with instructions for GeoLite2 / DB-IP Lite; integrate MISP/STIX feed import (Q2) |
| Kafka and Event Hubs tested against real brokers | Config-validated only | Q2 |
| Licensing | The codebase is MIT; Pro and Sovereign features need a commercial licence before sale | Incubation legal work |
