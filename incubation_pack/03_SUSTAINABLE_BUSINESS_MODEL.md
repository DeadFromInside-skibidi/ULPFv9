# ULPF — Sustainable Business Model and Go-to-Market

The arithmetic for every table in this file is in `incubation_pack/model.py`. Change an input there and run `python incubation_pack/generate_proposal_docs.py` again to rebuild the pack. Inputs are labelled as **measured** (with the result file named) or **assumption**. The Year 1–3 numbers are a planning model, not a forecast.

---

## 1. Open-core tiers

| Tier | Price | What it contains (as it exists in the code today) | Who it is for |
|---|---|---|---|
| **Community** | Free | CLI (`ulpf run`, `ulpf process`, `ulpf source onboard`), TUI, 8 parsers (syslog, CEF, LEEF, JSON, KV, CSV, W3C, XML), 180 field aliases, unified schema 1.1.0, DuckDB store, journal plus exactly-once delivery to file/syslog outputs, evidence seals | Students, researchers, small teams; drives adoption and contributions |
| **Pro** | **₹30,000/month or ₹3.6 L/year per node** | Plus: GUI (14 pages) and REST API with role-based keys; autonomous parser generation with the `soc` and `industrial` profiles; selective forwarding (`format: raw`, CEF, LEEF, ECS, OCSF) to the 12 outputs (Splunk HEC, Elasticsearch, Sentinel, Chronicle, Kafka, S3/Parquet …); clustering; support SLA | BFSI, NBFCs, UCBs, mid-market enterprises cutting SIEM ingest |
| **Sovereign** | **₹10–25 L/year per site** | Plus: `defence` mode (in-process egress guard, approval-gated learned parsers, `defense` APG profile with `offline_only`, `min_accuracy 0.98`); offline install bundle; keyed row MACs; evidence-package export for BSA s.63 certificates; on-site support. *Roadmap:* Ed25519 signatures (Q2), TPM-backed keys (Q3) | Defence units, PSUs, critical infrastructure, air-gapped sites |
| **MSSP partner** | **30 % revenue share** (partner keeps 30 %; ULPF nets ₹2.52 L per node per year) | Pro features, multi-tenant deployment pattern (one node or cluster per client), partner portal (roadmap) | CERT-In empanelled auditors, managed SOC providers |

**Licensing prerequisite.** The repository is MIT-licensed today, so Pro and Sovereign features cannot be sold as proprietary until the codebase is split into an open core and commercially licensed modules. That legal work is part of the incubation ask.

---

## 2. ROI for a 100 GB/day fintech

### 2.1 Inputs

| Input | Value | Type |
|---|---|---|
| Daily raw log volume | 100 GB/day | assumption (customer profile) |
| SIEM ingest rate | $4.30/GB (Sentinel pay-as-you-go, third-party reported) | assumption |
| Commitment-tier alternative | $2.96/GB (100 GB/day tier) | assumption |
| Exchange rate | ₹88/$ | assumption |
| Raw event size | 183.1 bytes | **measured** (`encoded_size_20261023_023215.json`) |
| Bytes upstream per raw byte | raw 1.02×, CEF 2.55×, LEEF 2.46×, OCSF 9.12×, ECS 10.51× | **measured** (same file) |
| Journal on disk per raw byte | 1.359× | **measured** (`latency_footprint_20261023_023101.json`) |
| Node capacity | 26,952 events/s measured; planned at 60 % | **measured** (`runtime_tcp_20261022_024737.json`), laptop |
| Retention | 180 days (CERT-In direction, April 2022) | regulation |
| Disk cost | ₹6,000 per usable TB | assumption |

### 2.2 Results

| Scenario | SIEM cost before | Upstream GB/day | SIEM cost after | ULPF licence | Net saving/year | Saving per licence rupee |
|---|---|---|---|---|---|---|
| Forward 10 % as raw lines | ₹1.38 Cr | 10.2 | ₹14.1 L | ₹3.6 L | **₹1.20 Cr** | **33.3×** |
| Forward 25 % as raw | ₹1.38 Cr | 25.5 | ₹35.2 L | ₹3.6 L | ₹98.8 L | 27.4× |
| Forward 40.6 % as raw (our synthetic, attack-heavy corpus) | ₹1.38 Cr | 41.4 | ₹57.2 L | ₹3.6 L | ₹76.8 L | 21.3× |
| Forward 10 % raw; customer on a commitment tier | ₹95.1 L | 10.2 | ₹9.7 L | ₹3.6 L | ₹81.3 L | 22.6× |
| Forward 10 % as CEF | ₹1.38 Cr | 25.5 | ₹35.2 L | ₹3.6 L | ₹98.8 L | 27.4× |
| **Forward 10 % as ECS JSON** | ₹1.38 Cr | **105.1** | **₹1.45 Cr** | ₹3.6 L | **−₹11.1 L (a loss)** | −3.1× |

Every row includes one-off archive disk (24.5 TB for 180 days, ₹1.47 L) amortised over three years. Sizing: 100 GB/day is 6,321 events/s on average, so one node is enough at a 60 % planning margin. Peak-hour bursts need checking against each customer's traffic.

### 2.3 Corrections to the original brief

- **"₹3.1 Cr/year at 100 GB/day"** is not reproducible: 100 GB × $4.30 × 365 × ₹88 = **₹1.38 Cr**. Reaching ₹3.1 Cr needs about $9.65/GB, roughly twice the published pay-as-you-go rate.
- **"50× ROI"** is not supported. The model gives **21–33×** at pay-as-you-go rates and 22.6× on a commitment tier.
- **The saving depends on the forwarding format.** Normalised JSON forwarding is 9–14× larger than the raw line and *increases* the SIEM bill. The SIEM-diet pitch therefore relies on `format: raw` (added in v9; covered by `tests/test_coverage.py::TestSelectiveForwarding`) or on CEF/LEEF.
- The forwarded share is customer-specific. 40.6 % came from our synthetic, attack-heavy corpus; real estates are usually dominated by low-severity traffic, but each pilot has to measure its own share.

---

## 3. Three-year unit economics (planning model)

| | Y1 | Y2 | Y3 |
|---|---|---|---|
| Pro nodes (direct) | 5 | 20 | 50 |
| Sovereign sites × price | 1 × ₹12 L | 3 × ₹15 L | 8 × ₹18 L |
| MSSP partners × client nodes | 2 × 5 | 6 × 10 | 15 × 15 |
| ARR: Pro | ₹18.0 L | ₹72.0 L | ₹1.80 Cr |
| ARR: Sovereign | ₹12.0 L | ₹45.0 L | ₹1.44 Cr |
| ARR: MSSP (net of 30 %) | ₹25.2 L | ₹1.51 Cr | ₹5.67 Cr |
| **Total ARR** | **₹55.2 L** | **₹2.68 Cr** | **₹8.91 Cr** |
| Gross margin (85 %, assumption: support and infrastructure) | ₹46.9 L | ₹2.28 Cr | ₹7.57 Cr |
| Team | 4 | 9 | 18 |
| Monthly burn | ₹6 L | ₹18 L | ₹40 L |
| Annual cost | ₹72 L | ₹2.16 Cr | ₹4.80 Cr |
| **Net** | **−₹25.1 L** | **+₹12.0 L** | **+₹2.77 Cr** |

| Unit economics | Pro node | Sovereign site | MSSP partner (10 nodes) |
|---|---|---|---|
| Annual revenue | ₹3.6 L | ₹15 L | ₹25.2 L |
| Assumed annual churn | 15 % | 10 % | 20 % |
| LTV (revenue × 85 % ÷ churn) | ₹20.4 L | ₹1.28 Cr | ₹1.07 Cr |
| CAC (assumption) | ₹1.5 L | ₹6 L | ₹3 L |
| **LTV / CAC** | **13.6×** | **21.2×** | **35.7×** |

**Risks in the plan.**
- MSSP revenue is 64 % of Y3 ARR, so the plan depends on the channel. Without MSSPs, Y3 ARR is about ₹3.2 Cr, and the Y3 cost base would have to fall accordingly.
- The Y1 loss of ₹25 L is covered by the grants in Deliverable 1 (₹40 L ask).
- The CAC and churn figures are assumptions with no customer data behind them yet. Defence sales cycles of 12–24 months may push Sovereign revenue a year later than shown.
- The ₹6 L monthly Y1 burn assumes incubator space and founder salaries below market rates.

---

## 4. Go-to-market playbook

### 4.1 Sequencing

1. **Q1: three design partners** in Noida/NCR. Start with one NBFC or UCB (SIEM diet), one CERT-In empanelled auditor (channel), and one PSU or defence lab through the iDEX or DSCI network (sovereign).
2. **Q2: convert the pilots to paid**, publish anonymised before/after ingest numbers, and sign two MSSP partner agreements.
3. **Q3–Q4: repeatable sales** through the MSSP channel and TechnoBind- or Redington-style distribution; GeM listing for public-sector buyers.

### 4.2 Outreach scripts

**To the CISO or IT head of an NBFC or UCB (email, 90 words)**
> Subject: Cutting your SIEM ingest without losing CERT-In retention
>
> Most of what your SIEM is billed for is routine traffic. ULPF sits in front of the SIEM, keeps every original log line on local disk with a hash chain (180-day retention), and forwards only the events you choose, byte for byte. In our model a 100 GB/day estate at pay-as-you-go rates saves ₹77 L–1.2 Cr per year for a ₹3.6 L licence. We would like to measure your real numbers in a 30-day pilot on one server, with no change to your SIEM. Can we have 15 minutes?

**To a CERT-In empanelled auditor or MSSP**
> You run log collection for many clients, and each new client format means writing parsers by hand. ULPF learns a new format from a few hundred sample lines (7 of 7 unseen formats learned in our tests, 12–29 ms each), seals the evidence chain, and lets you keep 30 % of every node you deploy. We are looking for two launch partners in NCR.

**To a defence or PSU programme officer (iDEX/DISC context)**
> ULPF runs fully offline: an in-process egress guard blocks any unlisted connection (0 external connections in our test suite), learned parsers need human approval in defence mode, and every record is tamper-evident (6 of 6 manipulation types detected). We would like to propose a DISC challenge or a lab evaluation.

### 4.3 15-minute demo script

| Minute | Show | Command or page | Proof point |
|---|---|---|---|
| 0–2 | The problem | Slide: per-GB bill against log volume | ₹1.38 Cr/year at 100 GB/day |
| 2–5 | Start the pipeline and send mixed logs | `ulpf run --mode industry`, then replay `benchmarks/live` corpus into TCP 5514 | Live events/s in the GUI dashboard |
| 5–8 | Onboard an unknown format | `ulpf source onboard --name vendorx --sample vendorx.log` | Coverage % and time printed; parser goes live without a restart |
| 8–10 | Selective forwarding | Pipeline YAML route with `when: {severity_gte: 7}` → syslog output with `format: raw` | Only high-severity lines leave, byte-identical |
| 10–13 | Tamper evidence | Edit a stored row, then run `ulpf evidence verify --check-store` | The edit is detected; `ulpf evidence prove --seq N` gives an inclusion proof |
| 13–15 | Defence mode and pricing | `ulpf run --mode defence` with an output pointed at an address not in `airgap.allow`; show `egress.blocked` in the runtime stats (also written to the hash-chained audit log at stop, checked with `ulpf audit verify`) | Offline guarantee; ₹3.6 L per node, flat |

*Check before every demo:* run it on the demo laptop from a clean data directory, because figures shown live must come from that run, not from this document.

### 4.4 30-day pilot

| Days | Activity | Exit criterion |
|---|---|---|
| 1–3 | Install on one customer server (offline bundle if required); mirror a syslog/HEC feed with no change to the SIEM | Events flowing; `ulpf evidence verify` clean |
| 4–10 | Onboard the customer's top 5 sources with `ulpf source onboard`; tune the routes | ≥ 99 % parse coverage per source, or a documented gap |
| 11–24 | Run in parallel with the SIEM; measure the forwarded share and upstream bytes per day | Customer-specific ROI table (same model as §2) |
| 25–30 | Tamper and restore drill; review results with the CISO | Signed pilot report; paid conversion or a written reason for not converting |

Pilot price: free for the three design partners, ₹50,000 credited against the first year afterwards.
