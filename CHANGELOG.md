# Changelog

## 10.0.0 — SOAR, forensic locker, Raft, tactical edge, compliance matrix, offline copilot, web console

Short tests: `tests/test_v10_*.py` plus the existing suites this release touches. Long runs:
[docs/LONG_TESTS.md](docs/LONG_TESTS.md) (not run yet; required before the tag).

### SOAR and case management (`ulpf/soar/`)
- **Cases**: lifecycle new → triaged → investigating → containment → eradication → closed → post_incident with
  enforced transitions; per-tenant isolation; SLA timers per severity with breach flags; MTTD, time to triage /
  contain, MTTR; tasks, notes and a full timeline. SQLite (WAL, `synchronous=FULL`).
- **Evidence locker**: content-addressed (SHA-256), write-once artifacts (raw events, Merkle proofs, PCAP, files,
  notes) with a chain-of-custody log on every access and `verify_artifact`.
- **DAG playbook engine**: YAML/JSON playbooks with branching (`condition` then/else), `when` guards, `foreach`
  loops (bounded, parallel), parallel steps, sub-playbooks (depth 5 at most), retries with exponential back-off,
  trigger rules (`all_success` / `any_success` / `all_done`), persisted run state that resumes after restarts.
  Expressions use a whitelisted AST evaluator (no `eval`, no attribute access on objects, bounded size).
- **Human in the loop**: every destructive connector action needs an approval (four-eyes rule: the author of a
  run cannot approve it); approvals expire; `approval: false` is accepted only below an explicit approval step.
- **Bi-directional connectors**: PAN-OS (User-ID DAG tags, URL categories), FortiOS, Check Point, Cisco ASA,
  nftables, iptables, Wazuh, Microsoft Defender for Endpoint, CrowdStrike Falcon, Active Directory, Okta,
  Entra ID, AWS IAM (SigV4 inline deny). Every containment records its inverse; `rollback` undoes a run.
  Targets are validated before they reach URLs, XML or argv (no shell). Credentials only from env variables.
- **Dry run** for every action (exact redacted requests, nothing sent); **hash-chained audit** of every step and
  remediation command. Detections at configured levels open cases automatically and start matching playbooks.
- Bundled playbooks: external brute force, compromised host isolation, compromised identity, SOC notification.

### Forensic integrity (`ulpf/forensic_verify.py`, `native/ulpf_forensic`, `ulpf/runtime/hwkeys.py`)
- **Fixed**: correlating stored events no longer rewrites MAC'd rows. Assignments go to the append-only
  `ulpf_correlations` table (newest wins in reads and filters); `evidence verify --check-store` stays valid.
- **Hardware keys**: `evidence.key_provider: pkcs11` (non-extractable Ed25519 generated and used on the token via
  `CKM_EDDSA`; YubiKey, Nitrokey, SoftHSM2, CloudHSM, Luna; ctypes, no extra package) and `tpm` (identity key
  sealed under a TPM-resident key: Windows Platform Crypto Provider / Linux tpm2-tools).
- **No plaintext keys at rest**: the sealer's forward-secure one-time key is stored AES-256-GCM encrypted under a
  key derived from the identity key (v9 state files are migrated on start).
- **Compiled crypto**: `ulpf_core` gains `FsSigner` (ed25519-dalek, zeroized keys, sealed export), `merkle_root`,
  `merkle_leaves` and `ed25519_verify`; seals use the native Merkle root when the core is built.
- **Air-gapped verifier** `ulpf-forensic-verify` (Python, stdlib-only, and a standalone Rust binary): journal
  blocks, CRC, AES-GCM, record SHA-256, gap-free sequences, seal chain, forward-secure signatures, pinned anchors,
  Merkle roots and row MACs, streaming with bounded memory. A single flipped bit is located to the exact file,
  byte offset, bit and sequence number (CRC-32 syndrome decoding). `ulpf forensic-kit DIR` packages it.

### Cluster and fleet (`ulpf/runtime/raft.py`, `ulpf/runtime/mesh.py`, `ulpf/fleet/`)
- **Embedded Raft** (`cluster.backend: raft`): pre-vote, check-quorum, persistent log with snapshots,
  single-server membership changes, mutual-TLS TCP transport. Leases carry fencing tokens equal to the Raft log
  index; checkpoints are fenced. Drop-in replacement for the shared-directory backend (no NFS/SMB needed).
- **Rendezvous mesh**: weighted HRW routing for NetFlow templates, TCP syslog sessions and APG canaries, with
  minimal movement and explicit re-balance plans.
- **Fleet control plane**: single-use enrollment tokens, a fleet CA issuing 30-day client certificates (CSR or
  bootstrap), rotation, revocation, Ed25519-signed versioned configs per group, heartbeats with cluster-wide
  back-pressure (`throttle_eps`), and the `ulpf fleet agent`.

### Tactical edge (`ulpf/runtime/telemetry.py`, `limits_os.py`, `egress_os.py`, `runtime/ebpf/`)
- **MAVLink v2 message signing** verified (SHA-256, 48-bit signature, per-stream replay and staleness checks,
  keys from env variables); unsigned, forged or replayed commands are flagged `auth=rejected` at critical
  severity. New messages: SET_MODE, PARAM_SET, COMMAND_INT, COMMAND_ACK.
- **CCSDS + ECSS PUS-A / PUS-C** secondary headers: service/subtype names, counters, source/destination ids,
  CUC on-board time, CRC-16 packet error control, request-verification and event-report severities.
- **Hard memory ceilings** (`limits.hard_memory_mb`): Windows Job Objects (job-wide committed memory) and
  cgroup v2 `memory.max`/`memory.high`, with systemd fall-back instructions.
- **Kernel egress**: cgroup-BPF `connect4/6` + `sendmsg4/6` programs with LPM allowlists (`--format ebpf`) and
  Windows Filtering Platform outbound block rules over the complement of the allowlist (`--format wfp`).

### Compliance (`ulpf/compliance/certin.py`, `matrix.py`)
- CERT-In: all 20 Annexure I incident types, the 6-hour incident report form, SNTP check against NIC/NPL,
  180-day / India-residency retention audit (`ulpf certin report|ntp-check|retention`).
- Evidence matrix for RBI CSF, SEBI CSCRF, SOC 2 (CC6.1–CC7.3), ISO/IEC 27001:2022 (A.8.15–A.8.17, A.8.24) and
  PCI DSS v4.0 Requirement 10 (incl. CDE boundary tracking and FIM of the audit artefacts of ULPF itself).
- Sealed evidence bundles: matrix, evidence events (Parquet), Merkle proofs, seals, HTML + PDF reports,
  Ed25519-signed manifest and the bundled `verify_pack.py` (`ulpf matrix export`).

### Offline SecOps copilot (`ulpf/copilot/`)
- Local inference only: llama.cpp GGUF (GPU offload with CPU fall-back) or ONNX Runtime GenAI (DirectML / CUDA),
  pinned model SHA-256, deterministic decoding, context-window budgeting; a deterministic rules engine when no
  model is present.
- NL to KQL / SPL2 / HQL: every candidate is compiled by the ULPF query compilers before it is returned; invalid
  model output falls back to the grammar translator.
- Evidence-grounded triage narratives (initial access to impact, affected assets, root cause, ATT&CK mapping,
  containment recommendations); model prose is rejected if it mentions indicators absent from the evidence.

### Web console (`ulpf/console/`), served at `/console/`
- Multi-tenant RBAC (`auditor`, `hunter`, `analyst`, `admin`; tenant-scoped keys for MSSPs; legacy roles map).
- SOC cockpit (EPS, bandwidth, buffer fill, drops, live incident feed, approvals), multi-tab query workbench
  (highlighting, autocomplete, schema explorer, histogram, JSON inspector, copilot), ATT&CK heat map, identity /
  lateral-movement graph and Sankey flows, case board with drag-and-drop lifecycle, playbook DAG editor,
  compliance, fleet, settings. WebSocket stream with single-use tickets. No CDN, strict CSP, no build step.
- Decision: a dependency-free ES-module SPA instead of Next.js/React, so the console ships inside the air-gapped
  wheel without a Node toolchain or third-party JavaScript supply chain.

### Launch pass (live operation and performance)
- **Fixed**: SOAR auto-case creation stopped after 10,000 Sigma detections (the poller indexed into the
  bounded detection deque); it now follows an identity cursor that costs O(new detections).
- Console: one shared 1 Hz sampler for all WebSocket clients (sampling runs off the event loop; it previously
  ran once per client and every sampler reset the EPS baseline of the others); new detections are pushed live.
- New console pages: Live Tail (stream queries in the workers), Detections (live), Evidence (seals, identity key,
  one-click verification), Intel & Risk (TIP lookup, risk notables, UEBA anomalies), Cluster & Runtime, Copilot.
- `config/pipeline.live.yaml`, `START_SIEM.bat`, `scripts/start_siem.sh`: one command starts ingest, analytics,
  SOAR, copilot and the console; the Docker config enables the same features.

### Other
- New CLI: `soar`, `copilot`, `matrix`, `certin`, `fleet`, `raft`, `forensic-kit`, `console`;
  `ulpf airgap os-policy --format ebpf|wfp`; entry point `ulpf-forensic-verify`.
- Extras: `copilot`, `copilot-directml`, `copilot-cuda`. Version 10.0.0.


## Unreleased — threat intelligence platform (phase 12)

Tests: `tests/test_tip.py`. Benchmark: `python -m benchmarks.tip_scale` (result: `benchmarks/results/tip_scale.json`).

- **Indicators of every kind** (`ulpf/intelligence/tip/`):
  - **Kinds:** IPv4 / IPv6 addresses, CIDR blocks, domains, wildcard domains (`*.evil.com`), URLs, MD5 / SHA-1 / SHA-256, e-mail senders, mutex names and registry keys.
  - **Normalised before matching:** case, default ports, `hxxp`, IPv4-mapped IPv6, registry hive names (`HKLM` = `HKEY_LOCAL_MACHINE`).
  - **Metadata per indicator:** threat actor, campaign, kill-chain phase, Diamond Model (adversary, capability, infrastructure, victim), first / last seen, confidence 0.0–1.0, source, STIX id.
  - **Store:** SQLite, `<data dir>/intel/tip.db`, bounded by `intel.max_indicators`.
- **Feeds** (`intel.feeds`; host-side `TipService`):
  - **Files:** STIX 2.1 bundles, MISP event exports and OTX pulses, re-imported when the file changes. Indicators that leave the file are revoked.
  - **STIX patterns:** read by a linear scanner (`=`, `ISSUBSET`, `LIKE '%.x'`, OR / AND); `indicates` / `attributed-to` / `targets` relationships give actor, campaign and victim.
  - **Network feeds:** TAXII 2.1 collections (paged from an `added_after` cursor), MISP `restSearch` and OTX subscriptions. Credentials come only from environment variables named in the config. https only, and bounded response sizes.
  - **Defence mode:** a network feed is refused unless its host is on `airgap.allow`.
- **Confidence decay:** `confidence × 0.5^(age / half-life)`, with a per-kind half-life (IP 14 days, domain 45, URL 30, hashes 365, …). A feed re-publishing an indicator, or `ulpf intel sight`, resets the clock. Indicators below `intel.min_confidence` (0.2) or past `valid_until` leave the match set; the set is rebuilt every `intel.rebuild_minutes`.
- **Compiled matcher** (`ulpf_core.IocMatcher`, `native/ulpf_core/src/intel.rs`):
  - **Lookups:** a Cuckoo filter (16-bit fingerprints, exact-size table) in front of an exact map keyed by a per-process seeded hash. Every hit is verified against the stored value, so a hash collision can never produce a match.
  - **Ranges and patterns:** CIDR blocks by prefix length, wildcard domains by parent, and Aho-Corasick for mutexes and registry keys (scanned from the first backslash; JSON-escaped variants included).
  - **Event text** is tokenised without allocating. Candidates are checked in order and the first indicator wins.
  - **Snapshot:** the host writes `<data dir>/intel/matcher.snap`. Workers load it at start and on `reload_intel`; the swap is atomic.
- **Enrichment:** with `intel.enabled` (the default), both lanes match the source / destination IPs and the raw event text.
  - **Fields:** a hit sets `threat.category`, `confidence`, `ioc_type`, `ioc_value` and the new `threat.intel` {id, source, threat_actor, campaign, kill_chain_phase}, plus the `threat:<category>` and `ioc_match` tags.
  - **Legacy feed:** `config/iocs.json` is imported as the never-decaying `builtin` feed, matched on source / destination IP only, as before.
  - **Consistency:** the native lane, the Python pipeline and the Python fallback matcher give identical results (tests compare all three).
- **CLI:** `ulpf intel import-stix | import-misp | import-otx --file …`, `sync`, `build`, `stats`, `lookup <value>`, `sight <value>`.
- **API:** `GET /api/v1/intel/stats`, `/api/v1/intel/lookup?value=`; admin: `POST /api/v1/intel/stix` (bundle body), `/intel/sync`, `/intel/sight`.
- **Measured** with 2,000,000 active indicators of all kinds, on one Haswell i7-4790 core:
  - **Snapshot:** written in 9 s, loaded in 0.9 s; the matcher takes about 250 MB.
  - **Per-event matching cost:**

    | Corpus | Matching cost per event (tight loop) | Added to the native lane (paired runs) |
    |---|---|---|
    | Mixed syslog / CEF / LEEF / JSON / XML / CSV (194 B) | 0.57 µs | not measurable (median −0.5 µs, IQR −0.9 to +0.1 µs) |
    | URL / hash / e-mail / Windows-path JSON (323 B, ~8 candidates) | 1.9 µs | 3.5–4.1 µs |

  - **The <1 µs target** is met for the mixed corpus and **not** for the URL-heavy one (see `docs/DEFERRED_WORK.md`).

## Unreleased — UEBA, identity graph and asset context (phase 11)

Tests: `tests/test_ueba.py`.

- **Identity resolution** (`ulpf/ueba/identity.py`):
  - **Identifier forms:** AD `CORP\user`, UPN / e-mail, Kerberos, LDAP DN, AWS IAM / STS ARNs, Linux `uid=`, and bare names.
  - **Merging into one actor:** a directory import, co-occurrence in one event, or the same name in one organisation (`ueba.realm_aliases`). Generic names (root, administrator, …) never merge by name.
  - **Storage:** SQLite is the source of truth, with a bounded LRU in front.
- **Asset context** (`ulpf/ueba/assets.py`): time-ranged IP → host / owner / criticality bindings from DHCP-style events and `ueba.cmdb`, plus subnet zones.
- **Detectors** (`ulpf/ueba/engine.py`, host side): impossible travel (vectorised Haversine), unusual hour, egress spike, rare application, first access to an asset, abnormal privilege use, first use of a privileged cloud API, and token reuse.
  - **Peer groups:** built with k-means++.
  - **Output:** each detection is an `anomaly` event and adds risk.
- **The worker projection** carries the user, geo, network and threat fields UEBA needs, identically in both lanes.
- **API:** `/api/v1/ueba/actors/{id}`, `/timeline/{id}`, `/assets/{ip}`, `/peer-groups`, `/anomalies`.

## Unreleased — detection engineering (phase 10)

Tests: `tests/test_sigma_pack.py` (official SigmaHQ pack, `tests/data/sigmahq`), `tests/test_detection_engineering.py`, `tests/test_yaral.py`. Benchmark: `python -m benchmarks.sigma_scale`.

- **The SigmaHQ pack runs unmodified.** All 3,302 rules of release r2026-07-01 compile.
  - 3,112 of them (94.2%) fire on an event built from their own selections.
  - The compiled core returns exactly the Python engine's hits for every test event against all rules at once.
- **Logsource guards:** Windows categories map to Sysmon and PowerShell event IDs and channels; Windows services to channels; cloud products and Zeek to their characteristic fields. Rules no longer run on unrelated events.
  - **Field names:** Sigma field names also resolve through the last segment of flattened keys (Windows XML `event.eventdata.image` → `Image`).
- **Compiled Sigma prefilter:**
  - **Anchors:** each rule carries the literal "anchors" it cannot match without.
  - **Field automata:** the core builds one Aho-Corasick automaton per field over all rules' anchors and scans each field present in an event once.
  - **Guards first:** guards are deduplicated and evaluated first, and only candidate rules are evaluated.
  - **Python-only matchers:** a matcher only Python reproduces exactly (some regexes, non-ASCII case folding) leaves just that event to Python instead of the whole rule set.
- **Sigma correlation rules:** `event_count`, `value_count`, `temporal`, `temporal_ordered`, with `group-by`, `aliases`, `timespan`, conditions and `generate`.
- **YARA-L 2.0** (`analytics.yaral.rules`):
  - **Rule syntax:** meta, events, match, outcome and condition sections; placeholders and joins; cross-event comparisons; regex literals and `re.regex` / `re.capture` (backreferences allowed, nested quantifiers rejected); `net.ip_in_range_cidr`; `strings.*`.
  - **Windows:** hop and sliding (`before` / `after`) windows.
  - **Conditions:** `#e`, `$e`, `!$e` (decided when the window closes) and outcome conditions.
  - **Split:** workers evaluate per-event predicates on the UDM view; the host joins the candidates.
- **Risk-based alerting** (`analytics.risk`):
  - Sigma and YARA-L detections add risk to users, hosts, IPs and domains, decaying with a 7-day half-life.
  - Notable Incidents fire past dynamic per-type thresholds, or past 3 distinct ATT&CK tactics, with suppression.
  - State is saved in `<data dir>/risk/state.json`.
  - API: `GET /api/v1/risk/entities`, `/api/v1/risk/entities/{type}/{value}`, `/api/v1/risk/notables`, `/api/v1/runtime/yaral`.
- **Measured** (worker ingest, native lane, one Haswell core, against Sigma with no rules):

  | Rules | Mixed formats | Sysmon-style JSON |
  |---|---|---|
  | 1,000 SigmaHQ | −21% | −17% |
  | All 3,302 | −31% | −49% |

  Before the prefilter, 1,000 rules cost −64% / −54%. The <5% target is not met (see `docs/DEFERRED_WORK.md`).

## Unreleased — security query languages and live tail (phase 9)

Tests: `tests/test_query.py`; benchmark `python -m benchmarks.query`.

- **KQL, SPL2 and LogScale (HQL) queries** (`ulpf.query`). Each language has a recursive-descent parser; all three produce one logical plan, which is compiled to DuckDB SQL over Arrow data. Syntax and semantic errors report the exact line and column, with a caret snippet.
  - **KQL:** where, extend, project, project-away, project-rename, summarize (with `bin()`), count, take, top, sort, distinct, mv-expand, join (inner, innerunique, left/right/full outer, leftanti, leftsemi) and make-series.
  - **SPL2:** from, where, search, eval, stats, timechart, bin, rex, dedup, lookup (CSV files in `<data dir>/lookups`), table, fields, sort, head, tail, rename and top.
  - **HQL:** field filters (wildcards and `/regex/`), free text, `/regex/` with named-group extraction, `:=`, groupBy, count, sum, avg, min, max, filter, eval, in, regex, bucket, timeChart, sort, head, tail, table, select, drop, rename, top, lowercase and length.
  - **Field names:** each product's names work, for example `TimeGenerated`, `_time`, `@timestamp`, `src`, `SrcIpAddr` and `user.name`. Any other unified field is read from the event JSON.
- **Sources:** the event store (scanned from its own DuckDB connection, without holding the store lock), any lakehouse output (`source: "lake:<name>"`, hot and cold tiers), or an Arrow table.
- **Workload governor:**
  - fair-share admission, round-robin across analysts (API key names), with per-analyst and global concurrency caps;
  - a memory reservation per query, each query in its own DuckDB instance with `memory_limit`;
  - deadlines that include queue time (interrupted when exceeded), and an even CPU thread share.
  - Configured in the `query:` section.
- **Live tail:** row-level queries run on every ingest batch in the workers, before anything is persisted. Tails are distributed as a lease. Matches go to bounded per-tail queues (drop-oldest, counted), read by long poll or server-sent events. Each tail is private to the analyst who opened it.
- **API:**
  - `POST /api/v1/query`, `POST /api/v1/query/validate`, `GET /api/v1/query/governor`;
  - `POST|GET /api/v1/live`, `GET /api/v1/live/{id}` (`?wait=`), `GET /api/v1/live/{id}/stream`, `DELETE /api/v1/live/{id}`.
- **Measured** (500k events, 8 CPUs, 2 threads per query): typical hunts take 15–438 ms. Four live tails cost 11 ms per 1,000-event batch.

## Unreleased — lakehouse output (phase 8)

Tests: `tests/test_lakehouse.py`; benchmark `python -m benchmarks.lakehouse`.

- **New output `lakehouse`.** Two tiers:
  - **Hot tier:** Arrow IPC batches in a memory-mapped ring on local NVMe (`ulpf_core.HotRing`). It has one writer and lock-free readers, and keys records by `tenant/date/hour`.
  - **Cold tier:** a Delta Lake table on local disk, S3, MinIO, Ceph or Azure Blob, partitioned `tenant_id=/date=/hour=`.
- **Cold-tier encryption (optional; required in defence mode):** client-side AES-256-GCM. Every file gets its own key, wrapped with a master key read from an environment variable. Commits carry an HMAC chain, which `ulpf lake verify` checks.
- **Daemons:**
  - the flusher commits each flush with a `txn` position, so a crash cannot duplicate data;
  - the compactor merges into files of up to 512 MB with zstd, dictionaries, statistics and page indexes, plus bloom filters on `source_ip`, `destination_ip`, `user_name` and `hash_sha256`;
  - retention and vacuum clean up old data.
- **Queries:**
  - federated DuckDB queries over both tiers prune by partition, file statistics and bloom filters, and run in a sandbox (allowed directories only, external access off, configuration locked);
  - an Arrow Flight endpoint requires a bearer token and supports TLS/mTLS;
  - `ulpf lake status|query|compact|verify` on the command line.
- **Measured** (one Haswell core, encrypted, 2M events):
  - host ingest 70.7k ev/s pipelined (2.4× the 2.5B events/day rate);
  - compaction 89.6k ev/s;
  - peak RSS 412 MB;
  - an IP lookup scans 1 of 48 files.
- `HttpClient` streams file bodies and responses; `sigv4_headers` accepts a precomputed payload hash (uploads of up to 512 MB with bounded memory).
- Native TLS syslog no longer sends TLS 1.3 session tickets. A sender that closed without reading them could lose its records to a connection reset on Windows.

## Unreleased — compiled ingestion kernel and standard views (phase 7)

Tests: `tests/test_native_scan.py`, `tests/test_native_analytics.py`, `tests/test_native_listeners.py`, `tests/test_standards.py`; goldens in `tests/golden/views` regenerated.

- **Analytics on the native lane.** Sigma (compiled IR), routes, anomaly and drift run in `ulpf_core` on the batch, so turning on routing or analytics no longer drops the lane back to Python dicts. Single core, 20k events: 4.2k → 23.4k ev/s with analytics on.
- **Zero-copy batches.** Record bytes are read in place and the batch is exported through the Arrow C Data Interface (`__arrow_c_array__`).
- **Hand-written scanners** (memchr) replace the hot-path regexes; each one is differential-tested against Python `re`.
- **Native network inputs** (`engine: auto|native|python`, default auto): syslog UDP/TCP/TLS on Tokio with SNI certificate selection (`tls.sni_certs`), SNI routing to another input (`tls.sni_routes`) and client certificates; NetFlow v5/v9/IPFIX with the same template-cache file; SNMP v1/v2c/v3 (USM adds SHA-224/256/384/512 and AES-192/256).
- **New input `otlp_grpc`**: OTLP logs over gRPC (port 4317), gzip, optional bearer API key and TLS.
- **Views**: `ocsf` is now OCSF 1.3.0 and validates against the bundled schema. New `udm` (Chronicle events, entities, security_result) and `asim` (Authentication, Network, DNS, Web, Process) views. Every view converts back (`from_view`) without loss; vendor fields with no standard home are kept under `x_<vendor>`.
- **Fix:** the Python NetFlow input crashed on flow times outside the platform's `gmtime` range. Such records are now rejected and counted, as in the native decoder.
- **Config:** `tls.sni_routes` targets must name an existing input; the SNI options require `engine: auto|native`.
- **Learned parsers (APG) dispatch in Rust.** Every live learned parser's pattern sits in one `RegexSet` (`ulpf_core.ApgSet`, linear time); the core picks the parser with the registry's priority rules, captures and extracts the fields (including the key=value scan). Lines that are not printable ASCII go to the unchanged Python path. Learned-format parse rate: 19k → 98k ev/s on one core. `ApgMatcher` publishes sets through ArcSwap. `ULPF_NATIVE_APG=0` turns it off.
- **`learning.engine: streaming`** runs the APG 2.0 streaming engine in the workers (default `classic`). Its hot-swap set now mirrors the registry, so operator approve/reject and signature checks reach it, and generic (anchor-less) parsers no longer match arbitrary lines.

## Unreleased — security and packaging hardening (phases 1–2)

Tests: `tests/test_hardening.py`; updated `tests/test_runtime.py`, `tests/test_usp.py`.

### Security fixes
- **API roles on the v8 routes.** `ulpf/api/routes.py` only checked that a key was valid, so a `read` key could call `/ingest`, `/auto-learn`, `/correlate` and `/listener/*`. Every route now declares `read`, `write` or `admin`. A test fails if a new route declares none.
- **Unsigned learned parsers are refused when approval is required** (defence mode). Before, a spec with its signature fields deleted loaded as "unsigned".
- **Evidence seals are signed with Ed25519, forward-securely.** Each seal is signed by a one-time key and names the next one. The signing key is erased once the seal is written. The first key of a chain is certified by the identity key (`evidence/evidence.pem`, public `evidence.pub`). Verifiers need only `evidence.pub`. Someone who takes over the host cannot re-sign seals written before the takeover.
- **Row MAC keys ratchet forward** (`K_{e+1} = BLAKE2b(K_e)`, one epoch per `evidence.row_key_epoch_records` records). The host erases the keys of committed epochs. `K_0` is escrowed: it is sealed to an auditor's X25519 key (`evidence.row_key_escrow`, `ulpf evidence escrow-keygen`) or written once to `evidence/row_key.k0` to be moved off-box.
- **Parser specs are signed with Ed25519** (`parser_signing.pem` / `.pub`). The signature binds content, state and the operator decision. Other nodes' keys can be trusted through `ULPF_PARSER_TRUSTED_KEYS`. Old HMAC specs still verify while `parser_signing.key` exists.
- **The egress guard follows DNS.** Allowed names are re-resolved every `airgap.dns_refresh_seconds`. Addresses the process itself resolves are allowed at once. Rotated-out addresses stay allowed for `airgap.dns_grace_seconds`.
- **Native-code egress.** Defence mode locks DuckDB's external access (`enable_external_access=false`, no extension autoload, `lock_configuration`). Kafka broker lists are checked against `airgap.allow` before they reach librdkafka. `ulpf airgap os-policy` renders an nftables or systemd policy that also binds native threads, and `ulpf airgap os-check` checks that the kernel enforces it (Linux).

### Behaviour changes
- Defence mode needs protected signing keys: set `ULPF_EVIDENCE_PASSPHRASE` (or `evidence.key_passphrase_env`), or use `evidence.key_provider: keyring`. To waive, add `defence.key_protection` to `overrides`.
- New installations no longer create `evidence.key` or `parser_signing.key`. `ulpf evidence verify` takes `--pubkey`, `--row-key` and `--escrow-key`. On the host it counts the row MACs of erased epochs as `row_macs_unchecked` and does not report them as problems.
- `pip install` installs only `ulpf` (no top-level `benchmarks` package). `ulpf benchmark` runs from a checkout. `[dev]` now includes the whole test and build toolchain.

### Scaling and clustering (phase 3; tests: `tests/test_scaling.py`)
- **Learned-parser dispatch no longer scans every parser.** Each adaptive parser is indexed under its rarest literal token. A line is split once per separator in use and looked up in a dict. Results are the same as the old ordered scan: active parsers beat canaries, and on a tie the parsers learned from the line's own source win. Measured per line, from 50 to 500 parsers: about 3 µs to 3.5 µs, against 33 µs to 426 µs for the old scan.
- **Time-partitioned event store.** The DuckDB output now writes one file per day by default (`partition: daily|hourly|none`, plus a size roll with `partition_max_mb`).
  - Only the active partition is open read-write. A finished partition is checkpointed and reopened read-only.
  - `events` is a view across all partitions, so existing queries and raw SQL keep working. Pages are still read with late materialisation, one partition at a time.
  - The exactly-once ledger lives in each partition and is checked across all of them.
  - `retention_days` retires whole files (deleted, or moved/exported as Parquet to `archive_dir`) instead of running `DELETE`.
  - The runtime runs rotation, retention and checkpoints every minute.
  - An existing single-table store is kept as a read-only `legacy` partition.
  - Statements that change stored rows go through `Database.execute_on_partitions`.
- **Cluster leases with fencing tokens.**
  - Nodes judge each other alive from heartbeat sequence progress on their own monotonic clock, so wall-clock time stamps are never compared.
  - `placement: one` inputs need a lease, taken under an OS record lock. A lease held by a live node is never taken, and every change of holder increments the token.
  - Shared checkpoints are written with the token, a write with an older token is refused, and positions are adopted by token.
  - A node that cannot write its heartbeat for half of `failover_seconds` stops its single-owner inputs.
  - A graceful stop releases leases after the last checkpoint flush.

### Compiled batch engine (phase 4; tests: `tests/test_native_lane.py`, benchmark: `benchmarks/native_lane.py`)
- `ulpf_core.Engine` handles whole dispatcher batches with the GIL released and no Python object per event. It covers detection, the syslog/CEF/LEEF/key=value/JSON parsers, normalisation (timestamps, severity, actions, protocols, field mapping) and the worker's fields. It also finishes the row: enrichment from per-IP lookups, the BLAKE2b row MAC and the store row in Arrow buffers.
- A record goes to Rust only when Rust reproduces the Python result exactly. Everything else (CSV/W3C/XML, APG, plugins, non-ASCII, unusual timestamps or numbers) goes to the Python pipeline in order. The tests check events (key order included), store rows and row MACs record by record, and compare whole-worker output across the Python, hybrid and columnar paths.
- Columnar lane: with anomaly/drift off, routing that does not depend on event fields, and DuckDB outputs, no event dicts are built. Measured on one core of this machine: ~22k ev/s against ~8k for the Python worker (syslog/CEF/LEEF/JSON/KV). This is short of the 100k EPS/core target; see docs/DEFERRED_WORK.md.
- On by default when the extension is built; `ULPF_NATIVE_LANE=0` turns it off. `scripts/build_native.ps1` also builds with the MSVC toolchain.
- Buffer segments are written without Parquet statistics and with dictionary pages only on low-cardinality columns: ~19 % faster to encode at the same size. Workers no longer build correlation projections when correlation is disabled.

### Sigma rules and MITRE ATT&CK (phase 5; tests: `tests/test_sigma.py`)
- `ulpf/intelligence/sigma.py` compiles Sigma YAML rules into closures (no eval/exec).
  - Supported: field modifiers (contains/startswith/endswith/all/re/cidr/exists/lt..gte/base64/base64offset/utf16/windash/cased/fieldref), keyword lists, null values, the full condition grammar (`N of x*`, `all of them`, not/and/or), and `count([field]) by group > N` aggregations over a timeframe.
  - Rule collections are supported. Unsupported rules are rejected with a reason.
- Field names resolve to the unified schema, then Sigma/Windows/ECS names, ULPF's vendor aliases, and finally the original vendor fields. Raw-field rules (`EventID`, `IpAddress`, `CommandLine`) therefore work on normalised events.
- A bundled pack of 19 rules covers T1110, T1110.003, T1078, T1046, T1595, T1190, T1505.003, T1059, T1071, T1571, T1572, T1048, T1041, T1566, T1105, T1136 and T1070.
- Workers evaluate rules on full events and send the hits with each correlation projection. The host runs the aggregation windows, emits `detection` events, and tags correlation groups with `mitre` (tactics, techniques) and `sigma_rules`. ATT&CK tactics also feed the 7 existing kill-chain stages, and the risk score gains up to +2 for the highest rule level.
- `EventCorrelator(sigma="builtin")` is the default (pass `sigma=None` for keyword stages only). It covers the API `/correlate`, the GUI and the CLI as well.
- New config `analytics.sigma` (enabled, builtin, rules, dedupe_seconds), new API endpoints `/api/v1/runtime/detections` and `/api/v1/runtime/sigma`, and new CLI `ulpf sigma list|check|test`.

### Compliance packs (phase 6; tests: `tests/test_compliance.py`)
- **Shared signed packs** (`ulpf/compliance/packs.py`): a ZIP with a SHA-256 manifest and an Ed25519 signature from the evidence identity key. Each pack carries `verify_pack.py`, a standalone verifier that uses only the standard library, including a pure-Python RFC 8032 Ed25519. It checks files, signature, seals and Merkle inclusion proofs.
- **DPDP Act** (`ulpf/compliance/dpdp.py`, `pii.py`):
  - PII discovery with validated detectors (Aadhaar with Verhoeff, PAN, Indian mobile, email, card with Luhn, IFSC, UPI, passport, voter ID, GSTIN, IP). Pipeline stage `compliance.dpdp` with `detect` (tags), `redact` or `tokenize` (keyed HMAC). The journal keeps the bytes received, and raw retrieval becomes admin-only.
  - Verifiable erasure (`ulpf compliance dpdp erase`, `POST /api/v1/compliance/dpdp/erase`):
    - Journal records are rewritten with a salted SHA-256 commitment in place of the raw bytes. The original digest is kept, so seals still verify.
    - Store rows lose their personal fields.
    - The result is an Ed25519-signed Certificate of Erasure (JSON + HTML) that also serves as the ledger `ulpf evidence verify` honours, plus a receipt with the salts for the Data Principal.
  - 72-hour breach pack (`ulpf compliance dpdp breach-pack`): incidents from correlation groups and detections, CERT-In 6-hour and DPB 72-hour deadlines, suggested CERT-In incident types, affected Data Principals by category (counts only), ATT&CK techniques, and redacted events with seals and Merkle proofs.
- **EU CBAM** (`ulpf/compliance/cbam.py`):
  - CSV templates. `csv2jsonl` adds the source-file SHA-256 and row number so records are journaled and sealed. There is a new `cbam` output view.
  - Calculation per good: direct, precursor and indirect emissions, SEE, direct-only rule for iron/steel/aluminium/hydrogen, defaults with the year's mark-up, the phase-in chargeable share 2026–2034, certificate and cost estimates, and the 50 t importer threshold.
  - `export-pack` writes `cbam_datapack_<installation>_<period>.zip` with a proof for every record.
- **Tactical edge** (Section 5.3): `profile: tactical_edge` (defence mode, 1 worker, hourly partitions, small buffers) and new `limits` (max_rss_mb, max_disk_mb, duckdb_memory_mb). Syslog UDP gains `telemetry: mavlink | ccsds`, with MAVLink v1/v2 decoding (X.25 CRC, 7 messages) and CCSDS Space Packets. New `ulpf bundle` writes a signed offline forensic bundle.

### Other
- `GET /api/v1/runtime/parsers` and the approve/reject endpoints use one engine per runtime instead of re-reading and re-compiling every spec on each request. Decisions are sent to the workers at once.
- The v8 routes stop using a runtime once its API server stops (stale module state caused 500s).
- `scripts/clean_repo.py` (dry run unless `--yes`), `MANIFEST.in`, and extended `.gitignore` / `.dockerignore`.

## 9.0.0

The live pipeline release. Every number below has a result file under
`benchmarks/results/`; docs/STATUS.md records how each was measured.

### Runtime (`ulpf run`)
- Inputs → durable journal (per-record SHA-256, CRC blocks, torn-tail repair, AES-256-GCM in defence mode) → worker processes → per-output disk buffers → senders, with exactly-once delivery into the buffers and a persisted commit watermark. A crash replays from the journal without duplicating anything.
- Validated YAML pipeline config: every error reported with its line number, `ulpf config check|show|example`, hot reload (`ulpf reload`, SIGHUP) that rejects an invalid file without changing anything.
- Two modes, **defence** and **industry**, with named, auditable waivers (`overrides:`).
- 15 inputs: syslog UDP/TCP/TLS, file tail (rotation, truncation, multiline, container logs), HTTP, OTLP (JSON and protobuf), journald, Windows event channels, NetFlow v5/v9, SNMP traps v1/v2c/v3, MQTT, Kafka, CloudTrail, Pub/Sub, Okta, Entra ID, Event Hubs.
- 12 outputs: DuckDB, file, Parquet lake, S3, Elasticsearch/OpenSearch, Splunk HEC, Kafka, Loki, OTLP, syslog (RFC 5424/CEF/LEEF), Azure Monitor Logs Ingestion, Chronicle. Each has retries with back-off, a bounded buffer (`block` or `drop_oldest`), and a dead-letter queue with per-record reasons; each can emit the unified, ECS or OCSF view.
- Routing by kind, input, source, format, category, severity or field.

### The five USPs, live (tests/test_usp.py)
- U1: autonomous learning on live traffic, learned parsers stored per node, `learning.max_parsers_per_source` enforced, defence-mode approval gate.
- U2: rolling chained Merkle seals emitted as events; `ulpf evidence verify|prove`; per-row keyed BLAKE2b MACs (on by default in defence mode) detect edits to any stored column.
- U3: golden-file tests for unified, ECS and OCSF views; schema 1.1.0 with registry and `ulpf schema diff`.
- U4: in-process egress guard (audit hooks) in host and workers: destinations are recorded in industry mode and blocked outside the allow-list in defence/air-gap mode.
- U5: per-source structural drift and anomaly events in the workers; cross-source correlation groups in the host.

### New
- `ulpf source onboard`, parser plugins (`ulpf.parsers` entry points, package-hash allow-list), `ulpf plugins list`.
- Raw retrieval (`GET /api/v1/events/{id}/raw`, `ulpf raw get`).
- Multi-node: shared-directory heartbeats, rendezvous-hashed placement, failover from shared checkpoints, `ulpf cluster status`, fan-out queries.
- API roles (read/write/admin) with `ulpf apikey new`, TLS and mTLS, hash-chained audit log.
- Offline MaxMind-format GeoIP (`.mmdb`) reader; special-purpose IP ranges are labelled, never geolocated.
- Parquet ML export with a column card. Chaos tests and soak harness. Competitive benchmark harness and configs.
- systemd unit, NSSM instructions; the Docker image runs the live pipeline.
- Optional Rust core (`native/ulpf_core`) for the normalisation step, equivalence-tested and opt-in, because it is not faster than the Python path (docs/STATUS.md, Phase F).

### Fixed
- Windows UDP listeners stopped after an ICMP port-unreachable (`WSAECONNRESET`).
- An omitted optional config section with a required key (`multiline`) failed validation.
- First-seen-IP anomalies fired for every new address after 50 events; `anomaly_type` was always empty.
- Integer fields above 2⁶³ made the whole batch fail to encode.
- With `when_full: block`, a full buffer could deadlock: later batches cannot drain before an earlier one. A segment larger than the whole buffer was rejected.
- The DLQ could exceed `dlq.max_mb` by a whole rotation file.
- Shutdown races: journal reads after close; input restarts and cluster take-overs during stop; buffer stats racing segment deletion.
- Pre-9.0 Parquet spool shards failed to ingest after the schema gained a column.
- Log DNA batch drift missed reordered tokens and raised false alarms on JSON with optional keys.
- The bundled GeoIP table gave documentation ranges US coordinates; re-imports kept deleted prefixes.
- Cloud inputs and token fetches leaked HTTP connections. sshd lines did not yield user or source port.
- DuckDB memory cap and WAL checkpoint now scale with the machine (they were fixed at 4 GB and 1 GB).
- Streaming correlation kept every group in memory after its window closed (up to 5,000 groups × 10,000 events). Host memory grew by about 1.1 GB per hour at 5,000 events/s. Closed groups are now emitted and evicted, and open groups are capped (`analytics.correlation.max_groups`, `max_group_events`).

### Known limitation
- The embedded DuckDB store's native memory grows with the number of stored rows (about 1.3 GB over 18 million rows in the soak). Allocator flushing is enabled. For sustained high volume, use the store for a retention window and send bulk data to the Parquet lake or a SIEM (docs/INSTALLATION.md, "Sizing the local store").

## 8.2.0

Production-hardening release: correctness fixes across the pipeline, removal of
synthesised metrics, a reworked auto-parser, and measured performance.

### Integrity of claims
- Desktop EPS was floored at 98 % of the simulator's *target* rate; it is now measured from completed events (worker counters).
- Live Log DNA similarity was floored at 0.85 and always "matched"; it now reports the computed similarity.
- `is_air_gapped()` returned `True` unconditionally; it now reports whether an outbound route exists.
- Integrity suite: drift detection passed unconditionally (`or True`) and APG precision/recall were hard-coded; both are now real measurements.
- Learned parsers carried a literal `"stub_signature_phase3"` as a "PKI signature"; specs are now HMAC-signed with a persisted per-installation key and verified on load.
- "SHA-256" provenance hashes were MD5; they are SHA-256, computed once per line.
- "Merkle chain" was a linear hash chain; chains now also have a Merkle root with inclusion proofs.

### Engine & parsers
- Severity labels covered 0-6 of the 0-10 scale (most events were `unknown`); full scale now.
- Timestamps are converted to UTC (offsets were kept); yearless syslog never lands in the future.
- W3C `#Fields:` directives were dropped before reaching the parser; CSV header rows were stored as events.
- CEF: spec-compliant `\|`, `\=`, `\\` escaping; values containing `=` (URLs) no longer split; `csNLabel` resolution.
- LEEF 2.0 delimiter field (`^`, `x5E`, `0x09`) parsed correctly; space-separated LEEF accepted.
- XML: DTD/entity payloads rejected; DNS events categorised; Windows `<Data Name=…>` fields mapped.
- JSON: orjson, exact-key-first lookup, ECS dotted paths (`source.ip`) mapped.
- Compound actions (`allow-url`, `client-rst`) normalised; categories folded into one taxonomy.
- `SCHEMA_DEFINITION` was an empty dict; it is now the 93-field catalogue used by the API and GUI.

### Auto-Parser Generator
- Constant-in-sample dates, severities and numbers were baked into templates, so learned parsers stopped matching the next day.
- Learned layouts were discarded (`MatchSpec` overwritten), regexes ignored the delimiter, positional groups were misaligned with KV groups, and `source.ip`/`destination.ip` collided as `{ip}`.
- New: multi-token timestamps, `ip:port`, context naming (`from <ip>`, `user <name>`), nested segment templates, bracket groups, validated IPv6, positional ports.
- Learned/promoted parsers are persisted and hot-reloaded in every process; registry is copy-on-write (no iteration races); retired parsers are no longer used.
- Anti-poisoning no longer quarantines busy legitimate sources for 60 s; it rate-limits sampling and quarantines only structure-fabricating sources.
- Shared `learn()` API with validation for CLI, REST and GUI; known-format lines are excluded.
- Tab-delimited values were compiled as `\S+` (tab treated as free whitespace), so `msg=Login failed` never matched; tab is now a structural delimiter.
- The tokenizer stripped quote characters from tokens, so literals rebuilt from them could not match the raw line, and `msg="a b"` was split in two. Quoted spans are kept whole, with their quotes; CSV fields may be quoted and contain the delimiter.
- The last `key=` value runs to the end of the line; the line-level KV fallback keeps spaces in tab-separated values.
- Formats that only share a structural fingerprint were mined as one cluster and rejected; they are now split by positional structure and learned separately, each validated on its own lines.

### Tools & docs
- `ulpf fingerprint` reports format drift against the last fingerprint stored under the same label.
- `qt_app --verify` also parses lines in a spawned worker process, which catches broken frozen builds.
- PyInstaller spec (`packaging/ulpf_desktop.spec`), verified by building `ULPF.exe` and passing `--verify`; Vector edge-collector example (`deploy/vector.toml`).
- Enterprise benchmark: workers sized to the machine (was 20), soak at a sustained 5k EPS (was 5M), CLI phases isolated from the user's data directory.
- GUI: primary buttons with invisible text, truncated `+00:` timestamps, and a clipped column header fixed; version shown from `ulpf.__version__`; schema labelled OCSF-inspired rather than "OCSF Standardized".
- Removed: stale launchers (`run_desktop.*`, old `ULPF.exe`), broken Tkinter GUI and stub workers, dead modules, committed runtime state (`learned_parsers/`, results, outputs). Docs rewritten to match the code.

### Storage & ingestion
- `reset_database()` called a non-existent method and left the store without tables.
- Writes were unlocked on a shared DuckDB connection; a locked store silently diverted data to a temp file (now: read-only + `DatabaseLockedError`).
- CLI, desktop and listener used three different stores; one canonical store now (`ULPF_DATA_DIR`, `ULPF_DB_PATH`, `--db`).
- Worker counters were lost when a non-blocking lock was contended; Parquet shards were read while being written; one bad shard blocked ingestion forever; string ports broke int32 batches; the writer exited without draining.
- WAL checkpoint tuning restored (22k → 61k rows/s bulk load); PK index removed (append cost grew with table size); anomalies bulk-inserted via Arrow; grouped commits.
- TCP octet-framing misdetection on lines starting with digits; UDP handler no longer blocks the event loop; drops are counted.
- Correlation was O(N²) in streaming mode with unbounded memory; now amortised O(1) with merges and bounds.

### Operations
- REST: sync handlers (no event-loop blocking), optional API key, `/health`, Prometheus `/metrics`, real CSV responses, upload limits, forensic package verification, listener shares the store.
- CLI: `--db`, streaming `process`, `forensic --verify/--list`, `purge --older-than-days`, validated `learn`.
- Docker: health check on `/api/v1/health`, state on volumes, binds 0.0.0.0 explicitly.
- Tests isolated to temp dirs (they wrote into `learned_parsers/` and the user's store); new 39-test core suite with a live HTTP API; APG evaluation; CI workflow.
