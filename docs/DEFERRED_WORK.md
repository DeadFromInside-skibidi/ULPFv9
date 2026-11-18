# Deferred work: refactor phases 1–6

This file tracks everything a phase left undone, simplified, or not verified.
Each phase adds its items here when it finishes, and they are worked through
after all six phases are done. Strike an item through (or delete it) only once
the work is done **and** has a test or measurement that shows it.

Status keys: **[verify]** built but not yet tested or measured well enough ·
**[build]** not implemented · **[decide]** needs a product or security decision first.

---

## Release 10.0 status

Resolved in 10.0 (each with a short test in `tests/test_v10_*.py`):
- ~~`set_correlation` rewrites the MAC'd `correlation_id`~~ → append-only `ulpf_correlations` side table (`test_v10_forensic.CorrelationIsolation`).
- ~~Hardware/HSM key providers: PKCS#11, TPM 2.0, YubiKey~~ → `pkcs11` and `tpm` providers (`ulpf/runtime/hwkeys.py`). Cloud KMS is still not implemented.
- ~~Rust `ed25519-dalek` signing in `ulpf_core`~~ → `FsSigner`, `merkle_root`, `ed25519_verify` (`native/ulpf_core/src/crypto.rs`).
- ~~A networked lease coordinator~~ → embedded Raft (`cluster.backend: raft`).
- ~~CERT-In 6-hour reporting and the 20 incident types~~ → `ulpf/compliance/certin.py`. Counsel review of the form fields is still required (see Phase 6 "Legal and regulatory review").
- ~~MAVLink v2 signatures reported, not authenticated; CCSDS primary header only~~ → authenticated signing, PUS-A/PUS-C secondary headers. TM/TC transfer frames and several packets per datagram are still not decoded.
- ~~`limits.max_rss_mb` only warns~~ → `limits.hard_memory_mb` (Job Objects / cgroup v2).
- ~~Windows has no OS-level egress filtering~~ → `--format wfp`; Linux gains `--format ebpf` (cgroup-BPF; covers native code).

Open after 10.0 (built and short-tested, not yet verified at scale or on the target hardware; see [LONG_TESTS.md](LONG_TESTS.md)):
- **[verify]** PKCS#11 against SoftHSM2 and real tokens (unit test uses a fake module; YubiKey EdDSA needs firmware 5.7+). TPM sealing tested with the CNG *software* KSP and on no Linux TPM.
- **[verify]** eBPF programs were not compiled or attached here (no Linux kernel); WFP rules were rendered, not applied (needs elevation).
- **[verify]** Raft: deterministic chaos (3 seeds × partitions/loss/duplication) and a 3-node localhost TCP cluster pass; multi-host partitions, process kills and the 500-seed run are long tests.
- **[verify]** Fleet: functional test only; the 10,000-agent / < 2 % CPU target is unmeasured. Agent connections are HTTPS long-poll with mTLS, not gRPC streams (the decision avoids a gRPC dependency in Python).
- **[verify]** 100 GB archive verification and exact bit localisation measured only on a 125-record fixture. Bit localisation needs a single-bit error within a block of at most 16 MiB; other corruptions are reported per record (SHA-256) or per seal window (Merkle).
- **[verify]** Copilot with a real GGUF/ONNX model: only the rules backend and fake models were exercised; DirectML/CUDA paths are untested.
- **[verify]** Web console: API and WebSocket tested end to end; the UI was syntax-checked but not exercised in a browser test harness (no Playwright here). Accessibility audit (axe) pending.
- **[decide]** Console stack: dependency-free ES-module SPA instead of Next.js/React/shadcn (air-gapped wheel, no Node toolchain, no third-party JS supply chain). Revisit if a separately deployed web tier is acceptable.
- **[build]** SOAR connectors are tested against recorded request shapes, not live firewalls/EDRs/IdPs. Wazuh isolate/kill/quarantine rely on custom active-response scripts named in `commands`.
- **[build]** Compliance control mappings are evidence heuristics over the unified schema; auditors must review them, and the SEBI CSCRF and RBI mappings cover the logging/monitoring controls only.

## Cross-phase verification (after phase 6)

- **[verify]** Run the whole test suite on Linux as well as Windows. The suite has only been run on Windows 10 with the bundled Python 3.11 (`python311/`). Linux-only code paths have never run: `fcntl.lockf` leases, `egress_os.os_check`, and nftables/systemd policies applied to a real host.
- **[verify]** Run the suites this refactor has not run so far: `tests/test_service_and_gui.py` (PySide6 GUI) and the TUI.
- **[verify]** Run the suite under `pytest` (now in `[dev]`). So far only `python -m unittest` has been used, and `pytest-asyncio` (`asyncio_mode = "auto"`) has never been exercised.
- **[verify]** Install the package (`pip install .`) and check: only `ulpf` is installed, `ulpf benchmark` prints its "run from a checkout" message, and the Docker image builds and starts.
- **[verify]** Look at two flaky chaos tests. `test_chaos.TestSinkFailures.test_buffer_full_drop_oldest_counts_exactly` failed in the baseline before any change.
  - `test_buffer_full_block_stalls_ingest_without_loss` failed in the full runs after phases 3 and 4, both times with the same numbers: 2 segments, 5.6 MB, against a 1 MB cap. It passed after phase 5, and 3 times out of 3 on its own.
  - Likely cause: a race in `DiskBuffer` `when_full: block` across worker processes. Each worker sees room before the other's segment lands, so two over-cap segments are written. This is a real bound violation, not only test flakiness.
- **[verify]** Upgrade a real 9.0 installation in place: existing `evidence.key` / HMAC seals, HMAC-signed parser specs, and a single-table `ulpf.duckdb`.

## Phase 1: security and packaging

- **[decide]** Run `scripts/clean_repo.py --yes`. It has only been dry-run: 276 MB found, nothing deleted. Deleting `ulpf/ulpf_core.pyd` disables the current native core until it is rebuilt.
- **[verify]** Role mapping of the v8 routes: `POST /fingerprint`, `/forensic/chain` and `/forensic/export/{id}` are **write**; `/parsers/test`, `/fingerprint/match`, `/fingerprint/drift` and `/forensic/verify-package` are **read**. Confirm this matches product intent.
- **[build]** Record which API key name (not only `"api"`) approved or rejected a parser in `decided_by`.

## Phase 2: cryptography and egress

- **[build]** Hardware/HSM key providers: PKCS#11, TPM 2.0, YubiKey, cloud KMS. Only `file` (PKCS#8, passphrase-encrypted) and `keyring` exist. The `keyring` provider has never run (the package is not installed here).
- **[build]** Rust `ed25519-dalek` signing in `ulpf_core`, as the original plan asked. Signing is Python `cryptography` only.
- **[build]** Linux seccomp-bpf / landlock / network-namespace / `LD_PRELOAD` egress enforcement. Only nftables and systemd policy rendering plus `os-check` exist. Landlock cannot filter by destination IP.
- **[build]** Kafka brokers that a cluster *advertises* after the first connection are not checked by `vet_endpoints`; only the OS-level policy stops them. Other native clients (pyarrow S3, the Azure Event Hubs SDK) have no endpoint vetting at all.
- **[build]** DNS refresh does not read real DNS TTLs (`getaddrinfo` does not expose them). It re-resolves on a fixed `airgap.dns_refresh_seconds` with a grace period.
- **[verify]** Key erasure is best effort (overwritten state files, dropped references). It has not been tested on an SSD or a journaling filesystem; recommend full-disk encryption.
- **[build]** `POST /api/v1/correlate` (`set_correlation`) rewrites `correlation_id`, which the row MAC covers, so correlating stored rows makes `evidence verify --check-store` report them as edited. This existed before phase 2. Fix: exclude `correlation_id` from the MAC (new MAC version) or keep correlations in a side table.
- **[verify]** The interaction between a seal written just before a crash and its recovery is tested in-process only, not with a real process kill.
- **[decide]** Defence mode now refuses to start without a key passphrase (`defence.key_protection`). Existing defence deployments need `ULPF_EVIDENCE_PASSPHRASE` or a waiver. Document this in the upgrade notes.

## Phase 3: scaling and clustering

- **[verify]** Memory target: bounded RSS under 500 MB in a sustained 5k–50k EPS soak (`benchmarks/soak.py`, 1 hour or more). Not measured.
- **[verify]** Ingest throughput of the partitioned store compared with the single table. Not benchmarked.
- **[build]** Lazy attach of sealed partitions. Every partition within retention is attached (180 daily files under defence retention); none are attached on demand or detached when idle.
- **[build]** A networked lease coordinator (HTTP/mTLS Raft-lite or gossip, or an etcd/Redis backend). Only the shared-directory backend with OS record locks exists. SQLite was rejected because it is unsafe on NFS.
- **[verify]** Leases on real NFSv4 and SMB shares, including a client crash while a lease lock is held (lock recovery through the server). Tested only on a local disk.
- **[build]** S3 or other remote cold archival of retired partitions. Only a local `archive_dir` (DuckDB move or Parquet export) exists.
- **[verify]** `cluster status` (one-shot CLI) still uses heartbeat ages for its `alive` column. Only the running nodes use progress-based liveness; the lease holders it prints are authoritative.
- **[build]** Size-based rolling uses `partition_max_mb` checked at write time. There is no row-count roll.
- **[build]** Kafka and Event Hubs inputs rely on their consumer groups, not on ULPF leases or fencing tokens.

## Phase 4: native columnar hot path

Measured on this machine (Haswell i7, Windows 10, Python 3.11, one core, `python -m benchmarks.native_lane`, file in `benchmarks/results/`). On syslog/CEF/LEEF/JSON/KV records: Python worker ~8k ev/s, columnar lane ~22k, engine alone ~37k. On a mixed corpus with CSV/XML: columnar ~13.5k.

- **[build]** **100k EPS/core has not been reached.**
  - Where the time goes in the engine: one record (~8–10 µs) and building its row (~6 µs, plus ~4 µs for the BLAKE2b MAC) are dominated by the general ordered-map value tree (about 200 small allocations per event) and by writing about 2.5 KB of `normalised_json`.
  - Next steps:
    - A typed event struct with pre-built JSON key fragments for the fixed schema skeleton.
    - Borrowed (`&str`) parsed fields instead of owned strings.
    - Avoiding the CEF `parsed` → `mapped` copy.
    - SHA-NI/AVX-512 hashing where available.
  - Re-measure on current server hardware: this is a 2013 CPU without SHA extensions.
- ~~Arrow buffers go to Python as `bytes`~~ Done in phase 7: the batch is exported through the Arrow C Data Interface (`__arrow_c_array__` PyCapsule). The `arrow-rs` / `parquet` crates are still not used.
- **[build]** Parquet segments are still written by pyarrow in Python (~6 µs per row). Writing them from Rust (`parquet` crate) would remove that step.
- ~~The hybrid lane rebuilds Python dicts when analytics or field routing are on~~ Done in phase 7: Sigma, routes, anomaly and drift run in Rust on the batch; dicts are built only for non-DuckDB sinks and Sigma rules the IR cannot express. DPDP still forces the dict path.
- **[build]** Formats still on the Python path:
  - CSV and W3C/CLF (stateful headers), XML/EVTX, APG-learned parsers (their matching runs in Rust since phase 7, the event is still built in Python), plugins, container decoders.
  - Timestamps outside the strict shared ISO subset, epoch forms, RFC 3164, and `%b %d %Y %H:%M:%S[.%f]`: the other strptime formats and dateutil.
  - Non-ASCII lines.
- **[verify]** Intentional difference from the Python path: an event without a usable source timestamp gets the batch start time (millisecond resolution) instead of a per-event clock reading, and `metadata.processing_time_ms` (sampled for 1 in 4096 events in Python) stays null.
- **[verify]** Native-lane equivalence has been tested on about 6,100 generated and demo records plus edge cases (`tests/test_native_lane.py`). It has not been tested on real customer corpora (LogHub etc.) or under Hypothesis-style fuzzing of every parser; only timestamps were randomised.
- **[verify]** `ULPF_NATIVE_LANE` is on by default when the extension exists. The Linux build (`scripts/build_native.sh`) of the new crate has not been compiled or tested.
- **[build]** The legacy 9.0 dict-based `build_normalized_event` (`ULPF_NATIVE=1`) is kept for its existing tests. Remove it once the native lane covers its uses.
- **[decide]** Toolchain: Rust 1.99.1 (MSVC) was installed on this machine with `winget` for phase 4. `scripts/build_native.ps1` generates a `python3.lib` import library when the interpreter ships none (embeddable Python).

## Phase 7: compiled ingestion kernel and standard views

Measured (`python -m benchmarks.native_lane`, 20k events, one Haswell core): Python worker with analytics 4.2k ev/s → native lane with analytics 23.4k, without analytics 37.6k, engine alone 55.1k.

- **[build]** **100k EPS/core is still not reached** (55k engine-only, 23k with full analytics on this 2013 CPU). The largest remaining cost is Parquet encoding (~5.8 µs/row even uncompressed) and `normalised_json` (71 % of row bytes, ~2.1 KB, mostly nulls).
- **[decide]** Store `normalised_json` sparse (omit nulls). This changes the stored format and the row MAC input, so it needs a format version and a migration decision.
- **[verify]** Tokenizers use memchr (SSE2/AVX2 on x86, NEON on ARM); there are no AVX-512 kernels.
- **[verify]** Native listeners (syslog UDP/TCP/TLS with SNI certificates, SNI routing and client certificates; NetFlow v5/v9/IPFIX; SNMP v1/v2c/v3; OTLP gRPC) are differential-tested against the Python decoders and run through the supervisor (`tests/test_native_listeners.py`). `engine: auto` uses them whenever `ulpf_core` is built. They have not been load-tested at line rate or on Linux (`SO_REUSEPORT` path).
- **[decide]** On Windows, TCP listeners do not set `SO_REUSEADDR` (it would let another process bind the same port and steal connections). UDP sockets disable `SIO_UDP_CONNRESET`.
- **[build]** SNMPv3 AES-192/256 uses Blumenthal key extension (as net-snmp does); the Reeder variant (some Cisco devices) is not implemented.
- **[verify]** OCSF 1.3.0, Chronicle UDM and ASIM views validate against the bundled schema catalogues with 0 failures and exact round trips on 1,702 corpus events (`tests/test_standards.py`). Native-lane equivalence now runs on 10,000 generated records plus the demo files (`tests/test_native_lane.py`); the views corpus is 1,702 events. OCSF class numbers follow the 1.3.0 registry, which differs from some numbers in the original brief.
- **[verify]** RSS < 256 MB per worker: the FFI export showed no growth over 300 batches (+4–5 MB), but no multi-hour soak has been run.
- **[build]** The host-side correlator is the next single-threaded bottleneck once workers exceed ~25k ev/s each.
- **[verify]** APG 2.0: learned-parser dispatch and extraction run in `ulpf_core` (`tests/test_native_apg.py`: native and Python agree on 12k mutated lines and 33k kv strings; 98k against 19k ev/s). Learned formats are still parsed in the workers' Python pipeline, not inside the native lane's `Engine` (the event built from APG fields is Python). The streaming engine's DFA tables and Python Aho-Corasick remain as the fallback when the core is missing. Autonomous learning reaches a canary within 5,000 events in the test; promotion to active still needs 10,000 canary events by design.

## Phase 12: threat intelligence platform

- **[build]** **"<1 µs overhead per event with 2M indicators" is met only for typical logs.**
  - **Measured** (`python -m benchmarks.tip_scale`, Haswell i7-4790): 0.57 µs per mixed-format event, 1.9 µs per URL / hash-dense JSON event in a tight loop. In the native lane the added cost is not measurable for mixed formats, and 3.5–4.1 µs for URL-dense events.
  - **Where it goes:**
    - The Aho-Corasick pass over 16k mutex / registry patterns (a 3.4 MB automaton) once a line contains a backslash.
    - About 12 filter lookups per URL-dense event, with the 4 MB filter cold after parsing.
    - URL normalisation, about 65 ns per URL.
  - **Tried without effect:** two-phase scanning with prefetch. The DFA variant of the automaton was only ~15% faster, at 100 MB.
  - **Next steps:** match mutexes and registry keys only in their fields (Sysmon `TargetObject`, EDR mutex fields) instead of the whole raw text; per-kind filters so small kinds stay in cache; a batch-level pass that sorts a batch's candidates by bucket.
- **[verify]** TAXII 2.1, MISP `restSearch` and OTX connectors are tested against recorded responses (paging, cursors). No live server was contacted (air-gapped build).
- **[decide]** Text matching:
  - Every IPv4 address, domain-like token, URL, e-mail and 32/40/64-hex token of the raw event is a candidate. Domains need a 2–24 letter TLD, so file names such as `svc.exe` are candidates too.
  - Exact domains do not match subdomains; use `*.domain`.
  - The legacy `config/iocs.json` IPs match source / destination fields only.
- **[verify]** Confidence decay runs at snapshot rebuilds (`intel.rebuild_minutes`, default 60). Sightings from the event stream itself do not reset decay; analysts and feeds do (`ulpf intel sight`, re-publication).
- **[build]** `threat.intel` is a nested object in `normalised_json`; the event store has no columns for actor / campaign yet.

## Phase 11: UEBA

- **[verify]** The host cost of UEBA (about 6 µs per event) was measured on a corpus with few distinct users. It has not been measured on a user-heavy load, such as a large IdP export.
- **[decide]** Name-based identity merging trusts `ueba.realm_aliases`. Without it, `CORP\jdoe` and `jdoe@corp.com` merge only by co-occurrence or a directory import.

## Phase 10: detection engineering

- **[build]** **"<5% ingest degradation with 1,000 rules" is not met.**
  - **Measured** (`python -m benchmarks.sigma_scale`): 1,000 SigmaHQ rules cost 17% (Sysmon-style JSON) to 21% (mixed formats) of a worker's throughput, against Sigma enabled with no rules; all 3,302 rules cost 31% to 49%.
  - **Where it goes:** in the core, about 9–11 µs per event at 1,000 rules: the per-event `parsed_fields` index (about 1 µs), the always-scanned fields, the keyword text, and the about 10 candidate rules that are evaluated.
  - **Next steps:** batch-level columnar scanning (one automaton pass over a whole column of a batch), a shared field index with the native lane's normaliser, and evaluating Sigma off the critical path (a second core per worker).
- **[verify]** The SigmaHQ execution test builds its events from each rule's own selections; 190 rules cannot be exercised that way (regex-only values, required absent fields). Real Sysmon / Security / cloud logs from SigmaHQ's regression data have not been replayed.
- **[decide]** Logsource guards:
  - Windows categories use Sysmon event IDs; Security 4688 process events are not mapped onto Sysmon field names (pySigma's windows pipeline does that).
  - Rules for unmapped logsources still run on every event unless their ULPF category applies.
- **[build]** Sigma: correlations of correlations, `near`, `expand` placeholders and non-count aggregations remain unsupported (rejected with a reason).
- **[verify]** YARA-L semantics are a documented subset:
  - **Windows:** hop windows start at a key's first event (one window at a time, not overlapping hops).
  - **Joins:** `#e` counts events that join the other present variables; disjunctions count variables separately.
  - **Missing:** reference lists (`%list`) and `$e.field[index]` are not supported.
- **[build]** YARA-L costs about 0.2 ms per event in the workers (the event's UDM view). It is opt-in, and `analytics.yaral.inputs` limits it to chosen inputs; native-lane events become dicts when rules are loaded.
- **[verify]** Kill-chain staging of correlation groups still uses the keyword heuristics as a fallback; detections add their ATT&CK stages. Domains reach risk scoring only through YARA-L match variables (the worker projection has no domain field).
- **[verify]** Risk state is saved every 60 s, so a crash can lose up to 60 s of risk accumulation. Thresholds adapt per entity type over the current population (mean + 3σ); there is no per-entity baseline yet.

## Phase 9: query languages and live tail

- **[decide]** Queries are compiled to DuckDB SQL instead of Apache DataFusion, following the phase 8 decision (no new native dependencies). The Arrow data, the vectorised execution and the plans are real; the engine is DuckDB.
- **[build]** Not supported yet:
  - **KQL:** `let`, `union`, `parse`, `materialize`, `arg_max`/`arg_min`, `series_*`, `render`, `evaluate`.
  - **SPL2:** `join`, `transaction`, `eventstats`, `streamstats`, `append`, `spath`, macros.
  - **HQL:** `join()`, `defineTable`, `case {}` / `match()`, `format()`, `parseJson()`, saved searches.
  - Unknown commands and functions are errors, never ignored.
- **[verify]** Semantics that differ from the products:
  - KQL `dcount` is exact (Kusto's is an estimate).
  - Unknown fields are null rather than an error.
  - `has` is matched on term boundaries with an RE2 expression, not Kusto's term index.
  - Text from the event JSON is compared as a string unless it meets a number (`TRY_CAST`).
- **[build]** Live tails are row-level only, with no windowed `summarize` or `count by` over a stream.
  - A tail returns at most 500 rows per ingest batch, and its queue keeps the newest 10,000 rows.
  - Workers learn about tails through a lease re-sent every 5 s, so a tail opened while a worker restarts can miss that worker's batches for up to 5 s.
- **[verify]** Governor limits:
  - CPU fair share comes from thread shares and admission order, not preemption: a running query keeps its threads until it finishes or hits its deadline.
  - Converting results to JSON in Python is not counted in the query's memory limit (rows are capped by `max_rows`, at most 100,000).
- **[verify]** Event-store scans run `TRY_CAST` on the text timestamp for each row and read every partition. Start/end bounds are applied per row; partitions are not pruned.
- **[build]** There is no `ulpf query` command: queries go through the API, because the store file belongs to the running runtime.

## Phase 8: lakehouse

Measured with `python -m benchmarks.lakehouse --events 2000000` (encrypted, Haswell, Windows): worker encode 23k ev/s per process, hot append 383k, flush 71k (4 partitions in parallel), compaction 90k ev/s, peak RSS 412 MB.

- **[decide]** Table formats and engines: by decision, Delta Lake only (written natively) and DuckDB only. Not built:
  - Apache Iceberg;
  - DataFusion;
  - DuckDB `httpfs` (remote files are downloaded to a bounded local cache instead).
- **[verify]** Encrypted Parquet interoperability:
  - DuckDB cannot read Arrow's modular-encryption files, so encrypted files are decrypted by pyarrow and scanned by DuckDB as Arrow datasets.
  - Arrow cannot write Parquet bloom filters into encrypted files, so pruning there relies on the ULPF bloom sidecars plus row-group statistics.
  - Spark/Databricks can read the plain tables; reading encrypted ones needs the per-file keys from `tags["ulpf.dek"]`.
- **[verify]** S3 / MinIO / Ceph / Azure are tested only against an in-process fake: SigV4, `If-None-Match` and streamed bodies. Not yet tested against real services. Ceph RGW needs a release with conditional PUT (Reef+).
- **[verify]** Compacted files reach 128–512 MB only when a partition has that much data. In the benchmark (45k events per tenant-hour) they are about 5 MB.
- **[verify]** 2.5B events/day (28.9k ev/s): the host side has 2.4× headroom on one core. End-to-end, the lake encode costs about 43 µs per event in a worker, so the workers need at least two cores beyond the pipeline itself. No 24-hour soak has been run.
- **[build]** The Delta log is listed in full on each refresh (S3 `start-after` not used). Readers outside the service replay all JSON commits since the last checkpoint.
- **[build]** The commit MAC chain detects edited, reordered and missing commits, but not truncation of the newest commits (no external anchor yet: the evidence seals could carry the head MAC).
- **[verify]** Redelivery after a crash is deduplicated only while the segment's records are still in the ring.
- **[build]** Hot-tier reads from other processes (the CLI while `ulpf run` is running) work, but there is no cross-process single-writer lock: only the runtime may append.

## Phase 5: Sigma and MITRE ATT&CK

- **[verify]** The compiler has been tested on its own unit tests and the 19 bundled rules. It has not been run against the SigmaHQ rule repository (no network here). The rejection reasons and the field-name coverage on real Windows/Sysmon/Zeek/cloud rules are unmeasured.
- **[build]** Not supported:
  - Sigma correlation rules (`correlation:` documents: event_count / value_count / temporal).
  - The `near` operator and `expand` placeholders.
  - Aggregation functions other than `count` (`min`/`max`/`avg`/`sum`).
  - pySigma processing pipelines.

  Such rules are rejected with a reason, never partly applied.
- **[verify]** Field resolution (`FIELD_MAP` + ULPF aliases + parsed_fields) and logsource mapping are approximate. A rule whose logsource has no mapping runs on every event, which may produce false positives with third-party packs.
- **[build]** Only a subset of ATT&CK technique names ships (`TECHNIQUES`); there is no import of the full ATT&CK STIX bundle. Technique-to-stage and tactic-to-stage mapping onto the 7 legacy kill-chain stages is a judgement call: lateral_movement and credential_access map to "exploitation", impact to "exfiltration".
- ~~Rules are evaluated in Python on full events~~ Done in phase 7: rules compile to an IR evaluated in `ulpf_core` (memchr/memmem matchers, per-event field cache). Rules the IR cannot express (regexes with `[[`, `&&`, `(?x`, non-ASCII) return "undecided" for that event and run in Python.
- **[decide]** Detection events (`event_kind: detection`) are emitted once per rule and source within `analytics.sigma.dedupe_seconds` (60 s), and aggregation rules once per timeframe per group. Tune with real traffic. The GUI and TUI do not show ATT&CK techniques or detections yet; the API does (`/api/v1/runtime/detections`, `/api/v1/runtime/sigma`).
- **[verify]** The bundled rules are keyword-heavy and were written for the demo and generated data. Measure their false-positive rate on real logs before they are trusted for alerting.

## Phase 6: DPDP, CBAM, tactical edge and the test suite

### Legal and regulatory review (before any customer files with these outputs)
- **[decide]** The regulatory facts in the code were written from the brief and the author's knowledge, not checked against the official texts. Verify them with counsel:
  - CERT-In 6-hour reporting and the 20 incident types (Directions of 28 April 2022).
  - DPDP Rules 2025: Board intimation without delay, detailed report within 72 hours, and the Data Principal notification text.
  - CBAM: phase-in shares 2.5 % / 5 % / 10 % / 22.5 % / 48.5 % / 61 % / 73.5 % / 86 % / 100 %, default-value mark-ups of 10 % / 20 % / 30 %, the 50 t de minimis threshold, and the direct-only goods.
- **[build]** No EU CBAM default values are bundled (users supply a CSV). There is no export in the EU CBAM Registry declaration XML format.

### DPDP
- **[build]** The Consent Manager obligations (in force 13 Nov 2026), notices and consent records are not implemented. Phase 6 covers PII discovery, erasure and breach packs only.
- **[build]** The PII detectors are pattern + checksum based (email, Indian mobile, Aadhaar/Verhoeff, PAN, card/Luhn, IFSC, UPI, passport, voter ID, GSTIN, IPv4/IPv6).
  - Not detected: names, postal addresses, bank account numbers, dates of birth, or free-text personal data (needs NER).
  - False-positive and false-negative rates on real logs have not been measured.
- **[build]** What erasure does not reach (it lists residual outputs, but does not erase there):
  - Copies already delivered to other outputs (SIEM, S3, lakes).
  - Undelivered sink buffer segments and the DLQ.
  - The `anomalies` table, APG sampler and learned-parser material, LogDNA baselines.
- **[verify]** Erasure through the API on a live runtime races with sink buffers that still hold the record. Only the offline path is tested end to end (`tests/test_compliance.py`); the API endpoints have no tests.
- **[build]** `compliance/token.key` (tokenisation) is a plaintext 0600 file. It should use the key providers from phase 2.
- **[build]** Certificates and breach reports are JSON + HTML; there is no PDF yet (reportlab is already in the `docs` extra). The affected-principal count is a heuristic: distinct identifiers in the largest category.

### CBAM
- **[build]** Ingestion is CSV → JSON lines through a file input. There are no ERP connectors (SAP, Tally) and no meter protocols (Modbus, DLMS/COSEM).
- **[build]** The calculation is simplified:
  - Indirect emissions are allocated by mass.
  - Precursor indirect emissions are not counted.
  - Free-allocation benchmarks and carbon prices paid in the country of origin are not deducted.

  The figures are estimates for preparing the declaration, as the pack says.

### Tactical edge profile
- **[build]** MAVLink decoding covers seven messages. MAVLink v2 signatures are reported, not authenticated. CCSDS covers the primary header only: no secondary header/PUS and no TM/TC transfer frames. A datagram is decoded as one frame.
- **[verify]** `limits.max_rss_mb` only warns and writes an audit entry; there is no hard ceiling (that needs cgroups / Job Objects). `limits.max_disk_mb` retires only store partitions, never journal or evidence. The 500 MB RSS target of the profile has not been measured in a soak.

### Test-suite coverage map (for the verification pass after phase 6)
| Item | Tests |
|---|---|
| Bug 1 packaging, Bug 2 API roles / shared APG engine | `tests/test_hardening.py` |
| Bug 3 native hot path | `tests/test_native_lane.py`, `benchmarks/native_lane.py` |
| Bug 4 partitioned store, Bug 5 parser index, Bug 7 leases | `tests/test_scaling.py` |
| Bug 6 egress, Bug 8 Ed25519 / forward security | `tests/test_hardening.py` |
| Section 4 Sigma / ATT&CK | `tests/test_sigma.py` |
| Section 5 DPDP, CBAM, tactical edge | `tests/test_compliance.py` |
