# ULPF CLI Reference

Every ULPF operation is available from the command line, for headless, automated and air-gapped hosts:

```bash
python -m ulpf.main [GLOBAL OPTIONS] COMMAND [OPTIONS]
ulpf [GLOBAL OPTIONS] COMMAND [OPTIONS]        # same, once installed with pip
```

**Global options**

| Option | Meaning |
|---|---|
| `--db PATH` | Event store to use (overrides `ULPF_DB_PATH`; default `<data dir>/ulpf.duckdb`) |
| `--log-level LEVEL` | `DEBUG`, `INFO`, `WARNING` (default, or `ULPF_LOG_LEVEL`), `ERROR` |

Live pipeline (v9): `run`, `config`, `reload`, `source`, `parsers`, `plugins`, `schema`, `evidence`, `raw`, `audit`, `dlq`, `cluster`, `apikey`.
Batch and tools: `process`, `listen`, `learn`, `fingerprint`, `correlate`, `forensic`, `purge`, `export-ml`, `serve`, `tui`, `desktop`, `benchmark`.

Commands that read node state take `--data-dir` (default: `ULPF_DATA_DIR`, otherwise the platform data directory).

---

## run — the live pipeline

```bash
ulpf run [--config pipeline.yaml] [--mode defence|industry] [--data-dir DIR] [--no-api]
```

Without `--config`, `run` uses the built-in pipeline: syslog TCP on `127.0.0.1:5514` into the local store, with the API on `127.0.0.1:8000`. It prints what it listens on, which destinations it connects to, any waived mode rules and the egress mode, then runs until Ctrl+C or SIGTERM, draining queued data before it exits. SIGHUP (Linux) reloads the config.

## config — validate and inspect

| Command | Effect |
|---|---|
| `ulpf config check FILE` | Reports every error with its line number (exit 2), or OK with the listener and destination report |
| `ulpf config show FILE` | The fully resolved config (mode defaults applied) as JSON |
| `ulpf config example` | Prints the annotated example config |

## reload — apply an edited config

```bash
ulpf reload [--url http://127.0.0.1:8000] [--key-env ULPF_API_KEY]
```

Calls `POST /api/v1/runtime/reload` (admin role). The new file is validated first; if it is invalid the running pipeline is unchanged and the errors are returned. Changing outputs, routes, analytics or workers rebuilds the stage without losing data; changing an input restarts only that input. Changing `mode`, `journal`, `evidence`, `node`, `api` or `cluster` needs a restart.

## source onboard — add a new log source

```bash
ulpf source onboard --name NAME --sample FILE [--mode defence|industry] [--config FILE --write-config]
                    [--input-type file|syslog] [--path GLOB] [--protocol udp|tcp|tls] [--host H] [--port P] [--json]
```

Measures built-in parser coverage of the sample, learns and validates parsers for the rest (saved as `pending_approval` in defence mode), and prints the template, fields, accuracy, total coverage and elapsed time. With `--write-config` it inserts the input under `inputs:` (comments are preserved) and refuses to write a config that does not validate. The command is recorded in the audit log.

## parsers — learned parsers

| Command | Effect |
|---|---|
| `ulpf parsers list` | ID, state (`canary`, `active`, `pending_approval`, `retired`), family, accuracy, template |
| `ulpf parsers approve ID` / `reject ID` | Defence-mode decision; re-signed and audited; workers pick it up within 2 s |

## plugins — parser plugins

`ulpf plugins list [--config FILE] [--json]` prints installed `ulpf.parsers` entry points, their package SHA-256 (for `plugins.allow`) and whether they load under the config's policy.

## schema — unified schema versions

| Command | Effect |
|---|---|
| `ulpf schema versions` | Registered versions |
| `ulpf schema diff [OLD] [NEW]` | Added, removed and retyped fields; exit 1 if a minor version is not additive. Versions, `current`, or exported files |
| `ulpf schema export [FILE]` | The live catalogue in registry form |

## evidence — seals

| Command | Effect |
|---|---|
| `ulpf evidence list` | Seal ranges, Merkle roots, seal hashes |
| `ulpf evidence verify [--from-seq N] [--to-seq N] [--check-store]` | Recomputes every root from the journal, checks the seal chain and HMAC, and with `--check-store` compares each stored event's raw hash and row MAC; every problem is listed with its record number |
| `ulpf evidence prove --seq N` | Merkle inclusion proof for one record |

## raw, audit, dlq

| Command | Effect |
|---|---|
| `ulpf raw get --event-id ID \| --seq N [--json]` | The original bytes of a record, as received |
| `ulpf audit verify` | Checks the hash chain of the audit log |
| `ulpf dlq list [--sink NAME] [--limit N]` | Dead-lettered events with the reason and per-record detail |

## cluster, apikey

| Command | Effect |
|---|---|
| `ulpf cluster status --config FILE [--json]` | Nodes, heartbeat age, liveness, running inputs, owner of every `placement: one` input |
| `ulpf apikey new --name N --role read\|write\|admin [--keys-file F \| --config F]` | Prints a new key once; only its SHA-256 is stored |

## intel — threat intelligence

All take `[--config FILE] [--data-dir DIR]`; the config supplies `intel` (feeds, decay) and the mode.

| Command | Effect |
|---|---|
| `ulpf intel import-stix --file BUNDLE.json [--name N]` | Imports a STIX 2.1 bundle (revoked indicators are retired), then rebuilds the match set |
| `ulpf intel import-misp --file EVENTS.json` / `import-otx --file PULSES.json` | Same, for a MISP event export or OTX pulses |
| `ulpf intel sync [--name FEED]` | Pulls the configured feeds now (TAXII / MISP / OTX from their cursors; network feeds are refused in defence mode unless allow-listed) |
| `ulpf intel build` | Re-applies confidence decay and writes `<data dir>/intel/matcher.snap` |
| `ulpf intel stats` | Indicators by kind and source, feed cursors and errors |
| `ulpf intel lookup VALUE` | Every copy of an indicator with its metadata and decayed confidence (exit 1: unknown) |
| `ulpf intel sight VALUE [--kind K]` | Records a re-sighting: resets the decay clock |

---

## process — parse, normalise, enrich and store files

```bash
python -m ulpf.main process --files <path-or-glob> [...] [OPTIONS]
```

| Option | Meaning |
|---|---|
| `--files`, `-f` *(required)* | One or more files or globs (`"logs/*.log"`; quote globs so ULPF expands them on every OS) |
| `--output`, `-o` | Also write the normalised events to this JSON file |
| `--correlate` | Run streaming correlation and print the correlation groups |
| `--verbose`, `-v` | Also print the first lines that failed to process, with the error |
| `--siem-forward HOST:PORT` | Forward every event to a SIEM as RFC 5424 syslog |
| `--siem-proto udp\|tcp` | Transport for `--siem-forward` (default `udp`; TCP uses octet counting) |

```bash
python -m ulpf.main process -f /var/log/syslog "/var/log/nginx/*.log" -o output.json --correlate
```

---

## listen — real-time syslog listener

```bash
python -m ulpf.main listen [--host 0.0.0.0] [--port 5514] [--protocol udp|tcp|both] [--workers N] [--siem-forward HOST:PORT]
```

Worker processes parse lines and write Parquet shards that a single writer bulk-loads into DuckDB. TCP accepts newline-delimited and RFC 6587 octet-counted framing. `--workers` defaults to CPU cores − 1. Stop with Ctrl+C: queued lines are drained before exit.

---

## learn — Auto-Parser Generator

```bash
python -m ulpf.main learn --file <path> [--min-samples 2] [--all-lines] [--dry-run]
```

| Option | Meaning |
|---|---|
| `--file`, `-f` *(required)* | Sample of the unknown log format |
| `--min-samples` | Minimum lines per structure to learn from (default 2) |
| `--all-lines` | Also learn lines that built-in parsers already handle |
| `--dry-run` | Validate and report, but do not save |

Lines are grouped by structure. Each structure is mined into a template, compiled to an anchored regex, validated (≥ 90% of its samples, < 1 ms/line), HMAC-signed and saved to `<data dir>/learned_parsers/` (or `ULPF_LEARNED_PARSERS_DIR`). Running ULPF processes hot-load new parsers within seconds. The report lists accepted templates with their fields, and rejected structures with the reason. The exit code is `0` if at least one parser was accepted.

```bash
python -m ulpf.main learn -f samples/custom_vendor.log --dry-run
```

---

## fingerprint — Log DNA

```bash
python -m ulpf.main fingerprint --file <path> [--label NAME]
```

Computes a structural fingerprint (delimiter, field count, type signature, character distribution, entropy) and stores it under the label (default: the file name). When the label already has a stored fingerprint with a different structure, the command prints a drift report: similarity score plus each change (field count, type signature, delimiter, entropy). A changed delimiter or field count always counts as drift.

```bash
python -m ulpf.main fingerprint -f auth.log -l "Linux PAM auth"
```

---

## correlate — multi-source correlation

```bash
python -m ulpf.main correlate [--limit 1000] [--window 60] [-o groups.json]
```

Links stored events that share entities (IPs, users, hosts, sessions) within the time window, and maps each group to MITRE ATT&CK kill-chain stages with a risk score.

| Option | Meaning |
|---|---|
| `--limit` | Newest N events to correlate (default 1000) |
| `--window` | Time window in seconds (default 60) |
| `--output`, `-o` | Write the groups as JSON |

---

## forensic — evidence chains

```bash
python -m ulpf.main forensic [--limit 100] [-d DESCRIPTION] [-t tag1,tag2]   # build a chain from the newest events
python -m ulpf.main forensic --list                                          # list stored chains
python -m ulpf.main forensic --verify evidence_package.json                  # verify an exported package
```

A chain hash-links every event (SHA-256 of event ID, raw hash and normalised hash), computes a Merkle root with inclusion proofs, and appends to a hash-linked custody log. `--verify` recomputes everything from the package alone and reports any modification.

---

## purge — retention

```bash
python -m ulpf.main purge --older-than-days 90 [--by ingested_at|timestamp]
python -m ulpf.main purge --raw-fallback        # delete events no parser recognised
```

---

## export-ml — feature matrix

```bash
python -m ulpf.main export-ml [--output output/ml_features.csv|.parquet] [--format csv|parquet] [--limit 10000]
```

Writes one row per event for ML pipelines, as CSV or typed Parquet (the default follows the file extension). The 28 columns are:

- numeric features: hour, weekday, severity, ports, protocol number, byte counts;
- categorical codes: action, category, format;
- flags: threat, cross-border, blocked, high-severity, learned format;
- the original categorical values (for labelling and joins) and the event ID.

`<output>.columns.json` documents each column's type and kind (`numeric`, `categorical`, `flag`, `timestamp`, `identifier`, `text`); in Parquet the kind is also stored as field metadata.

---

## serve — REST API

```bash
python -m ulpf.main serve [--host 127.0.0.1] [--port 8000]
```

Binds to `127.0.0.1` by default (or `ULPF_API_HOST`). Set `ULPF_API_KEY` to require an `X-API-Key` header on every endpoint except `/api/v1/health`. Interactive docs are at `http://localhost:8000/docs` and Prometheus metrics at `/api/v1/metrics`.

---

## tui, desktop, benchmark

```bash
python -m ulpf.main tui [--mode auto|rich|textual]     # terminal UI (works over SSH)
python -m ulpf.main desktop                            # PySide6 desktop application
python -m ulpf.main benchmark [--events 10000] [--workers N] [--db-bench] [--output results.json] [--seed 42]
```
