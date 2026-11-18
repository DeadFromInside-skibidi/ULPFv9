# Supported sources

Every configured input feeds the same journal → workers → outputs path, so every source gets the raw archive and evidence seals (U2), the unified schema (U3), drift, anomaly and correlation (U5), and autonomous learning (U1) for any format no parser recognises.

Status column:

- **built-in**: parsed by a bundled parser.
- **learned**: no bundled parser is needed. APG learns the format from live traffic, or from a sample with `ulpf source onboard`.
- **plugin**: install a package that registers an `ulpf.parsers` entry point (see [Parser plugins](#parser-plugins)).
- **tested**: exercised by the named test suite on real sockets, files, or local fakes of the remote API.

## Transport inputs

| Input `type` | Transport | Typical sources | Tested |
|---|---|---|---|
| `syslog` | UDP, TCP, TLS (RFC 5425 octet counting or newline framing) | firewalls, routers, switches, Linux/Unix hosts, appliances | `test_runtime`, `test_inputs`, `test_usp` |
| `file` | file tail with globs, rotation, copy-truncate, multiline, exactly-once restart | application logs, web servers, Windows/Linux log files, Docker/CRI container logs | `test_inputs` |
| `http` | `POST /api/v1/ingest/stream/{source}`: NDJSON, JSON array or text, gzip, per-input API key, 429 when saturated | webhooks, scripts, collectors | `test_inputs` |
| `otlp` | OTLP/HTTP logs `POST /v1/logs`, JSON and protobuf | OpenTelemetry SDKs and Collector | `test_inputs` |
| `journald` | `journalctl -o json` follow | systemd hosts | decoder in `test_inputs` |
| `evtx` | Windows event channels (`wevtutil`), bookmarks | Windows Security / System / Sysmon / any channel | `test_inputs` (live System channel) |
| `netflow` | UDP NetFlow v5, v9 (templates persisted) | routers, firewalls | `test_inputs` |
| `snmp_trap` | UDP SNMP v1/v2c traps and informs (acknowledged), SNMPv3 USM auth/priv (SHA/AES) | network devices, UPS, industrial equipment | `test_inputs` |
| `mqtt` | MQTT subscribe (paho-mqtt) | IoT gateways, OT telemetry | config only (no broker here) |
| `kafka` | Kafka consumer group (confluent-kafka), offsets committed after journaling | existing log buses | config only (no broker here) |

## Cloud inputs (industry mode only; refused in defence mode)

| Input `type` | Service | Tested |
|---|---|---|
| `cloudtrail` | AWS CloudTrail through S3 event notifications on SQS (SigV4), message deleted only after journaling | `test_inputs` (fake SQS + S3) |
| `pubsub` | Google Cloud Pub/Sub pull (service-account JWT), acknowledged after journaling | `test_inputs` (fake API) |
| `okta` | Okta System Log API with `Link` paging, cursor checkpointed | `test_inputs` (fake API) |
| `entra` | Microsoft Entra ID sign-in and directory audit logs (Graph, client credentials) | `test_inputs` (fake API) |
| `eventhubs` | Azure Event Hubs (azure-eventhub SDK) | config only (SDK not installed here) |

## Formats

| Format | Status | Notes |
|---|---|---|
| Syslog RFC 3164, RFC 5424 (structured data), plain BSD | built-in | OpenSSH lines yield user, source IP and port; Cisco `%FAC-SEV-MNEMONIC` severities |
| CEF | built-in | ArcSight extension keys mapped |
| LEEF 1.0 / 2.0 | built-in | custom delimiters |
| JSON (one object per line) | built-in | Suricata EVE, Zeek JSON, cloud audit logs and other vendor JSON through field aliases |
| XML | built-in | Windows Event XML |
| Key-value | built-in | Fortinet, Palo Alto, generic `k=v` |
| CSV with header | built-in | header learned per stream |
| W3C extended | built-in | IIS, `#Fields:` directive per stream |
| Docker JSON, CRI (Kubernetes), journald | built-in (decoders) | container and pod labels attached |
| Proprietary / unknown line formats | learned | learned from live traffic (industry) or held for approval (defence); `ulpf source onboard` for a sample |
| Vendor-specific formats published as packages | plugin | tried before the built-in parsers |

## Onboarding a new source

```
ulpf source onboard --name plc-line-3 --sample plc.log --config pipeline.yaml --write-config --path "/var/log/plc/*.log"
```

The command runs the sample through detection and reports built-in coverage. It then learns and validates parsers for the remaining lines and reports their template, fields, accuracy and total coverage. Finally, it inserts a `file` (or `--input-type syslog`) input into the config, leaving the rest of the file and its comments unchanged, and validates the result. In defence mode the learned parser is saved as `pending_approval`; approve it with `ulpf parsers approve <id>`. Each onboarding is written to the audit log.

## Parser plugins

A plugin is an installable package with an entry point in the `ulpf.parsers` group naming a `ulpf.parsers.base.BaseParser` subclass:

```toml
[project.entry-points."ulpf.parsers"]
acme_plc = "acme_ulpf.parser:AcmePlcParser"
```

Lookup order for each line: plugins (when their `can_parse` accepts the line), then the built-in parser for the detected format, then learned parsers, then the raw fallback (the line is still stored and sealed).

`ulpf plugins list` prints every installed plugin with its package hash. The hash is SHA-256 over the distribution's installed files, so it changes when any file changes. In defence mode a plugin loads only when its hash is listed in `plugins.allow`. In industry mode installed plugins load unless `plugins.enabled: false`, or an allow-list is set.

## Outputs

`duckdb` (local store), `file` (NDJSON with rotation), `parquet` (partitioned data lake), `s3`, `elasticsearch` / OpenSearch, `splunk_hec`, `kafka`, `loki`, `otlp`, `syslog` (RFC 5424, CEF or LEEF over UDP, TCP or TLS), `azure_log_analytics` (Logs Ingestion API) and `chronicle`. Every output except `kafka` is tested end to end in `test_outputs` with exact counts. Each output can request the `unified`, `ecs` or `ocsf` view.

## GeoIP data

Private, CGNAT, documentation, benchmarking, multicast and reserved ranges are labelled and never geolocated. For public addresses, place a MaxMind-format database in `config/geoip/`, `<data dir>/geoip/` or `$ULPF_GEOIP_DIR`. GeoLite2-City, GeoIP2 and DB-IP Lite all work. ULPF reads it offline with no extra dependency. Without one, a small bundled table covers only the demo data sets.
