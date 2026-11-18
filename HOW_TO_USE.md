# ULPF: Practical Evaluator & Testing Guide

This guide walks evaluators, security engineers and judges through every ULPF capability on Windows, Linux or macOS. Setup is in [docs/INSTALLATION.md](docs/INSTALLATION.md).

---

## 1. Launch the desktop application

ULPF's desktop app is native PySide6. It needs no browser and no internet.

- **Windows, one click:** double-click **`LAUNCH_GUI.bat`** in the project root. It uses the bundled `python311\` runtime, or `dist\ULPF\ULPF.exe` if you built a standalone bundle ([docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md)).
- **Any OS, terminal:**
  ```bash
  python -m ulpf.gui.qt_app        # or: python -m ulpf.main desktop
  ```
- **Headless self-check:** `python -m ulpf.gui.qt_app --verify` exercises the engine, a worker process and all 10 pages without opening a window. Exit code 0 means it passed.

> **Single instance:** on Windows a named mutex (`Local\ULPF_Desktop_SingleInstance_Mutex_v8`) ensures that launching ULPF a second time brings the running window to the front instead of opening a second instance against the same DuckDB store.

---

## 2. The 10 desktop views

1. **System Overview**: stored event count, the measured live parse/persist rate (events/s from worker counters, not a fixed number), format and category distribution, and a severity histogram (0–10).
2. **Ingestion Console**:
   - Load any file from `demo_data/` with "Select Log File", or drag and drop files.
   - Paste multi-line raw logs and click "Ingest Raw Text".
   - Start the UDP/TCP syslog listener (default `0.0.0.0:5514`) with in-process or multi-process workers.
   - Use the traffic simulator, which replays the demo corpus at an offered rate so you can watch the live pipeline.
   - Forward normalised events to an external SIEM as RFC 5424 syslog (UDP or TCP).
3. **Event Explorer**: browse the newest stored events (configurable row limit) with filters for format, category, severity, source IP and free text. Click a row to inspect the full normalised event JSON, which includes the original raw line, and export the filtered set to JSON or CSV.
4. **Parsers**: the 8 built-in parsers (Syslog 3164/5424, CEF, LEEF, JSON, XML, CSV, KV, W3C) and any learned parsers, with an interactive test box.
5. **Auto-Learn (APG)**: paste unknown or proprietary log lines. ULPF clusters them by structure, infers field types, compiles and validates a regex parser, signs it and hot-loads it.
6. **Log DNA**: structural fingerprints (token shape, delimiter and character distribution, entropy) per source, plus drift detection when a device changes its output format.
7. **Correlation**: streaming multi-source correlation by IP, user, host and session within a time window, mapped to MITRE ATT&CK kill-chain phases.
8. **Anomalies**: rolling z-score volume baselines, entropy outliers and high-severity bursts detected during ingestion.
9. **Forensics**: build SHA-256 hash-chained evidence sets with a Merkle root and a chain-of-custody log, verify them, and export self-verifying packages.
10. **Schema**: reference for the 93-field ULPF unified schema (OCSF-inspired), grouped into 12 sections.

---

## 3. Demo data

All samples are in **`demo_data/`**:

| File | Format |
|---|---|
| `firewall_cef.log` | ArcSight / Check Point CEF |
| `ids_leef.log` | IBM QRadar LEEF 1.0/2.0 |
| `router_syslog.log` | Cisco / RFC 3164 / RFC 5424 syslog |
| `waf_json.log` | WAF JSON |
| `fortigate_kv.log` | FortiGate key=value |
| `dns_xml.log` | Windows event XML |
| `proxy_w3c.log` | W3C extended log with `#Fields:` header |
| `mixed_formats.log` | all of the above interleaved in one stream |

---

## 4. Command line

```bash
# Process one file, or several at once (globs allowed)
python -m ulpf.main process --files demo_data/firewall_cef.log
python -m ulpf.main process --files "demo_data/*.log" --correlate

# Auto-Parser Generator: learn formats no built-in parser recognises
python -m ulpf.main learn --file path/to/unknown.log
python -m ulpf.main learn --file path/to/unknown.log --dry-run   # validate without saving

# Log DNA fingerprint
python -m ulpf.main fingerprint --file demo_data/router_syslog.log

# Correlate stored events (kill-chain mapping)
python -m ulpf.main correlate --window 120

# Forensic evidence chain: build, list, verify
python -m ulpf.main forensic --description "Investigation IR-2026-001"
python -m ulpf.main forensic --list
python -m ulpf.main forensic --verify path/to/evidence_package.json
```

---

## 5. Performance benchmark

```bash
python -m ulpf.main benchmark --events 100000             # pipeline + storage, single process
python -m ulpf.main benchmark --events 200000 --workers 4 # multi-process worker pool
```

The benchmark reports measured events per second, latency percentiles and query times on your hardware. Reference figures from a 4-core laptop are in [TESTING.md](TESTING.md).

---

## 6. Automated tests

```bash
python -m unittest tests.test_core -v          # engine, parsers, storage, forensics, APG, workers, live REST API
python tests/test_service_and_gui.py           # desktop service + Qt pages (set QT_QPA_PLATFORM=offscreen when headless)
python tests/test_audit_fixes.py
python tests/test_platform_and_listener.py
```

Every suite should report `OK` with zero failures.
