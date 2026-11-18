# ULPF Desktop Application — User Guide

## Architecture & Visual Overview

The ULPF Desktop Application delivers a native Qt interface designed specifically for enterprise security operations and forensic log analysis.

### Primary Navigation Sections

```
┌──────────────────┬────────────────────────────────────────────────────────┐
│ ULPF CONSOLE     │ Top Bar: Breadcrumb | Mode Indicator | Engine Status   │
├──────────────────┼────────────────────────────────────────────────────────┤
│ MONITOR          │                                                        │
│  📊 Overview     │                                                        │
│  📥 Ingestion    │                                                        │
│  📋 Explorer     │                   PAGE WORKSPACE                       │
│ ANALYSIS         │                                                        │
│  ⟨⟩ Parsers      │              (Reactive Native Views)                   │
│  ✦ Auto-Learn   │                                                        │
│  🧬 Log DNA      │                                                        │
│  🔗 Correlation  │                                                        │
│  ⚠️ Anomalies    │                                                        │
│ INTEGRITY        │                                                        │
│  🔒 Forensics    │                                                        │
│  📑 Schema       │                                                        │
│ OPERATIONS       │                                                        │
│  ⏩ Pipeline     │                                                        │
│  📡 Listener     │                                                        │
│  💾 Storage      │                                                        │
│  ⚙ Settings     │                                                        │
└──────────────────┴────────────────────────────────────────────────────────┘
```

---

## Page-by-Page Operational Guide

### 1. System Overview
- **Metric Cards:** Real-time statistics on total ingested events, ingestion rate, parser coverage, and anomaly counts.
- **Engine Status:** Live health indicators for pipeline workers, DuckDB storage backend, and network listeners.
- **Severity Breakdown:** Distribution across INFO, LOW, MEDIUM, HIGH, and CRITICAL severity classifications.
- **Format Distribution:** Breakdown of ingested logs by format (CEF, Syslog, JSON, W3C, LEEF, etc.).

### 2. Log Ingestion
- **File Drag-and-Drop:** Drag log files directly into the drop zone or click "Browse Log Files".
- **Batch Processing:** Select multiple files simultaneously; events are streamed through format detection, parsing, normalization, and bulk DuckDB storage on background worker threads.
- **Raw Text Ingestion:** Paste arbitrary multi-line log excerpts directly into the input area for immediate processing.
- **Live Summary:** Displays total lines, accepted events, rejected events, and processing speed (EPS).

### 3. Event Explorer
- **High-Density Table View:** Paginated, multi-column event table displaying timestamps, categories, severities, sources, destinations, actions, and messages.
- **Search & Filter Bar:** Instant full-text filtering by keyword (IP, username, error code) or structured attributes (severity level, log format, event category).
- **Event Detail Drawer:** Click any event to inspect:
  - Formatted normalized JSON fields
  - Raw log string exactly as ingested
  - Evidence hashes (SHA-256) and tamper-proof forensic metadata
  - One-click copy to clipboard

### 4. Parsers Registry & Live Tester
- **Registry View:** Explore all built-in and dynamically learned parser modules.
- **Live Interactive Tester:** Paste any raw log line to test parsing in real time. Inspect format detection, regex/token extraction, normalized schema mapping, and parser diagnostic messages.

### 5. Auto-Learn (Automated Parser Synthesis)
- **Zero-Code Parser Generation:** Provide sample log lines from an unknown device or application.
- **Mining & Inference:** The engine infers static delimiters, dynamic variable positions, and field data types.
- **Template Synthesis:** Review the synthesized extraction template and register it into the active parser registry without restarting the application.

### 6. Log DNA (Structural Fingerprinting)
- **Fingerprint Synthesis:** Compute structural AST masks from raw log streams to classify distinct template types.
- **Format Drift Detection:** Compare new incoming streams against known fingerprints to detect version upgrades or unexpected log format alterations.

### 7. Event Correlation
- **Temporal Analysis:** Select event thresholds and correlation time windows (seconds/minutes).
- **Incident Grouping:** Correlate related events across independent log sources by shared IP addresses, user accounts, and session identifiers.

### 8. Anomaly Detection
- **Statistical Profiling:** View events deviating from learned baseline distributions.
- **Metric Baselines:** Review mean, standard deviation, and anomaly scoring across event categories and sources.

### 9. Forensic Evidence Chains
- **Cryptographic Chains:** Create tamper-evident evidence packages backed by SHA-256 hash chains.
- **Integrity Verification:** Execute one-click mathematical integrity checks verifying that zero events within a chain have been altered or deleted.
- **Export Package:** Export verifiable forensic zip bundles containing raw evidence and cryptographically signed manifests.

### 10. Schema Taxonomy
- **Unified Schema Explorer:** Tree-based inspection of ULPF normalized fields, data types, descriptions, and standard SOC taxonomies.

### 11. Live Network Listener
- **Syslog Receiver:** Configure UDP/TCP listening sockets (e.g., port 5514).
- **Non-Blocking Operation:** Runs entirely in a dedicated background worker; incoming logs are continuously parsed and indexed into storage.

### 12. Storage Management
- **Database Metrics:** Live file path, size on disk (MB), total event count, and DuckDB health.
- **Export Facility:** One-click bulk export of stored events to structured JSON or CSV formats.

### 13. Settings & Diagnostics
- **Persistence:** Local settings saved automatically via OS-level native storage (`QSettings`).
- **Data Directory:** Inspect active database storage paths and logs.
