# ULPF Command Cheatsheet
### Universal Log Pre-processing Framework — Copy-Paste Ready Terminal Commands

> **For Linux (Kali, Ubuntu, RHEL), macOS, WSL and air-gapped servers.**
> On Windows use `venv\Scripts\activate` instead of `source venv/bin/activate`. The full flag list is in [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md).

---

## 1. FIRST-TIME SETUP (Do This Once)

### Step 1 — Go to the project folder
```bash
cd path/to/ulpf        # the folder that contains README.md
```

### Step 2 — Create a Python virtual environment
```bash
python3 -m venv venv
```
*This creates an isolated Python environment so nothing conflicts with your system.*

### Step 3 — Activate the virtual environment
```bash
source venv/bin/activate
```
> ⚠️ **You must run this EVERY time you open a new terminal tab before using ULPF.**  
> Your prompt should show `(venv)` at the start when it's active.

### Step 4 — Install all dependencies
```bash
pip install -r requirements.txt
```

### Step 5 — Verify it works
```bash
python -m ulpf.main --help
```
You should see a list of all available commands.

---

## 2. PROCESSING LOG FILES (PyArrow Vectorized)

**What it does:** Reads your log files, auto-detects each line's format, parses and normalises it into the unified schema, and bulk-loads the events into the local `ulpf.duckdb` store through Arrow batches.

### Process a single file
```bash
python -m ulpf.main process --files demo_data/mixed_formats.log
```

### Process multiple files at once
```bash
python -m ulpf.main process --files demo_data/firewall_cef.log demo_data/router_syslog.log demo_data/waf_json.log
```

### Process with verbose output
```bash
python -m ulpf.main process --files demo_data/mixed_formats.log --verbose
```

---

## 3. REAL-TIME NETWORK LISTENER

**What it does:** Opens a network port and listens for live syslog messages. Worker processes parse the lines and write Parquet shards, which a single writer bulk-loads into DuckDB.

### Start listening (default port 5514, both UDP and TCP)
```bash
python -m ulpf.main listen
```

### Start listening with multiple workers (highly parallel ingestion)
```bash
python -m ulpf.main listen --port 5514 --workers 4
```

### Test the listener (in a SECOND terminal tab)
```bash
# First activate venv in the second tab:
source venv/bin/activate

# Send a test syslog message via UDP:
echo "<34>Oct 11 22:14:15 mymachine myapp: test message" | nc -u 127.0.0.1 5514

# Or stream an entire file over UDP:
cat demo_data/mixed_formats.log | nc -u 127.0.0.1 5514
```

---

## 4. PERFORMANCE BENCHMARK

**What it does:** Measures parse → normalise → store throughput on your hardware with no network in the path, and reports measured events/s and latency percentiles.

### Run the pipeline benchmark
```bash
python -m ulpf.main benchmark
```

### Larger run, multi-process, with storage timings
```bash
python -m ulpf.main benchmark --events 500000 --workers 4 --db-bench
```
*Reference (4-core laptop): 12–15k events/s per core for the full pipeline; ~26k events/s parsed and persisted with a 7-worker pool. See [TESTING.md](TESTING.md).*

### Run the live network test (two terminals)
```bash
bash tests/scripts/terminal_1_listener.sh     # terminal 1
bash tests/scripts/terminal_2_sender.sh       # terminal 2
```
*Note: the sender uses Netcat (`nc`), which itself tops out at a few tens of thousands of UDP datagrams/s.*

---

## 5. ANALYTICS & MACHINE LEARNING

### Terminal Dashboard (TUI)
```bash
python -m ulpf.main tui
```

### Event Correlation
```bash
python -m ulpf.main correlate --window 120
```

### Forensic Evidence Chain Builder
```bash
python -m ulpf.main forensic --description "Incident 2026-09"
```

### ML Feature Extraction
```bash
python -m ulpf.main export-ml --output output/ml_features.csv
```

---

*ULPF v8.2 — offline security log pre-processing: parse, normalise, enrich, correlate, preserve evidence.*
