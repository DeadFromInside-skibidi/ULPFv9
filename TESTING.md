# ULPF Testing & Benchmarking Guide

Every command runs from the project root with the virtual environment active (see [docs/INSTALLATION.md](docs/INSTALLATION.md)).

---

## Directory structure

```
tests/
├── _isolation.py                 # points ULPF_DATA_DIR at a temp dir so tests never touch real data
├── test_core.py                  # engine, parsers, storage, forensics, correlation, APG, workers, live REST API
├── test_service_and_gui.py       # desktop service + every Qt page
├── test_audit_fixes.py           # regression tests for audited defects
├── test_platform_and_listener.py # platform paths, air-gap probe, UDP/TCP listener
├── scripts/
│   ├── generate_flood_logs.py    # synthetic multi-format attack-scenario generator
│   ├── run_live_test.py          # UDP/TCP traffic sender for a running listener
│   ├── terminal_1_listener.sh    # manual live test, terminal 1: start the listener
│   ├── terminal_2_sender.sh      # manual live test, terminal 2: flood the listener
│   ├── verify_ui_rendering.py    # renders every desktop page off-screen and checks the widgets
│   └── capture_native_screens.py # saves PNG screenshots of every desktop page
└── live_output/                  # output of the live scripts (git-ignored)
```

---

## Quick start: which test do I run?

| Goal | Command |
|------|---------|
| Correctness, all subsystems | `python -m unittest tests.test_core -v` |
| Pipeline + storage throughput | `python -m ulpf.main benchmark --events 200000` |
| Live network ingestion, scripted | `python tests/scripts/run_live_test.py` against a running listener |
| Live network ingestion, by hand | `tests/scripts/terminal_1_listener.sh` + `tests/scripts/terminal_2_sender.sh` |
| Full benchmark laboratory | `python benchmarks/run_benchmark.py --mode full` |
| Enterprise validation (soak, live UDP/TCP, memory, integrity) | `python -m benchmarks.enterprise` |

---

## 1. Pipeline benchmark

Measures parse, normalise and store throughput with no network in the path:

```bash
python -m ulpf.main benchmark --events 200000              # single process
python -m ulpf.main benchmark --events 200000 --workers 4  # multi-process worker pool
python -m ulpf.main benchmark --events 100000 --db-bench   # also DuckDB load and query timings
```

Reported metrics: events/s, latency percentiles (P50/P95/P99) and per-format throughput. `--db-bench` adds storage load and query timings. `--output results.json` saves everything as JSON.

---

## 2. Live network test

### Scripted sender (any OS)

Start a listener first, either from the desktop app (**Ingestion → Live Network Listener**) or with `python -m ulpf.main listen --port 5514`. Then, in another terminal:

```bash
python tests/scripts/run_live_test.py --format files                 # every demo file
python tests/scripts/run_live_test.py --format unknown --count 150   # proprietary formats for Auto-Learn
python tests/scripts/run_live_test.py --protocol tcp --count 200
python tests/scripts/run_live_test.py --speed max --count 5000       # unthrottled burst
```

Compare the number sent with the stored count (see "Check the result" below). UDP may drop datagrams under burst load; TCP should not drop any.

### Manual (two terminals, Linux/macOS/WSL)

```bash
# Terminal 1
bash tests/scripts/terminal_1_listener.sh

# Terminal 2
bash tests/scripts/terminal_2_sender.sh
```

| Phase | What happens |
|-------|--------------|
| 1 | Generate flood data (5 attack scenarios) |
| 2 | UDP flood: maximum offered rate |
| 3 | TCP flood: reliable delivery, plus every demo file |
| 4 | Concurrent multi-stream UDP |
| 5 | CLI feature run on the generated data: process, learn, forensic, fingerprint |

**On `nc` numbers:** a single `nc` process usually tops out at a few tens of thousands of UDP datagrams per second on loopback, and UDP drops packets under load by design. Use the TCP phase, or `python scripts/log_sender.py --proto tcp --eps 0`, when you need a loss-free comparison.

### Check the result

Events land in the canonical store (`ULPF_DB_PATH`, otherwise `<data dir>/ulpf.duckdb`). Set `ULPF_DATA_DIR=output` to keep it inside the project.

```bash
python -c 'import duckdb, os; print(duckdb.connect(os.path.join(os.environ.get("ULPF_DATA_DIR", "output"), "ulpf.duckdb"), read_only=True).execute("SELECT COUNT(*) FROM events").fetchone()[0])'
```

---

## 3. Automated test suites

```bash
python -m unittest tests.test_core -v      # engine, parsers, storage, forensics, correlation, APG, workers, live REST API
python tests/test_service_and_gui.py       # desktop service + Qt pages (QT_QPA_PLATFORM=offscreen on headless hosts)
python tests/test_audit_fixes.py
python tests/test_platform_and_listener.py
python -m ulpf.gui.qt_app --verify         # engine, worker process and all 10 pages, no window; exit 0 = pass
python -m benchmarks.apg_eval              # auto-parser generalisation on unseen lines + autonomous learning
python -m benchmarks.integrity_suite       # raw-byte integrity, tamper detection, crash recovery, drift, air-gap
```

CI (`.github/workflows/ci.yml`) runs the core and platform suites, the APG evaluation and the integrity suite on Linux and Windows (Python 3.10 and 3.12). It runs the GUI suites and `--verify` on Windows.

---

## 4. Measured performance (4-core laptop, Python 3.11)

| Metric | Measured |
|--------|----------|
| Full pipeline, single core | 12–15k events/s |
| Parse only, 8 processes | 39k events/s |
| Worker pool, 7 workers, parsed + persisted | 26k events/s, zero loss |
| DuckDB bulk load (Parquet) | ~61k rows/s |
| Newest-100 query on 1M events | 22 ms |

Throughput scales with physical cores. Re-run the benchmarks on the target hardware before sizing a deployment.

## Release 10.0

- Short v10 suites: `python -m pytest tests/test_v10_*.py -q` (49 tests, ~15 s).
- Long, hardware and soak runs that must pass before the 10.0.0 tag: [docs/LONG_TESTS.md](docs/LONG_TESTS.md).
