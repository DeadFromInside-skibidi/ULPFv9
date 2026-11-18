# ULPF — Installation Guide

ULPF runs as a desktop application (PySide6), a CLI, a terminal UI, a REST API server or a Docker container. All of them share the same engine and the same local DuckDB event store, and none of them needs an internet connection at runtime.

---

## System requirements

| Specification | Minimum | Recommended |
|---|---|---|
| **Operating system** | Windows 10/11 x64, Linux (glibc 2.27+), macOS 12+ | Windows 11 / RHEL 8+ / Ubuntu 22.04+ |
| **Python** | 3.10 (not needed for a PyInstaller bundle) | 3.11 |
| **Processor** | 2 cores | 4+ cores (ingest throughput scales with cores) |
| **Memory** | 2 GB | 8 GB+ for multi-million-event stores |
| **Disk** | ~150 MB of dependencies for CLI/API, ~800 MB with the desktop app (PySide6), plus log storage | SSD/NVMe |
| **Network** | None | Local UDP/TCP 5514 if syslog devices forward to ULPF |

---

## Option 1 — From source with pip (all platforms)

```bash
git clone <your-repo-url> ulpf && cd ulpf
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt      # core, API, TUI, desktop app and benchmark graphs
# or pick extras: pip install -e ".[api,tui]"   /   pip install -e ".[gui]"
python -m ulpf.main --help
```

Launch the desktop app:

```bash
python -m ulpf.gui.qt_app            # or: python -m ulpf.main desktop
```

## Option 2 — Windows, bundled interpreter

If the repository copy includes the `python311\` runtime folder (it is excluded from git because of its size), double-click **`LAUNCH_GUI.bat`**. It starts, in order of preference:

1. `dist\ULPF\ULPF.exe` if you have built a standalone bundle (see [BUILD_GUIDE.md](BUILD_GUIDE.md));
2. `python311\pythonw.exe -m ulpf.gui.qt_app`;
3. the system Python.

## Option 3 — Standalone bundle (no Python on the target)

Build `dist/ULPF/` with PyInstaller on a machine of the same OS/architecture ([BUILD_GUIDE.md](BUILD_GUIDE.md)), copy the whole folder to the target and run `ULPF.exe` (Windows) or `./ULPF` (Linux/macOS).

## Option 4 — Docker (live pipeline + REST API)

```bash
docker compose up -d                 # API on http://localhost:8000/docs, syslog on 5514/tcp+udp
logger -n 127.0.0.1 -P 5514 -T "hello ulpf"                       # send a test line
curl -s localhost:8000/api/v1/runtime/status | head -c 400
```

The container runs `ulpf run --config /app/config/pipeline.docker.yaml`, which listens for syslog TCP and UDP plus HTTP and OTLP ingest, and stores into the local DuckDB store. To change the pipeline, mount your own file over that path. The journal, store, evidence and learned parsers persist in the `ulpf-data` volume. Set `ULPF_API_KEY` (an admin key) and `ULPF_INGEST_KEY` in `docker-compose.yml`, or mount an `api.keys_file` created with `ulpf apikey new`. `docker compose stop` drains queued data before the container exits (`stop_grace_period: 60s`).

## Option 4b — Linux service (systemd)

```bash
sudo useradd --system --home /var/lib/ulpf --shell /usr/sbin/nologin ulpf
sudo install -d -o ulpf -g ulpf /var/lib/ulpf /etc/ulpf
sudo python3 -m venv /opt/ulpf/venv && sudo /opt/ulpf/venv/bin/pip install /path/to/ulpf   # or the offline bundle
sudo cp config/pipeline.example.yaml /etc/ulpf/pipeline.yaml
sudo /opt/ulpf/venv/bin/ulpf config check /etc/ulpf/pipeline.yaml
sudo cp deploy/systemd/ulpf.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ulpf
sudo systemctl reload ulpf           # SIGHUP: re-read the config; an invalid file is rejected, nothing changes
journalctl -u ulpf -f
```

Put secrets for `*_env` options in `/etc/ulpf/ulpf.env` (mode 0600). The unit grants `CAP_NET_BIND_SERVICE`, so ULPF can listen on port 514 without running as root.

## Option 4c — Windows service (NSSM)

```powershell
nssm install ULPF "C:\ULPF\python311\python.exe" "-m ulpf.main run --config C:\ULPF\config\pipeline.yaml"
nssm set ULPF AppDirectory C:\ULPF
nssm set ULPF AppEnvironmentExtra ULPF_DATA_DIR=C:\ProgramData\ULPF
nssm set ULPF AppStopMethodConsole 60000        # Ctrl+C first: inputs stop, queued data drains
nssm set ULPF AppRotateFiles 1
nssm set ULPF AppStdout C:\ProgramData\ULPF\service.log
nssm start ULPF
ulpf reload --url http://127.0.0.1:8000   # Windows has no SIGHUP: reload through the API (admin key in ULPF_API_KEY)
```

## Sizing the local store

The embedded DuckDB store (`type: duckdb`) suits interactive queries over recent data. Its buffer pool is capped at 25 % of RAM (at most 4 GB; `ULPF_DUCKDB_MEMORY` overrides), but the process's native memory also grows with the number of stored rows. A one-hour soak at 5,000 events/s added about 1.3 GB on top of the cap (docs/STATUS.md). For sustained high volume:

- send the full stream to the Parquet lake (`type: parquet`, optionally `s3`) or a SIEM output, which keep memory flat;
- route only what analysts query interactively to the store (for example `severity_gte: 5`, or the derived `kind_in: [correlation, drift, anomaly]` events);
- set retention: `ulpf purge --older-than-days N` for the store, and `journal.retention_days` for the raw archive.

## Several nodes

See [MULTI_NODE.md](MULTI_NODE.md).

## Option 5 — Air-gapped server install

See [AIR_GAPPED_DEPLOYMENT_GUIDE.md](AIR_GAPPED_DEPLOYMENT_GUIDE.md) for the offline wheel bundle produced by `scripts/package_offline.sh`.

---

## First run

On first start ULPF:

1. Resolves its data directory: `ULPF_DATA_DIR` if set, otherwise
   - **Windows:** `%LOCALAPPDATA%\ULPF\`
   - **Linux:** `~/.local/share/ulpf/` (or `$XDG_DATA_HOME/ulpf/`)
   - **macOS:** `~/Library/Application Support/ULPF/`
2. Creates the DuckDB event store `ulpf.duckdb` there (override with `ULPF_DB_PATH` or `--db`).
3. Loads the built-in parsers, the threat-intel feeds from `config/`, and any learned parsers from `<data dir>/learned_parsers/`.
4. Creates `parser_signing.key` (HMAC key for learned parser specs) on first use of the auto-parser.

No prompts, accounts or internet access are required.

## Verifying an installation

```bash
python -m ulpf.gui.qt_app --verify   # headless self-check of engine + every UI page, exit code 0 = pass
python -m unittest tests.test_core   # engine, storage, forensics, APG, workers, live REST API
python -m unittest tests.test_runtime tests.test_usp   # the live pipeline and the five USPs
ulpf config check config/pipeline.example.yaml          # what a config opens and connects to
```

## Optional components

| Component | Install |
|---|---|
| Kafka input/output | `pip install "ulpf[kafka]"` |
| MQTT input | `pip install "ulpf[mqtt]"` |
| Azure Event Hubs input | `pip install "ulpf[eventhubs]"` |
| GeoIP | place a GeoLite2-City / GeoIP2 / DB-IP Lite `.mmdb` in `config/geoip/` or `<data dir>/geoip/` |
| Compiled core (experimental) | Rust toolchain, then `scripts/build_native.ps1` or `scripts/build_native.sh`; enable with `ULPF_NATIVE=1`. It is not faster than the Python path today (docs/STATUS.md, Phase F) |
