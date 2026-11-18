# ULPF — Air-Gapped Deployment Guide

## 1. Isolation properties

ULPF is built to run on hosts with no internet access.

- **No outbound traffic of its own.** No telemetry, update checks, licence calls or DNS lookups. Outbound traffic happens only when you configure it explicitly: the SIEM forwarder (`--siem-forward`) or the desktop app's forwarding panel.
- **Inbound only when asked.** The syslog listener (UDP/TCP 5514) and the REST API (`serve`, bound to `127.0.0.1` by default) start only on request.
- **Air-gap detection without sending packets.** `is_air_gapped()` calls `connect()` on a UDP socket aimed at a TEST-NET address. That only asks the OS for a route, so nothing is transmitted.
- **Local state only.** Events, evidence chains, learned parsers and the parser-signing key live in the data directory and are protected by OS file permissions. ULPF does not encrypt the store itself. For encryption at rest, put the data directory on a BitLocker, LUKS or FileVault volume (see §3).
- **Provenance.** Every event carries the SHA-256 of its raw bytes from the point of entry. Forensic chains (hash chain + Merkle root + custody log) can be verified offline with `ulpf forensic --verify`.

---

## 2. Packaging and transfer

Choose one artefact. Build it on a connected staging machine with the **same OS, CPU architecture and Python minor version** as the target.

| Artefact | Built with | Target needs |
|---|---|---|
| Desktop bundle `dist/ULPF/` (zip/tar) | `python -m PyInstaller --clean --noconfirm packaging/ulpf_desktop.spec` ([BUILD_GUIDE.md](BUILD_GUIDE.md)) | nothing |
| Offline wheel bundle `ulpf-plugin-offline.tar.gz` | `bash scripts/package_offline.sh` | Python 3.10+ |
| Container image | `docker build -t ulpf . && docker save ulpf -o ulpf.tar` | Docker (`docker load -i ulpf.tar`) |

Checksum on the staging machine:

```bash
sha256sum ulpf-plugin-offline.tar.gz > SHA256SUMS
```

Transfer over approved offline media (data diode or encrypted removable storage), then verify on the target:

```powershell
Get-FileHash -Algorithm SHA256 .\ULPF-win-x64.zip      # Windows
```

```bash
sha256sum -c SHA256SUMS                                 # Linux
```

Install:

```bash
# Offline wheel bundle (server / CLI / TUI)
tar -xzf ulpf-plugin-offline.tar.gz && cd ulpf-offline-pkg && ./install.sh

# Desktop bundle: extract, then self-test (exit code 0 = pass)
dist/ULPF/ULPF --verify
```

---

## 3. Data and state paths

| OS | Default data directory |
|---|---|
| **Windows** | `%LOCALAPPDATA%\ULPF\` |
| **Linux** | `~/.local/share/ulpf/` (or `$XDG_DATA_HOME/ulpf/`) |
| **macOS** | `~/Library/Application Support/ULPF/` |

The data directory holds `ulpf.duckdb`, `spool/`, `evidence/`, `learned_parsers/`, `log_dna_db.json` and `parser_signing.key`. To move all of it to a secure volume, set `ULPF_DATA_DIR` before starting any ULPF component:

```cmd
set ULPF_DATA_DIR=E:\SecureStorage\ULPF
python -m ulpf.gui.qt_app
```

```bash
export ULPF_DATA_DIR=/srv/ulpf
ulpf run --config /etc/ulpf/pipeline.yaml        # with mode: defence in the file
```

`ULPF_DB_PATH` (or the CLI's `--db`) moves only the event store.

---

## 4. Ingestion inside the enclave

1. **Files.** Copy logs to local media, then either drop them on the desktop app's **Ingestion** page or run `ulpf process --files "/media/logs/*.log"`.
2. **Network syslog and other sources: the live pipeline in defence mode.**
   - Server: `ulpf run --config /etc/ulpf/pipeline.yaml` with `mode: defence`. Defence mode requires TLS on listeners (`protocol: tls`, RFC 5425) and outputs, encrypts the journal (AES-256-GCM), refuses cloud connectors, and enforces `airgap.allow` in every process: a connection to any other address fails before a packet is sent. `ulpf config check` lists everything the config listens on and connects to before you start it.
   - Each rule can be waived only by naming it in `overrides:` (for example, a legacy device that cannot do TLS). Waivers are printed at start-up and recorded in the audit log.
   - Desktop: **Ingestion → Live Network Listener**, choose UDP/TCP and a port (default 5514).
   - Point switches, firewalls and servers at the host's IP. TCP accepts newline-delimited and RFC 6587 octet-counted framing.
   - Ports below 1024 need administrator/root rights, or `CAP_NET_BIND_SERVICE` (granted by `deploy/systemd/ulpf.service`).
3. **Unknown formats.** In defence mode, learned parsers wait for an operator: review them with `ulpf parsers list` and decide with `ulpf parsers approve|reject <id>`. `ulpf source onboard --name <src> --sample sample.log --mode defence` learns from a sample in one step. Learned parsers are HMAC-signed with the local key and validated. Approved ones reach every worker without a restart.
4. **GeoIP without the internet.** Copy a MaxMind-format database (GeoLite2-City, GeoIP2, DB-IP Lite) into `config/geoip/` or `<data dir>/geoip/`. It is read locally with no extra dependency.
5. **Evidence.** `ulpf evidence verify --check-store` recomputes every seal from the journal and checks every stored row's MAC. Route `kind_in: [seal]` events to an off-box output, so that rewriting the local store cannot also rewrite the seals.

## 5. Operational hygiene

- Retention: `ulpf purge --older-than-days 90` deletes old events; `--raw-fallback` deletes lines no parser recognised.
- Back up the data directory as a whole. The signing key is needed to keep trusting existing learned parsers.
- Exported forensic packages are self-contained JSON and can be verified on any ULPF host with `ulpf forensic --verify <package.json>`.
