# ULPF Desktop Application — Build & Packaging Guide

ULPF ships as Python source. There are three ways to deliver it to a target host:

| Delivery | Target needs Python? | How |
|---|---|---|
| Standalone desktop bundle | No | PyInstaller with [`packaging/ulpf_desktop.spec`](../packaging/ulpf_desktop.spec) (this guide) |
| Server / CLI wheel bundle | Yes (3.10+) | [`scripts/package_offline.sh`](../scripts/package_offline.sh), see [AIR_GAPPED_DEPLOYMENT_GUIDE.md](AIR_GAPPED_DEPLOYMENT_GUIDE.md) |
| Container | Docker | `docker build -t ulpf .` ([`Dockerfile`](../Dockerfile)) |

---

## Standalone desktop bundle (PyInstaller)

The spec produces a **one-folder** build: an executable plus its Python runtime, Qt, DuckDB and PyArrow libraries, the `config/` intelligence feeds and the `demo_data/` corpus. The target host needs nothing else installed.

PyInstaller does not cross-compile. Build on the same OS and CPU architecture as the target (Windows x64 → Windows x64, Linux x64 → Linux x64, and so on).

### Prerequisites (build machine only)

```bash
pip install -r requirements.txt
pip install "pyinstaller>=6.0"
```

### Build

Run from the project root on any OS:

```bash
python -m unittest tests.test_core          # optional: test the source first
python -m PyInstaller --clean --noconfirm packaging/ulpf_desktop.spec
```

On Windows with the bundled interpreter:

```cmd
python311\python.exe -m PyInstaller --clean --noconfirm packaging\ulpf_desktop.spec
```

Output:

| OS | Executable |
|---|---|
| Windows | `dist\ULPF\ULPF.exe` |
| Linux | `dist/ULPF/ULPF` |
| macOS | `dist/ULPF/ULPF` (wrap in an `.app`/`.dmg` with your own signing pipeline) |

`LAUNCH_GUI.bat` automatically prefers `dist\ULPF\ULPF.exe` when it exists. Rebuild after every source change, otherwise the launcher runs stale code. Delete `dist\` to go back to running from source.

### Verify the build

```cmd
dist\ULPF\ULPF.exe --verify
echo %ERRORLEVEL%
```

`--verify` starts the engine without opening a window, parses a probe line, builds every UI page and exits with code `0` on success. Run it on the target host after transfer as well.

### Ship it

Archive the whole `dist/ULPF/` folder (not just the executable) and generate a checksum:

```powershell
Compress-Archive -Path dist\ULPF -DestinationPath ULPF-win-x64.zip
Get-FileHash -Algorithm SHA256 ULPF-win-x64.zip
```

```bash
tar -czf ULPF-linux-x64.tar.gz -C dist ULPF
sha256sum ULPF-linux-x64.tar.gz > SHA256SUMS
```

An installer (Inno Setup, MSI, AppImage, DMG) can wrap `dist/ULPF/` if your organisation requires one; the project does not ship installer scripts.

---

## Icons

The application icons are committed in `ulpf/gui/resources/`. To regenerate them after a design change:

```bash
pip install pillow
python scripts/generate_app_icon.py
```

---

## Air-gap checklist for a built bundle

- [ ] `ULPF.exe --verify` exits `0` on the target with network adapters disabled.
- [ ] The event store is created under `%LOCALAPPDATA%\ULPF\` (or `ULPF_DATA_DIR`).
- [ ] File ingestion and the local UDP/TCP listener work with no outbound connections.
- [ ] Forensic chains can be built and verified offline.
- [ ] No web server or browser process is started by the desktop app.
