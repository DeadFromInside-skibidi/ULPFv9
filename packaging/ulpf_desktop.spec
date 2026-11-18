# PyInstaller spec for the ULPF desktop application (one-folder build).
#
#   python -m PyInstaller --clean --noconfirm packaging/ulpf_desktop.spec
#
# Output: dist/ULPF/ULPF.exe (Windows) or dist/ULPF/ULPF (Linux/macOS).
# Build on the same OS/architecture as the target; PyInstaller does not cross-compile.
import os

from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, os.pardir))
ICON = os.path.join(ROOT, "ulpf", "gui", "resources", "ulpf_icon.ico")

# Read-only assets resolved through sys._MEIPASS at runtime. Mutable state
# (event store, evidence, learned parsers) goes to ULPF_DATA_DIR, never here.
datas = [
    (os.path.join(ROOT, "config"), "config"),
    (os.path.join(ROOT, "demo_data"), "demo_data"),
    (os.path.join(ROOT, "ulpf", "gui", "resources"), os.path.join("ulpf", "gui", "resources")),
    (os.path.join(ROOT, "ulpf", "plugin", "manifest.json"), os.path.join("ulpf", "plugin")),
]

a = Analysis(
    [os.path.join(SPECPATH, "ulpf_desktop.py")],
    pathex=[ROOT],
    datas=datas,
    # Custom parser modules are discovered with pkgutil, which static analysis cannot see
    hiddenimports=collect_submodules("ulpf.parsers"),
    # Server, TUI and report tooling are not used by the desktop app
    excludes=[
        "tkinter", "matplotlib", "pytest", "IPython", "docx", "reportlab",
        "fastapi", "starlette", "uvicorn", "textual",
    ],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="ULPF",
    console=False,
    icon=ICON if os.path.exists(ICON) else None,
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name="ULPF", upx=False)
