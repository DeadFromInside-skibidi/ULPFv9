"""
Native Screenshot Capture Tool
Captures pixel-accurate screenshots of all 10 views with the platform's native
fonts. The window is rendered off-screen (never appears on the desktop) and
the demo data goes into a temporary store unless ULPF_DATA_DIR is set.

    python tests/scripts/capture_native_screens.py      # PNGs in tests/live_output/screens
"""
import os
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
os.environ.setdefault("ULPF_DATA_DIR", tempfile.mkdtemp(prefix="ulpf_screens_"))

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication

from ulpf.gui.service import ULPFService
from ulpf.gui.main_window import ULPFMainWindow


def main():
    app = QApplication.instance() or QApplication(sys.argv)
    
    # Apply stylesheet
    from ulpf.gui.theme import APP_STYLESHEET
    app.setStyleSheet(APP_STYLESHEET)

    service = ULPFService()
    if not service.initialize():
        print("[FAIL] Could not initialize service")
        sys.exit(1)

    if service.get_stats().get("total_events", 0) == 0:
        for f in ["firewall_cef.log", "router_syslog.log", "waf_json.log", "ids_leef.log", "fortigate_kv.log"]:
            p = os.path.join(REPO_ROOT, "demo_data", f)
            if os.path.exists(p):
                service.ingest_file(p)

    window = ULPFMainWindow(service)
    window.resize(1440, 920)
    window.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
    window.show()
    app.processEvents()

    output_dir = Path(os.environ.get("ULPF_SCREENSHOT_DIR")
                      or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "live_output", "screens"))
    output_dir.mkdir(parents=True, exist_ok=True)

    pages = [
        ("overview", "native_01_overview.png"),
        ("ingestion", "native_02_ingestion.png"),
        ("events", "native_03_events.png"),
        ("parsers", "native_04_parsers.png"),
        ("autolearn", "native_05_autolearn.png"),
        ("logdna", "native_06_logdna.png"),
        ("correlation", "native_07_correlation.png"),
        ("anomalies", "native_08_anomalies.png"),
        ("forensics", "native_09_forensics.png"),
        ("schema", "native_10_schema.png"),
    ]

    for key, filename in pages:
        window.navigate_to(key)
        # Process events multiple times to ensure full layout and text paint
        for _ in range(10):
            app.processEvents()
            time.sleep(0.05)

        pixmap = window.grab()
        out_path = output_dir / filename
        pixmap.save(str(out_path), "PNG")
        print(f"[OK] Captured {key:12s} -> {filename}")

        if key == "ingestion":
            ingest_scroll = window._pages.get("ingestion")
            actual_page = ingest_scroll.widget() if hasattr(ingest_scroll, "widget") else ingest_scroll
            if actual_page and hasattr(actual_page, "set_mode"):
                actual_page.set_mode("B")
                for _ in range(10):
                    app.processEvents()
                    time.sleep(0.05)
                pixmap_b = window.grab()
                out_path_b = output_dir / "native_02b_ingestion_mode_b.png"
                pixmap_b.save(str(out_path_b), "PNG")
                print(f"[OK] Captured ingestion Mode B -> native_02b_ingestion_mode_b.png")
                actual_page.set_mode("A")

    window.close()
    service.shutdown()
    print("[SUCCESS] All 10 views captured with native DirectWrite fonts!")


if __name__ == "__main__":
    main()
