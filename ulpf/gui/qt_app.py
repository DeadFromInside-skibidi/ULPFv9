"""
ULPF Desktop Application — Entry Point
==========================================
Launches the native PySide6 desktop application.

Usage:
    python -m ulpf.gui.qt_app
    python -m ulpf.main desktop
"""
from __future__ import annotations

import sys
import logging
import os

# Configure logging before any imports
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("ulpf.gui")


_single_instance_mutex = None


def _acquire_single_instance_lock() -> bool:
    """Guarantee that only ONE instance of the ULPF application can run simultaneously."""
    global _single_instance_mutex
    if sys.platform != "win32":
        return True

    # Allow automated verification / testing without single-instance exit
    if any(arg in sys.argv for arg in ("--verify", "--test-mode", "--check", "--no-mutex")):
        return True

    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32
        ERROR_ALREADY_EXISTS = 183

        mutex_name = "Local\\ULPF_Desktop_SingleInstance_Mutex_v8"
        mutex = kernel32.CreateMutexW(None, False, mutex_name)
        last_error = kernel32.GetLastError()

        if last_error == ERROR_ALREADY_EXISTS:
            logger.info("Another instance of ULPF is already running. Bringing existing window to foreground.")
            
            def _enum_win_cb(hwnd, extra):
                if user32.IsWindowVisible(hwnd):
                    length = user32.GetWindowTextLengthW(hwnd)
                    if length > 0:
                        buff = ctypes.create_unicode_buffer(length + 1)
                        user32.GetWindowTextW(hwnd, buff, length + 1)
                        if "ULPF" in buff.value:
                            SW_RESTORE = 9
                            user32.ShowWindow(hwnd, SW_RESTORE)
                            user32.SetForegroundWindow(hwnd)
                            return False
                return True

            EnumProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
            user32.EnumWindows(EnumProc(_enum_win_cb), 0)

            if mutex:
                kernel32.CloseHandle(mutex)
            sys.exit(0)

        _single_instance_mutex = mutex
        return True
    except Exception as e:
        logger.debug(f"Single instance check non-fatal error: {e}")
        return True


def _verify_worker_pool(line: str, count: int = 10, timeout: float = 30.0) -> bool:
    """Parse lines in a spawned worker process (catches broken frozen builds)."""
    import time
    from ulpf.ingestion.workers import WorkerPool
    pool = WorkerPool(num_workers=1)
    try:
        pool.start(save_local=False)
        pool.submit_batch([line] * count)
        deadline = time.monotonic() + timeout
        while pool.total_success.value < count and time.monotonic() < deadline:
            time.sleep(0.05)
        return pool.total_success.value >= count
    except Exception as e:
        logger.error(f"Worker pool probe failed: {e}")
        return False
    finally:
        pool.stop(timeout=10.0)


def main():
    """Launch the ULPF native desktop application."""
    import multiprocessing
    multiprocessing.freeze_support()

    # If this process was launched as a multiprocessing child worker, do not launch GUI
    if any(arg.startswith("--multiprocessing") for arg in sys.argv):
        return

    # Enforce single instance - immediately exits if another instance is running
    _acquire_single_instance_lock()

    # Suppress Qt warnings about missing fonts etc in air-gapped env
    os.environ.setdefault("QT_LOGGING_RULES", "qt.qpa.*=false")

    from PySide6.QtWidgets import QApplication
    from PySide6.QtGui import QPixmap, QColor
    from PySide6.QtCore import Qt

    from ulpf import __version__
    app = QApplication(sys.argv)
    app.setApplicationName("ULPF")
    app.setOrganizationName("ULPF")
    app.setApplicationVersion(__version__)

    # Set application icon
    from PySide6.QtGui import QPixmap, QColor, QIcon
    icon_path = os.path.join(os.path.dirname(__file__), "resources", "ulpf_icon.ico")
    if not os.path.exists(icon_path):
        icon_path = os.path.join(os.path.dirname(__file__), "resources", "ulpf_icon.png")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    # Apply theme stylesheet
    from ulpf.gui.theme import APP_STYLESHEET
    app.setStyleSheet(APP_STYLESHEET)

    # Fast path for automated verification / CI / headless check
    if any(arg in sys.argv for arg in ("--verify", "--test-mode", "--check")):
        if sys.platform == "win32":
            try:
                import ctypes
                if ctypes.windll.kernel32.AttachConsole(-1):
                    sys.stdout = open("CONOUT$", "w", encoding="utf-8")
                    sys.stderr = open("CONOUT$", "w", encoding="utf-8")
            except Exception:
                pass

        from ulpf.gui.service import ULPFService
        from ulpf.gui.main_window import ULPFMainWindow

        service = ULPFService()
        ok = service.initialize(start_listener=False)
        window = ULPFMainWindow(service)

        from ulpf.platform.paths import get_system_info
        probe_line = "<134>Aug 28 10:15:01 core-rtr-01 %SYS-5-CONFIG_I: Configured from console"
        probe = service.test_parser(probe_line)
        parse_ok = bool(probe.get("success")) and probe["event"]["raw_format"] == "syslog"
        workers_ok = _verify_worker_pool(probe_line)
        air_gapped = get_system_info().get("is_air_gapped")
        h = service.health()
        parsers = service.list_parsers()
        ok = ok and parse_ok and workers_ok and h.get("status") == "healthy"
        print("=" * 65)
        print("  ULPF STANDALONE BINARY VERIFICATION")
        print("=" * 65)
        print(f"  Engine Status  : {h.get('status', 'unknown').upper()}")
        print(f"  Storage        : {service.get_storage_info().get('path')}")
        print(f"  Parsers Loaded : {len(parsers)}")
        print(f"  Parse Probe    : {'OK' if parse_ok else 'FAILED'}")
        print(f"  Worker Process : {'OK' if workers_ok else 'FAILED'}")
        print(f"  UI Pages Loaded: {window.page_stack.count()}")
        print(f"  Network Route  : {'none (air-gapped)' if air_gapped else 'present (ULPF makes no outbound connections)'}")
        print(f"  Verdict        : {'[PASS]' if ok else '[FAIL]'}")
        print("=" * 65)
        sys.stdout.flush()
        service.shutdown()
        sys.exit(0 if ok else 1)

    # Initialize service
    from ulpf.gui.service import ULPFService
    service = ULPFService()
    ok = service.initialize()
    if not ok:
        logger.error(f"Failed to initialize ULPF engine: {service.error}")

    # Build main window
    from ulpf.gui.main_window import ULPFMainWindow
    window = ULPFMainWindow(service)
    window.show()
    window.raise_()
    window.activateWindow()

    logger.info("ULPF Desktop application started.")
    from ulpf.engine.perf import tune_gc
    tune_gc()
    try:
        sys.exit(app.exec())
    finally:
        if _single_instance_mutex and sys.platform == "win32":
            try:
                import ctypes
                ctypes.windll.kernel32.CloseHandle(_single_instance_mutex)
            except Exception:
                pass


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    main()
