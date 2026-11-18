"""PyInstaller entry point for the ULPF desktop application."""
import multiprocessing

if __name__ == "__main__":
    # Must run first: frozen multiprocessing children (ingest workers) re-enter
    # this script with --multiprocessing-fork and must not start the GUI
    multiprocessing.freeze_support()
    from ulpf.gui.qt_app import main
    main()
