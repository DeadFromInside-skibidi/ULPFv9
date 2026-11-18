# ULPF Desktop Application — Development Guide

## Architecture

The ULPF desktop application follows a layered native architecture:

```
┌────────────────────────────────────────────────────────┐
│               PySide6 Native Desktop GUI               │
│  (MainWindow, QStackedWidget, Model/View Tables, Views)│
└───────────────────────────┬────────────────────────────┘
                            │ Signals / Slots / Method Calls
┌───────────────────────────▼────────────────────────────┐
│              ULPF Application Service Layer            │
│  (Thread-Safe façade for GUI, background task workers) │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│                    ULPF Core Engine                    │
│    Pipeline | Parsers | Auto-Parser | Forensics        │
└───────────────────────────┬────────────────────────────┘
                            │ Columnar PyArrow / SQL
┌───────────────────────────▼────────────────────────────┐
│                  DuckDB Storage Backend                │
│                 (In-Process OLAP Engine)               │
└────────────────────────────────────────────────────────┘
```

---

## Directory Organization

- `ulpf/gui/qt_app.py`: Entry point for launching the desktop application.
- `ulpf/gui/main_window.py`: Main shell containing the dark navy sidebar, topbar, stacked page container, and status bar.
- `ulpf/gui/theme.py`: Design tokens matching the ULPF design specifications (palette, fonts, dimensions, borders).
- `ulpf/gui/service.py`: Service layer abstracting backend functionality.
- `ulpf/gui/widgets.py`: Component library (`MetricCard`, `StatusBadge`, `DataTable`, `SearchBar`, `FilterBar`, `PageHeader`, `SectionCard`, `EmptyState`, `LoadingState`, `FileDropZone`, `KeyValueRow`).
- `ulpf/gui/workers/background.py`: `QThread` workers for asynchronous ingestion and heavy queries.
- `ulpf/gui/pages/`: The 14 native desktop pages:
  - `overview.py`
  - `ingestion.py`
  - `explorer.py`
  - `parsers.py`
  - `autolearn.py`
  - `logdna.py`
  - `correlation.py`
  - `anomalies.py`
  - `forensics.py`
  - `schema.py`
  - `pipeline.py`
  - `listener.py`
  - `storage.py`
  - `settings.py`

---

## Running in Development Mode

```bash
# Direct GUI launch
python -m ulpf.gui.qt_app

# CLI command launch
python -m ulpf.main desktop
```

---

## Testing

Run the comprehensive service and GUI test suite:
```bash
python -m unittest tests/test_service_and_gui.py
```
All tests execute without requiring an active X11/Wayland display server or external network connections.
