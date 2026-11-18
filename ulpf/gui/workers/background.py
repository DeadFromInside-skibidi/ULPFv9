"""
ULPF GUI Background Workers
==============================
QThread-based workers for heavy operations that must not block the GUI.
Every worker emits signals on completion so UI updates happen safely.
"""
from __future__ import annotations

from PySide6.QtCore import QObject, QRunnable, QThread, Signal, Slot
from typing import Any, Callable


class WorkerSignals(QObject):
    """Signals for WorkerRunnable."""
    finished = Signal()
    error = Signal(str)
    result = Signal(object)
    progress = Signal(int)            # 0-100
    status = Signal(str)              # human-readable status text


class WorkerRunnable(QRunnable):
    """
    Generic QRunnable for running a function in QThreadPool.

    Usage:
        worker = WorkerRunnable(service.ingest_file, filepath)
        worker.signals.result.connect(on_result)
        worker.signals.error.connect(on_error)
        QThreadPool.globalInstance().start(worker)
    """

    def __init__(self, fn: Callable, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()
        self.setAutoDelete(True)

    @Slot()
    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
            self.signals.result.emit(result)
        except Exception as e:
            self.signals.error.emit(str(e))
        finally:
            self.signals.finished.emit()


# Backward compatibility alias
ProcessingWorker = WorkerRunnable


class IngestionWorker(QThread):
    """Dedicated thread for file ingestion with progress."""
    progress = Signal(int, str)       # (percent, status_text)
    file_done = Signal(dict)          # per-file result
    all_done = Signal(list)           # all results
    error = Signal(str)

    def __init__(self, service, files: list[str], parent=None):
        super().__init__(parent)
        self.service = service
        self.files = files
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        results = []
        total = len(self.files)
        for i, f in enumerate(self.files):
            if self._cancel:
                break
            self.progress.emit(int((i / total) * 100),
                               f"Processing {i+1}/{total}: {f}")
            try:
                result = self.service.ingest_file(f)
                result["file"] = f
                results.append(result)
                self.file_done.emit(result)
            except Exception as e:
                err = {"file": f, "success": False, "error": str(e)}
                results.append(err)
                self.file_done.emit(err)

        self.progress.emit(100, "Complete")
        self.all_done.emit(results)


class QueryWorker(QThread):
    """Background event query."""
    result = Signal(list)
    error = Signal(str)

    def __init__(self, service, filters=None, limit=100, offset=0,
                 search_query=None, parent=None):
        super().__init__(parent)
        self.service = service
        self.filters = filters
        self.limit = limit
        self.offset = offset
        self.search_query = search_query

    def run(self):
        try:
            if self.search_query:
                events = self.service.search_events(self.search_query, self.limit)
            else:
                events = self.service.query_events(self.filters, self.limit, self.offset)
            self.result.emit(events)
        except Exception as e:
            self.error.emit(str(e))


class CorrelationWorker(QThread):
    """Background correlation analysis."""
    result = Signal(list)
    error = Signal(str)

    def __init__(self, service, limit=200, window=60.0, parent=None):
        super().__init__(parent)
        self.service = service
        self.limit = limit
        self.window = window

    def run(self):
        try:
            groups = self.service.correlate(self.limit, self.window)
            self.result.emit(groups)
        except Exception as e:
            self.error.emit(str(e))


class ForensicWorker(QThread):
    """Background forensic chain building."""
    result = Signal(dict)
    error = Signal(str)

    def __init__(self, service, limit=100, description="", tags=None, parent=None):
        super().__init__(parent)
        self.service = service
        self.limit = limit
        self.description = description
        self.tags = tags

    def run(self):
        try:
            chain = self.service.forensic_build_from_events(
                self.limit, self.description, self.tags
            )
            self.result.emit(chain)
        except Exception as e:
            self.error.emit(str(e))
