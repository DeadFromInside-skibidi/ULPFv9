"""
ULPF Event Explorer Page
===========================
Pixel-faithful reproduction of the Event Explorer investigation
workspace from reference photo WhatsApp Image 2026-09-27 at 23.56.39.jpeg.
"""
from __future__ import annotations

import json
import os
from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex, QThreadPool
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableView, QHeaderView, QSplitter, QTextEdit, QFrame,
    QLineEdit, QComboBox, QAbstractItemView, QApplication,
)

from ulpf.gui import theme as T
from ulpf.gui.widgets import (
    PillBadge, StatusBadge, SectionCard,
    SeverityBadgeDelegate, FormatPillDelegate, CategoryDelegate, MonoTextDelegate,
)
from ulpf.gui.service import ULPFService
from ulpf.gui.workers.background import WorkerRunnable


def _display_ts(ts) -> str:
    """'2024-08-28T10:15:30.123+00:00' -> '2024-08-28 10:15:30.123 UTC' (other offsets kept)."""
    if not ts:
        return "—"
    s = str(ts).replace("T", " ", 1)
    if s.endswith(("+00:00", "Z")):
        return s[:-6 if s.endswith("+00:00") else -1][:23] + " UTC"
    return s


class EventTableModel(QAbstractTableModel):
    HEADERS = [
        "TIMESTAMP", "SEV", "FORMAT", "PARSED", "CATEGORY", "ACTION",
        "SOURCE IP", "DESTINATION IP", "PROTOCOL", "PARSER", "EVIDENCE"
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._events: list[dict] = []

    def set_events(self, events: list[dict]):
        self.beginResetModel()
        self._events = events
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self._events)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        ev = self._events[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return _display_ts(ev.get("timestamp"))
            elif col == 1:
                return str(ev.get("severity", 0))
            elif col == 2:
                rf = str(ev.get("raw_format", "AUTO")).upper()
                return "UNKNOWN" if rf == "RAW_FALLBACK" else rf
            elif col == 3:
                fmt = str(ev.get("raw_format", "unknown")).lower()
                return "No" if fmt == "unknown" else "Yes"
            elif col == 4:
                return str(ev.get("category", "other"))
            elif col == 5:
                return str(ev.get("action", "other"))
            elif col == 6:
                src = ev.get("source", {}).get("ip") or ev.get("source_ip") or ev.get("source", {}).get("hostname") or "—"
                port = ev.get("source", {}).get("port") or ev.get("source_port")
                return f"{src}:{port}" if (port and src != "—") else str(src)
            elif col == 7:
                dst = ev.get("destination", {}).get("ip") or ev.get("destination_ip") or ev.get("destination", {}).get("hostname") or ev.get("device", {}).get("hostname") or "—"
                port = ev.get("destination", {}).get("port") or ev.get("destination_port")
                return f"{dst}:{port}" if (port and dst != "—") else str(dst)
            elif col == 8:
                return str(ev.get("network", {}).get("protocol") or ev.get("protocol") or "TCP").upper()
            elif col == 9:
                return str(ev.get("raw_format", "cef")).lower()
            elif col == 10:
                return str(ev.get("evidence", {}).get("raw_hash") or ev.get("raw_hash") or "")[:8]
        elif role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (1, 2, 3, 8, 9, 10):
                return Qt.AlignmentFlag.AlignCenter
        return None

    def get_event(self, row: int) -> dict | None:
        if 0 <= row < len(self._events):
            return self._events[row]
        return None


class ExplorerPage(QWidget):
    """Institutional Event Explorer Page."""

    def __init__(self, service: ULPFService, parent=None):
        super().__init__(parent)
        self.service = service
        self.threadpool = QThreadPool.globalInstance()

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(16)

        # ── Search & Filter Card ──
        filter_card = QFrame()
        filter_card.setStyleSheet(f"""
            QFrame {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 14px 18px;
            }}
        """)
        fl = QVBoxLayout(filter_card)
        fl.setContentsMargins(14, 12, 14, 12)
        fl.setSpacing(12)

        # Search Row
        search_row = QHBoxLayout()
        search_row.setSpacing(10)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍  Search events (message, raw text, tags, IPs)...")
        self.search_input.setFixedHeight(34)
        self.search_input.returnPressed.connect(self._apply_search)
        search_row.addWidget(self.search_input, 1)

        self.btn_pause = QPushButton("Pause Live View")
        self.btn_pause.setProperty("btnClass", "outline")
        self.btn_pause.setFixedHeight(34)
        self.btn_pause.clicked.connect(self._toggle_pause)
        search_row.addWidget(self.btn_pause)

        self.btn_refresh = QPushButton("Refresh")
        self.btn_refresh.setProperty("btnClass", "secondary")
        self.btn_refresh.setFixedHeight(34)
        self.btn_refresh.clicked.connect(self.refresh)
        search_row.addWidget(self.btn_refresh)

        self.btn_export = QPushButton("Export Data")
        T.set_button_class(self.btn_export, "primary")
        self.btn_export.setFixedHeight(34)
        self.btn_export.clicked.connect(self._export_data)
        search_row.addWidget(self.btn_export)

        fl.addLayout(search_row)

        # Filter Row
        filter_row = QHBoxLayout()
        filter_row.setSpacing(10)

        srv_lbl = QLabel("SERVER FILTERS:")
        srv_lbl.setFont(T.get_font(10.5, bold=True))
        srv_lbl.setStyleSheet(f"color: {T.NAVY_900};")
        filter_row.addWidget(srv_lbl)

        self.combo_format = QComboBox()
        self.combo_format.addItems([
            "All Formats", "CEF", "LEEF", "Syslog", "JSON", "XML", "Fortinet KV", "W3C", "Unknown (Auto-Learn)"
        ])
        self.combo_format.setFixedHeight(30)
        filter_row.addWidget(self.combo_format)

        self.combo_cat = QComboBox()
        self.combo_cat.addItems(["All Categories", "network", "firewall", "auth", "web", "ids", "system", "other"])
        self.combo_cat.setFixedHeight(30)
        filter_row.addWidget(self.combo_cat)

        self.combo_sev = QComboBox()
        self.combo_sev.addItems(["Min Severity: Any", "Low (1+)", "Medium (4+)", "High (7+)", "Critical (9+)"])
        self.combo_sev.setFixedHeight(30)
        filter_row.addWidget(self.combo_sev)

        self.ip_filter = QLineEdit()
        self.ip_filter.setPlaceholderText("Filter Source IP...")
        self.ip_filter.setFixedHeight(30)
        self.ip_filter.setFixedWidth(140)
        filter_row.addWidget(self.ip_filter)

        self.btn_apply = QPushButton("Apply")
        self.btn_apply.setProperty("btnClass", "secondary")
        self.btn_apply.setFixedHeight(30)
        self.btn_apply.clicked.connect(self._apply_filters)
        filter_row.addWidget(self.btn_apply)

        self.btn_reset = QPushButton("Reset")
        self.btn_reset.setProperty("btnClass", "outline")
        self.btn_reset.setFixedHeight(30)
        self.btn_reset.clicked.connect(self._reset_filters)
        filter_row.addWidget(self.btn_reset)

        self.combo_limit = QComboBox()
        self.combo_limit.addItems([
            "100 Rows", "250 Rows", "500 Rows", "1,000 Rows", "5,000 Rows", "10,000 Rows"
        ])
        self.combo_limit.setFixedHeight(30)
        self.combo_limit.currentIndexChanged.connect(self.refresh)
        filter_row.addWidget(self.combo_limit)

        filter_row.addStretch()
        fl.addLayout(filter_row)

        # Sort badge row
        sort_row = QHBoxLayout()
        sort_pill = PillBadge("SORT: INGESTION TIME (NEWEST FIRST)")
        sort_row.addWidget(sort_pill)
        self.lbl_count = QLabel("Displaying 0 normalized events")
        self.lbl_count.setFont(T.get_font(11))
        self.lbl_count.setStyleSheet(f"color: {T.SLATE_600};")
        sort_row.addWidget(self.lbl_count)
        sort_row.addStretch()
        fl.addLayout(sort_row)

        main_layout.addWidget(filter_card)

        # ── Splitter: Event Table on Top/Left, Detail Drawer on Right ──
        self.splitter = QSplitter(Qt.Orientation.Horizontal)

        # Table
        self.table = QTableView()
        self.model = EventTableModel()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.clicked.connect(self._on_row_clicked)

        # Attach item delegates for colored badges, pills, and typography
        self.table.setItemDelegateForColumn(0, MonoTextDelegate(self.table))
        self.table.setItemDelegateForColumn(1, SeverityBadgeDelegate(self.table))
        self.table.setItemDelegateForColumn(2, FormatPillDelegate(self.table))
        self.table.setItemDelegateForColumn(4, CategoryDelegate(self.table))
        self.table.setItemDelegateForColumn(6, MonoTextDelegate(self.table))
        self.table.setItemDelegateForColumn(7, MonoTextDelegate(self.table))
        self.table.setItemDelegateForColumn(8, MonoTextDelegate(self.table))
        self.table.setItemDelegateForColumn(9, MonoTextDelegate(self.table))
        self.table.setItemDelegateForColumn(10, MonoTextDelegate(self.table))

        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        self.table.setColumnWidth(0, 210)  # TIMESTAMP
        self.table.setColumnWidth(1, 55)   # SEV
        self.table.setColumnWidth(2, 80)   # FORMAT
        self.table.setColumnWidth(3, 80)   # PARSED
        self.table.setColumnWidth(4, 130)  # CATEGORY
        self.table.setColumnWidth(5, 95)   # ACTION
        self.table.setColumnWidth(6, 155)  # SOURCE IP
        self.table.setColumnWidth(7, 170)  # DESTINATION IP
        self.table.setColumnWidth(8, 85)   # PROTOCOL
        self.table.setColumnWidth(9, 85)   # PARSER
        self.table.setColumnWidth(10, 100)  # EVIDENCE

        self.splitter.addWidget(self.table)

        # Detail Drawer
        self.drawer = QFrame()
        self.drawer.setStyleSheet(f"""
            QFrame {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 16px;
            }}
        """)
        self.drawer.setFixedWidth(420)
        self.drawer.setVisible(False)

        dl = QVBoxLayout(self.drawer)
        dl.setContentsMargins(14, 14, 14, 14)
        dl.setSpacing(10)

        dh = QHBoxLayout()
        dt = QLabel("Event Detail Inspector")
        dt.setFont(T.get_font(13.5, bold=True))
        dt.setStyleSheet(f"color: {T.NAVY_900};")
        dh.addWidget(dt)
        dh.addStretch()

        close_btn = QPushButton("✕")
        close_btn.setFixedSize(24, 24)
        close_btn.clicked.connect(lambda: self.drawer.setVisible(False))
        dh.addWidget(close_btn)
        dl.addLayout(dh)

        self.drawer_text = QTextEdit()
        self.drawer_text.setReadOnly(True)
        self.drawer_text.setFont(T.get_font(11, mono=True))
        dl.addWidget(self.drawer_text)

        copy_btn = QPushButton("Copy Normalized JSON")
        copy_btn.setProperty("btnClass", "secondary")
        copy_btn.clicked.connect(self._copy_drawer)
        dl.addWidget(copy_btn)

        self.splitter.addWidget(self.drawer)
        self.drawer.setVisible(False)
        main_layout.addWidget(self.splitter, 1)

        self._is_paused = False
        self.refresh()

    def _toggle_pause(self):
        self._is_paused = not self._is_paused
        self.btn_pause.setText("▶ Resume Live View" if self._is_paused else "Pause Live View")

    def _get_limit(self) -> int:
        if not hasattr(self, "combo_limit"):
            return 100
        txt = self.combo_limit.currentText().replace(",", "")
        try:
            return int(txt.split()[0])
        except Exception:
            return 100

    def _on_events_loaded(self, events: list[dict]):
        # Only reload model if events actually changed to prevent table flicker and selection disruption
        new_ids = [e.get("event_id") for e in events]
        if getattr(self, "_last_event_ids", None) == new_ids:
            return
        self._last_event_ids = new_ids

        self.model.set_events(events)
        if hasattr(self, "lbl_count"):
            self.lbl_count.setText(f"Displaying {len(events):,} normalized events")

    def refresh(self):
        if getattr(self, "_is_paused", False):
            return
        query = self.search_input.text().strip()
        if query:
            self._apply_search()
            return
        if (self.combo_format.currentIndex() > 0 or 
            self.combo_cat.currentIndex() > 0 or 
            self.combo_sev.currentIndex() > 0 or 
            self.ip_filter.text().strip()):
            self._apply_filters()
            return
        lim = self._get_limit()
        worker = WorkerRunnable(self.service.query_events, limit=lim)
        worker.signals.result.connect(self._on_events_loaded)
        self.threadpool.start(worker)

    def set_search_query(self, query: str):
        self.search_input.setText(query)
        self._apply_search()

    def _apply_search(self):
        query = self.search_input.text().strip()
        if not query:
            self.refresh()
            return
        lim = self._get_limit()
        worker = WorkerRunnable(self.service.search_events, query=query, limit=lim)
        worker.signals.result.connect(self._on_events_loaded)
        self.threadpool.start(worker)

    def _apply_filters(self):
        filters = {}
        fmt = self.combo_format.currentText()
        if fmt != "All Formats":
            if "unknown" in fmt.lower():
                filters["raw_format"] = "raw_fallback"
            elif "kv" in fmt.lower():
                filters["raw_format"] = "kv"
            else:
                filters["raw_format"] = fmt.lower()
        cat = self.combo_cat.currentText()
        if cat != "All Categories":
            filters["category"] = cat
        
        sev = self.combo_sev.currentText()
        if "1+" in sev:
            filters["severity_min"] = 1
        elif "4+" in sev:
            filters["severity_min"] = 4
        elif "7+" in sev:
            filters["severity_min"] = 7
        elif "9+" in sev:
            filters["severity_min"] = 9

        ip = self.ip_filter.text().strip()
        if ip:
            filters["source_ip"] = ip

        lim = self._get_limit()
        worker = WorkerRunnable(self.service.query_events, filters=filters, limit=lim)
        worker.signals.result.connect(self._on_events_loaded)
        self.threadpool.start(worker)

    def _reset_filters(self):
        self.search_input.clear()
        self.combo_format.setCurrentIndex(0)
        self.combo_cat.setCurrentIndex(0)
        self.combo_sev.setCurrentIndex(0)
        self.ip_filter.clear()
        if hasattr(self, "combo_limit"):
            self.combo_limit.setCurrentIndex(0)
        self.refresh()

    def _on_row_clicked(self, index: QModelIndex):
        event = self.model.get_event(index.row())
        if event:
            self.drawer_text.setPlainText(json.dumps(event, indent=2, default=str))
            self.drawer.setVisible(True)

    def _copy_drawer(self):
        text = self.drawer_text.toPlainText()
        if text:
            QApplication.clipboard().setText(text)

    def _export_data(self):
        from PySide6.QtWidgets import QFileDialog
        out_file, _ = QFileDialog.getSaveFileName(
            self, "Export Security Events", "ulpf_events_export.json",
            "JSON Files (*.json);;CSV Files (*.csv);;All Files (*)"
        )
        if not out_file:
            return
        if out_file.endswith(".csv"):
            res = self.service.export_events_csv(out_file)
        else:
            res = self.service.export_events_json(out_file)
        if res.get("success"):
            self.drawer_text.setPlainText(f"Exported {res.get('count', 0)} events successfully to:\n{out_file}")
        else:
            self.drawer_text.setPlainText(f"Export error:\n{res.get('error')}")
        self.drawer.setVisible(True)
