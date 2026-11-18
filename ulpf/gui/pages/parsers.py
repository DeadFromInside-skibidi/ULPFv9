"""
ULPF Parsers Page
===================
Pixel-faithful reproduction of the Parsers & Rulesets studio
from reference photo WhatsApp Image 2026-09-27 at 23.56.40.jpeg.
"""
from __future__ import annotations

import json
from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTextEdit, QTableView, QHeaderView, QComboBox, QFrame,
    QAbstractItemView,
)

from ulpf.gui import theme as T
from ulpf.gui.widgets import SectionCard, StatusBadge, PillBadge, FormatPillDelegate, MonoTextDelegate, VectorIcon
from ulpf.gui.service import ULPFService


class ParserInventoryModel(QAbstractTableModel):
    HEADERS = ["PARSER ID", "PARSER NAME", "SUPPORTED FORMATS", "VERSION", "DESCRIPTION"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._parsers: list[dict] = []

    def set_parsers(self, parsers: list[dict]):
        self.beginResetModel()
        self._parsers = parsers
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self._parsers)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        p = self._parsers[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return str(p.get("parser_id") or p.get("format_name", "")).lower()
            elif col == 1:
                return str(p.get("parser_name") or f"{p.get('format_name', '').upper()} Parser")
            elif col == 2:
                fmts = p.get("supported_formats")
                if isinstance(fmts, list):
                    return ", ".join(f.upper() for f in fmts)
                return str(p.get("format_name", "")).upper()
            elif col == 3:
                return str(p.get("version", "1.0.0"))
            elif col == 4:
                return p.get("description", f"Standard parser for {p.get('parser_id', '')}")
        elif role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (2, 3):
                return Qt.AlignmentFlag.AlignCenter
        return None


class ParsersPage(QWidget):
    """Institutional Parsers & Rulesets Page."""

    SAMPLE_LOGS = {
        "CEF Firewall": "CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|drop|Log Drop|Low|src=192.168.1.100 dst=10.0.0.1 proto=tcp",
        "Syslog RFC 5424": "<134>1 2026-09-27T18:05:31.517Z router1 myapp 1234 ID47 [exampleSDID@32473 iut=\"3\"] User authentication failed",
        "LEEF IDS": "LEEF:2.0|IBM|QRadar|7.4.0|12345|src=10.0.1.50\tdst=192.168.1.1\tproto=TCP\tseverity=7",
        "JSON WAF": '{"timestamp":"2026-09-27T18:05:31.517Z","client_ip":"203.0.113.15","rule_id":"942100","action":"BLOCK","message":"SQL Injection Detected"}',
        "Fortinet KV": "date=2026-09-27 time=18:05:31 devname=FGT60D srcip=192.168.10.5 dstip=198.51.100.20 action=deny proto=6",
    }

    def __init__(self, service: ULPFService, parent=None):
        super().__init__(parent)
        self.service = service

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        # ── Card 1: Interactive Parser Testing Studio ──
        test_card = QFrame()
        test_card.setObjectName("testCardFrame")
        test_card.setStyleSheet(f"""
            #testCardFrame {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
            }}
        """)
        tl = QVBoxLayout(test_card)
        tl.setContentsMargins(18, 16, 18, 16)
        tl.setSpacing(12)

        # Header with </> Icon
        top_row = QHBoxLayout()
        top_row.setSpacing(16)

        icon_lbl = VectorIcon("code", 36, color=T.NAVY_900)
        top_row.addWidget(icon_lbl)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)

        t_row = QHBoxLayout()
        st_title = QLabel("Interactive Parser Testing Studio")
        st_title.setFont(T.get_font(15, bold=True))
        st_title.setStyleSheet(f"color: {T.NAVY_900};")
        t_row.addWidget(st_title)
        t_row.addStretch()

        dispatch_lbl = QLabel("Direct Engine Dispatch Tester (POST /api/v1/parsers/test)")
        dispatch_lbl.setFont(T.get_font(11))
        dispatch_lbl.setStyleSheet(f"color: {T.SLATE_400};")
        t_row.addWidget(dispatch_lbl)
        title_col.addLayout(t_row)

        desc = QLabel("Paste a single raw log line to test automatic format detection, parsing logic, and schema normalization in real-time.")
        desc.setFont(T.get_font(12))
        desc.setStyleSheet(f"color: {T.SLATE_600};")
        title_col.addWidget(desc)

        top_row.addLayout(title_col)
        tl.addLayout(top_row)

        # Input label + Presets combo
        input_head = QHBoxLayout()
        in_lbl = QLabel("RAW LOG LINE INPUT")
        in_lbl.setFont(T.get_font(10.5, bold=True))
        in_lbl.setStyleSheet(f"color: {T.SLATE_600};")
        input_head.addWidget(in_lbl)
        input_head.addStretch()

        preset_lbl = QLabel("Presets:")
        preset_lbl.setFont(T.get_font(11))
        preset_lbl.setStyleSheet(f"color: {T.SLATE_400};")
        input_head.addWidget(preset_lbl)

        self.preset_combo = QComboBox()
        self.preset_combo.addItem("Load Sample Log...", None)
        for name in self.SAMPLE_LOGS:
            self.preset_combo.addItem(name, name)
        self.preset_combo.setFixedWidth(160)
        self.preset_combo.currentIndexChanged.connect(self._on_preset_selected)
        input_head.addWidget(self.preset_combo)
        tl.addLayout(input_head)

        # Raw log line text area
        self.log_input = QTextEdit()
        self.log_input.setPlaceholderText("Paste raw security log line here (e.g. CEF:0|Vendor|Product|... or <134>1 ...)")
        self.log_input.setFont(T.get_font(12, mono=True))
        self.log_input.setFixedHeight(75)
        tl.addWidget(self.log_input)

        # Action Buttons
        btn_row = QHBoxLayout()
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setFixedWidth(80)
        self.clear_btn.setFixedHeight(32)
        self.clear_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {T.WHITE};
                color: {T.NAVY_900};
                border: 1px solid {T.SLATE_300};
                border-radius: {T.BORDER_RADIUS_SM}px;
                font-size: 12px;
                font-weight: 600;
                padding: 4px 12px;
            }}
            QPushButton:hover {{
                background-color: {T.GREY_100};
            }}
            QPushButton:pressed {{
                background-color: {T.GREY_200};
            }}
        """)
        self.clear_btn.clicked.connect(self.log_input.clear)
        btn_row.addWidget(self.clear_btn)
        btn_row.addStretch()

        self.test_btn = QPushButton("Test Parser")
        self.test_btn.setFixedWidth(130)
        self.test_btn.setFixedHeight(32)
        self.test_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {T.NAVY_900};
                color: {T.WHITE};
                border: 1px solid {T.NAVY_900};
                border-radius: {T.BORDER_RADIUS_SM}px;
                font-size: 12px;
                font-weight: 700;
                padding: 4px 14px;
            }}
            QPushButton:hover {{
                background-color: {T.NAVY_800};
            }}
            QPushButton:pressed {{
                background-color: #0A1420;
            }}
            QPushButton:disabled {{
                background-color: #CBD5E1;
                color: #64748B;
                border: 1px solid #94A3B8;
            }}
        """)
        self.test_btn.clicked.connect(self._run_test)
        btn_row.addWidget(self.test_btn)
        tl.addLayout(btn_row)

        # Test Results View (hidden by default)
        self.results_box = QTextEdit()
        self.results_box.setReadOnly(True)
        self.results_box.setFont(T.get_font(11, mono=True))
        self.results_box.setFixedHeight(120)
        self.results_box.setVisible(False)
        tl.addWidget(self.results_box)

        layout.addWidget(test_card)

        # ── Card 2: Registered Parser Inventory ──
        inv_card = QFrame()
        inv_card.setObjectName("invCardFrame")
        inv_card.setStyleSheet(f"""
            #invCardFrame {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
            }}
        """)
        il = QVBoxLayout(inv_card)
        il.setContentsMargins(16, 14, 16, 14)
        il.setSpacing(12)

        inv_top = QHBoxLayout()
        inv_top.setSpacing(16)

        doc_icon = VectorIcon("document", 36, color=T.NAVY_900)
        inv_top.addWidget(doc_icon)

        title_lbl = QLabel("Registered\nParser\nInventory")
        title_lbl.setFont(T.get_font(13, bold=True))
        title_lbl.setStyleSheet(f"color: {T.NAVY_900}; border: none;")
        inv_top.addWidget(title_lbl)
        inv_top.addStretch()

        self.count_badge = StatusBadge("healthy", "8 ACTIVE PARSERS")
        inv_top.addWidget(self.count_badge)
        il.addLayout(inv_top)

        self.table = QTableView()
        self.model = ParserInventoryModel()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setFixedHeight(220)

        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)

        self.table.setItemDelegateForColumn(0, MonoTextDelegate(self.table))
        self.table.setItemDelegateForColumn(2, FormatPillDelegate(self.table))
        self.table.setItemDelegateForColumn(3, MonoTextDelegate(self.table))

        il.addWidget(self.table)
        layout.addWidget(inv_card)

        layout.addStretch()
        self.refresh()

    def refresh(self):
        parsers = self.service.list_parsers()
        self.model.set_parsers(parsers)
        self.count_badge.set_status("healthy", f"{len(parsers)} ACTIVE PARSERS")

    def _on_preset_selected(self, index: int):
        key = self.preset_combo.currentData()
        if key and key in self.SAMPLE_LOGS:
            self.log_input.setPlainText(self.SAMPLE_LOGS[key])

    def _run_test(self):
        line = self.log_input.toPlainText().strip()
        if not line:
            return
        res = self.service.test_parser(line)
        self.results_box.setPlainText(json.dumps(res, indent=2, default=str))
        self.results_box.setVisible(True)
