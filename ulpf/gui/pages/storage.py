"""
ULPF Storage Page
===================
Shows real storage backend information from actual database queries.
"""
from __future__ import annotations

import os
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QFileDialog,
)

from ulpf.gui import theme as T
from ulpf.gui.widgets import PageHeader, SectionCard, MetricCard, KeyValueRow, StatusBadge
from ulpf.gui.service import ULPFService


class StoragePage(QWidget):
    def __init__(self, service: ULPFService, parent=None):
        super().__init__(parent)
        self.service = service

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header = PageHeader("Storage", "Database backend information")
        btn = QPushButton("Refresh")
        btn.setProperty("cssClass", "secondary")
        btn.clicked.connect(self.refresh)
        header.add_action(btn)
        layout.addWidget(header)

        # Metric cards
        cards = QHBoxLayout()
        self.card_events = MetricCard("Total Events", "0", "", T.BLUE_600)
        self.card_size = MetricCard("Database Size", "0 MB", "", T.NAVY_700)
        self.card_health = MetricCard("Health", "—", "", T.SUCCESS)
        cards.addWidget(self.card_events)
        cards.addWidget(self.card_size)
        cards.addWidget(self.card_health)
        layout.addLayout(cards)

        # Info
        info_card = SectionCard("Storage Details")
        il = info_card.content_layout()

        self.kv_backend = KeyValueRow("Backend", "DuckDB")
        self.kv_path = KeyValueRow("Path", "—")
        self.kv_status = KeyValueRow("Status", "—")

        self.status_badge = StatusBadge("info")

        il.addWidget(self.kv_backend)
        il.addWidget(self.kv_path)
        il.addWidget(self.kv_status)
        il.addWidget(self.status_badge)

        layout.addWidget(info_card)

        # Export
        export_card = SectionCard("Data Export")
        el = export_card.content_layout()

        btn_row = QHBoxLayout()
        btn_json = QPushButton("Export JSON")
        btn_json.clicked.connect(self._export_json)
        btn_csv = QPushButton("Export CSV")
        btn_csv.clicked.connect(self._export_csv)
        btn_row.addWidget(btn_json)
        btn_row.addWidget(btn_csv)
        btn_row.addStretch()
        el.addLayout(btn_row)

        self.export_result = QLabel("")
        self.export_result.setFont(T.get_font(T.FONT_SIZE_META))
        self.export_result.setStyleSheet(f"color: {T.SLATE_400}; border: none;")
        el.addWidget(self.export_result)

        layout.addWidget(export_card)

        # Maintenance
        maint_card = SectionCard("Database Maintenance")
        ml = maint_card.content_layout()

        m_btn_row = QHBoxLayout()
        btn_purge_fallback = QPushButton("Purge Raw Fallback Logs")
        btn_purge_fallback.setStyleSheet(f"""
            QPushButton {{
                background-color: {T.WHITE};
                border: 1px solid #DC2626;
                color: #DC2626;
                border-radius: {T.BORDER_RADIUS_SM}px;
                padding: 6px 14px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: #FEF2F2;
            }}
        """)
        btn_purge_fallback.clicked.connect(self._purge_fallback)

        btn_reset_all = QPushButton("Reset All Database Events")
        btn_reset_all.setStyleSheet(f"""
            QPushButton {{
                background-color: {T.WHITE};
                border: 1px solid {T.SLATE_400};
                color: {T.SLATE_700};
                border-radius: {T.BORDER_RADIUS_SM}px;
                padding: 6px 14px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {T.SLATE_100};
            }}
        """)
        btn_reset_all.clicked.connect(self._reset_all)

        m_btn_row.addWidget(btn_purge_fallback)
        m_btn_row.addWidget(btn_reset_all)
        m_btn_row.addStretch()
        ml.addLayout(m_btn_row)

        self.maint_result = QLabel("")
        self.maint_result.setFont(T.get_font(T.FONT_SIZE_META))
        self.maint_result.setStyleSheet(f"color: {T.SLATE_500}; border: none;")
        ml.addWidget(self.maint_result)

        layout.addWidget(maint_card)
        layout.addStretch()

    def _purge_fallback(self):
        count = self.service.purge_raw_fallback_events()
        self.maint_result.setText(f"✓ Purged {count:,} stale raw fallback events from database.")
        self.refresh()

    def _reset_all(self):
        self.service.reset_database()
        self.maint_result.setText("✓ Database reset: all events and anomalies cleared.")
        self.refresh()

    def refresh(self):
        info = self.service.get_storage_info()
        self.card_events.set_value(f"{info.get('total_events', 0):,}")
        self.card_size.set_value(f"{info.get('size_mb', 0):.2f} MB")
        healthy = info.get("healthy", False)
        self.card_health.set_value("Healthy" if healthy else "Unavailable")
        self.kv_path.set_value(info.get("path", ""))
        self.kv_status.set_value("Connected" if healthy else "Disconnected")
        self.status_badge.set_status("healthy" if healthy else "error")

    def _export_json(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Events as JSON", "events.json", "JSON (*.json)"
        )
        if path:
            result = self.service.export_events_json(path)
            if result.get("success"):
                self.export_result.setText(
                    f"✓ Exported {result['count']} events to {path}"
                )
            else:
                self.export_result.setText(f"✗ {result.get('error', 'Failed')}")

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Events as CSV", "events.csv", "CSV (*.csv)"
        )
        if path:
            result = self.service.export_events_csv(path)
            if result.get("success"):
                self.export_result.setText(
                    f"✓ Exported {result['count']} events to {path}"
                )
            else:
                self.export_result.setText(f"✗ {result.get('error', 'Failed')}")

