"""
ULPF System Overview Page
===========================
Pixel-faithful reproduction of the System Overview command center
from reference photo WhatsApp Image 2026-09-27 at 23.56.38.jpeg.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QTableView, QHeaderView, QAbstractItemView,
)

from ulpf.gui import theme as T
from ulpf.gui.widgets import (
    MetricCard, PillBadge, StatusBadge, SectionCard,
    SeverityHistogram, DistributionBar, KeyValueRow, SeverityPill, FormatBadge,
    SeverityBadgeDelegate, FormatPillDelegate, CategoryDelegate, MonoTextDelegate,
)
from ulpf.gui.service import ULPFService


# ── Recent Events Table Model ─────────────────────────────────────────

class RecentEventsModel(QAbstractTableModel):
    HEADERS = ["TIMESTAMP", "FORMAT", "PARSED", "CATEGORY", "ACTION", "SEVERITY", "SOURCE", "DESTINATION", "MESSAGE"]

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
                return str(ev.get("timestamp", ""))[:23] + " UTC" if ev.get("timestamp") else "—"
            elif col == 1:
                return str(ev.get("raw_format", "UNKNOWN")).upper()
            elif col == 2:
                fmt = str(ev.get("raw_format", "unknown")).lower()
                return "No" if fmt == "unknown" else "Yes"
            elif col == 3:
                return str(ev.get("category", "other"))
            elif col == 4:
                return str(ev.get("action", "other"))
            elif col == 5:
                return str(ev.get("severity", 0))
            elif col == 6:
                return ev.get("source", {}).get("ip") or ev.get("source_ip") or "—"
            elif col == 7:
                return ev.get("destination", {}).get("ip") or ev.get("destination_ip") or "—"
            elif col == 8:
                return (ev.get("message") or ev.get("raw_event") or "")[:80]
        elif role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (1, 2, 5):
                return Qt.AlignmentFlag.AlignCenter
        return None


# ── Overview Page ─────────────────────────────────────────────────────

class OverviewPage(QWidget):
    """Institutional System Overview Dashboard."""

    def __init__(self, service: ULPFService, parent=None):
        super().__init__(parent)
        self.service = service

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        # ── Row 1: 4 Metric Cards (No emoji icons, Card 2 with blue accent) ──
        metrics_row = QHBoxLayout()
        metrics_row.setSpacing(16)

        self.c_total = MetricCard(
            "TOTAL NORMALIZED EVENTS", "0",
            "Stored in DuckDB Columnar Store"
        )
        self.c_tput = MetricCard(
            "PIPELINE THROUGHPUT", "Ready",
            "100% Success Rate",
            accent_color=T.BLUE_600
        )
        self.c_anom = MetricCard(
            "STATISTICAL ANOMALIES", "0",
            "Z-score & Entropy Outliers"
        )
        self.c_fmts = MetricCard(
            "ACTIVE SOURCE FORMATS", "0",
            "Heterogeneous Formats Normalized"
        )

        metrics_row.addWidget(self.c_total)
        metrics_row.addWidget(self.c_tput)
        metrics_row.addWidget(self.c_anom)
        metrics_row.addWidget(self.c_fmts)
        layout.addLayout(metrics_row)

        # ── Row 2: Formats & Categories Distribution ──
        row2 = QHBoxLayout()
        row2.setSpacing(16)

        # Left: Events by Source Format
        self.fmt_badge = PillBadge("0 FORMATS")
        self.fmt_card = SectionCard("Events by Source Format", right_widget=self.fmt_badge)
        self.fmt_layout = self.fmt_card.content_layout()
        self.fmt_placeholder = QLabel("No format data available.")
        self.fmt_placeholder.setStyleSheet(f"color: {T.SLATE_400};")
        self.fmt_layout.addWidget(self.fmt_placeholder)
        row2.addWidget(self.fmt_card, 1)

        # Right: Events by Security Category
        self.cat_badge = PillBadge("0 CATEGORIES")
        self.cat_card = SectionCard("Events by Security Category", right_widget=self.cat_badge)
        self.cat_layout = self.cat_card.content_layout()
        self.cat_placeholder = QLabel("No category data available.")
        self.cat_placeholder.setStyleSheet(f"color: {T.SLATE_400};")
        self.cat_layout.addWidget(self.cat_placeholder)
        row2.addWidget(self.cat_card, 1)

        layout.addLayout(row2)

        # ── Row 3: Severity Distribution & Processing Engine Status ──
        row3 = QHBoxLayout()
        row3.setSpacing(16)

        # Left: Severity Distribution Histogram
        sev_meta = QLabel("Scale 0 (Unknown) to 10 (Critical)")
        sev_meta.setFont(T.get_font(11))
        sev_meta.setStyleSheet(f"color: {T.SLATE_400};")
        self.sev_card = SectionCard("Severity Distribution", right_widget=sev_meta)
        sl = self.sev_card.content_layout()
        self.histogram = SeverityHistogram()
        sl.addWidget(self.histogram)
        row3.addWidget(self.sev_card, 1)

        # Right: Processing Engine Status
        self.engine_badge = StatusBadge("operational", "OPERATIONAL")
        self.engine_card = SectionCard("Processing Engine Status", right_widget=self.engine_badge)
        el = self.engine_card.content_layout()

        self.kv_success = KeyValueRow("Pipeline Success Rate", "100% (Ready)")
        self.kv_threats = KeyValueRow("Known Threat IPs", "19 IP addresses tracked", mono=True)
        self.kv_listener = KeyValueRow("Network Listener", "Operated via CLI: python -m ulpf.main listen")
        self.kv_parsers = KeyValueRow("Active Parsers", "1 parsers active in this session")

        el.addWidget(self.kv_success)
        el.addWidget(self.kv_threats)
        el.addWidget(self.kv_listener)
        el.addWidget(self.kv_parsers)
        el.addStretch()
        row3.addWidget(self.engine_card, 1)

        layout.addLayout(row3)

        # ── Row 4: Recent Normalized Events (Latest 5) ──
        view_all_btn = QPushButton("View All in Event Explorer")
        view_all_btn.setProperty("btnClass", "outline")
        view_all_btn.setFixedHeight(28)
        view_all_btn.setMinimumWidth(190)
        view_all_btn.clicked.connect(self._go_to_explorer)

        self.events_card = SectionCard("Recent Normalized Events (Latest 5)", right_widget=view_all_btn)
        events_layout = self.events_card.content_layout()

        self.table = QTableView()
        self.model = RecentEventsModel()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setFixedHeight(190)

        self.table.setItemDelegateForColumn(0, MonoTextDelegate(self.table))
        self.table.setItemDelegateForColumn(1, FormatPillDelegate(self.table))
        self.table.setItemDelegateForColumn(3, CategoryDelegate(self.table))
        self.table.setItemDelegateForColumn(5, SeverityBadgeDelegate(self.table))
        self.table.setItemDelegateForColumn(6, MonoTextDelegate(self.table))
        self.table.setItemDelegateForColumn(7, MonoTextDelegate(self.table))

        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        self.table.setColumnWidth(0, 190)  # TIMESTAMP
        self.table.setColumnWidth(1, 80)   # FORMAT
        self.table.setColumnWidth(2, 60)   # PARSED
        self.table.setColumnWidth(3, 120)  # CATEGORY
        self.table.setColumnWidth(4, 90)   # ACTION
        self.table.setColumnWidth(5, 75)   # SEVERITY
        self.table.setColumnWidth(6, 140)  # SOURCE
        self.table.setColumnWidth(7, 140)  # DESTINATION

        events_layout.addWidget(self.table)
        layout.addWidget(self.events_card)

        self.refresh()

    def refresh(self):
        """Fetch actual data from the service layer."""
        stats = self.service.get_stats()
        total = stats.get("total_events", 0)

        self.c_total.set_value(f"{total:,}")

        # Ingestion metrics & Live Throughput
        metrics = self.service.metrics()
        success_rate = metrics.get("success_rate_pct", 100.0)
        live_eps = stats.get("live_eps", 0.0)
        if live_eps > 0:
            self.c_tput.set_value(f"{live_eps:,.0f} EPS")
            self.c_tput.set_subtitle(f"Live Stream Active • {success_rate:.0f}% Normal")
        else:
            self.c_tput.set_value("Active" if total > 0 else "Idle")
            self.c_tput.set_subtitle(f"{success_rate:.0f}% Success Rate")

        # Anomalies
        anomalies = self.service.get_anomalies(limit=10)
        self.c_anom.set_value(str(len(anomalies)))

        # Formats
        by_format = stats.get("by_format", {})
        fmt_count = len(by_format)
        self.c_fmts.set_value(str(fmt_count) if fmt_count > 0 else "0")
        self.fmt_badge.setText(f"{fmt_count} FORMATS")

        top_fmts = sorted(by_format.items(), key=lambda x: x[1], reverse=True)[:5] if total > 0 else []
        fmt_keys = [f[0] for f in top_fmts]
        if hasattr(self, "_fmt_bars") and list(self._fmt_bars.keys()) == fmt_keys and top_fmts:
            for fmt, count in top_fmts:
                self._fmt_bars[fmt].update_values(count, total)
        else:
            while self.fmt_layout.count() > 0:
                item = self.fmt_layout.takeAt(0)
                w = item.widget()
                if w:
                    w.setParent(None)
                    w.deleteLater()
            self._fmt_bars = {}
            if top_fmts:
                for fmt, count in top_fmts:
                    bar = DistributionBar(fmt.upper(), count, total, T.BLUE_600)
                    self._fmt_bars[fmt] = bar
                    self.fmt_layout.addWidget(bar)
            else:
                lbl = QLabel("No format data available.")
                lbl.setStyleSheet(f"color: {T.SLATE_400};")
                self.fmt_layout.addWidget(lbl)

        # Clear and repopulate category bars
        by_cat = stats.get("by_category", {})
        cat_count = len(by_cat)
        self.cat_badge.setText(f"{cat_count} CATEGORIES")

        top_cats = sorted(by_cat.items(), key=lambda x: x[1], reverse=True)[:5] if total > 0 else []
        cat_keys = [c[0] for c in top_cats]
        if hasattr(self, "_cat_bars") and list(self._cat_bars.keys()) == cat_keys and top_cats:
            for cat, count in top_cats:
                self._cat_bars[cat].update_values(count, total)
        else:
            while self.cat_layout.count() > 0:
                item = self.cat_layout.takeAt(0)
                w = item.widget()
                if w:
                    w.setParent(None)
                    w.deleteLater()
            self._cat_bars = {}
            if top_cats:
                for cat, count in top_cats:
                    bar = DistributionBar(cat, count, total, T.NAVY_800)
                    self._cat_bars[cat] = bar
                    self.cat_layout.addWidget(bar)
            else:
                lbl = QLabel("No category data available.")
                lbl.setStyleSheet(f"color: {T.SLATE_400};")
                self.cat_layout.addWidget(lbl)

        # Severity histogram
        by_sev = stats.get("by_severity", {})
        self.histogram.update_data(by_sev)

        # Health info
        health = self.service.health()
        is_healthy = health.get("status") == "healthy"
        self.engine_badge.set_status("operational" if is_healthy else "error", "OPERATIONAL" if is_healthy else "ERROR")
        parsed = metrics.get("events_successful", total)
        failed = metrics.get("events_failed", 0)
        self.kv_success.set_value(f"{success_rate:.0f}% ({parsed} parsed / {failed} failed)")

        # Dynamic Parsers and Threat Intelligence
        parsers = self.service.list_parsers()
        self.kv_parsers.set_value(f"{len(parsers)} parsers active in this session")

        try:
            from ulpf.intelligence.intel_db import get_intel_db
            ioc_count = len(get_intel_db()._ioc_keys)
            self.kv_threats.set_value(f"{ioc_count} threat indicators tracked")
        except Exception:
            self.kv_threats.set_value("Threat database active")

        # Network listener status
        l_stat = self.service.get_listener_status()
        if l_stat.get("running"):
            self.kv_listener.set_value(f"Active: {l_stat.get('host')}:{l_stat.get('port')} ({l_stat.get('proto')}) • {l_stat.get('packets')} pkts")
        else:
            self.kv_listener.set_value("Inactive • Configure in Ingestion Console")

        # Recent events
        events = self.service.query_events(limit=5)
        self.model.set_events(events)

    def _go_to_explorer(self):
        window = self.window()
        if hasattr(window, "navigate_to"):
            window.navigate_to("events")
