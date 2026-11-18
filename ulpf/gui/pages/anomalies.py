"""
ULPF Anomalies Page
=====================
Pixel-faithful reproduction of the Anomaly Center from reference
photo WhatsApp Image 2026-09-27 at 23.58.39.jpeg.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableView, QHeaderView, QFrame, QAbstractItemView,
)

from ulpf.gui import theme as T
from ulpf.gui.widgets import MetricCard, NoticeBanner, SectionCard, EmptyState
from ulpf.gui.service import ULPFService


class AnomalyTableModel(QAbstractTableModel):
    HEADERS = ["TIMESTAMP", "RISK ASSESSMENT", "ANOMALY TYPE", "STATISTICAL DESCRIPTION", "Z-SCORE", "ASSOCIATED EVENT"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._anomalies: list[dict] = []

    def set_anomalies(self, anomalies: list[dict]):
        self.beginResetModel()
        self._anomalies = anomalies
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self._anomalies)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        a = self._anomalies[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return str(a.get("detected_at", ""))[:19]
            elif col == 1:
                return str(a.get("risk", "MEDIUM")).upper()
            elif col == 2:
                return a.get("anomaly_type", "deviation")
            elif col == 3:
                return a.get("description", "")
            elif col == 4:
                z = a.get('z_score')
                return f"{z:.2f}" if z is not None else "—"
            elif col == 5:
                return str(a.get("event_id", ""))[:12]
        return None


class AnomaliesPage(QWidget):
    """Institutional Anomaly Center Page."""

    def __init__(self, service: ULPFService, parent=None):
        super().__init__(parent)
        self.service = service

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        # ── Row 1: 3 Metric Cards ──
        metrics_row = QHBoxLayout()
        metrics_row.setSpacing(16)

        self.c_outliers = MetricCard(
            "DETECTED OUTLIERS", "0",
            "0 Critical • 0 Warning / Elevated",
            accent_color=T.BLUE_600
        )
        self.c_baseline = MetricCard(
            "SEVERITY BASELINE (MEAN ± Σ)", "0.00 ± 0.00",
            "Samples: 0"
        )
        self.c_ips = MetricCard(
            "IP BEHAVIORAL PROFILE", "0",
            "0 new IP addresses recently observed"
        )

        metrics_row.addWidget(self.c_outliers)
        metrics_row.addWidget(self.c_baseline)
        metrics_row.addWidget(self.c_ips)
        layout.addLayout(metrics_row)

        # ── Row 2: Operational Notice Banner ──
        notice = NoticeBanner(
            "OPERATIONAL NOTICE: Statistical anomalies represent deviations from calculated rolling baseline averages "
            "(Z-score > 3.0 or Shannon entropy drops). Anomalies are flagged for analyst triage and do not constitute "
            "confirmed security breaches without corroborating indicators."
        )
        layout.addWidget(notice)

        # ── Row 3: Statistical Anomaly Registry ──
        self.btn_refresh = QPushButton("Refresh Baseline")
        self.btn_refresh.setProperty("btnClass", "outline")
        self.btn_refresh.setFixedHeight(28)
        self.btn_refresh.clicked.connect(self.refresh)

        self.card = SectionCard("Statistical Anomaly Registry (0 records)", right_widget=self.btn_refresh)
        cl = self.card.content_layout()

        self.table = QTableView()
        self.model = AnomalyTableModel()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setFixedHeight(34)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        self.table.setColumnWidth(0, 160)  # TIMESTAMP
        self.table.setColumnWidth(1, 140)  # RISK ASSESSMENT
        self.table.setColumnWidth(2, 160)  # ANOMALY TYPE
        self.table.setColumnWidth(3, 300)  # STATISTICAL DESCRIPTION
        self.table.setColumnWidth(4, 90)   # Z-SCORE
        self.table.setColumnWidth(5, 140)  # ASSOCIATED EVENT
        cl.addWidget(self.table)

        self.empty = EmptyState(
            "NO STATISTICAL ANOMALIES DETECTED",
            "Current traffic metrics adhere strictly within expected rolling distribution thresholds.",
            icon_char=""
        )
        cl.addWidget(self.empty)

        layout.addWidget(self.card)
        layout.addStretch()
        self.refresh()

    def refresh(self):
        anomalies = self.service.get_anomalies(limit=50)
        self.c_outliers.set_value(str(len(anomalies)))
        self.card.setTitle(f"Statistical Anomaly Registry ({len(anomalies)} records)")

        stats = self.service.get_stats()
        total = stats.get("total_events", 0)

        # Update baseline dynamically from real engine stats
        baseline = self.service.get_anomaly_baseline()
        sev_stats = baseline.get("severity", {})
        mean = sev_stats.get("mean", 0.0)
        std = sev_stats.get("std_dev", 0.0)
        samples = sev_stats.get("samples", total)

        self.c_baseline.set_value(f"{mean:.2f} ± {std:.2f}" if samples > 0 else "0.00 ± 0.00")
        self.c_baseline.set_subtitle(f"Samples: {samples}")

        known_ips = baseline.get("known_ips", 0)
        self.c_ips.set_value(str(known_ips))
        self.c_ips.set_subtitle(f"{known_ips} new IP addresses recently observed")

        if anomalies:
            self.empty.setVisible(False)
            self.model.set_anomalies(anomalies)
            self.table.setFixedHeight(220)
        else:
            self.table.setFixedHeight(34)
            self.empty.setVisible(True)

