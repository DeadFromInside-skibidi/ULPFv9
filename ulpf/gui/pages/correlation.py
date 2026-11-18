"""
ULPF Correlation Page
=======================
Pixel-faithful reproduction of the Event Correlation engine
from reference photo WhatsApp Image 2026-09-27 at 23.56.42.jpeg.
"""
from __future__ import annotations

import json
from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QComboBox, QSpinBox, QLineEdit, QFrame, QTextEdit,
)

from ulpf.gui import theme as T
from ulpf.gui.widgets import SectionCard, EmptyState, VectorIcon
from ulpf.gui.service import ULPFService
from ulpf.gui.workers.background import ProcessingWorker


class CorrelationPage(QWidget):
    """Institutional Event Correlation Page."""

    def __init__(self, service: ULPFService, parent=None):
        super().__init__(parent)
        self.service = service
        self.threadpool = QThreadPool.globalInstance()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        # ── Card 1: Multi-Source Correlation Config ──
        card1 = QFrame()
        card1.setObjectName("card1")
        card1.setStyleSheet(f"""
            #card1 {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 18px 22px;
            }}
        """)
        c1l = QVBoxLayout(card1)
        c1l.setContentsMargins(18, 16, 18, 16)
        c1l.setSpacing(14)

        # Header row with icon
        top_row = QHBoxLayout()
        top_row.setSpacing(16)

        icon_lbl = VectorIcon("nodes", 36, color=T.NAVY_900)
        top_row.addWidget(icon_lbl)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)

        t_row = QHBoxLayout()
        st_title = QLabel("Multi-Source Event Correlation Engine")
        st_title.setFont(T.get_font(15, bold=True))
        st_title.setStyleSheet(f"color: {T.NAVY_900};")
        t_row.addWidget(st_title)
        t_row.addStretch()

        dispatch_lbl = QLabel("Temporal & Indicator Clustering (POST /api/v1/correlate)")
        dispatch_lbl.setFont(T.get_font(11))
        dispatch_lbl.setStyleSheet(f"color: {T.SLATE_400};")
        t_row.addWidget(dispatch_lbl)
        title_col.addLayout(t_row)

        desc = QLabel("Correlates heterogeneous events based on shared indicators (source/dest IPs, user accounts, sessions) and temporal proximity within configurable sliding time windows.")
        desc.setFont(T.get_font(12))
        desc.setStyleSheet(f"color: {T.SLATE_600};")
        desc.setWordWrap(True)
        title_col.addWidget(desc)

        top_row.addLayout(title_col)
        c1l.addLayout(top_row)

        # Controls row
        ctrl_row = QHBoxLayout()
        ctrl_row.setSpacing(14)

        # Time window
        tw_col = QVBoxLayout()
        tw_lbl = QLabel("TIME WINDOW")
        tw_lbl.setFont(T.get_font(10.5, bold=True))
        tw_lbl.setStyleSheet(f"color: {T.SLATE_600};")
        tw_col.addWidget(tw_lbl)

        self.window_combo = QComboBox()
        self.window_combo.addItems(["60 Seconds (Default)", "120 Seconds", "300 Seconds", "600 Seconds"])
        self.window_combo.setFixedHeight(32)
        tw_col.addWidget(self.window_combo)
        ctrl_row.addLayout(tw_col)

        # Limit
        lim_col = QVBoxLayout()
        lim_lbl = QLabel("EVENT DATASET LIMIT")
        lim_lbl.setFont(T.get_font(10.5, bold=True))
        lim_lbl.setStyleSheet(f"color: {T.SLATE_600};")
        lim_col.addWidget(lim_lbl)

        self.limit_spin = QSpinBox()
        self.limit_spin.setRange(10, 5000)
        self.limit_spin.setValue(100)
        self.limit_spin.setFixedHeight(32)
        lim_col.addWidget(self.limit_spin)
        ctrl_row.addLayout(lim_col)

        # Target event IDs
        id_col = QVBoxLayout()
        id_lbl = QLabel("OPTIONAL TARGET EVENT IDS")
        id_lbl.setFont(T.get_font(10.5, bold=True))
        id_lbl.setStyleSheet(f"color: {T.SLATE_600};")
        id_col.addWidget(id_lbl)

        self.id_input = QLineEdit()
        self.id_input.setPlaceholderText("Comma-separated IDs (leave blank for latest events)")
        self.id_input.setFixedHeight(32)
        id_col.addWidget(self.id_input)
        ctrl_row.addLayout(id_col, 1)

        c1l.addLayout(ctrl_row)

        # Action button row
        act_row = QHBoxLayout()
        act_row.addStretch()

        self.btn_run = QPushButton("Run Event Correlation")
        T.set_button_class(self.btn_run, "primary")
        self.btn_run.setFixedHeight(34)
        self.btn_run.clicked.connect(self._run_correlation)
        act_row.addWidget(self.btn_run)
        c1l.addLayout(act_row)

        layout.addWidget(card1)

        # ── Card 2: Results / Empty State ──
        self.card2 = QFrame()
        self.card2.setObjectName("card2")
        self.card2.setStyleSheet(f"""
            #card2 {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 24px;
            }}
        """)
        self.c2l = QVBoxLayout(self.card2)
        self.c2l.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.empty_state = EmptyState(
            "CORRELATION INVESTIGATION READY",
            "Click \"Run Event Correlation\" to cluster recent security events by shared indicators and kill-chain stages.",
            icon_char="nodes"
        )
        self.c2l.addWidget(self.empty_state)

                # Prominent trigger button directly inside Card 2
        self.btn_run_card2 = QPushButton("▶ Run Event Correlation")
        T.set_button_class(self.btn_run_card2, "primary")
        self.btn_run_card2.setFixedSize(220, 38)
        self.btn_run_card2.setStyleSheet(f"""
            QPushButton {{
                background-color: {T.NAVY_800};
                color: {T.WHITE};
                border: 1px solid {T.NAVY_900};
                border-radius: 6px;
                font-weight: bold;
                font-size: 13px;
                padding: 6px 16px;
            }}
            QPushButton:hover {{
                background-color: {T.NAVY_700};
            }}
            QPushButton:pressed {{
                background-color: {T.NAVY_900};
            }}
            QPushButton:disabled {{
                background-color: #E2E8F0;
                color: #94A3B8;
                border: 1px solid #CBD5E1;
            }}
        """)
        self.btn_run_card2.clicked.connect(self._run_correlation)
        self.c2l.addWidget(self.btn_run_card2, alignment=Qt.AlignmentFlag.AlignCenter)

        # Output box for results
        self.results_box = QTextEdit()
        self.results_box.setReadOnly(True)
        self.results_box.setFont(T.get_font(11, mono=True))
        self.results_box.setMinimumHeight(300)
        self.results_box.setStyleSheet(f"""
            QTextEdit {{
                background-color: {T.GREY_100};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 12px;
                color: {T.NAVY_900};
            }}
        """)
        self.results_box.setVisible(False)
        self.c2l.addWidget(self.results_box)

        layout.addWidget(self.card2)
        layout.addStretch()

    def _run_correlation(self):
        self.btn_run.setEnabled(False)
        self.btn_run_card2.setEnabled(False)
        limit = self.limit_spin.value()

        # Parse selected time window (e.g. "60 Seconds (Default)" -> 60.0)
        w_text = self.window_combo.currentText()
        try:
            window_sec = float(w_text.split()[0])
        except Exception:
            window_sec = 60.0

        # Parse target event IDs if provided
        id_str = self.id_input.text().strip()
        target_ids = [x.strip() for x in id_str.split(",") if x.strip()] if id_str else None

        def _on_finish():
            self.btn_run.setEnabled(True)
            self.btn_run_card2.setEnabled(True)

        worker = ProcessingWorker(self.service.correlate, limit=limit, window=window_sec, target_ids=target_ids)
        worker.signals.result.connect(self._on_result)
        worker.signals.finished.connect(_on_finish)
        self.threadpool.start(worker)

    def _on_result(self, groups: list[dict]):
        from datetime import datetime
        now_str = datetime.now().strftime("%H:%M:%S")
        if groups:
            self.empty_state.setVisible(False)
            self.btn_run_card2.setVisible(False)
            summary_header = (
                f"● LIVE CORRELATION STREAM: ACTIVE (Sync: {now_str})\n"
                f"=== {len(groups)} IDENTIFIED ATTACK KILL-CHAIN / INCIDENT CLUSTERS ===\n\n"
            )
            summaries = []
            for i, g in enumerate(groups, 1):
                stages = ", ".join(g.get("kill_chain_stages", [])) or "Reconnaissance / Lateral Movement"
                risk = g.get("risk_score", 0.0)
                summaries.append(
                    f"Cluster #{i} [{g.get('correlation_id', '')}] • Risk: {risk:.1f}/10 • Stages: [{stages}]\n"
                    f"  {g.get('summary', '')}"
                )
            full_text = summary_header + "\n\n".join(summaries) + "\n\n=== CLUSTER DETAILS (JSON) ===\n" + json.dumps(groups, indent=2, default=str)
            self.results_box.setPlainText(full_text)
            self.results_box.setVisible(True)
        else:
            total_events = self.service.get_stats().get("total_events", 0)
            if total_events > 0:
                self.empty_state.setVisible(False)
                self.btn_run_card2.setVisible(False)
                self.results_box.setPlainText(
                    f"● LIVE CORRELATION STREAM: ACTIVE (Sync: {now_str})\n"
                    f"Evaluated sliding window over latest events ({total_events:,} events stored in DuckDB).\n"
                    f"No multi-event indicator intersection (shared IPs, subnets, users) found in current window.\n"
                    f"Engine continuously correlates incoming live traffic..."
                )
                self.results_box.setVisible(True)
            else:
                self.empty_state.setVisible(True)
                self.btn_run_card2.setVisible(True)
                self.results_box.setVisible(False)

    def refresh(self):
        """Periodic sync callback to auto-refresh correlation when live events arrive."""
        cached = getattr(self.service, "_cached_correlation_groups", None)
        if cached:
            self._on_result(cached)

        import time
        now = time.time()
        if getattr(self, "_last_auto_correlate", 0) + 3.0 > now:
            return
        self._last_auto_correlate = now

        if not self.btn_run.isEnabled():
            return

        w_text = self.window_combo.currentText()
        try:
            window_sec = float(w_text.split()[0])
        except Exception:
            window_sec = 60.0
        limit = self.limit_spin.value()

        def _bg_correlate():
            return self.service.correlate(limit=limit, window=window_sec)

        worker = ProcessingWorker(_bg_correlate)
        worker.signals.result.connect(self._on_result)
        self.threadpool.start(worker)

