"""
ULPF Auto-Learn Page
======================
Pixel-faithful reproduction of the Auto-Parser Generator studio
from reference photo WhatsApp Image 2026-09-27 at 23.56.41.jpeg.
"""
from __future__ import annotations

import json
from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTextEdit, QFrame, QProgressBar,
)

from ulpf.gui import theme as T
from ulpf.gui.widgets import SectionCard, PillBadge, WorkflowStepper, VectorIcon
from ulpf.gui.service import ULPFService
from ulpf.gui.workers.background import ProcessingWorker


class AutoLearnPage(QWidget):
    """Institutional Auto-Parser Generator Page."""

    # A proprietary format none of the built-in parsers recognise
    SAMPLE_PROPRIETARY = (
        "[2026-09-27 10:00:01] [AUTH] [WARN] Login failed for user jdoe from 192.168.1.50\n"
        "[2026-09-27 10:00:02] [AUTH] [WARN] Login failed for user jdoe from 192.168.1.50\n"
        "[2026-09-27 10:00:04] [AUTH] [INFO] Login succeeded for user admin from 10.0.0.1\n"
        "[2026-09-27 10:03:17] [AUTH] [WARN] Login failed for user svc_backup from 172.16.4.20"
    )

    def __init__(self, service: ULPFService, parent=None):
        super().__init__(parent)
        self.service = service
        self.threadpool = QThreadPool.globalInstance()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        # ── Stepper Header ──
        stepper = WorkflowStepper([
            "Input Logs", "Structure Analysis", "Field Identification",
            "Parser Generation", "Validation", "Saved"
        ], active_idx=0)
        layout.addWidget(stepper)

        # ── Card 1: Automated Parser Synthesis ──
        card = QFrame()
        card.setObjectName("autolearnCard")
        card.setStyleSheet(f"""
            #autolearnCard {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
            }}
        """)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(18, 16, 18, 16)
        cl.setSpacing(12)

        # Header with icon and badge
        top_row = QHBoxLayout()
        top_row.setSpacing(16)

        icon_lbl = VectorIcon("sunburst", 36, color=T.NAVY_900)
        top_row.addWidget(icon_lbl)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)

        t_row = QHBoxLayout()
        st_title = QLabel("Automated Parser Synthesis")
        st_title.setFont(T.get_font(15, bold=True))
        st_title.setStyleSheet(f"color: {T.NAVY_900};")
        t_row.addWidget(st_title)
        t_row.addStretch()

        badge = PillBadge("DETERMINISTIC REGEX / NATIVE MINER")
        t_row.addWidget(badge)
        title_col.addLayout(t_row)

        desc = QLabel("Paste 2 or more sample lines of a log format the built-in parsers do not recognise. ULPF detects the delimiter, separates constant structure from variable fields, infers types (timestamps, IPs, ports, users, severities), validates the generated parser against the samples, and activates it immediately.")
        desc.setFont(T.get_font(12))
        desc.setStyleSheet(f"color: {T.SLATE_600};")
        desc.setWordWrap(True)
        title_col.addWidget(desc)

        top_row.addLayout(title_col)
        cl.addLayout(top_row)

        # Input label and sample button
        in_row = QHBoxLayout()
        in_lbl = QLabel("SAMPLE LOG LINES (1 PER LINE)")
        in_lbl.setFont(T.get_font(10.5, bold=True))
        in_lbl.setStyleSheet(f"color: {T.SLATE_600};")
        in_row.addWidget(in_lbl)
        in_row.addStretch()

        self.btn_load_ingested = QPushButton("Load Ingested Unknown Logs")
        self.btn_load_ingested.setProperty("btnClass", "outline")
        self.btn_load_ingested.setFont(T.get_font(11))
        self.btn_load_ingested.setFixedHeight(26)
        self.btn_load_ingested.clicked.connect(self._load_ingested_unknown)
        in_row.addWidget(self.btn_load_ingested)

        self.btn_load_sample = QPushButton("Load Sample Proprietary Log")
        self.btn_load_sample.setProperty("btnClass", "outline")
        self.btn_load_sample.setFont(T.get_font(11))
        self.btn_load_sample.setFixedHeight(26)
        self.btn_load_sample.clicked.connect(lambda: self.sample_input.setPlainText(self.SAMPLE_PROPRIETARY))
        in_row.addWidget(self.btn_load_sample)
        cl.addLayout(in_row)

        # Sample input text area
        self.sample_input = QTextEdit()
        self.sample_input.setPlainText(self.SAMPLE_PROPRIETARY)
        self.sample_input.setFont(T.get_font(12, mono=True))
        self.sample_input.setFixedHeight(95)
        cl.addWidget(self.sample_input)

        # Action button row
        act_row = QHBoxLayout()
        act_row.addStretch()

        self.btn_run = QPushButton("Run Auto-Parser Generation")
        T.set_button_class(self.btn_run, "primary")
        self.btn_run.setFixedHeight(34)
        self.btn_run.clicked.connect(self._run_autolearn)
        act_row.addWidget(self.btn_run)
        cl.addLayout(act_row)

        # Result box
        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        self.result_box.setFont(T.get_font(11, mono=True))
        self.result_box.setFixedHeight(120)
        self.result_box.setVisible(False)
        cl.addWidget(self.result_box)

        layout.addWidget(card)

        # ── Card 2: Saved Auto-Learned Parser Configurations ──
        card2 = QFrame()
        card2.setStyleSheet(f"""
            QFrame {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 14px 18px;
            }}
        """)
        c2l = QVBoxLayout(card2)
        c2l.setContentsMargins(16, 14, 16, 14)
        c2l.setSpacing(12)

        c2_top = QHBoxLayout()
        c2_top.setSpacing(16)

        doc_icon = VectorIcon("document", 36, color=T.NAVY_900)
        c2_top.addWidget(doc_icon)

        c2_title = QLabel("Saved Auto-Learned\nParser\nConfigurations")
        c2_title.setFont(T.get_font(13, bold=True))
        c2_title.setStyleSheet(f"color: {T.NAVY_900}; border: none;")
        c2_top.addWidget(c2_title)
        c2_top.addStretch()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setProperty("btnClass", "outline")
        refresh_btn.setFixedHeight(26)
        refresh_btn.clicked.connect(self.refresh)
        c2_top.addWidget(refresh_btn)
        c2l.addLayout(c2_top)

        self.saved_container = QWidget()
        self.saved_container.setStyleSheet("background: transparent; border: none;")
        self.saved_layout = QVBoxLayout(self.saved_container)
        self.saved_layout.setContentsMargins(0, 0, 0, 0)
        self.saved_layout.setSpacing(8)
        c2l.addWidget(self.saved_container)

        layout.addWidget(card2)
        layout.addStretch()

        self.refresh()

    def refresh(self):
        """Periodic sync callback: populate saved auto-learned parsers."""
        # Clear existing items
        while self.saved_layout.count() > 0:
            item = self.saved_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        parsers = self.service.list_learned_parsers() if hasattr(self.service, "list_learned_parsers") else []

        if not parsers:
            doc_text = QLabel("No learned parsers yet. Learn one above, or let ULPF learn automatically: unknown formats seen in live traffic are sampled, mined and validated, then promoted canary → active.")
            doc_text.setFont(T.get_font(12))
            doc_text.setStyleSheet(f"color: {T.SLATE_600}; border: none; background: transparent;")
            self.saved_layout.addWidget(doc_text)
            return

        for p in parsers:
            row = QFrame()
            row.setStyleSheet(f"""
                QFrame {{
                    background-color: {T.GREY_50};
                    border: 1px solid {T.GREY_200};
                    border-radius: 6px;
                    padding: 8px 12px;
                }}
            """)
            rl = QVBoxLayout(row)
            rl.setContentsMargins(10, 8, 10, 8)
            rl.setSpacing(4)

            top_h = QHBoxLayout()
            pid_lbl = QLabel(p.get("parser_id", ""))
            pid_lbl.setFont(T.get_font(12, bold=True, mono=True))
            pid_lbl.setStyleSheet(f"color: {T.NAVY_900}; border: none;")
            top_h.addWidget(pid_lbl)

            fam_badge = PillBadge(p.get("family", "custom").upper(), "neutral")
            top_h.addWidget(fam_badge)

            state_badge = PillBadge(p.get("state", "candidate").upper(), "success" if p.get("state") in ("active", "canary") else "warning")
            top_h.addWidget(state_badge)

            top_h.addStretch()

            conf = p.get("confidence", 0.0)
            f_count = p.get("fields_count", 0)
            meta_lbl = QLabel(f"{f_count} fields • {conf:.0%} confidence")
            meta_lbl.setFont(T.get_font(11))
            meta_lbl.setStyleSheet(f"color: {T.SLATE_600}; border: none;")
            top_h.addWidget(meta_lbl)
            rl.addLayout(top_h)

            tpl = p.get("template", "")
            if tpl:
                tpl_lbl = QLabel(tpl[:100] + ("..." if len(tpl) > 100 else ""))
                tpl_lbl.setFont(T.get_font(10.5, mono=True))
                tpl_lbl.setStyleSheet(f"color: {T.SLATE_600}; border: none;")
                rl.addWidget(tpl_lbl)

            self.saved_layout.addWidget(row)

    def _load_ingested_unknown(self):
        """Fetch raw unparsed/proprietary logs stored in DuckDB for Auto-Learn analysis."""
        try:
            logs = self.service.get_unparsed_logs(limit=15)
            if logs:
                self.sample_input.setPlainText("\n".join(logs[:10]))
            else:
                self.sample_input.setPlainText(self.SAMPLE_PROPRIETARY)
        except Exception:
            self.sample_input.setPlainText(self.SAMPLE_PROPRIETARY)

    def _run_autolearn(self):
        text = self.sample_input.toPlainText().strip()
        lines = [l for l in text.split("\n") if l.strip()]
        if not lines:
            return

        self.btn_run.setEnabled(False)
        self.result_box.setPlainText("Synthesizing template, inferring entropy, and compiling parser...")
        self.result_box.setVisible(True)

        worker = ProcessingWorker(self.service.auto_learn, lines)
        worker.signals.result.connect(self._on_result)
        worker.signals.error.connect(self._on_error)
        worker.signals.finished.connect(lambda: self.btn_run.setEnabled(True))
        self.threadpool.start(worker)

    def _on_result(self, res: dict):
        self.result_box.setPlainText(json.dumps(res, indent=2, default=str))
        self.result_box.setVisible(True)
        self.refresh()

    def _on_error(self, err_tuple):
        err_msg = str(err_tuple[1]) if isinstance(err_tuple, (tuple, list)) and len(err_tuple) > 1 else str(err_tuple)
        self.result_box.setPlainText(f"Auto-Parser synthesis error: {err_msg}")
        self.result_box.setVisible(True)
