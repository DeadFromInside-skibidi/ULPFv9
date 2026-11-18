"""
ULPF Pipeline Visualization Page
===================================
Visualizes the actual processing pipeline stages with real metrics.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QGridLayout,
)

from ulpf.gui import theme as T
from ulpf.gui.widgets import PageHeader, SectionCard, MetricCard, StatusBadge
from ulpf.gui.service import ULPFService


class PipelineStage(QFrame):
    """Visual representation of a pipeline stage."""

    def __init__(self, name: str, icon: str = "●", parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            PipelineStage {{
                background: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS_MD}px;
                padding: 16px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        ic = QLabel(icon)
        ic.setFont(T.get_font(24))
        ic.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ic.setStyleSheet("border: none;")

        nm = QLabel(name)
        nm.setFont(T.get_font(T.FONT_SIZE_BODY, bold=True))
        nm.setAlignment(Qt.AlignmentFlag.AlignCenter)
        nm.setStyleSheet(f"color: {T.NAVY_900}; border: none;")

        self._status = StatusBadge("running")
        self._metric = QLabel("")
        self._metric.setFont(T.get_font(T.FONT_SIZE_META, mono=True))
        self._metric.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._metric.setStyleSheet(f"color: {T.SLATE_400}; border: none;")

        layout.addWidget(ic)
        layout.addWidget(nm)
        layout.addWidget(self._status, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._metric)

    def set_status(self, status: str):
        self._status.set_status(status)

    def set_metric(self, text: str):
        self._metric.setText(text)


class PipelinePage(QWidget):
    def __init__(self, service: ULPFService, parent=None):
        super().__init__(parent)
        self.service = service

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header = PageHeader("Processing Pipeline",
                            "Pipeline stage visualization")
        btn = QPushButton("Refresh")
        btn.setProperty("cssClass", "secondary")
        btn.clicked.connect(self.refresh)
        header.add_action(btn)
        layout.addWidget(header)

        # Pipeline stages
        stages_layout = QHBoxLayout()
        stages_layout.setSpacing(8)

        self.stages: list[PipelineStage] = []
        stage_defs = [
            ("Input", "📥"),
            ("Detection", "🔍"),
            ("Parsing", "⟨⟩"),
            ("Normalization", "📐"),
            ("Enrichment", "✨"),
            ("Storage", "💾"),
            ("Intelligence", "🧠"),
        ]

        for i, (name, icon) in enumerate(stage_defs):
            stage = PipelineStage(name, icon)
            self.stages.append(stage)
            stages_layout.addWidget(stage)

            if i < len(stage_defs) - 1:
                arrow = QLabel("→")
                arrow.setFont(T.get_font(20))
                arrow.setStyleSheet(f"color: {T.SLATE_300};")
                arrow.setAlignment(Qt.AlignmentFlag.AlignCenter)
                stages_layout.addWidget(arrow)

        layout.addLayout(stages_layout)

        # Metrics cards
        cards = QHBoxLayout()
        self.card_total = MetricCard("Total Processed", "0", "", T.BLUE_600)
        self.card_success = MetricCard("Successful", "0", "", T.SUCCESS)
        self.card_failed = MetricCard("Failed", "0", "", T.CRITICAL)
        self.card_avg = MetricCard("Avg Time", "0 ms", "", T.NAVY_700)
        cards.addWidget(self.card_total)
        cards.addWidget(self.card_success)
        cards.addWidget(self.card_failed)
        cards.addWidget(self.card_avg)
        layout.addLayout(cards)

        # Parser usage
        self.parser_card = SectionCard("Parser Usage")
        pl = self.parser_card.content_layout()
        self.parser_info = QLabel("")
        self.parser_info.setFont(T.get_font(T.FONT_SIZE_TECH, mono=True))
        self.parser_info.setStyleSheet(f"color: {T.NAVY_900}; border: none;")
        self.parser_info.setWordWrap(True)
        pl.addWidget(self.parser_info)
        layout.addWidget(self.parser_card)

        layout.addStretch()

    def refresh(self):
        metrics = self.service.metrics()
        state = self.service.state.lower()

        # Update stages
        for stage in self.stages:
            stage.set_status("running" if state == "running" else "stopped")

        self.card_total.set_value(f"{metrics.get('total_events', 0):,}")
        self.card_success.set_value(f"{metrics.get('successful', 0):,}")
        self.card_failed.set_value(f"{metrics.get('failed', 0):,}")
        self.card_avg.set_value(f"{metrics.get('avg_processing_time_ms', 0):.2f} ms")

        # Parser usage
        usage = metrics.get("parser_usage", {})
        if usage:
            lines = [f"{pid}: {cnt}" for pid, cnt in
                     sorted(usage.items(), key=lambda x: -x[1])]
            self.parser_info.setText("\n".join(lines))
        else:
            self.parser_info.setText("No events processed yet.")
