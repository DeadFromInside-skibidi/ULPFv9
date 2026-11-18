"""
ULPF Settings Page
====================
Persistent native desktop settings using QSettings.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QSettings
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QLineEdit, QSpinBox, QCheckBox, QGroupBox, QFormLayout,
    QMessageBox,
)

from ulpf.gui import theme as T
from ulpf.gui.widgets import PageHeader, SectionCard, KeyValueRow
from ulpf.gui.service import ULPFService


class SettingsPage(QWidget):
    def __init__(self, service: ULPFService, parent=None):
        super().__init__(parent)
        self.service = service
        self.settings = QSettings("ULPF", "UniversalLogPreprocessing")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header = PageHeader("Settings", "Application configuration")
        layout.addWidget(header)

        # General
        gen_card = SectionCard("General")
        gl = gen_card.content_layout()

        form = QFormLayout()
        self.chk_anomaly = QCheckBox("Anomaly Detection")
        self.chk_anomaly.setChecked(
            self.settings.value("enable_anomaly", True, type=bool)
        )
        form.addRow(self.chk_anomaly)

        self.chk_correlation = QCheckBox("Event Correlation")
        self.chk_correlation.setChecked(
            self.settings.value("enable_correlation", True, type=bool)
        )
        form.addRow(self.chk_correlation)

        self.chk_forensics = QCheckBox("Forensics")
        self.chk_forensics.setChecked(
            self.settings.value("enable_forensics", True, type=bool)
        )
        form.addRow(self.chk_forensics)

        self.chk_logdna = QCheckBox("Log DNA")
        self.chk_logdna.setChecked(
            self.settings.value("enable_logdna", True, type=bool)
        )
        form.addRow(self.chk_logdna)

        gl.addLayout(form)
        layout.addWidget(gen_card)

        # Data locations
        data_card = SectionCard("Data Locations")
        dl = data_card.content_layout()

        self.kv_data = KeyValueRow("Data Directory", str(service.data_dir))
        self.kv_db = KeyValueRow("Database", str(service.data_dir / "ulpf.duckdb"))
        self.kv_evidence = KeyValueRow("Evidence", str(service.data_dir / "evidence"))
        dl.addWidget(self.kv_data)
        dl.addWidget(self.kv_db)
        dl.addWidget(self.kv_evidence)
        layout.addWidget(data_card)

        # About
        about_card = SectionCard("About ULPF")
        al = about_card.content_layout()

        about_info = QLabel(
            "ULPF — Universal Log Pre-processing Framework\n"
            "Version 1.0.0\n"
            "Storage: DuckDB (Columnar)\n"
            "Mode: Air-Gapped / Offline Ready\n\n"
            "A native desktop application for security log ingestion,\n"
            "parsing, normalization, correlation, anomaly detection,\n"
            "and forensic evidence chain management."
        )
        about_info.setFont(T.get_font(T.FONT_SIZE_BODY))
        about_info.setStyleSheet(f"color: {T.SLATE_600}; border: none;")
        al.addWidget(about_info)
        layout.addWidget(about_card)

        # Save button
        btn_save = QPushButton("Save Settings")
        btn_save.clicked.connect(self._save)
        layout.addWidget(btn_save, alignment=Qt.AlignmentFlag.AlignRight)

        layout.addStretch()

    def refresh(self):
        pass

    def _save(self):
        self.settings.setValue("enable_anomaly", self.chk_anomaly.isChecked())
        self.settings.setValue("enable_correlation", self.chk_correlation.isChecked())
        self.settings.setValue("enable_forensics", self.chk_forensics.isChecked())
        self.settings.setValue("enable_logdna", self.chk_logdna.isChecked())
        self.settings.sync()
        QMessageBox.information(self, "Settings Saved",
                                 "Settings have been saved successfully.")
