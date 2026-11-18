"""
ULPF Log Ingestion Page
=========================
Pixel-faithful reproduction of the Ingestion Console from reference photo,
extended with fully interactive Mode A (Local File Queue) and Mode B (Remote Server & Listener).
"""
from __future__ import annotations

import os
from pathlib import Path
from PySide6.QtCore import Qt, QThreadPool, QTimer
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QFileDialog, QTextEdit, QProgressBar, QFrame, QTableView,
    QHeaderView, QAbstractItemView, QLineEdit, QComboBox,
    QStackedWidget, QCheckBox
)

from ulpf.gui import theme as T
from ulpf.gui.widgets import (
    FileDropZone, SectionCard, PipelineStageBar, PillBadge,
    StatusBadge, VectorIcon, KeyValueRow
)
from ulpf.gui.service import ULPFService
from ulpf.gui.workers.background import ProcessingWorker


class IngestionPage(QWidget):
    """Institutional Ingestion Console with interactive Mode A & Mode B."""

    def __init__(self, service: ULPFService, parent=None):
        super().__init__(parent)
        self.service = service
        self.threadpool = QThreadPool.globalInstance()
        self.current_mode = "A"

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        # ── Mode Selection Header ──
        mode_row = QHBoxLayout()
        mode_row.setSpacing(16)

        # Mode A Card
        self.mode_a = QFrame()
        self.mode_a.setCursor(Qt.CursorShape.PointingHandCursor)
        self.mode_a.mousePressEvent = lambda e: self.set_mode("A")
        ma_layout = QHBoxLayout(self.mode_a)
        ma_layout.setContentsMargins(24, 16, 24, 16)
        ma_layout.setSpacing(18)
        self.ma_icon = VectorIcon("document", size=48, color=T.NAVY_900)
        ma_layout.addWidget(self.ma_icon)

        ma_title = QLabel("MODE A: Local\nLog\nProcessing")
        ma_title.setFont(T.get_font(13.5, bold=True))
        ma_title.setStyleSheet(f"color: {T.NAVY_900}; border: none; line-height: 1.2; background: transparent;")
        ma_layout.addWidget(ma_title)
        ma_layout.addStretch()
        mode_row.addWidget(self.mode_a, 1)

        # Mode B Card
        self.mode_b = QFrame()
        self.mode_b.setCursor(Qt.CursorShape.PointingHandCursor)
        self.mode_b.mousePressEvent = lambda e: self.set_mode("B")
        mb_layout = QHBoxLayout(self.mode_b)
        mb_layout.setContentsMargins(24, 16, 24, 16)
        mb_layout.setSpacing(18)
        self.mb_icon = VectorIcon("server", size=48, color=T.NAVY_900)
        mb_layout.addWidget(self.mb_icon)

        mb_title = QLabel("MODE B:\nRemote Server &\nListener")
        mb_title.setFont(T.get_font(13.5, bold=True))
        mb_title.setStyleSheet(f"color: {T.NAVY_900}; border: none; line-height: 1.2; background: transparent;")
        mb_layout.addWidget(mb_title)
        mb_layout.addStretch()
        mode_row.addWidget(self.mode_b, 1)

        layout.addLayout(mode_row)

        # ── 7-Stage Pipeline Visualizer ──
        stage_bar = PipelineStageBar()
        layout.addWidget(stage_bar)

        # ── Stacked Container for Mode A and Mode B ──
        self.mode_stack = QStackedWidget()
        self.mode_stack.setStyleSheet("background: transparent;")

        # ── 1. MODE A WIDGET (Local File Processing) ──
        mode_a_widget = QWidget()
        mode_a_layout = QVBoxLayout(mode_a_widget)
        mode_a_layout.setContentsMargins(0, 0, 0, 0)
        mode_a_layout.setSpacing(16)

        batch_badge = QLabel("Multi-file batching supported")
        batch_badge.setFont(T.get_font(11))
        batch_badge.setStyleSheet(f"color: {T.SLATE_400};")

        source_card = SectionCard("Local Log File Ingestion Source", right_widget=batch_badge)
        sl = source_card.content_layout()

        # Drop Zone
        self.drop_zone = FileDropZone()
        self.drop_zone.files_dropped.connect(self._on_files_dropped)

        # Browse Button inside drop zone
        self.browse_btn = QPushButton("Browse Local Files")
        self.browse_btn.setProperty("btnClass", "secondary")
        self.browse_btn.setFixedWidth(160)
        self.browse_btn.setFixedHeight(32)
        self.browse_btn.clicked.connect(self._browse_files)
        self.drop_zone.layout().addSpacing(6)
        self.drop_zone.layout().addWidget(self.browse_btn, 0, Qt.AlignmentFlag.AlignCenter)
        sl.addWidget(self.drop_zone)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFixedHeight(4)
        self.progress_bar.setVisible(False)
        sl.addWidget(self.progress_bar)

        # Quick Load Standard Security Baselines
        quick_frame = QFrame()
        quick_frame.setStyleSheet(f"border-top: 1px solid {T.GREY_200}; padding-top: 12px; padding-bottom: 4px;")
        ql = QHBoxLayout(quick_frame)
        ql.setContentsMargins(0, 8, 0, 4)
        ql.setSpacing(8)

        quick_lbl = QLabel("PRE-PACKAGED VERIFICATION CORPORA:")
        quick_lbl.setFont(T.get_font(11, bold=True))
        quick_lbl.setStyleSheet(f"color: {T.SLATE_600};")
        ql.addWidget(quick_lbl)

        samples = [
            ("CEF Firewall", "demo_data/firewall_cef.log"),
            ("LEEF IDS", "demo_data/ids_leef.log"),
            ("Syslog Router", "demo_data/router_syslog.log"),
            ("JSON WAF", "demo_data/waf_json.log"),
            ("Fortinet KV", "demo_data/fortigate_kv.log"),
            ("Mixed Formats", "demo_data/mixed_formats.log"),
        ]

        for title, path in samples:
            btn = QPushButton(title)
            btn.setProperty("btnClass", "outline")
            btn.setFont(T.get_font(11))
            btn.setFixedHeight(28)
            btn.setMinimumWidth(100)
            btn.clicked.connect(lambda ch, p=path: self._load_sample(p))
            ql.addWidget(btn)

        ql.addStretch()
        sl.addWidget(quick_frame)
        mode_a_layout.addWidget(source_card)
        self.mode_stack.addWidget(mode_a_widget)

        # ── 2. MODE B WIDGET (Remote Server & Network Listener) ──
        mode_b_widget = QWidget()
        mode_b_layout = QVBoxLayout(mode_b_widget)
        mode_b_layout.setContentsMargins(0, 0, 0, 0)
        mode_b_layout.setSpacing(16)

        # Panel 1: Real-Time Network Syslog Listener
        self.listener_badge = StatusBadge("operational", "LISTENING")
        listener_card = SectionCard("Real-Time Network Syslog Daemon (Ingest from Servers)", right_widget=self.listener_badge)
        ll = listener_card.content_layout()

        ctl_row = QHBoxLayout()
        ctl_row.setSpacing(12)

        INP_STYLE = f"""
            QLineEdit {{
                background-color: {T.WHITE};
                border: 1px solid {T.SLATE_400};
                border-radius: 4px;
                padding: 4px 8px;
                color: {T.NAVY_900};
                font-weight: 600;
                font-size: 12px;
            }}
            QLineEdit:focus {{
                border: 1.5px solid {T.BLUE_600};
            }}
        """
        COMBO_STYLE = f"""
            QComboBox {{
                background-color: {T.WHITE};
                border: 1px solid {T.SLATE_400};
                border-radius: 4px;
                padding: 4px 8px;
                color: {T.NAVY_900};
                font-weight: 600;
                font-size: 12px;
            }}
            QComboBox::drop-down {{
                border: none;
                border-left: 1px solid {T.GREY_200};
                width: 20px;
            }}
        """

        lbl_host = QLabel("Bind Address:")
        lbl_host.setFont(T.get_font(11, bold=True))
        lbl_host.setStyleSheet(f"color: {T.SLATE_600};")
        ctl_row.addWidget(lbl_host)

        self.input_bind_host = QLineEdit("0.0.0.0")
        self.input_bind_host.setStyleSheet(INP_STYLE)
        self.input_bind_host.setFixedWidth(120)
        self.input_bind_host.setFixedHeight(30)
        ctl_row.addWidget(self.input_bind_host)

        lbl_port = QLabel("Port:")
        lbl_port.setFont(T.get_font(11, bold=True))
        lbl_port.setStyleSheet(f"color: {T.SLATE_600};")
        ctl_row.addWidget(lbl_port)

        self.input_bind_port = QLineEdit("5514")
        self.input_bind_port.setStyleSheet(INP_STYLE)
        self.input_bind_port.setFixedWidth(65)
        self.input_bind_port.setFixedHeight(30)
        ctl_row.addWidget(self.input_bind_port)

        lbl_proto = QLabel("Protocol:")
        lbl_proto.setFont(T.get_font(11, bold=True))
        lbl_proto.setStyleSheet(f"color: {T.SLATE_600};")
        ctl_row.addWidget(lbl_proto)

        self.combo_proto = QComboBox()
        self.combo_proto.setStyleSheet(COMBO_STYLE)
        self.combo_proto.addItems(["UDP (RFC 5426)", "TCP (RFC 5424)", "BOTH"])
        self.combo_proto.setFixedWidth(145)
        self.combo_proto.setFixedHeight(30)
        ctl_row.addWidget(self.combo_proto)

        lbl_workers = QLabel("Workers:")
        lbl_workers.setFont(T.get_font(11, bold=True))
        lbl_workers.setStyleSheet(f"color: {T.SLATE_600};")
        ctl_row.addWidget(lbl_workers)

        self.input_workers = QLineEdit(str(os.cpu_count() or 6))
        self.input_workers.setStyleSheet(INP_STYLE)
        self.input_workers.setFixedWidth(40)
        self.input_workers.setFixedHeight(30)
        ctl_row.addWidget(self.input_workers)

        ctl_row.addSpacing(10)

        BTN_PRIMARY = f"""
            QPushButton {{
                background-color: {T.NAVY_800};
                color: {T.WHITE};
                border: 1px solid {T.NAVY_900};
                border-radius: 4px;
                padding: 5px 12px;
                font-weight: 600;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background-color: {T.NAVY_700};
            }}
            QPushButton:disabled {{
                background-color: {T.GREY_200};
                color: {T.SLATE_400};
                border: 1px solid {T.SLATE_300};
            }}
        """

        BTN_OUTLINE = f"""
            QPushButton {{
                background-color: {T.WHITE};
                color: {T.NAVY_800};
                border: 1px solid {T.SLATE_400};
                border-radius: 4px;
                padding: 5px 12px;
                font-weight: 600;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background-color: {T.GREY_100};
                border-color: {T.SLATE_600};
            }}
            QPushButton:disabled {{
                background-color: {T.GREY_50};
                color: {T.SLATE_300};
                border: 1px solid {T.GREY_200};
            }}
        """

        self.btn_start_listener = QPushButton("Start Listener")
        self.btn_start_listener.setStyleSheet(BTN_PRIMARY)
        self.btn_start_listener.setFixedHeight(30)
        self.btn_start_listener.setFixedWidth(120)
        self.btn_start_listener.clicked.connect(self._start_listener)
        ctl_row.addWidget(self.btn_start_listener)

        self.btn_stop_listener = QPushButton("Stop")
        self.btn_stop_listener.setStyleSheet(BTN_OUTLINE)
        self.btn_stop_listener.setFixedHeight(30)
        self.btn_stop_listener.setFixedWidth(75)
        self.btn_stop_listener.clicked.connect(self._stop_listener)
        ctl_row.addWidget(self.btn_stop_listener)

        ctl_row.addStretch()
        ll.addLayout(ctl_row)

        opt_row = QHBoxLayout()
        opt_row.setSpacing(20)
        
        self.chk_save_local = QCheckBox("Save Locally to DuckDB")
        self.chk_save_local.setChecked(True)
        self.chk_save_local.setFont(T.get_font(11))
        self.chk_save_local.setStyleSheet(f"color: {T.NAVY_900};")
        opt_row.addWidget(self.chk_save_local)
        
        self.chk_forward_siem = QCheckBox("Enable Live SIEM Forwarding (Uses Target below)")
        self.chk_forward_siem.setChecked(False)
        self.chk_forward_siem.setFont(T.get_font(11))
        self.chk_forward_siem.setStyleSheet(f"color: {T.NAVY_900};")
        opt_row.addWidget(self.chk_forward_siem)
        
        opt_row.addStretch()
        ll.addLayout(opt_row)

        # Listener live metrics row
        metrics_frame = QFrame()
        metrics_frame.setStyleSheet(f"background-color: {T.GREY_50}; border: 1px solid {T.GREY_200}; border-radius: 4px; padding: 8px 14px;")
        mf_layout = QHBoxLayout(metrics_frame)
        mf_layout.setContentsMargins(12, 6, 12, 6)
        mf_layout.setSpacing(24)

        self.lbl_pkts = QLabel("Packets Received: 0")
        self.lbl_pkts.setFont(T.get_font(11, bold=True))
        self.lbl_pkts.setStyleSheet(f"color: {T.NAVY_900};")
        mf_layout.addWidget(self.lbl_pkts)

        self.lbl_bytes = QLabel("Volume: 0 KB")
        self.lbl_bytes.setFont(T.get_font(11))
        self.lbl_bytes.setStyleSheet(f"color: {T.SLATE_600};")
        mf_layout.addWidget(self.lbl_bytes)

        self.lbl_last_ts = QLabel("Last Packet: —")
        self.lbl_last_ts.setFont(T.get_font(11))
        self.lbl_last_ts.setStyleSheet(f"color: {T.SLATE_600};")
        mf_layout.addWidget(self.lbl_last_ts)

        mf_layout.addStretch()
        ll.addWidget(metrics_frame)

        # Live incoming network packets log
        lbl_act = QLabel("LIVE NETWORK ACTIVITY STREAM")
        lbl_act.setFont(T.get_font(10.5, bold=True))
        lbl_act.setStyleSheet(f"color: {T.SLATE_600};")
        ll.addWidget(lbl_act)

        self.log_ticker = QTextEdit()
        self.log_ticker.setReadOnly(True)
        self.log_ticker.setFixedHeight(68)
        self.log_ticker.setFont(T.get_font(10, mono=True))
        self.log_ticker.setStyleSheet(f"""
            QTextEdit {{
                background-color: {T.SLATE_800};
                color: #A7F3D0;
                border: 1px solid {T.GREY_200};
                border-radius: 4px;
                padding: 6px;
            }}
        """)
        self.log_ticker.setText("[DAEMON ACTIVE] Waiting for inbound network syslog packets on port 5514...")
        ll.addWidget(self.log_ticker)

        mode_b_layout.addWidget(listener_card)

        # Panel 2: Remote Server Integration & SIEM Forwarder
        fwd_badge = PillBadge("RFC 5424 CLIENT")
        fwd_card = SectionCard("Remote Server Integration & Outbound SIEM Forwarder", right_widget=fwd_badge)
        fl = fwd_card.content_layout()

        # Target configuration & actions in single unified row
        fwd_row = QHBoxLayout()
        fwd_row.setSpacing(10)

        lbl_target = QLabel("Target:")
        lbl_target.setFont(T.get_font(11, bold=True))
        lbl_target.setStyleSheet(f"color: {T.SLATE_600};")
        fwd_row.addWidget(lbl_target)

        self.input_target_host = QLineEdit("127.0.0.1")
        self.input_target_host.setStyleSheet(INP_STYLE)
        self.input_target_host.setFixedWidth(120)
        self.input_target_host.setFixedHeight(30)
        fwd_row.addWidget(self.input_target_host)

        lbl_tport = QLabel("Port:")
        lbl_tport.setFont(T.get_font(11, bold=True))
        lbl_tport.setStyleSheet(f"color: {T.SLATE_600};")
        fwd_row.addWidget(lbl_tport)

        self.input_target_port = QLineEdit("514")
        self.input_target_port.setStyleSheet(INP_STYLE)
        self.input_target_port.setFixedWidth(60)
        self.input_target_port.setFixedHeight(30)
        fwd_row.addWidget(self.input_target_port)

        lbl_tproto = QLabel("Proto:")
        lbl_tproto.setFont(T.get_font(11, bold=True))
        lbl_tproto.setStyleSheet(f"color: {T.SLATE_600};")
        fwd_row.addWidget(lbl_tproto)

        self.combo_target_proto = QComboBox()
        self.combo_target_proto.setStyleSheet(COMBO_STYLE)
        self.combo_target_proto.addItems(["UDP", "TCP"])
        self.combo_target_proto.setFixedWidth(70)
        self.combo_target_proto.setFixedHeight(30)
        fwd_row.addWidget(self.combo_target_proto)

        fwd_row.addSpacing(8)

        self.btn_test_conn = QPushButton("Test Connection")
        self.btn_test_conn.setStyleSheet(BTN_OUTLINE)
        self.btn_test_conn.setFixedHeight(30)
        self.btn_test_conn.setFixedWidth(140)
        self.btn_test_conn.clicked.connect(self._test_server_connection)
        fwd_row.addWidget(self.btn_test_conn)

        self.btn_forward = QPushButton("Forward Events to SIEM")
        self.btn_forward.setStyleSheet(BTN_PRIMARY)
        self.btn_forward.setFixedHeight(30)
        self.btn_forward.setFixedWidth(175)
        self.btn_forward.clicked.connect(self._forward_to_siem)
        fwd_row.addWidget(self.btn_forward)

        fwd_row.addStretch()
        fl.addLayout(fwd_row)

        self.conn_result_lbl = QLabel("")
        self.conn_result_lbl.setFont(T.get_font(11, bold=True))
        self.conn_result_lbl.setVisible(False)
        fl.addWidget(self.conn_result_lbl)

        mode_b_layout.addWidget(fwd_card)
        self.mode_stack.addWidget(mode_b_widget)

        layout.addWidget(self.mode_stack)

        # ── Results Banner / Summary ──
        self.results_banner = QLabel("")
        self.results_banner.setFont(T.get_font(12, bold=True))
        self.results_banner.setVisible(False)
        self.results_banner.setStyleSheet(f"""
            background-color: {T.SUCCESS_BG};
            color: {T.SUCCESS};
            border: 1px solid {T.SUCCESS_BD};
            border-radius: {T.BORDER_RADIUS}px;
            padding: 10px 14px;
        """)
        layout.addWidget(self.results_banner)

        layout.addStretch()

        # Set default active mode
        self.set_mode("A")

        # Telemetry timer for network listener stats in Mode B
        self._telemetry_timer = QTimer(self)
        self._telemetry_timer.timeout.connect(self._poll_telemetry)
        self._telemetry_timer.start(1500)

    def set_mode(self, mode: str):
        """Toggle between Mode A (Local Files) and Mode B (Remote Server & Listener)."""
        self.current_mode = mode
        if mode == "A":
            self.mode_a.setStyleSheet(f"""
                QFrame {{
                    background-color: {T.WHITE};
                    border: 1px solid {T.BLUE_600};
                    border-bottom: 3px solid {T.BLUE_600};
                    border-radius: {T.BORDER_RADIUS}px;
                }}
            """)
            self.mode_b.setStyleSheet(f"""
                QFrame {{
                    background-color: {T.WHITE};
                    border: 1px solid {T.GREY_200};
                    border-bottom: 1px solid {T.GREY_200};
                    border-radius: {T.BORDER_RADIUS}px;
                }}
            """)
            self.mode_stack.setCurrentIndex(0)
        else:
            self.mode_a.setStyleSheet(f"""
                QFrame {{
                    background-color: {T.WHITE};
                    border: 1px solid {T.GREY_200};
                    border-bottom: 1px solid {T.GREY_200};
                    border-radius: {T.BORDER_RADIUS}px;
                }}
            """)
            self.mode_b.setStyleSheet(f"""
                QFrame {{
                    background-color: {T.WHITE};
                    border: 1px solid {T.BLUE_600};
                    border-bottom: 3px solid {T.BLUE_600};
                    border-radius: {T.BORDER_RADIUS}px;
                }}
            """)
            self.mode_stack.setCurrentIndex(1)
            self._poll_telemetry()

    def _start_listener(self):
        host = self.input_bind_host.text().strip() or "0.0.0.0"
        try:
            port = int(self.input_bind_port.text().strip() or "5514")
        except ValueError:
            port = 5514
        proto = "TCP" if "TCP" in self.combo_proto.currentText() else "UDP"
        try:
            workers = int(self.input_workers.text().strip() or str(os.cpu_count() or 6))
        except ValueError:
            workers = os.cpu_count() or 6

        siem_host = None
        siem_port = None
        save_local = self.chk_save_local.isChecked() if hasattr(self, 'chk_save_local') else True
        if hasattr(self, 'chk_forward_siem') and self.chk_forward_siem.isChecked():
            siem_host = self.input_target_host.text().strip() or "127.0.0.1"
            try:
                siem_port = int(self.input_target_port.text().strip() or "514")
            except ValueError:
                siem_port = 514

        res = self.service.start_network_listener(host=host, port=port, proto=proto, workers=workers, siem_host=siem_host, siem_port=siem_port, save_local=save_local)
        self._poll_telemetry()

    def _stop_listener(self):
        self.service.stop_network_listener()
        self._poll_telemetry()

    def _poll_telemetry(self):
        if not hasattr(self, "lbl_pkts"):
            return
        status = self.service.get_listener_status()
        is_running = status.get("running", False)
        if is_running:
            self.listener_badge.set_status("operational", f"LISTENING ON {status.get('port')}/{status.get('proto')}")
            self.btn_start_listener.setEnabled(False)
            self.btn_start_listener.setText("Listening...")
            self.btn_stop_listener.setEnabled(True)
        else:
            self.listener_badge.set_status("stopped", "INACTIVE")
            self.btn_start_listener.setEnabled(True)
            self.btn_start_listener.setText("Start Listener")
            self.btn_stop_listener.setEnabled(False)

        pkts = status.get("packets", 0)
        vol_kb = round(status.get("bytes", 0) / 1024.0, 1)
        last_ts = status.get("last_packet", "—")
        self.lbl_pkts.setText(f"Packets Received: {pkts:,}")
        self.lbl_bytes.setText(f"Volume: {vol_kb} KB")
        self.lbl_last_ts.setText(f"Last Packet: {last_ts}")

        recent = status.get("recent", [])
        if recent:
            self.log_ticker.setText("\n".join(recent[-15:]))

    def _test_server_connection(self):
        host = self.input_target_host.text().strip() or "127.0.0.1"
        try:
            port = int(self.input_target_port.text().strip() or "514")
        except ValueError:
            port = 514

        res = self.service.test_remote_server(host=host, port=port)
        self.conn_result_lbl.setVisible(True)
        if res.get("success"):
            self.conn_result_lbl.setText(f"✓ {res.get('message')}")
            self.conn_result_lbl.setStyleSheet(f"color: {T.SUCCESS};")
        else:
            self.conn_result_lbl.setText(f"✗ {res.get('message')}")
            self.conn_result_lbl.setStyleSheet(f"color: {T.CRITICAL};")

    def _forward_to_siem(self):
        host = self.input_target_host.text().strip() or "127.0.0.1"
        try:
            port = int(self.input_target_port.text().strip() or "514")
        except ValueError:
            port = 514
        proto = self.combo_target_proto.currentText()

        res = self.service.forward_events_to_server(host=host, port=port, proto=proto, limit=50)
        self.conn_result_lbl.setVisible(True)
        if res.get("success"):
            self.conn_result_lbl.setText(f"✓ {res.get('message')}")
            self.conn_result_lbl.setStyleSheet(f"color: {T.SUCCESS};")
        else:
            self.conn_result_lbl.setText(f"✗ {res.get('message')}")
            self.conn_result_lbl.setStyleSheet(f"color: {T.CRITICAL};")

    def _browse_files(self):
        files, _ = QFileDialog.getOpenFileNames(
            self, "Select Security Log Files", "",
            "Log Files (*.log *.txt *.json *.csv *.xml);;All Files (*)"
        )
        if files:
            self._process_files(files)

    def _on_files_dropped(self, files: list[str]):
        self._process_files(files)

    def _load_sample(self, rel_path: str):
        import sys
        base = getattr(sys, "_MEIPASS", str(Path(__file__).parent.parent.parent.parent))
        target = os.path.join(base, rel_path)
        if os.path.exists(target):
            self._process_files([target])
        else:
            self.results_banner.setText(f"Verification corpus file not found: {rel_path}")
            self.results_banner.setVisible(True)

    def _process_files(self, files: list[str]):
        if not files:
            return
        self.progress_bar.setVisible(True)
        self.browse_btn.setEnabled(False)

        def _ingest_all(paths: list[str]):
            total_accepted = 0
            total_rejected = 0
            total_stored = 0
            total_anomalies = 0
            errors = []
            for p in paths:
                r = self.service.ingest_file(p)
                if r.get("success"):
                    total_accepted += r.get("events_accepted", 0)
                    total_rejected += r.get("events_rejected", 0)
                    total_stored += r.get("stored", 0)
                    total_anomalies += r.get("anomalies", 0)
                else:
                    errors.append(f"{os.path.basename(p)}: {r.get('error')}")
            return {
                "success": len(errors) == 0 or total_accepted > 0,
                "events_accepted": total_accepted,
                "events_rejected": total_rejected,
                "stored": total_stored,
                "anomalies": total_anomalies,
                "error": "; ".join(errors) if errors else None,
                "count": len(paths),
            }

        worker = ProcessingWorker(_ingest_all, files)
        worker.signals.result.connect(self._on_ingest_result)
        worker.signals.error.connect(self._on_ingest_error)
        worker.signals.finished.connect(lambda: self.progress_bar.setVisible(False))
        self.threadpool.start(worker)

    def _on_ingest_result(self, res: dict):
        self.browse_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

        if res.get("success"):
            accepted = res.get("events_accepted", 0)
            rejected = res.get("events_rejected", 0)
            stored = res.get("stored", 0)
            anom = res.get("anomalies", 0)
            count = res.get("count", 1)
            file_info = f"{count} file(s) with " if count > 1 else ""
            self.results_banner.setText(
                f"✓ Successfully processed {file_info}{accepted} events ({stored} stored in DuckDB, {anom} anomalies detected, {rejected} rejected)."
            )
            self.results_banner.setStyleSheet(f"""
                background-color: {T.SUCCESS_BG};
                color: {T.SUCCESS};
                border: 1px solid {T.SUCCESS_BD};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 10px 14px;
            """)
        else:
            self.results_banner.setText(f"Ingestion Error: {res.get('error')}")
            self.results_banner.setStyleSheet(f"""
                background-color: {T.CRITICAL_BG};
                color: {T.CRITICAL};
                border: 1px solid {T.CRITICAL_BD};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 10px 14px;
            """)
        self.results_banner.setVisible(True)
        win = self.window()
        if hasattr(win, "_on_refresh"):
            win._on_refresh(force_all=True)

    def _on_ingest_error(self, err: str):
        self.browse_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.results_banner.setText(f"Worker Error: {err}")
        self.results_banner.setVisible(True)

    def refresh(self):
        """Called on periodic timer or page switch."""
        if self.current_mode == "B":
            self._poll_telemetry()
