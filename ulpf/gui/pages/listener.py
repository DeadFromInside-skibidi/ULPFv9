"""
ULPF Live Network Listener Page
==================================
Exposes the real UDP/TCP listener with start/stop controls.
Listener runs on a background thread, never the GUI thread.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QLineEdit, QSpinBox, QComboBox, QGridLayout,
)

from ulpf.gui import theme as T
from ulpf.gui.widgets import PageHeader, SectionCard, MetricCard, StatusBadge, KeyValueRow
from ulpf.gui.service import ULPFService


class ListenerThread(QThread):
    """Runs the network listener via the high-throughput service layer."""
    status_update = Signal(dict)
    error = Signal(str)

    def __init__(self, service: ULPFService, host: str, port: int, protocol: str, parent=None):
        super().__init__(parent)
        self.service = service
        self.host = host
        self.port = port
        self.protocol = protocol
        self._running = False

    def run(self):
        try:
            self._running = True
            res = self.service.start_network_listener(
                host=self.host,
                port=self.port,
                proto=self.protocol,
            )
            if not res.get("success", False):
                self.error.emit(res.get("message", "Failed to start listener"))
        except Exception as e:
            self.error.emit(str(e))

    def stop_listener(self):
        self._running = False
        try:
            self.service.stop_network_listener()
        except Exception:
            pass
        self.quit()


class ListenerPage(QWidget):
    def __init__(self, service: ULPFService, parent=None):
        super().__init__(parent)
        self.service = service
        self._thread: ListenerThread | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header = PageHeader("Live Network Listener",
                            "Real-time UDP/TCP log receiver")
        layout.addWidget(header)

        # Config
        config_card = SectionCard("Listener Configuration")
        cl = config_card.content_layout()

        grid = QGridLayout()
        grid.addWidget(QLabel("Host:"), 0, 0)
        self.host_input = QLineEdit("0.0.0.0")
        grid.addWidget(self.host_input, 0, 1)

        grid.addWidget(QLabel("Port:"), 0, 2)
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(5514)
        grid.addWidget(self.port_spin, 0, 3)

        grid.addWidget(QLabel("Protocol:"), 1, 0)
        self.proto_combo = QComboBox()
        self.proto_combo.addItems(["both", "udp", "tcp"])
        grid.addWidget(self.proto_combo, 1, 1)

        cl.addLayout(grid)

        btn_row = QHBoxLayout()
        self.btn_start = QPushButton("▶ Start Listener")
        self.btn_start.clicked.connect(self._start)
        btn_row.addWidget(self.btn_start)

        self.btn_stop = QPushButton("■ Stop Listener")
        self.btn_stop.setProperty("cssClass", "danger")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop)
        btn_row.addWidget(self.btn_stop)

        btn_row.addStretch()
        cl.addLayout(btn_row)
        layout.addWidget(config_card)

        # Status
        status_card = SectionCard("Listener Status")
        sl = status_card.content_layout()

        self.status_badge = StatusBadge("stopped")
        sl.addWidget(self.status_badge)

        self.kv_host = KeyValueRow("Host", "—")
        self.kv_port = KeyValueRow("Port", "—")
        self.kv_proto = KeyValueRow("Protocol", "—")
        self.kv_status = KeyValueRow("State", "STOPPED")
        sl.addWidget(self.kv_host)
        sl.addWidget(self.kv_port)
        sl.addWidget(self.kv_proto)
        sl.addWidget(self.kv_status)

        layout.addWidget(status_card)
        layout.addStretch()

    def refresh(self):
        pass

    def _start(self):
        host = self.host_input.text().strip()
        port = self.port_spin.value()
        proto = self.proto_combo.currentText()

        self._thread = ListenerThread(self.service, host, port, proto)
        self._thread.error.connect(self._on_error)
        self._thread.start()

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.status_badge.set_status("running")
        self.kv_host.set_value(host)
        self.kv_port.set_value(str(port))
        self.kv_proto.set_value(proto.upper())
        self.kv_status.set_value("RUNNING")

    def _stop(self):
        if self._thread:
            self._thread.stop_listener()
            self._thread.wait(3000)
            self._thread = None

        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.status_badge.set_status("stopped")
        self.kv_status.set_value("STOPPED")

    def _on_error(self, msg: str):
        self.kv_status.set_value(f"ERROR: {msg}")
        self.status_badge.set_status("error")
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
