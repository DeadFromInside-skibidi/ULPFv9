"""
ULPF Main Window — Institutional Security Console
==================================================
Native PySide6 reproduction of the ULPF interface screenshots:
- Dark navy sidebar (#19314C) with brand block, grouped navigation, and engine status footer.
- White topbar (#FFFFFF) with dynamic institutional title, endpoint tag, health badge, sync clock, export, and search.
- Clean stacked page workspace with zero duplicate headers.
"""
from __future__ import annotations

import time
from datetime import datetime
from PySide6.QtCore import Qt, QTimer, QSize, Signal, QRectF, QPointF
from PySide6.QtGui import QIcon, QPixmap, QPainter, QPen, QColor, QCloseEvent
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QStackedWidget, QStatusBar,
    QScrollArea, QLineEdit, QApplication,
)

from ulpf.gui import theme as T
from ulpf.gui.service import ULPFService
from ulpf.gui.widgets import StatusBadge


# ── Navigation Items Definition ───────────────────────────────────────

NAV_GROUPS = [
    ("MONITOR", [
        ("overview",    "Overview",        "▦"),
        ("ingestion",   "Ingestion",       "⭱"),
        ("events",      "Event Explorer",  "☰"),
    ]),
    ("ANALYSIS", [
        ("parsers",     "Parsers",         "</>"),
        ("autolearn",   "Auto-Learn",      "✦"),
        ("logdna",      "Log DNA",         "🧬"),
        ("correlation", "Correlation",     "🔗"),
        ("anomalies",   "Anomalies",       "⚠"),
    ]),
    ("INTEGRITY & SCHEMA", [
        ("forensics",   "Forensics",       "🔒"),
        ("schema",      "Schema Taxonomy", "📑"),
    ]),
]

PAGE_TITLES = {
    "overview":    ("System\nOverview",                    "Unified Operational\nCommand Center"),
    "ingestion":   ("Log\nIngestion\nConsole",             "Local File Queue &\nRemote Server\nIntegration"),
    "events":      ("Event\nExplorer",                     "High-Density Security\nAnalyst Investigation\nWorkspace"),
    "parsers":     ("Parsers\n& Rulesets",                 "Parser Plugin Inventory &\nInteractive Testing Studio"),
    "autolearn":   ("Auto-Parser\nGenerator",              "Native Regex &\nPattern Mining\nStepper"),
    "logdna":      ("Log DNA\nFingerprinting",             "Structural\nEntropy &\nFormat Drift\nLaboratory"),
    "correlation": ("Event\nCorrelation",                  "Multi-Source\nTemporal Clustering\n& Kill-Chain Mapping"),
    "anomalies":   ("Anomaly\nCenter",                     "Statistical Rolling\nBaselines & Deviation\nTracking"),
    "forensics":   ("Forensic\nEvidence",                  "SHA-256 Merkle Chain\nIntegrity & Chain-of-\nCustody"),
    "schema":      ("Unified\nSchema\nDefinition",         "OCSF-Inspired\nEvent Data\nTaxonomy"),
}


# ── Sidebar Navigation Button ─────────────────────────────────────────

class NavButton(QPushButton):
    """Institutional sidebar button with active left accent bar."""

    def __init__(self, key: str, label: str, icon_text: str, parent=None):
        super().__init__(parent)
        self.key = key
        self.setText(f"   {icon_text}   {label}")
        self.setCheckable(True)
        self.setFixedHeight(38)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._update_style(False)

    def _update_style(self, active: bool):
        if active:
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {T.NAVY_800};
                    color: {T.WHITE};
                    border: none;
                    border-left: 3px solid {T.BLUE_600};
                    border-radius: 0px;
                    text-align: left;
                    padding-left: 18px;
                    font-size: 13px;
                    font-weight: 600;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: transparent;
                    color: {T.GREY_200};
                    border: none;
                    border-left: 3px solid transparent;
                    border-radius: 0px;
                    text-align: left;
                    padding-left: 18px;
                    font-size: 13px;
                    font-weight: 500;
                }}
                QPushButton:hover {{
                    background-color: {T.NAVY_800};
                    color: {T.WHITE};
                }}
            """)


# ── Sidebar ───────────────────────────────────────────────────────────

class Sidebar(QFrame):
    """Dark navy sidebar (#19314C) matching the institutional design."""

    nav_selected = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setAutoFillBackground(True)
        self.setFixedWidth(T.SIDEBAR_WIDTH)
        self.setStyleSheet(f"""
            #Sidebar, QFrame#Sidebar, Sidebar {{
                background-color: {T.NAVY_900};
                border-right: 1px solid {T.NAVY_800};
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── 1. Brand Block ──
        brand_frame = QFrame()
        brand_frame.setObjectName("brandFrame")
        brand_frame.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        brand_frame.setAutoFillBackground(True)
        brand_frame.setStyleSheet(f"""
            QFrame, #brandFrame {{
                background-color: {T.NAVY_900};
                border: none;
                border-bottom: 1px solid {T.NAVY_800};
            }}
        """)
        brand_layout = QHBoxLayout(brand_frame)
        brand_layout.setContentsMargins(20, 18, 20, 18)
        brand_layout.setSpacing(12)

        # Grid mark icon box
        from ulpf.gui.widgets import VectorIcon
        icon_box = VectorIcon("grid", size=32, color=T.BLUE_500)
        brand_layout.addWidget(icon_box)

        text_layout = QVBoxLayout()
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.setSpacing(3)

        brand_title = QLabel("ULPF CONSOLE")
        brand_title.setFont(T.get_font(13.5, bold=True))
        brand_title.setStyleSheet(f"color: {T.WHITE}; letter-spacing: 0.05em; border: none; background: transparent;")
        text_layout.addWidget(brand_title)

        brand_sub = QLabel("Universal Log Pre-processing")
        brand_sub.setFont(T.get_font(10.5))
        brand_sub.setStyleSheet(f"color: {T.SLATE_400}; border: none; background: transparent;")
        text_layout.addWidget(brand_sub)

        brand_layout.addLayout(text_layout)
        brand_layout.addStretch()
        layout.addWidget(brand_frame)

        # ── 2. Navigation List ──
        nav_container = QWidget()
        nav_container.setObjectName("navContainer")
        nav_container.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        nav_container.setAutoFillBackground(True)
        nav_container.setStyleSheet(f"""
            #navContainer, QWidget#navContainer {{
                background-color: {T.NAVY_900};
                border: none;
            }}
        """)
        nav_layout = QVBoxLayout(nav_container)
        nav_layout.setContentsMargins(0, 14, 0, 14)
        nav_layout.setSpacing(16)

        self._buttons: dict[str, NavButton] = {}

        for group_title, items in NAV_GROUPS:
            group_box = QVBoxLayout()
            group_box.setContentsMargins(0, 0, 0, 0)
            group_box.setSpacing(2)

            grp_lbl = QLabel(group_title)
            grp_lbl.setFont(T.get_font(10, bold=True))
            grp_lbl.setStyleSheet(f"""
                color: {T.SLATE_400};
                letter-spacing: 0.08em;
                padding-left: 20px;
                padding-bottom: 4px;
                border: none;
            """)
            group_box.addWidget(grp_lbl)

            for key, label, icon_char in items:
                btn = NavButton(key, label, icon_char)
                btn.clicked.connect(lambda checked, k=key: self._on_nav_click(k))
                self._buttons[key] = btn
                group_box.addWidget(btn)

            nav_layout.addLayout(group_box)

        nav_layout.addStretch()
        layout.addWidget(nav_container, 1)

        # ── 3. Sidebar Footer ──
        footer = QFrame()
        footer.setStyleSheet(f"""
            QFrame {{
                background-color: rgba(0, 0, 0, 0.22);
                border: none;
                border-top: 1px solid {T.NAVY_800};
            }}
        """)
        footer_layout = QVBoxLayout(footer)
        footer_layout.setContentsMargins(14, 12, 14, 12)
        footer_layout.setSpacing(6)

        # API Status row
        row1 = QHBoxLayout()
        r1_lbl = QLabel("API Status")
        r1_lbl.setFont(T.get_font(11))
        r1_lbl.setMinimumWidth(80)
        r1_lbl.setStyleSheet(f"color: {T.SLATE_400}; border: none;")
        self.footer_status = StatusBadge("online", "ONLINE", dark=True)
        row1.addWidget(r1_lbl)
        row1.addStretch()
        row1.addWidget(self.footer_status)
        footer_layout.addLayout(row1)

        # Engine Version row
        row2 = QHBoxLayout()
        r2_lbl = QLabel("Engine Version")
        r2_lbl.setFont(T.get_font(11))
        r2_lbl.setMinimumWidth(80)
        r2_lbl.setStyleSheet(f"color: {T.SLATE_400}; border: none;")
        from ulpf import __version__
        r2_val = QLabel(f"v{__version__} (DuckDB)")
        r2_val.setFont(T.get_font(10.5, mono=True))
        r2_val.setStyleSheet(f"color: {T.GREY_200}; border: none;")
        row2.addWidget(r2_lbl)
        row2.addStretch()
        row2.addWidget(r2_val)
        footer_layout.addLayout(row2)

        # Environment row
        row3 = QHBoxLayout()
        r3_lbl = QLabel("Environment")
        r3_lbl.setFont(T.get_font(11))
        r3_lbl.setMinimumWidth(80)
        r3_lbl.setStyleSheet(f"color: {T.SLATE_400}; border: none;")
        r3_val = QLabel("Air-Gapped Ready")
        r3_val.setFont(T.get_font(10))
        r3_val.setStyleSheet(f"color: {T.SLATE_400}; border: none;")
        row3.addWidget(r3_lbl)
        row3.addStretch()
        row3.addWidget(r3_val)
        footer_layout.addLayout(row3)

        layout.addWidget(footer)

    def _on_nav_click(self, key: str):
        self.set_active(key)
        self.nav_selected.emit(key)

    def set_active(self, key: str):
        for k, btn in self._buttons.items():
            is_active = (k == key)
            btn.setChecked(is_active)
            btn._update_style(is_active)

    def set_engine_status(self, status: str):
        self.footer_status.set_status(status)


# ── TopBar ────────────────────────────────────────────────────────────

class TopBar(QFrame):
    """
    Institutional top navigation bar (#FFFFFF):
    Title + Subtitle on left, Engine pill + Connection status + Sync time + Export + Search on right.
    """

    export_requested = Signal()
    refresh_requested = Signal()
    search_submitted = Signal(str)
    sim_toggled = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(T.TOPBAR_HEIGHT)
        self.setStyleSheet(f"""
            TopBar {{
                background-color: {T.WHITE};
                border-bottom: 1px solid {T.GREY_200};
            }}
            TopBar QLabel {{
                background: transparent;
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(24, 0, 24, 0)
        layout.setSpacing(14)

        # ── Left: Title and Subtitle side-by-side matching screenshots ──
        left_layout = QHBoxLayout()
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(14)
        left_layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        self._title = QLabel("System\nOverview")
        self._title.setFont(T.get_font(15, bold=True))
        self._title.setStyleSheet(f"color: {T.NAVY_900}; border: none;")

        self._subtitle = QLabel("Unified Operational Command Center")
        self._subtitle.setFont(T.get_font(10.5))
        self._subtitle.setStyleSheet(f"color: {T.SLATE_600}; border: none;")
        self._subtitle.setWordWrap(True)

        left_layout.addWidget(self._title)
        left_layout.addWidget(self._subtitle)
        layout.addLayout(left_layout)

        layout.addStretch()

        # ── Right: Controls matching screenshots ──
        # Server Endpoint Tag
        tag_box = QFrame()
        tag_box.setStyleSheet(f"""
            QFrame {{
                background-color: {T.GREY_100};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 2px 6px;
            }}
        """)
        tag_layout = QHBoxLayout(tag_box)
        tag_layout.setContentsMargins(6, 2, 6, 2)
        tag_layout.setSpacing(6)

        tag_lbl = QLabel("ULPF API")
        tag_lbl.setFont(T.get_font(9, bold=True))
        tag_lbl.setStyleSheet(f"color: {T.SLATE_600}; border: none;")

        tag_val = QLabel("localhost:8000")
        tag_val.setFont(T.get_font(10, mono=True))
        tag_val.setStyleSheet(f"color: {T.NAVY_900}; border: none;")

        tag_layout.addWidget(tag_lbl)
        tag_layout.addWidget(tag_val)
        layout.addWidget(tag_box)

        # Connection status badge
        self._conn_badge = StatusBadge("connected", "CONNECTED (LOCAL API)")
        layout.addWidget(self._conn_badge)

        # Live Sync Time
        self._sync_lbl = QLabel(f"Sync: {datetime.now().strftime('%H:%M:%S')}")
        self._sync_lbl.setFont(T.get_font(11, mono=True))
        self._sync_lbl.setStyleSheet(f"color: {T.NAVY_900};")
        layout.addWidget(self._sync_lbl)

        # Quick refresh button
        self._refresh_btn = QPushButton()
        self._refresh_btn.setFixedSize(28, 28)
        self._refresh_btn.setToolTip("Refresh Application Data")
        
        # Draw clean reload icon directly on pixmap
        pix = QPixmap(16, 16)
        pix.fill(Qt.GlobalColor.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor(T.NAVY_900))
        pen.setWidthF(1.8)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        p.drawArc(QRectF(2.5, 2.5, 11, 11), int(45 * 16), int(270 * 16))
        p.drawLine(QPointF(13.5, 7.5), QPointF(10.5, 5.0))
        p.drawLine(QPointF(13.5, 7.5), QPointF(13.0, 11.0))
        p.end()
        self._refresh_btn.setIcon(QIcon(pix))
        self._refresh_btn.setIconSize(QSize(16, 16))
        self._refresh_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {T.WHITE};
                border: 1px solid {T.SLATE_300};
                border-radius: {T.BORDER_RADIUS_SM}px;
            }}
            QPushButton:hover {{
                background-color: {T.GREY_100};
                border: 1px solid {T.SLATE_400};
            }}
        """)
        self._refresh_btn.clicked.connect(self.refresh_requested.emit)
        layout.addWidget(self._refresh_btn)

        # Global Export Data Action
        self._export_btn = QPushButton("⤓ Export")
        self._export_btn.setFixedHeight(28)
        self._export_btn.setToolTip("Export Security Event Data")
        self._export_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {T.WHITE};
                border: 1px solid {T.SLATE_300};
                border-radius: {T.BORDER_RADIUS_SM}px;
                color: {T.NAVY_900};
                padding: 0 10px;
                font-size: 11.5px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {T.GREY_100};
                border: 1px solid {T.SLATE_400};
            }}
        """)
        self._export_btn.clicked.connect(self.export_requested.emit)
        layout.addWidget(self._export_btn)

        # Topbar Global Quick Search
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search events...")
        self._search_input.setFixedWidth(160)
        self._search_input.setFixedHeight(28)
        self._search_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {T.WHITE};
                border: 1px solid {T.SLATE_300};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 2px 8px;
                font-size: 11.5px;
            }}
            QLineEdit:focus {{
                border: 1px solid {T.BLUE_600};
            }}
        """)
        self._search_input.returnPressed.connect(
            lambda: self.search_submitted.emit(self._search_input.text().strip())
        )
        layout.addWidget(self._search_input)

        # Native Live Traffic Simulation Toggle (Starts OFF in standby)
        self._sim_btn = QPushButton("○ TRAFFIC SIMULATOR: OFF")
        self._sim_btn.setFixedHeight(28)
        self._sim_btn.setToolTip("Replay the bundled demo corpus into live ingestion (offered load; the EPS shown is what the engine actually completes)")
        self._update_sim_btn_style(False)
        self._sim_btn.clicked.connect(self.sim_toggled.emit)
        layout.addWidget(self._sim_btn)

    def set_sim_state(self, active: bool):
        self._update_sim_btn_style(active)

    def _update_sim_btn_style(self, active: bool):
        if active:
            self._sim_btn.setText("● TRAFFIC SIMULATOR: ON")
            self._sim_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: #ECFDF5;
                    border: 1px solid #10B981;
                    border-radius: {T.BORDER_RADIUS_SM}px;
                    color: #047857;
                    padding: 0 10px;
                    font-size: 11px;
                    font-weight: 700;
                }}
                QPushButton:hover {{
                    background-color: #D1FAE5;
                }}
            """)
        else:
            self._sim_btn.setText("○ TRAFFIC SIMULATOR: OFF")
            self._sim_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {T.WHITE};
                    border: 1px solid {T.SLATE_300};
                    border-radius: {T.BORDER_RADIUS_SM}px;
                    color: {T.SLATE_600};
                    padding: 0 10px;
                    font-size: 11px;
                    font-weight: 600;
                }}
                QPushButton:hover {{
                    background-color: {T.GREY_100};
                }}
            """)

    def set_page(self, title: str, subtitle: str = ""):
        self._title.setText(title)
        self._subtitle.setText(subtitle)

    def set_engine_status(self, status: str):
        self._conn_badge.set_status(status)

    def update_sync_time(self):
        self._sync_lbl.setText(f"Sync: {datetime.now().strftime('%H:%M:%S')}")


# ── Main Window Shell ─────────────────────────────────────────────────

class ULPFMainWindow(QMainWindow):
    """
    Primary desktop application window combining the Sidebar, TopBar, and
    Page Workspace. Matches the institutional security console layout.
    """

    ingest_notification = Signal()

    def __init__(self, service: ULPFService):
        super().__init__()
        self.service = service

        self.setWindowTitle("ULPF — Universal Log Pre-processing Framework")
        self.setMinimumSize(1260, 800)
        self.resize(1440, 920)

        # Set application / window icon from the packaged GUI resources
        import os
        icon_path = os.path.join(os.path.dirname(__file__), "resources", "ulpf_icon.ico")
        if os.path.exists(icon_path):
            ico = QIcon(icon_path)
            self.setWindowIcon(ico)
            app = QApplication.instance()
            if app:
                app.setWindowIcon(ico)

        # Real-time event ingestion listener with high-speed debouncing
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.setInterval(500)  # Throttled to 2 FPS for silky-smooth UI and zero DB contention
        self._refresh_timer.timeout.connect(self._do_throttled_refresh)

        self.ingest_notification.connect(self._queue_refresh)
        if hasattr(self.service, "set_on_ingest_callback"):
            self.service.set_on_ingest_callback(lambda: self.ingest_notification.emit())

        # Main horizontal layout: Sidebar on left, right workspace on right
        central = QWidget()
        central.setObjectName("centralWidget")
        central.setStyleSheet(f"#centralWidget {{ background-color: {T.GREY_100}; }}")
        central_layout = QHBoxLayout(central)
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.setSpacing(0)

        # Sidebar
        self.sidebar = Sidebar()
        self.sidebar.nav_selected.connect(self.navigate_to)
        central_layout.addWidget(self.sidebar)

        # Right workspace: TopBar + Page Container
        right_panel = QWidget()
        right_panel.setObjectName("rightPanel")
        right_panel.setStyleSheet(f"#rightPanel {{ background-color: {T.GREY_100}; }}")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        self.topbar = TopBar()
        self.topbar.refresh_requested.connect(self._on_refresh)
        self.topbar.export_requested.connect(self._on_export)
        self.topbar.search_submitted.connect(self._on_global_search)
        self.topbar.sim_toggled.connect(self._on_toggle_sim)
        right_layout.addWidget(self.topbar)

        self.page_stack = QStackedWidget()
        self.page_stack.setStyleSheet(f"background-color: {T.GREY_100};")
        right_layout.addWidget(self.page_stack, 1)

        central_layout.addWidget(right_panel, 1)
        self.setCentralWidget(central)

        # Build pages
        self._pages: dict[str, QWidget] = {}
        self._build_pages()

        # Timers for health polling & sync clock (1-second live UI telemetry)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_tick)
        self._timer.start(1000)

        # Initial view
        self.navigate_to("overview")
        self._update_engine_status()

    def _build_pages(self):
        from ulpf.gui.pages.overview import OverviewPage
        from ulpf.gui.pages.ingestion import IngestionPage
        from ulpf.gui.pages.explorer import ExplorerPage
        from ulpf.gui.pages.parsers import ParsersPage
        from ulpf.gui.pages.autolearn import AutoLearnPage
        from ulpf.gui.pages.logdna import LogDNAPage
        from ulpf.gui.pages.correlation import CorrelationPage
        from ulpf.gui.pages.anomalies import AnomaliesPage
        from ulpf.gui.pages.forensics import ForensicsPage
        from ulpf.gui.pages.schema import SchemaPage

        page_map = {
            "overview":    OverviewPage,
            "ingestion":   IngestionPage,
            "events":      ExplorerPage,
            "parsers":     ParsersPage,
            "autolearn":   AutoLearnPage,
            "logdna":      LogDNAPage,
            "correlation": CorrelationPage,
            "anomalies":   AnomaliesPage,
            "forensics":   ForensicsPage,
            "schema":      SchemaPage,
        }

        for key, cls in page_map.items():
            page_inst = cls(self.service)
            page_inst.setStyleSheet(f"background-color: {T.GREY_100};")
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setWidget(page_inst)
            scroll.setStyleSheet(f"""
                QScrollArea, QScrollArea > QWidget, QScrollArea > QWidget > QWidget {{
                    background-color: {T.GREY_100};
                    border: none;
                }}
            """)
            self.page_stack.addWidget(scroll)
            self._pages[key] = scroll

    def navigate_to(self, key: str):
        self._current_key = key
        page = self._pages.get(key)
        if page:
            self.page_stack.setCurrentWidget(page)
            self.sidebar.set_active(key)
            title, subtitle = PAGE_TITLES.get(key, (key.title(), ""))
            self.topbar.set_page(title, subtitle)

            inner = page.widget()
            if hasattr(inner, "refresh"):
                inner.refresh()

    def _update_engine_status(self):
        state = self.service.state.lower()
        badge_state = "connected" if state == "running" else state
        self.sidebar.set_engine_status(badge_state)
        self.topbar.set_engine_status(badge_state)

    def _on_tick(self):
        self.topbar.update_sync_time()
        self._update_engine_status()
        self._on_refresh()

    def _queue_refresh(self):
        """Enqueue a throttled refresh safely from background threads."""
        from PySide6.QtCore import QMetaObject, Qt
        # Check isActive() is technically not thread-safe, but it's safe enough to prevent flooding
        if not self._refresh_timer.isActive():
            QMetaObject.invokeMethod(self._refresh_timer, "start", Qt.QueuedConnection)

    def _do_throttled_refresh(self):
        """Perform throttled UI refresh without blocking the GUI event loop."""
        try:
            cur = self.page_stack.currentWidget()
            if cur and hasattr(cur, "widget"):
                inner = cur.widget()
                if hasattr(inner, "refresh"):
                    inner.refresh()
            self.topbar.update_sync_time()
        except Exception as e:
            pass

    def _on_refresh(self, force_all: bool = False):
        try:
            if force_all:
                for scroll in self._pages.values():
                    inner = scroll.widget()
                    if hasattr(inner, "refresh"):
                        inner.refresh()
            else:
                cur = self.page_stack.currentWidget()
                if cur and hasattr(cur, "widget"):
                    inner = cur.widget()
                    if hasattr(inner, "refresh"):
                        inner.refresh()
        except Exception as e:
            pass

    def _on_toggle_sim(self):
        if hasattr(self.service, "toggle_traffic_simulation"):
            active = self.service.toggle_traffic_simulation()
            self.topbar.set_sim_state(active)

    def _on_export(self):
        # Switch to storage or trigger export
        self.navigate_to("events")

    def _on_global_search(self, query: str):
        if not query:
            return
        self.navigate_to("events")
        explorer_scroll = self._pages.get("events")
        if explorer_scroll:
            explorer_page = explorer_scroll.widget()
            if hasattr(explorer_page, "set_search_query"):
                explorer_page.set_search_query(query)

    def closeEvent(self, event: QCloseEvent):
        try:
            self._timer.stop()
            self.service.shutdown()
        except Exception:
            pass
        event.accept()


# Alias for compatibility
MainWindow = ULPFMainWindow
