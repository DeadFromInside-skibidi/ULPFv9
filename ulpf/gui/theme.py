"""
ULPF Desktop Theme System
===========================
Translates the ULPF web design tokens (variables.css, components.css, styles.css)
into native Qt colors, fonts, dimensions, and comprehensive application styling.
"""
from __future__ import annotations

from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QApplication, QPushButton

# ── Brand & Shell Colors (Exact variables.css) ────────────────────────
NAVY_900 = "#19314C"
NAVY_800 = "#244765"
NAVY_700 = "#315D7D"
BLUE_600 = "#2F6F9F"
BLUE_500 = "#3b82b6"
BLUE_50  = "#eef5fa"

# ── Neutral Palette ───────────────────────────────────────────────────
SLATE_800 = "#1E293B"
SLATE_700 = "#334155"
SLATE_600 = "#536579"
SLATE_500 = "#64748B"
SLATE_400 = "#8A99A8"
SLATE_300 = "#b1bdca"
SLATE_100 = "#F1F5F9"
GREY_200  = "#E6EBF0"
GREY_150  = "#ebf0f4"
GREY_100  = "#F2F5F7"
GREY_50   = "#f8fafc"
WHITE     = "#FFFFFF"

# ── Semantic Status Colors ────────────────────────────────────────────
SUCCESS     = "#2F7D5A"
SUCCESS_BG  = "rgba(47, 125, 90, 0.08)"
SUCCESS_BD  = "rgba(47, 125, 90, 0.25)"

WARNING     = "#B7791F"
WARNING_BG  = "rgba(183, 121, 31, 0.08)"
WARNING_BD  = "rgba(183, 121, 31, 0.25)"

CRITICAL    = "#B23A48"
CRITICAL_BG = "rgba(178, 58, 72, 0.08)"
CRITICAL_BD = "rgba(178, 58, 72, 0.25)"

INFO        = "#2F6F9F"
INFO_BG     = "rgba(47, 111, 159, 0.08)"
INFO_BD     = "rgba(47, 111, 159, 0.25)"

# ── Layout Dimensions ─────────────────────────────────────────────────
SIDEBAR_WIDTH     = 256
TOPBAR_HEIGHT     = 56
BORDER_RADIUS     = 4
BORDER_RADIUS_SM  = 3
BORDER_RADIUS_MD  = 6

# ── Typography ────────────────────────────────────────────────────────
FONT_SANS = "Segoe UI"
FONT_MONO = "Consolas"

FONT_SIZE_PAGE_TITLE    = 20
FONT_SIZE_SECTION_TITLE = 15
FONT_SIZE_SUBHEAD       = 13.5
FONT_SIZE_BODY          = 13
FONT_SIZE_META          = 11
FONT_SIZE_TECH          = 11.5

# ── Severity colors ───────────────────────────────────────────────────
def get_severity_color(lvl: int) -> str:
    if lvl >= 8:
        return "#B23A48"  # Critical red
    if lvl >= 4:
        return "#B7791F"  # Warning amber
    if lvl >= 1:
        return "#2F7D5A"  # Healthy green
    return "#8A99A8"      # Grey / unknown


def get_font(size: int = FONT_SIZE_BODY, bold: bool = False,
             mono: bool = False) -> QFont:
    family = FONT_MONO if mono else FONT_SANS
    font = QFont(family, size)
    if bold:
        font.setBold(True)
    return font


# ── Complete Master Application Stylesheet ────────────────────────────
APP_STYLESHEET = f"""
/* Global Reset */
QWidget {{
    font-family: "{FONT_SANS}", "Segoe UI", -apple-system, sans-serif;
    font-size: {FONT_SIZE_BODY}px;
    color: {NAVY_900};
}}

QMainWindow, QStackedWidget, QScrollArea, QScrollArea > QWidget, QScrollArea > QWidget > QWidget {{
    background-color: {GREY_100};
}}

/* Clean Custom Scrollbars */
QScrollBar:vertical {{
    border: none;
    background: {GREY_100};
    width: 8px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {SLATE_300};
    min-height: 24px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical:hover {{
    background: {SLATE_400};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    border: none;
    background: {GREY_100};
    height: 8px;
    margin: 0;
}}
QScrollBar::handle:horizontal {{
    background: {SLATE_300};
    min-width: 24px;
    border-radius: 4px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

/* Cards */
#SectionCard {{
    background-color: {WHITE};
    border: 1px solid {GREY_200};
    border-radius: {BORDER_RADIUS}px;
}}

#MetricCard {{
    background-color: {WHITE};
    border: 1px solid {GREY_200};
    border-radius: {BORDER_RADIUS}px;
}}

/* Buttons */
QPushButton {{
    font-family: "{FONT_SANS}", "Segoe UI", sans-serif;
    font-size: 13px;
    font-weight: 600;
    padding: 6px 14px;
    border-radius: {BORDER_RADIUS}px;
    border: 1px solid {GREY_200};
    background-color: {WHITE};
    color: {NAVY_800};
}}
QPushButton:hover {{
    background-color: {GREY_100};
    border-color: {SLATE_400};
}}
QPushButton:pressed {{
    background-color: {GREY_200};
}}
QPushButton:disabled {{
    opacity: 0.55;
    color: {SLATE_400};
}}

/* Primary Dark Navy Button */
QPushButton[btnClass="primary"] {{
    background-color: {NAVY_800};
    color: {WHITE};
    border: 1px solid {NAVY_900};
}}
QPushButton[btnClass="primary"]:hover {{
    background-color: {NAVY_700};
}}
QPushButton[btnClass="primary"]:pressed {{
    background-color: {NAVY_900};
}}
QPushButton[btnClass="primary"]:disabled {{
    background-color: #E2E8F0;
    color: #94A3B8;
    border: 1px solid #CBD5E1;
}}

/* Secondary / Light Button */
QPushButton[btnClass="secondary"] {{
    background-color: {GREY_100};
    color: {NAVY_900};
    border: 1px solid {SLATE_400};
}}
QPushButton[btnClass="secondary"]:hover {{
    background-color: {GREY_200};
    border-color: {SLATE_600};
}}

/* Outline Button */
QPushButton[btnClass="outline"] {{
    background-color: transparent;
    color: {NAVY_800};
    border: 1px solid {GREY_200};
}}
QPushButton[btnClass="outline"]:hover {{
    background-color: {GREY_100};
    border-color: {SLATE_400};
}}
QPushButton[btnClass="outline"]:disabled {{
    background-color: transparent;
    color: #CBD5E1;
    border: 1px solid #E2E8F0;
}}

/* Danger Button */
QPushButton[btnClass="danger"] {{
    background-color: {CRITICAL_BG};
    color: {CRITICAL};
    border: 1px solid {CRITICAL_BD};
}}

/* Tables */
QTableView {{
    background-color: {WHITE};
    alternate-background-color: {GREY_50};
    border: 1px solid {GREY_200};
    border-radius: {BORDER_RADIUS}px;
    gridline-color: {GREY_200};
    selection-background-color: {BLUE_50};
    selection-color: {NAVY_900};
    outline: none;
}}
QHeaderView::section {{
    background-color: {GREY_100};
    color: {SLATE_600};
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    padding: 8px 12px;
    border: none;
    border-bottom: 2px solid {GREY_200};
    text-align: left;
}}

/* Form Inputs */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {{
    background-color: {WHITE};
    border: 1px solid {SLATE_400};
    border-radius: {BORDER_RADIUS}px;
    padding: 4px 8px;
    font-size: 12px;
    color: {NAVY_900};
}}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QComboBox:focus {{
    border: 1.5px solid {BLUE_600};
}}
QComboBox::drop-down {{
    border: none;
    border-left: 1px solid {GREY_200};
    width: 20px;
}}
"""


def set_button_class(btn: QPushButton, btn_class: str) -> None:
    """Safely apply button class with explicit styles and unpolish/polish."""
    btn.setProperty("btnClass", btn_class)
    if btn_class == "primary":
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {NAVY_800};
                color: {WHITE};
                border: 1px solid {NAVY_900};
                font-weight: 700;
                padding: 6px 14px;
                border-radius: {BORDER_RADIUS_SM}px;
            }}
            QPushButton:hover {{
                background-color: {NAVY_700};
            }}
            QPushButton:pressed {{
                background-color: {NAVY_900};
            }}
            QPushButton:disabled {{
                background-color: #CBD5E1;
                color: #64748B;
                border: 1px solid #94A3B8;
            }}
        """)
    elif btn_class == "secondary":
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {GREY_100};
                color: {NAVY_900};
                border: 1px solid {SLATE_400};
                font-weight: 600;
                padding: 6px 14px;
                border-radius: {BORDER_RADIUS_SM}px;
            }}
            QPushButton:hover {{
                background-color: {GREY_200};
                border-color: {SLATE_600};
            }}
        """)
    elif btn_class == "outline":
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {WHITE};
                color: {NAVY_800};
                border: 1px solid {SLATE_300};
                font-weight: 600;
                padding: 6px 14px;
                border-radius: {BORDER_RADIUS_SM}px;
            }}
            QPushButton:hover {{
                background-color: {GREY_100};
                border-color: {SLATE_400};
            }}
        """)
    try:
        btn.style().unpolish(btn)
        btn.style().polish(btn)
    except Exception:
        pass

