"""
ULPF Reusable Widget Library — Institutional Design System
============================================================
Pixel-faithful components matching the ULPF screenshots and PDF specifications.
"""
from __future__ import annotations

from typing import Any
from PySide6.QtCore import Qt, Signal, QSize, QMimeData, QRect, QRectF, QPointF, QModelIndex
from PySide6.QtGui import QColor, QFont, QPainter, QBrush, QPen, QPainterPath, QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QWidget, QLabel, QHBoxLayout, QVBoxLayout, QFrame,
    QSizePolicy, QPushButton, QLineEdit, QProgressBar,
    QTableView, QTableWidget, QHeaderView, QAbstractItemView, QComboBox,
    QDialog, QDialogButtonBox, QStyledItemDelegate, QStyleOptionViewItem, QStyle,
)

from ulpf.gui import theme as T


# ── VectorIcon ────────────────────────────────────────────────────────

class VectorIcon(QWidget):
    """
    Native vector-drawn institutional icon.
    Renders cleanly and sharply without depending on OS emoji fonts.
    """

    def __init__(self, icon_type: str, size: int = 36, color: str = T.NAVY_900, parent=None):
        super().__init__(parent)
        self.icon_type = icon_type.lower()
        self.icon_size = size
        self.color = color
        self.setFixedSize(size, size)
        self.setStyleSheet("background: transparent; border: none;")

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor(self.color))
        pen.setWidthF(max(2.0, self.icon_size / 14.0))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        w = float(self.width())
        h = float(self.height())
        pad = w * 0.12

        if self.icon_type == "document":
            p = QPainterPath()
            p.moveTo(pad, pad)
            p.lineTo(w - pad - w*0.28, pad)
            p.lineTo(w - pad, pad + h*0.28)
            p.lineTo(w - pad, h - pad)
            p.lineTo(pad, h - pad)
            p.closeSubpath()
            painter.drawPath(p)
            painter.drawLine(QPointF(w - pad - w*0.28, pad), QPointF(w - pad - w*0.28, pad + h*0.28))
            painter.drawLine(QPointF(w - pad - w*0.28, pad + h*0.28), QPointF(w - pad, pad + h*0.28))

        elif self.icon_type == "server":
            chassis_h = (h - 3 * pad) / 2.0
            r1 = QRectF(pad, pad, w - 2*pad, chassis_h)
            painter.drawRoundedRect(r1, 4, 4)
            painter.drawEllipse(QPointF(pad + 8, pad + chassis_h/2.0), 1.8, 1.8)
            painter.drawEllipse(QPointF(pad + 16, pad + chassis_h/2.0), 1.8, 1.8)
            r2 = QRectF(pad, pad + chassis_h + pad*0.5, w - 2*pad, chassis_h)
            painter.drawRoundedRect(r2, 4, 4)
            painter.drawEllipse(QPointF(pad + 8, pad + chassis_h + pad*0.5 + chassis_h/2.0), 1.8, 1.8)
            painter.drawEllipse(QPointF(pad + 16, pad + chassis_h + pad*0.5 + chassis_h/2.0), 1.8, 1.8)

        elif self.icon_type == "code":
            painter.drawLine(QPointF(w*0.35, h*0.25), QPointF(w*0.16, h*0.5))
            painter.drawLine(QPointF(w*0.16, h*0.5), QPointF(w*0.35, h*0.75))
            painter.drawLine(QPointF(w*0.42, h*0.8), QPointF(w*0.58, h*0.2))
            painter.drawLine(QPointF(w*0.65, h*0.25), QPointF(w*0.84, h*0.5))
            painter.drawLine(QPointF(w*0.84, h*0.5), QPointF(w*0.65, h*0.75))

        elif self.icon_type in ("sunburst", "autolearn"):
            cx, cy = w / 2.0, h / 2.0
            import math
            inner_r = w * 0.22
            outer_r = w * 0.44
            for i in range(8):
                angle = i * (math.pi / 4.0)
                x1 = cx + inner_r * math.cos(angle)
                y1 = cy + inner_r * math.sin(angle)
                x2 = cx + outer_r * math.cos(angle)
                y2 = cy + outer_r * math.sin(angle)
                painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))

        elif self.icon_type in ("dna", "helix"):
            import math
            cx, cy = w / 2.0, h / 2.0
            steps = 18
            pts1, pts2 = [], []
            for i in range(steps + 1):
                t = i / float(steps)
                y = pad + t * (h - 2*pad)
                x_off = (w*0.3) * math.sin(t * 2 * math.pi)
                pts1.append(QPointF(cx + x_off, y))
                pts2.append(QPointF(cx - x_off, y))
            for i in range(len(pts1)-1):
                painter.drawLine(pts1[i], pts1[i+1])
                painter.drawLine(pts2[i], pts2[i+1])
            for i in (3, 6, 9, 12, 15):
                painter.drawLine(pts1[i], pts2[i])

        elif self.icon_type in ("nodes", "correlation"):
            n1 = QPointF(w*0.28, h*0.5)
            n2 = QPointF(w*0.75, h*0.25)
            n3 = QPointF(w*0.75, h*0.75)
            painter.drawLine(n1, n2)
            painter.drawLine(n1, n3)
            painter.setBrush(QBrush(QColor(self.color)))
            r = w * 0.12
            painter.drawEllipse(n1, r, r)
            painter.drawEllipse(n2, r, r)
            painter.drawEllipse(n3, r, r)

        elif self.icon_type in ("chain", "forensics"):
            pen.setWidthF(max(2.6, self.icon_size / 9.0))
            painter.setPen(pen)
            painter.save()
            painter.translate(w*0.38, h*0.42)
            painter.rotate(-45)
            painter.drawRoundedRect(QRectF(-w*0.26, -h*0.14, w*0.52, h*0.28), 6, 6)
            painter.restore()
            painter.save()
            painter.translate(w*0.62, h*0.58)
            painter.rotate(-45)
            painter.drawRoundedRect(QRectF(-w*0.26, -h*0.14, w*0.52, h*0.28), 6, 6)
            painter.restore()

        elif self.icon_type in ("magnifier", "search"):
            r = w * 0.26
            cx, cy = w*0.42, h*0.42
            painter.drawEllipse(QPointF(cx, cy), r, r)
            import math
            x1 = cx + r * math.cos(math.pi / 4.0)
            y1 = cy + r * math.sin(math.pi / 4.0)
            painter.drawLine(QPointF(x1, y1), QPointF(w - pad, h - pad))

        elif self.icon_type in ("alert_circle", "drift"):
            cx, cy = w / 2.0, h / 2.0
            r = (w - 2*pad) / 2.0
            painter.drawEllipse(QPointF(cx, cy), r, r)
            painter.drawLine(QPointF(cx, cy - r*0.5), QPointF(cx, cy + r*0.15))
            painter.setBrush(QBrush(QColor(self.color)))
            painter.drawEllipse(QPointF(cx, cy + r*0.5), 1.8, 1.8)

        elif self.icon_type in ("grid", "brand", "mark"):
            # Outer chassis
            r_outer = QRectF(1.0, 1.0, w - 2.0, h - 2.0)
            painter.setPen(QPen(QColor(T.NAVY_700), 1.0))
            painter.setBrush(QBrush(QColor(T.NAVY_800)))
            painter.drawRoundedRect(r_outer, 5.0, 5.0)

            # 4 squares
            gap = 3.0
            margin = pad + 1.0
            sq_w = (w - 2.0 * margin - gap) / 2.0
            sq_h = (h - 2.0 * margin - gap) / 2.0
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(QColor(T.BLUE_500)))
            painter.drawRoundedRect(QRectF(margin, margin, sq_w, sq_h), 1.5, 1.5)
            painter.drawRoundedRect(QRectF(margin + sq_w + gap, margin, sq_w, sq_h), 1.5, 1.5)
            painter.drawRoundedRect(QRectF(margin, margin + sq_h + gap, sq_w, sq_h), 1.5, 1.5)
            painter.drawRoundedRect(QRectF(margin + sq_w + gap, margin + sq_h + gap, sq_w, sq_h), 1.5, 1.5)

        elif self.icon_type == "reload":
            cx, cy = w / 2.0, h / 2.0
            r = (w - 2*pad) / 2.0
            painter.drawArc(QRectF(pad, pad, 2*r, 2*r), int(45 * 16), int(270 * 16))
            painter.drawLine(QPointF(w - pad, cy), QPointF(w - pad - 4, cy - 4))
            painter.drawLine(QPointF(w - pad, cy), QPointF(w - pad + 3, cy - 4))


# ── MetricCard ────────────────────────────────────────────────────────

class MetricCard(QFrame):
    """
    Dashboard metric card matching the institutional design.
    Features: uppercase title + icon header, 28px bold value, and metadata subtitle.
    Optionally includes an accent bar on the left.
    """

    def __init__(self, title: str, value: Any = "0",
                 subtitle: str = "", trend: str = "",
                 icon_text: str = "", accent_color: str | None = None, parent=None):
        super().__init__(parent)
        self._raw_title = title
        self.setObjectName("MetricCard")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.setMinimumHeight(116)

        # If trend is passed instead of icon_text, or icon_text is specified
        if trend and not icon_text and len(trend) <= 4:
            icon_text = trend

        border_style = f"border-left: 3px solid {accent_color};" if accent_color else ""
        self.setStyleSheet(f"""
            #MetricCard {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                {border_style}
                border-radius: {T.BORDER_RADIUS}px;
                padding: 12px 16px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)

        # Header: Label on left, subtle icon on right
        header_row = QHBoxLayout()
        header_row.setContentsMargins(0, 0, 0, 0)

        self._title = QLabel(str(title).upper())
        self._title.setFont(T.get_font(10, bold=True))
        self._title.setStyleSheet(f"color: {T.SLATE_400}; letter-spacing: 0.06em; border: none; background: transparent;")
        header_row.addWidget(self._title)
        header_row.addStretch()

        if icon_text:
            icon_lbl = QLabel(icon_text)
            icon_lbl.setFont(T.get_font(12))
            icon_lbl.setStyleSheet(f"color: {T.SLATE_400}; border: none; background: transparent;")
            header_row.addWidget(icon_lbl)

        layout.addLayout(header_row)

        # Value: 24px Bold Navy
        self._value = QLabel(str(value))
        self._value.setFont(T.get_font(22, bold=True))
        self._value.setStyleSheet(f"color: {T.NAVY_900}; border: none; background: transparent;")
        layout.addWidget(self._value)

        # Subtitle: 11px Slate
        self._subtitle = QLabel(str(subtitle))
        self._subtitle.setFont(T.get_font(T.FONT_SIZE_META))
        self._subtitle.setStyleSheet(f"color: {T.SLATE_400}; border: none; background: transparent;")
        layout.addWidget(self._subtitle)

    @property
    def title(self) -> str:
        return self._raw_title

    @property
    def value(self) -> str:
        return self._value.text()

    @property
    def subtitle(self) -> str:
        return self._subtitle.text()

    def set_value(self, value: Any):
        self._value.setText(str(value))

    def set_subtitle(self, text: str):
        self._subtitle.setText(str(text))


# ── StatusBadge ───────────────────────────────────────────────────────

class StatusBadge(QLabel):
    """Pill status badge with colored dot."""

    STATUS_STYLES = {
        "healthy":     (T.SUCCESS,  T.SUCCESS_BG, T.SUCCESS_BD),
        "connected":   (T.SUCCESS,  T.SUCCESS_BG, T.SUCCESS_BD),
        "running":     (T.SUCCESS,  T.SUCCESS_BG, T.SUCCESS_BD),
        "operational": (T.SUCCESS,  T.SUCCESS_BG, T.SUCCESS_BD),
        "online":      (T.SUCCESS,  T.SUCCESS_BG, T.SUCCESS_BD),
        "verified":    (T.SUCCESS,  T.SUCCESS_BG, T.SUCCESS_BD),
        "stopped":     (T.SLATE_400, T.GREY_100,  T.GREY_200),
        "warning":     (T.WARNING,  T.WARNING_BG, T.WARNING_BD),
        "error":       (T.CRITICAL, T.CRITICAL_BG, T.CRITICAL_BD),
        "critical":    (T.CRITICAL, T.CRITICAL_BG, T.CRITICAL_BD),
        "info":        (T.INFO,     T.INFO_BG,    T.INFO_BD),
    }

    def __init__(self, status: str = "connected", text: str = "", dark: bool = False, parent=None):
        super().__init__(parent)
        self._dark = dark
        self._status = status
        self._custom_text = text
        self.set_status(status, text)

    @property
    def status(self) -> str:
        return self._status

    def set_status(self, status: str, text: str = ""):
        self._status = status
        status_lower = status.lower()
        if self._dark:
            if status_lower in ("healthy", "connected", "running", "operational", "online", "verified"):
                fg, bg, bd = "#34D399", "rgba(16, 185, 129, 0.18)", "rgba(16, 185, 129, 0.35)"
            elif status_lower in ("warning",):
                fg, bg, bd = "#FBBF24", "rgba(245, 158, 11, 0.18)", "rgba(245, 158, 11, 0.35)"
            elif status_lower in ("error", "critical"):
                fg, bg, bd = "#F87171", "rgba(239, 68, 68, 0.18)", "rgba(239, 68, 68, 0.35)"
            else:
                fg, bg, bd = T.SLATE_400, "rgba(255, 255, 255, 0.08)", "rgba(255, 255, 255, 0.15)"
        else:
            fg, bg, bd = self.STATUS_STYLES.get(status_lower, (T.SLATE_600, T.GREY_100, T.GREY_200))
        display_text = text or status.upper()

        self.setText(f"● {display_text}")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {bg};
                color: {fg};
                border: 1px solid {bd};
                border-radius: 11px;
                padding: 3px 10px;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 0.04em;
            }}
        """)


# ── PillBadge ─────────────────────────────────────────────────────────

class PillBadge(QLabel):
    """Subtle neutral count/category pill (e.g. '1 FORMATS', '2 CATEGORIES')."""

    def __init__(self, text: str, parent=None):
        super().__init__(parent)
        self.setText(text.upper())
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedHeight(22)
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {T.GREY_50};
                color: {T.SLATE_600};
                border: 1px solid {T.SLATE_300};
                border-radius: {T.BORDER_RADIUS_SM}px;
                padding: 2px 8px;
                font-size: 10.5px;
                font-weight: 600;
                letter-spacing: 0.04em;
            }}
        """)


# ── SeverityPill ──────────────────────────────────────────────────────

class SeverityPill(QLabel):
    """Solid colored severity indicator (e.g. Red 10, Amber 7, Green 3)."""

    def __init__(self, level: int | str, parent=None):
        super().__init__(parent)
        self.set_level(level)

    def set_level(self, level: int | str):
        try:
            lvl = int(level)
        except (ValueError, TypeError):
            lvl = 0

        color = T.get_severity_color(lvl)
        self.setText(str(lvl))
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedSize(24, 20)
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {color};
                color: {T.WHITE};
                font-weight: 700;
                font-size: 11px;
                border-radius: {T.BORDER_RADIUS_SM}px;
            }}
        """)


# ── FormatBadge ───────────────────────────────────────────────────────

class FormatBadge(QLabel):
    """Format pill badge (e.g. 'CEF', 'JSON', 'SYSLOG')."""

    def __init__(self, format_name: str, parent=None):
        super().__init__(parent)
        self.setText(str(format_name).upper())
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {T.GREY_50};
                color: {T.NAVY_900};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS_SM}px;
                padding: 2px 7px;
                font-size: 11px;
                font-weight: 600;
                font-family: "{T.FONT_MONO}", monospace;
            }}
        """)


# ── SectionCard ───────────────────────────────────────────────────────

class SectionCard(QFrame):
    """Standard white card container with structured header and body."""

    def __init__(self, title: str = "", right_widget: QWidget | None = None, parent=None):
        super().__init__(parent)
        self.setObjectName("SectionCard")
        self.setStyleSheet(f"""
            #SectionCard {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
            }}
        """)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Header row if title is provided
        if title:
            header_frame = QFrame()
            header_frame.setStyleSheet(f"""
                border: none;
                border-bottom: 1px solid {T.GREY_200};
                padding: 12px 18px;
                background-color: transparent;
            """)
            header_layout = QHBoxLayout(header_frame)
            header_layout.setContentsMargins(18, 12, 18, 12)

            self._title_lbl = QLabel(title)
            self._title_lbl.setFont(T.get_font(T.FONT_SIZE_SECTION_TITLE, bold=True))
            self._title_lbl.setStyleSheet(f"color: {T.NAVY_900}; border: none;")
            header_layout.addWidget(self._title_lbl)
            header_layout.addStretch()

            if right_widget:
                header_layout.addWidget(right_widget, 0, Qt.AlignmentFlag.AlignVCenter)

            main_layout.addWidget(header_frame)

        # Body container
        self._body = QWidget()
        self._body.setStyleSheet("border: none; background: transparent;")
        self._body_layout = QVBoxLayout(self._body)
        self._body_layout.setContentsMargins(18, 18, 18, 18)
        self._body_layout.setSpacing(12)
        main_layout.addWidget(self._body)

    def setTitle(self, title: str):
        if hasattr(self, "_title_lbl"):
            self._title_lbl.setText(title)

    def content_layout(self) -> QVBoxLayout:
        return self._body_layout


# ── SeverityHistogram ─────────────────────────────────────────────────

class SeverityHistogram(QWidget):
    """
    11-column vertical bar chart representing severity levels 0 through 10.
    Direct reproduction of the histogram from the reference photos.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(0, 8, 0, 0)
        self._layout.setSpacing(6)
        self._bars: list[dict] = []
        self._build_columns()

    def _build_columns(self):
        for lvl in range(11):
            col = QVBoxLayout()
            col.setContentsMargins(0, 0, 0, 0)
            col.setSpacing(4)
            col.setAlignment(Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignHCenter)

            # Count on top
            count_lbl = QLabel("")
            count_lbl.setFont(T.get_font(10, bold=True, mono=True))
            count_lbl.setStyleSheet(f"color: {T.SLATE_600}; border: none;")
            count_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            col.addWidget(count_lbl)

            # Track + fill bar
            track = QFrame()
            track.setFixedWidth(28)
            track.setFixedHeight(72)
            track.setStyleSheet(f"background-color: {T.GREY_150}; border-radius: 3px; border: none;")

            track_layout = QVBoxLayout(track)
            track_layout.setContentsMargins(0, 0, 0, 0)
            track_layout.setAlignment(Qt.AlignmentFlag.AlignBottom)

            bar_fill = QFrame()
            bar_fill.setFixedWidth(28)
            bar_fill.setFixedHeight(0)
            bar_color = T.get_severity_color(lvl)
            bar_fill.setStyleSheet(f"background-color: {bar_color}; border-radius: 3px; border: none;")
            bar_fill.setVisible(False)
            track_layout.addWidget(bar_fill)

            col.addWidget(track)

            # Bottom level pill
            pill = QLabel(str(lvl))
            pill.setFont(T.get_font(10, bold=True))
            pill.setFixedSize(28, 18)
            pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
            pill.setStyleSheet(f"""
                background-color: {T.GREY_100};
                color: {T.SLATE_400};
                border: 1px solid {T.GREY_200};
                border-radius: 3px;
            """)
            col.addWidget(pill)

            self._layout.addLayout(col)
            self._bars.append({
                "count_lbl": count_lbl,
                "bar_fill": bar_fill,
                "pill": pill,
                "level": lvl,
            })

    def update_data(self, by_severity: dict):
        counts = [by_severity.get(i, by_severity.get(str(i), 0)) for i in range(11)]
        max_c = max(max(counts), 1)

        for i, info in enumerate(self._bars):
            c = counts[i]
            lvl = info["level"]
            bar_color = T.get_severity_color(lvl)
            if c > 0:
                info["count_lbl"].setText(str(c))
                info["bar_fill"].setVisible(True)
                pct = c / max_c
                h = max(8, int(pct * 70))
                info["bar_fill"].setFixedHeight(h)
                info["pill"].setStyleSheet(f"""
                    background-color: {T.WHITE};
                    color: {bar_color};
                    border: 1px solid {bar_color};
                    border-radius: 3px;
                    font-weight: bold;
                """)
            else:
                info["count_lbl"].setText("")
                info["bar_fill"].setVisible(False)
                info["pill"].setStyleSheet(f"""
                    background-color: {T.GREY_100};
                    color: {T.SLATE_400};
                    border: 1px solid {T.GREY_200};
                    border-radius: 3px;
                """)


# ── DistributionBar ───────────────────────────────────────────────────

class DistributionBar(QWidget):
    """Horizontal distribution bar with label, full-width responsive track fill, and count/pct."""

    def __init__(self, label: str, count: int, total: int, color: str = T.BLUE_600, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(12)

        lbl = QLabel(label)
        lbl.setFont(T.get_font(12, bold=True))
        lbl.setStyleSheet(f"color: {T.NAVY_900};")
        lbl.setFixedWidth(115)
        layout.addWidget(lbl)

        pct = int((count / total) * 100) if total > 0 else 0
        self._track = QFrame()
        self._track.setFixedHeight(14)
        self._track.setStyleSheet(f"background-color: {T.GREY_150}; border-radius: 3px; border: none;")

        self._track_layout = QHBoxLayout(self._track)
        self._track_layout.setContentsMargins(0, 0, 0, 0)
        self._track_layout.setSpacing(0)

        self._fill = QFrame()
        self._fill.setFixedHeight(14)
        self._fill.setStyleSheet(f"background-color: {color}; border-radius: 3px; border: none;")

        self._empty = QWidget()
        self._empty.setFixedHeight(14)
        self._empty.setStyleSheet("background: transparent; border: none;")

        self._track_layout.addWidget(self._fill, max(1, pct) if pct > 0 else 0)
        self._track_layout.addWidget(self._empty, max(1, 100 - pct) if pct < 100 else 0)
        self._fill.setVisible(pct > 0)

        layout.addWidget(self._track, 1)

        self._val = QLabel(f"{count} ({pct}%)")
        self._val.setFont(T.get_font(11.5))
        self._val.setStyleSheet(f"color: {T.SLATE_600};")
        self._val.setFixedWidth(75)
        self._val.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self._val)

    def update_values(self, count: int, total: int):
        """Update count and percentage bar smoothly in-place without widget reconstruction."""
        pct = int((count / total) * 100) if total > 0 else 0
        self._val.setText(f"{count} ({pct}%)")
        self._fill.setVisible(pct > 0)
        self._track_layout.setStretch(0, max(1, pct) if pct > 0 else 0)
        self._track_layout.setStretch(1, max(1, 100 - pct) if pct < 100 else 0)


# ── NoticeBanner ──────────────────────────────────────────────────────

class NoticeBanner(QFrame):
    """Operational informational notice banner."""

    def __init__(self, message: str, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            NoticeBanner {{
                background-color: {T.BLUE_50};
                border: 1px solid {T.BLUE_600}40;
                border-radius: {T.BORDER_RADIUS}px;
                padding: 12px 16px;
            }}
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        lbl = QLabel(message)
        lbl.setFont(T.get_font(11.5))
        lbl.setStyleSheet(f"color: {T.NAVY_900}; border: none; background: transparent;")
        lbl.setWordWrap(True)
        layout.addWidget(lbl)


# ── WorkflowStepper ───────────────────────────────────────────────────

class WorkflowStepper(QFrame):
    """
    Numbered step navigation header (e.g. Auto-Learn):
    01 INPUT LOGS ── 02 STRUCTURE ANALYSIS ── 03 FIELD IDENTIFICATION ── ...
    """

    def __init__(self, steps: list[str], active_idx: int = 0, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            WorkflowStepper {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 10px 16px;
            }}
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 8, 16, 8)
        layout.setSpacing(12)

        for i, title in enumerate(steps):
            is_active = (i == active_idx)
            num_str = f"{i+1:02d}"

            num_lbl = QLabel(num_str)
            num_lbl.setFont(T.get_font(10.5, bold=True))
            if is_active:
                num_lbl.setStyleSheet(f"""
                    background-color: {T.BLUE_600};
                    color: {T.WHITE};
                    border-radius: 10px;
                    padding: 2px 6px;
                """)
            else:
                num_lbl.setStyleSheet(f"""
                    background-color: {T.GREY_150};
                    color: {T.SLATE_600};
                    border-radius: 10px;
                    padding: 2px 6px;
                """)
            layout.addWidget(num_lbl)

            text_lbl = QLabel(title.upper())
            text_lbl.setFont(T.get_font(11, bold=is_active))
            text_lbl.setStyleSheet(f"color: {T.NAVY_900 if is_active else T.SLATE_400};")
            layout.addWidget(text_lbl)

            if i < len(steps) - 1:
                dash = QLabel("──")
                dash.setStyleSheet(f"color: {T.GREY_200};")
                layout.addWidget(dash)

        layout.addStretch()


# ── PipelineStageBar ──────────────────────────────────────────────────

class PipelineStageBar(QFrame):
    """Visualizes the 7-stage processing pipeline."""

    STAGES = [
        ("1. INPUT", "Files / Stream"),
        ("2. DETECT", "Prefix Jump"),
        ("3. PARSE", "Direct Dispatch"),
        ("4. NORMALIZE", "Unified Schema"),
        ("5. ENRICH", "GeoIP / Threats"),
        ("6. ANALYZE", "Z-Score / Drift"),
        ("7. STORE", "DuckDB Columnar"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        for i, (title, sub) in enumerate(self.STAGES):
            box = QFrame()
            box.setStyleSheet(f"""
                QFrame {{
                    background-color: {T.WHITE};
                    border: 1px solid {T.BLUE_600 if i == 0 else T.GREY_200};
                    border-radius: {T.BORDER_RADIUS}px;
                    padding: 6px 10px;
                }}
            """)
            box_layout = QVBoxLayout(box)
            box_layout.setContentsMargins(8, 6, 8, 6)
            box_layout.setSpacing(2)

            t = QLabel(title)
            t.setFont(T.get_font(11, bold=True))
            t.setStyleSheet(f"color: {T.NAVY_900}; border: none;")
            t.setAlignment(Qt.AlignmentFlag.AlignCenter)
            box_layout.addWidget(t)

            s = QLabel(sub)
            s.setFont(T.get_font(9.5))
            s.setStyleSheet(f"color: {T.SLATE_400}; border: none;")
            s.setAlignment(Qt.AlignmentFlag.AlignCenter)
            box_layout.addWidget(s)

            layout.addWidget(box, 1)

            if i < len(self.STAGES) - 1:
                arrow = QLabel("→")
                arrow.setFont(T.get_font(12, bold=True))
                arrow.setStyleSheet(f"color: {T.SLATE_400};")
                layout.addWidget(arrow)


# ── KeyValueRow ───────────────────────────────────────────────────────

class KeyValueRow(QWidget):
    """Institutional key: value row."""

    def __init__(self, key: str, value: str = "", mono: bool = False, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)

        k = QLabel(key)
        k.setFont(T.get_font(12))
        k.setStyleSheet(f"color: {T.SLATE_600};")
        k.setMinimumWidth(160)

        self._val = QLabel(str(value))
        self._val.setFont(T.get_font(12, bold=True, mono=mono))
        self._val.setStyleSheet(f"color: {T.NAVY_900};")
        self._val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        layout.addWidget(k)
        layout.addWidget(self._val, 1)

    def set_value(self, value: str):
        self._val.setText(str(value))


# ── DataTable ─────────────────────────────────────────────────────────

class DataTable(QTableView):
    """Enterprise pre-styled table matching the light institutional design."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setHighlightSections(False)
        self.verticalHeader().setVisible(False)
        self.setShowGrid(False)


# ── SearchBar ─────────────────────────────────────────────────────────

class SearchBar(QLineEdit):
    """Styled search bar."""

    search_triggered = Signal(str)

    def __init__(self, placeholder: str = "Search...", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(f"🔍  {placeholder}")
        self.setMinimumHeight(34)
        self.setStyleSheet(f"""
            QLineEdit {{
                background-color: {T.WHITE};
                border: 1px solid {T.SLATE_300};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 6px 12px;
                font-size: 12px;
                color: {T.NAVY_900};
            }}
            QLineEdit:focus {{
                border: 1px solid {T.BLUE_600};
            }}
        """)
        self.returnPressed.connect(lambda: self.search_triggered.emit(self.text()))


# ── FileDropZone ──────────────────────────────────────────────────────

class FileDropZone(QFrame):
    """File drag-and-drop zone with institutional dashed border."""

    files_dropped = Signal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setMinimumHeight(150)
        self._set_idle_style()

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(8)

        icon_row = QHBoxLayout()
        icon_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon = VectorIcon("document", 36, color=T.SLATE_400)
        icon_row.addWidget(self.icon)
        layout.addLayout(icon_row)

        title = QLabel("Drop security log files here")
        title.setFont(T.get_font(15, bold=True))
        title.setStyleSheet(f"color: {T.NAVY_900}; border: none; background: transparent;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        sub = QLabel("Supports CEF, LEEF, RFC 5424 Syslog, JSON, XML, Fortinet KV, W3C, and raw text")
        sub.setFont(T.get_font(12))
        sub.setStyleSheet(f"color: {T.SLATE_400}; border: none; background: transparent;")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(title)
        layout.addWidget(sub)

    def _set_idle_style(self):
        self.setStyleSheet(f"""
            FileDropZone {{
                background-color: {T.WHITE};
                border: 2px dashed {T.SLATE_300};
                border-radius: {T.BORDER_RADIUS}px;
            }}
        """)

    def _set_hover_style(self):
        self.setStyleSheet(f"""
            FileDropZone {{
                background-color: {T.BLUE_50};
                border: 2px dashed {T.BLUE_600};
                border-radius: {T.BORDER_RADIUS}px;
            }}
        """)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._set_hover_style()

    def dragLeaveEvent(self, event):
        self._set_idle_style()

    def dropEvent(self, event: QDropEvent):
        self._set_idle_style()
        urls = event.mimeData().urls()
        files = [u.toLocalFile() for u in urls if u.isLocalFile()]
        if files:
            self.files_dropped.emit(files)


# ── EmptyState ────────────────────────────────────────────────────────

class EmptyState(QWidget):
    """Institutional empty state."""

    def __init__(self, title: str = "NO DATA DETECTED",
                 message: str = "There are no records to display.",
                 icon_char: str = "", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setContentsMargins(24, 28, 24, 28)
        layout.setSpacing(8)

        if icon_char:
            normalized_icon = icon_char.lower().strip()
            if normalized_icon in ("document", "server", "code", "sunburst", "autolearn", "dna", "helix", "nodes", "correlation", "chain", "forensics", "magnifier", "search", "alert_circle", "drift", "reload"):
                row = QHBoxLayout()
                row.setAlignment(Qt.AlignmentFlag.AlignCenter)
                row.addWidget(VectorIcon(normalized_icon, 36, color=T.SLATE_400))
                layout.addLayout(row)
            else:
                icon = QLabel(icon_char)
                icon.setFont(T.get_font(36))
                icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
                layout.addWidget(icon)

        ttl = QLabel(title.upper())
        ttl.setFont(T.get_font(13.5, bold=True))
        ttl.setStyleSheet(f"color: {T.NAVY_900}; letter-spacing: 0.04em;")
        ttl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        msg = QLabel(message)
        msg.setFont(T.get_font(12))
        msg.setStyleSheet(f"color: {T.SLATE_400};")
        msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        msg.setWordWrap(True)

        layout.addWidget(ttl)
        layout.addWidget(msg)


# ── Compatibility Widgets ─────────────────────────────────────────────

class PageHeader(QWidget):
    """Institutional Page Header component."""

    def __init__(self, title: str, subtitle: str = "", parent=None):
        super().__init__(parent)
        self._main_layout = QHBoxLayout(self)
        self._main_layout.setContentsMargins(0, 0, 0, 0)

        left = QVBoxLayout()
        left.setContentsMargins(0, 0, 0, 0)
        left.setSpacing(2)

        ttl = QLabel(title)
        ttl.setFont(T.get_font(18, bold=True))
        ttl.setStyleSheet(f"color: {T.NAVY_900};")
        sub = QLabel(subtitle)
        sub.setFont(T.get_font(11))
        sub.setStyleSheet(f"color: {T.SLATE_600};")

        left.addWidget(ttl)
        left.addWidget(sub)
        self._main_layout.addLayout(left)
        self._main_layout.addStretch()

        self._actions_layout = QHBoxLayout()
        self._actions_layout.setSpacing(8)
        self._main_layout.addLayout(self._actions_layout)

    def add_action(self, widget: QWidget):
        self._actions_layout.addWidget(widget)


class DataTable(QTableWidget):
    """Standard ULPF Styled Data Table."""

    def __init__(self, headers: list[str], parent=None):
        super().__init__(0, len(headers), parent)
        self.setHorizontalHeaderLabels(headers)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        self.setShowGrid(False)
        self.horizontalHeader().setStretchLastSection(True)


class SearchBar(QWidget):
    """Search input bar emitting search_triggered on enter."""

    search_triggered = Signal(str)

    def __init__(self, placeholder: str = "Search...", parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.input = QLineEdit()
        self.input.setPlaceholderText(placeholder)
        self.input.returnPressed.connect(lambda: self.search_triggered.emit(self.input.text().strip()))
        layout.addWidget(self.input)


# ── Table Item Delegates ──────────────────────────────────────────────

class SeverityBadgeDelegate(QStyledItemDelegate):
    """Renders a rounded colored badge for severity level (0-10) matching reference photos."""

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex):
        val = index.data(Qt.ItemDataRole.DisplayRole)
        try:
            lvl = int(val)
        except (ValueError, TypeError):
            lvl = 0

        color_hex = T.get_severity_color(lvl)
        color = QColor(color_hex)

        painter.save()
        bg = QColor(T.WHITE) if (index.row() % 2 == 0) else QColor(T.GREY_50)
        if option.state & QStyle.StateFlag.State_Selected:
            bg = QColor("#E0F2FE")
        painter.fillRect(option.rect, bg)

        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Center a 26x18 pill within the cell
        w, h = 26, 18
        x = option.rect.x() + (option.rect.width() - w) // 2
        y = option.rect.y() + (option.rect.height() - h) // 2
        rect = QRect(x, y, w, h)

        painter.setBrush(QBrush(color))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(rect, 3, 3)

        painter.setPen(QColor("#FFFFFF"))
        font = option.font
        font.setBold(True)
        font.setPointSize(9)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, str(lvl))
        painter.restore()


class FormatPillDelegate(QStyledItemDelegate):
    """Renders a subtle bordered pill for format (e.g. CEF, LEEF, JSON)."""

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex):
        fmt = str(index.data(Qt.ItemDataRole.DisplayRole) or "").strip().upper()
        painter.save()
        bg = QColor(T.WHITE) if (index.row() % 2 == 0) else QColor(T.GREY_50)
        if option.state & QStyle.StateFlag.State_Selected:
            bg = QColor("#E0F2FE")
        painter.fillRect(option.rect, bg)

        if not fmt or fmt == "—":
            painter.restore()
            return

        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = min(max(10, option.rect.width() - 8), max(42, len(fmt) * 8 + 14))
        h = min(option.rect.height() - 4, 18)
        x = option.rect.x() + (option.rect.width() - w) // 2
        y = option.rect.y() + (option.rect.height() - h) // 2
        rect = QRect(x, y, w, h)

        painter.setBrush(QBrush(QColor(T.GREY_50)))
        painter.setPen(QPen(QColor(T.SLATE_300), 1))
        painter.drawRoundedRect(rect, 3, 3)

        painter.setPen(QColor(T.NAVY_900))
        font = option.font
        font.setBold(True)
        font.setPointSize(8.5)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, fmt)
        painter.restore()


class CategoryDelegate(QStyledItemDelegate):
    """Renders category name in semi-bold navy font with clean background and elision."""

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex):
        val = str(index.data(Qt.ItemDataRole.DisplayRole) or "")
        painter.save()
        bg = QColor(T.WHITE) if (index.row() % 2 == 0) else QColor(T.GREY_50)
        if option.state & QStyle.StateFlag.State_Selected:
            bg = QColor("#E0F2FE")
        painter.fillRect(option.rect, bg)

        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        font = option.font
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(QColor(T.NAVY_900))
        rect = option.rect.adjusted(6, 0, -6, 0)
        fm = painter.fontMetrics()
        elided = fm.elidedText(val, Qt.TextElideMode.ElideRight, rect.width())
        painter.drawText(rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, elided)
        painter.restore()


class MonoTextDelegate(QStyledItemDelegate):
    """Renders text in monospace font with background clearing and text elision."""

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex):
        val = str(index.data(Qt.ItemDataRole.DisplayRole) or "")
        painter.save()
        bg = QColor(T.WHITE) if (index.row() % 2 == 0) else QColor(T.GREY_50)
        if option.state & QStyle.StateFlag.State_Selected:
            bg = QColor("#E0F2FE")
        painter.fillRect(option.rect, bg)

        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        font = QFont(T.FONT_MONO, 9)
        painter.setFont(font)
        painter.setPen(QColor(T.SLATE_700))

        align = option.displayAlignment
        if align == Qt.AlignmentFlag.AlignCenter:
            rect = option.rect
        else:
            rect = option.rect.adjusted(6, 0, -6, 0)
            align = Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft

        fm = painter.fontMetrics()
        elided = fm.elidedText(val, Qt.TextElideMode.ElideRight, rect.width())
        painter.drawText(rect, align, elided)
        painter.restore()

