"""
ULPF Schema Taxonomy Page
============================
Browsable reference of the unified event schema, rendered from the engine's
field catalogue (``ulpf.engine.schema.SCHEMA_GROUPS``).
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableView, QHeaderView, QLineEdit, QFrame,
    QScrollArea, QPushButton, QAbstractItemView,
)

from ulpf.gui import theme as T
from ulpf.gui.widgets import PillBadge
from ulpf.gui.service import ULPFService
from ulpf.engine.schema import SCHEMA_GROUPS


# Single source of truth: the engine's field catalogue (ulpf/engine/schema.py)
SCHEMA_TAXONOMY = SCHEMA_GROUPS


class SchemaFieldsModel(QAbstractTableModel):
    HEADERS = ["ATTRIBUTE NAME", "DATA TYPE", "DESCRIPTION", "EXAMPLE VALUE"]

    def __init__(self, fields: list[dict], parent=None):
        super().__init__(parent)
        self._fields = fields

    def rowCount(self, parent=QModelIndex()):
        return len(self._fields)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        f = self._fields[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return f.get("name", "")
            elif col == 1:
                return f.get("type", "")
            elif col == 2:
                return f.get("description", "")
            elif col == 3:
                return f.get("example", "")
        elif role == Qt.ItemDataRole.FontRole:
            if col in (0, 1, 3):
                return T.get_font(11.5, mono=True, bold=(col == 0))
        elif role == Qt.ItemDataRole.ForegroundRole:
            if col == 1:
                from PySide6.QtGui import QColor
                return QColor("#0284C7")
            elif col == 0:
                from PySide6.QtGui import QColor
                return QColor(T.NAVY_900)
        return None


class CategoryCard(QFrame):
    """Card containing an OCSF Schema category header and table of attributes."""

    def __init__(self, category: dict, filtered_fields: list[dict], parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            CategoryCard {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                margin-bottom: 8px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header Bar
        header = QFrame()
        header.setStyleSheet(f"""
            QFrame {{
                background-color: {T.GREY_50};
                border-bottom: 1px solid {T.GREY_200};
                border-top-left-radius: {T.BORDER_RADIUS}px;
                border-top-right-radius: {T.BORDER_RADIUS}px;
                padding: 10px 18px;
            }}
        """)
        hl = QHBoxLayout(header)
        hl.setContentsMargins(18, 10, 18, 10)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        cat_title = QLabel(category.get("category", ""))
        cat_title.setFont(T.get_font(13.5, bold=True))
        cat_title.setStyleSheet(f"color: {T.NAVY_900}; border: none;")

        cat_desc = QLabel(category.get("description", ""))
        cat_desc.setFont(T.get_font(11))
        cat_desc.setStyleSheet(f"color: {T.SLATE_600}; border: none;")

        title_col.addWidget(cat_title)
        title_col.addWidget(cat_desc)
        hl.addLayout(title_col)
        hl.addStretch()

        badge = PillBadge(f"{len(filtered_fields)} ATTRIBUTES")
        hl.addWidget(badge)
        layout.addWidget(header)

        # Table
        table = QTableView()
        model = SchemaFieldsModel(filtered_fields)
        table.setModel(model)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setShowGrid(False)
        table.verticalHeader().setVisible(False)
        table.setStyleSheet(f"""
            QTableView {{
                background-color: {T.WHITE};
                border: none;
            }}
        """)

        # Calculate row height
        row_height = 36
        total_table_height = (len(filtered_fields) * row_height) + 38
        table.setFixedHeight(total_table_height)

        th = table.horizontalHeader()
        th.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        th.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        th.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        th.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        table.setColumnWidth(0, 220)
        table.setColumnWidth(1, 160)
        table.setColumnWidth(3, 260)

        layout.addWidget(table)


class SchemaPage(QWidget):
    """Institutional Schema Taxonomy Page."""

    def __init__(self, service: ULPFService, parent=None):
        super().__init__(parent)
        self.service = service
        self._active_category = "ALL"
        self._search_query = ""

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(16)

        # ── Top Filter Toolbar Card ──
        toolbar = QFrame()
        toolbar.setStyleSheet(f"""
            QFrame {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 12px 18px;
            }}
        """)
        tbl = QHBoxLayout(toolbar)
        tbl.setContentsMargins(16, 12, 16, 12)
        tbl.setSpacing(14)

        tb_text = QVBoxLayout()
        tb_text.setSpacing(2)
        from ulpf.engine.schema import SCHEMA_DEFINITION
        tb_title = QLabel(f"ULPF Unified Security Event Schema "
                          f"({SCHEMA_DEFINITION['field_count']} fields, OCSF-inspired)")
        tb_title.setFont(T.get_font(14, bold=True))
        tb_title.setStyleSheet(f"color: {T.NAVY_900}; border: none;")

        tb_sub = QLabel("Single target taxonomy normalizing all heterogeneous log formats into uniform representation.")
        tb_sub.setFont(T.get_font(11))
        tb_sub.setStyleSheet(f"color: {T.SLATE_600}; border: none;")
        tb_text.addWidget(tb_title)
        tb_text.addWidget(tb_sub)
        tbl.addLayout(tb_text, 1)

        # Search box
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍  Search schema attributes...")
        self.search_input.setFixedWidth(280)
        self.search_input.setFixedHeight(34)
        self.search_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {T.GREY_50};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 4px 12px;
                font-size: 12px;
            }}
            QLineEdit:focus {{
                background-color: {T.WHITE};
                border: 1px solid {T.BLUE_600};
            }}
        """)
        self.search_input.textChanged.connect(self._on_search_changed)
        tbl.addWidget(self.search_input)
        main_layout.addWidget(toolbar)

        # ── Category Filter Buttons (Two rows matching reference screenshot) ──
        pills_container = QVBoxLayout()
        pills_container.setSpacing(8)

        row1 = QHBoxLayout()
        row1.setSpacing(8)
        row2 = QHBoxLayout()
        row2.setSpacing(8)

        self._pills: dict[str, QPushButton] = {}
        all_btn = self._create_pill_btn("ALL", f"All Categories ({len(SCHEMA_TAXONOMY)})")
        row1.addWidget(all_btn)
        self._pills["ALL"] = all_btn

        for i, cat in enumerate(SCHEMA_TAXONOMY):
            name = cat["category"]
            btn = self._create_pill_btn(name, name)
            if i < 7:
                row1.addWidget(btn)
            else:
                row2.addWidget(btn)
            self._pills[name] = btn

        row1.addStretch()
        row2.addStretch()
        pills_container.addLayout(row1)
        pills_container.addLayout(row2)
        main_layout.addLayout(pills_container)

        # ── Scroll Area for Categories ──
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setStyleSheet("background: transparent; border: none;")

        self.cards_container = QWidget()
        self.cards_container.setStyleSheet("background: transparent; border: none;")
        self.cards_layout = QVBoxLayout(self.cards_container)
        self.cards_layout.setContentsMargins(0, 0, 0, 0)
        self.cards_layout.setSpacing(16)

        self.scroll.setWidget(self.cards_container)
        main_layout.addWidget(self.scroll, 1)

        self._update_cards()

    def _create_pill_btn(self, cat_key: str, label: str) -> QPushButton:
        btn = QPushButton(label)
        btn.setFixedHeight(28)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        is_active = (cat_key == self._active_category)
        self._apply_pill_style(btn, is_active)
        btn.clicked.connect(lambda: self._set_active_category(cat_key))
        return btn

    def _apply_pill_style(self, btn: QPushButton, active: bool):
        if active:
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {T.NAVY_800};
                    color: {T.WHITE};
                    border: 1px solid {T.NAVY_900};
                    border-radius: {T.BORDER_RADIUS_SM}px;
                    padding: 4px 12px;
                    font-size: 11px;
                    font-weight: 600;
                }}
            """)
        else:
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {T.WHITE};
                    color: {T.SLATE_600};
                    border: 1px solid {T.GREY_200};
                    border-radius: {T.BORDER_RADIUS_SM}px;
                    padding: 4px 12px;
                    font-size: 11px;
                    font-weight: 600;
                }}
                QPushButton:hover {{
                    background-color: {T.GREY_100};
                    color: {T.NAVY_900};
                }}
            """)

    def _set_active_category(self, cat_key: str):
        self._active_category = cat_key
        for k, btn in self._pills.items():
            self._apply_pill_style(btn, k == self._active_category)
        self._update_cards()

    def _on_search_changed(self, text: str):
        self._search_query = text.strip().lower()
        self._update_cards()

    def _update_cards(self):
        # Clear existing cards
        while self.cards_layout.count() > 0:
            item = self.cards_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Filter categories
        cats = SCHEMA_TAXONOMY if self._active_category == "ALL" else [
            c for c in SCHEMA_TAXONOMY if c["category"] == self._active_category
        ]

        count = 0
        for cat in cats:
            fields = cat["fields"]
            if self._search_query:
                fields = [
                    f for f in fields
                    if self._search_query in f["name"].lower()
                    or self._search_query in f["description"].lower()
                    or self._search_query in f["type"].lower()
                    or self._search_query in f.get("example", "").lower()
                ]

            if fields:
                card = CategoryCard(cat, fields)
                self.cards_layout.addWidget(card)
                count += 1

        if count == 0:
            empty = QLabel("No schema attributes match the filter query.")
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty.setStyleSheet(f"color: {T.SLATE_400}; padding: 40px; font-size: 13px;")
            self.cards_layout.addWidget(empty)

        self.cards_layout.addStretch()

    def refresh(self):
        self._update_cards()
