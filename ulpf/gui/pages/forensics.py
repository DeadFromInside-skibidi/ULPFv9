"""
ULPF Forensics Page
=====================
Pixel-faithful reproduction of the Forensic Chain-of-Evidence Manager
from reference photo WhatsApp Image 2026-09-27 at 23.59.12.jpeg.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex, QThreadPool
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableView, QHeaderView, QFrame, QAbstractItemView, QMessageBox,
)

from ulpf.gui import theme as T
from ulpf.gui.widgets import SectionCard, PillBadge, StatusBadge, EmptyState, FormatPillDelegate, MonoTextDelegate, VectorIcon
from ulpf.gui.service import ULPFService
from ulpf.gui.workers.background import ProcessingWorker


class ForensicsTableModel(QAbstractTableModel):
    HEADERS = ["CHAIN ID", "DESCRIPTION", "ITEMS LINKED", "FINAL CHAIN HASH (SHA-256)", "CREATED TIMESTAMP", "VERIFICATION & EXPORT"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._chains: list[dict] = []

    def set_chains(self, chains: list[dict]):
        self.beginResetModel()
        self._chains = chains
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self._chains)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        c = self._chains[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return str(c.get("chain_id", ""))[:12]
            elif col == 1:
                return c.get("description", "Evidence Chain")
            elif col == 2:
                count = c.get("item_count") or c.get("event_count") or c.get("items_count") or len(c.get("items", [])) or 1
                return f"{count} EVENTS"
            elif col == 3:
                h = c.get("chain_hash") or c.get("final_hash") or c.get("head_hash") or ""
                return h[:16] + "..." if len(h) > 16 else (h or "—")
            elif col == 4:
                return str(c.get("created_at", ""))[:23] + " UTC"
            elif col == 5:
                return ""
        elif role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (0, 2, 3):
                return Qt.AlignmentFlag.AlignCenter
        return None

    def get_chain(self, row: int) -> dict | None:
        if 0 <= row < len(self._chains):
            return self._chains[row]
        return None


class ForensicsPage(QWidget):
    """Institutional Forensic Evidence Manager Page."""

    def __init__(self, service: ULPFService, parent=None):
        super().__init__(parent)
        self.service = service
        self.threadpool = QThreadPool.globalInstance()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        # ── Card 1: Forensic Chain-of-Evidence Manager ──
        card1 = QFrame()
        card1.setStyleSheet(f"""
            QFrame {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 18px 22px;
            }}
        """)
        c1l = QVBoxLayout(card1)
        c1l.setContentsMargins(18, 16, 18, 16)
        c1l.setSpacing(12)

        # Header row with icon and buttons
        top_row = QHBoxLayout()
        top_row.setSpacing(16)

        icon_lbl = VectorIcon("chain", 36, color=T.NAVY_900)
        top_row.addWidget(icon_lbl)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)

        st_title = QLabel("Forensic Chain-of-Evidence Manager")
        st_title.setFont(T.get_font(15, bold=True))
        st_title.setStyleSheet(f"color: {T.NAVY_900};")
        title_col.addWidget(st_title)

        desc = QLabel(
            "Generates immutable cryptographic audit trails for incident response and legal compliance. "
            "Every raw event is hashed with SHA-256 at pipeline entry and chained sequentially (Merkle-style linked hashes). "
            "Any post-ingestion tampering immediately fails cryptographic verification."
        )
        desc.setFont(T.get_font(12))
        desc.setStyleSheet(f"color: {T.SLATE_600};")
        desc.setWordWrap(True)
        title_col.addWidget(desc)
        top_row.addLayout(title_col, 1)

        # Action buttons on right
        btn_box = QHBoxLayout()
        btn_box.setSpacing(8)

        self.btn_refresh = QPushButton("Refresh Chains")
        self.btn_refresh.setProperty("btnClass", "outline")
        self.btn_refresh.setFixedHeight(32)
        self.btn_refresh.clicked.connect(self.refresh)
        btn_box.addWidget(self.btn_refresh)

        self.btn_create = QPushButton("+ Build Evidence Chain")
        T.set_button_class(self.btn_create, "primary")
        self.btn_create.setFixedHeight(32)
        self.btn_create.clicked.connect(self._create_chain)
        btn_box.addWidget(self.btn_create)

        top_row.addLayout(btn_box)
        c1l.addLayout(top_row)
        layout.addWidget(card1)

        # ── Card 2: Registered Evidence Chains ──
        self.chains_card = SectionCard("Registered Evidence Chains")
        c2l = self.chains_card.content_layout()

        self.table = QTableView()
        self.model = ForensicsTableModel()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setFixedHeight(180)
        self.table.doubleClicked.connect(self._on_table_action)

        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        self.table.setColumnWidth(0, 130)  # CHAIN ID
        self.table.setColumnWidth(1, 160)  # DESCRIPTION
        self.table.setColumnWidth(2, 110)  # ITEMS LINKED
        self.table.setColumnWidth(3, 230)  # FINAL CHAIN HASH (SHA-256)
        self.table.setColumnWidth(4, 190)  # CREATED TIMESTAMP
        self.table.setColumnWidth(5, 230)  # VERIFICATION & EXPORT

        self.table.setItemDelegateForColumn(0, MonoTextDelegate(self.table))
        self.table.setItemDelegateForColumn(2, FormatPillDelegate(self.table))
        self.table.setItemDelegateForColumn(3, MonoTextDelegate(self.table))
        self.table.setItemDelegateForColumn(4, MonoTextDelegate(self.table))

        c2l.addWidget(self.table)

        # Action / status bar under table
        act_row = QHBoxLayout()
        self.status_lbl = QLabel("")
        self.status_lbl.setFont(T.get_font(12, bold=True))
        act_row.addWidget(self.status_lbl)
        act_row.addStretch()
        c2l.addLayout(act_row)

        layout.addWidget(self.chains_card)
        layout.addStretch()

        self.refresh()

    def refresh(self):
        chains = self.service.forensic_list_chains()
        if not chains and self.service.get_stats().get("total_events", 0) > 0:
            self.service.forensic_build_from_events(limit=50, description="Test Evidence Chain")
            chains = self.service.forensic_list_chains()
        self.model.set_chains(chains)
        self.chains_card.setTitle(f"Registered Evidence Chains ({len(chains)} registered chains)") if hasattr(self.chains_card, 'setTitle') else None

        # Embed direct action buttons in column 5 matching screenshot
        for row_idx, chain in enumerate(chains):
            cid = chain.get("chain_id")
            cell_widget = QWidget()
            cw_layout = QHBoxLayout(cell_widget)
            cw_layout.setContentsMargins(4, 2, 4, 2)
            cw_layout.setSpacing(6)
            cw_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

            v_btn = QPushButton("Verify Integrity")
            v_btn.setProperty("btnClass", "outline")
            v_btn.setFixedHeight(24)
            v_btn.clicked.connect(lambda ch, c=cid: self._verify_chain_id(c))
            cw_layout.addWidget(v_btn)

            e_btn = QPushButton("Export Package")
            e_btn.setProperty("btnClass", "outline")
            e_btn.setFixedHeight(24)
            e_btn.clicked.connect(lambda ch, c=cid: self._export_chain_id(c))
            cw_layout.addWidget(e_btn)

            self.table.setIndexWidget(self.model.index(row_idx, 5), cell_widget)

    def _verify_chain_id(self, chain_id: str):
        if not chain_id:
            return
        res = self.service.forensic_verify(chain_id)
        if res.get("valid"):
            self.status_lbl.setText("✓ VERIFIED — Chain integrity is mathematically valid.")
            self.status_lbl.setStyleSheet(f"color: {T.SUCCESS};")
        else:
            self.status_lbl.setText(f"✗ INVALID: {res.get('message', 'Tamper detected')}")
            self.status_lbl.setStyleSheet(f"color: {T.CRITICAL};")

    def _export_chain_id(self, chain_id: str):
        if not chain_id:
            return
        res = self.service.forensic_export(chain_id)
        if res.get("success"):
            self.status_lbl.setText(f"✓ Exported: {res.get('filepath')}")
            self.status_lbl.setStyleSheet(f"color: {T.SUCCESS};")
        else:
            self.status_lbl.setText(f"Export failed: {res.get('error')}")
            self.status_lbl.setStyleSheet(f"color: {T.CRITICAL};")

    def _create_chain(self):
        res = self.service.forensic_build_from_events(limit=50, description="Cryptographic Chain")
        if "chain_id" in res:
            self.status_lbl.setText(f"✓ Chain Created: {res['chain_id'][:12]}")
            self.status_lbl.setStyleSheet(f"color: {T.SUCCESS};")
            self.refresh()
        else:
            self.status_lbl.setText(f"Error: {res.get('error', 'Failed')}")
            self.status_lbl.setStyleSheet(f"color: {T.CRITICAL};")

    def _verify_selected(self):
        sel = self.table.selectionModel().selectedRows()
        if not sel:
            return
        row = sel[0].row()
        chain = self.model.get_chain(row)
        if chain and chain.get("chain_id"):
            self._verify_chain_id(chain["chain_id"])

    def _export_selected(self):
        sel = self.table.selectionModel().selectedRows()
        if not sel:
            return
        row = sel[0].row()
        chain = self.model.get_chain(row)
        if chain and chain.get("chain_id"):
            self._export_chain_id(chain["chain_id"])

    def _on_table_action(self, index: QModelIndex):
        self._verify_selected()
