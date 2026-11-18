"""
ULPF Log DNA Page
===================
Pixel-faithful reproduction of the Log DNA Fingerprint Laboratory
from reference photo WhatsApp Image 2026-09-27 at 23.56.412.jpeg.
"""
from __future__ import annotations

import json
from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTextEdit, QLineEdit, QFrame, QScrollArea,
)

from ulpf.gui import theme as T
from ulpf.gui.widgets import SectionCard, PillBadge, StatusBadge, VectorIcon
from ulpf.gui.service import ULPFService
from ulpf.gui.workers.background import ProcessingWorker


SAMPLE_CEF_LINES = (
    "CEF:0|Check Point|VPN-1 & FireWall-1|R81.20|Accept|Firewall Rule Accept|3|src=192.168.1.100 dst=203.0.113.50 spt=52341 dpt=443 proto=TCP act=Accept\n"
    "CEF:0|Check Point|VPN-1 & FireWall-1|R81.20|Drop|Firewall Rule Drop|8|src=45.33.32.156 dst=10.0.1.50 spt=12345 dpt=4444 proto=TCP act=Drop\n"
    "CEF:0|Check Point|VPN-1 & FireWall-1|R81.20|Accept|Firewall Rule Accept|2|src=10.0.0.25 dst=91.121.87.10 spt=38291 dpt=22 proto=TCP act=Accept"
)


class LogDNAPage(QWidget):
    """Institutional Log DNA Fingerprint Laboratory Page."""

    def __init__(self, service: ULPFService, parent=None):
        super().__init__(parent)
        self.service = service
        self.threadpool = QThreadPool.globalInstance()
        self._latest_fid = ""

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(18)

        # ── Card 1: Create Structural Log DNA Fingerprint ──
        c1 = QFrame()
        c1.setStyleSheet(f"""
            QFrame {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 18px 22px;
            }}
        """)
        c1l = QVBoxLayout(c1)
        c1l.setContentsMargins(18, 16, 18, 16)
        c1l.setSpacing(14)

        # Header
        h_row = QHBoxLayout()
        h_icon = VectorIcon("dna", 36, color=T.NAVY_900)
        h_row.addWidget(h_icon)

        h_title = QLabel("Create Structural Log DNA Fingerprint")
        h_title.setFont(T.get_font(14.5, bold=True))
        h_title.setStyleSheet(f"color: {T.NAVY_900};")
        h_row.addWidget(h_title)
        h_row.addStretch()

        meta_lbl = QLabel("Shannon Entropy & Token Signature (POST /api/v1/fingerprint)")
        meta_lbl.setFont(T.get_font(11))
        meta_lbl.setStyleSheet(f"color: {T.SLATE_400};")
        h_row.addWidget(meta_lbl)
        c1l.addLayout(h_row)

        desc = QLabel("Calculates character frequency distributions, structural delimiter patterns, and field-type signatures to identify log sources without running regex parsers.")
        desc.setFont(T.get_font(12))
        desc.setStyleSheet(f"color: {T.SLATE_600};")
        c1l.addWidget(desc)

        # Inputs layout
        in_grid = QHBoxLayout()
        in_grid.setSpacing(14)

        # Source Identifier
        src_col = QVBoxLayout()
        src_lbl = QLabel("SOURCE IDENTIFIER / LABEL")
        src_lbl.setFont(T.get_font(10.5, bold=True))
        src_lbl.setStyleSheet(f"color: {T.SLATE_600};")
        src_col.addWidget(src_lbl)

        self.src_input = QLineEdit()
        self.src_input.setText("perimeter-fw-01")
        self.src_input.setFixedWidth(240)
        self.src_input.setFixedHeight(34)
        src_col.addWidget(self.src_input)
        src_col.addStretch()
        in_grid.addLayout(src_col)

        # Sample Log Lines
        lines_col = QVBoxLayout()
        lines_lbl = QLabel("SAMPLE LOG LINES")
        lines_lbl.setFont(T.get_font(10.5, bold=True))
        lines_lbl.setStyleSheet(f"color: {T.SLATE_600};")
        lines_col.addWidget(lines_lbl)

        self.fp_input = QTextEdit()
        self.fp_input.setPlaceholderText("Paste sample log lines from this source...")
        self.fp_input.setFixedHeight(85)
        self.fp_input.setFont(T.get_font(11.5, mono=True))
        lines_col.addWidget(self.fp_input)
        in_grid.addLayout(lines_col, 1)

        c1l.addLayout(in_grid)

        # Buttons row
        b_row = QHBoxLayout()
        self.btn_load_sample = QPushButton("Load Sample Lines")
        self.btn_load_sample.setProperty("btnClass", "outline")
        self.btn_load_sample.setFixedHeight(32)
        self.btn_load_sample.clicked.connect(self._load_sample)
        b_row.addWidget(self.btn_load_sample)
        b_row.addStretch()

        self.btn_gen_fp = QPushButton("Generate Fingerprint")
        T.set_button_class(self.btn_gen_fp, "primary")
        self.btn_gen_fp.setFixedHeight(34)
        self.btn_gen_fp.clicked.connect(self._generate_fingerprint)
        b_row.addWidget(self.btn_gen_fp)
        c1l.addLayout(b_row)

        # Result box
        self.fp_result_box = QTextEdit()
        self.fp_result_box.setReadOnly(True)
        self.fp_result_box.setFont(T.get_font(11.5, mono=True))
        self.fp_result_box.setFixedHeight(120)
        self.fp_result_box.setVisible(False)
        self.fp_result_box.setStyleSheet(f"""
            QTextEdit {{
                background-color: {T.GREY_100};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 10px;
                color: {T.NAVY_800};
            }}
        """)
        c1l.addWidget(self.fp_result_box)
        main_layout.addWidget(c1)

        # ── Row 2: Match and Drift 2-Column Grid ──
        grid_row = QHBoxLayout()
        grid_row.setSpacing(16)

        # Left Card: Match Against Known DNA
        c2 = QFrame()
        c2.setStyleSheet(f"""
            QFrame {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 18px 22px;
            }}
        """)
        c2l = QVBoxLayout(c2)
        c2l.setContentsMargins(18, 16, 18, 16)
        c2l.setSpacing(12)

        m_head = QHBoxLayout()
        m_title = QLabel("Match Against Known DNA")
        m_title.setFont(T.get_font(13.5, bold=True))
        m_title.setStyleSheet(f"color: {T.NAVY_900};")
        m_head.addWidget(m_title)
        m_head.addStretch()
        m_sub = QLabel("POST /api/v1/fingerprint/match")
        m_sub.setFont(T.get_font(10.5))
        m_sub.setStyleSheet(f"color: {T.SLATE_400};")
        m_head.addWidget(m_sub)
        c2l.addLayout(m_head)

        m_desc = QLabel("Test unknown log lines against registered Log DNA profiles to identify the originating source.")
        m_desc.setFont(T.get_font(11.5))
        m_desc.setStyleSheet(f"color: {T.SLATE_600};")
        m_desc.setWordWrap(True)
        c2l.addWidget(m_desc)

        self.match_input = QTextEdit()
        self.match_input.setPlaceholderText("Paste unknown log lines...")
        self.match_input.setFixedHeight(75)
        self.match_input.setFont(T.get_font(11.5, mono=True))
        c2l.addWidget(self.match_input)

        m_btn_row = QHBoxLayout()
        m_btn_row.addStretch()
        self.btn_match = QPushButton("🔍  Match Signature")
        self.btn_match.setProperty("btnClass", "secondary")
        self.btn_match.setFixedHeight(30)
        self.btn_match.clicked.connect(self._run_match)
        m_btn_row.addWidget(self.btn_match)
        c2l.addLayout(m_btn_row)

        self.match_result = QLabel("")
        self.match_result.setFont(T.get_font(11.5, mono=True))
        self.match_result.setVisible(False)
        self.match_result.setStyleSheet(f"""
            QLabel {{
                background-color: {T.GREY_100};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 10px;
                color: {T.NAVY_900};
            }}
        """)
        c2l.addWidget(self.match_result)
        c2l.addStretch()
        grid_row.addWidget(c2, 1)

        # Right Card: Format Drift Detection
        c3 = QFrame()
        c3.setStyleSheet(f"""
            QFrame {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 18px 22px;
            }}
        """)
        c3l = QVBoxLayout(c3)
        c3l.setContentsMargins(18, 16, 18, 16)
        c3l.setSpacing(12)

        d_head = QHBoxLayout()
        d_title = QLabel("Format Drift Detection")
        d_title.setFont(T.get_font(13.5, bold=True))
        d_title.setStyleSheet(f"color: {T.NAVY_900};")
        d_head.addWidget(d_title)
        d_head.addStretch()
        d_sub = QLabel("POST /api/v1/fingerprint/drift")
        d_sub.setFont(T.get_font(10.5))
        d_sub.setStyleSheet(f"color: {T.SLATE_400};")
        d_head.addWidget(d_sub)
        c3l.addLayout(d_head)

        d_desc = QLabel("Detect structural schema changes, delimiter shifts, or firmware update format alterations.")
        d_desc.setFont(T.get_font(11.5))
        d_desc.setStyleSheet(f"color: {T.SLATE_600};")
        d_desc.setWordWrap(True)
        c3l.addWidget(d_desc)

        fid_lbl = QLabel("TARGET FINGERPRINT ID")
        fid_lbl.setFont(T.get_font(10.5, bold=True))
        fid_lbl.setStyleSheet(f"color: {T.SLATE_600};")
        c3l.addWidget(fid_lbl)

        self.drift_fid_input = QLineEdit()
        self.drift_fid_input.setPlaceholderText("Fingerprint ID (e.g. from generated profile)")
        self.drift_fid_input.setFixedHeight(30)
        self.drift_fid_input.setFont(T.get_font(11, mono=True))
        c3l.addWidget(self.drift_fid_input)

        self.drift_input = QTextEdit()
        self.drift_input.setPlaceholderText("Paste newer logs from same source...")
        self.drift_input.setFixedHeight(65)
        self.drift_input.setFont(T.get_font(11.5, mono=True))
        c3l.addWidget(self.drift_input)

        d_btn_row = QHBoxLayout()
        d_btn_row.addStretch()
        self.btn_drift = QPushButton("⚠  Detect Drift")
        self.btn_drift.setProperty("btnClass", "secondary")
        self.btn_drift.setFixedHeight(30)
        self.btn_drift.clicked.connect(self._run_drift)
        d_btn_row.addWidget(self.btn_drift)
        c3l.addLayout(d_btn_row)

        self.drift_result = QLabel("")
        self.drift_result.setFont(T.get_font(11.5, mono=True))
        self.drift_result.setVisible(False)
        self.drift_result.setStyleSheet(f"""
            QLabel {{
                background-color: {T.GREY_100};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 10px;
                color: {T.NAVY_900};
            }}
        """)
        c3l.addWidget(self.drift_result)
        c3l.addStretch()
        grid_row.addWidget(c3, 1)

        main_layout.addLayout(grid_row)

        # ── Card 4: Active Log DNA Signature Registry ──
        c4 = QFrame()
        c4.setStyleSheet(f"""
            QFrame {{
                background-color: {T.WHITE};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 16px 20px;
            }}
        """)
        c4l = QVBoxLayout(c4)
        c4l.setContentsMargins(16, 14, 16, 14)
        c4l.setSpacing(10)

        c4_head = QHBoxLayout()
        self.dna_count_lbl = QLabel("Active Log DNA Profiles (0 Registered)")
        self.dna_count_lbl.setFont(T.get_font(13.5, bold=True))
        self.dna_count_lbl.setStyleSheet(f"color: {T.NAVY_900};")
        c4_head.addWidget(self.dna_count_lbl)
        c4_head.addStretch()

        self.btn_auto_dna = QPushButton("⚡ Auto-Fingerprint Live Traffic")
        self.btn_auto_dna.setProperty("btnClass", "secondary")
        self.btn_auto_dna.setFixedHeight(28)
        self.btn_auto_dna.clicked.connect(self._auto_fingerprint_live)
        c4_head.addWidget(self.btn_auto_dna)
        c4l.addLayout(c4_head)

        self.dna_table_box = QTextEdit()
        self.dna_table_box.setReadOnly(True)
        self.dna_table_box.setFont(T.get_font(11, mono=True))
        self.dna_table_box.setFixedHeight(140)
        self.dna_table_box.setStyleSheet(f"""
            QTextEdit {{
                background-color: {T.GREY_100};
                border: 1px solid {T.GREY_200};
                border-radius: {T.BORDER_RADIUS}px;
                padding: 8px;
                color: {T.NAVY_800};
            }}
        """)
        c4l.addWidget(self.dna_table_box)
        main_layout.addWidget(c4)

        main_layout.addStretch()

    def _load_sample(self):
        recent = self.service.query_events(limit=5)
        raw_lines = [e.get("raw_event") for e in recent if e.get("raw_event")]
        if raw_lines:
            self.fp_input.setPlainText("\n".join(raw_lines))
            fmt = recent[0].get("raw_format", "live_stream")
            self.src_input.setText(f"live-{fmt}-stream")
        else:
            self.fp_input.setPlainText(SAMPLE_CEF_LINES)

    def _generate_fingerprint(self):
        text = self.fp_input.toPlainText().strip()
        label = self.src_input.text().strip() or "unlabeled_source"
        if not text:
            return

        lines = [l.strip() for l in text.split("\n") if l.strip()]
        result = self.service.log_dna_fingerprint(lines, label)

        fid = result.get("fingerprint_id", "FP_GEN")
        self._latest_fid = fid
        self.drift_fid_input.setText(fid)

        self.fp_result_box.setVisible(True)
        self.fp_result_box.setPlainText(json.dumps(result, indent=2, default=str))
        self.refresh()

    def _run_match(self):
        text = self.match_input.toPlainText().strip()
        if not text:
            return
        lines = [l.strip() for l in text.split("\n") if l.strip()]
        result = self.service.log_dna_match(lines)

        self.match_result.setVisible(True)
        if result.get("matched"):
            sim = result.get("similarity", 0.0)
            fid = result.get("fingerprint_id", "Unknown")
            self.match_result.setText(
                f"MATCH CONFIRMED: {fid}\n"
                f"Similarity Confidence: {sim:.1%}\n"
                f"Status: Profile Matched within Tolerance Threshold"
            )
        else:
            self.match_result.setText("NO MATCH: Unknown log signature does not meet threshold confidence.")

    def _run_drift(self):
        fid = self.drift_fid_input.text().strip()
        text = self.drift_input.toPlainText().strip()
        if not fid or not text:
            return
        lines = [l.strip() for l in text.split("\n") if l.strip()]
        result = self.service.log_dna_drift(fid, lines)

        self.drift_result.setVisible(True)
        drift_detected = result.get("drift_detected", False)
        sim_score = result.get("similarity_score", 1.0)
        deviation = max(0.0, round(1.0 - sim_score, 4))

        if drift_detected:
            self.drift_result.setText(
                f"DRIFT DETECTED: Deviation {deviation:.2f} (Similarity {sim_score:.1%})\n"
                f"Structural Delimiters or Token Types Altered\n"
                f"Recommendation: Retrain parser via Auto-Learn"
            )
        else:
            self.drift_result.setText(
                f"NO DRIFT DETECTED (Deviation {deviation:.2f}, Similarity {sim_score:.1%})\n"
                f"Format remains within tolerance baseline."
            )

    def refresh(self):
        """Auto-populate known DNA signatures and stream live matching/drift telemetry."""
        import time
        from datetime import datetime
        try:
            known = self.service.log_dna_list()
            self.dna_count_lbl.setText(f"Active Log DNA Profiles ({len(known)} Registered)")
            if known:
                lines = []
                for p in known:
                    fid = p.get("fingerprint_id", "")[:12]
                    lbl = p.get("source_label", "unlabeled")
                    delim = p.get("delimiter", "' '")
                    ent = p.get("entropy", 0.0)
                    sig = p.get("field_type_signature", "—")
                    avg_len = p.get("avg_line_length", 0)
                    lines.append(f"• [{fid}] Source: {lbl:<18} | Delim: {delim:<4} | Entropy: {ent:.3f} | AvgLen: {avg_len}B | Sig: {sig}")
                self.dna_table_box.setPlainText("\n".join(lines))
            else:
                self.dna_table_box.setPlainText("No Log DNA profiles registered yet. Click 'Auto-Fingerprint Live Traffic' or generate a profile above.")

            # Live Stream Telemetry Integration
            telem = self.service.get_live_dna_telemetry() if hasattr(self.service, "get_live_dna_telemetry") else None
            if telem:
                m = telem.get("match", {})
                d = telem.get("drift", {})
                t_str = datetime.fromtimestamp(telem.get("timestamp", time.time())).strftime("%H:%M:%S")

                # Update live match box
                self.match_result.setVisible(True)
                if m.get("matched"):
                    sim = m.get("similarity", 1.0)
                    fid = m.get("fingerprint_id", "Known Profile")
                    self.match_result.setText(
                        f"● LIVE STREAM DNA MATCH: ACTIVE (Sync: {t_str})\n"
                        f"Matched Profile: {fid}\n"
                        f"Similarity Confidence: {sim:.1%}\n"
                        f"Status: Profile Matched within Tolerance Threshold ({telem.get('sample_count', 0)} events evaluated)"
                    )
                else:
                    self.match_result.setText(f"● LIVE STREAM DNA MONITOR (Sync: {t_str}): Ingestion conforming to known signatures.")

                # Update live drift box
                self.drift_result.setVisible(True)
                drift_detected = d.get("drift_detected", False)
                sim_score = d.get("similarity_score", 1.0)
                dev = max(0.0, round(1.0 - sim_score, 4))
                if drift_detected:
                    self.drift_result.setText(
                        f"● LIVE STRUCTURAL DRIFT DETECTED (Sync: {t_str})\n"
                        f"Deviation: {dev:.2%} (Similarity: {sim_score:.1%})\n"
                        f"Structural Delimiters or Token Types Altered"
                    )
                else:
                    self.drift_result.setText(
                        f"● LIVE STRUCTURAL INTEGRITY: STABLE (Sync: {t_str})\n"
                        f"Drift Deviation: {dev:.2%} (Similarity: {sim_score:.1%})\n"
                        f"Format adheres strictly to baseline schema (Zero Mutations)"
                    )
        except Exception:
            pass

    def _auto_fingerprint_live(self):
        events = self.service.query_events(limit=50)
        if not events:
            return
        by_fmt = {}
        for ev in events:
            rf = ev.get("raw_format", "stream")
            if rf not in by_fmt and ev.get("raw_event"):
                by_fmt[rf] = ev["raw_event"]
        for rf, raw in by_fmt.items():
            self.service.log_dna_fingerprint([raw], label=f"live_{rf}")
        self.refresh()

