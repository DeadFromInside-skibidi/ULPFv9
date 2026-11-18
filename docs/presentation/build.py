"""
Build the technical presentation (max 5 slides):

    docs/PRESENTATION.pptx   (python-pptx)
    docs/PRESENTATION.pdf    (reportlab, same content, for viewers without PowerPoint)

    python docs/presentation/build.py

Numbers come from docs/architecture_document/figures.json (each cites its result file).
Fails if either file has more than five slides.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DOCS = os.path.dirname(HERE)

with open(os.path.join(DOCS, "architecture_document", "figures.json"), encoding="utf-8") as _f:
    FIG = json.load(_f)

SLIDES = [
    {
        "title": "The problem, and what ULPF does about it",
        "bullets": [
            "Perimeter and enterprise devices log in hundreds of formats: syslog, CEF, LEEF, JSON, XML, CSV, "
            "key-value, vendor-proprietary.",
            "Analysts need one standardised, lossless and traceable representation, delivered to SIEMs, data "
            "lakes and ML, including in air-gapped networks.",
            "ULPF v9 is a live pipeline: 15 input types → durable journal → worker processes → 12 output types, "
            "with no loss under failure.",
            "Every record is kept byte for byte, hashed, sealed, normalised to one versioned schema, and traceable "
            "from any event back to its original bytes.",
            "Two modes. Industry favours throughput and cloud connectors; defence enforces an encrypted journal, "
            "TLS, an egress allow-list and operator approval.",
        ],
    },
    {
        "title": "Architecture",
        "bullets": [
            "Journal first: sequence number + SHA-256 per record, then the raw archive, replay and the evidence feed.",
            "Workers: detect → plugin / built-in / learned / raw fallback → unified schema → enrich → drift + "
            "anomaly → routes.",
            "Disk buffer per output, named by journal range: exactly-once into buffers, bounded, retry, DLQ.",
            "Host: Merkle seals (chained + HMAC), cross-source correlation, API (roles, TLS), audit chain, "
            "egress guard.",
            "Scale-out: shared-nothing nodes, rendezvous-hashed placement, failover from shared checkpoints.",
        ],
    },
    {
        "title": "Five differentiators, demonstrated on the live pipeline",
        "bullets": [
            "U1 Autonomous learning: " + FIG["u1"],
            "U2 Tamper-evident evidence: " + FIG["u2"],
            "U3 One schema at every output: golden files for unified / ECS / OCSF; store, Elasticsearch and "
            "file outputs identical.",
            "U4 Verifiably offline: the default config opened no outbound connection; in defence mode an unlisted "
            "connection fails before a packet leaves.",
            "U5 Stream analytics: " + FIG["u5"],
        ],
    },
    {
        "title": "Measured performance and resilience",
        "table": [["Measurement", "Result"]] + [[r[0], r[1]] for r in FIG["performance"]],
        "note": "Chaos tests: kill -9 + restart, sink outage, full buffers (block / drop_oldest), TCP partition, "
                "DLQ bound, multi-node failover, each with zero loss or exactly counted drops. " + FIG["sizing"],
    },
    {
        "title": "Problem-statement coverage",
        "bullets": [
            "Sources: network devices, servers and OS, applications, databases, cloud, containers, EDR, IAM, "
            "IoT (MQTT), hardware: each has an input and a test.",
            "a–d: lossless raw archive, source attributes kept, 100-field taxonomy, raw retrieval by event ID "
            "with a hash check.",
            "e: one-command onboarding (" + FIG["onboarding"] + "); f: API, desktop console, Grafana dashboard.",
            "g–h: SIEM and lake outputs (QRadar LEEF, Splunk, Elastic, Sentinel, Chronicle, S3, Parquet); ML "
            "feature export with a column card.",
            "i–k: measured parser effort, defence mode for air-gapped networks, Docker image with health check. "
            "Details: docs/PROBLEM_STATEMENT_COVERAGE.md",
        ],
    },
]


def build_pptx(path: str) -> int:
    from pptx import Presentation
    from pptx.dml.color import RGBColor
    from pptx.util import Inches, Pt
    prs = Presentation()
    prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
    blank = prs.slide_layouts[6]
    ink, accent, muted = RGBColor(0x1B, 0x24, 0x30), RGBColor(0x1F, 0x5F, 0xA8), RGBColor(0x5B, 0x66, 0x75)
    for n, sl in enumerate(SLIDES, 1):
        s = prs.slides.add_slide(blank)
        tb = s.shapes.add_textbox(Inches(0.6), Inches(0.35), Inches(12.1), Inches(0.9)).text_frame
        tb.text = sl["title"]
        tb.paragraphs[0].runs[0].font.size = Pt(30)
        tb.paragraphs[0].runs[0].font.bold = True
        tb.paragraphs[0].runs[0].font.color.rgb = ink
        foot = s.shapes.add_textbox(Inches(0.6), Inches(6.95), Inches(12.1), Inches(0.4)).text_frame
        foot.text = f"ULPF v9  ·  SIH problem statement 26156  ·  {n}/{len(SLIDES)}"
        foot.paragraphs[0].runs[0].font.size = Pt(11)
        foot.paragraphs[0].runs[0].font.color.rgb = muted
        if "bullets" in sl:
            body = s.shapes.add_textbox(Inches(0.6), Inches(1.35), Inches(12.1), Inches(5.4)).text_frame
            body.word_wrap = True
            for i, b in enumerate(sl["bullets"]):
                p = body.paragraphs[0] if i == 0 else body.add_paragraph()
                p.text = "•  " + b
                p.space_after = Pt(10)
                for r in p.runs:
                    r.font.size = Pt(18)
                    r.font.color.rgb = ink
        if "table" in sl:
            rows, cols = len(sl["table"]), 2
            t = s.shapes.add_table(rows, cols, Inches(0.6), Inches(1.35), Inches(12.1), Inches(0.42 * rows)).table
            t.columns[0].width, t.columns[1].width = Inches(8.6), Inches(3.5)
            for i, row in enumerate(sl["table"]):
                for j, v in enumerate(row):
                    c = t.cell(i, j)
                    c.text = str(v)
                    for p in c.text_frame.paragraphs:
                        for r in p.runs:
                            r.font.size = Pt(15)
                            r.font.bold = i == 0
            note = s.shapes.add_textbox(Inches(0.6), Inches(1.5 + 0.42 * rows), Inches(12.1), Inches(1.6)).text_frame
            note.word_wrap = True
            note.text = sl["note"]
            for r in note.paragraphs[0].runs:
                r.font.size = Pt(14)
                r.font.color.rgb = accent
    prs.save(path)
    return len(prs.slides)


def build_pdf(path: str) -> int:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import landscape
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    size = landscape((7.5 * inch, 13.333 * inch))
    ink, accent = colors.HexColor("#1b2430"), colors.HexColor("#1f5fa8")
    title = ParagraphStyle("t", fontName="Helvetica-Bold", fontSize=26, leading=32, textColor=ink)
    bullet = ParagraphStyle("b", fontName="Helvetica", fontSize=15.5, leading=21, textColor=ink, leftIndent=14,
                            bulletIndent=0, spaceAfter=8)
    note = ParagraphStyle("n", parent=bullet, fontSize=12.5, leading=17, textColor=accent, leftIndent=0)
    cell = ParagraphStyle("c", fontName="Helvetica", fontSize=12.5, leading=15, textColor=ink)
    doc = SimpleDocTemplate(path, pagesize=size, leftMargin=0.6 * inch, rightMargin=0.6 * inch,
                            topMargin=0.45 * inch, bottomMargin=0.4 * inch, title="ULPF v9 presentation")
    story = []
    for n, sl in enumerate(SLIDES, 1):
        story.append(Paragraph(sl["title"], title))
        story.append(Spacer(1, 12))
        for b in sl.get("bullets", []):
            story.append(Paragraph(b, bullet, bulletText="•"))
        if "table" in sl:
            data = [[Paragraph(str(v), cell) for v in row] for row in sl["table"]]
            t = Table(data, colWidths=[8.4 * inch, 3.6 * inch])
            t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d3df")),
                                   ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef3f9"))]))
            story.append(t)
            story.append(Spacer(1, 10))
            story.append(Paragraph(sl["note"], note))
        if n < len(SLIDES):
            story.append(PageBreak())
    doc.build(story)
    from pypdf import PdfReader
    return len(PdfReader(path).pages)


def main() -> int:
    pptx_path, pdf_path = os.path.join(DOCS, "PRESENTATION.pptx"), os.path.join(DOCS, "PRESENTATION.pdf")
    n_pptx, n_pdf = build_pptx(pptx_path), build_pdf(pdf_path)
    print(f"{pptx_path}: {n_pptx} slides\n{pdf_path}: {n_pdf} pages")
    if n_pptx > 5 or n_pdf > 5:
        print("ERROR: the presentation must not exceed five slides", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
