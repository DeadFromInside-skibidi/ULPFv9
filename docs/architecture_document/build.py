"""
Build docs/ARCHITECTURE_DOCUMENT.pdf (the submission's architecture document, max 2 pages).

    python docs/architecture_document/build.py

Needs reportlab (``pip install "ulpf[docs]"``). Fails if the PDF exceeds two pages.
Measured figures come from docs/architecture_document/figures.json, which cites
the result file of each number.
"""
from __future__ import annotations

import json
import os
import sys

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

HERE = os.path.dirname(os.path.abspath(__file__))
DOCS = os.path.dirname(HERE)
OUT = os.path.join(DOCS, "ARCHITECTURE_DOCUMENT.pdf")

INK, MUTED, ACCENT, LIGHT = colors.HexColor("#1b2430"), colors.HexColor("#5b6675"), colors.HexColor("#1f5fa8"), colors.HexColor("#eef3f9")

body = ParagraphStyle("b", fontName="Helvetica", fontSize=8.2, leading=10.4, textColor=INK, alignment=TA_LEFT)
small = ParagraphStyle("s", parent=body, fontSize=7.4, leading=9.2)
h1 = ParagraphStyle("h1", parent=body, fontName="Helvetica-Bold", fontSize=15, leading=18, textColor=INK)
sub = ParagraphStyle("sub", parent=body, fontSize=8.6, textColor=MUTED, leading=11)
h2 = ParagraphStyle("h2", parent=body, fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=ACCENT,
                    spaceBefore=5, spaceAfter=2)
cell = ParagraphStyle("c", parent=body, fontSize=7.3, leading=8.9)
cellb = ParagraphStyle("cb", parent=cell, fontName="Helvetica-Bold")


def table(rows, widths, header=True):
    data = [[Paragraph(str(c), cellb if (header and i == 0) else cell) for c in r] for i, r in enumerate(rows)]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c9d3df")),
             ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
             ("TOPPADDING", (0, 0), (-1, -1), 1.6), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.6)]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), LIGHT))
    t.setStyle(TableStyle(style))
    return t


def box(d, x, y, w, h, title, lines, fill=LIGHT):
    d.add(Rect(x, y, w, h, fillColor=fill, strokeColor=ACCENT, strokeWidth=0.6, rx=2, ry=2))
    d.add(String(x + 4, y + h - 9, title, fontName="Helvetica-Bold", fontSize=7.4, fillColor=INK))
    for i, l in enumerate(lines):
        d.add(String(x + 4, y + h - 18 - i * 8, l, fontName="Helvetica", fontSize=6.3, fillColor=MUTED))


def arrow(d, x1, y1, x2, y2):
    d.add(Line(x1, y1, x2, y2, strokeColor=ACCENT, strokeWidth=0.9))
    if x2 > x1:
        d.add(Polygon([x2, y2, x2 - 4, y2 + 2.2, x2 - 4, y2 - 2.2], fillColor=ACCENT, strokeColor=ACCENT))
    else:
        d.add(Polygon([x2, y2, x2 + 2.2, y2 + 4, x2 - 2.2, y2 + 4], fillColor=ACCENT, strokeColor=ACCENT))


def diagram(width):
    d = Drawing(width, 150)
    w = (width - 4 * 10) / 5
    xs = [i * (w + 10) for i in range(5)]
    y, h = 62, 82
    box(d, xs[0], y, w, h, "Inputs (15)", ["syslog UDP/TCP/TLS, file", "HTTP, OTLP, journald", "Windows events, NetFlow",
                                           "SNMP v1/v2c/v3, MQTT, Kafka", "CloudTrail, Pub/Sub, Okta,", "Entra ID, Event Hubs"])
    box(d, xs[1], y, w, h, "Journal (host)", ["sequence + SHA-256 per record", "CRC blocks, torn-tail repair",
                                              "AES-256-GCM (defence)", "= raw archive + replay", "commit watermark"])
    box(d, xs[2], y, w, h, "Workers (N processes)", ["detect -> plugin / built-in /", "learned (APG) / raw fallback",
                                                     "-> unified schema 1.1.0", "-> enrich -> drift, anomaly", "-> routes -> encode"])
    box(d, xs[3], y, w, h, "Disk buffers", ["one per output", "segment = journal range", "exactly once, bounded",
                                            "block | drop_oldest", "retry, back-off, DLQ"])
    box(d, xs[4], y, w, h, "Outputs (12)", ["DuckDB store, file, Parquet", "S3, Elasticsearch, Splunk", "Kafka, Loki, OTLP, syslog",
                                            "(CEF/LEEF), Azure Monitor,", "Chronicle; view per output:", "unified | ECS | OCSF"])
    for i in range(4):
        arrow(d, xs[i] + w, y + h / 2, xs[i + 1], y + h / 2)
    box(d, xs[1], 4, w, 46, "Evidence sealer", ["Merkle root per window,", "chained + HMAC, emitted", "as events; row MACs"],
        fill=colors.HexColor("#f6f1e8"))
    box(d, xs[2], 4, w, 46, "Host analytics", ["cross-source correlation,", "kill-chain stages ->", "derived events"],
        fill=colors.HexColor("#f6f1e8"))
    box(d, xs[3], 4, w * 2 + 10, 46, "Control plane", ["API (roles, TLS/mTLS), audit log, reload,",
                                                         "egress guard in every process, cluster",
                                                         "heartbeats + placement, metrics"], fill=colors.HexColor("#f6f1e8"))
    arrow(d, xs[1] + w / 2, y, xs[1] + w / 2, 50)
    return d


def build() -> int:
    with open(os.path.join(HERE, "figures.json"), encoding="utf-8") as f:
        fig = json.load(f)
    doc = SimpleDocTemplate(OUT, pagesize=A4, leftMargin=14 * mm, rightMargin=14 * mm, topMargin=12 * mm,
                            bottomMargin=11 * mm, title="ULPF Architecture", author="ULPF team")
    W = A4[0] - 28 * mm
    s = []
    s.append(Paragraph("ULPF: Universal Log Pre-processing Framework (v9)", h1))
    s.append(Paragraph("Architecture document, SIH problem statement 26156. It covers converting any perimeter-device "
                       "log into a standardised, lossless, analytics-ready representation, offline.", sub))
    s.append(Spacer(1, 4))
    s.append(Paragraph("1. Approach", h2))
    s.append(Paragraph(
        "ULPF is a streaming pipeline built around a <b>durable journal</b>. Every received record is written, "
        "hashed (SHA-256) and numbered before anything else happens to it. The journal serves as the raw archive "
        "(requirement a), the replay log after a crash, the index that traces a normalised event back to its "
        "original bytes (d), and the feed for tamper-evident seals. Worker processes turn records into one "
        "<b>unified, versioned schema</b> and write each output's encoding into a disk buffer named by the journal "
        "range. Event IDs derive from (node, sequence), so a replay rewrites the same segments and IDs: delivery "
        "into the buffers is exactly once, and idempotent outputs never see duplicates.", body))
    s.append(Spacer(1, 3))
    s.append(diagram(W))
    s.append(Paragraph("2. Components and data flow", h2))
    s.append(table([
        ["Stage", "What happens", "Guarantee"],
        ["Ingest", "15 input types; CIDR allow-lists, per-source rate limits; bounded worker queues push back on "
                   "TCP, files, HTTP (429) and pull inputs", "Journaled before acknowledgement; checkpoints persisted "
                                                               "only once durable"],
        ["Parse", "Format detection; installed plugins, then 8 built-in parsers (CEF, LEEF, syslog, JSON, XML / "
                  "Windows Event, key-value, CSV, W3C/CLF), then APG-learned parsers, then the raw fallback",
         "Every line yields one event; source attributes kept in <i>parsed_fields</i>"],
        ["Normalise, enrich", "100-field schema 1.1.0, UTC timestamps, 0–10 severity, field aliases, ECS dotted "
                              "paths; offline GeoIP (MaxMind format) and IOC tags",
         "Schema registry; minor versions are additive (<i>ulpf schema diff</i>)"],
        ["Analyse", "Per-source Log DNA drift and anomaly detection in the workers; cross-source correlation with "
                    "kill-chain stages in the host", "Results are ordinary events (drift, anomaly, correlation, seal)"],
        ["Deliver", "12 output types; unified, ECS or OCSF view per output; routing by kind, input, source, "
                    "format, category, severity or field", "Bounded buffers, retry with back-off, dead-letter queue "
                                                           "with reasons"],
    ], [0.13 * W, 0.55 * W, 0.32 * W]))
    s.append(Paragraph("3. The five differentiators (each proven by a live-pipeline test)", h2))
    s.append(table([
        ["USP", "Capability", "Demonstrated"],
        ["U1 Autonomous learning", "Unknown formats are mined, validated, signed and activated from live traffic "
                                   "without a restart; defence mode holds them for operator approval",
         f"{fig['u1']}"],
        ["U2 Evidence chain", "Rolling Merkle seals, chained and HMAC'd, emitted to outputs; inclusion proofs; "
                              "keyed row MACs on stored events", f"{fig['u2']}"],
        ["U3 One schema everywhere", "The same canonical event at every output, with pure ECS and OCSF views",
         "Golden files, 7 formats × 3 views; store, Elasticsearch and file outputs identical"],
        ["U4 Offline by default", "An audit-hook egress guard in every process: it records destinations, and "
                                  "in defence mode blocks any address not on the allow-list",
         "Default config contacts nothing; an unlisted connection fails before a packet leaves"],
        ["U5 Stream analytics", "Drift, anomaly and correlation on the stream, as events", f"{fig['u5']}"],
    ], [0.18 * W, 0.47 * W, 0.35 * W]))

    s.append(Paragraph("4. Two operating modes", h2))
    s.append(table([
        ["", "industry", "defence"],
        ["Learned parsers", "active automatically (canary, then active)", "pending until <i>ulpf parsers approve</i>"],
        ["Journal", "fsync every 200 ms", "AES-256-GCM, fsync per write, 180-day retention"],
        ["Network", "destinations recorded; cloud connectors allowed", "allow-list enforced in process and in config; "
                                                                          "TLS listeners and outputs; no cloud"],
        ["Stored rows / plugins", "raw hash checked against the journal; installed plugins load",
         "every column MAC'd; only allow-listed plugin package hashes load"],
    ], [0.2 * W, 0.38 * W, 0.42 * W]))
    s.append(Paragraph("A rule can be waived only by naming it in <i>overrides:</i>. The waiver is printed at start-up "
                       "and written to the hash-chained audit log.", small))

    s.append(Paragraph("5. Deployment", h2))
    s.append(Paragraph(
        "One package runs everywhere: Windows and Linux hosts, a systemd unit (<i>systemctl reload</i> applies a "
        "validated config), a Windows service (NSSM), a container (<i>docker compose up</i> runs the live pipeline "
        "with its health check), and an offline wheel bundle for air-gapped networks. All state lives in one data "
        "directory: journal, buffers, store, seals, keys, learned parsers and audit log. "
        "<b>Scale-out</b> uses shared-nothing nodes that coordinate through a shared directory. Push inputs run on "
        "every node behind a load balancer; inputs with <i>placement: one</i> run on exactly one live node, chosen "
        "by rendezvous hashing, and fail over to the next node from a shared checkpoint. "
        "<i>ulpf cluster status</i> shows placement, and the API can query all nodes at once.", body))

    s.append(Paragraph("6. Measured performance and sizing", h2))
    perf = [["Measurement (Intel i5-8279U laptop, 4 cores; TCP, 9 formats; journal, seals and analytics on)",
             "Result", "Result file"]] + [[r[0], r[1], r[2]] for r in fig["performance"]]
    s.append(table(perf, [0.55 * W, 0.17 * W, 0.28 * W]))
    s.append(Paragraph(fig["sizing"], small))

    s.append(Paragraph("7. Reliability, verified by failure injection", h2))
    s.append(Paragraph(
        "kill -9 during file ingest, then a restart: no line missing, none twice. A sink outage: the buffer drains "
        "with no loss and no duplicates. A full buffer: <i>block</i> stalls the inputs without loss, "
        "<i>drop_oldest</i> counts every dropped event exactly. A TCP partition: every line sent on a surviving "
        "connection is stored. The DLQ stays within its cap. Multi-node: a graceful hand-over loses and duplicates "
        "nothing. Defects these tests exposed (a buffer-ordering deadlock, DLQ overshoot, shutdown races, Windows "
        "UDP resets) are fixed and covered by regression tests.", body))
    s.append(Paragraph("8. Problem-statement coverage", h2))
    s.append(Paragraph(fig["coverage"], body))

    doc.build(s)
    from pypdf import PdfReader
    pages = len(PdfReader(OUT).pages)
    print(f"{OUT}: {pages} page(s)")
    if pages > 2:
        print("ERROR: the architecture document must not exceed two pages", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(build())
