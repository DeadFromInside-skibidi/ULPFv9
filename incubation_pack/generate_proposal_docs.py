"""
Builds the incubation pack's shareable files from the Markdown sources:

    ULPF_Incubation_Business_Proposal.docx   (python-docx: cover page, contents, tables)
    ULPF_Incubation_Business_Proposal.pdf    (reportlab: cover page, linked contents, bookmarks)
    PITCH_DECK_10_SLIDES.md                  (slide script; numbers come from model.py)

    python incubation_pack/generate_proposal_docs.py

The Markdown files are the single source; edit them (or model.py) and re-run.
Only the Markdown subset used in the pack is supported: headings, paragraphs,
block quotes, bullet and numbered lists, pipe tables, fenced code, rules, and
inline bold, italic, code and links.
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import model  # noqa: E402

SOURCES = ["01_INCUBATION_PROPOSAL.md", "02_MARKET_RESEARCH_AND_COMPETITORS.md", "03_SUSTAINABLE_BUSINESS_MODEL.md"]
DOCX_OUT = os.path.join(HERE, "ULPF_Incubation_Business_Proposal.docx")
PDF_OUT = os.path.join(HERE, "ULPF_Incubation_Business_Proposal.pdf")
DECK_OUT = os.path.join(HERE, "PITCH_DECK_10_SLIDES.md")

TITLE = "ULPF — Incubation Business Proposal"
SUBTITLE = ("Universal Log Pre-processing Framework: a sovereign, self-learning log pipeline that cuts SIEM "
            "ingest and keeps tamper-evident evidence on Indian soil")
PREPARED_FOR = ("Amity Innovation Incubator · DSCI Centre of Excellence (Noida) · iDEX DISC · "
                "MeitY TIDE 2.0 / SAMRIDH")
EDITION = "Software version 9.0.0 · October 2026"
EVIDENCE_NOTE = ("Every technical figure in this document comes from the ULPF repository's source code or from a "
                 "measured result file under benchmarks/results/, named next to the figure. Market figures cite "
                 "their published source. Financial projections are a planning model (incubation_pack/model.py) "
                 "with labelled assumptions, not a forecast.")
PARTS = ["Part 1 — Incubation Proposal", "Part 2 — Market Research and Competitor Strategy",
         "Part 3 — Sustainable Business Model and Go-to-Market"]


# ---------------------------------------------------------------- Markdown → blocks
@dataclass
class Block:
    kind: str                 # h, p, quote, ul, ol, table, code, hr
    level: int = 0
    text: str = ""
    items: list | None = None
    header: list | None = None
    rows: list | None = None


def _cells(line: str) -> list[str]:
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [c.strip() for c in s.split("|")]


def parse_markdown(text: str) -> list[Block]:
    lines = text.splitlines()
    out: list[Block] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        s = line.strip()
        if not s:
            i += 1
            continue
        if s.startswith("```"):
            buf = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            out.append(Block("code", text="\n".join(buf)))
            i += 1
            continue
        m = re.match(r"(#{1,6})\s+(.*)", s)
        if m:
            out.append(Block("h", level=len(m.group(1)), text=m.group(2).strip()))
            i += 1
            continue
        if re.fullmatch(r"-{3,}|\*{3,}", s):
            out.append(Block("hr"))
            i += 1
            continue
        if s.startswith("|") and i + 1 < len(lines) and re.fullmatch(r"\|?\s*:?-{2,}.*", lines[i + 1].strip()):
            header = _cells(s)
            rows = []
            i += 2
            while i < len(lines) and lines[i].strip().startswith("|"):
                r = _cells(lines[i])
                rows.append((r + [""] * len(header))[:len(header)])
                i += 1
            out.append(Block("table", header=header, rows=rows))
            continue
        if s.startswith(">"):
            buf = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                buf.append(lines[i].strip()[1:].strip())
                i += 1
            paras, cur = [], []
            for b in buf:
                if b:
                    cur.append(b)
                elif cur:
                    paras.append(" ".join(cur))
                    cur = []
            if cur:
                paras.append(" ".join(cur))
            out.extend(Block("quote", text=p) for p in paras)
            continue
        if re.match(r"[-*]\s+", s) or re.match(r"\d+\.\s+", s):
            ordered = bool(re.match(r"\d+\.\s+", s))
            pat = r"\d+\.\s+" if ordered else r"[-*]\s+"
            items: list[str] = []
            while i < len(lines):
                t = lines[i]
                if re.match(pat, t.strip()) and (len(t) - len(t.lstrip())) < 2:
                    items.append(re.sub(pat, "", t.strip(), count=1))
                elif t.strip() and t.startswith("  ") and items:
                    items[-1] += " " + t.strip()            # wrapped / nested continuation
                else:
                    break
                i += 1
            out.append(Block("ol" if ordered else "ul", items=items))
            continue
        buf = []
        while i < len(lines):
            t = lines[i].strip()
            if (not t or t.startswith(("#", "|", ">", "```")) or re.match(r"[-*]\s+|\d+\.\s+", t)
                    or re.fullmatch(r"-{3,}", t)):
                break
            buf.append(t)
            i += 1
        out.append(Block("p", text="\n".join(buf)))
    return out


# ---------------------------------------------------------------- inline markup → runs
@dataclass
class Run:
    text: str
    bold: bool = False
    italic: bool = False
    code: bool = False
    url: str | None = None


_INLINE = re.compile(r"`([^`]+)`|\[([^\]]+)\]\(([^)\s]+)\)|\*\*(.+?)\*\*|(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])")


def runs(text: str, bold=False, italic=False, url=None) -> list[Run]:
    out, pos = [], 0
    for m in _INLINE.finditer(text):
        if m.start() > pos:
            out.append(Run(text[pos:m.start()], bold, italic, False, url))
        if m.group(1) is not None:
            out.append(Run(m.group(1), bold, italic, True, url))
        elif m.group(2) is not None:
            out.extend(runs(m.group(2), bold, italic, m.group(3)))
        elif m.group(4) is not None:
            out.extend(runs(m.group(4), True, italic, url))
        else:
            out.extend(runs(m.group(5), bold, True, url))
        pos = m.end()
    if pos < len(text):
        out.append(Run(text[pos:], bold, italic, False, url))
    return out


def plain(text: str) -> str:
    return "".join(r.text for r in runs(text))


def load_parts() -> list[list[Block]]:
    parts = []
    for name in SOURCES:
        with open(os.path.join(HERE, name), encoding="utf-8") as f:
            blocks = parse_markdown(f.read())
        parts.append(blocks)
    return parts


# ---------------------------------------------------------------- DOCX
def build_docx(parts: list[list[Block]], path: str) -> None:
    from docx import Document
    from docx.enum.section import WD_ORIENT  # noqa: F401  (kept for readers changing orientation)
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
    from docx.opc.constants import RELATIONSHIP_TYPE as RT
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Cm, Pt, RGBColor

    doc = Document()
    sec = doc.sections[0]
    sec.page_height, sec.page_width = Cm(29.7), Cm(21.0)
    for side in ("left_margin", "right_margin"):
        setattr(sec, side, Cm(2.0))
    sec.top_margin = sec.bottom_margin = Cm(2.0)
    normal = doc.styles["Normal"]
    normal.font.name, normal.font.size = "Calibri", Pt(10.5)
    navy = RGBColor(0x1F, 0x3A, 0x5F)
    for lvl, size in ((1, 18), (2, 14), (3, 12)):
        st = doc.styles[f"Heading {lvl}"]
        st.font.name, st.font.size, st.font.color.rgb = "Calibri", Pt(size), navy

    def add_runs(par, text, size=None, base_bold=False):
        for r in runs(text, bold=base_bold):
            if r.url:
                rid = par.part.relate_to(r.url, RT.HYPERLINK, is_external=True)
                link = OxmlElement("w:hyperlink")
                link.set(qn("r:id"), rid)
                run = par.add_run(r.text)
                run.font.color.rgb = RGBColor(0x05, 0x63, 0xC1)
                run.font.underline = True
                link.append(run._r)
                par._p.append(link)
            else:
                run = par.add_run(r.text)
            run.bold, run.italic = r.bold, r.italic
            if r.code:
                run.font.name = "Consolas"
                run.font.size = Pt((size or 10.5) - 1)
            elif size:
                run.font.size = Pt(size)

    def add_text(par, text, size=None, base_bold=False):
        for k, line in enumerate(text.split("\n")):
            if k:
                par.add_run().add_break()
            add_runs(par, line, size, base_bold)

    def shade(cell, fill):
        tc_pr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), fill)
        tc_pr.append(shd)

    def repeat_header(row):
        tr_pr = row._tr.get_or_add_trPr()
        el = OxmlElement("w:tblHeader")
        el.set(qn("w:val"), "true")
        tr_pr.append(el)

    # footer with page numbers
    fpar = sec.footer.paragraphs[0]
    fpar.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = fpar.add_run("ULPF incubation proposal · page ")
    r.font.size = Pt(8)
    fld = OxmlElement("w:fldSimple")
    fld.set(qn("w:instr"), "PAGE")
    fr = OxmlElement("w:r")
    ft = OxmlElement("w:t")
    ft.text = "1"
    fr.append(ft)
    fld.append(fr)
    fpar._p.append(fld)

    # cover page
    for _ in range(6):
        doc.add_paragraph()
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(TITLE)
    r.bold, r.font.size, r.font.color.rgb = True, Pt(28), navy
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(SUBTITLE)
    r.italic, r.font.size = True, Pt(13)
    doc.add_paragraph()
    for line, size in ((f"Prepared for: {PREPARED_FOR}", 11), (EDITION, 11)):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.add_run(line).font.size = Pt(size)
    for _ in range(6):
        doc.add_paragraph()
    p = doc.add_paragraph()
    r = p.add_run("Evidence policy. ")
    r.bold, r.font.size = True, Pt(9)
    p.add_run(EVIDENCE_NOTE).font.size = Pt(9)
    p.add_run().add_break(WD_BREAK.PAGE)

    # contents
    doc.add_heading("Contents", level=1)
    for k, blocks in enumerate(parts):
        p = doc.add_paragraph()
        p.add_run(PARTS[k]).bold = True
        for b in blocks:
            if b.kind == "h" and b.level == 2:
                doc.add_paragraph(plain(b.text), style="List Bullet")

    for k, blocks in enumerate(parts):
        doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
        for b in blocks:
            if b.kind == "h":
                text = PARTS[k] if b.level == 1 else plain(b.text)
                doc.add_heading(text, level=min(b.level, 3))
                if b.level == 1:
                    sub = plain(b.text)
                    q = doc.add_paragraph()
                    q.add_run(sub).italic = True
            elif b.kind == "p":
                add_text(doc.add_paragraph(), b.text)
            elif b.kind == "quote":
                q = doc.add_paragraph()
                q.paragraph_format.left_indent = Cm(0.8)
                add_text(q, b.text, size=9.5)
            elif b.kind in ("ul", "ol"):
                for it in b.items:
                    add_text(doc.add_paragraph(style="List Bullet" if b.kind == "ul" else "List Number"), it)
            elif b.kind == "code":
                for line in b.text.split("\n"):
                    q = doc.add_paragraph()
                    q.paragraph_format.space_after = Pt(0)
                    q.paragraph_format.space_before = Pt(0)
                    rr = q.add_run(line or " ")
                    rr.font.name, rr.font.size = "Consolas", Pt(7)
            elif b.kind == "table":
                ncol = len(b.header)
                size = 9 if ncol <= 3 else 8 if ncol <= 5 else 7
                t = doc.add_table(rows=1 + len(b.rows), cols=ncol)
                t.style = "Table Grid"
                t.alignment = WD_TABLE_ALIGNMENT.CENTER
                for c, h in enumerate(b.header):
                    cell = t.rows[0].cells[c]
                    cell.paragraphs[0].text = ""
                    add_text(cell.paragraphs[0], h, size, base_bold=True)
                    shade(cell, "D9E2F3")
                repeat_header(t.rows[0])
                for ri, row in enumerate(b.rows, start=1):
                    for c, v in enumerate(row):
                        add_text(t.rows[ri].cells[c].paragraphs[0], v, size)
                doc.add_paragraph()
            elif b.kind == "hr":
                pass
    doc.save(path)


# ---------------------------------------------------------------- PDF
def build_pdf(parts: list[list[Block]], path: str) -> None:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether, PageBreak, PageTemplate, Paragraph, Spacer,
                                    Table, TableStyle, XPreformatted)
    from reportlab.platypus.tableofcontents import TableOfContents

    fonts = _register_fonts(pdfmetrics, TTFont)
    body, bold, ital, boldital, mono, sym = fonts
    pdfmetrics.registerFontFamily("Body", normal=body, bold=bold, italic=ital, boldItalic=boldital)
    glyphs = {name: set(pdfmetrics.getFont(name).face.charToGlyph) for name in (body, mono)}
    sym_glyphs = set(pdfmetrics.getFont(sym).face.charToGlyph) if sym else set()

    def esc(s: str, face: str) -> str:
        out = []
        for ch in s:
            e = {"&": "&amp;", "<": "&lt;", ">": "&gt;"}.get(ch, ch)
            if ord(ch) > 127 and ord(ch) not in glyphs[face]:
                e = f'<font name="{sym}">{ch}</font>' if ord(ch) in sym_glyphs else "?"
            out.append(e)
        return "".join(out)

    def markup(text: str) -> str:
        parts_ = []
        for line in text.split("\n"):
            seg = []
            for r in runs(line):
                s = (f'<font name="{mono}" size="-1">{esc(r.text, mono)}</font>' if r.code
                     else esc(r.text, body))
                if r.bold:
                    s = f"<b>{s}</b>"
                if r.italic:
                    s = f"<i>{s}</i>"
                if r.url:
                    s = f'<link href="{esc(r.url, body)}" color="#0563C1"><u>{s}</u></link>'
                seg.append(s)
            parts_.append("".join(seg))
        return "<br/>".join(parts_)

    navy = colors.HexColor("#1F3A5F")
    base = ParagraphStyle("base", fontName=body, fontSize=9.5, leading=13, spaceAfter=5)
    h = {1: ParagraphStyle("h1", parent=base, fontName=bold, fontSize=18, leading=22, textColor=navy, spaceAfter=4),
         2: ParagraphStyle("h2", parent=base, fontName=bold, fontSize=13.5, leading=17, textColor=navy,
                           spaceBefore=10, spaceAfter=5),
         3: ParagraphStyle("h3", parent=base, fontName=bold, fontSize=11, leading=14, textColor=navy,
                           spaceBefore=7, spaceAfter=4)}
    sub = ParagraphStyle("sub", parent=base, fontName=ital, fontSize=10.5, leading=14, spaceAfter=10)
    quote = ParagraphStyle("quote", parent=base, fontSize=8.8, leading=12, leftIndent=12, borderColor=navy,
                           borderWidth=0, backColor=colors.HexColor("#EEF2F8"), borderPadding=5, spaceBefore=4,
                           spaceAfter=9)
    bullet = ParagraphStyle("bullet", parent=base, leftIndent=14, bulletIndent=4, spaceAfter=3)
    code = ParagraphStyle("code", fontName=mono, fontSize=6.3, leading=7.8, backColor=colors.HexColor("#F4F4F4"),
                          borderPadding=4, spaceBefore=4, spaceAfter=8)
    cover_t = ParagraphStyle("ct", parent=base, fontName=bold, fontSize=26, leading=32, alignment=TA_CENTER,
                             textColor=navy)
    cover_s = ParagraphStyle("cs", parent=base, fontName=ital, fontSize=13, leading=18, alignment=TA_CENTER)
    cover_m = ParagraphStyle("cm", parent=base, fontSize=11, leading=15, alignment=TA_CENTER)
    small = ParagraphStyle("small", parent=base, fontSize=8.5, leading=11.5)

    class Doc(BaseDocTemplate):
        def __init__(self, fn, **kw):
            super().__init__(fn, pagesize=A4, leftMargin=1.8 * cm, rightMargin=1.8 * cm, topMargin=1.8 * cm,
                             bottomMargin=1.8 * cm, title=TITLE, author="ULPF founding team",
                             subject="Incubation proposal, market research and business model", **kw)
            frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="f")
            self.addPageTemplates([PageTemplate("p", [frame], onPage=self._footer)])

        def _footer(self, canv, d):
            if d.page == 1:
                return
            canv.saveState()
            canv.setFont(body, 7.5)
            canv.setFillColor(colors.grey)
            canv.drawCentredString(A4[0] / 2, 1.0 * cm, f"ULPF incubation proposal · page {d.page}")
            canv.restoreState()

        def afterFlowable(self, f):
            lvl = getattr(f, "_toc_level", None)
            if lvl is None:
                return
            text, key = f._toc_text, f._toc_key
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(text, key, level=lvl, closed=lvl > 0)
            self.notify("TOCEntry", (lvl, text, self.page, key))

    def heading(text, style, lvl):
        p = Paragraph(markup(text), style)
        if lvl is not None:   # keys fixed at creation so multiBuild's passes agree
            p._toc_level, p._toc_text, p._toc_key = lvl, plain(text), f"h{len(toc_keys)}"
            toc_keys.append(p._toc_key)
        return p

    toc_keys: list[str] = []

    width = A4[0] - 3.6 * cm

    def table(b: Block):
        ncol = len(b.header)
        fs = 8.3 if ncol <= 3 else 7.4 if ncol <= 5 else 6.6
        cs = ParagraphStyle("cell", parent=base, fontSize=fs, leading=fs * 1.28, spaceAfter=0)
        chs = ParagraphStyle("cellh", parent=cs, fontName=bold)
        weights = []
        for c in range(ncol):
            lens = [len(plain(b.header[c]))] + [len(plain(r[c])) for r in b.rows]
            weights.append(min(max(max(lens), 6), 70) + 0.25 * sum(lens) / max(1, len(lens)))
        # never narrower than the column's longest word (no mid-word breaks)
        mins = [max(pdfmetrics.stringWidth(w, bold, fs) for x in [b.header[c]] + [r[c] for r in b.rows]
                    for w in (plain(x).split() or [""])) + 7 for c in range(ncol)]
        mins = [min(m, width * 0.3) for m in mins]
        widths = [width * w / sum(weights) for w in weights]
        for _ in range(ncol):
            short = [c for c in range(ncol) if widths[c] < mins[c]]
            if not short:
                break
            for c in short:
                widths[c] = mins[c]
            rest = [c for c in range(ncol) if c not in short]
            scale = (width - sum(widths[c] for c in short)) / max(1e-9, sum(widths[c] for c in rest))
            for c in rest:
                widths[c] *= scale
        data = [[Paragraph(markup(x), chs) for x in b.header]]
        data += [[Paragraph(markup(x), cs) for x in r] for r in b.rows]
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9AA8BC")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9E2F3")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F9FC")]),
        ]))
        return t

    story = [Spacer(1, 6 * cm), Paragraph(esc(TITLE, body), cover_t), Spacer(1, 0.8 * cm),
             Paragraph(esc(SUBTITLE, body), cover_s), Spacer(1, 1.2 * cm),
             Paragraph(esc("Prepared for: " + PREPARED_FOR, body), cover_m), Spacer(1, 0.3 * cm),
             Paragraph(esc(EDITION, body), cover_m), Spacer(1, 5 * cm),
             Paragraph(f"<b>Evidence policy.</b> {esc(EVIDENCE_NOTE, body)}", small), PageBreak()]
    toc = TableOfContents()
    toc.levelStyles = [ParagraphStyle("t0", parent=base, fontName=bold, fontSize=10.5, leading=15),
                       ParagraphStyle("t1", parent=base, fontSize=9, leading=12, leftIndent=14)]
    story += [Paragraph("Contents", h[1]), Spacer(1, 0.3 * cm), toc]

    for k, blocks in enumerate(parts):
        story.append(PageBreak())
        for b in blocks:
            if b.kind == "h":
                if b.level == 1:
                    story += [heading(PARTS[k], h[1], 0), Paragraph(markup(b.text), sub)]
                else:
                    story.append(heading(b.text, h[min(b.level, 3)], 1 if b.level == 2 else None))
            elif b.kind == "p":
                story.append(Paragraph(markup(b.text), base))
            elif b.kind == "quote":
                story.append(Paragraph(markup(b.text), quote))
            elif b.kind in ("ul", "ol"):
                for n, it in enumerate(b.items, start=1):
                    story.append(Paragraph(markup(it), bullet, bulletText="•" if b.kind == "ul" else f"{n}."))
            elif b.kind == "code":
                story.append(KeepTogether([XPreformatted(esc(b.text, mono), code)]))
            elif b.kind == "table":
                story += [table(b), Spacer(1, 0.3 * cm)]
            elif b.kind == "hr":
                story.append(Spacer(1, 0.2 * cm))
    Doc(path).multiBuild(story)


def _register_fonts(pdfmetrics, TTFont):
    """Arial (has ₹) + Consolas + Segoe UI Symbol (arrows, box drawing) on Windows; DejaVu elsewhere."""
    candidates = [
        ("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf", "C:/Windows/Fonts/ariali.ttf",
         "C:/Windows/Fonts/arialbi.ttf", "C:/Windows/Fonts/consola.ttf", "C:/Windows/Fonts/seguisym.ttf"),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
         "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf",
         "/usr/share/fonts/truetype/dejavu/DejaVuSans-BoldOblique.ttf",
         "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", None),
    ]
    for files in candidates:
        if all(f is None or os.path.exists(f) for f in files):
            names = ["Body", "Body-Bold", "Body-Italic", "Body-BoldItalic", "Mono", "Sym"]
            for n, f in zip(names, files):
                if f:
                    pdfmetrics.registerFont(TTFont(n, f))
            return tuple(n if f else None for n, f in zip(names, files))
    raise SystemExit("no Unicode TrueType font found (need Arial/Consolas on Windows or DejaVu on Linux)")


# ---------------------------------------------------------------- pitch deck
def build_deck(path: str) -> None:
    r = {(s["forward_share_pct"], s["siem_rate_usd_per_gb"], s["upstream_format"]): s for s in model.ROI_SCENARIOS}
    payg = model.ASSUME["sentinel_payg_usd_per_gb"]
    r10, r40 = r[(10.0, payg, "raw (format: raw)")], r[(40.6, payg, "raw (format: raw)")]
    ecs = r[(10.0, payg, "ECS JSON")]
    mk, pl = model.market(), model.plan()
    u = pl["unit"]
    cr = model.cr
    som_share = 100 * pl["Y3"]["arr_total"] / mk["sam_inr"]

    slides = [
        ("ULPF — keep every log, pay for the few that matter",
         "Title slide: product name, one-line promise, logo area, founders, incubator logos along the bottom.",
         ["Sovereign, self-learning log pipeline for Indian BFSI, MSSPs and defence",
          "Open core · runs fully offline · tamper-evident by design",
          "Software v9.0.0 · 159 automated tests passing"],
         "We built ULPF for organisations that must keep every log for 180 days, cannot send it abroad, and "
         "cannot afford to send all of it to a per-GB SIEM.",
         "python -m unittest discover -s tests → 159 tests OK"),
        ("The problem: a per-GB tax on compliance",
         "Three columns, one icon each: ₹ (cost), puzzle piece (parsers), shield (regulation).",
         [f"100 GB/day at Sentinel pay-as-you-go ≈ {cr(r10['siem_cost_before_inr'])} per year (${payg:.2f}/GB, ₹88/$)",
          "Every new device needs a hand-written parser (Grok, regex, decoders)",
          "CERT-In: 180-day log retention in India, 6-hour incident reporting · DPDP: up to ₹250 Cr penalty · "
          "BSA s.63: hash-value certificates for electronic evidence"],
         "Logs grow faster than budgets. The cheapest compliant answer today is to drop data, and that is the "
         "one thing regulators no longer allow.",
         "Microsoft Sentinel pricing (third-party reported rate); CERT-In Directions 28-Apr-2022; DPDP Rules 2025"),
        ("The solution: one pipeline in front of everything",
         "The architecture diagram from Part 1 §3.1, simplified to five boxes: inputs → journal → workers → "
         "buffers → outputs.",
         ["15 input types → SHA-256 journal (the lossless archive) → parse, normalise (100-field schema) and "
          "enrich → 12 output types",
          "Keep 100 % locally; forward only selected events, byte for byte (format: raw)",
          "No loss under failure: kill -9, sink outage and full-buffer tests pass"],
         "ULPF sits between devices and the SIEM. Everything is kept and sealed locally, and only what matters "
         "goes upstream.",
         "ulpf/runtime/*, tests/test_chaos.py"),
        ("What nobody else combines",
         "Four tiles, each showing a number.",
         ["Learns unknown formats: 7 of 7 learned, 100 % coverage, 11.7–28.5 ms each",
          "Tamper evidence: 6 of 6 manipulation types detected; Merkle inclusion proofs",
          "Verifiable air-gap: 0 external connections; unlisted sockets blocked in-process",
          "Format drift: 5 of 5 drift types, 0 false positives, 233 ms average detection"],
         "Pipelines like Cribl route data; SIEMs search it. Neither learns parsers offline while proving the "
         "evidence chain.",
         "benchmarks/results/integrity/integrity_suite_results.json (sections 14–17)"),
        ("Proof, measured on a 4-core laptop",
         "Table on the left, 'what we have not proven' box on the right.",
         ["26,952 events/s with 6 workers, 0 loss · 1-hour soak: 18,000,000 of 18,000,000 events",
          "Receipt → store commit p99: 536 ms at 2k/s, 919 ms at 10k/s",
          "Pipeline without the store: 70–77 MB host memory",
          "Not yet proven: Loghub-2k accuracy, head-to-head vs Vector/Logstash, server sizing"],
         "Every number here has a result file in the repo. Two things we do not claim: the old 8.x figure of "
         "154k EPS (our own archive marks it FAIL), and a small memory footprint once the embedded store holds "
         "millions of rows.",
         "runtime_tcp_20261022_024737.json, soak_20261023_012358.json, latency_footprint_20261023_023101.json"),
        ("ROI: a 100 GB/day fintech",
         "Waterfall chart: SIEM bill before → after → ULPF licence → net saving.",
         [f"Forward 10 % raw: net {cr(r10['net_saving_inr_per_year'])} per year "
          f"({r10['saving_per_license_rupee']}× the ₹3.6 L licence)",
          f"Forward 40.6 % raw (attack-heavy test corpus): {cr(r40['net_saving_inr_per_year'])} "
          f"({r40['saving_per_license_rupee']}×)",
          f"Honest caveat: forwarding 10 % as ECS JSON costs MORE ({cr(ecs['net_saving_inr_per_year'])}), because "
          "normalised JSON is 10.5× the raw line"],
         "The saving comes from sending fewer events at their raw size, so a pilot measures each customer's "
         "real forwarded share.",
         "incubation_pack/model.py; encoded_size_20261023_023215.json"),
        ("Market",
         "Concentric circles TAM / SAM / SOM with segment labels.",
         ["India cybersecurity: $6.56 B (2026) → $15.06 B (2031), 18.07 % CAGR; BFSI is the largest segment "
          "(Mordor Intelligence)",
          f"Bottom-up TAM {cr(mk['tam_inr'])}: 9,291 NBFCs, 1,457 UCBs, 231 CERT-In auditors as a channel, "
          "300 defence/PSU sites (assumption)",
          f"SAM {cr(mk['sam_inr'])} · Y3 plan {cr(pl['Y3']['arr_total'])} ARR = {som_share:.1f} % of SAM"],
         "We sized the market from entity counts we can name, not from a top-down percentage.",
         "RBI NBFC list (Dec 2024); RBI annual report FY25; PIB Jan 2026; Mordor Intelligence"),
        ("Competition",
         "2×2: x = per-GB vs flat pricing, y = cloud-only vs offline-capable. ULPF top-right.",
         ["Splunk, QRadar, Sentinel, Chronicle: detection depth and scale; priced per GB or by workload",
          "Elastic, Wazuh: free, but 16–64 GB per indexer node; Wazuh has the endpoint agent we lack",
          "Cribl, Vector: mature pipelines with faster per-core throughput; no learned parsers or evidence chain",
          "DNIF, Vehere (India): SIEM/SOAR and NDR; ULPF feeds them rather than replacing them"],
         "We complement SIEMs by sitting in front of them. Where we lose today: detection content (Sigma comes "
         "in Q1), certifications, and raw speed per core.",
         "Part 2 §2 (cited sources)"),
        ("Business model",
         "Four pricing cards plus a small Y1–Y3 table.",
         ["Community (free) · Pro ₹3.6 L per node per year · Sovereign ₹10–25 L per site per year · "
          "MSSP partners keep 30 %",
          f"ARR plan: Y1 {cr(pl['Y1']['arr_total'])} → Y2 {cr(pl['Y2']['arr_total'])} → "
          f"Y3 {cr(pl['Y3']['arr_total'])} (planning model)",
          f"LTV/CAC: Pro {u['ltv_cac_pro']}×, Sovereign {u['ltv_cac_sovereign']}×, MSSP {u['ltv_cac_mssp']}× "
          "(assumed churn and CAC)",
          f"Break-even in Y2 (net {cr(pl['Y2']['net'])}); Y1 net {cr(pl['Y1']['net'])}, covered by grants"],
         "MSSPs are 64 % of the Y3 plan. If the channel fails, Y3 ARR is about ₹3.2 Cr from direct sales, so the "
         "first two partners are our most important milestone.",
         "incubation_pack/model.py"),
        ("The ask",
         "Left: what we need. Right: Q1–Q4 milestones as a timeline.",
         ["Incubation: CISO mentors, CERT-In auditor and MSSP introductions, iDEX DISC guidance, a ≥16-core test bed",
          "Seed ₹40 L: test bed ₹6 L · pen test + ISO 27001 readiness ₹10 L · systems engineer ₹14 L · "
          "pilots ₹5 L · legal and licensing ₹5 L",
          "Q1: Sigma, ATT&CK IDs, Loghub-2k, competitive run, 3 pilots · Q2: Ed25519, store memory fix, pen test · "
          "Q3: columnar fast path, TPM keys · Q4: fleet console, ₹55 L ARR"],
         "Give us the introductions and the test bed, and in 12 months we will publish third-party-checkable "
         "accuracy and speed numbers and have paying customers.",
         "Part 1 §5"),
    ]
    lines = ["# ULPF — 10-Slide Pitch Deck (script and layout)", "",
             f"Generated by `incubation_pack/generate_proposal_docs.py` from `model.py`; figures match the proposal. "
             "Each slide lists its layout, on-screen bullets, about 30 seconds of speaker notes, and the evidence to "
             "have open if asked.", ""]
    for n, (title, layout, bullets, notes, evidence) in enumerate(slides, start=1):
        lines += ["---", "", f"## Slide {n}: {title}", "", f"**Layout:** {layout}", "", "**On screen:**", ""]
        lines += [f"- {b}" for b in bullets]
        lines += ["", f"**Speaker notes:** {notes}", "", f"**Evidence if asked:** {evidence}", ""]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ---------------------------------------------------------------- main
def main() -> int:
    parts = load_parts()
    build_deck(DECK_OUT)
    build_docx(parts, DOCX_OUT)
    build_pdf(parts, PDF_OUT)
    ok = True
    for p in [os.path.join(HERE, s) for s in SOURCES] + [DECK_OUT, DOCX_OUT, PDF_OUT]:
        size = os.path.getsize(p) if os.path.exists(p) else 0
        ok &= size > 0
        print(f"{'OK  ' if size else 'FAIL'} {size:>9,} B  {os.path.relpath(p, os.path.dirname(HERE))}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
