"""
Build the field catalogues ULPF's UDM and ASIM views are checked against, from
the vendors' reference pages saved as HTML in a directory:

    udm-field-list.html   https://cloud.google.com/chronicle/docs/reference/udm-field-list
    asim-<page>.html      https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-<schema>
                          (pages and schemas in ASIM_PAGES) and
    asim-common.html      .../normalization-common-fields

    python scripts/build_standards_catalog.py <download dir>

Writes ``ulpf/engine/standards/udm_catalog.json`` (message -> field -> [type, label];
enum -> values) and ``asim_catalog.json`` (schema -> field -> class). Only field
names, types and enumerations are kept (facts of the published schemas).
"""
from __future__ import annotations

import json
import os
import sys
from html.parser import HTMLParser


class Tables(HTMLParser):
    """Tables with the text of the nearest preceding h2/h3 heading."""

    def __init__(self):
        super().__init__()
        self.tables: list[tuple[str, list[list[str]]]] = []
        self.heading = ""
        self._h: list[str] | None = None
        self.rows: list[list[str]] | None = None
        self.row: list[str] | None = None
        self.cell: list[str] | None = None
        self.mangled: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in ("h2", "h3", "h4"):
            self._h = []
        elif tag == "table":
            self.rows = []
        elif tag == "tr" and self.rows is not None:
            self.row = []
        elif tag in ("td", "th") and self.row is not None:
            self.cell = []
        elif tag in ("br", "li") and self.cell is not None:
            self.cell.append(" ")
        elif tag == "em" and self.cell is not None and self.row == []:
            # the UDM page renders "registry_key" from Markdown as "registry<em>key": in a
            # field-name cell, emphasis stands for the underscore it swallowed
            self.cell.append("_")
            self.mangled.append(self.heading)

    def handle_endtag(self, tag):
        if tag in ("h2", "h3", "h4") and self._h is not None:
            self.heading = " ".join("".join(self._h).split())
            self._h = None
        elif tag in ("td", "th") and self.cell is not None and self.row is not None:
            self.row.append(" ".join("".join(self.cell).split()))
            self.cell = None
        elif tag == "tr" and self.row is not None and self.rows is not None:
            self.rows.append(self.row)
            self.row = None
        elif tag == "table" and self.rows is not None:
            self.tables.append((self.heading, self.rows))
            self.rows = None

    def handle_data(self, data):
        if self._h is not None:
            self._h.append(data)
        if self.cell is not None:
            self.cell.append(data)


def parse(path: str) -> list[tuple[str, list[list[str]]]]:
    p = Tables()
    p.feed(open(path, encoding="utf-8", errors="replace").read())
    return p.tables


def udm(path: str) -> dict:
    messages: dict = {}
    enums: dict = {}
    for heading, rows in parse(path):
        if not rows:
            continue
        head = [c.lower() for c in rows[0]]
        if head[:2] == ["field name", "type"]:
            messages[heading] = {r[0]: [r[1], r[2] if len(r) > 2 else ""] for r in rows[1:] if r and r[0]}
        elif head and head[0] in ("enum value", "enum name", "value"):
            enums[heading] = [r[0] for r in rows[1:] if r and r[0]]
        elif len(rows[0]) >= 2 and rows[0][1].isdigit():   # enum tables without a header row
            enums[heading] = [r[0] for r in rows if r and r[0]]
    return {"messages": messages, "enums": enums}


ASIM_PAGES = {   # schema name -> saved page (asim-<page>.html)
    "Common": "common", "Authentication": "auth", "NetworkSession": "net", "Dns": "dns", "WebSession": "web",
    "ProcessEvent": "process", "FileEvent": "file", "RegistryEvent": "registry", "UserManagement": "usermgmt",
    "AuditEvent": "audit", "Alert": "alert",
}


def asim(d: str) -> dict:
    import re
    out = {}
    for schema, page in ASIM_PAGES.items():
        fields, version = {}, None
        for _heading, rows in parse(os.path.join(d, f"asim-{page}.html")):
            if not rows or [c.lower() for c in rows[0][:2]] != ["field", "class"]:
                continue
            for r in rows[1:]:
                if len(r) >= 2 and r[0] and " " not in r[0]:
                    fields[r[0]] = r[1]
                if r and r[0] == "EventSchemaVersion" and len(r) > 3:
                    m = re.search(r"documented here is (\d+\.\d+\.\d+)", r[3])
                    version = m.group(1) if m else version
        out[schema] = {"version": version, "fields": fields}
    return out


def main(d: str) -> int:
    dest = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ulpf", "engine", "standards")
    u = udm(os.path.join(d, "udm-field-list.html"))
    a = asim(d)
    for fn, data in (("udm_catalog.json", u), ("asim_catalog.json", a)):
        with open(os.path.join(dest, fn), "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, separators=(",", ":"), sort_keys=True)
    print(f"udm: {len(u['messages'])} messages, {len(u['enums'])} enums; "
          f"asim: " + ", ".join(f"{k} {v['version']} ({len(v['fields'])})" for k, v in a.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
