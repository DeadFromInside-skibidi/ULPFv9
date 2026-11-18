"""CSV Parser — CSV/TSV log parser with header detection."""
from __future__ import annotations
import csv
import io
import re
from typing import Optional
from ulpf.engine.normalizer import build_normalized_event
from ulpf.parsers.base import HEADER_LINE, BaseParser

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_ .\-()]*$")
_HEADER_HINTS = frozenset(("time", "timestamp", "date", "src", "dst", "source", "destination",
                           "ip", "port", "action", "severity", "user", "host", "protocol", "proto",
                           "event", "message", "msg", "level", "status"))


def _split(line: str) -> tuple[list[str], str]:
    delim = "\t" if "\t" in line and line.count("\t") > line.count(",") else ","
    try:
        return next(csv.reader(io.StringIO(line), delimiter=delim)), delim
    except (csv.Error, StopIteration):
        return [], delim


def _looks_like_header(values: list[str]) -> bool:
    """A header row: every cell is an identifier and at least one is a known column name."""
    cells = [v.strip() for v in values if v.strip()]
    if len(cells) < 3 or not all(_IDENT.match(c) for c in cells):
        return False
    words = {w for c in cells for w in re.split(r"[_ .\-()]+", c.lower()) if w}
    return bool(words & _HEADER_HINTS)


class CSVParser(BaseParser):
    parser_id = "csv"
    parser_name = "CSV Parser"
    supported_formats = ["csv"]
    description = "CSV/TSV log parser with header auto-detection"
    version = "1.1.0"
    _TS = ("timestamp", "time", "datetime", "date", "event_time", "log_time")
    _SEV = ("severity", "level", "priority", "sev", "risk")

    def __init__(self):
        self._headers: list[str] = []

    def reset_state(self) -> None:
        self._headers = []

    def consume_header(self, raw_line: str) -> bool:
        values, _ = _split(raw_line.strip())
        if values and _looks_like_header(values):
            self._headers = [v.strip().lower() for v in values]
            return True
        return False

    def can_parse(self, raw_line: str) -> bool:
        s = raw_line.strip()
        return bool(s and not s.startswith("#") and len(s.split(",")) >= 3)

    def parse(self, raw_line: str, **kwargs) -> Optional[dict]:
        s = raw_line.strip()
        if not s:
            return None
        values, _ = _split(s)
        if len(values) < 3:
            return None
        if _looks_like_header(values):
            self._headers = [v.strip().lower() for v in values]
            return HEADER_LINE

        headers = self._headers
        parsed = {headers[i] if i < len(headers) else f"field_{i}": v.strip() for i, v in enumerate(values)}

        ts = next((parsed[h] for h in self._TS if h in parsed), None)
        if ts and "date" in parsed and "time" in parsed:
            ts = f"{parsed['date']} {parsed['time']}"
        sev = next((parsed[h] for h in self._SEV if h in parsed), None)
        msg = parsed.get("message") or parsed.get("msg") or s[:200]

        return build_normalized_event(**kwargs,
            raw_line=raw_line, raw_format="csv", parsed_fields=parsed,
            parser_id=self.parser_id, parser_name=self.parser_name, parser_version=self.version,
            timestamp_str=ts, severity_raw=sev, severity_source="generic",
            category=parsed.get("category") or "network", event_type=parsed.get("type") or "csv_event",
            device_vendor="Generic", device_product="CSV Source",
            message=msg)
