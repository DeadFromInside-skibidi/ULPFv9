"""W3C Extended Log Format / Common Log Format Parser — proxy & web server logs."""
from __future__ import annotations
import re
from typing import Optional
from ulpf.engine.normalizer import build_normalized_event
from ulpf.parsers.base import HEADER_LINE, BaseParser

_HTTP_METHODS = frozenset(("GET", "POST", "CONNECT", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE"))
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_W3C_LEAD = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)")
_TRAILING_KV = re.compile(r"(\w+)=(\S+)")


def _status_outcome(status: str | None) -> tuple[str | None, int | None]:
    """Map an HTTP status code to (action, severity)."""
    if not status or not status[:3].isdigit():
        return None, None
    code = int(status[:3])
    if code < 400:
        return "allowed", 1
    if code in (401, 403, 407):
        return "denied", 3
    if code < 500:
        return "failed", 2
    return "failed", 5


class W3CParser(BaseParser):
    parser_id = "w3c"
    parser_name = "W3C Parser"
    supported_formats = ["w3c", "iis"]
    description = "W3C Extended Log Format and Apache/Nginx Common/Combined Log Format"
    version = "1.1.0"

    DEFAULT_FIELDS = [
        "date", "time", "c-ip", "cs-method", "cs-uri-stem",
        "sc-status", "sc-bytes", "cs(User-Agent)", "cs(Referer)",
        "s-ip", "s-port", "time-taken"
    ]

    _FIELD_MAP = {
        "date": "date", "time": "time",
        "c-ip": "src_ip", "cs-ip": "src_ip", "c-port": "src_port",
        "s-ip": "dst_ip", "s-port": "dst_port",
        "cs-method": "method", "cs-uri-stem": "url", "cs-uri-query": "query",
        "sc-status": "status_code", "sc-bytes": "bytes_out", "cs-bytes": "bytes_in",
        "cs(User-Agent)": "user_agent", "cs(Referer)": "referer",
        "cs-username": "user",
        "time-taken": "duration",
        "s-computername": "devname",
        "s-sitename": "site",
        "sc-substatus": "sub_status",
        "x-action": "action",
    }

    CLF_REGEX = re.compile(
        r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)(?:\s+([^"]+))?"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)")?(?:\s+"([^"]*)")?'
    )

    def __init__(self):
        # Per-stream state: the most recent #Fields directive
        self._fields: list[str] = []

    def reset_state(self) -> None:
        self._fields = []

    def consume_header(self, raw_line: str) -> bool:
        s = raw_line.strip()
        if s.startswith("#Fields:"):
            self._fields = s[len("#Fields:"):].split()
            return True
        return s.startswith("#")

    def can_parse(self, raw_line: str) -> bool:
        s = raw_line.strip()
        if s.startswith("#Fields:") or s.startswith("#Software:"):
            return True
        if self.CLF_REGEX.match(s):
            return True
        m = _W3C_LEAD.match(s)
        if not m:
            return False
        tok1, tok2 = m.group(2), m.group(3)
        # Avoid hijacking generic logs like 2026-09-30 12:45:10 [TAG]
        if tok1.startswith("[") or tok2.startswith("[") or tok1.startswith("<"):
            return False
        is_ip = bool(_IPV4.match(tok1))
        is_method = tok1.upper() in _HTTP_METHODS or tok2.upper() in _HTTP_METHODS
        return (is_ip or is_method) and len(s.split()) >= 6

    def parse(self, raw_line: str, **kwargs) -> Optional[dict]:
        s = raw_line.strip()
        if s.startswith("#"):
            self.consume_header(s)
            return HEADER_LINE

        clf_match = self.CLF_REGEX.match(s)
        if clf_match:
            ip, _ident, user, ts_raw, method, path, _proto, status, bytes_out, referer, ua = clf_match.groups()
            parsed_clf: dict = {"src_ip": ip, "method": method, "url": path, "status_code": status}
            if user and user != "-":
                parsed_clf["user"] = user
            if bytes_out and bytes_out != "-":
                parsed_clf["bytes_out"] = bytes_out
            if referer and referer != "-":
                parsed_clf["referer"] = referer
            if ua and ua != "-":
                parsed_clf["user_agent"] = ua
            trailing = s[clf_match.end():].strip()
            if trailing:
                for kv_m in _TRAILING_KV.finditer(trailing):
                    parsed_clf[kv_m.group(1)] = kv_m.group(2)
            return self._build(raw_line, parsed_clf, ts_raw, "web", "http_access", "Web Server",
                               f"{method} {path} {status}", kwargs)

        values = s.split()
        fields = self._fields or self.DEFAULT_FIELDS
        parsed: dict = {}
        for i, val in enumerate(values):
            if val == "-":
                continue
            fname = fields[i] if i < len(fields) else f"field_{i}"
            parsed[self._FIELD_MAP.get(fname, fname)] = val

        ts = None
        if "date" in parsed and "time" in parsed:
            ts = f"{parsed['date']} {parsed['time']}"
        elif "date" in parsed:
            ts = parsed["date"]
        message = f"{parsed.get('method', '')} {parsed.get('url', '')} {parsed.get('status_code', '')}".strip()
        return self._build(raw_line, parsed, ts, "proxy", "w3c_access", "Web Proxy", message, kwargs)

    def _build(self, raw_line: str, parsed: dict, ts: str | None, category: str,
               event_type: str, product: str, message: str, kwargs: dict) -> dict:
        action, sev = _status_outcome(parsed.get("status_code"))
        event = build_normalized_event(**kwargs,
            raw_line=raw_line, raw_format="w3c", parsed_fields=parsed,
            parser_id=self.parser_id, parser_name=self.parser_name, parser_version=self.version,
            timestamp_str=ts, severity_raw=sev, severity_source="generic",
            category=category, event_type=event_type,
            device_vendor="Generic", device_product=product, message=message)
        if action and event["action"] == "other":
            event["action"] = action
        return event
