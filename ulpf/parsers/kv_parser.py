"""Key-Value Parser — For FortiGate, Palo Alto, and similar logs."""
from __future__ import annotations
import re
from typing import Optional
from ulpf.engine.normalizer import build_normalized_event
from ulpf.parsers.base import BaseParser

# Matches key=value and key="quoted value", preserving colons in timestamps while supporting colon/comma/semicolon delimited streams
_KV = re.compile(r'([\w.]+)=(?:"([^"]*)"|((?:(?![\s,;]+|:(?=[a-zA-Z_][\w.-]*=))\S)+))')
_LEAD_ISO = re.compile(r"\b(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b")
_LEAD_SYSLOG = re.compile(r"\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b")


class KVParser(BaseParser):
    parser_id = "kv"
    parser_name = "Key-Value Parser"
    supported_formats = ["kv"]
    description = "Key=Value pair parser (FortiGate, Palo Alto, etc.)"
    version = "1.0.0"

    def can_parse(self, raw_line: str) -> bool:
        return len(_KV.findall(raw_line)) >= 3

    def parse(self, raw_line: str, **kwargs) -> Optional[dict]:
        matches = _KV.findall(raw_line.strip())
        if len(matches) < 3:
            return None

        parsed: dict = {}
        for key, quoted, unquoted in matches:
            parsed[key.lower()] = quoted if quoted else unquoted

        # Identify timestamp
        ts = None
        for k in ("date", "time", "eventtime", "timestamp", "start"):
            if k in parsed:
                ts = parsed[k]
                break
        # FortiGate combines date + time
        if "date" in parsed and "time" in parsed:
            ts = f"{parsed['date']} {parsed['time']}"

        # If not in KV pairs, check if raw line has timestamp in leading section
        if not ts:
            head = raw_line[:60]
            m_ts = _LEAD_ISO.search(head) or _LEAD_SYSLOG.search(head)
            if m_ts:
                ts = m_ts.group(1)

        sev = parsed.get("level") or parsed.get("severity") or parsed.get("pri")
        msg = parsed.get("msg") or parsed.get("message") or parsed.get("logdesc")
        if not msg:
            if parsed.get("virus"):
                msg = f"Infection detected: {parsed.get('virus')}"
            elif parsed.get("attack"):
                msg = f"Attack blocked: {parsed.get('attack')}"
            elif parsed.get("action"):
                msg = f"{parsed.get('type', 'traffic').capitalize()} session {parsed.get('action')}"
            else:
                msg = f"{parsed.get('type', 'system').capitalize()} log event"

        # Detect vendor from known keys
        vendor = "Unknown"
        product = "KV Source"
        if "devname" in parsed or "devid" in parsed:
            vendor = "Fortinet"
            product = "FortiGate"
        elif "serial" in parsed and "type" in parsed:
            vendor = parsed.get("vendor", "Unknown")
            product = parsed.get("type", "KV Source")

        cat = _cat(parsed)

        event = build_normalized_event(
            **kwargs,
            raw_line=raw_line, raw_format="kv", parsed_fields=parsed,
            parser_id=self.parser_id, parser_name=self.parser_name, parser_version=self.version,
            timestamp_str=ts, severity_raw=sev, severity_source="generic",
            category=cat, event_type=parsed.get("type") or parsed.get("subtype") or "kv_event",
            device_vendor=vendor, device_product=product,
            message=msg)

        return event


def _cat(p: dict) -> str:
    t = p.get("type", "").lower()
    st = p.get("subtype", "").lower()
    c = f"{t} {st}"
    if "traffic" in c or "forward" in c: return "firewall"
    if "utm" in c or "ips" in c or "virus" in c or "attack" in c: return "ids_ips"
    if "event" in c and "vpn" in c: return "vpn"
    if "dns" in c: return "dns"
    if "auth" in c or "login" in c: return "authentication"
    if "web" in c or "waf" in c: return "web"
    return "network"
