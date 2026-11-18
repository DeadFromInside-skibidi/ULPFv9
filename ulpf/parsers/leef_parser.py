"""LEEF Parser — IBM QRadar Log Event Extended Format (1.0 / 2.0)."""
from __future__ import annotations
import re
from typing import Optional
from ulpf.engine.normalizer import build_normalized_event
from ulpf.parsers.base import BaseParser
from ulpf.parsers.cef_parser import parse_cef_extension

_FMAP = {
    "src": "src_ip", "dst": "dst_ip", "srcPort": "src_port", "dstPort": "dst_port",
    "srcMAC": "src_mac", "dstMAC": "dst_mac", "proto": "protocol",
    "srcBytes": "bytes_out", "dstBytes": "bytes_in", "action": "action",
    "usrName": "user", "identSrc": "user", "devTime": "timestamp",
    "sev": "severity", "policy": "rule_name", "url": "url",
    "msg": "message", "message": "message",
    "srcPackets": "sentpkt", "dstPackets": "rcvdpkt",
}

_PREFIX_ISO = re.compile(r"\b(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b")
_PREFIX_SYSLOG_TS = re.compile(r"\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b")


def _decode_delimiter(field: str) -> str | None:
    """Decode a LEEF 2.0 delimiter field: '^', 'x5E', '0x09', '\\t' or empty (tab)."""
    f = field.strip()
    if f == "":
        return "\t"
    if len(f) == 1:
        return f
    low = f.lower()
    if low in ("\\t", "tab"):
        return "\t"
    if low.startswith("0x"):
        low = low[2:]
    elif low.startswith("x"):
        low = low[1:]
    try:
        return chr(int(low, 16)) if 1 <= len(low) <= 4 else None
    except ValueError:
        return None


class LEEFParser(BaseParser):
    parser_id = "leef"
    parser_name = "LEEF Parser"
    supported_formats = ["leef"]
    description = "IBM QRadar Log Event Extended Format (LEEF 1.0/2.0)"
    version = "1.1.0"

    def can_parse(self, raw_line: str) -> bool:
        return "LEEF:" in raw_line.upper()

    def parse(self, raw_line: str, **kwargs) -> Optional[dict]:
        s = raw_line.strip()
        idx = s.find("LEEF:")
        if idx < 0:
            return None
        prefix = s[:idx]
        parts = s[idx + 5:].split("|", 5)
        if len(parts) < 5:
            return None
        if len(parts) == 5:
            parts.append("")
        version, vendor, product, dev_ver, event_id, kv_str = parts
        if not re.match(r"^\d+(\.\d+)?$", version.strip()):
            return None

        delim = "\t"
        if version.startswith("2"):
            head, sep, tail = kv_str.partition("|")
            if sep and "=" not in head:
                decoded = _decode_delimiter(head)
                if decoded:
                    delim, kv_str = decoded, tail

        raw_pairs: dict[str, str] = {}
        if delim in kv_str:
            for pair in kv_str.split(delim):
                k, eq, v = pair.partition("=")
                if eq and k.strip():
                    raw_pairs[k.strip()] = v.strip()
        elif "=" in kv_str:
            # Non-compliant producers often separate pairs with spaces
            raw_pairs = parse_cef_extension(kv_str)

        parsed: dict = {_FMAP.get(k, k): v for k, v in raw_pairs.items()}
        parsed["leef_version"] = version
        parsed["event_id"] = event_id

        ts = parsed.get("timestamp")
        if not ts and prefix.strip():
            m_ts = _PREFIX_ISO.search(prefix) or _PREFIX_SYSLOG_TS.search(prefix)
            if m_ts:
                ts = m_ts.group(1)

        msg_text = parsed.get("message") or f"{product}: {event_id}"
        event = build_normalized_event(
            **kwargs,
            raw_line=raw_line, raw_format="leef", parsed_fields=parsed,
            parser_id=self.parser_id, parser_name=self.parser_name, parser_version=self.version,
            timestamp_str=ts, severity_raw=parsed.get("severity"), severity_source="generic",
            category=_categorize(product, event_id, raw_pairs.get("cat", "")),
            event_type=f"leef_{event_id}",
            device_vendor=vendor, device_product=product,
            device_version=dev_ver, message=msg_text,
        )
        event["rule"]["id"] = event_id
        if raw_pairs.get("cat"):
            event["rule"]["category"] = raw_pairs["cat"]
        if event["category"] == "ids_ips":
            event["threat"]["signature"] = msg_text
            event["threat"]["signature_id"] = event_id
        return event


def _categorize(product: str, eid: str, cat: str) -> str:
    c = f"{product} {eid} {cat}".lower()
    if any(w in c for w in ("ids", "ips", "intrusion", "snort", "suricata", "attack", "trojan", "recon")):
        return "ids_ips"
    if any(w in c for w in ("firewall", "fw")):
        return "firewall"
    if "dns" in c:
        return "dns"
    if any(w in c for w in ("auth", "login", "logon")):
        return "authentication"
    return "network"
