"""XML Parser — Generic XML event log parser."""
from __future__ import annotations
import re
from typing import Any, Optional
from xml.etree import ElementTree as ET
from ulpf.engine.normalizer import build_normalized_event
from ulpf.parsers.base import BaseParser


class XMLParser(BaseParser):
    parser_id = "xml"
    parser_name = "XML Parser"
    supported_formats = ["xml"]
    description = "Generic XML event log parser with recursive extraction"
    version = "1.1.0"

    _TS = {"timestamp", "time", "datetime", "date", "eventtime", "systemtime", "timecreated"}
    _SEV = {"severity", "level", "priority", "sev"}
    _MSG = {"message", "msg", "description", "data", "eventdata"}
    _DOMAIN = {"domain", "query", "qname", "queryname"}

    def can_parse(self, raw_line: str) -> bool:
        s = raw_line.strip()
        if s.startswith("<?xml"):
            return True
        if s.startswith("<") and not s.startswith("<!"):
            return "</" in s or (s.endswith(">") and re.search(r"<\w+[\s>]", s) is not None)
        return False

    def parse(self, raw_line: str, **kwargs) -> Optional[dict]:
        s = raw_line.strip()
        # Untrusted network input: never expand DTDs or entities (XXE / billion laughs)
        if "<!DOCTYPE" in s or "<!ENTITY" in s:
            return None
        xml_str = s
        extra_str = ""

        # Extract root XML if trailing metadata exists (e.g. bench_id=...)
        if s.startswith("<") and not s.startswith("<?xml"):
            m = re.match(r"^<([A-Za-z0-9_:]+)(?:[\s>].*)", s)
            if m:
                tag = m.group(1)
                closing = f"</{tag}>"
                pos = s.rfind(closing)
                if pos != -1:
                    xml_str = s[:pos + len(closing)]
                    extra_str = s[pos + len(closing):].strip()

        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return None

        flat = _extract(root)
        if extra_str:
            for kv_m in re.finditer(r'(\w+)=(\S+)', extra_str):
                flat[kv_m.group(1)] = kv_m.group(2)

        ts = _find_tag(flat, self._TS)
        sev = _find_tag(flat, self._SEV)
        msg = _find_tag(flat, self._MSG)
        vendor = _find_tag(flat, {"vendor", "provider"}) or "Unknown"
        product = _find_tag(flat, {"product", "channel"}) or root_tag(flat) or "XML Source"
        category = _cat(flat)
        domain = _find_tag(flat, self._DOMAIN)
        if msg is None and domain:
            qtype = _find_tag(flat, {"querytype", "qtype"}) or ""
            rcode = _find_tag(flat, {"responsecode", "rcode"}) or ""
            msg = f"DNS {qtype} query {domain} {rcode}".replace("  ", " ").strip()

        event = build_normalized_event(**kwargs,
            raw_line=raw_line, raw_format="xml", parsed_fields=flat,
            parser_id=self.parser_id, parser_name=self.parser_name, parser_version=self.version,
            timestamp_str=str(ts) if ts else None, severity_raw=sev,
            severity_source="generic", category=category,
            event_type=_find_tag(flat, {"event_type", "eventid"}) or root_tag(flat) or "xml_event",
            device_vendor=str(vendor), device_product=str(product),
            message=str(msg) if msg else None)
        threat_cat = _find_tag(flat, {"threatcategory", "threat"})
        if threat_cat:
            event["threat"]["category"] = str(threat_cat)
        if domain and not event["destination"]["hostname"] and category != "dns":
            event["destination"]["hostname"] = str(domain)
        return event


def _local(name: str) -> str:
    """Strip an ElementTree '{namespace}' prefix and lowercase."""
    if name[0] == "{":
        name = name[name.find("}") + 1:]
    return name.lower()


def _extract(el: ET.Element, prefix: str = "", result: dict[str, Any] | None = None) -> dict[str, Any]:
    if result is None:
        result = {}
    tag = _local(el.tag)
    key = f"{prefix}.{tag}" if prefix else tag
    if tag == "data" and "Name" in el.attrib:
        # Windows Event Log <Data Name="TargetUserName">value</Data>
        value = (el.text or "").strip()
        if value:
            result[f"{prefix}.{el.attrib['Name'].lower()}"] = value
        return result
    text = el.text
    if text:
        text = text.strip()
        if text:
            if key in result:
                # Repeated sibling elements: keep every value
                prev = result[key]
                result[key] = prev + [text] if isinstance(prev, list) else [prev, text]
            else:
                result[key] = text
    for an, av in el.attrib.items():
        result[f"{key}.{_local(an)}"] = av
    for child in el:
        _extract(child, key, result)
    return result


def _find_tag(flat: dict, candidates: set[str]) -> Any:
    for k, v in flat.items():
        if k.split(".")[-1].lower() in candidates:
            return v
    return None


def root_tag(flat: dict) -> str | None:
    """Return the root element name (first key segment) of a flattened document."""
    for k in flat:
        return k.split(".", 1)[0]
    return None


def _cat(flat: dict) -> str:
    keys = " ".join(flat).lower()
    txt = " ".join(str(v) for v in flat.values()).lower()
    if "dns" in keys or any(k.endswith(("querytype", "qname", "responsecode")) for k in flat):
        return "dns"
    if any(w in txt for w in ("firewall", "fw")): return "firewall"
    if any(w in txt for w in ("ids", "intrusion")): return "ids_ips"
    if any(w in txt for w in ("auth", "login", "logon")): return "authentication"
    if "audit" in txt or "audit" in keys: return "audit"
    return "system"
