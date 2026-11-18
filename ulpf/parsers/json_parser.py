"""JSON Parser — Generic JSON logs with nested flattening."""
from __future__ import annotations
import json
from typing import Any, Optional

import orjson

from ulpf.engine.normalizer import build_normalized_event
from ulpf.parsers.base import BaseParser


class JSONParser(BaseParser):
    parser_id = "json"
    parser_name = "JSON Parser"
    supported_formats = ["json"]
    description = "Generic JSON log parser with nested field flattening"
    version = "1.1.0"

    _TS = ("timestamp", "@timestamp", "time", "datetime", "date", "event_time", "eventtime",
           "created", "ts")
    _SEV = ("severity", "level", "priority", "sev", "risk", "threat_level", "log.level")
    _MSG = ("message", "msg", "description", "summary", "event_message", "detail")

    def can_parse(self, raw_line: str) -> bool:
        s = raw_line.strip()
        return s.startswith("{") and s.endswith("}")

    def parse(self, raw_line: str, **kwargs) -> Optional[dict]:
        try:
            data = orjson.loads(raw_line.strip())
        except orjson.JSONDecodeError:
            # orjson rejects integers wider than 64 bits; stdlib json does not
            try:
                data = json.loads(raw_line.strip())
            except ValueError:
                return None
        if not isinstance(data, dict):
            return None

        flat = _flatten(data)
        lower = {k.lower(): k for k in flat}
        ts = _find(flat, lower, self._TS)
        sev = _find(flat, lower, self._SEV)
        msg = _find(flat, lower, self._MSG)
        vendor = flat.get("vendor") or flat.get("device_vendor") or flat.get("observer.vendor")
        if vendor is None and isinstance(data.get("source"), str):
            vendor = data["source"]
        product = flat.get("product") or flat.get("device_product") or flat.get("observer.product") \
            or flat.get("service") or "JSON Source"

        return build_normalized_event(**kwargs,
            raw_line=raw_line, raw_format="json", parsed_fields=flat,
            parser_id=self.parser_id, parser_name=self.parser_name, parser_version=self.version,
            timestamp_str=str(ts) if ts is not None else None, severity_raw=sev,
            severity_source="generic", category=_cat(flat),
            event_type=str(flat.get("event_type") or flat.get("type") or flat.get("event.action") or "json_event"),
            device_vendor=str(vendor or "Unknown"), device_product=str(product),
            message=str(msg) if msg is not None else None)


def _flatten(obj: dict, prefix: str = "") -> dict[str, Any]:
    items: dict[str, Any] = {}
    for k, v in obj.items():
        nk = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            items.update(_flatten(v, nk))
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    items.update(_flatten(item, f"{nk}[{i}]"))
        else:
            items[nk] = v
    return items


def _find(flat: dict, lower: dict[str, str], candidates: tuple[str, ...]) -> Any:
    """Exact (case-insensitive) key match first, then dotted-suffix match."""
    for c in candidates:
        key = lower.get(c)
        if key is not None and flat[key] not in (None, ""):
            return flat[key]
    for c in candidates:
        suffix = "." + c
        for lk, key in lower.items():
            if lk.endswith(suffix) and flat[key] not in (None, ""):
                return flat[key]
    return None


def _cat(flat: dict) -> str:
    txt = " ".join(str(v) for v in flat.values() if isinstance(v, str)).lower()
    keys = " ".join(flat).lower()
    if any(w in txt for w in ("waf", "xss", "sqli", "sql injection", "injection", "modsecurity")):
        return "web"
    if any(w in txt for w in ("firewall", "fw_rule")):
        return "firewall"
    if any(w in txt for w in ("intrusion", "ids_alert", "suricata", "snort")):
        return "ids_ips"
    if any(w in txt for w in ("login", "logon", "authentication")) or "auth" in keys:
        return "authentication"
    if "dns" in txt or "query" in keys or "qname" in keys:
        return "dns"
    if "http" in keys or "url" in keys or "uri" in keys:
        return "web"
    return "network"
