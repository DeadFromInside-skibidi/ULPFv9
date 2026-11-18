"""CEF Parser — ArcSight Common Event Format (spec-compliant escaping)."""
from __future__ import annotations
import re
from typing import Optional
from ulpf.engine.normalizer import build_normalized_event
from ulpf.parsers.base import BaseParser

# Header fields are separated by unescaped pipes
_PIPE_SPLIT = re.compile(r"(?<!\\)\|")
# Extension keys start at line start or after whitespace; '=' inside values must be escaped
_EXT_SPLIT = re.compile(r"(?:^|\s+)([A-Za-z0-9_.\[\]-]+)=")
_ESCAPES = {"\\=": "=", "\\\\": "\\", "\\n": "\n", "\\r": "\r", "\\|": "|"}
_ESC_RE = re.compile(r"\\[=\\nr|]")

# Mapping from raw CEF extension keys to normalizer-compatible field names.
# Used ONLY for schema alignment; parsed_fields keeps the original keys.
_FMAP = {
    "src": "src_ip", "dst": "dst_ip", "spt": "src_port", "dpt": "dst_port",
    "smac": "src_mac", "dmac": "dst_mac", "shost": "src_host", "dhost": "dst_host",
    "proto": "protocol", "in": "bytes_in", "out": "bytes_out",
    "act": "action", "suser": "suser", "duser": "duser",
    "rt": "timestamp", "end": "end_time", "start": "start_time",
    "msg": "message", "reason": "reason", "app": "application",
    "requestUrl": "url", "request": "url", "fname": "filename",
    "deviceExternalId": "devid", "deviceDirection": "direction",
    "sourceTranslatedAddress": "src_nat_ip", "destinationTranslatedAddress": "dst_nat_ip",
}

_PREFIX_HOSTNAME = re.compile(
    r"(?:^<\d{1,3}>)?(?:\d\s+)?"
    r"(?:(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}T\S+)"
    r"\s+([\w.\-]+)\s"
)
_PREFIX_ISO = re.compile(r"\b(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b")
_PREFIX_SYSLOG_TS = re.compile(r"\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b")

_ENFORCEMENT_VERBS = frozenset(("drop", "allow", "block", "deny", "accept", "pass"))
_ACTION_DENIED = re.compile(r"failed logon|logon failed|failure|fail|bad password|4625")
_ACTION_ALLOWED = re.compile(r"allow|accept|pass|permit|success")
_ACTION_BLOCKED = re.compile(r"block|drop|deny|denied|reject|prevented")


def _kw(*words: str) -> re.Pattern:
    return re.compile("|".join(re.escape(w) for w in words))


_CATEGORY_RULES: list[tuple[str, re.Pattern]] = [
    ("authentication", _kw("active directory", "logon", "login", "auth", "kerberos", "ldap", "radius",
                           "saml", "sso", "password", "credential", "4624", "4625")),
    ("endpoint", _kw("crowdstrike", "falcon", "endpoint", "process", "sensor", "edr", "antivirus", "filepath")),
    ("web", _kw("waf", "web", "asm", "sql injection", "xss", "cross-site", "http", "uri", "url", "injection")),
    ("dns", _kw("dns", "bind", "named")),
    ("firewall", _kw("firewall", "fw", "iptables", "palo alto", "pa-", "fortigate", "fgt", "asa",
                     "checkpoint", "check point", "threat alert")),
    ("ids_ips", _kw("ids", "ips", "intrusion", "snort", "suricata", "threat")),
    ("vpn", _kw("vpn", "tunnel")),
    ("proxy", _kw("proxy", "squid")),
]


def _unescape(value: str) -> str:
    if "\\" not in value:
        return value
    return _ESC_RE.sub(lambda m: _ESCAPES[m.group(0)], value)


def parse_cef_extension(ext: str) -> dict[str, str]:
    """Split a CEF extension string into key/value pairs (values may contain spaces)."""
    # split() yields [prefix, key1, value1, key2, value2, ...] in one C call
    it = iter(_EXT_SPLIT.split(ext)[1:])
    if "\\" in ext:
        return {k: _unescape(v.strip()) for k, v in zip(it, it)}
    return {k: v.strip() for k, v in zip(it, it)}


class CEFParser(BaseParser):
    parser_id = "cef"
    parser_name = "CEF Parser"
    supported_formats = ["cef"]
    description = "ArcSight Common Event Format (CEF)"
    version = "1.2.0"

    def can_parse(self, raw_line: str) -> bool:
        return "CEF:" in raw_line.upper()

    def parse(self, raw_line: str, **kwargs) -> Optional[dict]:
        s = raw_line.strip()
        idx = s.find("CEF:")
        if idx < 0:
            idx = s.upper().find("CEF:")
            if idx < 0:
                return None
        prefix = s[:idx]
        parts = _PIPE_SPLIT.split(s[idx + 4:], maxsplit=7)
        if len(parts) < 7:
            return None
        if len(parts) == 7:
            parts.append("")
        version, vendor, product, dev_ver, sig_id, name, sev, ext_str = (
            _unescape(p) if i < 7 else p for i, p in enumerate(parts))
        if not version.strip().isdigit():
            return None

        # parsed: original keys (forensic fidelity); mapped: normalizer-aligned keys
        parsed = parse_cef_extension(ext_str)
        for key in [k for k in parsed if k.endswith("Label")]:
            base = key[:-5]
            label = parsed[key]
            if base in parsed and label and label not in parsed:
                parsed[label] = parsed[base]
        mapped = {_FMAP.get(k, k): v for k, v in parsed.items()}
        for d in (parsed, mapped):
            d["cef_version"] = version
            d["signature_id"] = sig_id
            d["event_name"] = name

        syslog_hostname = None
        if prefix.strip():
            hm = _PREFIX_HOSTNAME.search(prefix)
            if hm:
                syslog_hostname = hm.group(1)
                parsed["syslog_hostname"] = syslog_hostname

        ts = mapped.get("timestamp") or mapped.get("start_time")
        if not ts and prefix.strip():
            m_ts = _PREFIX_ISO.search(prefix) or _PREFIX_SYSLOG_TS.search(prefix)
            if m_ts:
                ts = m_ts.group(1)

        cat = _categorize(vendor, product, name, mapped, sig_id)

        msg_text = mapped.get("message") or name
        if msg_text and msg_text.strip().lower() in _ENFORCEMENT_VERBS:
            msg_text = f"{product} {name} enforcement" if name else f"{product} rule {sig_id}"

        if "action" not in mapped:
            for candidate in (name, mapped.get("message", ""), sig_id):
                if not candidate:
                    continue
                clow = candidate.strip().lower()
                if _ACTION_DENIED.search(clow):
                    mapped["action"] = "denied"
                    break
                if _ACTION_ALLOWED.search(clow):
                    mapped["action"] = "allowed"
                    break
                if _ACTION_BLOCKED.search(clow):
                    mapped["action"] = "blocked"
                    break

        event = build_normalized_event(
            **kwargs,
            raw_line=raw_line, raw_format="cef", parsed_fields=mapped,
            parser_id=self.parser_id, parser_name=self.parser_name, parser_version=self.version,
            timestamp_str=ts, severity_raw=sev, severity_source="cef",
            category=cat, event_type=f"cef_{sig_id}",
            device_vendor=vendor, device_product=product,
            device_version=dev_ver, message=msg_text,
        )
        event["parsed_fields"] = parsed
        event["rule"]["id"] = sig_id
        event["rule"]["name"] = parsed.get("RuleName") or name
        if mapped.get("cat"):
            event["rule"]["category"] = mapped["cat"]
        if event["category"] in ("ids_ips", "web", "endpoint") or event["severity"] >= 7:
            event["threat"]["signature"] = name
            event["threat"]["signature_id"] = sig_id
        if syslog_hostname and not event["device"]["hostname"]:
            event["device"]["hostname"] = syslog_hostname
        return event


def _categorize(vendor: str, product: str, name: str, parsed: dict, sig_id: str) -> str:
    c = f"{vendor} {product} {name} {parsed.get('cat', '')} {sig_id}".lower()
    for category, pattern in _CATEGORY_RULES:
        if pattern.search(c):
            return category
    return "network"
