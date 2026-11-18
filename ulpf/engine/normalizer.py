"""
Normalization Engine
====================
Transforms parsed vendor-specific fields into the ULPF unified schema.
Handles timestamp normalization, severity harmonization, protocol mapping.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any

from ulpf.engine.schema import canonical_category, new_unified_event, severity_label, utc_now_iso

_UTC = timezone.utc

# ---------------------------------------------------------------------------
# Protocol mapping
# ---------------------------------------------------------------------------
PROTOCOL_MAP: dict[int, str] = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6",
    47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}
PROTOCOL_NAME_MAP: dict[str, int] = {v.lower(): k for k, v in PROTOCOL_MAP.items()}

# ---------------------------------------------------------------------------
# Severity mapping tables (target scale: 0-10)
# ---------------------------------------------------------------------------
SYSLOG_SEV: dict[int, int] = {0: 10, 1: 9, 2: 9, 3: 7, 4: 5, 5: 3, 6: 1, 7: 0}

CEF_SEV: dict[str, int] = {
    "unknown": 0, "low": 3, "medium": 5, "high": 7,
    "very-high": 9, "critical": 10,
}

TEXT_SEV: dict[str, int] = {
    "debug": 0, "trace": 0,
    "info": 1, "informational": 1, "information": 1,
    "notice": 3, "low": 3,
    "warning": 5, "warn": 5, "medium": 5, "med": 5, "moderate": 5,
    "error": 7, "err": 7, "high": 7, "severe": 7,
    "critical": 9, "crit": 9, "alert": 9, "very-high": 9,
    "emergency": 10, "emerg": 10, "fatal": 10, "panic": 10,
}

# ---------------------------------------------------------------------------
# Timestamp formats attempted after the fast paths
# ---------------------------------------------------------------------------
TS_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%d-%b-%Y %H:%M:%S",
    "%a %b %d %H:%M:%S %Y",
    "%Y%m%d%H%M%S",
    "%b %d %Y %H:%M:%S",
    "%b %d %Y %H:%M:%S.%f",
    "%d %b %Y %H:%M:%S",
    "%b %d %H:%M:%S.%f",
]

_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

# ---------------------------------------------------------------------------
# Field alias mapping: vendor-specific → unified schema path
# ---------------------------------------------------------------------------
FIELD_ALIASES: dict[str, str] = {
    # Source IP
    "src": "source.ip", "src_ip": "source.ip", "srcip": "source.ip", "src-ip": "source.ip",
    "source_ip": "source.ip", "sourceip": "source.ip", "source-ip": "source.ip",
    "sip": "source.ip",
    "sourceaddress": "source.ip", "source_address": "source.ip", "src_addr": "source.ip", "srcaddr": "source.ip",
    "c-ip": "source.ip", "c_ip": "source.ip", "cs-ip": "source.ip", "cs_ip": "source.ip",
    "client_ip": "source.ip", "clientip": "source.ip", "client-ip": "source.ip", "client": "source.ip",
    "remip": "source.ip", "remote_ip": "source.ip", "remoteip": "source.ip", "remote_addr": "source.ip",
    "caller_ip": "source.ip", "origin_ip": "source.ip",
    # Source Port
    "src_port": "source.port", "srcport": "source.port", "sport": "source.port", "spt": "source.port",
    "sourceport": "source.port", "source_port": "source.port",
    "c-port": "source.port", "c_port": "source.port", "client_port": "source.port", "clientport": "source.port",
    # Source Host / Mac / Interface / Zone
    "src_mac": "source.mac", "srcmac": "source.mac", "smac": "source.mac",
    "src_host": "source.hostname", "srchost": "source.hostname", "shost": "source.hostname", "source_host": "source.hostname",
    "src_zone": "source.zone", "srczone": "source.zone",
    "srcintf": "source.interface", "src_intf": "source.interface",

    # Destination IP
    "dst": "destination.ip", "dst_ip": "destination.ip", "dstip": "destination.ip", "dst-ip": "destination.ip",
    "dest": "destination.ip", "dest_ip": "destination.ip", "destip": "destination.ip", "dest-ip": "destination.ip",
    "destination_ip": "destination.ip", "destinationip": "destination.ip", "destination-ip": "destination.ip",
    "dip": "destination.ip", "d_ip": "destination.ip",
    "destinationaddress": "destination.ip", "destination_address": "destination.ip",
    "dst_addr": "destination.ip", "dstaddr": "destination.ip", "dest_addr": "destination.ip", "destaddr": "destination.ip",
    # W3C: s-ip is the *server* address, i.e. the destination of the request
    "s-ip": "destination.ip", "s_ip": "destination.ip",
    "server_ip": "destination.ip", "serverip": "destination.ip", "server-ip": "destination.ip", "server": "destination.ip",
    "target_ip": "destination.ip", "targetip": "destination.ip", "target-ip": "destination.ip", "target": "destination.ip",
    "locip": "destination.ip", "local_ip": "destination.ip", "localip": "destination.ip",
    # Destination Port
    "dst_port": "destination.port", "dstport": "destination.port", "dport": "destination.port", "dpt": "destination.port",
    "dest_port": "destination.port", "destport": "destination.port",
    "destinationport": "destination.port", "destination_port": "destination.port", "d_port": "destination.port",
    "s-port": "destination.port", "s_port": "destination.port", "server_port": "destination.port", "serverport": "destination.port",
    # Destination Host / Mac / Interface / Zone
    "dst_mac": "destination.mac", "dstmac": "destination.mac", "dmac": "destination.mac",
    "dst_host": "destination.hostname", "dsthost": "destination.hostname", "dhost": "destination.hostname",
    "dest_host": "destination.hostname", "destination_host": "destination.hostname",
    "dst_zone": "destination.zone", "dstzone": "destination.zone",
    "dstintf": "destination.interface", "dst_intf": "destination.interface",

    # Network
    "proto": "network.protocol", "protocol": "network.protocol", "ip_proto": "network.protocol", "transport": "network.protocol",
    "app": "network.application", "application": "network.application",
    "service": "network.application",
    "sent": "network.bytes_out", "sentbyte": "network.bytes_out", "bytes_out": "network.bytes_out",
    "sc-bytes": "network.bytes_out", "sc_bytes": "network.bytes_out",
    "rcvd": "network.bytes_in", "rcvdbyte": "network.bytes_in", "bytes_in": "network.bytes_in",
    "cs-bytes": "network.bytes_in", "cs_bytes": "network.bytes_in",
    "sentpkt": "network.packets_out", "rcvdpkt": "network.packets_in",
    "direction": "network.direction",
    "sessionid": "network.session_id", "session_id": "network.session_id",
    "vlanid": "network.vlan_id",
    # Device
    "devname": "device.hostname", "device_name": "device.hostname", "dvchost": "device.hostname",
    "devid": "device.serial", "device_id": "device.serial",
    "dvc": "device.ip",
    # Rule
    "policyid": "rule.id", "policy_id": "rule.id", "rule_id": "rule.id",
    "policyname": "rule.name", "policy_name": "rule.name", "rule_name": "rule.name",
    # User
    "user": "user.name", "username": "user.name", "usr": "user.name", "cs-username": "user.name",
    "suser": "user.source.name", "src_user": "user.source.name", "source_user": "user.source.name",
    "duser": "user.target.name", "dst_user": "user.target.name", "target_user": "user.target.name",
    "userdomain": "user.domain",
    # Cloud identity providers (CloudTrail userIdentity, Okta actor, Azure / Entra UPN)
    "useridentity.arn": "user.id", "actor.alternateid": "user.email", "userprincipalname": "user.email",
    "upn": "user.email", "user_email": "user.email", "email": "user.email",
    # Windows Security Event Log (EventData Name=…)
    "targetusername": "user.target.name", "targetdomainname": "user.target.domain",
    "targetusersid": "user.target.id",
    "subjectusername": "user.source.name", "subjectdomainname": "user.source.domain",
    "subjectusersid": "user.source.id",
    "ipaddress": "source.ip", "ipport": "source.port", "workstationname": "source.hostname",
    "computer": "device.hostname",
    # EDR telemetry (CrowdStrike, Defender for Endpoint, SentinelOne, Elastic Agent)
    "computername": "device.hostname", "devicename": "device.hostname", "endpoint_name": "device.hostname",
    "agent_hostname": "device.hostname", "aid": "device.serial", "deviceid": "device.serial",
    "localaddressip4": "source.ip", "localip": "source.ip", "localport": "source.port",
    "remoteaddressip4": "destination.ip", "remoteip": "destination.ip", "remoteport": "destination.port",
    "accountname": "user.name", "initiatingprocessaccountname": "user.name", "user_name": "user.name",
    # Databases (MySQL Enterprise / Percona audit, PostgreSQL, SQL Server, Oracle)
    "db_user": "user.name", "dbuser": "user.name", "login_name": "user.name", "server_principal_name": "user.name",
    "client_hostname": "source.hostname", "host_name": "source.hostname", "connection_ip": "source.ip",
}

# Action mapping
ACTION_MAP: dict[str, str] = {
    "allow": "allowed", "allowed": "allowed", "accept": "allowed", "accepted": "allowed",
    "pass": "allowed", "passed": "allowed", "permit": "allowed", "permitted": "allowed",
    "block": "blocked", "blocked": "blocked", "prevent": "blocked", "prevented": "blocked",
    "quarantine": "blocked", "quarantined": "blocked",
    "drop": "dropped", "dropped": "dropped", "discard": "dropped",
    "deny": "denied", "denied": "denied", "reject": "denied", "rejected": "denied",
    "reset": "reset", "rst": "reset",
    "log": "logged", "logged": "logged", "monitor": "logged", "monitored": "logged",
    "detect": "detected", "detected": "detected",
    "alert": "alerted", "alerted": "alerted",
    "connect": "connected", "connected": "connected", "established": "connected",
    "disconnect": "disconnected", "disconnected": "disconnected", "close": "disconnected",
    "closed": "disconnected", "timeout": "disconnected",
    "fail": "failed", "failed": "failed", "failure": "failed", "denial": "denied",
    "success": "success", "successful": "success", "succeeded": "success",
}

DIRECTION_MAP: dict[str, str] = {
    "inbound": "inbound", "in": "inbound", "ingress": "inbound", "incoming": "inbound",
    "outbound": "outbound", "out": "outbound", "egress": "outbound", "outgoing": "outbound",
    "internal": "internal", "lateral": "internal",
    "external": "external",
}

_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_EPOCH = re.compile(r"^\d{10}(?:\d{3})?(?:\.\d+)?$")
_NULLISH = frozenset(("", "none", "null", "undefined", "-", "None", "NULL", " ", "n/a", "N/A"))
_INT_FIELDS = frozenset(("port", "bytes_in", "bytes_out", "bytes_total", "packets_in", "packets_out",
                         "protocol_number"))


# ---------------------------------------------------------------------------
# Public normalisation functions
# ---------------------------------------------------------------------------

_utc_now = utc_now_iso


def _infer_syslog_year(month: int, day: int, hour: int, minute: int, second: int) -> datetime:
    """RFC 3164 timestamps carry no year: pick the most recent past occurrence."""
    now = datetime.now(_UTC)
    dt = datetime(now.year, month, day, hour, minute, second, tzinfo=_UTC)
    if dt - now > timedelta(days=1):
        dt = dt.replace(year=now.year - 1)
    return dt


@lru_cache(maxsize=8192)
def _parse_ts(ts_str: str) -> str | None:
    """Parse a timestamp string to an ISO-8601 UTC string, or None."""
    # Epoch seconds / milliseconds
    if _EPOCH.match(ts_str):
        val = float(ts_str)
        if val > 1e11:
            val /= 1000.0
        return datetime.fromtimestamp(val, tz=_UTC).isoformat()

    # ISO 8601 / RFC 3339 (C-implemented, ~15x faster than strptime)
    if len(ts_str) >= 10 and ts_str[4] == "-" and ts_str[7] == "-":
        try:
            dt = datetime.fromisoformat(ts_str[:-1] + "+00:00" if ts_str[-1] in "Zz" else ts_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_UTC)
            return dt.astimezone(_UTC).isoformat()
        except ValueError:
            pass

    # RFC 3164 "Oct 11 22:14:15" / "Oct  1 22:14:15"
    if len(ts_str) == 15 and ts_str[3] == " " and ts_str[9] == ":" and ts_str[12] == ":":
        mon = _MONTHS.get(ts_str[:3])
        if mon:
            try:
                dt = _infer_syslog_year(mon, int(ts_str[4:6]), int(ts_str[7:9]),
                                        int(ts_str[10:12]), int(ts_str[13:15]))
                return dt.isoformat()
            except ValueError:
                pass

    for fmt in TS_FORMATS:
        try:
            dt = datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
        if dt.year == 1900:
            dt = _infer_syslog_year(dt.month, dt.day, dt.hour, dt.minute, dt.second).replace(
                microsecond=dt.microsecond)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_UTC)
        return dt.astimezone(_UTC).isoformat()

    try:
        from dateutil import parser as dp
        dt = dp.parse(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_UTC)
        return dt.astimezone(_UTC).isoformat()
    except Exception:
        return None


def normalize_timestamp(ts_str: str | None) -> tuple[str, str | None]:
    """Normalize a timestamp to ISO-8601 UTC. Returns (normalised, original).

    If the value cannot be parsed, the ingestion time is used and the
    original is still returned so the source value is never lost.
    """
    if ts_str is None:
        return _utc_now(), None
    ts_str = str(ts_str).strip()
    if not ts_str:
        return _utc_now(), None
    parsed = _parse_ts(ts_str)
    if parsed is None:
        return _utc_now(), ts_str
    return parsed, ts_str


def _clamp_sev(val: float) -> int:
    return max(0, min(int(round(val)), 10))


def normalize_severity(raw: Any, source_type: str = "generic") -> tuple[int, str]:
    """Normalize severity to the 0-10 scale. Returns (number, label)."""
    if raw is None or raw == "":
        return 0, "unknown"

    s = str(raw).strip().lower()

    if source_type == "syslog" and s.isdigit():
        val = SYSLOG_SEV.get(int(s), 0)
        return val, severity_label(val)

    if s.isdigit():
        val = _clamp_sev(int(s))
        return val, severity_label(val)

    try:
        val = _clamp_sev(float(s))
        return val, severity_label(val)
    except ValueError:
        pass

    if source_type == "cef" and s in CEF_SEV:
        val = CEF_SEV[s]
    else:
        val = TEXT_SEV.get(s, CEF_SEV.get(s, 0))
    return val, severity_label(val)


def normalize_protocol(raw: Any) -> tuple[str | None, int | None]:
    """Normalize protocol to (name, number)."""
    if raw is None:
        return None, None
    s = str(raw).strip()
    if not s:
        return None, None
    if s.isdigit():
        num = int(s)
        return PROTOCOL_MAP.get(num, s), num
    return s.upper(), PROTOCOL_NAME_MAP.get(s.lower())


@lru_cache(maxsize=4096)
def _normalize_action_str(s: str) -> str:
    hit = ACTION_MAP.get(s)
    if hit:
        return hit
    hit = ACTION_MAP.get(s.replace("-", "").replace("_", ""))
    if hit:
        return hit
    # Compound vendor actions: "allow-url", "client-rst", "Accept (NAT)"
    for tok in _NON_ALNUM.split(s):
        hit = ACTION_MAP.get(tok)
        if hit:
            return hit
    return "other"


def normalize_action(raw: Any) -> str:
    if raw is None:
        return "other"
    s = str(raw).strip().lower()
    return _normalize_action_str(s) if s else "other"


def normalize_direction(raw: Any) -> str | None:
    if raw is None:
        return None
    return DIRECTION_MAP.get(str(raw).strip().lower(), "unknown")


_I64 = (-(2 ** 63), 2 ** 63 - 1)


def _to_int(value: Any) -> Any:
    """Integer value of a counter/port field, or None.

    Values outside the signed 64-bit range are dropped from the unified field
    (they stay in parsed_fields and raw_event): no output format can carry them.
    """
    if type(value) is int:
        return value if _I64[0] <= value <= _I64[1] else None
    try:
        v = int(value)
    except (ValueError, TypeError):
        try:
            v = int(float(value))
        except (ValueError, TypeError, OverflowError):
            return None
    return v if _I64[0] <= v <= _I64[1] else None


_RE_FALLBACK_ISO = re.compile(r"\b(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b")
_RE_FALLBACK_SYSLOG = re.compile(r"\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b")
_RE_FALLBACK_IPV4 = re.compile(r"\b((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b")
_RE_SRC_KEY_HINT = re.compile(r"\b(?:client|src|src_ip|srcip|source|from|remip)\s*[=:]\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", re.I)
_RE_DST_KEY_HINT = re.compile(r"\b(?:target|dst|dst_ip|dstip|dest|dest_ip|destination|to|server|locip)\s*[=:]\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", re.I)
_RE_SPORT_KEY_HINT = re.compile(r"\b(?:spt|sport|src_port|client_port)\s*[=:]\s*(\d+)", re.I)
_RE_DPORT_KEY_HINT = re.compile(r"\b(?:dpt|dport|dst_port|server_port)\s*[=:]\s*(\d+)", re.I)


_FIELD_ALIASES_TUPLES: dict[str, tuple[str, ...]] = {k: tuple(v.split(".")) for k, v in FIELD_ALIASES.items()}

# Canonical dotted schema paths accepted verbatim (ECS-style JSON, learned parsers)
_SCHEMA_PATHS: dict[str, tuple[str, ...]] = {}
for _grp, _keys in (
    ("source", ("ip", "port", "mac", "hostname", "interface", "zone")),
    ("destination", ("ip", "port", "mac", "hostname", "interface", "zone")),
    ("network", ("protocol", "protocol_number", "direction", "bytes_in", "bytes_out", "bytes_total",
                 "packets_in", "packets_out", "application", "session_id", "vlan_id")),
    ("device", ("vendor", "product", "version", "hostname", "ip", "type", "serial")),
    ("rule", ("id", "name", "description", "action", "category")),
    ("user", ("name", "domain", "id", "email", "group")),
):
    for _k in _keys:
        _SCHEMA_PATHS[f"{_grp}.{_k}"] = (_grp, _k)
for _side in ("source", "target"):
    for _k in ("name", "domain", "id"):
        _SCHEMA_PATHS[f"user.{_side}.{_k}"] = ("user", _side, _k)

# Bounded memo of resolved keys (keys come from untrusted input, so cap it)
_RESOLVE_CACHE: dict[str, tuple[str, ...] | None] = {}
_RESOLVE_CACHE_MAX = 20_000


def _resolve_field(key: str) -> tuple[str, ...] | None:
    try:
        return _RESOLVE_CACHE[key]
    except KeyError:
        pass
    target = _FIELD_ALIASES_TUPLES.get(key)
    if target is None:
        k = key.lower()
        target = _SCHEMA_PATHS.get(k) or _FIELD_ALIASES_TUPLES.get(k)
        if target is None and "." in k:
            target = _FIELD_ALIASES_TUPLES.get(k.rsplit(".", 1)[-1])
        if target is None:
            target = _FIELD_ALIASES_TUPLES.get(k.replace("_", "").replace("-", ""))
    if len(_RESOLVE_CACHE) >= _RESOLVE_CACHE_MAX:
        _RESOLVE_CACHE.clear()
    _RESOLVE_CACHE[key] = target
    return target


def apply_field_mappings(parsed: dict[str, Any], event: dict) -> dict:
    """Map parsed vendor-specific fields to the unified event schema."""
    cache = _RESOLVE_CACHE
    nullish = _NULLISH
    int_fields = _INT_FIELDS
    for key, value in parsed.items():
        try:
            target = cache[key]
        except KeyError:
            target = _resolve_field(key)
        if target is None or value is None:
            continue
        vtype = type(value)
        if vtype is str:
            if value in nullish:
                continue
        elif vtype is dict or vtype is list:
            continue

        final = target[-1]
        if final in int_fields:
            value = _to_int(value)
            if value is None:
                continue
        if len(target) == 2:
            event[target[0]][final] = value
        else:
            event[target[0]][target[1]][final] = value

    # Primary user.name: explicit user → target account → source account
    user = event["user"]
    if not user["name"]:
        user["name"] = user["target"]["name"] or user["source"]["name"]

    return event


def build_normalized_event(
    *,
    raw_line: str,
    raw_format: str,
    parsed_fields: dict[str, Any],
    parser_id: str,
    parser_name: str,
    timestamp_str: str | None = None,
    severity_raw: Any = None,
    severity_source: str = "generic",
    category: str = "other",
    event_type: str | None = None,
    device_vendor: str | None = None,
    device_product: str | None = None,
    device_version: str | None = None,
    message: str | None = None,
    raw_hash: str | None = None,
    event_id: str | None = None,
    timestamp_now: str | None = None,
    parser_version: str | None = None,
) -> dict:
    """Build a fully normalized UnifiedEvent dict from parsed data.

    Args:
        raw_hash: Pre-computed SHA-256 hex digest of the raw line. If provided
                  it is NOT recomputed (single-hash provenance invariant).
    """
    event = new_unified_event(event_id=event_id, timestamp=timestamp_now)
    event["raw_event"] = raw_line
    event["raw_format"] = raw_format
    event["parsed_fields"] = parsed_fields
    event["category"] = canonical_category(category)
    event["event_type"] = event_type
    event["message"] = message

    ts_norm, ts_orig = normalize_timestamp(timestamp_str)
    event["timestamp"] = ts_norm
    event["timestamp_original"] = ts_orig

    sev_num, sev_label = normalize_severity(severity_raw, severity_source)
    event["severity"] = sev_num
    event["severity_label"] = sev_label

    device = event["device"]
    device["vendor"] = device_vendor
    device["product"] = device_product
    device["version"] = device_version

    apply_field_mappings(parsed_fields, event)

    for action_key in ("action", "act", "status"):
        if action_key in parsed_fields:
            event["action"] = normalize_action(parsed_fields[action_key])
            break

    net = event["network"]
    if net["protocol"] is not None:
        net["protocol"], num = normalize_protocol(net["protocol"])
        if net["protocol_number"] is None:
            net["protocol_number"] = num
    if net["direction"] is not None:
        net["direction"] = normalize_direction(net["direction"])
    if net["bytes_total"] is None and (net["bytes_in"] is not None or net["bytes_out"] is not None):
        total = (net["bytes_in"] or 0) + (net["bytes_out"] or 0)
        if type(total) is not int or _I64[0] <= total <= _I64[1]:
            net["bytes_total"] = total

    if raw_hash is None:
        raw_hash = hashlib.sha256(raw_line.encode("utf-8", errors="replace")).hexdigest()
    event["evidence"]["raw_hash"] = raw_hash
    meta = event["metadata"]
    meta["raw_hash_sha256"] = raw_hash
    meta["parser_id"] = parser_id
    meta["parser_name"] = parser_name
    meta["parser_version"] = parser_version

    return event


build_normalized_event_py = build_normalized_event   # the reference implementation
NATIVE = False


def _load_native():
    """The compiled core (``ulpf/ulpf_core*.pyd|so``, built from native/ulpf_core).

    It handles the inputs whose Python semantics it reproduces exactly and
    calls the functions above for everything else, so results are identical
    (tests/test_native.py). Opt-in with ``ULPF_NATIVE=1``: measured on the
    benchmark corpus it is not faster than this module (18.6 vs 16.4 us per
    event; building Python dicts through the C API costs what it saves), see
    docs/STATUS.md, Phase F.
    """
    import os
    if os.environ.get("ULPF_NATIVE", "0") != "1":
        return None
    try:
        from ulpf import ulpf_core
    except ImportError:
        return None
    from ulpf.engine import schema
    try:
        ulpf_core.init({
            "parse_ts": _parse_ts, "normalize_severity": normalize_severity, "normalize_action": normalize_action,
            "normalize_protocol": normalize_protocol, "normalize_direction": normalize_direction,
            "to_int": _to_int, "resolve_field": _resolve_field, "utc_now": _utc_now,
            "new_uuid": schema.new_uuid, "canonical_category": canonical_category,
            "sha256_py": lambda s: hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest(),
            "schema_version": schema.SCHEMA_VERSION,
            "aliases": {k: list(v) for k, v in _FIELD_ALIASES_TUPLES.items()},
            "schema_paths": {k: list(v) for k, v in _SCHEMA_PATHS.items()},
            "action_map": ACTION_MAP, "direction_map": DIRECTION_MAP,
            "protocol_map": PROTOCOL_MAP, "protocol_names": PROTOCOL_NAME_MAP,
            "syslog_sev": SYSLOG_SEV, "cef_sev": CEF_SEV, "text_sev": TEXT_SEV,
            "categories": list(schema.CATEGORIES), "category_aliases": schema.CATEGORY_ALIASES,
            "nullish": sorted(_NULLISH), "int_fields": sorted(_INT_FIELDS),
        })
    except Exception:
        import logging
        logging.getLogger(__name__).warning("ulpf_core failed to initialise; using the Python path",
                                            exc_info=True)
        return None
    return ulpf_core.build_normalized_event


def set_native(enabled: bool) -> bool:
    """Switch every parser between the compiled and the Python builder (tests, benchmarks)."""
    import os
    import sys
    global build_normalized_event, NATIVE
    fast = None
    if enabled:
        prev = os.environ.get("ULPF_NATIVE")
        os.environ["ULPF_NATIVE"] = "1"
        try:
            fast = _load_native()
        finally:
            if prev is None:
                os.environ.pop("ULPF_NATIVE", None)
            else:
                os.environ["ULPF_NATIVE"] = prev
    new = fast or build_normalized_event_py
    old = (build_normalized_event, build_normalized_event_py)   # captured: the loop rebinds our own global
    for name, mod in list(sys.modules.items()):
        if name == "ulpf.ulpf_core":
            continue
        if getattr(mod, "build_normalized_event", None) in old:
            mod.build_normalized_event = new
    build_normalized_event = new
    NATIVE = fast is not None
    return NATIVE


_native = _load_native()
if _native is not None:
    build_normalized_event = _native
    NATIVE = True


def build_raw_fallback_event(raw_line: str, raw_hash: str | None = None, event_id: str | None = None,
                             timestamp_now: str | None = None) -> dict:
    """Build a minimal normalized event for unknown / unclassified formats.

    No line is ever dropped: the raw text is preserved verbatim and the
    timestamp, IPs and ports are recovered heuristically when present.
    """
    event = new_unified_event(event_id=event_id, timestamp=timestamp_now)
    event["raw_event"] = raw_line
    event["raw_format"] = "raw_fallback"
    event["message"] = raw_line[:512]

    ts_found = None
    m_iso = _RE_FALLBACK_ISO.search(raw_line)
    if m_iso:
        ts_found = m_iso.group(1)
    else:
        m_sys = _RE_FALLBACK_SYSLOG.search(raw_line)
        if m_sys:
            ts_found = m_sys.group(1)
    if ts_found:
        event["timestamp"], event["timestamp_original"] = normalize_timestamp(ts_found)

    src_match = _RE_SRC_KEY_HINT.search(raw_line)
    dst_match = _RE_DST_KEY_HINT.search(raw_line)
    src_ip = src_match.group(1) if src_match else None
    dst_ip = dst_match.group(1) if dst_match else None

    if not src_ip and not dst_ip:
        all_ips: list[str] = []
        for match in _RE_FALLBACK_IPV4.finditer(raw_line):
            ip = match.group(1)
            if ip not in ("0.0.0.0", "255.255.255.0", "255.255.255.255") and ip not in all_ips:
                all_ips.append(ip)
                if len(all_ips) == 2:
                    break
        if all_ips:
            src_ip = all_ips[0]
        if len(all_ips) >= 2:
            dst_ip = all_ips[1]

    if src_ip:
        event["source"]["ip"] = src_ip
    if dst_ip:
        event["destination"]["ip"] = dst_ip

    sport_m = _RE_SPORT_KEY_HINT.search(raw_line)
    if sport_m:
        event["source"]["port"] = int(sport_m.group(1))
    dport_m = _RE_DPORT_KEY_HINT.search(raw_line)
    if dport_m:
        event["destination"]["port"] = int(dport_m.group(1))

    if raw_hash is None:
        raw_hash = hashlib.sha256(raw_line.encode("utf-8", errors="replace")).hexdigest()
    event["evidence"]["raw_hash"] = raw_hash
    event["metadata"]["raw_hash_sha256"] = raw_hash
    event["metadata"]["parser_id"] = "raw_fallback"
    event["metadata"]["parser_name"] = "Raw Fallback"
    event["tags"].append("unclassified")

    return event
