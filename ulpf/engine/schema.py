"""
ULPF Unified Event Schema
==========================
OCSF-inspired universal event schema that normalizes heterogeneous security logs
into a single, analytics-ready representation while preserving complete raw data.

``new_unified_event()`` is on the per-event hot path, so it builds the event
from literal dicts (no deepcopy / JSON round-trip) and uses a urandom-backed
UUIDv4 generator that is ~10x faster than ``uuid.uuid4()``.

``SCHEMA_DEFINITION`` is the single source of truth for field documentation;
the REST API and the desktop Schema page both render from it.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any

# Semantic version of the unified schema. Minor versions are additive only
# (``ulpf schema diff`` enforces it against ulpf/engine/schema_registry/).
SCHEMA_VERSION = "1.1.0"

_urandom = os.urandom
_VARIANT = "89ab"
_UTC = timezone.utc
_now_cache: list = [0, ""]  # [epoch milliseconds, iso string]


def _utc_now_iso() -> str:
    """Current UTC time (ISO-8601, millisecond resolution).

    datetime.now().isoformat() costs ~2.5 µs; at tens of thousands of events
    per second many events share a millisecond, so the string is reused.
    """
    ms = int(time.time() * 1000)
    cache = _now_cache
    if cache[0] != ms:
        cache[1] = datetime.fromtimestamp(ms / 1000, _UTC).isoformat(timespec="milliseconds")
        cache[0] = ms
    return cache[1]


utc_now_iso = _utc_now_iso


def new_uuid() -> str:
    """Return a random RFC 4122 version-4 UUID string."""
    h = _urandom(16).hex()
    return (f"{h[:8]}-{h[8:12]}-4{h[13:16]}-"
            f"{_VARIANT[int(h[16], 16) & 3]}{h[17:20]}-{h[20:]}")


# ---------------------------------------------------------------------------
# Severity scale (0-10) and canonical category taxonomy
# ---------------------------------------------------------------------------

SEVERITY_LABELS: dict[int, str] = {
    0: "unknown",
    1: "info", 2: "info",
    3: "low", 4: "low",
    5: "medium", 6: "medium",
    7: "high", 8: "high",
    9: "critical", 10: "critical",
}


def severity_label(value: int) -> str:
    """Map a 0-10 severity score to its label."""
    return SEVERITY_LABELS.get(value, "unknown")


CATEGORIES: tuple[str, ...] = (
    "network", "firewall", "ids_ips", "authentication", "web", "dns",
    "proxy", "vpn", "endpoint", "system", "audit", "other",
)

# Parser-specific category names folded into the canonical taxonomy
CATEGORY_ALIASES: dict[str, str] = {
    "identity": "authentication",
    "auth": "authentication",
    "ids": "ids_ips",
    "ips": "ids_ips",
    "threat": "ids_ips",
    "waf": "web",
    "host": "endpoint",
}


def canonical_category(name: str | None) -> str:
    if not name:
        return "other"
    name = name.lower()
    if name in CATEGORY_ALIASES:
        return CATEGORY_ALIASES[name]
    return name if name in CATEGORIES else "other"


# ---------------------------------------------------------------------------
# Event construction (hot path)
# ---------------------------------------------------------------------------

def new_endpoint() -> dict:
    return {"ip": None, "port": None, "mac": None, "hostname": None,
            "interface": None, "zone": None}


def new_network() -> dict:
    return {"protocol": None, "protocol_number": None, "direction": None,
            "bytes_in": None, "bytes_out": None, "bytes_total": None,
            "packets_in": None, "packets_out": None,
            "application": None, "session_id": None, "vlan_id": None}


def new_device() -> dict:
    return {"vendor": None, "product": None, "version": None,
            "hostname": None, "ip": None, "type": None, "serial": None}


def new_rule() -> dict:
    return {"id": None, "name": None, "description": None,
            "action": None, "category": None}


def new_threat() -> dict:
    return {"category": None, "signature": None, "signature_id": None,
            "cve": [], "confidence": None, "ioc_type": None, "ioc_value": None}


def new_user() -> dict:
    return {
        "name": None, "domain": None, "id": None, "email": None, "group": None,
        "source": {"name": None, "domain": None, "id": None},
        "target": {"name": None, "domain": None, "id": None},
    }


def new_geo() -> dict:
    return {"src_country": None, "src_country_code": None, "src_city": None,
            "src_latitude": None, "src_longitude": None,
            "dst_country": None, "dst_country_code": None, "dst_city": None,
            "dst_latitude": None, "dst_longitude": None}


def new_metadata(ingestion_time: str | None = None) -> dict:
    return {"ingestion_time": ingestion_time or _utc_now_iso(),
            "schema_version": SCHEMA_VERSION,
            "processing_time_ms": None,
            "pipeline_version": SCHEMA_VERSION, "parser_id": None, "parser_name": None,
            "detection_confidence": None, "normalization_version": SCHEMA_VERSION,
            "raw_hash_sha256": None, "parser_version": None,
            "source_fingerprint": None, "parser_confidence": None,
            "template_id": None}


def new_unified_event(event_id: str | None = None, timestamp: str | None = None) -> dict:
    """Create an empty, schema-conformant event."""
    ts = timestamp or _utc_now_iso()
    return {
        "event_id": event_id or new_uuid(),
        "timestamp": ts,
        "timestamp_original": None,
        "category": "other",
        "event_type": None,
        "action": "other",
        "severity": 0,
        "severity_label": "unknown",
        "source": new_endpoint(),
        "destination": new_endpoint(),
        "network": new_network(),
        "device": new_device(),
        "rule": new_rule(),
        "threat": new_threat(),
        "user": new_user(),
        "geo": new_geo(),
        "raw_event": None,
        "raw_format": None,
        "parsed_fields": {},
        "tags": [],
        "extensions": {},
        "metadata": new_metadata(ts),
        "message": None,
        "correlation_id": None,
        "related_events": [],
        "evidence": {"raw_hash": None, "chain_of_custody": []},
    }


# Static template (documentation / GUI preview only — never mutated)
_TEMPLATE: dict = new_unified_event(event_id="00000000-0000-4000-8000-000000000000",
                                    timestamp="1970-01-01T00:00:00+00:00")


# ---------------------------------------------------------------------------
# Field catalogue
# ---------------------------------------------------------------------------

def _f(name: str, ftype: str, description: str, example: Any = "") -> dict:
    return {"name": name, "type": ftype, "description": description, "example": str(example)}


_ENDPOINT_DOC = {
    "ip": ("IPv4/IPv6 string", "IP address", "198.51.100.20"),
    "port": ("integer (0-65535)", "TCP/UDP port number", "52341"),
    "mac": ("string", "MAC address", "00:1A:2B:3C:4D:5E"),
    "hostname": ("string", "Hostname", "ws-042.corp.local"),
    "interface": ("string", "Device interface the traffic used", "port1"),
    "zone": ("string", "Security zone", "trust"),
}


def _endpoint_fields(prefix: str, role: str) -> list[dict]:
    return [_f(f"{prefix}.{k}", t, f"{role} {d}", e) for k, (t, d, e) in _ENDPOINT_DOC.items()]


SCHEMA_GROUPS: list[dict] = [
    {
        "category": "IDENTITY",
        "description": "Primary event identification, chronological markers and correlation keys",
        "fields": [
            _f("event_id", "UUID string", "Universally unique identifier for the normalized event",
               "d3b07384-d113-4a1e-8a9a-24156f2f9d83"),
            _f("timestamp", "ISO 8601 string (UTC)", "Event time normalized to UTC", "2026-09-27T10:15:30+00:00"),
            _f("timestamp_original", "string", "Timestamp exactly as supplied by the source", "Sep 27 10:15:30"),
            _f("correlation_id", "string", "Correlation group this event belongs to", "c8f12a9e01ab"),
            _f("related_events", "array of strings", "Event IDs correlated with this event", '["a1b2…"]'),
        ],
    },
    {
        "category": "CLASSIFICATION",
        "description": "Semantic categorisation, action outcome and severity",
        "fields": [
            _f("category", "enum string", "Functional category: " + ", ".join(CATEGORIES), "firewall"),
            _f("event_type", "string", "Source-specific event subtype", "cef_100"),
            _f("action", "enum string",
               "Normalized outcome (allowed, blocked, dropped, denied, reset, detected, alerted, "
               "logged, connected, disconnected, failed, success, other)", "blocked"),
            _f("severity", "integer (0-10)", "Normalized severity score, 0 = unknown, 10 = most severe", "7"),
            _f("severity_label", "enum string", "unknown, info, low, medium, high or critical", "high"),
            _f("message", "string", "Human-readable event message", "SQL injection attempt"),
            _f("tags", "array of strings", "Enrichment tags (ioc_match, cross_border, high_severity …)",
               '["ioc_match"]'),
        ],
    },
    {
        "category": "SOURCE ENDPOINT",
        "description": "Initiator of the activity",
        "fields": _endpoint_fields("source", "Source"),
    },
    {
        "category": "DESTINATION ENDPOINT",
        "description": "Target of the activity",
        "fields": _endpoint_fields("destination", "Destination"),
    },
    {
        "category": "NETWORK",
        "description": "Transport protocol, volume counters and session identifiers",
        "fields": [
            _f("network.protocol", "string", "Transport protocol name", "TCP"),
            _f("network.protocol_number", "integer", "IANA protocol number", "6"),
            _f("network.direction", "enum string", "inbound, outbound, internal, external or unknown", "inbound"),
            _f("network.bytes_in", "integer", "Bytes received", "4096"),
            _f("network.bytes_out", "integer", "Bytes sent", "12800"),
            _f("network.bytes_total", "integer", "bytes_in + bytes_out", "16896"),
            _f("network.packets_in", "integer", "Packets received", "12"),
            _f("network.packets_out", "integer", "Packets sent", "9"),
            _f("network.application", "string", "Application-layer service", "HTTPS"),
            _f("network.session_id", "string", "Device session identifier", "123456"),
            _f("network.vlan_id", "string", "VLAN identifier", "100"),
        ],
    },
    {
        "category": "DEVICE",
        "description": "Appliance or host that produced the log",
        "fields": [
            _f("device.vendor", "string", "Vendor name", "Check Point"),
            _f("device.product", "string", "Product name", "VPN-1 & FireWall-1"),
            _f("device.version", "string", "Firmware / software version", "R81.20"),
            _f("device.hostname", "string", "Hostname of the logging device", "fw-perimeter-01"),
            _f("device.ip", "IPv4/IPv6 string", "Management IP of the device", "10.0.0.1"),
            _f("device.type", "string", "Device class", "firewall"),
            _f("device.serial", "string", "Device serial / ID", "FG100F1234567890"),
        ],
    },
    {
        "category": "RULE",
        "description": "Policy or detection rule that matched",
        "fields": [
            _f("rule.id", "string", "Rule / policy identifier", "941100"),
            _f("rule.name", "string", "Rule / policy name", "Block_Suspicious_Egress"),
            _f("rule.description", "string", "Rule description", ""),
            _f("rule.action", "string", "Action configured on the rule", "deny"),
            _f("rule.category", "string", "Rule category", "malware"),
        ],
    },
    {
        "category": "THREAT",
        "description": "Detection signatures and threat-intelligence matches",
        "fields": [
            _f("threat.category", "string", "Threat classification (from IOC feed or signature)", "C2 Server"),
            _f("threat.signature", "string", "Detection signature name", "ET TROJAN Beacon"),
            _f("threat.signature_id", "string", "Signature identifier", "2200074"),
            _f("threat.cve", "array of strings", "Referenced CVE identifiers", '["CVE-2024-21413"]'),
            _f("threat.confidence", "float (0-1)", "Confidence of the IOC match", "0.95"),
            _f("threat.ioc_type", "string", "Indicator type that matched", "ip"),
            _f("threat.ioc_value", "string", "Indicator value that matched", "185.220.101.1"),
        ],
    },
    {
        "category": "USER",
        "description": "Accounts involved in the activity",
        "fields": [
            _f("user.name", "string", "Primary account name", "secops_admin"),
            _f("user.domain", "string", "Authentication realm / AD domain", "CORP"),
            _f("user.id", "string", "Account identifier", "S-1-5-21-…"),
            _f("user.email", "string", "Account email", "admin@corp.internal"),
            _f("user.group", "string", "Group membership", "Domain Admins"),
            _f("user.source.name", "string", "Initiating account", "alice"),
            _f("user.source.domain", "string", "Initiating account domain", "CORP"),
            _f("user.source.id", "string", "Initiating account identifier", "1001"),
            _f("user.target.name", "string", "Target account", "administrator"),
            _f("user.target.domain", "string", "Target account domain", "CORP"),
            _f("user.target.id", "string", "Target account identifier", "500"),
        ],
    },
    {
        "category": "GEO",
        "description": "Offline GeoIP enrichment from the bundled database",
        "fields": [
            _f(f"geo.{side}_{attr}", t, f"{label} {d}", e)
            for side, label in (("src", "Source"), ("dst", "Destination"))
            for attr, t, d, e in (
                ("country", "string", "country", "Germany"),
                ("country_code", "string", "ISO country code (XX = private)", "DE"),
                ("city", "string", "city", "Frankfurt"),
                ("latitude", "float", "latitude", "50.11"),
                ("longitude", "float", "longitude", "8.68"),
            )
        ],
    },
    {
        "category": "RAW & PARSED",
        "description": "Lossless original data and source-specific attributes",
        "fields": [
            _f("raw_event", "string", "Verbatim original log line", "CEF:0|Check Point|…"),
            _f("raw_format", "string", "Detected format (cef, leef, syslog, json, xml, kv, csv, w3c, "
               "auto_detected, raw_fallback)", "cef"),
            _f("parsed_fields", "object", "Every vendor field extracted by the parser, original keys "
               "(attributes with no unified field are kept here, so nothing is dropped)", '{"act": "drop"}'),
            _f("extensions", "object", "Pipeline extensions (anomaly, drift, correlation, seal, container, "
               "journald); vendor or plugin additions use an x-<vendor> key", '{"x-acme": {"plant": "7"}}'),
            _f("event_kind", "enum string", "log, anomaly, drift, correlation, detection, notable or seal (derived events)", "log"),
        ],
    },
    {
        "category": "FORENSIC & PROVENANCE",
        "description": "Integrity hashes and pipeline metadata",
        "fields": [
            _f("evidence.raw_hash", "SHA-256 hex", "SHA-256 of raw_event computed once at pipeline entry",
               "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            _f("evidence.chain_of_custody", "array", "Custody entries attached by forensic export", "[]"),
            _f("evidence.journal_seq", "integer", "Sequence of the raw record in the node's journal "
               "(original bytes: GET /api/v1/events/{id}/raw)", "48213"),
            _f("evidence.node_id", "string", "Node that journaled and sealed the record", "node-7f3a91"),
            _f("metadata.ingestion_time", "ISO 8601 string", "When ULPF ingested the event", "2026-09-27T10:15:31+00:00"),
            _f("metadata.schema_version", "string", "Unified schema version of this event", SCHEMA_VERSION),
            _f("metadata.input", "string", "Configured input that received the record", "edge-syslog"),
            _f("metadata.ingestion_source", "string", "Sender address, file path or stream name", "10.0.0.1"),
            _f("metadata.ingestion_source_ip", "IPv4/IPv6 string", "Sender address (network inputs)", "10.0.0.1"),
            _f("metadata.processing_time_ms", "float", "Sampled pipeline latency (every 4096th event)", "0.142"),
            _f("metadata.pipeline_version", "string", "Pipeline version", SCHEMA_VERSION),
            _f("metadata.parser_id", "string", "Parser that produced the event", "cef"),
            _f("metadata.parser_name", "string", "Human-readable parser name", "CEF Parser"),
            _f("metadata.parser_version", "string", "Parser version", "1.1.0"),
            _f("metadata.parser_confidence", "float", "Confidence of a learned (APG) parser", "0.85"),
            _f("metadata.detection_confidence", "float (0-1)", "Format detector confidence", "0.98"),
            _f("metadata.normalization_version", "string", "Normalizer version", SCHEMA_VERSION),
            _f("metadata.raw_hash_sha256", "SHA-256 hex", "Same digest as evidence.raw_hash", "e3b0c442…"),
            _f("metadata.source_fingerprint", "string", "Structural fingerprint of the source format", "e6d6dac1cf8f571c"),
            _f("metadata.template_id", "string", "Learned template identifier", "auto_239255553bf0"),
        ],
    },
]

# Industry schemas an output can deliver instead of the unified event (``view``). Each maps
# both ways (ulpf.engine.views.apply_view / from_view): vendor fields without a standard
# home are kept under x_<vendor>, unified fields without one under x_ulpf.
STANDARD_VIEWS: dict = {
    "ecs": {"name": "Elastic Common Schema", "version": "8.11.0", "inverse": False},
    "ocsf": {"name": "Open Cybersecurity Schema Framework", "version": "1.3.0", "inverse": True,
             "extension_field": "unmapped"},
    "udm": {"name": "Google Security Operations Unified Data Model", "version": "field list 2026-10",
            "inverse": True, "extension_field": "additional"},
    "asim": {"name": "Microsoft Sentinel Advanced Security Information Model", "version": "schemas 1.0.0",
             "inverse": True, "extension_field": "AdditionalFields"},
}

SCHEMA_DEFINITION: dict = {
    "name": "ULPF Unified Event Schema",
    "version": SCHEMA_VERSION,
    "severity_scale": {str(k): v for k, v in SEVERITY_LABELS.items()},
    "categories": list(CATEGORIES),
    "groups": SCHEMA_GROUPS,
    "field_count": sum(len(g["fields"]) for g in SCHEMA_GROUPS),
    "views": STANDARD_VIEWS,
}
