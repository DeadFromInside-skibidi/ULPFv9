"""
Semantic Field Mapper
=======================
Maps extracted fields to ULPF's unified schema paths using heuristics
based on field name patterns, positional context, type, and surrounding tokens.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# Schema path mapping rules
# ---------------------------------------------------------------------------

# Key name → schema path (case-insensitive matching)
_KEY_TO_SCHEMA: dict[str, str] = {
    # Source
    "src": "source.ip", "src_ip": "source.ip", "srcip": "source.ip",
    "source_ip": "source.ip", "sip": "source.ip", "s_ip": "source.ip",
    "sourceaddress": "source.ip", "src_addr": "source.ip",
    "src_port": "source.port", "srcport": "source.port", "sport": "source.port",
    "sourceport": "source.port", "s_port": "source.port",
    "src_mac": "source.mac", "srcmac": "source.mac", "smac": "source.mac",
    "src_host": "source.hostname", "srchost": "source.hostname", "shost": "source.hostname",
    "src_zone": "source.zone", "srczone": "source.zone",
    "srcintf": "source.interface", "src_intf": "source.interface",
    # Destination
    "dst": "destination.ip", "dst_ip": "destination.ip", "dstip": "destination.ip",
    "destination_ip": "destination.ip", "dip": "destination.ip", "d_ip": "destination.ip",
    "destinationaddress": "destination.ip", "dst_addr": "destination.ip",
    "dst_port": "destination.port", "dstport": "destination.port", "dport": "destination.port",
    "destinationport": "destination.port", "d_port": "destination.port",
    "dst_mac": "destination.mac", "dstmac": "destination.mac", "dmac": "destination.mac",
    "dst_host": "destination.hostname", "dsthost": "destination.hostname", "dhost": "destination.hostname",
    "dst_zone": "destination.zone", "dstzone": "destination.zone",
    "dstintf": "destination.interface", "dst_intf": "destination.interface",
    # Network
    "proto": "network.protocol", "protocol": "network.protocol",
    "app": "network.application", "application": "network.application",
    "service": "network.application",
    "sent": "network.bytes_out", "sentbyte": "network.bytes_out", "bytes_out": "network.bytes_out",
    "rcvd": "network.bytes_in", "rcvdbyte": "network.bytes_in", "bytes_in": "network.bytes_in",
    "sentpkt": "network.packets_out", "rcvdpkt": "network.packets_in",
    "direction": "network.direction",
    "sessionid": "network.session_id", "session_id": "network.session_id",
    "vlanid": "network.vlan_id",
    # Device
    "devname": "device.hostname", "device_name": "device.hostname", "dvchost": "device.hostname",
    "hostname": "device.hostname",
    "devid": "device.serial", "device_id": "device.serial",
    # Rule
    "policyid": "rule.id", "policy_id": "rule.id", "rule_id": "rule.id",
    "policyname": "rule.name", "policy_name": "rule.name", "rule_name": "rule.name",
    # User
    "user": "user.name", "username": "user.name", "usr": "user.name",
    "duser": "user.name", "suser": "user.name", "login": "user.name",
    "userdomain": "user.domain", "user_domain": "user.domain",
    "userid": "user.id", "uid": "user.id",
    # Action
    "action": "action", "act": "action", "status": "action",
    # Severity
    "severity": "severity", "level": "severity", "priority": "severity",
    # Event type
    "event_type": "event_type", "type": "event_type", "eventtype": "event_type",
    "logtype": "event_type",
    # Message
    "msg": "message", "message": "message", "description": "message",
    # PID
    "pid": "metadata.pid", "process_id": "metadata.pid",
    "ppid": "metadata.ppid",
}

# Type-based positional inference rules
_TYPE_POSITION_RULES: list[dict[str, Any]] = [
    # First timestamp → event timestamp (a lone date counts when no full timestamp exists)
    {"type": "timestamp", "ordinal": 0, "schema": "timestamp"},
    {"type": "date", "ordinal": 0, "schema": "timestamp"},
    # First IPv4 → source.ip, second → destination.ip
    {"type": "ipv4", "ordinal": 0, "schema": "source.ip"},
    {"type": "ipv4", "ordinal": 1, "schema": "destination.ip"},
    # "ip:port" endpoints (split into ip + port during normalisation)
    {"type": "ipv4_port", "ordinal": 0, "schema": "source.ip"},
    {"type": "ipv4_port", "ordinal": 1, "schema": "destination.ip"},
    {"type": "ipv6", "ordinal": 0, "schema": "source.ip"},
    {"type": "ipv6", "ordinal": 1, "schema": "destination.ip"},
    # First port → source.port, second → destination.port
    {"type": "port", "ordinal": 0, "schema": "source.port"},
    {"type": "port", "ordinal": 1, "schema": "destination.port"},
    # First MAC → source.mac, second → destination.mac
    {"type": "mac", "ordinal": 0, "schema": "source.mac"},
    {"type": "mac", "ordinal": 1, "schema": "destination.mac"},
    # Severity
    {"type": "severity", "ordinal": 0, "schema": "severity"},
    # Action
    {"type": "action", "ordinal": 0, "schema": "action"},
    # Protocol
    {"type": "protocol", "ordinal": 0, "schema": "network.protocol"},
    # Hostname (first one → device.hostname)
    {"type": "hostname", "ordinal": 0, "schema": "device.hostname"},
    # URL
    {"type": "url", "ordinal": 0, "schema": "url"},
    # Email
    {"type": "email", "ordinal": 0, "schema": "user.email"},
    # Domain
    {"type": "domain", "ordinal": 0, "schema": "destination.hostname"},
]


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class SemanticMapping:
    """Mapping of a field to its ULPF schema path."""
    position: int
    field_type: str
    schema_path: str
    confidence: float
    source: str             # "kv_key", "type_position", "heuristic"
    original_key: str = ""  # e.g. "srcip", "" if positional

    def __repr__(self) -> str:
        return f"Map(pos={self.position}, {self.schema_path}, conf={self.confidence:.0%})"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def map_fields(
    positions: list[dict[str, Any]],
    kv_pairs: dict[str, str] | None = None,
) -> list[SemanticMapping]:
    """
    Map variable field positions to ULPF schema paths.

    Args:
        positions: list of dicts with at least:
            - position: int
            - type: str (inferred type)
            - kv_key: str | None (if from a KV pair)
        kv_pairs: optional dict of key→value pairs detected in the line

    Returns:
        list of SemanticMappings
    """
    mappings: list[SemanticMapping] = []
    used_schemas: set[str] = set()
    type_ordinals: dict[str, int] = {}

    # Phase 1: Map KV keys to schema paths (highest confidence)
    for pos_info in positions:
        kv_key = pos_info.get("kv_key")
        if kv_key:
            schema = _lookup_key(kv_key)
            if schema and schema not in used_schemas:
                mappings.append(SemanticMapping(
                    position=pos_info["position"],
                    field_type=pos_info.get("type", "string"),
                    schema_path=schema,
                    confidence=0.95,
                    source="kv_key",
                    original_key=kv_key,
                ))
                used_schemas.add(schema)
                continue

    # Also map standalone KV pairs
    if kv_pairs:
        for key, value in kv_pairs.items():
            schema = _lookup_key(key)
            if schema and schema not in used_schemas:
                mappings.append(SemanticMapping(
                    position=-1,  # KV position not tracked separately
                    field_type="string",
                    schema_path=schema,
                    confidence=0.90,
                    source="kv_key",
                    original_key=key,
                ))
                used_schemas.add(schema)

    # Phase 2: Map by type + positional order
    mapped_positions = {m.position for m in mappings}
    for pos_info in positions:
        if pos_info["position"] in mapped_positions:
            continue

        field_type = pos_info.get("type", "string")
        ordinal = type_ordinals.get(field_type, 0)
        type_ordinals[field_type] = ordinal + 1

        schema = _lookup_type_position(field_type, ordinal)
        if schema and schema not in used_schemas:
            mappings.append(SemanticMapping(
                position=pos_info["position"],
                field_type=field_type,
                schema_path=schema,
                confidence=0.70,
                source="type_position",
            ))
            used_schemas.add(schema)
        else:
            # Fallback: generate a generic field name
            fallback = _generate_fallback_name(field_type, pos_info["position"])
            mappings.append(SemanticMapping(
                position=pos_info["position"],
                field_type=field_type,
                schema_path=fallback,
                confidence=0.30,
                source="heuristic",
            ))

    return mappings


def infer_family(
    mappings: list[SemanticMapping],
    kv_keys: list[str] | None = None,
) -> tuple[str, float]:
    """
    Infer the parser family from semantic mappings.

    Returns (family_name, confidence).
    """
    schema_paths = {m.schema_path for m in mappings}
    keys = set(k.lower() for k in (kv_keys or []))

    # Scoring heuristics
    scores: dict[str, float] = {
        "network.firewall": 0.0,
        "identity.auth": 0.0,
        "network.ids": 0.0,
        "endpoint.process": 0.0,
        "application.web": 0.0,
        "application.custom": 0.0,
    }

    # Network indicators
    if "source.ip" in schema_paths and "destination.ip" in schema_paths:
        scores["network.firewall"] += 0.3
    if "source.port" in schema_paths or "destination.port" in schema_paths:
        scores["network.firewall"] += 0.2
    if "network.protocol" in schema_paths:
        scores["network.firewall"] += 0.15
    if "action" in schema_paths:
        scores["network.firewall"] += 0.1
        if any(k in keys for k in ("policyid", "policy_id", "rule_id")):
            scores["network.firewall"] += 0.2

    # Auth indicators
    if "user.name" in schema_paths:
        scores["identity.auth"] += 0.3
    if any(k in keys for k in ("auth", "login", "logon", "password", "credential")):
        scores["identity.auth"] += 0.3
    if "action" in schema_paths:
        scores["identity.auth"] += 0.1

    # IDS indicators
    if any(k in keys for k in ("signature", "sig_id", "attack", "cve", "threat")):
        scores["network.ids"] += 0.5

    # Endpoint indicators
    if any(k in keys for k in ("pid", "ppid", "process", "cmdline", "image")):
        scores["endpoint.process"] += 0.5

    # Web indicators
    if any(k in keys for k in ("request", "method", "uri", "referer", "user_agent", "status_code")):
        scores["application.web"] += 0.5

    best_family = max(scores, key=scores.get)
    best_score = scores[best_family]

    if best_score < 0.2:
        return "application.custom", 0.3

    return best_family, min(best_score, 1.0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _lookup_key(key: str) -> str | None:
    """Look up a KV key in the schema mapping."""
    return _KEY_TO_SCHEMA.get(key.lower().replace("-", "_").replace(".", "_"))


def _lookup_type_position(field_type: str, ordinal: int) -> str | None:
    """Look up schema path by type + ordinal position."""
    for rule in _TYPE_POSITION_RULES:
        if rule["type"] == field_type and rule["ordinal"] == ordinal:
            return rule["schema"]
    return None


def _generate_fallback_name(field_type: str, position: int) -> str:
    """Generate a fallback field name."""
    type_prefix = {
        "string": "field", "integer": "numeric", "float": "numeric",
        "ipv4": "ip", "ipv6": "ip", "ipv4_port": "endpoint", "port": "port", "mac": "mac",
        "date": "date", "time": "time", "severity": "level", "action": "outcome",
        "hostname": "host", "domain": "domain", "url": "url",
        "email": "email", "uuid": "uuid", "hash": "hash",
        "hex": "hex", "path": "path", "pid": "pid",
    }
    prefix = type_prefix.get(field_type, "field")
    return f"extensions.{prefix}_{position}"
