"""
Type Inference Engine
=======================
Evolves the original FieldProfile._detect_type() into a proper multi-sample
voting engine with confidence scores and type hierarchy support.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Type hierarchy
# ---------------------------------------------------------------------------

TYPE_HIERARCHY = {
    "timestamp": {"parent": None, "priority": 10},
    "date":      {"parent": None, "priority": 9},
    "time":      {"parent": None, "priority": 9},
    "month":     {"parent": None, "priority": 9},
    "ipv4_port": {"parent": "ip", "priority": 9},
    "ipv4":      {"parent": "ip",  "priority": 9},
    "ipv6":      {"parent": "ip",  "priority": 9},
    "ip":        {"parent": None,  "priority": 8},
    "mac":       {"parent": None,  "priority": 8},
    "uuid":      {"parent": None,  "priority": 8},
    "email":     {"parent": None,  "priority": 7},
    "url":       {"parent": None,  "priority": 7},
    "domain":    {"parent": None,  "priority": 7},
    "hostname":  {"parent": None,  "priority": 6},
    "path":      {"parent": None,  "priority": 6},
    "port":      {"parent": "integer", "priority": 5},
    "pid":       {"parent": "integer", "priority": 5},
    "severity":  {"parent": "enum",    "priority": 5},
    "action":    {"parent": "enum",    "priority": 5},
    "protocol":  {"parent": "enum",    "priority": 5},
    "hash":      {"parent": None,  "priority": 4},
    "hex":       {"parent": None,  "priority": 4},
    "integer":   {"parent": "numeric", "priority": 3},
    "float":     {"parent": "numeric", "priority": 3},
    "numeric":   {"parent": None,  "priority": 2},
    "enum":      {"parent": None,  "priority": 2},
    "boolean":   {"parent": None,  "priority": 2},
    "string":    {"parent": None,  "priority": 0},
}


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
_IPV4_PORT_RE = re.compile(r'^((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})$')
_IPV6_RE = re.compile(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$')
_PORT_RE = re.compile(r'^\d{1,5}$')
_MAC_RE = re.compile(r'^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$')
_UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
_EMAIL_RE = re.compile(r'^[\w.+-]+@[\w-]+\.[\w.]+$')
_URL_RE = re.compile(r'^https?://|^ftp://')
_DOMAIN_RE = re.compile(r'^[a-zA-Z][\w-]*(?:\.[\w-]+)+\.[a-zA-Z]{2,}$')
# Hostnames need a digit or hyphen ("fw-01", "srv42"); plain words are strings
_HOSTNAME_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9-]*(?:[0-9-][a-zA-Z0-9-]*)$')
_DATE_RE = re.compile(r'^(?:\d{4}[-/.]\d{2}[-/.]\d{2}|\d{2}[-/.]\d{2}[-/.]\d{4}|\d{2}/[A-Za-z]{3}/\d{4})$')
_TIME_RE = re.compile(r'^\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?$')
_MONTHS = frozenset(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"))
_HASH_RE = re.compile(r'^[0-9a-fA-F]{32,64}$')
_HEX_RE = re.compile(r'^0x[0-9a-fA-F]+$')
_PATH_RE = re.compile(r'^(?:/[\w.\-]+){2,}$|^[A-Z]:\\')
_INT_RE = re.compile(r'^-?\d+$')
_FLOAT_RE = re.compile(r'^-?\d+\.\d+$')
_BOOL_RE = re.compile(r'^(?:true|false|yes|no|on|off)$', re.I)

_TIMESTAMP_RES = [
    re.compile(r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'),
    re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'),
    re.compile(r'^\d{10,13}(\.\d+)?$'),
    re.compile(r'^\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}'),
    re.compile(r'^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}'),
    re.compile(r'^\d{14}$'),
    # ctime / Apache error log: "Sat Aug 28 10:15:30 2026"
    re.compile(r'^[A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: \d{4})?$'),
]

_SEVERITY_WORDS = frozenset({
    "emergency", "alert", "critical", "error", "warning", "notice", "info",
    "debug", "high", "medium", "low", "fatal", "crit", "err", "warn",
})

_ACTION_WORDS = frozenset({
    "allow", "deny", "drop", "block", "accept", "reject", "permit",
    "pass", "reset", "detect", "alert", "success", "fail",
    "allowed", "denied", "dropped", "blocked", "rejected", "permitted",
    "detected", "alerted", "failed",
})

_PROTOCOL_WORDS = frozenset({
    "tcp", "udp", "icmp", "http", "https", "dns", "ssh", "ftp",
    "smtp", "snmp", "telnet", "rdp", "gre", "esp", "tls",
})


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class TypeVote:
    """A single type vote with confidence."""
    type_name: str
    confidence: float   # 0.0–1.0
    evidence: str = ""  # human-readable reason

    def __repr__(self) -> str:
        return f"{self.type_name}({self.confidence:.0%})"


@dataclass
class InferredType:
    """Result of type inference for a field position."""
    best_type: str
    confidence: float
    votes: list[TypeVote] = field(default_factory=list)
    sample_count: int = 0
    unique_values: int = 0

    def __repr__(self) -> str:
        return f"InferredType({self.best_type}, conf={self.confidence:.0%})"


# ---------------------------------------------------------------------------
# Single-value classifier
# ---------------------------------------------------------------------------

def classify_value(value: str) -> list[TypeVote]:
    """
    Classify a single value against all known types.
    Returns a list of TypeVotes sorted by confidence descending.
    """
    if not value or value == "-":
        return [TypeVote("string", 0.1, "empty or dash")]

    v = value.strip()
    votes: list[TypeVote] = []

    # Timestamp (check first — highest priority)
    for ts_re in _TIMESTAMP_RES:
        if ts_re.match(v):
            votes.append(TypeVote("timestamp", 0.95, "timestamp pattern"))
            break
    else:
        if _DATE_RE.match(v):
            votes.append(TypeVote("date", 0.95, "date pattern"))
        elif _TIME_RE.match(v):
            votes.append(TypeVote("time", 0.95, "time-of-day pattern"))
            return votes
        elif v.lower() in _MONTHS:
            votes.append(TypeVote("month", 0.95, "month name"))
            return votes

    m_ep = _IPV4_PORT_RE.match(v)
    if m_ep and all(0 <= int(o) <= 255 for o in m_ep.group(1).split(".")):
        return [TypeVote("ipv4_port", 0.97, "ip:port endpoint")]

    # UUID
    if _UUID_RE.match(v):
        votes.append(TypeVote("uuid", 0.98, "uuid pattern"))

    # Email
    if _EMAIL_RE.match(v):
        votes.append(TypeVote("email", 0.95, "email pattern"))

    # URL
    if _URL_RE.match(v):
        votes.append(TypeVote("url", 0.95, "url pattern"))

    # Path
    if _PATH_RE.match(v):
        votes.append(TypeVote("path", 0.85, "path pattern"))

    # IPv6 (before MAC) — validated, so "10:15:01" is not mistaken for an address
    if ":" in v and _IPV6_RE.match(v) and not _MAC_RE.match(v):
        try:
            ipaddress.IPv6Address(v)
            votes.append(TypeVote("ipv6", 0.90, "valid ipv6"))
        except ValueError:
            pass

    # IPv4
    if _IPV4_RE.match(v):
        octets = v.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            votes.append(TypeVote("ipv4", 0.95, "valid ipv4"))

    # MAC
    if _MAC_RE.match(v):
        votes.append(TypeVote("mac", 0.95, "mac pattern"))

    # Hash
    if _HASH_RE.match(v) and len(v) in (32, 40, 64):
        votes.append(TypeVote("hash", 0.85, f"hex hash len={len(v)}"))

    # Hex
    if _HEX_RE.match(v):
        votes.append(TypeVote("hex", 0.80, "hex literal"))

    # Domain
    if _DOMAIN_RE.match(v) and not _IPV4_RE.match(v):
        votes.append(TypeVote("domain", 0.80, "domain pattern"))

    # Hostname (short, no dots, contains a digit or hyphen)
    if len(v) <= 63 and _HOSTNAME_RE.match(v) and not v.isdigit():
        votes.append(TypeVote("hostname", 0.50, "hostname heuristic"))

    # Severity
    if v.lower() in _SEVERITY_WORDS:
        votes.append(TypeVote("severity", 0.90, "severity keyword"))

    # Action
    if v.lower() in _ACTION_WORDS:
        votes.append(TypeVote("action", 0.90, "action keyword"))

    # Protocol
    if v.lower() in _PROTOCOL_WORDS:
        votes.append(TypeVote("protocol", 0.90, "protocol keyword"))

    # Boolean
    if _BOOL_RE.match(v):
        votes.append(TypeVote("boolean", 0.85, "boolean literal"))

    # Integers. A bare number is only a *port* with positional context (it
    # directly follows an IPv4 field) — infer_types_for_positions decides that.
    if _INT_RE.match(v):
        votes.append(TypeVote("integer", 0.70, "integer pattern"))

    # Float
    if _FLOAT_RE.match(v):
        votes.append(TypeVote("float", 0.80, "float pattern"))

    # Default: string
    if not votes:
        votes.append(TypeVote("string", 0.3, "default fallback"))

    votes.sort(key=lambda vt: vt.confidence, reverse=True)
    return votes


# ---------------------------------------------------------------------------
# Multi-sample type inference
# ---------------------------------------------------------------------------

def infer_type(values: list[str], min_agreement: float = 0.5) -> InferredType:
    """
    Infer the field type from multiple sample values using voting.

    Each value casts votes for candidate types. The type with the highest
    aggregate confidence across all samples wins, provided it exceeds
    min_agreement.
    """
    if not values:
        return InferredType(best_type="string", confidence=0.0, sample_count=0)

    # Aggregate votes
    type_scores: dict[str, float] = {}
    type_counts: dict[str, int] = {}
    all_votes: list[TypeVote] = []

    for val in values:
        if not val or val.strip() == "-":
            continue
        val_votes = classify_value(val.strip())
        for vote in val_votes:
            type_scores[vote.type_name] = type_scores.get(vote.type_name, 0.0) + vote.confidence
            type_counts[vote.type_name] = type_counts.get(vote.type_name, 0) + 1
            all_votes.append(vote)

    if not type_scores:
        return InferredType(best_type="string", confidence=0.0,
                            sample_count=len(values), unique_values=len(set(values)))

    # Normalise scores by sample count
    n_samples = max(len(values), 1)
    normalised: dict[str, float] = {}
    for t, score in type_scores.items():
        agreement = type_counts[t] / n_samples
        normalised[t] = (score / n_samples) * agreement

    # Pick best type
    best_type = max(normalised, key=normalised.get)
    best_conf = min(normalised[best_type], 1.0)

    # If agreement is too low, fall back to string
    agreement_ratio = type_counts.get(best_type, 0) / n_samples
    if agreement_ratio < min_agreement and best_type != "string":
        best_type = "string"
        best_conf = 0.3

    return InferredType(
        best_type=best_type,
        confidence=round(best_conf, 4),
        votes=all_votes,
        sample_count=len(values),
        unique_values=len(set(values)),
    )


def infer_types_for_positions(
    samples: list[list[str]],
    min_agreement: float = 0.5,
) -> list[InferredType]:
    """
    Given multiple tokenised lines (each a list of token values),
    infer the type for each token position.
    """
    if not samples:
        return []

    max_pos = max(len(row) for row in samples)
    results: list[InferredType] = []

    for pos in range(max_pos):
        values = [row[pos] for row in samples if pos < len(row)]
        results.append(infer_type(values, min_agreement))

    # Positional context: an integer right after an IPv4 address is its port
    for pos in range(1, len(results)):
        if results[pos].best_type == "integer" and results[pos - 1].best_type == "ipv4":
            values = [row[pos] for row in samples if pos < len(row)]
            if all(v.isdigit() and 0 < int(v) <= 65535 for v in values if v):
                results[pos].best_type = "port"
    return results


# Types whose values vary between events even if a small sample happens to
# repeat them; such positions must never be baked into a template literal.
GENERALISABLE_TYPES = frozenset({
    "timestamp", "date", "time", "month", "ipv4", "ipv6", "ipv4_port", "mac", "uuid", "hash", "hex",
    "integer", "float", "port", "pid", "email", "url", "severity", "action", "numeric",
})


def is_generalisable(value: str) -> bool:
    """True if a literal token is really an instance of a variable type."""
    votes = classify_value(value)
    return bool(votes) and votes[0].type_name in GENERALISABLE_TYPES
