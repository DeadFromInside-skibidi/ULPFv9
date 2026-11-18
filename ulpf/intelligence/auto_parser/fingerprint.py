"""
Format Fingerprinting
=======================
Creates a compact structural signature for each log event so that
the registry can perform O(1) lookups. This is the hot-path-optimised
version — no full entropy/character-frequency computation per event.

Fingerprint format:
    FORMAT: syslog=yes timestamp=iso8601 delimiters=space kv=true fields=6 ipv4=1 numeric=1 quoted=false
    → SHA-256[:16] → fingerprint_id
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# Quick detection patterns (compiled once)
# ---------------------------------------------------------------------------

_IS_SYSLOG = re.compile(r'^<\d{1,3}>|^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}')
_IS_CEF = re.compile(r'CEF:\d+\|', re.I)
_IS_LEEF = re.compile(r'LEEF:\d+', re.I)
_IS_JSON = re.compile(r'^\s*[{\[]')
_IS_XML = re.compile(r'^\s*<(?:\?xml|[a-zA-Z])')
_HAS_KV = re.compile(r'[\w.]+=[^\s]+')
_HAS_IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_HAS_IPV6 = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b')
_HAS_TS_ISO = re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}')
_HAS_TS_SYSLOG = re.compile(r'[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}')
_HAS_TS_EPOCH = re.compile(r'\b\d{10,13}\b')
_HAS_NUMERIC = re.compile(r'\b\d+\b')


# ---------------------------------------------------------------------------
# Data container
# ---------------------------------------------------------------------------

@dataclass
class FormatFingerprint:
    """Compact structural signature of a log line or batch."""
    fingerprint_id: str = ""
    # Structural features
    format_type: str = ""       # syslog, cef, leef, json, xml, kv, csv, unknown
    timestamp_format: str = ""  # iso8601, syslog, epoch, none
    delimiter: str = " "
    kv_format: bool = False
    field_count: int = 0
    ipv4_count: int = 0
    ipv6_count: int = 0
    numeric_count: int = 0
    has_quotes: bool = False
    line_length_bucket: str = ""    # short (<100), medium (100-500), long (>500)
    # Signature string for hashing
    signature: str = ""

    def to_dict(self) -> dict:
        return {
            "fingerprint_id": self.fingerprint_id,
            "format_type": self.format_type,
            "timestamp_format": self.timestamp_format,
            "delimiter": repr(self.delimiter),
            "kv_format": self.kv_format,
            "field_count": self.field_count,
            "ipv4_count": self.ipv4_count,
            "ipv6_count": self.ipv6_count,
            "numeric_count": self.numeric_count,
            "has_quotes": self.has_quotes,
            "line_length_bucket": self.line_length_bucket,
            "signature": self.signature,
        }

    def __repr__(self) -> str:
        return f"FP({self.fingerprint_id[:8]}… {self.format_type} fields={self.field_count})"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_fingerprint(raw_line: str) -> FormatFingerprint:
    """
    Compute a structural fingerprint for a single raw log line.

    This is designed to be fast enough for the hot path:
    - No full entropy computation
    - No character frequency analysis
    - O(1)-ish regex checks
    """
    fp = FormatFingerprint()
    stripped = raw_line.strip()

    if not stripped:
        fp.fingerprint_id = "empty"
        return fp

    # ------ Format type ------
    if _IS_CEF.search(stripped[:100]):
        fp.format_type = "cef"
    elif _IS_LEEF.search(stripped[:100]):
        fp.format_type = "leef"
    elif _IS_JSON.match(stripped):
        fp.format_type = "json"
    elif _IS_XML.match(stripped):
        fp.format_type = "xml"
    elif _IS_SYSLOG.match(stripped):
        fp.format_type = "syslog"
    else:
        # Check KV
        kv_matches = _HAS_KV.findall(stripped)
        if len(kv_matches) >= 3:
            fp.format_type = "kv"
            fp.kv_format = True
        elif "\t" in stripped and stripped.count("\t") >= 3:
            fp.format_type = "tsv"
        elif "," in stripped and stripped.count(",") >= 3:
            fp.format_type = "csv"
        else:
            fp.format_type = "unknown"

    # ------ KV detection ------
    if not fp.kv_format:
        kv_matches = _HAS_KV.findall(stripped)
        fp.kv_format = len(kv_matches) >= 3

    # ------ Timestamp format ------
    if _HAS_TS_ISO.search(stripped):
        fp.timestamp_format = "iso8601"
    elif _HAS_TS_SYSLOG.search(stripped):
        fp.timestamp_format = "syslog"
    elif _HAS_TS_EPOCH.search(stripped):
        fp.timestamp_format = "epoch"
    else:
        fp.timestamp_format = "none"

    # ------ Delimiter ------
    fp.delimiter = _quick_delimiter(stripped)

    # ------ Field count ------
    if fp.format_type in ("json", "xml"):
        fp.field_count = 0  # not token-countable
    else:
        fp.field_count = len(stripped.split(fp.delimiter))

    # ------ IP counts ------
    fp.ipv4_count = len(_HAS_IPV4.findall(stripped))
    fp.ipv6_count = len(_HAS_IPV6.findall(stripped))

    # ------ Numeric count ------
    fp.numeric_count = len(_HAS_NUMERIC.findall(stripped))

    # ------ Quotes ------
    fp.has_quotes = '"' in stripped or "'" in stripped

    # ------ Line length bucket ------
    length = len(stripped)
    if length < 100:
        fp.line_length_bucket = "short"
    elif length < 500:
        fp.line_length_bucket = "medium"
    else:
        fp.line_length_bucket = "long"

    # ------ Build signature + hash ------
    # numeric_count is deliberately NOT part of the signature: it varies with
    # values (thread names, version strings, decimals) and would split one
    # format across many fingerprints.
    fp.signature = (
        f"fmt={fp.format_type} ts={fp.timestamp_format} "
        f"delim={repr(fp.delimiter)} kv={fp.kv_format} "
        f"fields={fp.field_count} ipv4={fp.ipv4_count} quoted={fp.has_quotes}"
    )
    fp.fingerprint_id = hashlib.sha256(fp.signature.encode()).hexdigest()[:16]

    return fp


def compute_batch_fingerprint(lines: list[str]) -> FormatFingerprint:
    """
    Compute a consensus fingerprint from multiple lines (e.g. a file).
    Uses majority voting across individual fingerprints.
    """
    if not lines:
        return FormatFingerprint(fingerprint_id="empty")

    # Sample up to 50 lines for efficiency
    sample = [l for l in lines[:50] if l.strip() and not l.strip().startswith("#")]
    if not sample:
        return FormatFingerprint(fingerprint_id="empty")

    fps = [compute_fingerprint(line) for line in sample]

    # Majority vote on format_type
    type_votes: dict[str, int] = {}
    for fp in fps:
        type_votes[fp.format_type] = type_votes.get(fp.format_type, 0) + 1
    majority_type = max(type_votes, key=type_votes.get)

    # Use the first fingerprint matching the majority type as representative
    representative = next((fp for fp in fps if fp.format_type == majority_type), fps[0])

    # Average field count among matching fingerprints
    matching = [fp for fp in fps if fp.format_type == majority_type]
    if matching:
        avg_fields = sum(fp.field_count for fp in matching) // len(matching)
        representative.field_count = avg_fields

    return representative


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _quick_delimiter(line: str) -> str:
    """Fast delimiter detection for a single line."""
    candidates = {"\t": 0, "|": 0, ",": 0, ";": 0, " ": 0}
    for d in candidates:
        count = line.count(d)
        if count >= 2:
            candidates[d] = count

    # Prefer structured delimiters
    non_space = {d: c for d, c in candidates.items() if d != " " and c > 0}
    if non_space:
        best_non_space = max(non_space, key=non_space.get)
        if non_space[best_non_space] >= candidates[" "] * 0.3:
            return best_non_space

    return " "
