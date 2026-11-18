"""
Value Masker
==============
Stage 2 of the native learning pipeline.
Aggressively replaces dynamic values with typed placeholders so that
structural clustering converges on templates deterministically.

Before masking:
    2026-09-15T22:30:01 FW01 AUTH_FAIL user=admin src=10.2.3.4 pid=8421

After masking:
    <TIMESTAMP> <HOST> AUTH_FAIL user=<USERNAME> src=<IPV4> pid=<PID>

Two messages that differ only in dynamic values converge immediately
to the same structural template *before* expensive clustering runs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# Typed mask labels
# ---------------------------------------------------------------------------

MASK_TIMESTAMP = "<TIMESTAMP>"
MASK_IPV4 = "<IPV4>"
MASK_IPV6 = "<IPV6>"
MASK_MAC = "<MAC>"
MASK_UUID = "<UUID>"
MASK_HASH_VALUE = "<HASH>"
MASK_PID = "<PID>"
MASK_PORT = "<PORT>"
MASK_NUMERIC_ID = "<NUMERIC_ID>"
MASK_HEX = "<HEX>"
MASK_DOMAIN = "<DOMAIN>"
MASK_EMAIL = "<EMAIL>"
MASK_URL = "<URL>"
MASK_PATH = "<PATH>"
MASK_USERNAME = "<USERNAME>"
MASK_STRING = '"<STRING>"'


# ---------------------------------------------------------------------------
# Compiled patterns (order matters — more specific patterns first)
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[re.Pattern, str]] = [
    # ISO 8601 timestamps (various precisions)
    (re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'), MASK_TIMESTAMP),
    # Standalone ISO dates: 2026-09-30
    (re.compile(r'\b\d{4}-\d{2}-\d{2}\b'), MASK_TIMESTAMP),
    # Standalone times: 10:15:01 or 10:15:01.123
    (re.compile(r'\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b'), MASK_TIMESTAMP),
    # Syslog timestamps: Sep 15 22:30:01
    (re.compile(r'[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'), MASK_TIMESTAMP),
    # Apache/NCSA timestamps: 15/Sep/2026:22:30:01 +0530
    (re.compile(r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]?\d{4}'), MASK_TIMESTAMP),
    # Epoch timestamps (10-13 digits)
    (re.compile(r'\b\d{10,13}(?:\.\d+)?\b'), MASK_TIMESTAMP),
    # Compact timestamps: 20260915223001
    (re.compile(r'\b\d{14}\b'), MASK_TIMESTAMP),

    # UUIDs
    (re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'), MASK_UUID),

    # Email addresses (before domain to avoid partial matches)
    (re.compile(r'\b[\w.+-]+@[\w-]+\.[\w.]+\b'), MASK_EMAIL),

    # URLs
    (re.compile(r'https?://[^\s,;|"\']+'), MASK_URL),
    (re.compile(r'ftp://[^\s,;|"\']+'), MASK_URL),

    # File paths (Unix and Windows)
    (re.compile(r'(?:/[\w.\-]+){2,}'), MASK_PATH),
    (re.compile(r'[A-Z]:\\(?:[\w.\- ]+\\)*[\w.\- ]+'), MASK_PATH),

    # IPv6 (at least 3 colons to avoid conflict with HH:MM:SS)
    (re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b'), MASK_IPV6),
    (re.compile(r'\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b'), MASK_IPV6),

    # IPv4
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), MASK_IPV4),

    # Quoted string values in key="value" or standalone
    (re.compile(r'(?<==)"[^"]*"'), MASK_STRING),

    # Key-value numeric values: key=1234
    (re.compile(r'(?<==)\d+\b'), MASK_NUMERIC_ID),

    # MAC addresses
    (re.compile(r'\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b'), MASK_MAC),

    # SHA-256 hashes (64 hex chars)
    (re.compile(r'\b[0-9a-fA-F]{64}\b'), MASK_HASH_VALUE),
    # SHA-1 / other (40 hex chars)
    (re.compile(r'\b[0-9a-fA-F]{40}\b'), MASK_HASH_VALUE),
    # MD5 (32 hex chars)
    (re.compile(r'\b[0-9a-fA-F]{32}\b'), MASK_HASH_VALUE),

    # Hex values (8+ chars, not matching other patterns)
    (re.compile(r'\b0x[0-9a-fA-F]{2,16}\b'), MASK_HEX),

    # Domain names (after IP to avoid false positives)
    (re.compile(r'\b[a-zA-Z][\w-]*(?:\.[\w-]+)+\.[a-zA-Z]{2,}\b'), MASK_DOMAIN),
]

# Patterns used within KV values for more targeted masking
_KV_VALUE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$'), MASK_IPV4),
    (re.compile(r'^\d{1,5}$'), MASK_PORT),
    (re.compile(r'^\d+$'), MASK_NUMERIC_ID),
    (re.compile(r'^[a-zA-Z][\w.-]+$'), MASK_USERNAME),
]


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class MaskedToken:
    """A token with its mask label (if dynamic) or original value (if invariant)."""
    original: str
    masked: str
    mask_type: str | None   # None means the token was not masked (likely invariant)
    position: int

    @property
    def is_masked(self) -> bool:
        return self.mask_type is not None

    def __repr__(self) -> str:
        if self.is_masked:
            return f"M({self.mask_type}, orig={self.original!r})"
        return f"I({self.original!r})"


@dataclass
class MaskedLine:
    """Result of masking a tokenised line."""
    original: str
    masked_text: str
    tokens: list[MaskedToken]
    mask_summary: dict[str, int]    # count of each mask type applied

    @property
    def structural_template(self) -> str:
        """The masked text as a structural template for clustering."""
        return self.masked_text

    def __repr__(self) -> str:
        return f"MaskedLine({self.masked_text[:80]}...)"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def mask_line(raw_line: str) -> MaskedLine:
    """
    Mask all dynamic values in a raw log line.

    Returns a MaskedLine with each dynamic segment replaced by a typed
    placeholder (e.g. <IPV4>, <TIMESTAMP>, <PID>).
    """
    text = raw_line.strip()
    masked_text = text
    mask_counts: dict[str, int] = {}
    applied: list[tuple[int, int, str]] = []

    # Apply patterns in priority order, tracking spans to avoid overlaps
    for pattern, label in _PATTERNS:
        for m in pattern.finditer(masked_text):
            start, end = m.start(), m.end()
            # Check for overlap with already-applied masks
            if any(s <= start < e or s < end <= e for s, e, _ in applied):
                continue
            applied.append((start, end, label))
            mask_counts[label] = mask_counts.get(label, 0) + 1

    # Sort by position descending so replacements don't shift offsets
    applied.sort(key=lambda x: x[0], reverse=True)
    for start, end, label in applied:
        masked_text = masked_text[:start] + label + masked_text[end:]

    # Build token list from the masked text
    tokens: list[MaskedToken] = []
    raw_parts = text.split()
    masked_parts = masked_text.split()

    for i, (orig, msk) in enumerate(zip(raw_parts, masked_parts)):
        mask_type = msk if msk.startswith("<") and msk.endswith(">") else None
        tokens.append(MaskedToken(
            original=orig,
            masked=msk,
            mask_type=mask_type,
            position=i,
        ))

    # Handle length mismatch (splitting differences due to masking)
    remaining_raw = raw_parts[len(tokens):]
    remaining_masked = masked_parts[len(tokens):]
    for i, (orig, msk) in enumerate(zip(remaining_raw, remaining_masked)):
        mask_type = msk if msk.startswith("<") and msk.endswith(">") else None
        tokens.append(MaskedToken(
            original=orig,
            masked=msk,
            mask_type=mask_type,
            position=len(tokens),
        ))

    return MaskedLine(
        original=text,
        masked_text=masked_text,
        tokens=tokens,
        mask_summary=mask_counts,
    )


def mask_kv_values(kv_pairs: dict[str, str]) -> dict[str, str]:
    """
    Mask values within key-value pairs for targeted type inference.

    Returns dict mapping each key to its mask label or the original value.
    """
    result: dict[str, str] = {}
    for key, value in kv_pairs.items():
        masked = value
        for pattern, label in _KV_VALUE_PATTERNS:
            if pattern.match(value):
                masked = label
                break
        result[key] = masked
    return result


def mask_batch(lines: list[str]) -> list[MaskedLine]:
    """Mask multiple lines."""
    return [mask_line(line) for line in lines]


def get_type_for_value(value: str) -> str | None:
    """
    Classify a single value against all mask patterns.
    Returns the mask label or None if unclassifiable.
    """
    for pattern, label in _PATTERNS:
        if pattern.fullmatch(value):
            return label
    return None
