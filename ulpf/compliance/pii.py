"""
Personal-data discovery, redaction and tokenisation (Indian and common identifiers).

Every detector validates what it can (Aadhaar: Verhoeff check digit; card
numbers: Luhn; PAN: holder-type letter; GSTIN: state code and embedded PAN),
so a 12-digit order number is not reported as an Aadhaar number.

    scanner = PIIScanner()
    scanner.scan("Aadhaar 2345 6789 0124 ...")        -> [PIIMatch(type="aadhaar", ...)]
    scanner.redact(text)                               -> "Aadhaar [REDACTED:aadhaar] ..."
    scanner.tokenize(text, key)                        -> "Aadhaar tok_aadhaar_5f1c0e4b9a7d2e31 ..."

Tokens are keyed HMAC-SHA256 (deterministic per key), so the same identifier
maps to the same token everywhere and searches / joins still work, while the
value cannot be recovered without the key.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Iterable

# Verhoeff (dihedral group D5) tables
_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def verhoeff_valid(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_PAN_HOLDER = set("ABCFGHLJPTK")    # 4th character: holder type (P individual, C company, ...)
_GST_STATES = {f"{i:02d}" for i in range(1, 39)} | {"97", "99"}


def _aadhaar(m: re.Match) -> bool:
    d = re.sub(r"[\s-]", "", m.group(0))
    return len(d) == 12 and d[0] not in "01" and verhoeff_valid(d)


def _card(m: re.Match) -> bool:
    d = re.sub(r"[\s-]", "", m.group(0))
    return 13 <= len(d) <= 19 and luhn_valid(d) and len(set(d)) > 1


def _pan(m: re.Match) -> bool:
    return m.group(0)[3].upper() in _PAN_HOLDER


def _gstin(m: re.Match) -> bool:
    g = m.group(0).upper()
    return g[:2] in _GST_STATES and g[5] in _PAN_HOLDER


def _ip(m: re.Match) -> bool:
    try:
        ipaddress.ip_address(m.group(0))
        return True
    except ValueError:
        return False


# (type, pattern, validator). Order matters: earlier types win overlapping spans.
_DETECTORS: list[tuple[str, re.Pattern, Any]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),
    ("gstin", re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b"), _gstin),
    ("aadhaar", re.compile(r"(?<!\d)[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?!\d)"), _aadhaar),
    ("card", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), _card),
    ("pan", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), _pan),
    ("phone_in", re.compile(r"(?<![\w+])(?:\+91[\s-]?|91[\s-]|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"), None),
    ("upi", re.compile(r"\b[A-Za-z0-9._-]{2,256}@(?:ok)?(?:sbi|hdfc|icici|axis|paytm|ybl|ibl|upi|apl|"
                       r"okaxis|okhdfcbank|okicici|oksbi|airtel|kotak|barodampay|axl|pz|freecharge)\b", re.I), None),
    ("ifsc", re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"), None),
    ("passport_in", re.compile(r"\b[A-PR-WY][1-9]\d{5}[1-9]\b"), None),
    ("voter_id", re.compile(r"\b[A-Z]{3}\d{7}\b"), None),
    ("ipv4", re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"), _ip),
    ("ipv6", re.compile(r"(?<![:\w])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}(?![:\w])"), _ip),
]

TYPES = tuple(t for t, _, _ in _DETECTORS)
# Categories as reported in breach notifications
CATEGORY = {"email": "contact", "phone_in": "contact", "aadhaar": "government_id", "pan": "government_id",
            "passport_in": "government_id", "voter_id": "government_id", "gstin": "business_id",
            "card": "financial", "upi": "financial", "ifsc": "financial", "ipv4": "online_identifier",
            "ipv6": "online_identifier"}


@dataclass(frozen=True)
class PIIMatch:
    type: str
    start: int
    end: int
    value: str


def normalize(ptype: str, value: str) -> str:
    """Canonical form of an identifier (for tokens, subject matching and counting)."""
    if ptype in ("aadhaar", "card"):
        return re.sub(r"[\s-]", "", value)
    if ptype == "phone_in":
        d = re.sub(r"\D", "", value)
        return d[-10:]
    if ptype in ("email", "upi"):
        return value.lower()
    return value.upper() if ptype in ("pan", "gstin", "ifsc", "passport_in", "voter_id") else value


class PIIScanner:
    def __init__(self, types: Iterable[str] | None = None):
        wanted = set(types) if types else set(TYPES)
        unknown = wanted - set(TYPES)
        if unknown:
            raise ValueError(f"unknown PII type(s): {', '.join(sorted(unknown))} (known: {', '.join(TYPES)})")
        self.detectors = [d for d in _DETECTORS if d[0] in wanted]

    def scan(self, text: str) -> list[PIIMatch]:
        if not text:
            return []
        found: list[PIIMatch] = []
        taken: list[tuple[int, int]] = []
        for ptype, rx, check in self.detectors:
            for m in rx.finditer(text):
                s, e = m.span()
                if any(s < te and ts < e for ts, te in taken):
                    continue
                if check is not None and not check(m):
                    continue
                found.append(PIIMatch(ptype, s, e, m.group(0)))
                taken.append((s, e))
        found.sort(key=lambda x: x.start)
        return found

    def _replace(self, text: str, fn) -> tuple[str, list[PIIMatch]]:
        matches = self.scan(text)
        if not matches:
            return text, []
        out, pos = [], 0
        for m in matches:
            out.append(text[pos:m.start])
            out.append(fn(m))
            pos = m.end
        out.append(text[pos:])
        return "".join(out), matches

    def redact(self, text: str) -> str:
        return self._replace(text, lambda m: f"[REDACTED:{m.type}]")[0]

    def tokenize(self, text: str, key: bytes) -> str:
        return self._replace(text, lambda m: token(m.type, m.value, key))[0]


def token(ptype: str, value: str, key: bytes) -> str:
    digest = hmac.new(key, f"{ptype}:{normalize(ptype, value)}".encode(), hashlib.sha256).hexdigest()
    return f"tok_{ptype}_{digest[:16]}"


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

def _walk_strings(obj: Any, fn):
    """Apply fn to every string in a JSON-like structure (returns the new structure)."""
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, dict):
        return {k: _walk_strings(v, fn) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk_strings(v, fn) for v in obj]
    return obj


# Event parts that never hold personal data (identifiers, hashes, schema metadata)
_SKIP_KEYS = ("event_id", "timestamp", "timestamp_original", "evidence", "metadata", "event_kind",
              "severity", "severity_label", "raw_format", "category", "action", "correlation_id",
              "related_events", "geo")


def event_types(scanner: PIIScanner, event: dict) -> set[str]:
    """PII types present anywhere in an event's text."""
    types: set[str] = set()

    def visit(s: str) -> str:
        types.update(m.type for m in scanner.scan(s))
        return s
    for k, v in event.items():
        if k not in _SKIP_KEYS:
            _walk_strings(v, visit)
    return types


def transform_event(event: dict, scanner: PIIScanner, mode: str, key: bytes | None = None) -> set[str]:
    """Detect (tag), redact or tokenise personal data in an event in place. Returns the types found."""
    found: set[str] = set()
    if mode == "detect":
        found = event_types(scanner, event)
    else:
        def fix(s: str) -> str:
            new, matches = scanner._replace(
                s, (lambda m: f"[REDACTED:{m.type}]") if mode == "redact" else (lambda m: token(m.type, m.value, key)))
            found.update(m.type for m in matches)
            return new
        for k in list(event):
            if k not in _SKIP_KEYS:
                event[k] = _walk_strings(event[k], fix)
    if found:
        tags = list(event.get("tags") or [])
        for t in sorted(found):
            tag = f"pii:{t}"
            if tag not in tags:
                tags.append(tag)
        event["tags"] = tags
    return found
