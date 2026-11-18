"""
Format Auto-Detection Engine
==============================
Detects the format of raw log lines using signature patterns and heuristics.
Returns the detected format name and a confidence score.

v7: Constant-time prefix jump table for known formats.  Regex/heuristic
    fallback is isolated to truly unknown lines only.
"""
from __future__ import annotations

import json
import re

try:
    from orjson import loads as _orjson_loads

    def _json_loads(s: str):
        try:
            return _orjson_loads(s)
        except ValueError:
            # orjson rejects >64-bit integers; defer to stdlib before giving up
            return json.loads(s)
except ImportError:  # pragma: no cover
    _json_loads = json.loads

_CLF_PATTERN = re.compile(r"^\S+\s+\S+\s+\S+\s+\[\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}")
_IPV4_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HTTP_METHODS = frozenset(("GET", "POST", "CONNECT", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE"))


def _make_result(fmt: str, confidence: float, sub: str | None = None) -> dict:
    return {"format_name": fmt, "confidence": confidence, "sub_format": sub}


# ---------------------------------------------------------------------------
# Fallback regex patterns — only evaluated for lines that fail prefix checks
# ---------------------------------------------------------------------------
_FALLBACK_PATTERNS: list[tuple[str, re.Pattern, float, str | None]] = [
    ("cef",    re.compile(r"CEF:\d+\|", re.I), 0.98, None),
    ("leef",   re.compile(r"LEEF:\d+\.\d+\|", re.I), 0.98, None),
    ("syslog", re.compile(r"^<\d{1,3}>\d{1,2}\s+\d{4}-\d{2}-\d{2}T"), 0.95, "rfc5424"),
    ("syslog", re.compile(r"^<\d{1,3}>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+"), 0.92, "rfc3164"),
    ("syslog", re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+"), 0.80, "rfc3164"),
    ("w3c",    re.compile(r"^#(Fields|Version|Date|Software|Start-Date):"), 0.97, None),
    ("w3c",    re.compile(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+\s+\S+\s+\d+\s+"), 0.75, None),
]

# Pre-compiled ReDoS-safe KV pattern
_KV_PATTERN = re.compile(r'[\w.]+=[^\s]+')
# XML tag detector (used only in fallback)
_XML_TAG_PATTERN = re.compile(r"<\w+[\s>]")
_CEF_PATTERN = re.compile(r"(?:^|[\s|])CEF:\d+\|", re.I)
_LEEF_PATTERN = re.compile(r"(?:^|[\s|])LEEF:\d+", re.I)


# ---------------------------------------------------------------------------
# Primary: O(1) prefix jump table
# ---------------------------------------------------------------------------

def detect_format(raw_line: str) -> dict:
    """
    Auto-detect the format of a raw log line.

    Uses constant-time byte-prefix checks for known formats before
    falling back to regex/heuristic analysis for unknown lines.

    Returns dict with keys: format_name, confidence, sub_format.
    """
    stripped = raw_line.strip()
    if not stripped:
        return _make_result("unknown", 0.0)

    first = stripped[0]

    # ── CEF branch (starts with CEF or syslog-prefixed CEF) ─────────
    if "CEF:" in stripped or "cef:" in stripped:
        if stripped[:4] == 'CEF:' or _CEF_PATTERN.search(stripped):
            return _make_result("cef", 0.98)

    # ── LEEF branch (starts with LEEF or syslog-prefixed LEEF) ───────
    if "LEEF:" in stripped or "leef:" in stripped:
        if stripped[:5] == 'LEEF:' or _LEEF_PATTERN.search(stripped):
            return _make_result("leef", 0.98)

    # ── Syslog / XML branch (starts with '<') ──────────────────────
    if first == '<':
        # <digits> → syslog priority header
        if len(stripped) > 1 and stripped[1:2].isdigit():
            # Distinguish RFC 5424 vs 3164 by looking past the PRI
            close = stripped.find('>', 1)
            if close > 0 and close < 6:
                after_pri = stripped[close + 1:]
                # RFC 5424: <PRI>VERSION TIMESTAMP  (version is a digit)
                if after_pri and after_pri[0:1].isdigit():
                    return _make_result("syslog", 0.95, "rfc5424")
                # RFC 3164: <PRI>MONTH DAY …
                return _make_result("syslog", 0.92, "rfc3164")
            return _make_result("syslog", 0.90, None)

        # <Event … → XML event element
        if stripped.startswith("<Event"):
            return _make_result("xml", 0.92)

        # <?xml … → XML declaration
        if stripped.startswith("<?xml"):
            return _make_result("xml", 0.93)

        # Generic XML: starts with '<', contains '</' or ends with '>', not a comment
        if stripped.startswith("<") and not stripped.startswith("<!"):
            if "</" in stripped or (stripped.endswith(">") and _XML_TAG_PATTERN.search(stripped)):
                return _make_result("xml", 0.90)

    # ── JSON branch ─────────────────────────────────────────────────
    if first == '{' and stripped[-1] == '}':
        try:
            _json_loads(stripped)
            return _make_result("json", 0.97)
        except ValueError:
            pass

    if first == '[' and stripped[-1] == ']':
        try:
            data = _json_loads(stripped)
            if isinstance(data, list) and data:
                return _make_result("json", 0.95, "array")
        except ValueError:
            pass



    # ── W3C branch ──────────────────────────────────────────────────
    if stripped[:8] == '#Fields:':
        return _make_result("w3c", 0.97)

    # ── CLF / Combined Log Format (Apache / Nginx / Web access) ────
    if " [" in stripped and '] "' in stripped:
        if _CLF_PATTERN.search(stripped):
            return _make_result("w3c", 0.90, "clf")

    # ── W3C data lines: "YYYY-MM-DD HH:MM:SS IP METHOD ..." ────────
    if (len(stripped) > 19
            and stripped[4:5] == '-' and stripped[7:8] == '-'
            and stripped[10:11] == ' ' and stripped[13:14] == ':'
            and stripped[16:17] == ':'):
        parts = stripped.split()
        if len(parts) >= 6:
            tok1, tok2 = parts[2], parts[3]
            if not tok1.startswith("[") and not tok2.startswith("[") and not tok1.startswith("<"):
                if _IPV4_PATTERN.match(tok1) or tok1.upper() in _HTTP_METHODS or tok2.upper() in _HTTP_METHODS:
                    return _make_result("w3c", 0.75)

    # ── KV fast path: "key=value key=value ..." ─────────────────────
    if '=' in stripped:
        eq_count = stripped.count('=')
        if eq_count >= 3:
            # Include tab count in denominator to catch tab-delimited KV logs
            # from hardware switches (e.g. FortiGate, Cisco ASA output logs)
            sp_count = stripped.count(' ') + stripped.count('\t')
            if sp_count >= 2 and eq_count / max(sp_count + 1, 1) > 0.4:
                return _make_result("kv", 0.85)

    # ── CSV fast path: 4+ commas, no syslog-like structure ──────────
    if ',' in stripped:
        comma_count = stripped.count(',')
        if comma_count >= 3:
            # Not KV (few '=') and not a sentence (even field distribution)
            if stripped.count('=') < 2:
                return _make_result("csv", 0.70)

    # ── Fast path did not match → run full fallback ─────────────────
    return _detect_fallback(stripped)


# ---------------------------------------------------------------------------
# Fallback: regex + heuristic analysis (only for truly unknown lines)
# ---------------------------------------------------------------------------

def _detect_fallback(stripped: str) -> dict:
    """
    Full regex and heuristic detection — only invoked when the O(1)
    prefix jump table returns no match.
    """
    # Phase 1: Regex signatures
    for fmt_name, pattern, conf, sub in _FALLBACK_PATTERNS:
        if pattern.search(stripped):
            return _make_result(fmt_name, conf, sub)

    # Phase 2: Key-Value heuristic (ReDoS-guarded)
    # Quick gate: only engage regex if there are enough '=' signs
    if stripped.count('=') >= 3:
        kv_matches = _KV_PATTERN.findall(stripped)
        if len(kv_matches) >= 3:
            kv_ratio = len(" ".join(kv_matches)) / max(len(stripped), 1)
            if kv_ratio > 0.4:
                return _make_result("kv", 0.85)

    # Phase 3: CSV
    if "," in stripped:
        parts = stripped.split(",")
        if len(parts) >= 4:
            non_empty = sum(1 for p in parts if p.strip())
            if non_empty / len(parts) > 0.6:
                return _make_result("csv", 0.70)

    # Phase 4: TSV
    if "\t" in stripped:
        parts = stripped.split("\t")
        if len(parts) >= 4:
            return _make_result("csv", 0.65, "tsv")

    # Fallback
    return _make_result("unknown", 0.30)


# ---------------------------------------------------------------------------
# Bulk detection (unchanged API, benefits from faster per-line dispatch)
# ---------------------------------------------------------------------------

def detect_format_bulk(lines: list[str]) -> dict:
    """Detect format for a batch of lines using majority voting."""
    if not lines:
        return _make_result("unknown", 0.0)

    votes: dict[str, list[float]] = {}
    for line in lines[:100]:
        if not line.strip() or line.strip().startswith("#"):
            continue
        result = detect_format(line)
        key = f"{result['format_name']}:{result['sub_format'] or ''}"
        votes.setdefault(key, []).append(result["confidence"])

    if not votes:
        return _make_result("unknown", 0.0)

    best_key = max(votes, key=lambda k: sum(votes[k]) * len(votes[k]))
    parts = best_key.split(":", 1)
    avg_conf = sum(votes[best_key]) / len(votes[best_key])

    return _make_result(parts[0], min(avg_conf, 1.0), parts[1] if parts[1] else None)
