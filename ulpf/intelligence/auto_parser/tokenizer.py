"""
Tokenizer
============
Stage 1 of the native learning pipeline.
Handles: Unicode/encoding normalisation → length/resource validation →
         protocol/format detection → tokenisation.

v8.1: Multi-character delimiter detection, symmetrical enclosure stripping,
      and sub-field KV parsing for nested metadata blocks.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum raw line length we'll accept (anti-poisoning)
MAX_LINE_LENGTH = 65_536
MAX_TOKEN_COUNT = 512

# Single-character delimiters ranked by specificity
_DELIMITER_CANDIDATES = ["\t", "|", ",", ";", " "]

# Multi-character delimiter candidates — checked BEFORE single-char.
# Ordered by length (longest first) so longer patterns take precedence.
_MULTI_CHAR_DELIMITER_CANDIDATES = [
    "}|{",  # common in custom enterprise log formats
    "||",   # double-pipe separated formats
    " | ",  # pipe with surrounding spaces
    " - ",  # dash with spaces (some app logs)
    "::",   # double-colon separated (some LDAP/directory logs)
    "}{",   # brace-to-brace
    "\t\t", # double-tab
]

# Symmetrical enclosure pairs to strip from token values.
# Ordered by specificity — multi-char enclosures first.
_ENCLOSURE_PAIRS: list[tuple[str, str]] = [
    ("((", "))"),
    ("{{", "}}"),
    ("[[", "]]"),
    ("<<", ">>"),
    ("<", ">"),
    ("[", "]"),
    ("(", ")"),
    ("*", "*"),
    ("+", "+"),
    ("~", "~"),
]

# Compiled patterns for quote-aware splitting
_KV_PAIR = re.compile(r'([\w.\-]+)=("(?:[^"\\]|\\.)*"|[^\s,;|]+)')
_QUOTED_FIELD = re.compile(r'"(?:[^"\\]|\\.)*"')

# Sub-field KV patterns for nested metadata blocks
_SUB_KV_SEMICOLON_COLON = re.compile(r'([\w.\-]+)\s*:\s*([^;]+)')
_SUB_KV_SEMICOLON_EQUALS = re.compile(r'([\w.\-]+)\s*=\s*([^;]+)')


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class Token:
    """A single token from a log line."""
    value: str
    position: int
    start_offset: int = 0
    end_offset: int = 0
    is_kv_key: bool = False
    is_kv_value: bool = False
    kv_key: str | None = None
    # v8.1: Track enclosure-stripped value and sub-field KV pairs
    stripped_value: str | None = None   # value after enclosure stripping
    enclosure: str | None = None        # the enclosure chars detected
    sub_kv_pairs: dict[str, str] | None = None  # nested key:value pairs

    def __repr__(self) -> str:
        tag = f" kv={self.kv_key}" if self.kv_key else ""
        enc = f" enc={self.enclosure}" if self.enclosure else ""
        return f"Token({self.value!r}, pos={self.position}{tag}{enc})"


@dataclass
class TokenisedLine:
    """Result of tokenising a single log line."""
    raw: str
    normalised: str
    tokens: list[Token] = field(default_factory=list)
    delimiter: str = " "
    has_kv_pairs: bool = False
    kv_pairs: dict[str, str] = field(default_factory=dict)
    format_hint: str = ""       # e.g. "syslog", "kv", "csv", "json"
    valid: bool = True
    rejection_reason: str = ""

    @property
    def token_count(self) -> int:
        return len(self.tokens)

    def token_values(self) -> list[str]:
        return [t.value for t in self.tokens]

    def __repr__(self) -> str:
        return f"TokenisedLine({self.token_count} tokens, delim={self.delimiter!r})"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def tokenise(raw_line: str, max_length: int = MAX_LINE_LENGTH,
             max_tokens: int = MAX_TOKEN_COUNT) -> TokenisedLine:
    """
    Full tokenisation pipeline for a single raw log line.

    Steps:
        1. Unicode / encoding normalisation
        2. Length / resource validation
        3. Key-value pair extraction
        4. Delimiter detection (multi-char then single-char)
        5. Token splitting
        6. Enclosure stripping
        7. Sub-field KV parsing
    """
    result = TokenisedLine(raw=raw_line, normalised="")

    # ------ Step 1: Normalise ------
    text = _normalise_unicode(raw_line)
    result.normalised = text

    # ------ Step 2: Validate ------
    if not text or not text.strip():
        result.valid = False
        result.rejection_reason = "empty"
        return result

    stripped = text.strip()

    if len(stripped) > max_length:
        result.valid = False
        result.rejection_reason = f"exceeds_max_length:{len(stripped)}"
        return result

    # ------ Step 3: Key-value extraction ------
    kv_matches = _KV_PAIR.findall(stripped)
    if len(kv_matches) >= 3:
        result.has_kv_pairs = True
        result.kv_pairs = {k: v.strip('"') for k, v in kv_matches}
        result.format_hint = "kv"

    # ------ Step 4: Format hint detection ------
    if not result.format_hint:
        result.format_hint = _detect_format_hint(stripped)

    # ------ Step 5: Delimiter detection + tokenisation ------
    # Try multi-character delimiters first (higher structural signal)
    delim = _detect_multi_char_delimiter(stripped)
    if delim is None:
        delim = _detect_delimiter(stripped)
    result.delimiter = delim

    # Split by detected delimiter
    if len(delim) > 1:
        # Multi-char delimiter: simple split (no quote merging needed)
        tokens = [part.strip() for part in stripped.split(delim) if part.strip()]
    else:
        tokens = _split_respecting_quotes(stripped, delim)

    if len(tokens) > max_tokens:
        result.valid = False
        result.rejection_reason = f"exceeds_max_tokens:{len(tokens)}"
        return result

    # Build Token objects
    offset = 0
    for i, val in enumerate(tokens):
        start = stripped.find(val, offset)
        if start == -1:
            start = offset
        end = start + len(val)
        offset = end

        tok = Token(value=val, position=i, start_offset=start, end_offset=end)

        # ------ Step 6: Enclosure stripping ------
        stripped_val, enclosure = _strip_enclosure(val)
        if enclosure:
            tok.stripped_value = stripped_val
            tok.enclosure = enclosure

        # ------ Step 7: Sub-field KV parsing ------
        # Detect nested key:value or key=value pairs separated by ';'
        effective_val = stripped_val if enclosure else val
        if ";" in effective_val and (":" in effective_val or "=" in effective_val):
            sub_kvs = _parse_sub_kv(effective_val)
            if sub_kvs and len(sub_kvs) >= 2:
                tok.sub_kv_pairs = sub_kvs
                # Merge sub-KV pairs into the line-level KV tracking
                result.has_kv_pairs = True
                for sk, sv in sub_kvs.items():
                    result.kv_pairs[sk] = sv

        # Tag KV tokens
        if result.has_kv_pairs and "=" in val:
            eq = val.find("=")
            key = val[:eq]
            if key in result.kv_pairs:
                tok.is_kv_key = True
                tok.is_kv_value = True
                tok.kv_key = key

        result.tokens.append(tok)

    return result


def tokenise_batch(lines: list[str], **kwargs: Any) -> list[TokenisedLine]:
    """Tokenise multiple lines."""
    return [tokenise(line, **kwargs) for line in lines]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise_unicode(text: str) -> str:
    """NFC-normalise and strip control characters (except whitespace)."""
    text = unicodedata.normalize("NFC", text)
    # Remove control chars except tab, newline, carriage return
    return "".join(
        ch for ch in text
        if ch in ("\t", "\n", "\r") or not unicodedata.category(ch).startswith("C")
    )


def _detect_format_hint(line: str) -> str:
    """Quick structural sniff (not full detection — that's the detector's job)."""
    if line.startswith("{") and line.endswith("}"):
        return "json"
    if line.startswith("<?xml") or (line.startswith("<") and ">" in line):
        return "xml"
    if re.match(r"^<\d{1,3}>", line):
        return "syslog"
    if "CEF:" in line[:50]:
        return "cef"
    if "LEEF:" in line[:50]:
        return "leef"
    return ""


def _detect_multi_char_delimiter(line: str) -> str | None:
    """Detect multi-character delimiters by frequency analysis.

    A multi-char sequence is accepted as a delimiter when it appears
    >= 2 times consistently in the line, producing >= 3 non-empty segments.
    Returns the best multi-char delimiter or None if none qualifies.
    """
    best: str | None = None
    best_score: float = 0.0

    for candidate in _MULTI_CHAR_DELIMITER_CANDIDATES:
        count = line.count(candidate)
        if count < 2:
            continue

        # Split and check that we get meaningful segments
        parts = [p.strip() for p in line.split(candidate)]
        non_empty = [p for p in parts if p]

        if len(non_empty) < 3:
            continue

        # Score: occurrences * specificity bonus for longer delimiters.
        # Longer delimiters are more reliable (less likely to be coincidence).
        specificity_bonus = len(candidate) * 2.0
        score = count * specificity_bonus

        # Penalise if segments are very uneven in length (likely wrong split)
        seg_lens = [len(p) for p in non_empty]
        if seg_lens:
            avg_len = sum(seg_lens) / len(seg_lens)
            if avg_len > 0:
                # Coefficient of variation — lower is more uniform
                cv = (sum((l - avg_len) ** 2 for l in seg_lens) / len(seg_lens)) ** 0.5 / avg_len
                if cv < 2.0:  # reasonable uniformity
                    score *= (1.0 + 1.0 / (1.0 + cv))  # bonus for uniform segments

        if score > best_score:
            best_score = score
            best = candidate

    return best


def _detect_delimiter(line: str) -> str:
    """Detect the most likely single-character delimiter from a single line."""
    best = " "
    best_score = 0

    for delim in _DELIMITER_CANDIDATES:
        parts = line.split(delim)
        count = len(parts)
        if count < 3:
            continue

        # Penalise space if a structured delimiter is competitive
        score = count
        if delim == " ":
            score = count * 0.7  # bias toward structured delimiters

        if score > best_score:
            best_score = score
            best = delim

    return best


def _strip_enclosure(value: str) -> tuple[str, str | None]:
    """Strip symmetrical enclosure characters from a token value.

    Detects patterns like *INFO*, [timestamp], <component>, ((message)), +metadata+
    and returns the inner value plus the enclosure string.

    Returns:
        (stripped_value, enclosure_chars) or (original_value, None) if no match.
    """
    v = value.strip()
    if len(v) < 2:
        return value, None

    for opener, closer in _ENCLOSURE_PAIRS:
        if v.startswith(opener) and v.endswith(closer):
            inner = v[len(opener):-len(closer)].strip()
            if inner:  # don't strip to empty
                return inner, f"{opener}...{closer}"

    return value, None


def _parse_sub_kv(value: str) -> dict[str, str]:
    """Parse nested key:value or key=value pairs separated by ';'.

    Handles formats like:
        ps_id:26156;env:prod;status:active
        key1=val1;key2=val2;key3=val3
    """
    result: dict[str, str] = {}

    # Try semicolon + colon first (e.g. ps_id:26156;env:prod)
    parts = [p.strip() for p in value.split(";") if p.strip()]
    if len(parts) >= 2:
        for part in parts:
            # Try colon separator
            colon_idx = part.find(":")
            equals_idx = part.find("=")

            if colon_idx > 0 and (equals_idx < 0 or colon_idx < equals_idx):
                key = part[:colon_idx].strip()
                val = part[colon_idx + 1:].strip()
                if key and val:
                    result[key] = val
            elif equals_idx > 0:
                key = part[:equals_idx].strip()
                val = part[equals_idx + 1:].strip()
                if key and val:
                    result[key] = val

    return result


def _odd_quotes(part: str) -> bool:
    """True if ``part`` opens or closes a double-quoted span."""
    return (part.count('"') - part.count('\\"')) % 2 == 1


def _split_respecting_quotes(line: str, delimiter: str) -> list[str]:
    """Split by delimiter, keeping double-quoted spans (msg="a b", "x,y") whole.

    Quote characters stay in the token text: literals rebuilt from tokens must
    match the raw line. Quotes are removed only when values are classified
    and extracted.
    """
    parts = line.split(delimiter)
    merged: list[str] = []
    buf: list[str] = []
    for p in parts:
        if buf:
            buf.append(p)
            if _odd_quotes(p):
                merged.append(delimiter.join(buf))
                buf = []
        elif _odd_quotes(p):
            buf = [p]
        else:
            merged.append(p)
    if buf:
        merged.extend(buf)  # unterminated quote: no span to keep together

    tokens = [p for p in merged if p]  # filter empties
    if delimiter == " ":
        tokens = _merge_brackets(tokens)
    return tokens


def _merge_brackets(tokens: list[str]) -> list[str]:
    """Re-join space-split bracket groups: ["[2024-01-01", "10:00:00]"] -> ["[2024-01-01 10:00:00]"]."""
    out: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("[") and "]" not in tok:
            j = i + 1
            while j < len(tokens) and "]" not in tokens[j] and j - i < 8:
                j += 1
            if j < len(tokens) and tokens[j].endswith("]"):
                out.append(" ".join(tokens[i:j + 1]))
                i = j + 1
                continue
        out.append(tok)
        i += 1
    return out
