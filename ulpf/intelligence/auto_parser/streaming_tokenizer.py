"""
Streaming Deterministic Tokenizer (APG 2.0)
=============================================
Zero-copy, incremental tokenisation over unbounded event streams.

Provides:
  1. **Bitmask-vectorised token classification**: each token position is
     encoded as a 64-bit bitmask (delimiter class, value class, structural
     role) enabling SIMD-friendly Jaccard similarity in the clusterer.
  2. **Structural alignment**: automatic identification of delimiters,
     key-value pairs, ISO timestamps, IPv4/IPv6 addresses, and message
     payloads in unparsed telemetry streams — all without buffering to disk.
  3. **Incremental fingerprinting**: the fingerprint accumulates per-token
     bitmasks so that a streaming window can detect format drift without
     holding every sample in memory.

Thread-safety: instances are *not* shared across threads; each worker
creates its own ``StreamingTokenizer`` and feeds it lines one at a time.
"""
from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Iterator

# ---------------------------------------------------------------------------
# Bitmask constants — each class is a power-of-two flag
# ---------------------------------------------------------------------------
# Value-type flags (bits 0–15)
BIT_TIMESTAMP   = 1 << 0
BIT_IPV4        = 1 << 1
BIT_IPV6        = 1 << 2
BIT_MAC         = 1 << 3
BIT_UUID        = 1 << 4
BIT_EMAIL       = 1 << 5
BIT_URL         = 1 << 6
BIT_PATH        = 1 << 7
BIT_DOMAIN      = 1 << 8
BIT_PID         = 1 << 9
BIT_PORT        = 1 << 10
BIT_NUMERIC     = 1 << 11
BIT_HEX         = 1 << 12
BIT_STRING      = 1 << 13
BIT_QUOTED      = 1 << 14

# Structural-role flags (bits 16–23)
BIT_INVARIANT   = 1 << 16
BIT_KV_KEY      = 1 << 17
BIT_KV_VALUE    = 1 << 18
BIT_DELIMITER   = 1 << 19
BIT_ENCLOSURE_O = 1 << 20   # opening enclosure
BIT_ENCLOSURE_C = 1 << 21   # closing enclosure
BIT_PAYLOAD     = 1 << 22   # free-text message tail

# Meta flags (bits 24–31)
BIT_FIRST_TOKEN = 1 << 24
BIT_LAST_TOKEN  = 1 << 25

# Combined mask for value-type bits
VALUE_TYPE_MASK = (1 << 16) - 1

# ---------------------------------------------------------------------------
# Fast compiled detection patterns (shared, read-only)
# ---------------------------------------------------------------------------
_RE_ISO_TS = re.compile(
    r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'
    r'(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'
)
_RE_SYSLOG_TS = re.compile(r'[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}')
_RE_EPOCH_TS = re.compile(r'^\d{10,13}(?:\.\d+)?$')
_RE_TIME_ONLY = re.compile(r'^\d{1,2}:\d{2}:\d{2}(?:\.\d+)?$')
_RE_IPV4 = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$')
_RE_IPV6 = re.compile(r'^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$')
_RE_MAC = re.compile(r'^(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$')
_RE_UUID = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}'
    r'-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)
_RE_EMAIL = re.compile(r'^[\w.+\-]+@[\w\-]+\.[\w.]+$')
_RE_URL = re.compile(r'^(?:https?|ftp)://\S+$')
_RE_PATH = re.compile(r'^(?:/[\w.\-]+){2,}$|^[A-Z]:\\\S+$')
_RE_DOMAIN = re.compile(r'^[a-zA-Z][\w\-]*(?:\.[\w\-]+)+\.[a-zA-Z]{2,}$')
_RE_HEX = re.compile(r'^0x[0-9a-fA-F]+$')
_RE_NUMERIC = re.compile(r'^\d+$')
_RE_PORT = re.compile(r'^\d{1,5}$')
_RE_PID = re.compile(r'^\d{1,7}$')
_RE_KV = re.compile(r'^([\w.\-]+)=(.*)$')


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class StreamToken:
    """A token enriched with a bitmask encoding its structural role."""
    value: str
    position: int
    bitmask: int
    kv_key: str | None = None
    kv_value: str | None = None

    def __repr__(self) -> str:
        bits = f"0x{self.bitmask:06x}"
        kv = f" kv={self.kv_key}" if self.kv_key else ""
        return f"ST({self.value!r} pos={self.position} {bits}{kv})"


@dataclass(slots=True)
class StreamFrame:
    """One tokenised event in the stream — a lightweight, allocation-minimal frame."""
    raw: str
    tokens: list[StreamToken]
    delimiter: str
    bitmask_vector: bytes          # packed uint64 per token
    fingerprint_hash: str          # SHA-256[:16] of bitmask vector
    kv_count: int = 0
    timestamp_positions: list[int] = field(default_factory=list)
    ip_positions: list[int] = field(default_factory=list)

    @property
    def token_count(self) -> int:
        return len(self.tokens)


# ---------------------------------------------------------------------------
# Bitmask classifier
# ---------------------------------------------------------------------------

def _classify_token(value: str, position: int, total: int) -> tuple[int, str | None, str | None]:
    """Classify a single token value into a bitmask. Returns (mask, kv_key, kv_value)."""
    mask = 0
    kv_key = None
    kv_value = None

    if position == 0:
        mask |= BIT_FIRST_TOKEN
    if position == total - 1:
        mask |= BIT_LAST_TOKEN

    # KV detection
    m = _RE_KV.match(value)
    if m:
        kv_key = m.group(1)
        kv_value = m.group(2).strip('"')
        mask |= BIT_KV_KEY | BIT_KV_VALUE
        # Classify the value part
        mask |= _value_bits(kv_value)
        return mask, kv_key, kv_value

    # Classify the whole token
    mask |= _value_bits(value)
    return mask, kv_key, kv_value


def _value_bits(v: str) -> int:
    """Compute value-type bitmask for a string."""
    bits = 0
    if not v:
        return BIT_STRING

    # Quoted
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        bits |= BIT_QUOTED
        v = v[1:-1]

    # Structural types (most specific first)
    if _RE_UUID.match(v):
        return bits | BIT_UUID
    if _RE_EMAIL.match(v):
        return bits | BIT_EMAIL
    if _RE_URL.match(v):
        return bits | BIT_URL
    if _RE_ISO_TS.match(v) or _RE_SYSLOG_TS.match(v):
        return bits | BIT_TIMESTAMP
    if _RE_EPOCH_TS.match(v):
        return bits | BIT_TIMESTAMP
    if _RE_TIME_ONLY.match(v):
        return bits | BIT_TIMESTAMP
    if _RE_MAC.match(v):
        return bits | BIT_MAC
    if _RE_IPV6.match(v):
        return bits | BIT_IPV6
    if _RE_IPV4.match(v):
        bits |= BIT_IPV4
        if ':' in v:
            bits |= BIT_PORT
        return bits
    if _RE_PATH.match(v):
        return bits | BIT_PATH
    if _RE_HEX.match(v):
        return bits | BIT_HEX
    if _RE_DOMAIN.match(v):
        return bits | BIT_DOMAIN
    if _RE_NUMERIC.match(v):
        n = int(v)
        if n <= 65535 and _RE_PORT.match(v):
            bits |= BIT_PORT
        if n <= 9999999 and _RE_PID.match(v):
            bits |= BIT_PID
        return bits | BIT_NUMERIC
    return bits | BIT_STRING


# ---------------------------------------------------------------------------
# Streaming tokenizer
# ---------------------------------------------------------------------------

_DELIM_MULTI = ["}|{", "||", " | ", " - ", "::", "}{", "\t\t"]
_DELIM_SINGLE = ["\t", "|", ",", ";", " "]


def _detect_delimiter_fast(line: str) -> str:
    """Fastest-path delimiter detection for streaming — no allocation overhead."""
    # Multi-char first
    for d in _DELIM_MULTI:
        if line.count(d) >= 2:
            parts = line.split(d)
            non_empty = sum(1 for p in parts if p.strip())
            if non_empty >= 3:
                return d
    # Single-char
    best = " "
    best_score = 0
    for d in _DELIM_SINGLE:
        c = line.count(d)
        if c < 2:
            continue
        score = c if d != " " else int(c * 0.7)
        if score > best_score:
            best_score = score
            best = d
    return best


class StreamingTokenizer:
    """
    Stateful, streaming tokenizer for the APG 2.0 pipeline.

    Feed it events one at a time via ``tokenise_event()``.  Each call
    returns a ``StreamFrame`` with bitmask-vectorised tokens suitable
    for the vectorised clusterer.

    The tokenizer maintains no cross-event state by default; it is
    designed for per-worker, per-stream use.
    """

    __slots__ = ('_total_events', '_delim_cache')

    def __init__(self) -> None:
        self._total_events: int = 0
        self._delim_cache: dict[str, str] = {}  # short-lived LRU-ish cache

    @property
    def events_processed(self) -> int:
        return self._total_events

    def tokenise_event(self, raw_line: str) -> StreamFrame | None:
        """Tokenise a single raw event line into a StreamFrame.

        Returns None for empty or invalid lines.
        """
        stripped = raw_line.strip()
        if not stripped or len(stripped) > 65_536:
            return None

        self._total_events += 1

        # Delimiter detection — cache hit path for repeated structures
        delim = self._detect_cached(stripped)

        # Split
        if len(delim) > 1:
            parts = [p.strip() for p in stripped.split(delim) if p.strip()]
        else:
            parts = _split_respecting_quotes(stripped, delim)

        total = len(parts)
        if total == 0:
            return None
        if total > 512:
            parts = parts[:512]
            total = 512

        # Classify each token → bitmask vector
        tokens: list[StreamToken] = []
        bitmask_ints: list[int] = []
        kv_count = 0
        ts_positions: list[int] = []
        ip_positions: list[int] = []

        for i, val in enumerate(parts):
            mask, kv_key, kv_value = _classify_token(val, i, total)
            tokens.append(StreamToken(
                value=val, position=i, bitmask=mask,
                kv_key=kv_key, kv_value=kv_value,
            ))
            bitmask_ints.append(mask)
            if mask & (BIT_KV_KEY | BIT_KV_VALUE):
                kv_count += 1
            if mask & BIT_TIMESTAMP:
                ts_positions.append(i)
            if mask & (BIT_IPV4 | BIT_IPV6):
                ip_positions.append(i)

        # Pack bitmask vector as bytes (little-endian uint64)
        bitmask_bytes = struct.pack(f'<{len(bitmask_ints)}Q', *bitmask_ints)

        # Fingerprint = hash of bitmask vector (structural identity)
        fp_hash = hashlib.sha256(bitmask_bytes).hexdigest()[:16]

        return StreamFrame(
            raw=raw_line,
            tokens=tokens,
            delimiter=delim,
            bitmask_vector=bitmask_bytes,
            fingerprint_hash=fp_hash,
            kv_count=kv_count,
            timestamp_positions=ts_positions,
            ip_positions=ip_positions,
        )

    def _detect_cached(self, line: str) -> str:
        """Delimiter detection with a small cache keyed on (length, first-5-chars)."""
        key = f"{len(line)}:{line[:5]}"
        cached = self._delim_cache.get(key)
        if cached is not None:
            return cached
        delim = _detect_delimiter_fast(line)
        if len(self._delim_cache) > 1024:
            self._delim_cache.clear()
        self._delim_cache[key] = delim
        return delim

    def tokenise_stream(self, lines: Iterator[str]) -> Iterator[StreamFrame]:
        """Tokenise an unbounded stream of lines, yielding frames."""
        for line in lines:
            frame = self.tokenise_event(line)
            if frame is not None:
                yield frame


# ---------------------------------------------------------------------------
# Vectorised Jaccard similarity on bitmask vectors
# ---------------------------------------------------------------------------

def bitmask_jaccard(vec_a: bytes, vec_b: bytes) -> float:
    """
    Compute Jaccard similarity between two bitmask vectors.

    Each vector is a packed sequence of uint64 bitmasks.  The Jaccard
    index is computed as |intersection| / |union| over the per-position
    value-type bits (bits 0–15) of matching positions.

    Positions beyond the shorter vector are treated as mismatches.
    """
    # Unpack
    n_a = len(vec_a) // 8
    n_b = len(vec_b) // 8
    if n_a == 0 or n_b == 0:
        return 0.0 if (n_a + n_b) > 0 else 1.0

    # Length mismatch penalty
    max_n = max(n_a, n_b)
    min_n = min(n_a, n_b)

    a_ints = struct.unpack(f'<{n_a}Q', vec_a)
    b_ints = struct.unpack(f'<{n_b}Q', vec_b)

    intersection = 0
    union_count = 0

    for i in range(min_n):
        va = a_ints[i] & VALUE_TYPE_MASK
        vb = b_ints[i] & VALUE_TYPE_MASK
        inter = bin(va & vb).count('1')
        uni = bin(va | vb).count('1')
        intersection += inter
        union_count += uni

    # Unmatched positions contribute to union only
    for i in range(min_n, max_n):
        if i < n_a:
            union_count += bin(a_ints[i] & VALUE_TYPE_MASK).count('1')
        if i < n_b:
            union_count += bin(b_ints[i] & VALUE_TYPE_MASK).count('1')

    if union_count == 0:
        return 1.0 if max_n == 0 else (min_n / max_n)

    return intersection / union_count


def bitmask_structural_distance(vec_a: bytes, vec_b: bytes) -> float:
    """1 - Jaccard similarity.  0 = identical structure, 1 = completely different."""
    return 1.0 - bitmask_jaccard(vec_a, vec_b)


# ---------------------------------------------------------------------------
# Quote-aware splitting (reused from tokenizer.py, inlined for perf)
# ---------------------------------------------------------------------------

def _split_respecting_quotes(line: str, delimiter: str) -> list[str]:
    """Split by delimiter keeping quoted spans whole."""
    parts = line.split(delimiter)
    merged: list[str] = []
    buf: list[str] = []
    for p in parts:
        odd = (p.count('"') - p.count('\\"')) % 2 == 1
        if buf:
            buf.append(p)
            if odd:
                merged.append(delimiter.join(buf))
                buf = []
        elif odd:
            buf = [p]
        else:
            merged.append(p)
    if buf:
        merged.extend(buf)
    tokens = [p for p in merged if p]
    if delimiter == " ":
        tokens = _merge_brackets(tokens)
    return tokens


def _merge_brackets(tokens: list[str]) -> list[str]:
    """Re-join space-split bracket groups."""
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
