"""Stable node identity and deterministic event IDs."""
from __future__ import annotations

import hashlib
import os
import uuid


def node_id(data_dir: str, configured: str | None = None) -> str:
    """A stable identifier for this ULPF node, created once per data directory."""
    if configured and configured != "auto":
        return configured
    path = os.path.join(data_dir, "node_id")
    try:
        with open(path, "r", encoding="utf-8") as f:
            value = f.read().strip()
            if value:
                return value
    except OSError:
        pass
    value = f"node-{uuid.uuid4().hex[:12]}"
    os.makedirs(data_dir, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(value)
    os.replace(tmp, path)
    return value


def event_id(node: str, seq: int | str, ordinal: int = 0) -> str:
    """Deterministic UUID (version 8) for journal record ``seq`` on ``node``.

    Replaying a record after a crash yields the same ID, which keeps
    idempotent sinks (Elasticsearch ``_id``, the DuckDB store) duplicate-free.
    ``ordinal`` distinguishes several events derived from one record.
    """
    # First 16 bytes of SHA-256, version nibble 8, RFC 4122 variant; formatted
    # directly (uuid.UUID() costs ~10 us per event on the hot path)
    hx = _sha256(f"{node}:{seq}:{ordinal}".encode()).hexdigest()
    return (f"{hx[:8]}-{hx[8:12]}-8{hx[13:16]}-"
            f"{_VARIANT[int(hx[16], 16) & 3]}{hx[17:20]}-{hx[20:32]}")


_sha256 = hashlib.sha256
_VARIANT = "89ab"
