"""
Lakehouse rows: the flat lake schema (``sinks/lake.py``) plus the file hash and the partition
columns ``tenant_id`` / ``date`` / ``hour`` (event time, UTC). Partition columns live in the
directory names of the cold tier (Delta convention), not inside the data files.
"""
from __future__ import annotations

import re
import time

import pyarrow as pa

from ulpf.runtime.sinks.lake import LAKE_SCHEMA, lake_row

PARTITION_COLUMNS = ("tenant_id", "date", "hour")
BLOOM_COLUMNS = ("source_ip", "destination_ip", "user_name", "hash_sha256")
# Delta per-file min/max statistics (zonemaps for file pruning)
STATS_COLUMNS = ("timestamp", "severity", "journal_seq", "source_port", "destination_port")

DATA_SCHEMA = pa.schema(list(LAKE_SCHEMA) + [pa.field("hash_sha256", pa.string())])
SCHEMA = pa.schema(list(DATA_SCHEMA) + [pa.field(c, pa.string()) for c in PARTITION_COLUMNS])

TENANT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_SHA256_KEYS = ("file.hash.sha256", "hash.sha256", "sha256", "filehash_sha256", "file_sha256")


def _sha256(e: dict):
    h = ((e.get("file") or {}).get("hash") or {}).get("sha256")
    if h:
        return str(h)
    pf = e.get("parsed_fields") or {}
    for k in _SHA256_KEYS:
        v = pf.get(k)
        if v:
            return str(v)
    return None


def rows(events: list[dict], tenant_of) -> list[dict]:
    """Lakehouse rows for events; ``tenant_of(event) -> tenant id``."""
    out = []
    now = None
    for e in events:
        r = lake_row(e)
        r["hash_sha256"] = _sha256(e)
        ts = r["timestamp"]
        if ts is None:
            now = now or time.gmtime()
            r["date"], r["hour"] = time.strftime("%Y-%m-%d", now), time.strftime("%H", now)
        else:
            u = ts.utctimetuple() if ts.tzinfo else ts.timetuple()
            r["date"], r["hour"] = time.strftime("%Y-%m-%d", u), f"{u.tm_hour:02d}"
        r["tenant_id"] = tenant_of(e)
        out.append(r)
    return out


def partition_key(tenant: str, date: str, hour: str) -> str:
    return f"{tenant}/{date}/{hour}"


def partition_dir(tenant: str, date: str, hour: str) -> str:
    return f"tenant_id={tenant}/date={date}/hour={hour}"
