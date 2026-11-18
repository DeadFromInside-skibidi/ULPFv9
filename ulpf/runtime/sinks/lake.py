"""
Data-lake encoding: a flat, typed Arrow schema for Parquet outputs (local and S3).

Flat columns make the lake directly usable by Spark, DuckDB, pandas and ML
tooling (requirement h); the full event is kept in ``event_json`` so nothing
is lost. ``dt`` (UTC date of the event) and ``source``/``category`` are the
usual partition keys.
"""
from __future__ import annotations

import io

import orjson
import pyarrow as pa

LAKE_SCHEMA = pa.schema([
    ("event_id", pa.string()), ("event_kind", pa.string()),
    ("timestamp", pa.timestamp("ms", tz="UTC")), ("dt", pa.string()),
    ("category", pa.string()), ("action", pa.string()), ("severity", pa.int8()),
    ("severity_label", pa.string()), ("raw_format", pa.string()), ("event_type", pa.string()),
    ("source_ip", pa.string()), ("source_port", pa.int32()), ("destination_ip", pa.string()),
    ("destination_port", pa.int32()), ("protocol", pa.string()), ("bytes_in", pa.int64()),
    ("bytes_out", pa.int64()), ("user_name", pa.string()), ("device_vendor", pa.string()),
    ("device_product", pa.string()), ("device_hostname", pa.string()), ("rule_name", pa.string()),
    ("threat_category", pa.string()), ("src_country_code", pa.string()),
    ("dst_country_code", pa.string()), ("message", pa.string()), ("input", pa.string()),
    ("source", pa.string()), ("node_id", pa.string()), ("journal_seq", pa.int64()),
    ("raw_hash", pa.string()), ("raw_event", pa.string()), ("event_json", pa.string()),
])

COLUMN_KINDS = {  # documented for ML consumers (export-ml and the lake share this)
    "numeric": ["severity", "source_port", "destination_port", "bytes_in", "bytes_out"],
    "categorical": ["event_kind", "category", "action", "severity_label", "raw_format", "event_type",
                    "protocol", "device_vendor", "device_product", "threat_category",
                    "src_country_code", "dst_country_code", "input"],
    "timestamp": ["timestamp"],
    "identifier": ["event_id", "source_ip", "destination_ip", "user_name", "device_hostname",
                   "rule_name", "source", "node_id", "journal_seq", "raw_hash"],
    "text": ["message", "raw_event", "event_json"],
}


def _int(v, lo, hi):
    try:
        v = int(v)
    except (TypeError, ValueError):
        return None
    return v if lo <= v <= hi else None


def _ts(s):
    from datetime import datetime
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def lake_row(e: dict) -> dict:
    src, dst = e.get("source") or {}, e.get("destination") or {}
    net, dev, geo = e.get("network") or {}, e.get("device") or {}, e.get("geo") or {}
    meta, ev = e.get("metadata") or {}, e.get("evidence") or {}
    ts = _ts(e.get("timestamp"))
    return {
        "event_id": e.get("event_id"), "event_kind": e.get("event_kind") or "log",
        "timestamp": ts, "dt": ts.strftime("%Y-%m-%d") if ts else "unknown",
        "category": e.get("category"), "action": e.get("action"),
        "severity": _int(e.get("severity"), 0, 10), "severity_label": e.get("severity_label"),
        "raw_format": e.get("raw_format"), "event_type": e.get("event_type"),
        "source_ip": src.get("ip"), "source_port": _int(src.get("port"), 0, 65535),
        "destination_ip": dst.get("ip"), "destination_port": _int(dst.get("port"), 0, 65535),
        "protocol": net.get("protocol"), "bytes_in": _int(net.get("bytes_in"), 0, 2**62),
        "bytes_out": _int(net.get("bytes_out"), 0, 2**62),
        "user_name": (e.get("user") or {}).get("name"), "device_vendor": dev.get("vendor"),
        "device_product": dev.get("product"), "device_hostname": dev.get("hostname"),
        "rule_name": (e.get("rule") or {}).get("name"),
        "threat_category": (e.get("threat") or {}).get("category"),
        "src_country_code": geo.get("src_country_code"), "dst_country_code": geo.get("dst_country_code"),
        "message": e.get("message"), "input": meta.get("input"), "source": meta.get("ingestion_source"),
        "node_id": ev.get("node_id"), "journal_seq": ev.get("journal_seq"),
        "raw_hash": ev.get("raw_hash"), "raw_event": e.get("raw_event"),
        "event_json": orjson.dumps(e, default=str).decode("utf-8"),
    }


def encode_lake(events: list[dict], view: str = "unified") -> bytes:
    import pyarrow.parquet as pq
    rows = [lake_row(e) for e in events]
    if view != "unified":
        from ulpf.engine.views import apply_view
        for r, e in zip(rows, events):
            r["event_json"] = orjson.dumps(apply_view(e, view), default=str).decode("utf-8")
    table = pa.Table.from_pylist(rows, schema=LAKE_SCHEMA)
    buf = io.BytesIO()
    pq.write_table(table, buf, compression="lz4")
    return buf.getvalue()


def partitioned_tables(table: pa.Table, keys: list[str]):
    """Yield (relative_dir, sub_table) per distinct combination of partition keys."""
    import pyarrow.compute as pc
    keys = [k for k in keys if k in table.column_names]
    if not keys:
        yield "", table
        return
    combos = table.select(keys).group_by(keys).aggregate([]).to_pylist()
    for combo in combos:
        mask = None
        for k in keys:
            v = combo[k]
            m = pc.is_null(table[k]) if v is None else pc.equal(table[k], v)
            mask = m if mask is None else pc.and_(mask, m)
        rel = "/".join(f"{k}={_safe(combo[k])}" for k in keys)
        yield rel, table.filter(mask)


def _safe(v) -> str:
    s = "null" if v is None else str(v)
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)[:100]
