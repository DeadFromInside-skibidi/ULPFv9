"""
HTTP and OTLP inputs, served by the runtime's API server.

* ``http``: ``POST /api/v1/ingest/stream/{source}`` with NDJSON, a JSON array,
  or plain text lines (``Content-Encoding: gzip`` accepted). Each line or
  array element becomes one journal record.
* ``otlp``: ``POST /v1/logs`` with OTLP/HTTP protobuf
  (``application/x-protobuf``) or JSON (``application/json``).

When the pipeline is saturated both return 429 with ``Retry-After`` so
well-behaved shippers back off instead of losing data.

OTLP records: a log record whose body is a string is journaled as that string
(usually the original line, so the right parser detects it). Otherwise the
record is journaled as compact JSON of its body, attributes and severity.
"""
from __future__ import annotations

import gzip
import struct
import threading

import orjson

from ulpf.runtime.inputs.base import Input


class HttpInput(Input):
    """The endpoint lives in the API server; this object holds options and counters."""

    def run(self, stop: threading.Event) -> None:
        stop.wait()


class OtlpInput(HttpInput):
    pass


def decode_body(body: bytes, content_encoding: str | None) -> bytes:
    if (content_encoding or "").lower() == "gzip" or body[:2] == b"\x1f\x8b":
        return gzip.decompress(body)
    return body


def split_records(body: bytes, content_type: str | None) -> list[bytes]:
    """NDJSON / JSON array / text → one record per line or element (exact bytes for lines)."""
    stripped = body.lstrip()
    ctype = (content_type or "").lower()
    if stripped[:1] == b"[" and ("json" in ctype or not ctype):
        try:
            arr = orjson.loads(stripped)
            if isinstance(arr, list):
                return [x.encode() if isinstance(x, str) else orjson.dumps(x) for x in arr]
        except orjson.JSONDecodeError:
            pass
    return [l.rstrip(b"\r") for l in body.split(b"\n") if l.strip()]


# ---------------------------------------------------------------------------
# OTLP decoding
# ---------------------------------------------------------------------------

def _varint(b: bytes, i: int) -> tuple[int, int]:
    shift = result = 0
    while True:
        c = b[i]
        i += 1
        result |= (c & 0x7F) << shift
        if not c & 0x80:
            return result, i
        shift += 7


def _fields(b: bytes):
    """Yield (field_number, wire_type, value) of one protobuf message."""
    i = 0
    n = len(b)
    while i < n:
        key, i = _varint(b, i)
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _varint(b, i)
        elif wt == 1:
            v = b[i:i + 8]
            i += 8
        elif wt == 2:
            ln, i = _varint(b, i)
            v = b[i:i + ln]
            i += ln
        elif wt == 5:
            v = b[i:i + 4]
            i += 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wt}")
        yield fn, wt, v


def _any_value(b: bytes):
    for fn, wt, v in _fields(b):
        if fn == 1:
            return v.decode("utf-8", "replace")
        if fn == 2:
            return bool(v)
        if fn == 3:
            return v - (1 << 64) if v >= 1 << 63 else v
        if fn == 4:
            return struct.unpack("<d", v)[0]
        if fn == 5:
            return [_any_value(x) for f2, _, x in _fields(v) if f2 == 1]
        if fn == 6:
            return dict(_kv(x) for f2, _, x in _fields(v) if f2 == 1)
        if fn == 7:
            return v.hex()
    return None


def _kv(b: bytes) -> tuple[str, object]:
    key, val = "", None
    for fn, _, v in _fields(b):
        if fn == 1:
            key = v.decode("utf-8", "replace")
        elif fn == 2:
            val = _any_value(v)
    return key, val


def _log_record(b: bytes) -> dict:
    r: dict = {"attributes": {}}
    for fn, _, v in _fields(b):
        if fn == 1:
            r["time_unix_nano"] = struct.unpack("<Q", v)[0]
        elif fn == 11:
            r["observed_time_unix_nano"] = struct.unpack("<Q", v)[0]
        elif fn == 2:
            r["severity_number"] = v
        elif fn == 3:
            r["severity_text"] = v.decode("utf-8", "replace")
        elif fn == 5:
            r["body"] = _any_value(v)
        elif fn == 6:
            k, val = _kv(v)
            r["attributes"][k] = val
        elif fn == 9:
            r["trace_id"] = v.hex()
        elif fn == 10:
            r["span_id"] = v.hex()
        elif fn == 12:
            r["event_name"] = v.decode("utf-8", "replace")
    return r


def otlp_protobuf_records(body: bytes) -> list[tuple[dict, dict]]:
    """[(resource_attributes, log_record), ...] from an ExportLogsServiceRequest."""
    out = []
    for fn, _, rl in _fields(body):
        if fn != 1:
            continue
        resource: dict = {}
        scopes = []
        for f2, _, v in _fields(rl):
            if f2 == 1:
                resource = dict(_kv(a) for f3, _, a in _fields(v) if f3 == 1)
            elif f2 == 2:
                scopes.append(v)
        for sl in scopes:
            for f3, _, v in _fields(sl):
                if f3 == 2:
                    out.append((resource, _log_record(v)))
    return out


def _json_any(v: dict):
    if not isinstance(v, dict):
        return v
    for k, conv in (("stringValue", str), ("boolValue", bool), ("intValue", int), ("doubleValue", float)):
        if k in v:
            return conv(v[k])
    if "arrayValue" in v:
        return [_json_any(x) for x in v["arrayValue"].get("values", [])]
    if "kvlistValue" in v:
        return {x["key"]: _json_any(x.get("value")) for x in v["kvlistValue"].get("values", [])}
    if "bytesValue" in v:
        return v["bytesValue"]
    return None


def otlp_json_records(doc: dict) -> list[tuple[dict, dict]]:
    out = []
    for rl in doc.get("resourceLogs") or []:
        resource = {a["key"]: _json_any(a.get("value")) for a in (rl.get("resource") or {}).get("attributes", [])}
        for sl in rl.get("scopeLogs") or []:
            for lr in sl.get("logRecords") or []:
                rec = {"attributes": {a["key"]: _json_any(a.get("value")) for a in lr.get("attributes", [])}}
                if lr.get("timeUnixNano"):
                    rec["time_unix_nano"] = int(lr["timeUnixNano"])
                if lr.get("severityNumber") is not None:
                    rec["severity_number"] = int(lr["severityNumber"]) if str(lr["severityNumber"]).isdigit() else 0
                if lr.get("severityText"):
                    rec["severity_text"] = lr["severityText"]
                if lr.get("body") is not None:
                    rec["body"] = _json_any(lr["body"])
                out.append((resource, rec))
    return out


def otlp_to_records(pairs: list[tuple[dict, dict]], fallback_source: str) -> dict[str, list[bytes]]:
    """Group journal records by source (service / file / host) — see the module docstring."""
    by_source: dict[str, list[bytes]] = {}
    for resource, rec in pairs:
        attrs = rec.get("attributes") or {}
        source = str(resource.get("service.name") or attrs.get("log.file.path") or resource.get("host.name")
                      or fallback_source)
        body = rec.get("body")
        if isinstance(body, str) and body.strip():
            raw = body.encode("utf-8")
        else:
            doc = {k: v for k, v in rec.items() if v not in (None, {}, [])}
            if resource:
                doc["resource"] = resource
            raw = orjson.dumps(doc, default=str)
        by_source.setdefault(source, []).append(raw)
    return by_source
