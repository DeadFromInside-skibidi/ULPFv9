"""
HTTP outputs: Elasticsearch/OpenSearch, Splunk HEC, Loki, OTLP, Azure Monitor
(Logs Ingestion API), Google Security Operations (Chronicle).

Encoders run in workers and produce one record per line. Senders split a
segment into requests within ``batch.max_events`` / ``batch.max_bytes`` and
map destination responses onto RetriableError / PermanentError (with the
indexes of individually rejected records where the API reports them).
"""
from __future__ import annotations

import base64
import time
import uuid
from datetime import datetime, timezone

import orjson

from ulpf.engine.views import apply_view
from ulpf.runtime.buffer import Segment
from ulpf.runtime.net import EntraToken, GoogleToken, HttpClient
from ulpf.runtime.retry import PermanentError, RetriableError, classify_http
from ulpf.runtime.sinks.base import Sink, client_ssl_context, dumps, env_secret

_SEV_OTLP = {0: 0, 1: 9, 2: 9, 3: 10, 4: 11, 5: 13, 6: 14, 7: 17, 8: 18, 9: 21, 10: 22}


def _ts(event: dict) -> datetime:
    ts = event.get("timestamp")
    try:
        d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)


def _chunks(records: list[bytes], max_events: int, max_bytes: int, overhead: int = 1):
    """Yield (start_index, records) slices within the limits."""
    start, size = 0, 0
    for i, r in enumerate(records):
        if i > start and (i - start >= max_events or size + len(r) + overhead > max_bytes):
            yield start, records[start:i]
            start, size = i, 0
        size += len(r) + overhead
    if start < len(records):
        yield start, records[start:]


class _HttpSink(Sink):
    remote = True

    def _limits(self) -> tuple[int, int]:
        b = self.opts.get("batch") or {}
        return int(b.get("max_events", 5000)), int(b.get("max_bytes", 5 * 2**20))

    def _client(self, urls) -> HttpClient:
        tls = self.opts.get("tls") or {}
        any_https = any(str(u).startswith("https://") for u in ([urls] if isinstance(urls, str) else urls))
        return HttpClient(urls, client_ssl_context(tls) if any_https else None, timeout=60)

    def deliver(self, payload: bytes, seg: Segment) -> None:
        records = self.records(payload)
        max_events, max_bytes = self._limits()
        rejected: list[int] = []
        reasons: dict[int, str] = {}
        for start, chunk in _chunks(records, max_events, max_bytes):
            try:
                self._send(chunk)
            except PermanentError as e:
                if e.rejected is None:
                    idx = list(range(start, start + len(chunk)))
                else:
                    idx = [start + i for i in e.rejected]
                rejected += idx
                for i in idx:
                    reasons[i] = e.reasons.get(i - start, str(e))
        if rejected:
            raise PermanentError(f"{len(rejected)} of {len(records)} record(s) rejected",
                                 rejected=rejected, reasons=reasons)

    def _send(self, records: list[bytes]) -> None:
        raise NotImplementedError

    def close(self) -> None:
        c = getattr(self, "client", None)
        if c is not None:
            c.close()


# ---------------------------------------------------------------------------
# Elasticsearch / OpenSearch
# ---------------------------------------------------------------------------

class ElasticsearchSink(_HttpSink):
    """Bulk API with ``create`` and ``_id = event_id``: redelivery is idempotent (409 = already stored)."""

    idempotent = True

    def encode(self, events: list[dict]) -> bytes:
        pattern = self.opts.get("index", "ulpf-%Y.%m.%d")
        lines = []
        for e in events:
            index = _ts(e).strftime(pattern).lower()
            lines.append(dumps({"create": {"_index": index, "_id": e.get("event_id")}}))
            lines.append(dumps(apply_view(e, self.view)))
        return b"\n".join(lines) + b"\n"

    def records(self, payload: bytes) -> list[bytes]:
        lines = [l for l in payload.split(b"\n") if l]
        return [lines[i] + b"\n" + lines[i + 1] for i in range(0, len(lines) - 1, 2)]

    def open(self) -> None:
        headers = {"Content-Type": "application/x-ndjson"}
        if self.opts.get("api_key_env"):
            headers["Authorization"] = f"ApiKey {env_secret(self.opts['api_key_env'], 'Elasticsearch API key')}"
        elif self.opts.get("username"):
            pw = env_secret(self.opts.get("password_env"), "Elasticsearch password") or ""
            token = base64.b64encode(f"{self.opts['username']}:{pw}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"
        self.client = self._client(self.opts["urls"])
        self.client.headers.update(headers)

    def _send(self, records: list[bytes]) -> None:
        path = "/_bulk" + (f"?pipeline={self.opts['pipeline']}" if self.opts.get("pipeline") else "")
        r = self.client.request("POST", path, b"\n".join(records) + b"\n")
        err = classify_http(r.status, r.text)
        if err is not None:
            raise err
        body = r.json()
        if not body.get("errors"):
            return
        retry = False
        rejected, reasons = [], {}
        for i, item in enumerate(body.get("items", [])):
            res = next(iter(item.values()))
            st = res.get("status", 200)
            if st < 300 or st == 409:     # 409: this _id is already indexed (replay)
                continue
            if st == 429 or st >= 500:
                retry = True
            else:
                rejected.append(i)
                reasons[i] = orjson.dumps(res.get("error"), default=str).decode()[:500]
        if retry:
            raise RetriableError("Elasticsearch asked to back off (429/5xx on bulk items)")
        if rejected:
            raise PermanentError(f"{len(rejected)} bulk item(s) rejected", rejected=rejected, reasons=reasons)

    def health(self) -> dict:
        try:
            r = self.client.request("GET", "/")
            return {"ok": r.status < 300, "status": r.status}
        except RetriableError as e:
            return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Splunk HTTP Event Collector
# ---------------------------------------------------------------------------

class SplunkHecSink(_HttpSink):
    def encode(self, events: list[dict]) -> bytes:
        o = self.opts
        out = []
        for e in events:
            doc = {"time": round(_ts(e).timestamp(), 3),
                   "host": (e.get("device") or {}).get("hostname") or (e.get("metadata") or {}).get("ingestion_source"),
                   "source": f"ulpf:{(e.get('metadata') or {}).get('input') or 'ulpf'}",
                   "sourcetype": o.get("sourcetype") or "ulpf:event",
                   "event": apply_view(e, self.view)}
            if o.get("index"):
                doc["index"] = o["index"]
            out.append(dumps({k: v for k, v in doc.items() if v is not None}))
        return b"\n".join(out) + b"\n"

    def open(self) -> None:
        self.client = self._client(self.opts["url"])
        self.client.headers["Authorization"] = f"Splunk {env_secret(self.opts['token_env'], 'HEC token')}"
        if self.opts.get("ack"):
            self.channel = str(uuid.uuid4())
            self.client.headers["X-Splunk-Request-Channel"] = self.channel

    def _send(self, records: list[bytes]) -> None:
        r = self.client.request("POST", "/services/collector/event", b"\n".join(records))
        if r.status >= 300:
            try:
                code = r.json().get("code")
            except ValueError:
                code = None
            if code in (6, 12, 13) or r.status in (400, 401, 403):  # invalid data / auth / disabled token
                raise PermanentError(f"HEC {r.status}: {r.text[:300]}")
            raise RetriableError(f"HEC {r.status}: {r.text[:300]}")
        if self.opts.get("ack"):
            ack_id = r.json().get("ackId")
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                a = self.client.checked("POST", "/services/collector/ack",
                                        orjson.dumps({"acks": [ack_id]})).json()
                if a.get("acks", {}).get(str(ack_id)):
                    return
                time.sleep(1)
            raise RetriableError(f"HEC did not acknowledge ack id {ack_id} in time")

    def health(self) -> dict:
        try:
            r = self.client.request("GET", "/services/collector/health")
            return {"ok": r.status < 300, "status": r.status}
        except RetriableError as e:
            return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Grafana Loki
# ---------------------------------------------------------------------------

def _label(name: str) -> str:
    return "".join(c if c.isalnum() or c == "_" else "_" for c in name)


class LokiSink(_HttpSink):
    def encode(self, events: list[dict]) -> bytes:
        from ulpf.runtime.router import get_path
        labels = self.opts.get("labels") or []
        out = []
        for e in events:
            lab = {"job": "ulpf"}
            for path in labels:
                v = get_path(e, path)
                if v is not None:
                    lab[_label(path)] = str(v)
            out.append(dumps({"s": lab, "t": str(int(_ts(e).timestamp() * 1e9)),
                              "l": dumps(apply_view(e, self.view)).decode()}))
        return b"\n".join(out) + b"\n"

    def open(self) -> None:
        self.client = self._client(self.opts["url"])
        self.client.headers["Content-Type"] = "application/json"
        if self.opts.get("tenant_id"):
            self.client.headers["X-Scope-OrgID"] = self.opts["tenant_id"]

    def _send(self, records: list[bytes]) -> None:
        streams: dict[tuple, list] = {}
        for r in records:
            d = orjson.loads(r)
            streams.setdefault(tuple(sorted(d["s"].items())), []).append([d["t"], d["l"]])
        body = {"streams": [{"stream": dict(k), "values": sorted(v)} for k, v in streams.items()]}
        r = self.client.request("POST", "/loki/api/v1/push", orjson.dumps(body))
        err = classify_http(r.status, r.text)
        if err is not None:
            raise err


# ---------------------------------------------------------------------------
# OpenTelemetry OTLP/HTTP (JSON)
# ---------------------------------------------------------------------------

def _otlp_value(v):
    if isinstance(v, bool):
        return {"boolValue": v}
    if isinstance(v, int):
        return {"intValue": str(v)}
    if isinstance(v, float):
        return {"doubleValue": v}
    if isinstance(v, (list, tuple)):
        return {"arrayValue": {"values": [_otlp_value(x) for x in v][:100]}}
    return {"stringValue": str(v)}


def _flatten(d: dict, prefix: str = "", out: dict | None = None, depth: int = 0) -> dict:
    out = {} if out is None else out
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict) and depth < 4:
            _flatten(v, key + ".", out, depth + 1)
        elif v not in (None, "", [], {}):
            out[key] = v
    return out


def otlp_log_record(e: dict, view: str) -> dict:
    doc = apply_view(e, view)
    body = e.get("raw_event") or e.get("message") or ""
    attrs = {k: v for k, v in _flatten(doc).items() if k not in ("raw_event", "event.original", "raw_data")}
    sev = int(e.get("severity") or 0)
    return {"timeUnixNano": str(int(_ts(e).timestamp() * 1e9)),
            "observedTimeUnixNano": str(time.time_ns()),
            "severityNumber": _SEV_OTLP.get(sev, 0), "severityText": e.get("severity_label") or "",
            "body": {"stringValue": body},
            "attributes": [{"key": k, "value": _otlp_value(v)} for k, v in list(attrs.items())[:200]]}


class OtlpSink(_HttpSink):
    def encode(self, events: list[dict]) -> bytes:
        return b"\n".join(dumps(otlp_log_record(e, self.view)) for e in events) + b"\n"

    def open(self) -> None:
        self.client = self._client(self.opts["url"])
        self.client.headers.update({"Content-Type": "application/json", **(self.opts.get("headers") or {})})

    def _send(self, records: list[bytes]) -> None:
        body = {"resourceLogs": [{
            "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "ulpf"}}]},
            "scopeLogs": [{"scope": {"name": "ulpf"}, "logRecords": [orjson.loads(r) for r in records]}]}]}
        r = self.client.request("POST", "/v1/logs", orjson.dumps(body))
        err = classify_http(r.status, r.text)
        if err is not None:
            raise err


# ---------------------------------------------------------------------------
# Azure Monitor — Logs Ingestion API (DCR based)
# ---------------------------------------------------------------------------

def azure_record(e: dict, view: str) -> dict:
    """Columns of the DCR stream ULPF documents (see docs/SOURCES.md):
    TimeGenerated, EventId, Kind, Category, Action, Severity, SourceIp, DestinationIp,
    UserName, DeviceVendor, Message, RawEvent, RawHash, Event (dynamic)."""
    src, dst = e.get("source") or {}, e.get("destination") or {}
    return {"TimeGenerated": _ts(e).isoformat(), "EventId": e.get("event_id"),
            "Kind": e.get("event_kind") or "log", "Category": e.get("category"), "Action": e.get("action"),
            "Severity": e.get("severity"), "SourceIp": src.get("ip"), "DestinationIp": dst.get("ip"),
            "UserName": (e.get("user") or {}).get("name"), "DeviceVendor": (e.get("device") or {}).get("vendor"),
            "Message": e.get("message"), "RawEvent": e.get("raw_event"),
            "RawHash": (e.get("evidence") or {}).get("raw_hash"), "Event": apply_view(e, view)}


class AzureLogAnalyticsSink(_HttpSink):
    def _limits(self) -> tuple[int, int]:
        max_events, max_bytes = super()._limits()
        return max_events, min(max_bytes, 1_000_000)     # API limit: 1 MB per call

    def encode(self, events: list[dict]) -> bytes:
        return b"\n".join(dumps(azure_record(e, self.view)) for e in events) + b"\n"

    def open(self) -> None:
        o = self.opts
        self.token = EntraToken(o["tenant_id"], o["client_id"], env_secret(o["client_secret_env"], "client secret"),
                                "https://monitor.azure.com//.default", o.get("login_endpoint"))
        self.client = self._client(o["endpoint"])
        self.path = (f"/dataCollectionRules/{o['dcr_immutable_id']}/streams/{o['stream_name']}"
                     "?api-version=2023-01-01")

    def _send(self, records: list[bytes]) -> None:
        body = b"[" + b",".join(records) + b"]"
        r = self.client.request("POST", self.path, body, {"Content-Type": "application/json",
                                                          "Authorization": f"Bearer {self.token.get()}"})
        err = classify_http(r.status, r.text)
        if err is not None:
            raise err


# ---------------------------------------------------------------------------
# Google Security Operations (Chronicle) ingestion API
# ---------------------------------------------------------------------------

class ChronicleSink(_HttpSink):
    def _limits(self) -> tuple[int, int]:
        max_events, max_bytes = super()._limits()
        return max_events, min(max_bytes, 900_000)        # API limit: 1 MB per request

    def encode(self, events: list[dict]) -> bytes:
        return b"\n".join(dumps({"log_text": dumps(apply_view(e, self.view)).decode(),
                                 "ts_epoch_microseconds": int(_ts(e).timestamp() * 1e6)})
                          for e in events) + b"\n"

    def open(self) -> None:
        o = self.opts
        self.token = GoogleToken(o["credentials_file"], "https://www.googleapis.com/auth/malachite-ingestion")
        self.client = self._client(o.get("endpoint") or "https://malachiteingestion-pa.googleapis.com")

    def _send(self, records: list[bytes]) -> None:
        body = {"customer_id": self.opts["customer_id"], "log_type": self.opts.get("log_type") or "UDM",
                "entries": [orjson.loads(r) for r in records]}
        r = self.client.request("POST", "/v2/unstructuredlogentries:batchCreate", orjson.dumps(body),
                                {"Content-Type": "application/json", "Authorization": f"Bearer {self.token.get()}"})
        err = classify_http(r.status, r.text)
        if err is not None:
            raise err
