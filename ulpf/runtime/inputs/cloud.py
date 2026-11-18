"""
Cloud pull inputs (industry mode only; config validation rejects them in defence mode).

Each input advances its position only after the records are journaled and
the journal is flushed, so a crash re-reads rather than loses data.

* CloudTrail  — SQS notifications of new log objects → S3 GET (SigV4); each
                ``Records[]`` element is one record; the SQS message is
                deleted after its objects are journaled.
* Pub/Sub     — REST pull with a service-account token; acknowledged after journaling.
* Okta        — System Log API, ``Link: rel="next"`` pagination; the next URL is the checkpoint.
* Entra ID    — Microsoft Graph sign-ins and directory audits; ``createdDateTime``
                of the newest record is the checkpoint.
* Event Hubs  — Azure SDK (``ulpf[azure]``), checkpoints kept by ULPF.
"""
from __future__ import annotations

import base64
import gzip
import json
import logging
import os
import re
import threading
import time
import urllib.parse

import orjson

from ulpf.runtime.inputs.base import Input
from ulpf.runtime.net import EntraToken, GoogleToken, HttpClient, sigv4_headers
from ulpf.runtime.retry import classify_http
from ulpf.runtime.sinks.base import env_secret

logger = logging.getLogger(__name__)


def _check(r) -> None:
    err = classify_http(r.status, r.text)
    if err is not None:
        raise err


class _Poller(Input):
    """Common loop: poll(); on error back off without crashing the input (unless auth is wrong)."""

    interval = 5.0

    def run(self, stop: threading.Event) -> None:
        if self.ctx.cfg.mode == "defence":
            raise RuntimeError(f"{self.opts['type']} is a cloud input and is disabled in defence mode")
        self.setup()
        delay = self.interval
        try:
            while not stop.is_set():
                try:
                    more = self.poll()
                    delay = 0.0 if more else self.interval
                except Exception as e:
                    self.stats.errors += 1
                    self.stats.last_error = f"{type(e).__name__}: {e}"
                    logger.warning(f"input {self.name}: {self.stats.last_error}")
                    delay = min(max(delay * 2, self.interval), 300.0)
                if delay:
                    stop.wait(delay)
        finally:
            for attr in ("client", "sqs"):
                c = getattr(self, attr, None)
                if c is not None:
                    c.close()

    def setup(self) -> None:
        pass

    def poll(self) -> bool:
        raise NotImplementedError

    def durable(self) -> None:
        self.ctx.journal.flush()


# ---------------------------------------------------------------------------
# AWS CloudTrail via SQS + S3
# ---------------------------------------------------------------------------

class CloudTrailInput(_Poller):
    def setup(self) -> None:
        o = self.opts
        self.interval = o.get("poll_interval_ms", 5000) / 1000.0
        self.access = env_secret(o.get("access_key_env"), "AWS access key") or ""
        self.secret = env_secret(o.get("secret_key_env"), "AWS secret key") or ""
        self.token = env_secret(o.get("session_token_env"), "AWS session token") if o.get("session_token_env") else None
        self.region = o["region"]
        self.queue_url = o["queue_url"]
        self.sqs_base = o.get("endpoint") or f"https://sqs.{self.region}.amazonaws.com"
        self.sqs = HttpClient(self.sqs_base, timeout=60)

    def _sqs(self, action: str, body: dict) -> dict:
        payload = orjson.dumps(body)
        url = self.sqs_base.rstrip("/") + "/"
        headers = sigv4_headers("POST", url, self.region, "sqs", self.access, self.secret, payload, self.token,
                                {"content-type": "application/x-amz-json-1.0",
                                 "x-amz-target": f"AmazonSQS.{action}"})
        r = self.sqs.request("POST", "/", payload, headers)
        _check(r)
        return r.json() or {}

    def _s3_get(self, bucket: str, key: str) -> bytes:
        if self.opts.get("endpoint"):
            base = self.opts["endpoint"].rstrip("/") + "/" + bucket
        else:
            base = f"https://{bucket}.s3.{self.region}.amazonaws.com"
        path = "/" + urllib.parse.quote(key, safe="/-_.~")
        headers = sigv4_headers("GET", base + path, self.region, "s3", self.access, self.secret, b"", self.token)
        with HttpClient(base, timeout=120) as c:
            r = c.request("GET", path, None, headers)
        _check(r)
        return gzip.decompress(r.body) if r.body[:2] == b"\x1f\x8b" else r.body

    def poll(self) -> bool:
        resp = self._sqs("ReceiveMessage", {"QueueUrl": self.queue_url, "MaxNumberOfMessages": 10,
                                            "WaitTimeSeconds": 10, "VisibilityTimeout": 300})
        msgs = resp.get("Messages") or []
        for m in msgs:
            body = json.loads(m["Body"])
            if "Message" in body and isinstance(body["Message"], str):   # SNS envelope
                body = json.loads(body["Message"])
            objects = []
            for rec in body.get("Records") or []:            # S3 event notification
                s3 = rec.get("s3") or {}
                if s3.get("bucket") and s3.get("object"):
                    objects.append((s3["bucket"]["name"], urllib.parse.unquote_plus(s3["object"]["key"])))
            if body.get("s3Bucket"):                          # CloudTrail SNS notification
                objects += [(body["s3Bucket"], k) for k in body.get("s3ObjectKey") or []]
            for bucket, key in objects:
                doc = json.loads(self._s3_get(bucket, key))
                recs = [orjson.dumps(r) for r in doc.get("Records") or []]
                if recs:
                    self.accept(f"s3://{bucket}/{key}", recs, block=True)
            self.durable()
            self._sqs("DeleteMessage", {"QueueUrl": self.queue_url, "ReceiptHandle": m["ReceiptHandle"]})
        return bool(msgs)


# ---------------------------------------------------------------------------
# Google Cloud Pub/Sub (REST)
# ---------------------------------------------------------------------------

class PubSubInput(_Poller):
    def setup(self) -> None:
        o = self.opts
        self.interval = o.get("poll_interval_ms", 2000) / 1000.0
        self.token = GoogleToken(o["credentials_file"], "https://www.googleapis.com/auth/pubsub")
        self.client = HttpClient(o.get("endpoint") or "https://pubsub.googleapis.com", timeout=60)
        self.path = f"/v1/projects/{o['project']}/subscriptions/{o['subscription']}"

    def poll(self) -> bool:
        auth = {"Authorization": f"Bearer {self.token.get()}", "Content-Type": "application/json"}
        r = self.client.request("POST", self.path + ":pull", orjson.dumps({"maxMessages": 1000}), auth)
        _check(r)
        received = (r.json() or {}).get("receivedMessages") or []
        if not received:
            return False
        recs = [base64.b64decode(m["message"].get("data") or b"") for m in received]
        self.accept(self.opts["subscription"], [x for x in recs if x], block=True)
        self.durable()
        r = self.client.request("POST", self.path + ":acknowledge",
                                orjson.dumps({"ackIds": [m["ackId"] for m in received]}), auth)
        _check(r)
        return len(received) >= 1000


# ---------------------------------------------------------------------------
# Okta System Log
# ---------------------------------------------------------------------------

_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')


class OktaInput(_Poller):
    def setup(self) -> None:
        o = self.opts
        self.interval = float(o.get("poll_interval_s", 60))
        base = o.get("endpoint") or f"https://{o['domain']}"
        self.client = HttpClient(base, timeout=60,
                                 headers={"Authorization": f"SSWS {env_secret(o['token_env'], 'Okta token')}",
                                          "Accept": "application/json"})
        self.base_path = urllib.parse.urlsplit(base).path.rstrip("/")
        self.key = f"okta:{self.name}"

    def poll(self) -> bool:
        ck = self.ctx.checkpoints.get(self.key)
        if ck:
            path = ck["value"]
        else:
            since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))
            path = f"{self.base_path}/api/v1/logs?since={since}&limit=1000&sortOrder=ASCENDING"
        r = self.client.request("GET", path)
        _check(r)
        events = r.json() or []
        if events:
            self.accept(self.opts["domain"], [orjson.dumps(e) for e in events], block=True)
        m = _NEXT.search(r.headers.get("link", ""))
        if m:
            nxt = urllib.parse.urlsplit(m.group(1))
            nxt_path = nxt.path + ("?" + nxt.query if nxt.query else "")
            self.ctx.checkpoints.set(self.key, nxt_path, self.last_seq or self.ctx.journal.next_seq - 1)
        return bool(events) and len(events) >= 1000


# ---------------------------------------------------------------------------
# Microsoft Entra ID (Graph)
# ---------------------------------------------------------------------------

class EntraInput(_Poller):
    STREAMS = ("auditLogs/signIns", "auditLogs/directoryAudits")

    def setup(self) -> None:
        o = self.opts
        self.interval = float(o.get("poll_interval_s", 60))
        self.token = EntraToken(o["tenant_id"], o["client_id"], env_secret(o["client_secret_env"], "client secret"),
                                "https://graph.microsoft.com/.default", o.get("login_endpoint"))
        base = o.get("graph_endpoint") or "https://graph.microsoft.com"
        self.client = HttpClient(base, timeout=60)
        self.base_path = urllib.parse.urlsplit(base).path.rstrip("/")

    def poll(self) -> bool:
        for stream in self.STREAMS:
            key = f"entra:{self.name}:{stream}"
            ck = self.ctx.checkpoints.get(key)
            since = ck["value"] if ck else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))
            flt = urllib.parse.quote(f"createdDateTime gt {since}")
            path = f"{self.base_path}/v1.0/{stream}?$filter={flt}&$orderby=createdDateTime&$top=999"
            newest = since
            while path:
                r = self.client.request("GET", path, headers={"Authorization": f"Bearer {self.token.get()}"})
                _check(r)
                doc = r.json() or {}
                items = doc.get("value") or []
                if items:
                    self.accept(stream, [orjson.dumps(x) for x in items], block=True)
                    newest = max([newest] + [x.get("createdDateTime") or "" for x in items])
                nxt = doc.get("@odata.nextLink")
                path = None
                if nxt:
                    u = urllib.parse.urlsplit(nxt)
                    path = u.path + ("?" + u.query if u.query else "")
            if newest != since:
                self.ctx.checkpoints.set(key, newest, self.last_seq or self.ctx.journal.next_seq - 1)
        return False    # every page was followed above; wait for the next interval


# ---------------------------------------------------------------------------
# Azure Event Hubs (SDK)
# ---------------------------------------------------------------------------

class EventHubsInput(_Poller):
    def run(self, stop: threading.Event) -> None:
        if self.ctx.cfg.mode == "defence":
            raise RuntimeError("eventhubs is a cloud input and is disabled in defence mode")
        from azure.eventhub import EventHubConsumerClient
        o = self.opts
        ck_path = os.path.join(self.ctx.data_dir, f"eventhubs_{self.name}.json")
        try:
            with open(ck_path, "r", encoding="utf-8") as f:
                positions = json.load(f)
        except (OSError, ValueError):
            positions = {}
        client = EventHubConsumerClient.from_connection_string(
            env_secret(o["connection_string_env"], "Event Hubs connection string"),
            consumer_group=o.get("consumer_group") or "$Default", eventhub_name=o["eventhub"])

        def on_batch(ctx, events):
            if not events:
                return
            pid = ctx.partition_id
            self.accept(f"{o['eventhub']}/{pid}", [e.body_as_str(encoding="utf-8").encode() for e in events],
                        block=True)
            self.durable()
            positions[pid] = events[-1].sequence_number
            tmp = ck_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(positions, f)
            os.replace(tmp, ck_path)

        start = {pid: seq for pid, seq in positions.items()}

        def runner():
            with client:
                client.receive_batch(on_event_batch=on_batch, max_batch_size=500, max_wait_time=1,
                                     starting_position=start or "@latest", starting_position_inclusive=False)

        t = threading.Thread(target=runner, name=f"ulpf-in-{self.name}-eh", daemon=True)
        t.start()
        stop.wait()
        client.close()
        t.join(10)
