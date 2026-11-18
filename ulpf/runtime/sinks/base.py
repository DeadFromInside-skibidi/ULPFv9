"""
Sink interface.

A sink has two halves that never share state:

* **encoder** (``encode``) — runs in worker processes, turns events into the
  bytes of one buffer segment. No I/O besides what the runtime does with the
  returned bytes.
* **sender** (``open`` / ``deliver_many`` / ``close``) — runs in the host, one
  thread per sink (``SinkRunner``), and delivers buffered segments.

Delivery errors are reported with ``RetriableError`` (kept in the buffer,
retried with backoff) or ``PermanentError`` (sent to the dead-letter queue).
"""
from __future__ import annotations

import os
import ssl
from typing import Any

import orjson

from ulpf.engine.views import apply_view
from ulpf.runtime.buffer import Segment

_OPT = orjson.OPT_NON_STR_KEYS


def dumps(obj: Any) -> bytes:
    return orjson.dumps(obj, default=str, option=_OPT)


def env_secret(name: str | None, what: str = "secret") -> str | None:
    """Read a secret from the environment variable a config names (never from the config itself)."""
    if not name:
        return None
    value = os.environ.get(name)
    if value is None:
        raise RuntimeError(f"environment variable {name} ({what}) is not set")
    return value


def client_ssl_context(tls: dict | None) -> ssl.SSLContext | None:
    tls = tls or {}
    ctx = ssl.create_default_context(cafile=tls.get("ca") or None)
    if tls.get("cert"):
        ctx.load_cert_chain(tls["cert"], tls.get("key") or None)
    if tls.get("verify") is False:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class Sink:
    ext = "ndjson"
    batch_segments = 1        # segments handed to deliver_many at once
    idempotent = False        # re-delivery cannot create duplicates downstream
    remote = False

    def __init__(self, name: str, options: dict, context: dict | None = None):
        self.name = name
        self.opts = options
        self.view = options.get("view", "unified")
        self.ctx = context or {}

    # ---- worker side --------------------------------------------------
    def encode(self, events: list[dict]) -> bytes:
        """Default: NDJSON of the configured view."""
        view = self.view
        return b"\n".join(dumps(apply_view(e, view)) for e in events) + b"\n"

    # ---- host side ----------------------------------------------------
    def open(self) -> None:
        pass

    def deliver(self, payload: bytes, seg: Segment) -> None:
        raise NotImplementedError

    def deliver_many(self, segs: list[Segment], read) -> None:
        for seg in segs:
            self.deliver(read(seg), seg)

    def records(self, payload: bytes) -> list[bytes]:
        """Split a payload into records (dead-letter granularity)."""
        return [l for l in payload.split(b"\n") if l]

    def health(self) -> dict:
        return {"ok": True}

    def close(self) -> None:
        pass
