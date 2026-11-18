"""Host-side delivery loop: one thread per sink."""
from __future__ import annotations

import logging
import threading
import time

import orjson

from ulpf.runtime.buffer import DiskBuffer, Segment
from ulpf.runtime.dlq import DeadLetterQueue
from ulpf.runtime.retry import Backoff, PermanentError, RetriableError
from ulpf.runtime.sinks.base import Sink

logger = logging.getLogger(__name__)


class SinkRunner(threading.Thread):
    def __init__(self, sink: Sink, buffer: DiskBuffer, dlq: DeadLetterQueue, watermark,
                 retry: dict, stop: threading.Event):
        super().__init__(name=f"ulpf-sink-{sink.name}", daemon=True)
        self.sink = sink
        self.buffer = buffer
        self.dlq = dlq
        self.watermark = watermark          # callable -> persisted commit seq
        self.retry = retry or {}
        self.stop_event = stop
        self.drain_deadline: float | None = None
        self.delivered_events = 0
        self.delivered_segments = 0
        self.dead_lettered = 0
        self.retries = 0
        self.last_error: str | None = None
        self.last_success: float | None = None
        self.healthy = True
        self._opened = False

    def _backoff(self) -> Backoff:
        return Backoff(self.retry.get("initial_ms", 500), self.retry.get("max_ms", 60_000),
                       self.retry.get("max_attempts", 0))

    def run(self) -> None:
        backoff = self._backoff()
        while True:
            if self.stop_event.is_set():
                if self.drain_deadline is None or time.monotonic() > self.drain_deadline:
                    break
            try:
                if not self._opened:
                    self.sink.open()
                    self._opened = True
                ready = self.buffer.ready(self.watermark())
            except Exception as e:
                self._fail(e, backoff)
                continue
            if not ready:
                if self.stop_event.is_set():
                    break
                time.sleep(0.05)
                continue
            batch = ready[:max(1, self.sink.batch_segments)]
            try:
                self.sink.deliver_many(batch, DiskBuffer.read)
            except PermanentError as e:
                if len(batch) > 1:
                    self._deliver_individually(batch, backoff)
                else:
                    self._dead_letter(batch[0], e, backoff.attempt + 1)
                backoff.reset()
                continue
            except Exception as e:  # RetriableError, OSError, timeouts, bugs
                if backoff.exhausted:
                    for seg in batch:
                        self._dead_letter(seg, e, backoff.attempt)
                    backoff.reset()
                else:
                    self._fail(e, backoff)
                continue
            for seg in batch:
                self._acked(seg)
            backoff.reset()
        try:
            self.sink.close()
        except Exception:
            logger.debug("sink close failed", exc_info=True)

    def _deliver_individually(self, batch: list[Segment], backoff: Backoff) -> None:
        for seg in batch:
            try:
                self.sink.deliver_many([seg], DiskBuffer.read)
                self._acked(seg)
            except PermanentError as e:
                self._dead_letter(seg, e, 1)
            except Exception as e:
                self._fail(e, backoff)
                return

    def _acked(self, seg: Segment) -> None:
        self.buffer.ack(seg)
        self.delivered_events += seg.count
        self.delivered_segments += 1
        self.last_success = time.time()
        self.healthy = True

    def _fail(self, e: Exception, backoff: Backoff) -> None:
        self.retries += 1
        self.healthy = False
        self.last_error = f"{type(e).__name__}: {e}"
        if not isinstance(e, (RetriableError, OSError, TimeoutError)):
            logger.warning(f"sink {self.sink.name}: unexpected delivery error", exc_info=True)
        delay = backoff.next_delay()
        if self.retries == 1 or self.retries % 20 == 0:
            logger.warning(f"sink {self.sink.name}: {self.last_error}; retrying in {delay:.1f}s")
        if self.stop_event.is_set():
            time.sleep(min(delay, 0.2))   # draining: keep trying until the deadline
        else:
            self.stop_event.wait(delay)

    def _dead_letter(self, seg: Segment, err: Exception, attempts: int) -> None:
        try:
            payload = DiskBuffer.read(seg)
            records = self.sink.records(payload)
        except OSError:
            records = []
        rejected = getattr(err, "rejected", None)
        reasons = getattr(err, "reasons", {}) or {}
        indexes = range(len(records)) if rejected is None else rejected
        out = []
        for i in indexes:
            if i >= len(records):
                continue
            rec = records[i]
            meta = {}
            try:
                doc = orjson.loads(rec.split(b"\n")[-1])     # bulk records: action line + document
                meta = {"event_id": doc.get("event_id") or (doc.get("event") or {}).get("id"),
                        "raw_hash": (doc.get("evidence") or {}).get("raw_hash")
                        or (doc.get("event") or {}).get("hash")}
            except (orjson.JSONDecodeError, TypeError, AttributeError):
                pass
            entry = {**meta, "record": rec.decode("utf-8", "replace")}
            if i in reasons:
                entry["reason_detail"] = reasons[i]
            out.append(entry)
        if rejected is None and not out:
            out.append({"record": f"<{seg.count} events in {seg.name}: binary segment>"})
        reason = f"{type(err).__name__}: {err}"
        self.dlq.write(self.sink.name, reason, out, attempts)
        self.dead_lettered += len(out)
        if rejected is not None:          # the rest of the segment was accepted
            self.delivered_events += max(0, seg.count - len(out))
        self.buffer.ack(seg)
        self.delivered_segments += 1
        self.last_error = reason
        logger.error(f"sink {self.sink.name}: {len(out)} event(s) from {seg.name} sent to the "
                     f"dead-letter queue: {reason}")

    def stats(self) -> dict:
        return {"delivered_events": self.delivered_events, "delivered_segments": self.delivered_segments,
                "dead_lettered": self.dead_lettered, "retries": self.retries, "healthy": self.healthy,
                "last_error": self.last_error, "last_success": self.last_success,
                "buffer": self.buffer.stats(), "health": self._safe_health()}

    def _safe_health(self) -> dict:
        try:
            return self.sink.health()
        except Exception as e:
            return {"ok": False, "error": str(e)}
