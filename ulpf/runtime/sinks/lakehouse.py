"""
Lakehouse output: events into the hot tier (mmap Arrow ring), flushed and compacted into a
Delta Lake table (local, S3 / MinIO / Ceph, Azure), queried across both tiers with DuckDB or
Arrow Flight. See ``ulpf.lake``.

Workers encode Arrow IPC (lake schema + tenant/date/hour); the host appends each segment to the
ring. A full ring (the cold tier is behind) is a retriable error: the segment stays in the disk
buffer and ingestion backs off, nothing is dropped.
"""
from __future__ import annotations

from ulpf.runtime.buffer import Segment
from ulpf.runtime.retry import RetriableError
from ulpf.runtime.sinks.base import Sink


class LakehouseSink(Sink):
    ext = "arrow"
    idempotent = True          # ring keys dedupe a redelivered segment
    batch_segments = 32        # one ring sync per batch

    def __init__(self, name, options, context=None):
        super().__init__(name, options, context)
        self.tenant = options.get("tenant", "default")
        self.by_input = options.get("tenant_by_input") or {}
        self.service = None

    def _tenant(self, e: dict) -> str:
        return self.by_input.get((e.get("metadata") or {}).get("input"), self.tenant)

    # ---- worker side
    def encode(self, events: list[dict]) -> bytes:
        import pyarrow as pa
        from ulpf.lake import hot, schema
        rows = schema.rows(events, self._tenant)
        if self.view != "unified":
            import orjson
            from ulpf.engine.views import apply_view
            for r, e in zip(rows, events):
                r["event_json"] = orjson.dumps(apply_view(e, self.view), default=str).decode("utf-8")
        return hot.encode_framed(pa.Table.from_pylist(rows, schema=schema.SCHEMA))

    def records(self, payload: bytes) -> list[bytes]:
        from ulpf.lake import hot
        try:
            return [v.encode() for _k, ipc in hot.iter_framed(payload)
                    for v in hot.decode(ipc).column("event_json").to_pylist() if v]
        except ValueError:
            return [payload]

    # ---- host side
    def open(self) -> None:
        if self.service is None:
            from ulpf.lake.service import LakeService
            self.service = LakeService(self.name, self.opts, self.ctx.get("data_dir") or ".").start()

    def deliver_many(self, segs: list[Segment], read) -> None:
        """Append every segment, then one msync before the runner acknowledges them. On an
        error the whole batch is retried; segments already in the ring are skipped then."""
        try:
            for seg in segs:
                self._append(read(seg), seg)
        finally:
            self.service.hot.sync()

    def deliver(self, payload: bytes, seg: Segment) -> None:
        self._append(payload, seg)
        self.service.hot.sync()

    def _append(self, payload: bytes, seg: Segment) -> None:
        try:
            ok = self.service.hot.append_framed(payload, seg.name)
        except ValueError as e:
            from ulpf.runtime.retry import PermanentError
            raise PermanentError(f"lakehouse: malformed segment {seg.name}: {e}") from None
        if not ok:
            raise RetriableError("lakehouse hot tier full: waiting for the flusher")

    def health(self) -> dict:
        if self.service is None:
            return {"ok": False, "error": "not open"}
        st = self.service.status()
        return {"ok": st["errors"] == 0 or st["flushes"] > 0, **st}

    def close(self) -> None:
        if self.service is not None:
            self.service.stop()
            self.service = None
