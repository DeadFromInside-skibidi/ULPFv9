"""Local file outputs: NDJSON (rotated, optional gzip) and a partitioned Parquet data lake."""
from __future__ import annotations

import gzip
import io
import os
import time

from ulpf.runtime.buffer import Segment
from ulpf.runtime.sinks.base import Sink


class NdjsonFileSink(Sink):
    ext = "ndjson"
    batch_segments = 64

    def __init__(self, name, options, context=None):
        super().__init__(name, options, context)
        self.dir = options["path"]
        self.rotate_bytes = int(options.get("rotate_mb", 128) * 2**20)
        self.rotate_seconds = options.get("rotate_seconds", 300)
        self.gzip = options.get("compress") == "gzip"
        self._path: str | None = None
        self._opened_at = 0.0

    def open(self) -> None:
        os.makedirs(self.dir, exist_ok=True)

    def _target(self) -> str:
        now = time.time()
        if (self._path is None or now - self._opened_at > self.rotate_seconds
                or (os.path.exists(self._path) and os.path.getsize(self._path) > self.rotate_bytes)):
            stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime(now))
            self._path = os.path.join(self.dir, f"{self.name}-{stamp}-{time.time_ns() % 10**9:09d}"
                                      f".ndjson{'.gz' if self.gzip else ''}")
            self._opened_at = now
        return self._path

    def deliver_many(self, segs: list[Segment], read) -> None:
        data = b"".join(read(s) for s in segs)
        if self.gzip:
            data = gzip.compress(data)   # appended gzip members form a valid stream
        with open(self._target(), "ab") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

    def health(self) -> dict:
        return {"ok": os.path.isdir(self.dir), "current_file": self._path}


class ParquetSink(Sink):
    """Writes Parquet files under <path>/<partition=value>/..., one file per delivery batch."""

    ext = "parquet"
    batch_segments = 256
    idempotent = True

    def __init__(self, name, options, context=None):
        super().__init__(name, options, context)
        self.dir = options["path"]
        self.partition = list(options.get("partition") or ["dt"])
        self.rotate_bytes = int(options.get("rotate_mb", 128) * 2**20)

    def encode(self, events: list[dict]) -> bytes:
        from ulpf.runtime.sinks.lake import encode_lake
        return encode_lake(events, self.view)

    def open(self) -> None:
        os.makedirs(self.dir, exist_ok=True)

    def deliver_many(self, segs: list[Segment], read) -> None:
        from ulpf.runtime.sinks.lake import partitioned_tables
        import pyarrow.parquet as pq
        import pyarrow as pa
        # Group consecutive segments into files of at most rotate_mb
        group: list[Segment] = []
        size = 0
        for seg in segs:
            if group and size + seg.size > self.rotate_bytes:
                self._write_group(group, read, pq, pa, partitioned_tables)
                group, size = [], 0
            group.append(seg)
            size += seg.size
        if group:
            self._write_group(group, read, pq, pa, partitioned_tables)

    def _write_group(self, group, read, pq, pa, partitioned_tables) -> None:
        tables = [pq.read_table(io.BytesIO(read(s))) for s in group]
        table = pa.concat_tables(tables, promote_options="default")
        # Deterministic name: re-delivery after a crash overwrites instead of duplicating
        stem = f"{self.name}-{group[0].name.split('.')[0]}-{len(group)}"
        for rel, part in partitioned_tables(table, self.partition):
            d = os.path.join(self.dir, rel)
            os.makedirs(d, exist_ok=True)
            path = os.path.join(d, stem + ".parquet")
            tmp = path + ".tmp"
            pq.write_table(part, tmp, compression="zstd")
            os.replace(tmp, path)

    def records(self, payload: bytes) -> list[bytes]:
        import orjson
        import pyarrow.parquet as pq
        return [orjson.dumps(r, default=str) for r in pq.read_table(io.BytesIO(payload)).to_pylist()]

    def health(self) -> dict:
        return {"ok": os.path.isdir(self.dir), "path": self.dir}
