"""The local DuckDB event store as a sink (Parquet segments, exactly-once ingest)."""
from __future__ import annotations

import io

from ulpf.runtime.buffer import Segment
from ulpf.runtime.sinks.base import Sink


def _rows(events: list[dict], row_key=None) -> list[tuple]:
    from ulpf.storage.database import event_to_row, sign_row

    rows = [event_to_row(e) for e in events]
    if isinstance(row_key, (bytes, bytearray)):
        rows = [sign_row(row_key, r) for r in rows]
    elif row_key is not None:
        signed = []
        for e, r in zip(events, rows):
            seq = (e.get("evidence") or {}).get("journal_seq")
            # derived events (seals, correlations) carry no journal sequence: newest epoch key
            k = row_key.key_for_seq(seq) if seq is not None else row_key.current
            signed.append(sign_row(k, r) if k is not None else r)
        rows = signed
    return rows


# Segments are read whole by DuckDB: column statistics are never used, and only the
# low-cardinality columns benefit from dictionary pages (measured ~19 % faster to write)
_DICT_COLUMNS = ["category", "action", "severity_label", "raw_format", "protocol", "device_vendor",
                 "device_product", "event_type"]


def _write(table) -> bytes:
    import pyarrow.parquet as pq
    buf = io.BytesIO()
    pq.write_table(table, buf, compression="lz4", write_statistics=False, use_dictionary=_DICT_COLUMNS)
    return buf.getvalue()


def encode_parquet(events: list[dict], row_key=None) -> bytes:
    """``row_key``: a static key (bytes) or a ``keys.RowKeyChain`` (key chosen by journal sequence)."""
    from ulpf.storage.database import rows_to_arrow

    return _write(rows_to_arrow(_rows(events, row_key)))


def encode_mixed(native_table, native_idx: list[int], py_events: list[tuple[int, dict]], row_key=None) -> bytes:
    """One segment from rows the compiled core built and events of the Python path, in record order."""
    import pyarrow as pa
    from ulpf.storage.database import rows_to_arrow

    table, order = native_table, list(native_idx)
    if py_events:
        table = pa.concat_tables([table, rows_to_arrow(_rows([e for _, e in py_events], row_key))])
        order += [i for i, _ in py_events]
        if any(order[k] > order[k + 1] for k in range(len(order) - 1)):
            table = table.take(sorted(range(len(order)), key=order.__getitem__))
        # else: already in record order (e.g. derived events after the batch's records)
    return _write(table)


class DuckDBSink(Sink):
    ext = "parquet"
    batch_segments = 128    # one transaction (one WAL sync) for up to 128 segments
    idempotent = True

    def __init__(self, name, options, context=None):
        super().__init__(name, options, context)
        self.db = None
        self.stored = 0

    def encode(self, events: list[dict]) -> bytes:
        # The store keeps the unified schema; views apply to external outputs
        return encode_parquet(events, self.ctx.get("row_key"))

    def open(self) -> None:
        if self.db is None:
            self.db = self.ctx.get("database")
            if self.db is None:
                from ulpf.storage import create_storage
                o = self.opts
                self.db = create_storage(path=o.get("path"), partition=o.get("partition") or "none",
                                         partition_max_mb=o.get("partition_max_mb") or None,
                                         retention_days=o.get("retention_days"),
                                         archive_dir=o.get("archive_dir"),
                                         archive_format=o.get("archive_format") or "duckdb")
                self.ctx["database"] = self.db
            self.db._require_writable()
            if self.ctx.get("mode") == "defence" and not getattr(self.db, "locked_down", False):
                self.db.lock_down([self.ctx.get("data_dir")])
            self.db.prune_segment_ledger()

    def deliver_many(self, segs: list[Segment], read) -> None:
        self.stored += self.db.ingest_segments([s.path for s in segs], [f"{self.name}/{s.name}" for s in segs])

    def records(self, payload: bytes) -> list[bytes]:
        import pyarrow.parquet as pq
        import orjson
        table = pq.read_table(io.BytesIO(payload))
        return [orjson.dumps(r, default=str) for r in table.to_pylist()]

    def health(self) -> dict:
        return {"ok": self.db is not None and not self.db.read_only,
                "path": getattr(self.db, "db_path", None), "stored": self.stored}

    def close(self) -> None:
        pass  # the runtime owns the database connection and closes it last
