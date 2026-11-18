"""
Cold-tier data files: one Parquet file per partition per flush or compaction output.

Written with zstd, dictionary encoding, column statistics and page indexes (row-group and page
zonemaps). Encrypted tables use Parquet modular encryption (AES_GCM_V1) under a per-file DEK;
plain tables also get Parquet bloom filters (Arrow cannot write both). Either way each file has
a ULPF bloom sidecar under ``_ulpf_bloom/`` (sealed with the DEK when encrypted) for file-level
pruning on ``BLOOM_COLUMNS``, and Delta ``stats`` (min/max/nulls on ``STATS_COLUMNS``).
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import struct
import tempfile
import time
import uuid

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

from ulpf.lake.crypto import LakeKey, open_sealed, seal
from ulpf.lake.schema import BLOOM_COLUMNS, DATA_SCHEMA, STATS_COLUMNS, partition_dir
from ulpf.lake.store import Store

ROW_GROUP_ROWS = 256 * 1024
BLOOM_FPP = 0.01


def _bloom_cls():
    from ulpf.ulpf_core import Bloom
    return Bloom


def _stat_value(k, v):
    if k == "timestamp":            # epoch milliseconds (no tz database needed)
        t = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc) + _dt.timedelta(milliseconds=v)
        return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"
    return v


class _Stats:
    def __init__(self):
        self.n = 0
        self.min: dict = {}
        self.max: dict = {}
        self.nulls: dict = {c: 0 for c in STATS_COLUMNS + BLOOM_COLUMNS}

    def add(self, batch: pa.RecordBatch) -> None:
        self.n += batch.num_rows
        for c in self.nulls:
            col = batch.column(c)
            self.nulls[c] += col.null_count
            if c in STATS_COLUMNS and col.null_count < len(col):
                if pa.types.is_timestamp(col.type):
                    col = col.cast(pa.int64())
                mm = pc.min_max(col)
                lo, hi = mm["min"].as_py(), mm["max"].as_py()
                if c not in self.min or lo < self.min[c]:
                    self.min[c] = lo
                if c not in self.max or hi > self.max[c]:
                    self.max[c] = hi

    def json(self) -> str:
        return json.dumps({"numRecords": self.n,
                           "minValues": {k: _stat_value(k, v) for k, v in self.min.items()},
                           "maxValues": {k: _stat_value(k, v) for k, v in self.max.items()},
                           "nullCount": self.nulls}, separators=(",", ":"))


def _encode_blooms(blooms: dict) -> bytes:
    parts = [(c, b.to_bytes()) for c, b in blooms.items()]
    head = json.dumps({c: len(d) for c, d in parts}).encode()
    return struct.pack("<I", len(head)) + head + b"".join(d for _, d in parts)


def decode_blooms(blob: bytes) -> dict:
    Bloom = _bloom_cls()
    (n,) = struct.unpack("<I", blob[:4])
    head = json.loads(blob[4:4 + n])
    out, off = {}, 4 + n
    for c, size in head.items():
        out[c] = Bloom.from_bytes(blob[off:off + size])
        off += size
    return out


def write_file(store: Store, key: LakeKey | None, tenant: str, date: str, hour: str, batches, ndv: int,
               tmp_dir: str | None = None, data_change: bool = True, level: int = 3) -> dict | None:
    """Write ``batches`` (DATA_SCHEMA record batches or tables, one row group each) as one file
    of the partition; returns its Delta add action (None when there were no rows). ``level``:
    zstd level (flushes use 1, compaction rewrites them at 3)."""
    Bloom = _bloom_cls()
    path = f"{partition_dir(tenant, date, hour)}/part-{uuid.uuid4().hex}.zstd.parquet"
    dek = LakeKey.new_dek() if key is not None else None
    opts = dict(compression="zstd", compression_level=level, use_dictionary=True, write_statistics=True,
                write_page_index=True)
    if dek is not None:
        from pyarrow._parquet_encryption import create_encryption_properties
        opts["encryption_properties"] = create_encryption_properties(dek)
    else:
        opts["bloom_filter_options"] = {c: {"ndv": max(ndv, 1), "fpp": BLOOM_FPP} for c in BLOOM_COLUMNS}
    blooms = {c: Bloom(max(ndv, 1), BLOOM_FPP) for c in BLOOM_COLUMNS}
    stats = _Stats()
    fd, tmp = tempfile.mkstemp(suffix=".parquet", dir=tmp_dir)
    os.close(fd)
    try:
        w = pq.ParquetWriter(tmp, DATA_SCHEMA, **opts)
        try:
            for b in batches:
                if b.num_rows == 0:
                    continue
                b = b.select(DATA_SCHEMA.names) if b.schema.names != DATA_SCHEMA.names else b
                if isinstance(b, pa.Table):
                    w.write_table(b, row_group_size=b.num_rows)
                    parts = b.to_batches()
                else:
                    w.write_batch(b, row_group_size=ROW_GROUP_ROWS)
                    parts = [b]
                for x in parts:
                    stats.add(x)
                    for c in BLOOM_COLUMNS:
                        blooms[c].add_many(x.column(c))      # Arrow buffers read in Rust
        finally:
            w.close()
        if stats.n == 0:
            return None
        size = os.path.getsize(tmp)
        store.put_file(path, tmp)
    finally:
        os.unlink(tmp)
    sidecar = f"_ulpf_bloom/{path}.ublm"
    blob = _encode_blooms(blooms)
    store.put(sidecar, seal(dek, blob, f"bloom|{path}".encode()) if dek is not None else blob)
    tags = {"ulpf.bloom": sidecar}
    if dek is not None:
        tags["ulpf.dek"] = key.wrap(dek, path)
    return {"path": path, "partitionValues": {"tenant_id": tenant, "date": date, "hour": hour},
            "size": size, "modificationTime": int(time.time() * 1000), "dataChange": data_change,
            "stats": stats.json(), "tags": tags}


def dek_of(add: dict, key: LakeKey | None) -> bytes | None:
    w = (add.get("tags") or {}).get("ulpf.dek")
    if w is None:
        return None
    if key is None:
        raise PermissionError(f"{add['path']} is encrypted: the lakehouse master key is required")
    return key.unwrap(w, add["path"])


def read_blooms(store: Store, add: dict, key: LakeKey | None) -> dict | None:
    side = (add.get("tags") or {}).get("ulpf.bloom")
    if not side:
        return None
    try:
        blob = store.get(side)
    except KeyError:
        return None
    dek = dek_of(add, key)
    if dek is not None:
        blob = open_sealed(dek, blob, f"bloom|{add['path']}".encode())
    return decode_blooms(blob)


def parquet_file(local_path: str, dek: bytes | None) -> pq.ParquetFile:
    if dek is None:
        return pq.ParquetFile(local_path)
    from pyarrow._parquet_encryption import create_decryption_properties
    return pq.ParquetFile(local_path, decryption_properties=create_decryption_properties(dek))
