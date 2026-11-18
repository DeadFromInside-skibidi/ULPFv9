"""
Hot tier: Arrow IPC record batches in a memory-mapped ring on local NVMe (``ulpf_core.HotRing``).

One ring record per (buffer segment, partition): key ``tenant/date/hour|segment``, payload an
Arrow IPC stream of SCHEMA rows. A segment's records are appended together or not at all (the
free space is checked first; the ring has a single writer), and keys already in the ring are
skipped, so a segment redelivered after a crash is not stored twice while its records are
still in the ring. Readers decode only the partitions they ask for.
"""
from __future__ import annotations

import os
import struct

import pyarrow as pa
import pyarrow.compute as pc

from ulpf.lake.schema import SCHEMA, partition_key

REC_OVERHEAD = 32


def encode(table: pa.Table) -> bytes:
    sink = pa.BufferOutputStream()
    with pa.ipc.new_stream(sink, table.schema) as w:
        w.write_table(table)
    return sink.getvalue().to_pybytes()


def decode(payload: bytes) -> pa.Table:
    return pa.ipc.open_stream(payload).read_all()


FRAMED = b"ULH1"


def encode_framed(table: pa.Table) -> bytes:
    """A segment payload already split by partition (done in the worker): ``ULH1`` then
    ``key_len u32 | key | ipc_len u64 | ipc`` per partition."""
    out = [FRAMED]
    for k, t in split_partitions(table):
        kb, ipc = k.encode(), encode(t)
        out += [struct.pack("<I", len(kb)), kb, struct.pack("<Q", len(ipc)), ipc]
    return b"".join(out)


def iter_framed(payload: bytes):
    """(partition key, ipc bytes) of a framed payload; ValueError if malformed."""
    if payload[:4] != FRAMED:
        raise ValueError("not a framed lakehouse payload")
    p, n = 4, len(payload)
    while p < n:
        if p + 4 > n:
            raise ValueError("truncated frame")
        (kl,) = struct.unpack_from("<I", payload, p)
        if kl > 4096 or p + 4 + kl + 8 > n:
            raise ValueError("bad frame key")
        key = payload[p + 4:p + 4 + kl].decode()
        (pl,) = struct.unpack_from("<Q", payload, p + 4 + kl)
        start = p + 12 + kl
        if start + pl > n:
            raise ValueError("truncated frame")
        yield key, payload[start:start + pl]
        p = start + pl


def split_partitions(table: pa.Table):
    """Yield (partition key, sub-table) per tenant/date/hour."""
    combos = table.select(["tenant_id", "date", "hour"]).group_by(["tenant_id", "date", "hour"]).aggregate([])
    for c in combos.to_pylist():
        mask = pc.and_(pc.and_(pc.equal(table["tenant_id"], c["tenant_id"]), pc.equal(table["date"], c["date"])),
                       pc.equal(table["hour"], c["hour"]))
        yield partition_key(c["tenant_id"], c["date"], c["hour"]), table.filter(mask)


class HotTier:
    def __init__(self, path: str, capacity_bytes: int):
        from ulpf.ulpf_core import HotRing
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.path = path
        self.ring = HotRing(path, capacity_bytes)
        self._seen: dict[str, None] = {}           # insertion-ordered: trimming drops the oldest
        pos = self.ring.tail
        while pos < self.ring.head:                 # keys still in the ring (redelivery check)
            recs, pos, _ = self.ring.read(pos, 64 << 20)
            self._seen.update((r[2], None) for r in recs)

    def free(self) -> int:
        r = self.ring
        return r.capacity - (r.head - r.flushed)

    def append(self, table: pa.Table, segment: str) -> bool:
        """Append a segment's rows; False when the ring has no room (nothing appended)."""
        return self._append([(f"{k}|{segment}", encode(t)) for k, t in split_partitions(table)])

    def append_framed(self, payload: bytes, segment: str) -> bool:
        """``append`` for a payload the worker already split (``encode_framed``): no decoding."""
        return self._append([(f"{k}|{segment}", ipc) for k, ipc in iter_framed(payload)])

    def _append(self, parts: list) -> bool:
        parts = [(k, p) for k, p in parts if k not in self._seen]
        need = sum(len(k) + len(p) + REC_OVERHEAD for k, p in parts)
        biggest = max((len(k) + len(p) + REC_OVERHEAD for k, p in parts), default=0)
        if need + biggest > self.free():           # a wrap can waste up to one record
            return False
        for k, p in parts:
            if self.ring.append(k, p) is None:
                raise RuntimeError("hot tier: ring full after the free-space check (second writer?)")
            self._seen[k] = None
        if len(self._seen) > 1_000_000:
            self._seen = dict.fromkeys(list(self._seen)[-100_000:])
        return True

    def read(self, pos: int, max_bytes: int = 64 << 20, want=None):
        """Records from ``pos``: ([(pos, partition key, table)], next pos, skipped bytes).
        ``want(partition_key) -> bool`` filters before decoding."""
        recs, nxt, skipped = self.ring.read(pos, max_bytes)
        out = []
        for p, _seq, key, payload in recs:
            part = key.split("|", 1)[0]
            if want is None or want(part):
                out.append((p, part, decode(payload)))
        return out, nxt, skipped

    def sync(self) -> None:
        self.ring.sync()

    def mark_flushed(self, pos: int) -> None:
        self.ring.set_flushed(pos)

    def stats(self) -> dict:
        r = self.ring
        return {"path": self.path, "capacity": r.capacity, "head": r.head, "tail": r.tail, "flushed": r.flushed,
                "unflushed_bytes": r.head - r.flushed}


def empty() -> pa.Table:
    return SCHEMA.empty_table()
