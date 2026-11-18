"""
The lakehouse of one output: hot ring, Delta table, and the background daemons.

* **Flusher**: moves hot records to the cold tier, one file per partition per flush, in one
  Delta commit that also records the ring position reached (``txn``), then marks the ring
  flushed. After a crash the position is taken from the table, so nothing is flushed twice.
* **Compactor**: merges a partition's small files (below ``min_mb``) into files of up to
  ``max_mb``, streaming batch by batch (bounded memory), and swaps them in with one commit that
  only succeeds if every input is still live. Recent partitions wait until ``min_mb`` worth of
  small files exist; partitions older than ``settle_minutes`` are compacted whatever their size.
* **Retention / vacuum**: drops partitions older than ``retention_days`` and deletes files
  removed more than ``vacuum_hours`` ago.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import logging
import os
import tempfile
import threading
import time

import pyarrow as pa

from ulpf.lake.crypto import LakeKey
from ulpf.lake.delta import DeltaTable
from ulpf.lake.files import dek_of, parquet_file, write_file
from ulpf.lake.hot import HotTier
from ulpf.lake.query import LakeQuery
from ulpf.lake.schema import DATA_SCHEMA, PARTITION_COLUMNS
from ulpf.lake.store import open_store

logger = logging.getLogger(__name__)
_SERVICES: dict[str, "LakeService"] = {}
_LOCK = threading.Lock()
BATCH_BYTES = 32 << 20          # rows held in memory per output row group while compacting
FLUSH_THREADS = 4               # partitions written in parallel (Parquet encoding releases the GIL)


def get(name: str) -> "LakeService | None":
    return _SERVICES.get(name)


class LakeService:
    def __init__(self, name: str, opts: dict, data_dir: str, node_id: str = "node"):
        self.name, self.opts = name, opts
        self.key = LakeKey.from_env(opts["encryption"]["key_env"]) if (opts.get("encryption") or {}).get("key_env") else None
        self.store = open_store(opts["storage"])
        self.table = DeltaTable(self.store, self.key)
        if not self.table.exists():
            self.table.create(pa.schema(list(DATA_SCHEMA) + [pa.field(c, pa.string()) for c in PARTITION_COLUMNS]),
                              list(PARTITION_COLUMNS), name)
        hot = opts.get("hot") or {}
        self.work = os.path.join(data_dir, "lakehouse", name)
        os.makedirs(self.work, exist_ok=True)
        self.hot = HotTier(hot.get("path") or os.path.join(self.work, "hot.ring"), int(hot.get("capacity_mb", 1024)) << 20)
        self.app_id = "ulpf-hot-" + hashlib.sha256(f"{node_id}|{name}|{os.path.abspath(self.hot.path)}".encode()).hexdigest()[:16]
        done = self.table.snapshot().txns.get(self.app_id, 0)
        if done > self.hot.ring.flushed:
            self.hot.mark_flushed(done)          # committed before a crash, ring not yet marked
        self.flush_bytes = int(opts.get("flush_mb", 64)) << 20
        self.flush_seconds = float(opts.get("flush_seconds", 60))
        c = opts.get("compaction") or {}
        self.compaction = c.get("enabled", True)
        self.min_bytes = int(c.get("min_mb", 128)) << 20
        self.max_bytes = int(c.get("max_mb", 512)) << 20
        self.settle = float(c.get("settle_minutes", 90)) * 60
        self.compact_interval = float(c.get("interval_seconds", 300))
        self.retention_days = int(opts.get("retention_days") or 0)
        self.vacuum_hours = float(opts.get("vacuum_hours", 24))
        self.tmp = os.path.join(self.work, "tmp")
        os.makedirs(self.tmp, exist_ok=True)
        self.query = LakeQuery(self.table, self.key, self.hot, self.app_id, os.path.join(self.work, "cache"),
                               int(opts.get("cache_mb", 2048)) << 20, int(opts.get("query_memory_mb", 256)))
        self.stats = {"flushes": 0, "flushed_rows": 0, "files_written": 0, "compactions": 0, "compacted_files": 0,
                      "vacuumed_files": 0, "errors": 0}
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._first_unflushed: float | None = None
        self._commit_lock = threading.Lock()
        self.flight = None

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> "LakeService":
        with _LOCK:
            _SERVICES[self.name] = self
        for target, nm in ((self._flush_loop, "flush"), (self._compact_loop, "compact")):
            t = threading.Thread(target=target, name=f"lake-{self.name}-{nm}", daemon=True)
            t.start()
            self._threads.append(t)
        fl = self.opts.get("flight") or {}
        if fl.get("enabled"):
            from ulpf.lake.flight import start_flight
            self.flight = start_flight(self, fl)
        return self

    def stop(self, timeout: float = 30.0) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout)
        try:
            self.flush_once()
        except Exception:
            logger.warning(f"lakehouse {self.name}: final flush failed", exc_info=True)
        if self.flight is not None:
            self.flight.shutdown()
        with _LOCK:
            _SERVICES.pop(self.name, None)

    # ------------------------------------------------------------------ flush

    def _flush_loop(self) -> None:
        while not self._stop.wait(1.0):
            try:
                pending = self.hot.ring.head - self.hot.ring.flushed
                if pending <= 0:
                    self._first_unflushed = None
                    continue
                now = time.monotonic()
                self._first_unflushed = self._first_unflushed or now
                if pending >= self.flush_bytes or now - self._first_unflushed >= self.flush_seconds \
                        or self.hot.free() < self.hot.ring.capacity // 4:
                    self.flush_once()
            except Exception:
                self.stats["errors"] += 1
                logger.warning(f"lakehouse {self.name}: flush failed", exc_info=True)
                self._stop.wait(5)

    def flush_once(self) -> int:
        """Flush hot records up to the current head (in chunks of ``flush_mb``). Returns rows."""
        total = 0
        start, head = self.hot.ring.flushed, self.hot.ring.head
        while start < head:
            recs, end, _ = self.hot.read(start, self.flush_bytes)
            by_part: dict[str, list[pa.Table]] = {}
            for _p, part, t in recs:
                by_part.setdefault(part, []).append(t)
            def one(item):
                part, tables = item
                tenant, date, hour = part.split("/")
                t = pa.concat_tables(tables).select(DATA_SCHEMA.names)
                return write_file(self.store, self.key, tenant, date, hour, [t], t.num_rows, self.tmp, level=1), t.num_rows
            items = list(by_part.items())
            if len(items) > 1:
                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(min(FLUSH_THREADS, len(items))) as ex:
                    written = list(ex.map(one, items))
            else:
                written = [one(i) for i in items]
            del recs, by_part, items
            adds = [{"add": a} for a, _n in written if a]
            total += sum(n for a, n in written if a)

            def build(snap, adds=adds, end=end):
                if snap.txns.get(self.app_id, 0) >= end:
                    return None
                return adds + [{"txn": {"appId": self.app_id, "version": end, "lastUpdated": int(time.time() * 1000)}}]
            with self._commit_lock:
                self.table.commit_with_retry(build, "WRITE")
            self.hot.mark_flushed(end)
            self.stats["flushes"] += 1
            self.stats["files_written"] += len(adds)
            start = end
        self.stats["flushed_rows"] += total
        pa.default_memory_pool().release_unused()       # return the flush's buffers to the OS
        return total

    # ------------------------------------------------------------------ compaction

    def _compact_loop(self) -> None:
        last_maint = 0.0
        while not self._stop.wait(self.compact_interval):
            try:
                if self.compaction:
                    self.compact_once()
                if time.monotonic() - last_maint > 3600:
                    self.retention_once()
                    self.vacuum_once()
                    last_maint = time.monotonic()
            except Exception:
                self.stats["errors"] += 1
                logger.warning(f"lakehouse {self.name}: compaction failed", exc_info=True)

    def _local(self, add: dict) -> tuple[str, bool]:
        root = self.store.local_root
        if root:
            return os.path.join(root, *add["path"].split("/")), False
        fd, tmp = tempfile.mkstemp(suffix=".parquet", dir=self.tmp)
        os.close(fd)
        self.store.get_file(add["path"], tmp)
        return tmp, True

    def compact_once(self, force: bool = False) -> int:
        """Compact every partition that qualifies; returns the number of files replaced."""
        snap = self.table.snapshot()
        parts: dict[tuple, list[dict]] = {}
        for a in snap.files.values():
            pv = a["partitionValues"]
            parts.setdefault((pv["tenant_id"], pv["date"], pv["hour"]), []).append(a)
        now = _dt.datetime.now(_dt.timezone.utc)
        replaced = 0
        for (tenant, date, hour), files in sorted(parts.items()):
            small = sorted((a for a in files if a["size"] < self.min_bytes), key=lambda a: a["path"])
            if len(small) < 2:
                continue
            try:
                hour_end = _dt.datetime.strptime(f"{date} {hour}", "%Y-%m-%d %H").replace(
                    tzinfo=_dt.timezone.utc) + _dt.timedelta(hours=1)
                settled = (now - hour_end).total_seconds() >= self.settle
            except ValueError:
                settled = True
            if not (force or settled or sum(a["size"] for a in small) >= self.min_bytes):
                continue
            groups, cur, size = [], [], 0
            for a in small:
                if cur and size + a["size"] > self.max_bytes:
                    groups.append(cur)
                    cur, size = [], 0
                cur.append(a)
                size += a["size"]
            groups.append(cur)
            for g in groups:
                if len(g) >= 2:
                    replaced += self._compact_group(tenant, date, hour, g)
        return replaced

    def _compact_group(self, tenant: str, date: str, hour: str, group: list[dict]) -> int:
        import json
        rows = sum(json.loads(a["stats"])["numRecords"] for a in group)

        def batches():
            pending, nbytes = [], 0
            for a in group:
                local, temp = self._local(a)
                try:
                    pf = parquet_file(local, dek_of(a, self.key))
                    for b in pf.iter_batches(batch_size=8192):
                        pending.append(b)
                        nbytes += b.nbytes
                        if nbytes >= BATCH_BYTES:
                            yield pa.Table.from_batches(pending)      # one row group, no copy
                            pending, nbytes = [], 0
                    del pf
                finally:
                    if temp:
                        os.unlink(local)
            if pending:
                yield pa.Table.from_batches(pending)

        new = write_file(self.store, self.key, tenant, date, hour, batches(), rows, self.tmp, data_change=False)
        paths = {a["path"] for a in group}
        ts = int(time.time() * 1000)

        def build(snap):
            if not paths.issubset(snap.files):
                return None                          # an input was removed meanwhile
            out = [{"remove": {"path": p, "deletionTimestamp": ts, "dataChange": False, "extendedFileMetadata": True,
                               "partitionValues": snap.files[p]["partitionValues"], "size": snap.files[p]["size"]}}
                   for p in sorted(paths)]
            return out + ([{"add": new}] if new else [])
        with self._commit_lock:
            v = self.table.commit_with_retry(build, "OPTIMIZE")
        if v is None:
            if new:
                self.store.delete(new["path"])
                self.store.delete(new["tags"]["ulpf.bloom"])
            return 0
        self.stats["compactions"] += 1
        self.stats["compacted_files"] += len(group)
        pa.default_memory_pool().release_unused()
        return len(group)

    # ------------------------------------------------------------------ retention / vacuum

    def retention_once(self) -> int:
        if self.retention_days <= 0:
            return 0
        cutoff = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=self.retention_days)).strftime("%Y-%m-%d")
        ts = int(time.time() * 1000)

        def build(snap):
            old = [a for a in snap.files.values() if a["partitionValues"]["date"] < cutoff]
            return [{"remove": {"path": a["path"], "deletionTimestamp": ts, "dataChange": True,
                                "extendedFileMetadata": True, "partitionValues": a["partitionValues"],
                                "size": a["size"]}} for a in old]
        with self._commit_lock:
            v = self.table.commit_with_retry(build, "DELETE")
        return 0 if v is None else 1

    def vacuum_once(self) -> int:
        snap = self.table.snapshot()
        cutoff = (time.time() - self.vacuum_hours * 3600) * 1000
        n = 0
        for p, r in list(snap.removed.items()):
            if r.get("deletionTimestamp", 0) < cutoff and self.store.exists(p):
                self.store.delete(p)
                self.store.delete(f"_ulpf_bloom/{p}.ublm")
                n += 1
        self.stats["vacuumed_files"] += n
        return n

    # ------------------------------------------------------------------ status

    def status(self) -> dict:
        snap = self.table.snapshot()
        return {"name": self.name, "hot": self.hot.stats(), "table_version": snap.version,
                "files": len(snap.files), "bytes": sum(a["size"] for a in snap.files.values()),
                "encrypted": self.key is not None, **self.stats}
