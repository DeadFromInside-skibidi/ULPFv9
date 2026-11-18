"""
Federated queries over the hot and cold tiers with DuckDB.

Pruning, in order: partitions (tenant, date/hour range), Delta file statistics (timestamp
min/max), file bloom sidecars (equality on source_ip / destination_ip / user_name / hash_sha256),
then DuckDB itself (row-group and page zonemaps, Parquet blooms). Hot records are read from the
ring position the cold snapshot's ``txn`` names, so each record is counted once.

The caller's SQL runs over a view ``events`` in a sandboxed connection: file access is limited
to the table and cache directories, external access is then switched off and the configuration
locked, and memory is capped.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import threading
import time
from collections import OrderedDict

import duckdb
import pyarrow as pa

from ulpf.lake.delta import DeltaTable
from ulpf.lake.files import dek_of, read_blooms
from ulpf.lake.schema import BLOOM_COLUMNS, DATA_SCHEMA, SCHEMA

MAX_FILES = 5000
_IDENT = {f.name for f in SCHEMA}


def _hour_bounds(date: str, hour: str):
    try:
        t = _dt.datetime.strptime(f"{date} {hour}", "%Y-%m-%d %H").replace(tzinfo=_dt.timezone.utc)
    except ValueError:
        return None
    return t, t + _dt.timedelta(hours=1)


def _parse_stat_ts(v):
    if not v:
        return None
    return _dt.datetime.fromisoformat(v.replace("Z", "+00:00"))


class _Cache:
    """Local copies of remote data files, bounded by bytes (least recently used evicted)."""

    def __init__(self, store, root: str, max_bytes: int):
        self.store, self.root, self.max = store, root, max_bytes
        self.files: OrderedDict[str, int] = OrderedDict()
        self.lock = threading.Lock()
        os.makedirs(root, exist_ok=True)

    def path(self, key: str, size: int) -> str:
        local = os.path.join(self.root, *key.split("/"))
        with self.lock:
            if key in self.files and os.path.exists(local):
                self.files.move_to_end(key)
                return local
        os.makedirs(os.path.dirname(local), exist_ok=True)
        tmp = local + ".part"
        self.store.get_file(key, tmp)
        os.replace(tmp, local)
        with self.lock:
            self.files[key] = size
            while sum(self.files.values()) > self.max and len(self.files) > 1:
                old, _ = self.files.popitem(last=False)
                try:
                    os.unlink(os.path.join(self.root, *old.split("/")))
                except OSError:
                    pass
        return local


class LakeQuery:
    def __init__(self, table: DeltaTable, key=None, hot=None, hot_app_id: str | None = None,
                 cache_dir: str | None = None, cache_bytes: int = 2 << 30, memory_mb: int = 256, threads: int = 2):
        self.table, self.key, self.hot, self.app = table, key, hot, hot_app_id
        self.store = table.store
        self.local_root = self.store.local_root
        self.cache = None if self.local_root else _Cache(self.store, cache_dir or "lake_cache", cache_bytes)
        self.memory_mb, self.threads = memory_mb, threads
        self._blooms: OrderedDict[str, dict] = OrderedDict()

    def _bloom(self, add: dict):
        p = add["path"]
        b = self._blooms.get(p)
        if b is None:
            b = read_blooms(self.store, add, self.key) or {}
            self._blooms[p] = b
            if len(self._blooms) > 2000:
                self._blooms.popitem(last=False)
        return b

    def plan(self, tenant: str | None, start=None, end=None, eq: dict | None = None):
        """(cold add actions to scan, hot start position, stats)."""
        s = self.table.snapshot()
        eq = {k: str(v) for k, v in (eq or {}).items() if v is not None}
        stats = {"snapshot_version": s.version, "files_total": len(s.files)}
        files = []
        for a in s.files.values():
            pv = a.get("partitionValues", {})
            if tenant is not None and pv.get("tenant_id") != tenant:
                continue
            hb = _hour_bounds(pv.get("date", ""), pv.get("hour", ""))
            if hb and ((start and hb[1] <= start) or (end and hb[0] > end)):
                continue
            files.append(a)
        stats["files_after_partitions"] = len(files)
        if start or end:
            kept = []
            for a in files:
                st = a.get("stats")
                st = json.loads(st) if isinstance(st, str) else (st or {})
                lo, hi = _parse_stat_ts(st.get("minValues", {}).get("timestamp")), \
                    _parse_stat_ts(st.get("maxValues", {}).get("timestamp"))
                if lo and hi and ((start and hi < start) or (end and lo > end)):
                    continue
                kept.append(a)
            files = kept
        stats["files_after_stats"] = len(files)
        bloom_eq = {k: v for k, v in eq.items() if k in BLOOM_COLUMNS}
        if bloom_eq:
            files = [a for a in files if all(v in self._bloom(a)[c] for c, v in bloom_eq.items()
                                             if c in self._bloom(a))]
        stats["files_scanned"] = len(files)
        stats["bytes_scanned"] = sum(a.get("size", 0) for a in files)
        hot_from = s.txns.get(self.app, 0) if self.app else None
        return files, hot_from, stats

    def _hot_table(self, pos: int, tenant, start, end):
        def want(part: str) -> bool:
            t, d, h = part.split("/")
            if tenant is not None and t != tenant:
                return False
            hb = _hour_bounds(d, h)
            return not (hb and ((start and hb[1] <= start) or (end and hb[0] > end)))
        tables, skipped, n = [], 0, 0
        while pos < self.hot.ring.head:
            recs, pos, sk = self.hot.read(pos, 64 << 20, want)
            skipped += sk
            for _p, _k, t in recs:
                tables.append(t)
                n += t.num_rows
        return (pa.concat_tables(tables) if tables else SCHEMA.empty_table()), skipped, n

    def run(self, sql: str = "SELECT * FROM events", tenant: str | None = None, start=None, end=None,
            eq: dict | None = None, max_rows: int = 100_000, con_hook=None):
        """Run ``sql`` over ``events`` (SCHEMA columns); returns (arrow table, stats).
        ``con_hook(connection)``: called before the query runs (e.g. to arm a deadline); an object
        it returns with ``cancel()`` is cancelled afterwards."""
        for attempt in range(3):
            files, hot_from, stats = self.plan(tenant, start, end, eq)
            if len(files) > MAX_FILES:
                raise ValueError(f"query touches {len(files)} files (max {MAX_FILES}): narrow the time range")
            hot_t, skipped, nhot = (None, 0, 0)
            if self.hot is not None and hot_from is not None:
                hot_t, skipped, nhot = self._hot_table(hot_from, tenant, start, end)
                if skipped:              # the snapshot fell behind the ring: take a newer one
                    continue
            stats["hot_rows"] = nhot
            t0 = time.perf_counter()
            out = self._execute(sql, files, hot_t, tenant, start, end, eq or {}, max_rows, con_hook)
            stats["query_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            stats["rows"] = out.num_rows
            return out, stats
        raise RuntimeError("hot tier overwritten faster than the query could snapshot it")

    def _execute(self, sql, files, hot_t, tenant, start, end, eq, max_rows, con_hook=None):
        dirs = [self.local_root or self.cache.root]
        con = duckdb.connect(config={"memory_limit": f"{self.memory_mb}MB", "threads": self.threads})
        armed = con_hook(con) if con_hook else None
        try:
            con.execute("SET TimeZone='UTC'")
            parts = []
            for i, a in enumerate(files):
                local = os.path.join(self.local_root, *a["path"].split("/")) if self.local_root \
                    else self.cache.path(a["path"], a.get("size", 0))
                local = local.replace("\\", "/").replace("'", "''")
                dek = dek_of(a, self.key)
                if dek is None:
                    parts.append(f"SELECT * FROM read_parquet('{local}', hive_partitioning=true, "
                                 f"hive_types={{'tenant_id': VARCHAR, 'date': VARCHAR, 'hour': VARCHAR}})")
                    continue
                # encrypted: pyarrow decrypts with the file's DEK (DuckDB's Parquet encryption does
                # not read Arrow's); DuckDB scans the dataset with filter and projection pushdown
                import pyarrow.dataset as ds
                from pyarrow._parquet_encryption import create_decryption_properties
                fmt = ds.ParquetFileFormat(default_fragment_scan_options=ds.ParquetFragmentScanOptions(
                    decryption_properties=create_decryption_properties(dek)))
                con.register(f"f{i}", ds.dataset(local, format=fmt, schema=DATA_SCHEMA))
                pv = a["partitionValues"]
                parts.append(f"SELECT *, {_lit(pv['tenant_id'])} AS tenant_id, {_lit(pv['date'])} AS date, "
                             f"{_lit(pv['hour'])} AS hour FROM f{i}")
            if hot_t is not None and hot_t.num_rows:
                con.register("hot_rows", hot_t)
                parts.append("SELECT * FROM hot_rows")
            if not parts:
                con.register("hot_rows", SCHEMA.empty_table())
                parts.append("SELECT * FROM hot_rows")
            where = []
            if tenant is not None:
                where.append(f"tenant_id = {_lit(tenant)}")
            if start:
                where.append(f"timestamp >= {_lit(start)}")
            if end:
                where.append(f"timestamp <= {_lit(end)}")
            for k, v in eq.items():
                if k not in _IDENT:
                    raise ValueError(f"unknown column {k!r}")
                where.append(f'"{k}" = {_lit(v)}')
            union = " UNION ALL BY NAME ".join(parts)
            con.execute(f"CREATE TEMP VIEW events AS SELECT * FROM ({union})"
                        + (" WHERE " + " AND ".join(where) if where else ""))
            norm = [d.replace("\\", "/").rstrip("/") + "/" for d in dirs]
            con.execute("SET allowed_directories=[" + ",".join(f"'{d}'" for d in norm) + "]")
            con.execute("SET enable_external_access=false")
            con.execute("SET lock_configuration=true")
            reader = con.execute(sql).fetch_record_batch(8192)
            batches, n = [], 0
            for b in reader:
                batches.append(b)
                n += b.num_rows
                if n >= max_rows:
                    break
            return pa.Table.from_batches(batches, reader.schema).slice(0, max_rows) if batches else \
                reader.schema.empty_table()
        finally:
            if hasattr(armed, "cancel"):
                armed.cancel()
            con.close()


def _lit(v) -> str:
    if isinstance(v, _dt.datetime):
        v = v.astimezone(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f+00")
        return f"TIMESTAMPTZ '{v}'"
    return "'" + str(v).replace("'", "''") + "'"
