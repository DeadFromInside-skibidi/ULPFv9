"""
DuckDB Storage Backend
========================
Columnar event store for ULPF.

* Bulk inserts go through typed PyArrow tables (one ``INSERT … SELECT`` per
  chunk) — no per-row SQL round-trips.
* Explorer queries use late materialization: filters/sort/limit run on light
  columns first, and the heavy ``normalised_json`` column is fetched only for
  the requested page.
* A single connection is shared by all threads behind a lock (DuckDB
  connections are not thread-safe).
* If another *process* holds the write lock, the store opens read-only and
  any write raises ``DatabaseLockedError`` instead of silently diverting data
  to a throwaway file.
* Optional time partitioning (``partition="daily"|"hourly"``): one DuckDB file
  per period, a federated ``events`` view, whole-file retention. See
  ``Database``.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

import duckdb
import orjson
import pyarrow as pa

from ulpf.platform.paths import get_db_path
from ulpf.storage.interface import StorageBackend

logger = logging.getLogger(__name__)


class DatabaseLockedError(RuntimeError):
    """The event store is locked for writing by another ULPF process."""


def _default_db_path() -> str:
    return str(get_db_path())


def _safe_int(val: Any, default: Any = None) -> Any:
    """Convert to int, or return default for blanks / junk / out-of-range values."""
    if val is None or val == "":
        return default
    try:
        v = int(val)
    except (ValueError, TypeError):
        try:
            v = int(float(val))
        except (ValueError, TypeError):
            return default
    return v if -2_147_483_648 <= v <= 2_147_483_647 else default


EVENT_COLUMNS: tuple[str, ...] = (
    "event_id", "timestamp", "timestamp_original", "category", "event_type",
    "action", "severity", "severity_label",
    "source_ip", "source_port", "destination_ip", "destination_port",
    "protocol", "device_vendor", "device_product",
    "raw_event", "raw_format", "raw_hash", "parsed_fields",
    "normalised_json", "message", "tags", "correlation_id", "row_mac",
)

ARROW_SCHEMA = pa.schema([
    (c, pa.int32() if c in ("severity", "source_port", "destination_port") else pa.string())
    for c in EVENT_COLUMNS
])

_INSERT_COLS = ", ".join(EVENT_COLUMNS)
_PLACEHOLDERS = ", ".join("?" for _ in EVENT_COLUMNS)
_dumps = orjson.dumps
_OPT = orjson.OPT_NON_STR_KEYS


def _memory_limit() -> str:
    """DuckDB buffer pool cap: ULPF_DUCKDB_MEMORY, else 25 % of RAM, at most 4 GB, at least 256 MB.

    DuckDB keeps pages cached up to this cap, so the store's resident memory
    grows to it under sustained ingest and then stays flat.
    """
    env = os.environ.get("ULPF_DUCKDB_MEMORY")
    if env:
        return env
    try:
        import psutil
        mb = int(psutil.virtual_memory().total / 2**20 * 0.25)
    except Exception:
        mb = 4096
    return f"{max(256, min(mb, 4096))}MB"


def _wal_checkpoint(memory_limit: str) -> str:
    """WAL auto-checkpoint size: a quarter of the memory cap, between 64 MB and 1 GB.

    Un-checkpointed WAL data stays in memory and a checkpoint briefly needs
    about as much again; small checkpoints cost ingest speed (16 MB capped the
    store near 22k rows/s, 1 GB measured 61k rows/s on the same data).
    """
    try:
        mb = int(memory_limit.upper().removesuffix("MB")) if memory_limit.upper().endswith("MB") else \
            int(float(memory_limit.upper().removesuffix("GB")) * 1024)
    except ValueError:
        return "1GB"
    return f"{max(64, min(mb // 4, 1024))}MB"


def _json(obj: Any) -> str:
    # Plain orjson first (~40 % faster); non-string keys need OPT_NON_STR_KEYS
    try:
        return _dumps(obj, default=str).decode("utf-8")
    except TypeError:
        return _dumps(obj, default=str, option=_OPT).decode("utf-8")


def _str_or_none(v: Any) -> str | None:
    return v if v is None or isinstance(v, str) else str(v)


_SPLIT_KEYS = frozenset(("raw_event", "parsed_fields"))


def _hydrate(normalised_json: str, raw_event: str | None, parsed_fields: str | None) -> dict:
    """Rebuild the full event: raw_event / parsed_fields are stored in their own columns."""
    event = orjson.loads(normalised_json)
    if "raw_event" not in event:
        event["raw_event"] = raw_event
    if "parsed_fields" not in event:
        event["parsed_fields"] = orjson.loads(parsed_fields) if parsed_fields else {}
    return event


_EVENT_SELECT = "normalised_json, raw_event, parsed_fields"


def event_to_row(event: dict) -> tuple:
    """Flatten a normalized event into the ``events`` table column order.

    ``normalised_json`` omits raw_event and parsed_fields (each already has a
    column) — ~15 % fewer bytes per row; reads re-attach them losslessly.
    """
    src = event.get("source") or {}
    dst = event.get("destination") or {}
    dev = event.get("device") or {}
    eid = event.get("event_id")
    if not eid:
        from ulpf.engine.schema import new_uuid
        eid = event["event_id"] = new_uuid()
    return (
        eid,
        _str_or_none(event.get("timestamp")),
        _str_or_none(event.get("timestamp_original")),
        event.get("category"),
        _str_or_none(event.get("event_type")),
        event.get("action"),
        _safe_int(event.get("severity"), 0),
        event.get("severity_label"),
        _str_or_none(src.get("ip") or src.get("hostname")),
        _safe_int(src.get("port")),
        _str_or_none(dst.get("ip") or dst.get("hostname") or dev.get("hostname")),
        _safe_int(dst.get("port")),
        _str_or_none((event.get("network") or {}).get("protocol")),
        _str_or_none(dev.get("vendor")),
        _str_or_none(dev.get("product")),
        event.get("raw_event"),
        event.get("raw_format"),
        (event.get("evidence") or {}).get("raw_hash"),
        _json(event.get("parsed_fields") or {}),
        _json({k: v for k, v in event.items() if k not in _SPLIT_KEYS}),
        _str_or_none(event.get("message")),
        _json(event.get("tags") or []),
        event.get("correlation_id"),
        None,
    )


def _mac_str(v: Any) -> str:
    return "\x00" if v is None else (v if v.__class__ is str else str(v))


def row_mac(key: bytes, row: tuple | list) -> str:
    """Keyed BLAKE2b-256 (RFC 7693) over every stored column except ``row_mac``.

    Written by the runtime when ``evidence.row_mac`` is on (default in defence
    mode); ``ulpf evidence verify --check-store`` recomputes it, so editing
    any column of a stored event is detected, not only its ``raw_hash``.
    Columns are joined with U+001F; NULL is U+0000.
    """
    import hashlib
    data = "\x1f".join(map(_mac_str, row[:-1])).encode("utf-8", "surrogatepass")
    return hashlib.blake2b(data, key=key[:64], digest_size=32).hexdigest()


def sign_row(key: bytes, row: tuple) -> tuple:
    return row[:-1] + (row_mac(key, row),)


def rows_to_arrow(rows: list[tuple]) -> pa.Table:
    """Build a typed Arrow table from ``event_to_row`` tuples."""
    columns = list(zip(*rows)) if rows else [()] * len(EVENT_COLUMNS)
    return pa.Table.from_arrays(
        [pa.array(col, type=ARROW_SCHEMA.field(i).type) for i, col in enumerate(columns)],
        schema=ARROW_SCHEMA,
    )




_EVENTS_DDL = """
    CREATE TABLE IF NOT EXISTS {table} (
        event_id VARCHAR,
        timestamp VARCHAR,
        timestamp_original VARCHAR,
        category VARCHAR,
        event_type VARCHAR,
        action VARCHAR,
        severity INTEGER,
        severity_label VARCHAR,
        source_ip VARCHAR,
        source_port INTEGER,
        destination_ip VARCHAR,
        destination_port INTEGER,
        protocol VARCHAR,
        device_vendor VARCHAR,
        device_product VARCHAR,
        raw_event VARCHAR,
        raw_format VARCHAR,
        raw_hash VARCHAR,
        parsed_fields VARCHAR,
        normalised_json VARCHAR,
        message VARCHAR,
        tags VARCHAR,
        correlation_id VARCHAR,
        ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        row_mac VARCHAR
    )
"""
_LEDGER_DDL = ("CREATE TABLE IF NOT EXISTS {table} "
               "(name VARCHAR PRIMARY KEY, ingested_at TIMESTAMP DEFAULT current_timestamp)")

PARTITION_MODES = ("none", "daily", "hourly")
_PERIOD_FMT = {"daily": "%Y%m%d", "hourly": "%Y%m%d%H"}
_PERIOD_SECONDS = {"daily": 86400, "hourly": 3600}


def _sql_str(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _period_bounds(period: str) -> tuple[float, float]:
    """UTC [start, end) of a partition period string (YYYYMMDD or YYYYMMDDHH)."""
    from datetime import datetime, timezone
    fmt = _PERIOD_FMT["hourly" if len(period) == 10 else "daily"]
    start = datetime.strptime(period, fmt).replace(tzinfo=timezone.utc).timestamp()
    return start, start + (3600 if len(period) == 10 else 86400)


class Database(StorageBackend):
    """DuckDB columnar storage backend.

    ``partition`` (``daily`` / ``hourly``) stores events in one DuckDB file per
    period next to the catalog (``<store>_partitions/events_<period>.duckdb``):

    * writes go only to the active partition, attached read-write as ``hot``;
      when the period ends (or the file passes ``partition_max_mb``) it is
      checkpointed and re-attached read-only, so its write buffers are released;
    * ``events`` is a view over every partition: queries and raw SQL written
      against ``events`` keep working; statements that modify stored rows go
      through ``execute_on_partitions``;
    * the exactly-once ledger (``ulpf_segments``) lives in each partition, in
      the same transaction as the rows (DuckDB cannot write two databases in
      one transaction); duplicates are checked against every partition's ledger;
    * retention (``retention_days``) retires whole partition files — removed, or
      moved / exported to ``archive_dir`` — instead of ``DELETE`` (no WAL growth).

    A store that was opened partitioned stays partitioned; readers detect it.
    An existing single-table store is kept as a read-only ``legacy`` partition.
    Without ``partition`` the store is the single ``events`` table of v9.0.
    """

    def __init__(self, db_path: str | None = None, read_only: bool = False, partition: str | None = None,
                 partition_max_mb: float | None = None, retention_days: float | None = None,
                 archive_dir: str | None = None, archive_format: str = "duckdb"):
        if partition not in (None,) + PARTITION_MODES:
            raise ValueError(f"partition must be one of {', '.join(PARTITION_MODES)}")
        if archive_format not in ("duckdb", "parquet"):
            raise ValueError("archive_format must be duckdb or parquet")
        self.db_path = db_path or _default_db_path()
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self.read_only = read_only
        self._conn_lock = threading.RLock()
        try:
            self.conn = duckdb.connect(self.db_path, read_only=read_only)
        except duckdb.IOException as e:
            if read_only or not os.path.exists(self.db_path):
                raise
            # Another process (desktop app, API server) holds the write lock
            logger.warning(f"{self.db_path} is locked by another process; opening read-only ({e})")
            self.conn = duckdb.connect(self.db_path, read_only=True)
            self.read_only = True

        # wal_autocheckpoint: the 16MB default checkpoints every ~5k events and
        # caps ingestion near 22k rows/s; 1GB measured 61k rows/s on the same data.
        limit = _memory_limit()
        # The allocator settings return freed memory to the OS between ingest batches
        # (without them the process grew ~1 GB/hour above memory_limit under sustained ingest)
        for pragma in ("PRAGMA threads=4", f"PRAGMA memory_limit='{limit}'",
                       f"PRAGMA wal_autocheckpoint='{_wal_checkpoint(limit)}'",
                       "SET allocator_background_threads=true", "SET allocator_flush_threshold='64MB'"):
            try:
                self.conn.execute(pragma)
            except duckdb.Error:
                pass

        self._stats_cache: dict = {}
        self._stats_cache_ts: float = 0.0
        self._stats_lock = threading.Lock()
        self._live_total_events: int = 0
        self._batch_seq = 0
        self.locked_down = False

        self.partition_mode = "none"
        self.partition_max_bytes = int(float(partition_max_mb) * 2**20) if partition_max_mb else 0
        self.retention_days = float(retention_days) if retention_days else None
        self.archive_dir = archive_dir
        self.archive_format = archive_format
        self.parts_dir = os.path.splitext(self.db_path)[0] + "_partitions"
        self._parts: list[dict] = []          # catalog rows, oldest first
        self._hot: dict | None = None
        self.partitions_retired = 0

        if not self.read_only:
            self._init_tables()
        stored_mode = self._stored_partition_mode()
        if stored_mode or partition in ("daily", "hourly"):
            self._open_partitions(partition if partition in ("daily", "hourly") else stored_mode)
        elif not self.read_only:
            with self._conn_lock:
                self.conn.execute(_EVENTS_DDL.format(table="events"))
                # Stores created before v9 have no row_mac column
                self.conn.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS row_mac VARCHAR")

    @property
    def partitioned(self) -> bool:
        return self.partition_mode != "none"

    def lock_down(self, allowed_dirs: list[str]) -> None:
        """Defence mode: DuckDB may read and write files only under ``allowed_dirs``.

        DuckDB's network-capable extensions (httpfs, azure, ...) open sockets from
        C++ where the Python egress guard cannot see them, so external access is
        switched off, extension install/autoload is refused, and the
        configuration is locked so no later statement can re-enable either.
        Partition files and the archive directory stay reachable.
        """
        wanted = {os.path.abspath(d) for d in list(allowed_dirs) + [self.archive_dir] if d}
        dirs = sorted(wanted | {os.path.dirname(os.path.abspath(self.db_path))})
        listing = ", ".join("'" + (d.rstrip("\\/") + os.sep).replace("'", "''") + "'" for d in dirs)
        with self._conn_lock:
            for stmt in (f"SET allowed_directories=[{listing}]",
                         "SET autoinstall_known_extensions=false",
                         "SET autoload_known_extensions=false",
                         "SET enable_external_access=false",
                         "SET lock_configuration=true"):
                self.conn.execute(stmt)
        self.locked_down = True
        logger.info(f"DuckDB external access disabled; files allowed only under {', '.join(dirs)}")

    def _require_writable(self) -> None:
        if self.read_only:
            raise DatabaseLockedError(
                f"Event store {self.db_path} is open read-only because another ULPF process "
                "(desktop app or API server) holds the write lock. Stop it, or set ULPF_DB_PATH "
                "to use a separate store.")

    def _init_tables(self):
        with self._conn_lock:
            # No PRIMARY KEY on events: an ART index on random UUIDs makes append
            # cost grow with table size (measured 31k → 14k rows/s by 150k rows).
            # Event IDs are random UUIDv4s generated by the pipeline.
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS anomalies (
                    anomaly_type VARCHAR,
                    description VARCHAR,
                    risk VARCHAR,
                    event_id VARCHAR,
                    details_json VARCHAR,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS parser_configs (
                    config_id VARCHAR PRIMARY KEY,
                    config_json VARCHAR,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Correlation assignments live beside the events, never in them: the row
            # MAC covers every event column, so rewriting ``correlation_id`` in place
            # made correlated rows verify as tampered. Append-only; the newest wins.
            self.conn.execute("CREATE TABLE IF NOT EXISTS ulpf_correlations (event_id VARCHAR, "
                              "correlation_id VARCHAR, assigned_at DOUBLE)")

    # -------------------------------------------------------------------
    # Partitions
    # -------------------------------------------------------------------

    def _table_exists(self, name: str) -> bool:
        """A table in the catalog file itself (its database is named after the file, not ``main``)."""
        return bool(self.conn.execute(
            "SELECT 1 FROM duckdb_tables() WHERE database_name = current_database() AND schema_name = 'main' "
            "AND table_name = ?", [name]).fetchone())

    def _stored_partition_mode(self) -> str | None:
        with self._conn_lock:
            if not self._table_exists("ulpf_store_meta"):
                return None
            row = self.conn.execute("SELECT value FROM ulpf_store_meta WHERE key = 'partition'").fetchone()
        return row[0] if row and row[0] in ("daily", "hourly") else None

    @staticmethod
    def _alias(part: dict) -> str:
        return "main" if part["name"] == "legacy" else f"p_{part['name']}"

    def _part_path(self, part: dict) -> str:
        return os.path.join(self.parts_dir, part["file"])

    def _rel(self, part: dict) -> str:
        """Table reference of a partition's events."""
        if part["name"] == "legacy":
            return "main.events_legacy"
        return "hot.events" if part is self._hot else f"{self._alias(part)}.events"

    def _open_partitions(self, mode: str) -> None:
        self.partition_mode = mode
        with self._conn_lock:
            if not self.read_only:
                os.makedirs(self.parts_dir, exist_ok=True)
                self.conn.execute("CREATE TABLE IF NOT EXISTS ulpf_store_meta (key VARCHAR PRIMARY KEY, value VARCHAR)")
                self.conn.execute("INSERT OR REPLACE INTO ulpf_store_meta VALUES ('partition', ?)", [mode])
                self.conn.execute("CREATE TABLE IF NOT EXISTS ulpf_partitions (name VARCHAR PRIMARY KEY, "
                                  "file VARCHAR, period VARCHAR, seq INTEGER, ord INTEGER, period_end DOUBLE, "
                                  "state VARCHAR, rows BIGINT)")
                if self._table_exists("events"):
                    # A v9.0 single-table store: kept, read-only, as the oldest partition
                    self.conn.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS row_mac VARCHAR")
                    self.conn.execute("ALTER TABLE events RENAME TO events_legacy")
                    n = self.conn.execute("SELECT COUNT(*) FROM events_legacy").fetchone()[0]
                    self.conn.execute("INSERT OR IGNORE INTO ulpf_partitions VALUES "
                                      "('legacy', '', '', 0, -1, NULL, 'sealed', ?)", [n])
                    logger.info(f"event store: existing events table ({n} rows) kept as the legacy partition")
            rows = self.conn.execute("SELECT name, file, period, seq, ord, period_end, state, rows "
                                     "FROM ulpf_partitions ORDER BY ord").fetchall()
            keys = ("name", "file", "period", "seq", "ord", "period_end", "state", "rows")
            self._parts = [dict(zip(keys, r)) for r in rows]
            for p in self._parts:
                if p["name"] == "legacy":
                    continue
                if p["state"] == "hot" and not self.read_only:
                    self.conn.execute(f"ATTACH {_sql_str(self._part_path(p))} AS hot")
                    self._ensure_partition_tables("hot")
                    self._hot = p
                else:
                    self.conn.execute(f"ATTACH {_sql_str(self._part_path(p))} AS {self._alias(p)} (READ_ONLY)")
            if not self.read_only:
                self._maybe_rotate(force_new=self._hot is None)
            self._rebuild_views()

    def _ensure_partition_tables(self, alias: str) -> None:
        self.conn.execute(_EVENTS_DDL.format(table=f"{alias}.events"))
        self.conn.execute(_LEDGER_DDL.format(table=f"{alias}.ulpf_segments"))

    def _current_period(self) -> str:
        return time.strftime(_PERIOD_FMT[self.partition_mode], time.gmtime())

    def _hot_bytes(self) -> int:
        path = self._part_path(self._hot)
        total = 0
        for p in (path, path + ".wal"):
            try:
                total += os.path.getsize(p)
            except OSError:
                pass
        return total

    def _maybe_rotate(self, force_new: bool = False) -> bool:
        """Start a new active partition when the period changed or the active one is full. Lock held."""
        period = self._current_period()
        hot = self._hot
        if not force_new and hot is not None:
            if hot["period"] == period and not (self.partition_max_bytes and self._hot_bytes() > self.partition_max_bytes):
                return False
        seq = 0
        if hot is not None and hot["period"] == period:
            seq = hot["seq"] + 1
        while any(p["period"] == period and p["seq"] == seq for p in self._parts):
            seq += 1
        if hot is not None:
            self._seal_hot()
        name = period if seq == 0 else f"{period}_{seq}"
        part = {"name": name, "file": f"events_{name}.duckdb", "period": period, "seq": seq,
                "ord": max([p["ord"] for p in self._parts] + [0]) + 1, "period_end": _period_bounds(period)[1],
                "state": "hot", "rows": 0}
        self.conn.execute(f"ATTACH {_sql_str(self._part_path(part))} AS hot")
        self._ensure_partition_tables("hot")
        self.conn.execute("INSERT INTO ulpf_partitions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                          [part[k] for k in ("name", "file", "period", "seq", "ord", "period_end", "state", "rows")])
        self._parts.append(part)
        self._hot = part
        self._rebuild_views()
        logger.info(f"event store: active partition {name}")
        return True

    def _seal_hot(self) -> None:
        """Checkpoint the active partition and re-attach it read-only. Lock held."""
        hot = self._hot
        rows = self.conn.execute("SELECT COUNT(*) FROM hot.events").fetchone()[0]
        self.conn.execute("CHECKPOINT hot")
        self.conn.execute("DETACH hot")
        self.conn.execute(f"ATTACH {_sql_str(self._part_path(hot))} AS {self._alias(hot)} (READ_ONLY)")
        self.conn.execute("UPDATE ulpf_partitions SET state = 'sealed', rows = ? WHERE name = ?", [rows, hot["name"]])
        hot.update(state="sealed", rows=rows)
        self._hot = None

    def _rebuild_views(self) -> None:
        """``events`` (and the ledger view) over every partition, newest first. Lock held."""
        rels = [self._rel(p) for p in reversed(self._parts)]
        if not rels:
            return
        self.conn.execute("CREATE OR REPLACE TEMP VIEW events AS " +
                          " UNION ALL BY NAME ".join(f"SELECT * FROM {r}" for r in rels))
        ledgers = [f"SELECT name, ingested_at FROM {r.rsplit('.', 1)[0]}.ulpf_segments"
                   for r in rels if r != "main.events_legacy"]
        if self._table_exists("ulpf_segments"):
            ledgers.append("SELECT name, ingested_at FROM main.ulpf_segments")
        if ledgers:
            self.conn.execute("CREATE OR REPLACE TEMP VIEW ulpf_segments_all AS " + " UNION ALL ".join(ledgers))

    def partitions(self) -> list[dict]:
        """Partition catalog, oldest first (``state``: hot / sealed)."""
        with self._conn_lock:
            out = []
            for p in self._parts:
                d = dict(p)
                d["path"] = self._part_path(p) if p["name"] != "legacy" else self.db_path
                if p is self._hot:
                    d["rows"] = self.conn.execute("SELECT COUNT(*) FROM hot.events").fetchone()[0]
                out.append(d)
            return out

    def _read_relations(self) -> list[str]:
        """Event tables newest first."""
        if not self.partitioned:
            return ["events"]
        return [self._rel(p) for p in reversed(self._parts)]

    @property
    def _write_table(self) -> str:
        return "hot.events" if self.partitioned else "events"

    @property
    def _ledger_table(self) -> str:
        return "hot.ulpf_segments" if self.partitioned else "ulpf_segments"

    def _before_write(self) -> None:
        """Lock held: roll the active partition if its period ended or it is full."""
        if self.partitioned:
            self._maybe_rotate()

    def execute_on_partitions(self, sql: str, params: list | None = None, probe: str | None = None,
                              probe_params: list | None = None) -> int:
        """Run a statement that modifies stored events on every partition holding matching rows.

        ``sql`` names the table ``{events}``. ``probe`` is a WHERE clause: a sealed
        partition is only re-opened read-write when it has a matching row.
        Returns the number of rows changed (when DuckDB reports it).
        """
        self._require_writable()
        total = 0
        with self._conn_lock:
            if not self.partitioned:
                return self._count_changed(self.conn.execute(sql.format(events="events"), params or []))
            for p in list(self._parts):
                rel = self._rel(p)
                if probe and not self.conn.execute(f"SELECT 1 FROM {rel} WHERE {probe} LIMIT 1",
                                                   probe_params or []).fetchone():
                    continue
                if p is self._hot or p["name"] == "legacy":
                    total += self._count_changed(self.conn.execute(sql.format(events=rel), params or []))
                    continue
                alias, path = self._alias(p), _sql_str(self._part_path(p))
                self.conn.execute(f"DETACH {alias}")
                try:
                    self.conn.execute(f"ATTACH {path} AS {alias}")
                    total += self._count_changed(self.conn.execute(sql.format(events=rel), params or []))
                    self.conn.execute(f"CHECKPOINT {alias}")
                finally:
                    self.conn.execute(f"DETACH DATABASE IF EXISTS {alias}")
                    self.conn.execute(f"ATTACH {path} AS {alias} (READ_ONLY)")
        self._invalidate_stats()
        return total

    @staticmethod
    def _count_changed(cursor) -> int:
        try:
            row = cursor.fetchone()
            return int(row[0]) if row and isinstance(row[0], int) else 0
        except duckdb.Error:
            return 0

    def _retire(self, part: dict, reason: str, archive: bool = True) -> None:
        """Remove a sealed partition from the store: archived or deleted, never DELETEd row by row. Lock held."""
        if part["name"] == "legacy":
            self.conn.execute("DROP TABLE IF EXISTS events_legacy")
        else:
            alias, path = self._alias(part), self._part_path(part)
            archived = None
            archive = archive and bool(self.archive_dir)
            if archive:
                os.makedirs(self.archive_dir, exist_ok=True)
                if self.archive_format == "parquet":
                    archived = os.path.join(self.archive_dir, f"events_{part['name']}.parquet")
                    self.conn.execute(f"COPY (SELECT * FROM {alias}.events) TO {_sql_str(archived)} "
                                      "(FORMAT parquet, COMPRESSION zstd)")
            self.conn.execute(f"DETACH DATABASE IF EXISTS {alias}")
            if archive and self.archive_format == "duckdb":
                archived = os.path.join(self.archive_dir, part["file"])
                os.replace(path, archived)
            for f in (path, path + ".wal"):
                try:
                    os.remove(f)
                except FileNotFoundError:
                    pass
            if archived:
                logger.info(f"event store: partition {part['name']} archived to {archived} ({reason})")
        self.conn.execute("DELETE FROM ulpf_partitions WHERE name = ?", [part["name"]])
        self._parts.remove(part)
        self.partitions_retired += 1
        logger.info(f"event store: partition {part['name']} retired ({reason})")

    def _expired(self, part: dict, cutoff_epoch: float, seconds: int) -> bool:
        if part is self._hot:
            return False
        if part["name"] == "legacy":
            row = self.conn.execute("SELECT max(ingested_at) < (CAST(now() AS TIMESTAMP) - to_seconds(?)) "
                                    "FROM events_legacy", [seconds]).fetchone()
            return bool(row and row[0])
        return part["period_end"] is not None and part["period_end"] <= cutoff_epoch

    def apply_retention(self, days: float | None = None) -> int:
        """Retire every partition that ended more than ``days`` (default ``retention_days``) ago."""
        days = days if days is not None else self.retention_days
        if not self.partitioned or not days or self.read_only:
            return 0
        seconds = int(float(days) * 86400)
        cutoff = time.time() - seconds
        with self._conn_lock:
            expired = [p for p in self._parts if self._expired(p, cutoff, seconds)]
            for p in expired:
                self._retire(p, f"older than {days:g} days")
            if expired:
                self._rebuild_views()
        if expired:
            self._invalidate_stats()
        return len(expired)

    def retire_oldest(self, reason: str = "disk quota") -> bool:
        """Retire the oldest sealed partition (disk quota). False when only the active one is left."""
        if not self.partitioned or self.read_only:
            return False
        with self._conn_lock:
            cands = [p for p in self._parts if p is not self._hot]
            if not cands:
                return False
            self._retire(cands[0], reason)
            self._rebuild_views()
        self._invalidate_stats()
        return True

    def maintain(self) -> dict:
        """Periodic upkeep (the runtime calls it every minute): rotate, retire expired partitions,
        checkpoint the active partition so its WAL and dirty pages are released."""
        if self.read_only:
            return {}
        rotated = False
        with self._conn_lock:
            if self.partitioned:
                rotated = self._maybe_rotate()
                self.conn.execute("CHECKPOINT hot")
            else:
                self.conn.execute("CHECKPOINT")
        retired = self.apply_retention()
        self.prune_segment_ledger()
        return {"rotated": rotated, "retired": retired}

    # -------------------------------------------------------------------
    # Store methods
    # -------------------------------------------------------------------

    def store_event(self, event: dict) -> str:
        """Store a single normalised event (idempotent on event_id)."""
        self.store_events_bulk([event])
        return event["event_id"]

    def store_events(self, events: list[dict]) -> int:
        return self.store_events_bulk(events)

    def insert_batch(self, events: list[dict]) -> int:
        """StorageBackend interface alias."""
        return self.store_events_bulk(events)

    def store_events_bulk(self, events: list[dict], chunk_size: int = 20000) -> int:
        """High-performance bulk insert via typed Arrow tables.

        Events whose event_id already exists are ignored (events are immutable
        evidence). Returns the number of rows newly stored.
        """
        if not events:
            return 0
        self._require_writable()
        stored = 0
        for i in range(0, len(events), chunk_size):
            rows = []
            for event in events[i:i + chunk_size]:
                try:
                    rows.append(event_to_row(event))
                except Exception:
                    logger.warning("Skipping unserialisable event %r", event.get("event_id"), exc_info=True)
            if rows:
                stored += self._insert_arrow(rows_to_arrow(rows))
        return stored

    def store_arrow_table(self, table: Any) -> int:
        """Insert a PyArrow table whose columns follow EVENT_COLUMNS."""
        if table is None or getattr(table, "num_rows", 0) == 0:
            return 0
        self._require_writable()
        return self._insert_arrow(table)

    def _parquet_source(self, file_list: str) -> str:
        """SELECT over Parquet files in EVENT_COLUMNS order. Columns a file lacks (shards
        written by an older version, e.g. without row_mac) are read as NULL. Caller holds the lock."""
        src = f"read_parquet([{file_list}], union_by_name=true)"
        have = {r[0] for r in self.conn.execute(f"DESCRIBE SELECT * FROM {src}").fetchall()}
        cols = ", ".join(c if c in have else f"NULL AS {c}" for c in EVENT_COLUMNS)
        return f"SELECT {cols} FROM {src}"

    def ingest_parquet(self, paths: list[str]) -> int:
        """Insert events from parquet shards written by worker processes."""
        if not paths:
            return 0
        self._require_writable()
        file_list = ", ".join("'" + p.replace("'", "''") + "'" for p in paths)
        with self._conn_lock:
            self._before_write()
            table = self._write_table
            source = self._parquet_source(file_list)
            before = self._count_unlocked()
            try:
                self.conn.execute(f"INSERT INTO {table} ({_INSERT_COLS}) {source}")
            except duckdb.ConstraintException:
                # Legacy store with an event_id PRIMARY KEY: skip duplicates
                self.conn.execute(f"INSERT OR IGNORE INTO {table} ({_INSERT_COLS}) {source}")
            stored = self._count_unlocked() - before
        self._bump_live_total(stored)
        return stored

    def ingest_segments(self, paths: list[str], names: list[str]) -> int:
        """Insert Parquet buffer segments exactly once.

        The segment names are recorded in ``ulpf_segments`` in the same
        transaction as the rows, so a crash between this commit and the buffer
        deleting the files cannot insert the same segment twice.
        """
        if not paths:
            return 0
        self._require_writable()
        with self._conn_lock:
            self._before_write()
            table, ledger = self._write_table, self._ledger_table
            if not self.partitioned:
                self.conn.execute(_LEDGER_DDL.format(table=ledger))
            seen = "ulpf_segments_all" if self.partitioned else ledger
            placeholders = ", ".join("?" for _ in names)
            done = {r[0] for r in self.conn.execute(
                f"SELECT name FROM {seen} WHERE name IN ({placeholders})", names).fetchall()}
            todo = [(p, n) for p, n in zip(paths, names) if n not in done]
            if not todo:
                return 0
            file_list = ", ".join("'" + p.replace("'", "''") + "'" for p, _ in todo)
            source = self._parquet_source(file_list)
            self.conn.execute("BEGIN TRANSACTION")
            try:
                before = self._count_unlocked()
                self.conn.execute(f"INSERT INTO {table} ({_INSERT_COLS}) {source}")
                self.conn.executemany(f"INSERT INTO {ledger} (name) VALUES (?)", [[n] for _, n in todo])
                stored = self._count_unlocked() - before
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        self._bump_live_total(stored)
        return stored

    def prune_segment_ledger(self, older_than_hours: float = 24.0) -> None:
        if self.read_only:
            return
        with self._conn_lock:
            try:
                self.conn.execute(f"DELETE FROM {self._ledger_table} WHERE ingested_at < "
                                  f"current_timestamp - INTERVAL '{int(older_than_hours * 60)} minutes'")
            except duckdb.CatalogException:
                pass

    def _count_unlocked(self) -> int:
        """Rows in the table writes go to (the active partition)."""
        return self.conn.execute(f"SELECT COUNT(*) FROM {self._write_table}").fetchone()[0]

    def _insert_arrow(self, table: pa.Table) -> int:
        with self._conn_lock:
            self._before_write()
            target = self._write_table
            self._batch_seq += 1
            name = f"ulpf_batch_{self._batch_seq}"
            self.conn.register(name, table)
            try:
                try:
                    self.conn.execute(f"INSERT INTO {target} ({_INSERT_COLS}) SELECT {_INSERT_COLS} FROM {name}")
                    stored = table.num_rows
                except duckdb.ConstraintException:
                    # Duplicate event_id(s): keep the first copy, insert the rest
                    before = self._count_unlocked()
                    self.conn.execute(
                        f"INSERT OR IGNORE INTO {target} ({_INSERT_COLS}) "
                        f"SELECT {_INSERT_COLS} FROM (SELECT DISTINCT ON (event_id) * FROM {name})")
                    stored = self._count_unlocked() - before
            finally:
                self.conn.unregister(name)
        self._bump_live_total(stored)
        return stored

    def _bump_live_total(self, n: int) -> None:
        if n > 0:
            with self._stats_lock:
                self._live_total_events += n
                if self._stats_cache:
                    self._stats_cache["total_events"] = max(self._stats_cache.get("total_events", 0),
                                                            self._live_total_events)

    def set_correlation(self, event_ids: list[str], correlation_id: str) -> None:
        """Persist a correlation group assignment in ``ulpf_correlations``.

        Stored event rows are never rewritten (their row MAC covers
        ``correlation_id``); the side table is append-only and the newest
        assignment of an event wins in reads and filters.
        """
        if not event_ids or self.read_only:
            return
        now = time.time()
        rows = [(str(e), str(correlation_id), now) for e in dict.fromkeys(event_ids) if e]
        with self._conn_lock:
            self.conn.executemany("INSERT INTO ulpf_correlations VALUES (?, ?, ?)", rows)

    def _has_correlations(self) -> bool:
        if getattr(self, "_corr_table", False):
            return True
        with self._conn_lock:
            self._corr_table = self._table_exists("ulpf_correlations")
        return self._corr_table

    def correlations_for(self, event_ids: list[str]) -> dict[str, str]:
        """{event_id: newest correlation_id} from the side table."""
        if not event_ids:
            return {}
        with self._conn_lock:
            if not self._has_correlations():
                return {}
            rows = self.conn.execute(
                "SELECT event_id, arg_max(correlation_id, assigned_at) FROM ulpf_correlations "
                "WHERE event_id IN (SELECT UNNEST(?)) GROUP BY event_id", [list(event_ids)]).fetchall()
        return dict(rows)

    # -------------------------------------------------------------------
    # Query methods
    # -------------------------------------------------------------------

    _EQ_FILTERS = frozenset(("category", "event_type", "action", "severity", "source_ip",
                             "destination_ip", "raw_format", "severity_label", "correlation_id",
                             "protocol", "device_vendor"))

    def _where(self, filters: dict | None) -> tuple[str, list]:
        clauses: list[str] = []
        params: list = []
        for key, value in (filters or {}).items():
            if value is None or value == "":
                continue
            if key == "correlation_id" and self._has_correlations():
                # newest side-table assignment wins; the ingest-time column applies otherwise
                clauses.append("((correlation_id = ? AND event_id NOT IN (SELECT event_id FROM ulpf_correlations)) "
                               "OR event_id IN (SELECT event_id FROM ulpf_correlations GROUP BY event_id "
                               "HAVING arg_max(correlation_id, assigned_at) = ?))")
                params.extend((value, value))
            elif key in self._EQ_FILTERS:
                clauses.append(f"{key} = ?")
                params.append(value)
            elif key == "severity_min":
                clauses.append("severity >= ?")
                params.append(int(value))
            elif key == "severity_max":
                clauses.append("severity <= ?")
                params.append(int(value))
            elif key == "timestamp_after":
                clauses.append("timestamp >= ?")
                params.append(str(value))
            elif key == "timestamp_before":
                clauses.append("timestamp <= ?")
                params.append(str(value))
            elif key == "q":
                pattern = "%" + str(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
                clauses.append("(raw_event ILIKE ? ESCAPE '\\' OR message ILIKE ? ESCAPE '\\' "
                               "OR tags ILIKE ? ESCAPE '\\')")
                params.extend((pattern, pattern, pattern))
        return (" AND ".join(clauses) if clauses else "1=1"), params

    def query(self, filters: dict | None = None, limit: int = 100, offset: int = 0) -> list[dict]:
        """StorageBackend interface alias."""
        return self.query_events(filters, limit, offset)

    def query_events(self, filters: dict | None = None, limit: int = 100, offset: int = 0,
                     order_by: str = "newest") -> list[dict]:
        """Query events, newest first (or by event time with order_by='timestamp').

        Late materialization per partition: filters, sort and limit run on light
        columns, and ``normalised_json`` is read only for the requested page.
        """
        where, params = self._where(filters)
        order = "timestamp DESC, rowid DESC" if order_by == "timestamp" else "rowid DESC"
        limit, offset = int(limit), int(offset)
        with self._conn_lock:
            rels = self._read_relations()
            if len(rels) == 1:
                rel = rels[0]
                sql = (f"SELECT {_EVENT_SELECT} FROM {rel} WHERE rowid IN ("
                       f"SELECT rowid FROM {rel} WHERE {where} ORDER BY {order} LIMIT ? OFFSET ?) "
                       f"ORDER BY {order}")
                result = self.conn.execute(sql, params + [limit, offset]).fetchall()
            elif order_by == "timestamp":
                result = self._page_by_timestamp(rels, where, params, limit, offset)
            else:
                result = self._page_newest(rels, where, params, limit, offset)
        return [_hydrate(*r) for r in result if r and r[0]]

    def _page_newest(self, rels: list[str], where: str, params: list, limit: int, offset: int) -> list:
        out: list = []
        for rel in rels:
            if offset:
                n = self.conn.execute(f"SELECT COUNT(*) FROM {rel} WHERE {where}", params).fetchone()[0]
                if n <= offset:
                    offset -= n
                    continue
            sql = (f"SELECT {_EVENT_SELECT} FROM {rel} WHERE rowid IN ("
                   f"SELECT rowid FROM {rel} WHERE {where} ORDER BY rowid DESC LIMIT ? OFFSET ?) "
                   f"ORDER BY rowid DESC")
            rows = self.conn.execute(sql, params + [limit - len(out), offset]).fetchall()
            offset = 0
            out.extend(rows)
            if len(out) >= limit:
                break
        return out

    def _page_by_timestamp(self, rels: list[str], where: str, params: list, limit: int, offset: int) -> list:
        cand = []
        for i, rel in enumerate(rels):       # i = 0 is the newest partition
            for rid, ts in self.conn.execute(
                    f"SELECT rowid, timestamp FROM {rel} WHERE {where} ORDER BY timestamp DESC, rowid DESC "
                    "LIMIT ?", params + [limit + offset]).fetchall():
                cand.append((ts is not None, ts or "", -i, rid, i))
        cand.sort(reverse=True)               # timestamp DESC (NULLs last), newer partition, rowid DESC
        page = cand[offset:offset + limit]
        by_rel: dict[int, list[int]] = {}
        for c in page:
            by_rel.setdefault(c[4], []).append(c[3])
        fetched: dict[tuple[int, int], tuple] = {}
        for i, rids in by_rel.items():
            for row in self.conn.execute(f"SELECT rowid, {_EVENT_SELECT} FROM {rels[i]} "
                                         "WHERE rowid IN (SELECT UNNEST(?))", [rids]).fetchall():
                fetched[(i, row[0])] = row[1:]
        return [fetched[(c[4], c[3])] for c in page if (c[4], c[3]) in fetched]

    def count_events(self, filters: dict | None = None) -> int:
        where, params = self._where(filters)
        with self._conn_lock:
            return self.conn.execute(f"SELECT COUNT(*) FROM events WHERE {where}", params).fetchone()[0]

    def search(self, query: str, limit: int = 50) -> list[dict]:
        """StorageBackend interface alias."""
        return self.search_events(query, limit)

    def search_events(self, query: str, limit: int = 50) -> list[dict]:
        """Case-insensitive substring search over raw text, message and tags (newest first)."""
        if not query:
            return []
        return self.query_events({"q": query}, limit=limit)

    def get_event(self, event_id: str) -> dict | None:
        with self._conn_lock:
            result = self.conn.execute(
                f"SELECT {_EVENT_SELECT}, correlation_id FROM events WHERE event_id = ? LIMIT 1",
                [event_id]).fetchone()
        if not result or not result[0]:
            return None
        event = _hydrate(result[0], result[1], result[2])
        side = self.correlations_for([event_id]).get(event_id)
        if side or result[3]:
            event["correlation_id"] = side or result[3]
        return event

    def get_events(self, event_ids: list[str]) -> list[dict]:
        if not event_ids:
            return []
        with self._conn_lock:
            rows = self.conn.execute(
                f"SELECT {_EVENT_SELECT} FROM events WHERE event_id IN (SELECT UNNEST(?))",
                [list(event_ids)]).fetchall()
        return [_hydrate(*r) for r in rows if r and r[0]]

    def stats(self) -> dict:
        """StorageBackend interface alias."""
        return self.get_stats()

    def get_stats(self) -> dict:
        """Aggregate statistics, cached for 1 s so GUI polling never stalls ingestion."""
        now = time.time()
        with self._stats_lock:
            if self._stats_cache and now - self._stats_cache_ts < 1.0:
                res = dict(self._stats_cache)
                res["total_events"] = max(res.get("total_events", 0), self._live_total_events)
                return res
        with self._conn_lock:
            try:
                total = self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                by_format = dict(self.conn.execute(
                    "SELECT raw_format, COUNT(*) FROM events GROUP BY raw_format").fetchall())
                by_category = dict(self.conn.execute(
                    "SELECT category, COUNT(*) FROM events GROUP BY category").fetchall())
                by_severity = dict(self.conn.execute(
                    "SELECT severity, COUNT(*) FROM events GROUP BY severity").fetchall())
                by_action = dict(self.conn.execute(
                    "SELECT action, COUNT(*) FROM events GROUP BY action").fetchall())
            except duckdb.Error as e:
                logger.error(f"Stats query failed: {e}")
                with self._stats_lock:
                    return dict(self._stats_cache) or {"total_events": self._live_total_events,
                                                       "by_format": {}, "by_category": {},
                                                       "by_severity": {}, "by_action": {}}
        res = {"total_events": total, "by_format": by_format, "by_category": by_category,
               "by_severity": by_severity, "by_action": by_action}
        if self.partitioned:
            res["partitions"] = len(self._parts)
        with self._stats_lock:
            self._live_total_events = total
            self._stats_cache = res
            self._stats_cache_ts = now
        return dict(res)

    # -------------------------------------------------------------------
    # Anomalies
    # -------------------------------------------------------------------

    def store_anomaly(self, anomaly: dict):
        self.store_anomalies_bulk([anomaly])

    def store_anomalies_bulk(self, anomalies: list[dict]):
        if not anomalies or self.read_only:
            return
        # Arrow bulk insert: executemany() is row-at-a-time in DuckDB
        table = pa.table({
            "anomaly_type": pa.array([_str_or_none(a.get("type") or a.get("anomaly_type")) for a in anomalies],
                                     pa.string()),
            "description": pa.array([_str_or_none(a.get("description")) for a in anomalies], pa.string()),
            "risk": pa.array([_str_or_none(a.get("risk")) for a in anomalies], pa.string()),
            "event_id": pa.array([_str_or_none(a.get("event_id")) for a in anomalies], pa.string()),
            "details_json": pa.array([_json(a) for a in anomalies], pa.string()),
        })
        with self._conn_lock:
            self._batch_seq += 1
            name = f"ulpf_anom_{self._batch_seq}"
            self.conn.register(name, table)
            try:
                self.conn.execute(
                    "INSERT INTO main.anomalies (anomaly_type, description, risk, event_id, details_json) "
                    f"SELECT anomaly_type, description, risk, event_id, details_json FROM {name}")
            finally:
                self.conn.unregister(name)

    def query_anomalies(self, limit: int = 100) -> list[dict]:
        with self._conn_lock:
            rows = self.conn.execute(
                "SELECT details_json FROM main.anomalies ORDER BY detected_at DESC LIMIT ?", [int(limit)]).fetchall()
        return [orjson.loads(r[0]) for r in rows if r and r[0]]

    # -------------------------------------------------------------------
    # Maintenance
    # -------------------------------------------------------------------

    def _invalidate_stats(self) -> None:
        with self._stats_lock:
            self._stats_cache = {}
            self._stats_cache_ts = 0.0
            self._live_total_events = 0

    def purge_raw_fallback(self) -> int:
        """Delete unclassified raw_fallback events. Returns rows deleted."""
        self._require_writable()
        with self._conn_lock:
            cnt = self.conn.execute(
                "SELECT COUNT(*) FROM events WHERE raw_format = 'raw_fallback'").fetchone()[0]
        if cnt:
            self.execute_on_partitions("DELETE FROM {events} WHERE raw_format = 'raw_fallback'",
                                       probe="raw_format = 'raw_fallback'")
        self._invalidate_stats()
        return cnt

    def purge_older_than(self, days: float, by: str = "ingested_at") -> int:
        """Retention: delete events older than ``days``. Returns rows deleted.

        ``by="ingested_at"`` (default) uses arrival time; ``by="timestamp"`` uses
        the normalised event time (UTC ISO-8601 strings compare chronologically).
        A partitioned store first retires whole partitions that ended before the
        cutoff, then deletes the remaining old rows of partitions straddling it.
        """
        self._require_writable()
        from datetime import datetime, timedelta, timezone
        cutoff = datetime.now(timezone.utc) - timedelta(days=float(days))
        seconds = int(float(days) * 86400)
        # ingested_at / detected_at are written by DuckDB's CURRENT_TIMESTAMP, so the
        # cutoff is computed by DuckDB on the same clock and session time zone.
        db_cutoff = "(CAST(now() AS TIMESTAMP) - to_seconds(CAST(? AS BIGINT)))"
        if by == "timestamp":
            where, param = "timestamp < ?", cutoff.isoformat()
        else:
            where, param = f"ingested_at < {db_cutoff}", seconds
        with self._conn_lock:
            n = self.conn.execute(f"SELECT COUNT(*) FROM events WHERE {where}", [param]).fetchone()[0]
        if self.partitioned and by != "timestamp":
            self.apply_retention(days)
        if n:
            self.execute_on_partitions(f"DELETE FROM {{events}} WHERE {where}", [param], probe=where,
                                       probe_params=[param])
        with self._conn_lock:
            self.conn.execute(f"DELETE FROM main.anomalies WHERE detected_at < {db_cutoff}", [seconds])
            self.conn.execute("CHECKPOINT")
        self._invalidate_stats()
        return n

    def reset_database(self) -> None:
        """Delete all events and anomalies."""
        self._require_writable()
        with self._conn_lock:
            if self.partitioned:
                for p in [p for p in self._parts if p is not self._hot]:
                    self._retire(p, "reset", archive=False)
                self.conn.execute("DELETE FROM hot.events")
                self.conn.execute("DELETE FROM hot.ulpf_segments")
                self.conn.execute("CHECKPOINT hot")
                self._rebuild_views()
            else:
                self.conn.execute("DROP TABLE IF EXISTS events")
                self.conn.execute(_EVENTS_DDL.format(table="events"))
            self.conn.execute("DROP TABLE IF EXISTS main.anomalies")
            self.conn.execute("DROP TABLE IF EXISTS ulpf_correlations")
            self._init_tables()
            self.conn.execute("CHECKPOINT")
        self._invalidate_stats()

    def close(self):
        with self._conn_lock:
            try:
                self.conn.close()
            except duckdb.Error:
                pass
