"""
Query execution: a plan compiled to DuckDB SQL, run in its own in-memory DuckDB instance
(``memory_limit`` and thread share per query) over the event store, a lakehouse output or an
Arrow table, under the workload governor.

Governor:
* admission is fair-share across analysts: waiting queries are granted round-robin by analyst,
  each analyst at most ``per_user`` running, at most ``max_concurrent`` overall, and a query's
  memory is reserved from ``memory_mb`` (the total) before it starts;
* each query has a deadline (queue wait included); past it the query is interrupted;
* CPU: every query runs with ``threads = cpus // max_concurrent`` (at least 1), so concurrent
  analysts share cores evenly instead of one query taking all of them.

The generated SQL only contains escaped literals and quoted identifiers; the instance is still
locked down (no file access, configuration locked) before it runs.
"""
from __future__ import annotations

import csv
import itertools
import os
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass

import duckdb
import pyarrow as pa

from ulpf.query import QuerySyntaxError, dialect_of, parse
from ulpf.query.resolve import LakeResolver, StoreResolver, qident
from ulpf.query.sqlgen import Gen, parse_datetime


class QueryError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


class Busy(QueryError):
    def __init__(self, message: str):
        super().__init__(message, 429)


class Timeout(QueryError):
    def __init__(self, message: str):
        super().__init__(message, 408)


@dataclass
class _Ticket:
    user: str
    mem: int
    granted: bool = False
    cancelled: bool = False


class Governor:
    def __init__(self, max_concurrent: int = 4, per_user: int = 2, memory_mb: int = 1024,
                 query_memory_mb: int = 256, max_queue: int = 64, timeout_s: float = 30.0):
        self.max_concurrent, self.per_user = max_concurrent, per_user
        self.memory_mb, self.query_memory_mb = memory_mb, min(query_memory_mb, memory_mb)
        self.max_queue, self.timeout_s = max_queue, timeout_s
        self.threads = max(1, (os.cpu_count() or 2) // max_concurrent)
        self._cv = threading.Condition()
        self._waiting: OrderedDict[str, deque] = OrderedDict()    # user -> tickets, in arrival order
        self._running: dict[str, int] = {}
        self._mem_used = 0
        self._rr = itertools.count()
        self.stats = {"admitted": 0, "rejected_busy": 0, "timeouts": 0, "completed": 0, "failed": 0}

    def _grant(self) -> None:
        """Grant free slots round-robin over analysts with waiting queries (lock held)."""
        while sum(self._running.values()) < self.max_concurrent:
            users = [u for u, q in self._waiting.items() if q and self._running.get(u, 0) < self.per_user]
            if not users:
                return
            granted = False
            for u in users:                      # OrderedDict order rotates: fair share
                t = self._waiting[u][0]
                if self._mem_used + t.mem > self.memory_mb:
                    continue
                self._waiting[u].popleft()
                if not self._waiting[u]:
                    del self._waiting[u]
                else:
                    self._waiting.move_to_end(u)
                t.granted = True
                self._running[u] = self._running.get(u, 0) + 1
                self._mem_used += t.mem
                granted = True
                break
            if not granted:
                return
        self._cv.notify_all()

    def acquire(self, user: str, deadline: float, mem_mb: int | None = None) -> _Ticket:
        mem = min(mem_mb or self.query_memory_mb, self.memory_mb)
        with self._cv:
            if sum(len(q) for q in self._waiting.values()) >= self.max_queue:
                self.stats["rejected_busy"] += 1
                raise Busy("query queue is full: retry later")
            t = _Ticket(user, mem)
            self._waiting.setdefault(user, deque()).append(t)
            self._grant()
            while not t.granted:
                left = deadline - time.monotonic()
                if left <= 0:
                    q = self._waiting.get(user)
                    if q and t in q:
                        q.remove(t)
                        if not q:
                            del self._waiting[user]
                    self.stats["timeouts"] += 1
                    raise Timeout("query waited past its deadline for a free slot")
                self._cv.wait(min(left, 0.5))
            self.stats["admitted"] += 1
            return t

    def release(self, t: _Ticket) -> None:
        with self._cv:
            self._running[t.user] -= 1
            if not self._running[t.user]:
                del self._running[t.user]
            self._mem_used -= t.mem
            self._grant()
            self._cv.notify_all()

    def snapshot(self) -> dict:
        with self._cv:
            return {"running": dict(self._running), "waiting": {u: len(q) for u, q in self._waiting.items()},
                    "memory_mb_reserved": self._mem_used, "memory_mb_total": self.memory_mb,
                    "max_concurrent": self.max_concurrent, "per_user": self.per_user,
                    "threads_per_query": self.threads, **self.stats}


# ---------------------------------------------------------------- result rows

def _iso(v):
    return None if v is None else v.isoformat().replace("+00:00", "Z")


def to_rows(table: pa.Table) -> tuple[list[dict], list[dict]]:
    """JSON-ready rows; timestamps as ISO-8601 UTC (no time-zone database needed)."""
    cols, arrays = [], []
    for f, col in zip(table.schema, table.columns):
        t = f.type
        if pa.types.is_timestamp(t) and t.tz:
            col = col.cast(pa.timestamp(t.unit))
            cols.append({"name": f.name, "type": "datetime"})
            arrays.append([None if v is None else v.isoformat() + "Z" for v in col.to_pylist()])
            continue
        if pa.types.is_list(t) and pa.types.is_timestamp(t.value_type) and t.value_type.tz:
            col = col.cast(pa.list_(pa.timestamp(t.value_type.unit)))
            cols.append({"name": f.name, "type": "datetime[]"})
            arrays.append([None if v is None else [x.isoformat() + "Z" if x else None for x in v]
                           for v in col.to_pylist()])
            continue
        cols.append({"name": f.name, "type": str(t)})
        arrays.append(col.to_pylist())
    names = [c["name"] for c in cols]
    return cols, [dict(zip(names, r)) for r in zip(*arrays)] if arrays else []


# ---------------------------------------------------------------- engine

class QueryEngine:
    """Runs KQL / SPL2 / HQL against the runtime's sources."""

    def __init__(self, database=None, lakes=None, lookup_dir: str | None = None, governor: Governor | None = None):
        self.database = database            # ulpf.storage.database.Database (the event store) or None
        self.lakes = lakes or (lambda name: None)
        self.lookup_dir = lookup_dir
        self.gov = governor or Governor()

    # ---- catalog
    def lookups(self) -> dict:
        out = {}
        d = self.lookup_dir
        if d and os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                if f.lower().endswith(".csv"):
                    with open(os.path.join(d, f), newline="", encoding="utf-8") as fh:
                        head = next(csv.reader(fh), [])
                    if head:
                        out[f[:-4]] = head
        return out

    def compile(self, dialect: str, text: str, source: str = "store", max_rows: int | None = None) -> tuple:
        plan = parse(dialect, text)
        resolver = LakeResolver() if source.startswith("lake:") else StoreResolver()
        gen = Gen(resolver, self.lookups(), strict=False)
        try:
            return plan, gen.compile(plan, max_rows)
        except RecursionError:
            raise QuerySyntaxError("query nested too deeply", text, 0) from None

    def run(self, dialect: str, text: str, *, source: str = "store", user: str = "anonymous", start=None, end=None,
            max_rows: int = 10_000, timeout_s: float | None = None, table: pa.Table | None = None) -> dict:
        t0 = time.monotonic()
        timeout_s = min(timeout_s or self.gov.timeout_s, self.gov.timeout_s * 10)
        deadline = t0 + timeout_s
        dialect = dialect_of(dialect)
        start, end = _time(start, "start"), _time(end, "end")
        plan, sql = self.compile(dialect, text, source if table is None else "store", max_rows + 1)
        ticket = self.gov.acquire(user, deadline)
        try:
            out = self._execute(sql, source, table, start, end, deadline, ticket)
            self.gov.stats["completed"] += 1
        except duckdb.InterruptException:
            self.gov.stats["timeouts"] += 1
            raise Timeout(f"query exceeded its {timeout_s:.0f} s deadline") from None
        except duckdb.Error as e:
            self.gov.stats["failed"] += 1
            raise QueryError(f"query failed: {str(e).splitlines()[0][:300]}") from None
        finally:
            self.gov.release(ticket)
        cols, rows = to_rows(out)
        truncated = len(rows) > max_rows
        return {"dialect": dialect, "source": source, "columns": cols, "rows": rows[:max_rows], "truncated": truncated,
                "elapsed_ms": round((time.monotonic() - t0) * 1000, 1), "sql": sql}

    def _execute(self, sql: str, source: str, table, start, end, deadline: float, ticket) -> pa.Table:
        if source.startswith("lake:") and table is None:
            return self._run_lake(sql, source[5:], start, end, deadline)
        con = duckdb.connect(config={"memory_limit": f"{ticket.mem}MB", "threads": self.gov.threads})
        timer = threading.Timer(max(0.0, deadline - time.monotonic()), con.interrupt)
        timer.daemon = True
        timer.start()
        try:
            con.execute("SET TimeZone='UTC'")
            if table is not None:
                con.register("events", _windowed(table, start, end))
            else:
                con.register("events", self._store_reader(start, end))
            for name in self.lookups():
                path = os.path.join(self.lookup_dir, name + ".csv").replace("\\", "/").replace("'", "''")
                con.execute(f"CREATE TEMP TABLE {qident('lookup_' + name)} AS SELECT * FROM "
                            f"read_csv('{path}', header=true, all_varchar=true)")
            con.execute("SET enable_external_access=false")
            con.execute("SET lock_configuration=true")
            return con.execute(sql).fetch_arrow_table()
        finally:
            timer.cancel()
            con.close()

    def _store_reader(self, start, end):
        db = self.database
        if db is None:
            raise QueryError("no event store: configure a duckdb output, or query a lakehouse (source=lake:<name>)", 404)
        where = []
        if start:
            where.append(f"TRY_CAST(\"timestamp\" AS TIMESTAMPTZ) >= TIMESTAMPTZ '{start.isoformat(sep=' ')}'")
        if end:
            where.append(f"TRY_CAST(\"timestamp\" AS TIMESTAMPTZ) <= TIMESTAMPTZ '{end.isoformat(sep=' ')}'")
        with db._conn_lock:
            rels = db._read_relations()              # the partitions (the store's events view is connection-local)
            cur = db.conn.cursor()                   # its own connection: no store lock while scanning
        cond = " WHERE " + " AND ".join(where) if where else ""
        q = " UNION ALL BY NAME ".join(f"SELECT * FROM {rel}{cond}" for rel in rels)
        return cur.execute(q).fetch_record_batch(16384)

    def _run_lake(self, sql, name, start, end, deadline):
        svc = self.lakes(name)
        if svc is None:
            raise QueryError(f"no lakehouse output named {name!r}", 404)
        table, _stats = svc.query.run(sql, None, start, end, max_rows=10**9,
                                      con_hook=lambda con: _arm(con, deadline))
        return table


def _arm(con, deadline):
    t = threading.Timer(max(0.0, deadline - time.monotonic()), con.interrupt)
    t.daemon = True
    t.start()
    return t


def _windowed(table: pa.Table, start, end) -> pa.Table:
    if not (start or end) or "timestamp" not in table.column_names:
        return table
    import pyarrow.compute as pc
    ts = table["timestamp"]
    if pa.types.is_string(ts.type):
        mask = None
        for bound, op in ((start, pc.greater_equal), (end, pc.less_equal)):
            if bound:
                iso = bound.astimezone(__import__("datetime").timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
                m = op(pc.utf8_slice_codeunits(ts, 0, 19), iso)
                mask = m if mask is None else pc.and_(mask, m)
        return table.filter(mask)
    return table


def _time(v, what):
    if v is None or v == "":
        return None
    if hasattr(v, "isoformat"):
        return v
    t = parse_datetime(str(v))
    if t is None:
        raise QueryError(f"{what}: not an ISO-8601 time: {v!r}")
    return t


__all__ = ["QueryEngine", "Governor", "QueryError", "Busy", "Timeout", "QuerySyntaxError", "to_rows"]
