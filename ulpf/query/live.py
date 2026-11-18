"""
Live tail: queries evaluated continuously on the ingest path, before anything is persisted.

Host (``LiveBus``): an analyst opens a tail; the query is parsed, must be row-level (where,
extend, project, rex, ... — no summarize / sort / join, which need all rows), and is compiled
to SQL over one batch. The current set of tails is broadcast to every worker as a lease
(re-sent every ``LEASE / 3`` seconds, so a respawned worker picks it up and a vanished host's
tails expire). Matches come back with each batch result and are fanned out to per-tail
bounded queues: a slow reader loses the oldest rows (counted), never stalls ingestion.

Worker (``LiveFilters``): while a lease is valid, each processed batch (the store-format Arrow
table the event store would get) is registered in a worker-local DuckDB connection and every
tail's SQL runs over it. Per batch a tail returns at most ``MAX_BATCH_ROWS`` rows; a tail
whose SQL fails is reported once and dropped. No tails: no cost.
"""
from __future__ import annotations

import threading
import time
import uuid
from collections import deque

from ulpf.query import QuerySyntaxError, dialect_of, parse
from ulpf.query.resolve import StoreResolver
from ulpf.query.sqlgen import Gen

LEASE = 15.0
MAX_BATCH_ROWS = 500


class LiveError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def compile_live(dialect: str, text: str) -> str:
    plan = parse(dialect, text)
    bad = next((type(s).__name__ for s in plan.stages if not _row_stage(s)), None)
    if bad is not None:
        raise LiveError(f"live tail runs row by row: {bad.lower()} needs all rows (use a historical query)")
    limit = next((s.n for s in plan.stages if type(s).__name__ == "Limit"), None)
    gen = Gen(StoreResolver(), {}, strict=False)
    try:
        return gen.compile(plan, min(MAX_BATCH_ROWS, limit or MAX_BATCH_ROWS))
    except RecursionError:
        raise QuerySyntaxError("query nested too deeply", text, 0) from None


def _row_stage(s) -> bool:
    from ulpf.query import ir
    return isinstance(s, (ir.Where, ir.Extend, ir.Project, ir.ProjectAway, ir.Rename, ir.Rex, ir.MvExpand)) or \
        (isinstance(s, ir.Limit) and not s.tail)


class _Tail:
    def __init__(self, tid, user, dialect, text, sql, queue_rows):
        self.id, self.user, self.dialect, self.text, self.sql = tid, user, dialect, text, sql
        self.rows: deque = deque(maxlen=queue_rows)
        self.matched = self.dropped = self.delivered = 0
        self.error: str | None = None
        self.created = self.last_poll = time.monotonic()


class LiveBus:
    def __init__(self, broadcast, max_tails: int = 32, per_user: int = 4, queue_rows: int = 10_000,
                 idle_seconds: float = 120.0):
        self.broadcast = broadcast              # broadcast(specs: list, lease_seconds: float)
        self.max_tails, self.per_user = max_tails, per_user
        self.queue_rows, self.idle = queue_rows, idle_seconds
        self.tails: dict[str, _Tail] = {}
        self._cv = threading.Condition()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="ulpf-live-bus", daemon=True)
        self._thread.start()

    # ---- analysts
    def open(self, user: str, dialect: str, text: str) -> dict:
        dialect = dialect_of(dialect)
        sql = compile_live(dialect, text)       # QuerySyntaxError / LiveError to the caller
        with self._cv:
            if len(self.tails) >= self.max_tails:
                raise LiveError("too many live tails open", 429)
            if sum(1 for t in self.tails.values() if t.user == user) >= self.per_user:
                raise LiveError(f"at most {self.per_user} live tails per analyst", 429)
            t = _Tail(uuid.uuid4().hex, user, dialect, text, sql, self.queue_rows)
            self.tails[t.id] = t
        self._push()
        return {"id": t.id, "dialect": dialect, "sql": sql}

    def _get(self, tid: str, user: str) -> _Tail:
        t = self.tails.get(tid)
        if t is None or (t.user != user and user != "admin"):
            raise LiveError("no such live tail", 404)
        return t

    def poll(self, tid: str, user: str, max_rows: int = 1000, wait: float = 0.0) -> dict:
        deadline = time.monotonic() + max(0.0, min(wait, 30.0))
        with self._cv:
            t = self._get(tid, user)
            t.last_poll = time.monotonic()
            while not t.rows and t.error is None and time.monotonic() < deadline and tid in self.tails:
                self._cv.wait(min(0.25, deadline - time.monotonic()))
            out = [t.rows.popleft() for _ in range(min(max_rows, len(t.rows)))]
            t.delivered += len(out)
            t.last_poll = time.monotonic()
            return {"id": tid, "rows": out, "pending": len(t.rows), "matched": t.matched, "dropped": t.dropped,
                    "error": t.error}

    def close(self, tid: str, user: str) -> None:
        with self._cv:
            self._get(tid, user)
            self.tails.pop(tid, None)
            self._cv.notify_all()
        self._push()

    def list(self, user: str) -> list:
        with self._cv:
            return [{"id": t.id, "user": t.user, "dialect": t.dialect, "query": t.text, "matched": t.matched,
                     "dropped": t.dropped, "pending": len(t.rows), "error": t.error,
                     "age_s": round(time.monotonic() - t.created, 1)}
                    for t in self.tails.values() if user in ("admin", t.user)]

    # ---- workers
    def publish(self, results: dict) -> None:
        """Matches from one worker batch: {tail id: rows | {"error": message}}."""
        with self._cv:
            for tid, rows in results.items():
                t = self.tails.get(tid)
                if t is None:
                    continue
                if isinstance(rows, dict):
                    t.error = rows.get("error") or "live filter failed"
                    continue
                t.matched += len(rows)
                over = len(t.rows) + len(rows) - t.rows.maxlen
                if over > 0:
                    t.dropped += over
                t.rows.extend(rows)
            self._cv.notify_all()

    def _specs(self) -> list:
        with self._cv:
            return [{"id": t.id, "sql": t.sql} for t in self.tails.values() if t.error is None]

    def _push(self) -> None:
        try:
            self.broadcast(self._specs(), LEASE)
        except Exception:
            pass

    def _loop(self) -> None:
        last = 0.0
        while not self._stop.wait(1.0):
            now = time.monotonic()
            with self._cv:
                idle = [k for k, t in self.tails.items() if now - t.last_poll > self.idle]
                for k in idle:
                    del self.tails[k]
            if idle or (self.tails and now - last >= LEASE / 3) or (not self.tails and last and now - last >= LEASE / 3):
                self._push()
                last = now

    def stop(self) -> None:
        self._stop.set()
        with self._cv:
            self.tails.clear()
        self._push()


class LiveFilters:
    """Worker side: the tails of the current lease, run over each batch."""

    def __init__(self):
        self.specs: list = []
        self.expires = 0.0
        self.con = None
        self.stats = {"batches": 0, "ms": 0.0}

    def set(self, specs: list, lease: float) -> None:
        self.specs = list(specs or [])
        self.expires = time.monotonic() + float(lease)

    def active(self) -> bool:
        return bool(self.specs) and time.monotonic() < self.expires

    def run(self, table) -> dict:
        import duckdb
        from ulpf.query.engine import to_rows
        if self.con is None:
            self.con = duckdb.connect(config={"memory_limit": "128MB", "threads": 1})
            self.con.execute("SET TimeZone='UTC'")
            self.con.execute("SET enable_external_access=false")
        t0 = time.perf_counter()
        out: dict = {}
        self.con.register("events", table)
        try:
            for spec in list(self.specs):
                try:
                    res = self.con.execute(spec["sql"]).fetch_arrow_table()
                except duckdb.Error as e:
                    out[spec["id"]] = {"error": str(e).splitlines()[0][:300]}
                    self.specs = [s for s in self.specs if s["id"] != spec["id"]]
                    continue
                if res.num_rows:
                    out[spec["id"]] = to_rows(res)[1][:MAX_BATCH_ROWS]
        finally:
            self.con.unregister("events")
        self.stats["batches"] += 1
        self.stats["ms"] += (time.perf_counter() - t0) * 1000
        return out


__all__ = ["LiveBus", "LiveFilters", "LiveError", "compile_live", "QuerySyntaxError"]
