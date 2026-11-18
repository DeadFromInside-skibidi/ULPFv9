"""
SQLite backing tables for UEBA state, with bounded in-memory caches in front.

The engine works on ``LRU`` caches (fixed number of entries); evicted and changed entries are
written behind to SQLite in batches (one transaction per flush), and a cache miss reads the row
back. So memory is bounded by the cache sizes while the state itself (identities, asset
bindings, baselines, timelines) survives restarts and can grow on disk.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections import OrderedDict

_SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (ident TEXT PRIMARY KEY, actor TEXT NOT NULL, kind TEXT,
    first_seen REAL, last_seen REAL);
CREATE INDEX IF NOT EXISTS identities_actor ON identities(actor);
CREATE TABLE IF NOT EXISTS actors (actor TEXT PRIMARY KEY, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS asset_bindings (ip TEXT NOT NULL, mac TEXT, hostname TEXT, os TEXT,
    first_seen REAL NOT NULL, last_seen REAL NOT NULL, source TEXT);
CREATE INDEX IF NOT EXISTS asset_bindings_ip ON asset_bindings(ip, first_seen);
CREATE TABLE IF NOT EXISTS profiles (actor TEXT PRIMARY KEY, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS timeline (actor TEXT NOT NULL, ts REAL NOT NULL, session TEXT, activity TEXT,
    doc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS timeline_actor ON timeline(actor, ts);
CREATE TABLE IF NOT EXISTS anomalies (ts REAL NOT NULL, actor TEXT, kind TEXT, score REAL, doc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS anomalies_ts ON anomalies(ts);
"""


class Store:
    def __init__(self, path: str | None):
        self.path = path or ":memory:"
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(_SCHEMA)
        self.lock = threading.RLock()
        self._pending: list[tuple[str, tuple]] = []

    def queue(self, sql: str, args: tuple) -> None:
        with self.lock:
            self._pending.append((sql, args))

    def flush(self) -> int:
        with self.lock:
            batch, self._pending = self._pending, []
            if not batch:
                return 0
            self.db.execute("BEGIN")
            try:
                for sql, args in batch:
                    self.db.execute(sql, args)
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
            return len(batch)

    def one(self, sql: str, args: tuple = ()):
        with self.lock:
            return self.db.execute(sql, args).fetchone()

    def all(self, sql: str, args: tuple = ()):
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    def close(self) -> None:
        self.flush()
        with self.lock:
            self.db.close()


class LRU:
    """A bounded dict: the least recently used entry is evicted (``on_evict(key, value)``)."""

    def __init__(self, maxsize: int, on_evict=None):
        self.max = maxsize
        self.d: OrderedDict = OrderedDict()
        self.on_evict = on_evict
        self.evictions = 0

    def get(self, k, default=None):
        v = self.d.get(k, default)
        if k in self.d:
            self.d.move_to_end(k)
        return v

    def __contains__(self, k) -> bool:
        return k in self.d

    def __len__(self) -> int:
        return len(self.d)

    def put(self, k, v) -> None:
        self.d[k] = v
        self.d.move_to_end(k)
        while len(self.d) > self.max:
            ok, ov = self.d.popitem(last=False)
            self.evictions += 1
            if self.on_evict:
                self.on_evict(ok, ov)

    def items(self):
        return self.d.items()

    def values(self):
        return self.d.values()


def dumps(x) -> str:
    return json.dumps(x, separators=(",", ":"), default=str)
