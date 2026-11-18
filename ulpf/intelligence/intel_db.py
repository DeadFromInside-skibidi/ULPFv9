"""
Embedded Threat-Intelligence / GeoIP Store
==========================================
SQLite-backed cache for IOC and GeoIP feeds so large feeds stay out of Python
dictionaries. Lookups are O(1) negative checks against in-memory key sets and
LRU-cached positive hits.
"""
import json
import logging
import os
import sqlite3
import threading
from functools import lru_cache
from typing import Any

logger = logging.getLogger(__name__)


def _resolve_db_path() -> str:
    """Resolve the intel cache DB path.

    Lives in the ULPF data directory (writable even for read-only installs).
    When ULPF_INTEL_DB_DIR is set (multi-process benchmarks), each process
    uses a PID-unique file to avoid SQLite lock contention.
    """
    bench_dir = os.environ.get("ULPF_INTEL_DB_DIR")
    if bench_dir:
        return os.path.join(bench_dir, f"intel_cache_{os.getpid()}.sqlite")
    from ulpf.platform.paths import get_data_dir
    return str(get_data_dir() / "intel_cache.sqlite")


class IntelDB:
    """
    SQLite-backed embedded cache for Threat Intelligence (IOCs) and GeoIP.
    """
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or _resolve_db_path()
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        # sqlite3 connections are not shareable across threads: one per thread
        self._local = threading.local()
        self._write_lock = threading.Lock()
        self._ioc_keys: set[str] = set()
        self._geo_prefixes: set[str] = set()
        self._init_schema()

    @property
    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.db_path, check_same_thread=False, timeout=10)
            self._local.conn = c
        return c

    def _init_schema(self):
        c = self.conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS iocs (ip VARCHAR PRIMARY KEY, cat VARCHAR, conf DOUBLE)")
        c.execute("""
            CREATE TABLE IF NOT EXISTS geoip (
                prefix VARCHAR PRIMARY KEY, country VARCHAR, cc VARCHAR,
                city VARCHAR, lat DOUBLE, lon DOUBLE
            )
        """)
        c.execute("CREATE TABLE IF NOT EXISTS feeds (path VARCHAR PRIMARY KEY, mtime DOUBLE)")
        self.conn.commit()
        c.execute("SELECT ip FROM iocs")
        self._ioc_keys = {r[0] for r in c.fetchall()}
        c.execute("SELECT prefix FROM geoip")
        self._geo_prefixes = {r[0] for r in c.fetchall()}

    def feed_is_current(self, file_path: str) -> bool:
        """True if this feed file was already ingested and has not changed since."""
        try:
            mtime = os.path.getmtime(file_path)
        except OSError:
            return True
        row = self.conn.execute("SELECT mtime FROM feeds WHERE path = ?",
                                (os.path.abspath(file_path),)).fetchone()
        return bool(row) and row[0] >= mtime

    def _mark_feed(self, file_path: str) -> None:
        self.conn.execute("INSERT OR REPLACE INTO feeds (path, mtime) VALUES (?, ?)",
                          (os.path.abspath(file_path), os.path.getmtime(file_path)))

    @lru_cache(maxsize=16384)
    def lookup_ioc(self, ip: str) -> dict | None:
        if not ip or ip not in self._ioc_keys:
            return None
        row = self.conn.execute("SELECT cat, conf FROM iocs WHERE ip = ?", (ip,)).fetchone()
        return {"cat": row[0], "conf": row[1]} if row else None

    @lru_cache(maxsize=4096)
    def _get_geo_by_prefix(self, prefix: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT country, cc, city, lat, lon FROM geoip WHERE prefix = ?", (prefix,)).fetchone()
        return {"country": row[0], "cc": row[1], "city": row[2], "lat": row[3], "lon": row[4]} if row else None

    def lookup_geo(self, ip: str) -> dict[str, Any] | None:
        if not ip:
            return None
        if ip in self._geo_prefixes:
            return self._get_geo_by_prefix(ip)
        parts = ip.split(".")
        if len(parts) == 4:
            for prefix in (f"{parts[0]}.{parts[1]}.{parts[2]}.", f"{parts[0]}.{parts[1]}.", f"{parts[0]}."):
                if prefix in self._geo_prefixes:
                    return self._get_geo_by_prefix(prefix)
        return None

    def _invalidate(self) -> None:
        self.lookup_ioc.cache_clear()
        self._get_geo_by_prefix.cache_clear()

    def ingest_iocs_json(self, file_path: str) -> int:
        """Ingest a JSON feed of IOCs ({ip: {cat, conf}}) into the cache."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load IOCs from {file_path}: {e}")
            return 0
        rows = [(ip, info.get("cat", "Unknown"), float(info.get("conf", 0.5)))
                for ip, info in data.items() if not ip.startswith("_") and isinstance(info, dict)]
        with self._write_lock:
            self.conn.executemany("INSERT OR REPLACE INTO iocs (ip, cat, conf) VALUES (?, ?, ?)", rows)
            self._mark_feed(file_path)
            self.conn.commit()
            self._ioc_keys.update(r[0] for r in rows)
            self._invalidate()
        return len(rows)

    def ingest_geoip_json(self, file_path: str) -> int:
        """Ingest a JSON feed of GeoIP prefixes ({prefix: {country, cc, city, lat, lon}})."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load GeoIP from {file_path}: {e}")
            return 0
        def coord(v):   # absent coordinates stay absent (not 0,0)
            return float(v) if v is not None else None
        rows = [(prefix, info.get("country", "Unknown"), info.get("cc", "??"), info.get("city", "Unknown"),
                 coord(info.get("lat")), coord(info.get("lon")))
                for prefix, info in data.items() if not prefix.startswith("_") and isinstance(info, dict)]
        with self._write_lock:
            # The file is the whole feed: prefixes removed from it must not linger
            self.conn.execute("DELETE FROM geoip")
            self.conn.executemany(
                "INSERT OR REPLACE INTO geoip (prefix, country, cc, city, lat, lon) VALUES (?, ?, ?, ?, ?, ?)", rows)
            self._mark_feed(file_path)
            self.conn.commit()
            self._geo_prefixes = {r[0] for r in rows}
            self._invalidate()
        return len(rows)


_db_instance: IntelDB | None = None
_db_lock = threading.Lock()


def get_intel_db() -> IntelDB:
    global _db_instance
    if _db_instance is None:
        with _db_lock:
            if _db_instance is None:
                _db_instance = IntelDB()
    return _db_instance
