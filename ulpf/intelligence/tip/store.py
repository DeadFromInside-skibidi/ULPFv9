"""
Threat-intelligence store: every indicator of every feed (SQLite, ``<data dir>/intel/tip.db``), feed
cursors, and the confidence decay that retires stale indicators.

Decay: ``confidence(t) = published * 0.5 ** ((t - last_seen) / half_life)``. A feed that publishes the
indicator again (or ``sight``) resets ``last_seen``; indicators past ``valid_until`` or below
``min_confidence`` leave the match set. Half-lives are per kind (IP addresses churn in days, file
hashes stay bad for a year); a half-life of 0 never decays (the bundled ``config/iocs.json``).
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

from ulpf.intelligence.tip.indicators import KINDS, Indicator, normalize

DEFAULT_HALF_LIFE_DAYS = {"ip": 14, "cidr": 30, "domain": 45, "domain_wildcard": 60, "url": 30, "md5": 365,
                          "sha1": 365, "sha256": 365, "email": 90, "mutex": 365, "registry": 365}
MAX_TEXT = 256

_SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    kind TEXT NOT NULL, value TEXT NOT NULL, source TEXT NOT NULL,
    confidence REAL NOT NULL, category TEXT, threat_actor TEXT, campaign TEXT, kill_chain_phase TEXT,
    diamond TEXT, stix_id TEXT, first_seen REAL, last_seen REAL, valid_until REAL, half_life REAL,
    flags INTEGER DEFAULT 0, revoked INTEGER DEFAULT 0,
    PRIMARY KEY (kind, value, source));
CREATE INDEX IF NOT EXISTS indicators_value ON indicators(value);
CREATE INDEX IF NOT EXISTS indicators_stix ON indicators(stix_id);
CREATE TABLE IF NOT EXISTS feeds (
    name TEXT PRIMARY KEY, type TEXT, cursor TEXT, last_sync REAL, last_error TEXT, imported INTEGER DEFAULT 0);
"""


def effective(conf: float, last_seen: float | None, half_life: float | None, now: float) -> float:
    if not half_life or last_seen is None:
        return conf
    age = max(0.0, now - last_seen)
    return conf * 0.5 ** (age / half_life)


def _clip(s) -> str:
    return "" if s is None else str(s)[:MAX_TEXT]


class TipStore:
    def __init__(self, path: str, half_life_days: dict | None = None, max_indicators: int = 10_000_000):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(_SCHEMA)
        self.lock = threading.RLock()
        self.half_life = {k: float(v) * 86400 for k, v in {**DEFAULT_HALF_LIFE_DAYS, **(half_life_days or {})}.items()}
        self.max_indicators = max_indicators

    def close(self) -> None:
        self.db.close()

    # ---- writes
    def upsert(self, indicators, source: str, now: float | None = None, no_decay: bool = False) -> dict:
        """Add or refresh indicators of one feed. Returns {"added", "updated", "rejected"}.

        An indicator seen again keeps its first_seen and gets the newer last_seen / confidence."""
        now = now or time.time()
        stats = {"added": 0, "updated": 0, "rejected": 0}
        rows = []
        for ind in indicators:
            kv = normalize(ind.kind, ind.value)
            conf = ind.confidence
            if kv is None or not isinstance(conf, (int, float)) or not 0.0 <= conf <= 1.0:
                stats["rejected"] += 1
                continue
            kind, value = kv
            hl = 0.0 if no_decay else self.half_life.get(kind, 30 * 86400)
            first = ind.first_seen if ind.first_seen is not None else now
            last = ind.last_seen if ind.last_seen is not None else now
            rows.append((kind, value, _clip(source or ind.source or "manual"), float(conf), _clip(ind.category) or "Unknown",
                         _clip(ind.threat_actor), _clip(ind.campaign), _clip(ind.kill_chain_phase),
                         json.dumps(ind.diamond, sort_keys=True)[:4096] if ind.diamond else None, _clip(ind.stix_id),
                         min(first, last), last, ind.valid_until, hl, int(ind.flags)))
        with self.lock:
            before = self.count()
            room = self.max_indicators - before
            if len(rows) > room:                       # bounded: new rows beyond the cap are dropped
                exist = self.db.execute
                keep, extra = [], 0
                for r in rows:
                    if exist("SELECT 1 FROM indicators WHERE kind=? AND value=? AND source=?", r[:3]).fetchone():
                        keep.append(r)
                    elif extra < room:
                        keep.append(r)
                        extra += 1
                stats["rejected"] += len(rows) - len(keep)
                rows = keep
            self.db.executemany("""INSERT INTO indicators VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)
                ON CONFLICT(kind, value, source) DO UPDATE SET confidence=excluded.confidence,
                    category=excluded.category, threat_actor=excluded.threat_actor, campaign=excluded.campaign,
                    kill_chain_phase=excluded.kill_chain_phase, diamond=excluded.diamond, stix_id=excluded.stix_id,
                    first_seen=min(coalesce(indicators.first_seen, excluded.first_seen), excluded.first_seen),
                    last_seen=max(coalesce(indicators.last_seen, 0), excluded.last_seen),
                    valid_until=excluded.valid_until, half_life=excluded.half_life, flags=excluded.flags, revoked=0""",
                                rows)
            self.db.commit()
            stats["added"] = self.count() - before
            stats["updated"] = len(rows) - stats["added"]
        return stats

    def revoke(self, stix_ids=None, source: str | None = None, keep: set | None = None) -> int:
        """Revoke by STIX id, or (``source`` + ``keep``) every indicator of a feed not in ``keep``."""
        with self.lock:
            n = 0
            if stix_ids:
                for sid in stix_ids:
                    n += self.db.execute("UPDATE indicators SET revoked=1 WHERE stix_id=?", (sid,)).rowcount
            elif source is not None and keep is not None:
                for kind, value in self.db.execute("SELECT kind, value FROM indicators WHERE source=? AND revoked=0",
                                                   (source,)).fetchall():
                    if (kind, value) not in keep:
                        n += self.db.execute("UPDATE indicators SET revoked=1 WHERE kind=? AND value=? AND source=?",
                                             (kind, value, source)).rowcount
            self.db.commit()
        return n

    def sight(self, kind: str, value: str, now: float | None = None) -> int:
        """Re-sighting (analyst, sandbox, another feed): resets the decay clock of every copy."""
        kv = normalize(kind, value)
        if kv is None:
            return 0
        with self.lock:
            n = self.db.execute("UPDATE indicators SET last_seen=? WHERE kind=? AND value=?",
                                (now or time.time(), *kv)).rowcount
            self.db.commit()
        return n

    def purge(self, min_confidence: float, now: float | None = None) -> int:
        """Delete revoked, expired and fully decayed indicators."""
        now = now or time.time()
        drop = []
        for rowid, conf, last, hl, until in self.db.execute(
                "SELECT rowid, confidence, last_seen, half_life, valid_until FROM indicators"):
            if (until is not None and until < now) or effective(conf, last, hl, now) < min_confidence / 4:
                drop.append((rowid,))
        with self.lock:
            self.db.executemany("DELETE FROM indicators WHERE rowid=?", drop)
            self.db.execute("DELETE FROM indicators WHERE revoked=1")
            self.db.commit()
        return len(drop)

    # ---- feed cursors
    def feed_state(self, name: str) -> dict:
        r = self.db.execute("SELECT type, cursor, last_sync, last_error, imported FROM feeds WHERE name=?",
                            (name,)).fetchone()
        return dict(zip(("type", "cursor", "last_sync", "last_error", "imported"), r)) if r else {}

    def set_feed_state(self, name: str, typ: str, cursor=None, error: str | None = None, imported: int = 0) -> None:
        with self.lock:
            self.db.execute("""INSERT INTO feeds VALUES (?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET type=excluded.type,
                               cursor=coalesce(excluded.cursor, feeds.cursor), last_sync=excluded.last_sync,
                               last_error=excluded.last_error, imported=feeds.imported + excluded.imported""",
                            (name, typ, cursor, time.time(), (error or "")[:500] or None, imported))
            self.db.commit()

    def feeds(self) -> list[dict]:
        cols = ("name", "type", "cursor", "last_sync", "last_error", "imported")
        return [dict(zip(cols, r)) for r in self.db.execute(f"SELECT {', '.join(cols)} FROM feeds ORDER BY name")]

    # ---- reads
    def count(self) -> int:
        return self.db.execute("SELECT count(*) FROM indicators").fetchone()[0]

    def active(self, min_confidence: float, now: float | None = None):
        """(kind, value, confidence now, category, actor, campaign, kill_chain, id, source, flags) of every
        indicator in force, best copy of each value first."""
        now = now or time.time()
        best: dict = {}
        for (kind, value, source, conf, cat, actor, camp, kill, sid, last, until, hl, flags) in self.db.execute(
                """SELECT kind, value, source, confidence, category, threat_actor, campaign, kill_chain_phase,
                          stix_id, last_seen, valid_until, half_life, flags FROM indicators WHERE revoked=0"""):
            if until is not None and until < now:
                continue
            c = effective(conf, last, hl, now)
            if c < min_confidence:
                continue
            k = (kind, value)
            old = best.get(k)
            if old is None or c > old[2]:
                best[k] = (kind, value, round(c, 4), cat, actor, camp, kill, sid, source, flags)
        return sorted(best.values(), key=lambda r: -r[2])

    def lookup(self, value: str, now: float | None = None) -> list[dict]:
        now = now or time.time()
        out = []
        cands = {value, value.strip().lower()}
        for kind in ("auto", "hash", "domain_wildcard"):
            kv = normalize(kind, value)
            if kv:
                cands.add(kv[1])
        cols = ("kind", "value", "source", "confidence", "category", "threat_actor", "campaign", "kill_chain_phase",
                "diamond", "stix_id", "first_seen", "last_seen", "valid_until", "half_life", "flags", "revoked")
        for v in cands:
            for r in self.db.execute(f"SELECT {', '.join(cols)} FROM indicators WHERE value=?", (v,)):
                d = dict(zip(cols, r))
                d["diamond"] = json.loads(d["diamond"]) if d["diamond"] else {}
                d["effective_confidence"] = round(effective(d["confidence"], d["last_seen"], d["half_life"], now), 4)
                out.append(d)
        return out

    def stats(self, min_confidence: float, now: float | None = None) -> dict:
        by_kind = dict(self.db.execute("SELECT kind, count(*) FROM indicators WHERE revoked=0 GROUP BY kind"))
        by_source = dict(self.db.execute("SELECT source, count(*) FROM indicators WHERE revoked=0 GROUP BY source"))
        return {"indicators": sum(by_kind.values()), "by_kind": {k: by_kind.get(k, 0) for k in KINDS if k},
                "by_source": by_source, "feeds": self.feeds()}


def indicator(kind, value, **kw) -> Indicator:
    return Indicator(kind=kind, value=value, **kw)
