"""
Risk-based alerting (Splunk RBA style): detections add risk to the entities they involve
(users, hosts, IP addresses, domains); risk decays with a half-life; an entity whose
cumulative risk crosses its threshold raises one Notable Incident.

Score of an entity at time t: ``sum(score_i * 0.5 ** ((t - t_i) / half_life))``, kept as one
decayed total per entity (O(1) per risk event). Thresholds are per entity type and dynamic:
``max(base, mean + k * stdev)`` of the current scores of that type once ``min_entities``
entities carry risk, so a noisy environment does not page on its normal level. An entity
also becomes notable when its risk events span ``tactic_threshold`` distinct MITRE ATT&CK
tactics. After a notable, the entity is quiet for ``suppress_hours`` unless its score grows by
``renotify_growth`` (a fraction). State is bounded (lowest scores dropped) and can be saved
and restored.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field

ENTITY_TYPES = ("user", "host", "ip", "domain")
LEVEL_SCORES = {"informational": 5, "low": 15, "medium": 30, "high": 50, "critical": 80}


@dataclass
class RiskEvent:
    entity_type: str
    entity: str
    score: float
    ts: float
    source: str                 # rule id / title
    tactics: tuple = ()
    techniques: tuple = ()
    event_id: str | None = None
    kind: str = "sigma"


@dataclass
class _Entity:
    total: float = 0.0
    t: float = 0.0
    events: int = 0
    tactics: dict = field(default_factory=dict)       # tactic -> last time
    techniques: dict = field(default_factory=dict)
    sources: dict = field(default_factory=dict)       # rule -> risk contributed
    recent: deque = field(default_factory=lambda: deque(maxlen=20))
    notified_at: float | None = None
    notified_score: float = 0.0


class RiskEngine:
    def __init__(self, half_life_days: float = 7.0, thresholds: dict | None = None, dynamic: bool = True,
                 dynamic_sigma: float = 3.0, min_entities: int = 20, tactic_threshold: int = 3,
                 suppress_hours: float = 24.0, renotify_growth: float = 0.5, max_entities: int = 200_000,
                 level_scores: dict | None = None):
        self.half_life = float(half_life_days) * 86400
        self.base = {t: 100.0 for t in ENTITY_TYPES}
        self.base.update({k: float(v) for k, v in (thresholds or {}).items()})
        self.dynamic, self.k, self.min_entities = dynamic, float(dynamic_sigma), int(min_entities)
        self.tactic_threshold = int(tactic_threshold)
        self.suppress = float(suppress_hours) * 3600
        self.growth = float(renotify_growth)
        self.max_entities = int(max_entities)
        self.level_scores = {**LEVEL_SCORES, **(level_scores or {})}
        self.entities: dict[tuple, _Entity] = {}
        self.notables: deque = deque(maxlen=1000)
        self._thr: dict[str, float] = {}
        self._thr_at = -1e18
        self._thr_n = 0                 # entities when the dynamic thresholds were computed
        self._lock = threading.Lock()
        self.stats = {"risk_events": 0, "notables": 0, "evicted": 0}

    # ---- scores
    def _decay(self, e: _Entity, now: float) -> float:
        if now <= e.t:
            return e.total
        return e.total * math.pow(0.5, (now - e.t) / self.half_life)

    def score(self, entity_type: str, entity: str, now: float | None = None) -> float:
        e = self.entities.get((entity_type, entity))
        return 0.0 if e is None else self._decay(e, now if now is not None else e.t)

    def threshold(self, entity_type: str, now: float) -> float:
        base = self.base.get(entity_type, 100.0)
        if not self.dynamic:
            return base
        n = len(self.entities)
        if now - self._thr_at > 60 or now < self._thr_at or abs(n - self._thr_n) > max(10, self._thr_n // 10):
            self._thr, self._thr_at, self._thr_n = {}, now, n
            per: dict[str, list] = {}
            for (t, _), e in self.entities.items():
                per.setdefault(t, []).append(self._decay(e, now))
            for t, vals in per.items():
                if len(vals) >= self.min_entities:
                    mean = sum(vals) / len(vals)
                    sd = math.sqrt(sum((v - mean) ** 2 for v in vals) / len(vals))
                    self._thr[t] = mean + self.k * sd
        return max(base, self._thr.get(entity_type, 0.0))

    def _tactics(self, e: _Entity, now: float) -> list:
        return sorted(t for t, at in e.tactics.items() if now - at <= self.half_life)

    # ---- input
    def add(self, events: list[RiskEvent]) -> list[dict]:
        """Apply risk events (any order); returns the Notable Incidents they raise."""
        out = []
        with self._lock:
            for r in sorted(events, key=lambda x: x.ts):
                if not r.entity or r.score <= 0:
                    continue
                key = (r.entity_type, str(r.entity))
                e = self.entities.get(key)
                if e is None:
                    e = self.entities[key] = _Entity(t=r.ts)
                    if len(self.entities) > self.max_entities:
                        self._evict(r.ts)
                if r.ts >= e.t:
                    e.total = self._decay(e, r.ts) + r.score
                    e.t = r.ts
                else:                                     # late event: add it already decayed
                    e.total += r.score * math.pow(0.5, (e.t - r.ts) / self.half_life)
                e.events += 1
                for t in r.tactics:
                    e.tactics[t] = max(e.tactics.get(t, 0.0), r.ts)
                for t in r.techniques:
                    e.techniques[t] = max(e.techniques.get(t, 0.0), r.ts)
                e.sources[r.source] = e.sources.get(r.source, 0.0) + r.score
                e.recent.append({"source": r.source, "score": r.score, "ts": r.ts, "event_id": r.event_id,
                                 "kind": r.kind, "tactics": list(r.tactics)})
                self.stats["risk_events"] += 1
                n = self._check(key, e, r.ts)
                if n:
                    out.append(n)
        return out

    def _check(self, key, e: _Entity, now: float) -> dict | None:
        score = self._decay(e, now)
        thr = self.threshold(key[0], now)
        tactics = self._tactics(e, now)
        reasons = []
        if score >= thr:
            reasons.append(f"risk score {score:.0f} >= threshold {thr:.0f}")
        if len(tactics) >= self.tactic_threshold:
            reasons.append(f"{len(tactics)} ATT&CK tactics: {', '.join(tactics)}")
        if not reasons:
            return None
        if e.notified_at is not None and now - e.notified_at < self.suppress and \
                score < e.notified_score * (1 + self.growth):
            return None
        e.notified_at, e.notified_score = now, score
        top = sorted(e.sources.items(), key=lambda kv: -kv[1])[:10]
        n = {"entity_type": key[0], "entity": key[1], "score": round(score, 2), "threshold": round(thr, 2),
             "reasons": reasons, "tactics": tactics,
             "techniques": sorted(t for t, at in e.techniques.items() if now - at <= self.half_life),
             "risk_events": e.events, "top_sources": [{"source": s, "risk": round(v, 2)} for s, v in top],
             "recent": list(e.recent), "time": now}
        self.notables.append(n)
        self.stats["notables"] += 1
        return n

    def _evict(self, now: float) -> None:
        """Drop the lowest-scoring tenth of the entities (never one notified in the last day)."""
        ranked = sorted(self.entities.items(), key=lambda kv: self._decay(kv[1], now))
        drop = max(1, len(ranked) // 10)
        for key, e in ranked:
            if drop == 0:
                break
            if e.notified_at is not None and now - e.notified_at < 86400:
                continue
            del self.entities[key]
            drop -= 1
            self.stats["evicted"] += 1

    # ---- views
    def top(self, entity_type: str | None = None, min_score: float = 0.0, limit: int = 100,
            now: float | None = None) -> list[dict]:
        now = now if now is not None else time.time()
        with self._lock:
            rows = []
            for (t, v), e in self.entities.items():
                if entity_type and t != entity_type:
                    continue
                s = self._decay(e, now)
                if s >= min_score:
                    rows.append({"entity_type": t, "entity": v, "score": round(s, 2), "risk_events": e.events,
                                 "tactics": self._tactics(e, now), "last_risk": e.t,
                                 "threshold": round(self.threshold(t, now), 2)})
        rows.sort(key=lambda r: -r["score"])
        return rows[:limit]

    def entity(self, entity_type: str, value: str, now: float | None = None) -> dict | None:
        e = self.entities.get((entity_type, value))
        if e is None:
            return None
        now = now if now is not None else time.time()
        return {"entity_type": entity_type, "entity": value, "score": round(self._decay(e, now), 2),
                "risk_events": e.events, "tactics": self._tactics(e, now), "techniques": sorted(e.techniques),
                "sources": dict(sorted(e.sources.items(), key=lambda kv: -kv[1])[:50]), "recent": list(e.recent)}

    # ---- persistence
    def save(self, path: str) -> None:
        with self._lock:
            data = {"v": 1, "entities": [[t, v, e.total, e.t, e.events, e.tactics, e.techniques, e.sources,
                                          list(e.recent), e.notified_at, e.notified_score]
                                         for (t, v), e in self.entities.items()],
                    "notables": list(self.notables)}
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, path)

    def load(self, path: str) -> int:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return 0
        with self._lock:
            for t, v, total, ts, n, tac, tech, src, recent, nat, nsc in data.get("entities", []):
                e = _Entity(total=total, t=ts, events=n, tactics=tac, techniques=tech, sources=src,
                            notified_at=nat, notified_score=nsc)
                e.recent.extend(recent)
                self.entities[(t, v)] = e
            self.notables.extend(data.get("notables", []))
        return len(self.entities)


# ---------------------------------------------------------------------------- sources of risk

def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def entities_of(projection: dict) -> list[tuple[str, str]]:
    """The entities an event involves (from the worker projection of the event)."""
    out = []
    u = (projection.get("user") or {}).get("name")
    if u:
        out.append(("user", str(u)))
    h = (projection.get("device") or {}).get("hostname") or (projection.get("source") or {}).get("hostname")
    if h:
        out.append(("host", str(h)))
    ip = (projection.get("source") or {}).get("ip")
    if ip:
        out.append(("ip", str(ip)))
    dom = (projection.get("url") or {}).get("domain") or (projection.get("dns") or {}).get("question")
    if dom:
        out.append(("domain", str(dom).lower()))
    return out


def classify_entity(name: str, value) -> str | None:
    """Entity type of a YARA-L match variable (by its name, then its value)."""
    n = name.lower()
    v = str(value)
    if "user" in n or "account" in n or "principal" in n:
        return "user"
    if "host" in n or "asset" in n or "device" in n:
        return "host"
    if "ip" in n or _is_ip(v):
        return "ip" if _is_ip(v) else None
    if "domain" in n or ("." in v and any(c.isalpha() for c in v) and " " not in v):
        return "domain"
    return None
