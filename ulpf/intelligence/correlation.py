"""
Event Correlation Engine
=========================
Links related events across log sources:
  - Temporal correlation within a sliding time window
  - Indicator-based correlation (shared IPs, users, sessions, hostnames)
  - Kill-chain stage mapping (MITRE ATT&CK-aligned phases): keyword stages,
    plus the techniques / tactics of the Sigma rules the group's events matched
    (``ulpf.intelligence.sigma``; the bundled pack by default)
  - Composite 0-10 risk score per correlation group

Complexity: events are indexed on insert into entity buckets (deques with
amortised O(1) eviction), so correlating an event is O(B) in the size of its
matching buckets, not O(N). Related events always land in ONE group: when a
new event bridges existing groups, they are merged (union-find).

Memory is bounded: buckets are evicted by time and pruned when empty, and
the number of retained events/groups is capped.
"""
from __future__ import annotations

import re
from collections import OrderedDict, defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from ulpf.engine.schema import new_uuid
from ulpf.intelligence.sigma import LEVELS

_UTC = timezone.utc


def _kw(*words: str) -> re.Pattern:
    return re.compile(r"\b(?:" + "|".join(re.escape(w) for w in words) + r")", re.I)


# MITRE ATT&CK-aligned kill-chain stages. "ioc" lists threat-intel categories
# (config/iocs.json "cat") that imply the stage on their own.
KILL_CHAIN: dict[str, dict[str, Any]] = {
    "reconnaissance": {
        "pattern": _kw("scan", "probe", "nmap", "sweep", "enumerat", "attempted-recon", "discovery"),
        "ioc": ("scanner",),
        "severity_range": (1, 6),
    },
    "weaponization": {
        "pattern": _kw("payload", "malware", "trojan", "dropper", "weaponi"),
        "ioc": ("malware",),
        "severity_range": (5, 10),
    },
    "delivery": {
        "pattern": _kw("phish", "drive-by", "malicious attachment", "payload.exe", "malicious url"),
        "ioc": ("phishing",),
        "severity_range": (3, 10),
    },
    "exploitation": {
        "pattern": _kw("exploit", "overflow", "injection", "xss", "sqli", "rce", "cve-", "brute force",
                       "web-application-attack", "attempted-admin"),
        "ioc": ("brute force", "exploit"),
        "severity_range": (5, 10),
    },
    "installation": {
        "pattern": _kw("backdoor", "rootkit", "persistence", "webshell", "web shell"),
        "ioc": (),
        "severity_range": (6, 10),
    },
    "command_and_control": {
        "pattern": _kw("c2", "c&c", "command and control", "command-and-control", "beacon", "callback",
                       "trojan-activity"),
        "ioc": ("c2 server", "c2 domain", "botnet", "tor exit node"),
        "severity_range": (6, 10),
    },
    "exfiltration": {
        "pattern": _kw("exfil", "data leak", "dns tunnel", "tunneling", "data theft"),
        "ioc": ("dns tunneling", "exfiltration"),
        "severity_range": (6, 10),
    },
}
STAGE_ORDER = list(KILL_CHAIN)


class CorrelationGroup:
    """A group of correlated events."""

    def __init__(self, correlation_id: str | None = None):
        self.correlation_id: str = correlation_id or new_uuid().replace("-", "")[:12]
        self.events: list[dict] = []
        self.event_ids: set[str] = set()
        self.shared_indicators: dict[str, set[str]] = defaultdict(set)
        self.kill_chain_stages: list[str] = []
        self.time_span_seconds: float = 0.0
        self.risk_score: float = 0.0
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None
        self._stages: set[str] = set()
        self._max_severity = 0
        self._ioc_hit = False
        self._techniques: set[str] = set()
        self._tactics: set[str] = set()
        self._rules: dict[str, dict] = {}
        self._max_level = -1

    def add_rule_hit(self, rule) -> None:
        """A Sigma rule an event of this group matched (or an aggregation that fired)."""
        r = self._rules.get(rule.id)
        if r is None:
            r = self._rules[rule.id] = {"id": rule.id, "title": rule.title, "level": rule.level, "hits": 0}
        r["hits"] += 1
        self._techniques.update(rule.techniques)
        self._tactics.update(rule.tactics)
        self._stages.update(rule.stages)
        self._max_level = max(self._max_level, rule.level_score)

    def add(self, event: dict, ts: datetime, rules=()) -> bool:
        """Add an event, updating group metrics incrementally. False if already present."""
        eid = event.get("event_id") or str(id(event))
        if eid in self.event_ids:
            return False
        self.event_ids.add(eid)
        self.events.append(event)
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts
        self._stages.update(map_kill_chain([event]))
        self._max_severity = max(self._max_severity, event.get("severity") or 0)
        self._ioc_hit = self._ioc_hit or bool((event.get("threat") or {}).get("ioc_value"))
        for rule in rules:
            self.add_rule_hit(rule)
        event["correlation_id"] = self.correlation_id
        if len(self.events) <= 100:
            event["related_events"] = [e.get("event_id") for e in self.events[:-1]]
        return True

    def refresh(self) -> None:
        """Recompute derived fields from the incremental state."""
        if self.first_seen and self.last_seen:
            self.time_span_seconds = (self.last_seen - self.first_seen).total_seconds()
        self.kill_chain_stages = [s for s in STAGE_ORDER if s in self._stages]
        score = min(len(self._stages) * 1.5, 5.0)
        score += min(len(self.events) * 0.2, 1.5)
        score += self._max_severity * 0.25
        if self._ioc_hit:
            score += 1.0
        if self._max_level >= 0:
            # informational .. critical Sigma detections: +0 .. +2
            score += self._max_level * 0.5
        self.risk_score = min(score, 10.0)

    def to_dict(self) -> dict:
        return {
            "correlation_id": self.correlation_id,
            "event_count": len(self.events),
            "event_ids": [e.get("event_id", "unknown") for e in self.events],
            "shared_indicators": {k: sorted(v) for k, v in self.shared_indicators.items()},
            "kill_chain_stages": self.kill_chain_stages,
            "time_span_seconds": round(self.time_span_seconds, 2),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "risk_score": round(self.risk_score, 2),
            "mitre": self.mitre(),
            "sigma_rules": sorted(self._rules.values(), key=lambda r: (-LEVELS.get(r["level"], 2), r["id"])),
            "summary": self._build_summary(),
        }

    def mitre(self) -> dict:
        from ulpf.intelligence.sigma import TACTICS, TECHNIQUES
        tactics = [{"id": TACTICS[t][0], "name": TACTICS[t][1]} for t in TACTICS if t in self._tactics]
        techniques = [{"id": t, "name": TECHNIQUES.get(t) or TECHNIQUES.get(t.split(".")[0], "")}
                      for t in sorted(self._techniques)]
        return {"tactics": tactics, "techniques": techniques}

    def _build_summary(self) -> str:
        stages = ", ".join(self.kill_chain_stages) if self.kill_chain_stages else "N/A"
        indicators = ", ".join(f"{k}: {', '.join(sorted(v)[:3])}" for k, v in self.shared_indicators.items())
        attack = f" ATT&CK: [{', '.join(sorted(self._techniques))}]." if self._techniques else ""
        return (f"Correlated {len(self.events)} events over {self.time_span_seconds:.1f}s. "
                f"Kill-chain: [{stages}].{attack} Indicators: [{indicators}]. Risk: {self.risk_score:.1f}/10.")


class _KeyState:
    """Activity state of one entity (an IP, user, session or hostname)."""
    __slots__ = ("last_ts", "group_id", "pending")

    def __init__(self, ts: datetime, pending: dict | None):
        self.last_ts = ts
        self.group_id: str | None = None
        self.pending = pending  # first event seen for this entity, until a group forms


def parse_event_time(event: dict) -> datetime:
    """Event timestamp as an aware UTC datetime (ingestion time if unparseable)."""
    ts = event.get("timestamp")
    if isinstance(ts, str) and ts:
        try:
            dt = datetime.fromisoformat(ts[:-1] + "+00:00" if ts[-1] in "Zz" else ts)
            return dt if dt.tzinfo else dt.replace(tzinfo=_UTC)
        except ValueError:
            pass
    return datetime.now(_UTC)


class EventCorrelator:
    """
    Correlates events by temporal proximity + shared indicators and maps
    groups onto kill-chain stages.

    Each entity key (kind, value) keeps its last-seen time and the group it
    feeds. An event that shares an entity seen within ``time_window`` joins
    that entity's group; if it bridges several groups they are merged. This
    is amortised O(1) per event regardless of how chatty an entity is.
    """

    def __init__(self, time_window_seconds: float = 60.0, max_events: int = 100_000,
                 max_groups: int = 5_000, max_group_events: int = 10_000, sigma="builtin"):
        """``sigma``: a ``SigmaEngine``, ``"builtin"`` (the bundled rules) or None (keyword stages only).

        An event that carries ``sigma`` hits (a worker's projection) is not re-evaluated:
        projections lack the fields rules read.
        """
        if sigma == "builtin":
            from ulpf.intelligence.sigma import builtin_engine
            sigma = builtin_engine()
        self.sigma = sigma
        self.detections: deque = deque(maxlen=10_000)   # Sigma detections, newest last
        # rules matched by an event that has no group yet (it may become a pending partner)
        self._pending_rules: OrderedDict[str, list] = OrderedDict()
        self.time_window = float(time_window_seconds)
        self.max_events = max_events
        self.max_groups = max_groups
        self.max_group_events = max_group_events
        self._keys: dict[tuple[str, str], _KeyState] = {}
        self.events: deque[dict] = deque(maxlen=max_events)
        self._groups: OrderedDict[str, CorrelationGroup] = OrderedDict()
        self._alias: dict[str, str] = {}  # merged group id -> surviving group id
        self._watermark: datetime | None = None
        self._since_prune = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def groups(self) -> list[CorrelationGroup]:
        return list(self._groups.values())

    def add_event(self, event: dict) -> None:
        """Retain an event for batch ``correlate()``."""
        self.events.append(event)

    def add_events(self, events: list[dict]) -> None:
        self.events.extend(events)

    def correlate_event(self, event: dict) -> CorrelationGroup | None:
        """Correlate one event against entity activity; returns its group or None."""
        ts = parse_event_time(event)
        if self._watermark is None or ts > self._watermark:
            self._watermark = ts
        rules = self._sigma(event, ts)
        window = self.time_window
        keys = self._keys

        touched: set[str] = set()
        partners: list[dict] = []
        shared: dict[str, set[str]] = defaultdict(set)
        states: list[_KeyState] = []
        for kind, values in self._entities(event).items():
            for value in values:
                key = (kind, value)
                st = keys.get(key)
                if st is None or abs((ts - st.last_ts).total_seconds()) > window:
                    keys[key] = _KeyState(ts, event)
                    continue
                shared[kind].add(value)
                states.append(st)
                gid = self._resolve(st.group_id) if st.group_id is not None else None
                if gid is not None and gid in self._groups:
                    touched.add(gid)
                elif st.pending is not None and st.pending is not event:
                    partners.append(st.pending)
                elif st.pending is None:
                    # Its group was evicted (max_groups): restart from this event
                    st.group_id = None
                    st.pending = event
                if ts > st.last_ts:
                    st.last_ts = ts

        self._since_prune += 1
        if not touched and not partners:
            if rules:
                pending = self._pending_rules
                pending[self._eid(event)] = rules
                while len(pending) > 50_000:
                    pending.popitem(last=False)
            if self._since_prune >= 4096:
                self._prune()
            return None

        if touched:
            target = self._groups[max(touched, key=lambda g: len(self._groups[g].events))]
            for gid in touched - {target.correlation_id}:
                self._merge(target, self._groups.pop(gid))
        else:
            target = CorrelationGroup()
            self._groups[target.correlation_id] = target
        self._groups.move_to_end(target.correlation_id)

        for e in partners:
            if len(target.events) < self.max_group_events:
                target.add(e, parse_event_time(e), self._pending_rules.pop(self._eid(e), ()))
        if len(target.events) < self.max_group_events:
            target.add(event, ts, rules)
        for kind, values in shared.items():
            target.shared_indicators[kind].update(values)
        for st in states:
            st.group_id = target.correlation_id
            st.pending = None
        # Entities first seen on this event now also feed the group
        for kind, values in self._entities(event).items():
            for value in values:
                st = keys[(kind, value)]
                if st.group_id is None:
                    st.group_id = target.correlation_id
                    st.pending = None

        target.refresh()
        while len(self._groups) > self.max_groups:
            self._groups.popitem(last=False)
        if self._since_prune >= 4096:
            self._prune()
        return target

    def _sigma(self, event: dict, ts: datetime) -> list:
        """Rules the event's group is tagged with; Sigma detections are recorded."""
        eng = self.sigma
        if eng is None:
            return []
        hits = event.get("sigma")
        if hits is None:
            hits = eng.match(event)
        if not hits:
            return []
        dets = eng.observe(hits, ts, event.get("event_id"))
        if dets:
            from ulpf.intelligence.risk import entities_of
            ents = entities_of(event)
            for d in dets:
                d.entities = ents
        self.detections.extend(dets)
        # plain rules tag the group on every match; aggregation rules once their threshold is crossed
        out = [eng.by_id[h[0]] for h in hits if h[0] in eng.by_id and eng.by_id[h[0]].aggregation is None]
        out += [d.rule for d in dets if d.rule.aggregation is not None]
        return out

    def _resolve(self, gid: str) -> str:
        """Follow merge aliases (with path compression)."""
        alias = self._alias
        root = gid
        while root in alias:
            root = alias[root]
        while gid in alias and alias[gid] != root:
            alias[gid], gid = root, alias[gid]
        return root

    def add_and_correlate(self, event: dict) -> CorrelationGroup | None:
        """Streaming API: correlate one event as it arrives."""
        return self.correlate_event(event)

    def correlate(self) -> list[CorrelationGroup]:
        """Batch API: correlate all retained events in chronological order."""
        events = sorted(self.events, key=lambda e: (parse_event_time(e), e.get("event_id") or ""))
        self._keys.clear()
        self._groups.clear()
        self._alias.clear()
        self._pending_rules.clear()
        self._watermark = None
        for e in events:
            self.correlate_event(e)
        return self.groups

    def reset(self) -> None:
        self._keys.clear()
        self.events.clear()
        self._groups.clear()
        self._alias.clear()
        self._watermark = None

    def get_results(self) -> list[dict]:
        return [g.to_dict() for g in sorted(self._groups.values(), key=lambda g: -g.risk_score)]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _prune(self) -> None:
        """Forget entity states that fell out of the window (bounded memory)."""
        self._since_prune = 0
        if self._watermark is None:
            return
        horizon = self.time_window
        wm = self._watermark
        stale = [k for k, st in self._keys.items() if (wm - st.last_ts).total_seconds() > horizon]
        for k in stale:
            del self._keys[k]
        # Re-point surviving keys at live roots so the alias map can be dropped
        for st in self._keys.values():
            if st.group_id is not None:
                st.group_id = self._resolve(st.group_id)
        self._alias.clear()

    @staticmethod
    def _eid(event: dict) -> str:
        return event.get("event_id") or str(id(event))

    @staticmethod
    def _entities(event: dict) -> dict[str, set[str]]:
        src = event.get("source") or {}
        dst = event.get("destination") or {}
        dev = event.get("device") or {}
        out: dict[str, set[str]] = {}
        ips = {ip for ip in (src.get("ip"), dst.get("ip")) if ip}
        if ips:
            out["ip"] = ips
        user = (event.get("user") or {}).get("name")
        if user:
            out["user"] = {user}
        sess = (event.get("network") or {}).get("session_id")
        if sess:
            out["session"] = {str(sess)}
        hosts = {h for h in (src.get("hostname"), dst.get("hostname"), dev.get("hostname")) if h}
        if hosts:
            out["hostname"] = hosts
        return out

    def _merge(self, target: CorrelationGroup, other: CorrelationGroup) -> None:
        for e in other.events:
            if len(target.events) >= self.max_group_events:
                break
            target.add(e, parse_event_time(e))
        for k, v in other.shared_indicators.items():
            target.shared_indicators[k].update(v)
        self._alias[other.correlation_id] = target.correlation_id


def map_kill_chain(events: list[dict]) -> list[str]:
    """Map events onto kill-chain stages (ordered by the kill chain)."""
    stages: set[str] = set()
    for event in events:
        text = f"{event.get('message') or ''} {event.get('raw_event') or ''} {event.get('event_type') or ''}"
        ioc_cat = ((event.get("threat") or {}).get("category") or "").lower()
        severity = event.get("severity") or 0
        for stage, crit in KILL_CHAIN.items():
            if stage in stages:
                continue
            if ioc_cat and any(c == ioc_cat for c in crit["ioc"]):
                stages.add(stage)
                continue
            lo, hi = crit["severity_range"]
            if lo <= severity <= hi and crit["pattern"].search(text):
                stages.add(stage)
    return [s for s in STAGE_ORDER if s in stages]
