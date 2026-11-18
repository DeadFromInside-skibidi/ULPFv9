"""
Stream analytics (U5) and derived events.

Derived events are ordinary unified events with ``event_kind`` set to
``anomaly``, ``drift``, ``correlation`` or ``seal``, so they route, buffer
and deliver like any other event (``routes[].when.kind_in`` selects them).

* Anomalies and drift are computed in the workers, per batch, and travel in
  the same buffer segment as the batch (exactly-once with it).
* Correlation needs every source, so it runs in the host over slim
  projections sent by the workers; a group is emitted once its window has
  closed (and again if it later grows).
"""
from __future__ import annotations

import datetime as _dt
import logging
import os
import threading
import time
from collections import deque

from ulpf.engine.schema import new_unified_event, severity_label
from ulpf.runtime.ids import event_id

logger = logging.getLogger(__name__)

_RISK_SEVERITY = {"low": 3, "medium": 5, "high": 8, "critical": 10}


def derived_event(kind: str, node: str, anchor: str, ordinal: int, message: str, severity: int,
                  extensions: dict, related: list[str] | None = None, category: str = "system",
                  input_name: str | None = None, source: str | None = None,
                  timestamp: str | None = None) -> dict:
    e = new_unified_event(event_id=event_id(node, f"{kind}:{anchor}", ordinal), timestamp=timestamp)
    e["event_kind"] = kind
    e["category"] = category
    e["event_type"] = kind
    e["action"] = "detected" if kind in ("anomaly", "drift", "correlation", "detection", "notable") else "sealed"
    e["severity"] = max(0, min(10, int(severity)))
    e["severity_label"] = severity_label(e["severity"])
    e["message"] = message
    e["raw_format"] = "ulpf_derived"
    e["extensions"] = {kind: extensions}
    e["related_events"] = list(related or [])[:1000]
    e["tags"] = [kind]
    e["evidence"]["node_id"] = node
    meta = e["metadata"]
    meta["parser_id"] = f"ulpf.{kind}"
    meta["parser_name"] = f"ULPF {kind}"
    if input_name:
        meta["input"] = input_name
    if source:
        meta["ingestion_source"] = source
    return e


def anomaly_event(a: dict, node: str, first_seq: int, k: int, input_name: str, source: str) -> dict:
    risk = str(a.get("risk") or "medium").lower()
    related = [a["event_id"]] if a.get("event_id") else []
    return derived_event(
        "anomaly", node, str(first_seq), k,
        message=a.get("description") or a.get("type") or "anomaly",
        severity=_RISK_SEVERITY.get(risk, 5),
        extensions={"anomaly_type": a.get("type") or a.get("anomaly_type"), "risk": risk,
                    "details": {k: v for k, v in a.items()
                                if k not in ("type", "description", "risk", "event_id")}},
        related=related, input_name=input_name, source=source)


def structure_signature(e: dict) -> str:
    """Cheap structural identity of a parsed event (no re-parsing).

    * built-in formats: the set of attribute names the parser extracted — a
      vendor renaming or dropping fields changes it, which is the drift that
      silently empties normalised fields;
    * learned (APG) formats: which learned parser matched;
    * unparsed lines: delimiter and field count of the raw line.
    """
    fmt = e.get("raw_format") or "unknown"
    if fmt == "auto_detected":
        return "apg:" + str((e.get("metadata") or {}).get("parser_id"))
    if fmt == "raw_fallback":
        from ulpf.intelligence.auto_parser.fingerprint import compute_fingerprint
        fp = compute_fingerprint(e.get("raw_event") or "")
        return f"raw:{fp.delimiter!r}:{fp.field_count}"
    keys = e.get("parsed_fields") or {}
    return fmt + ":" + ",".join(sorted(keys)[:60])


def _overlap(a: dict, b: dict) -> float:
    """Shared probability mass of two signature distributions (1.0 = identical)."""
    return sum(min(p, b.get(s, 0.0)) for s, p in a.items())


class DriftMonitor:
    """Per-source structural drift detection on the live stream (U5).

    Events are grouped by (input, source, family) where learned and unparsed
    lines share one family, so a learned parser that stops matching shows up
    as drift. The first ``sample_lines`` events of a group form its baseline
    distribution of structure signatures; each later window is compared with
    it (at most once per ``min_interval_seconds``). When less than
    ``threshold`` of the probability mass overlaps, a drift event is emitted
    with a Log DNA comparison of sample lines, and the new window becomes the
    baseline — one change raises one event.
    """

    def __init__(self, sample_lines: int = 500, min_interval_seconds: float = 5.0,
                 data_dir: str | None = None, threshold: float = 0.5):
        self.sample_lines = sample_lines
        self.min_interval = min_interval_seconds
        self.threshold = threshold
        self.data_dir = data_dir
        self._win: dict[tuple, dict] = {}
        self._base: dict[tuple, dict] = {}
        self._last_check: dict[tuple, float] = {}
        self.events_emitted = 0

    @staticmethod
    def _new_window() -> dict:
        return {"n": 0, "sig": {}, "lines": []}

    def observe(self, input_name: str, source: str, events: list[dict]) -> list[dict]:
        return self.observe_items(input_name, source, (
            (e.get("raw_format"), None if (e.get("raw_format") or "unknown") == "ulpf_derived"
             else structure_signature(e), e.get("raw_event"), e) for e in events))

    def observe_items(self, input_name: str, source: str, items) -> list[dict]:
        """``observe`` over (raw_format, structure signature, raw_event, event) items; the event
        is only read when a drift fires (event_id and evidence), so the native lane passes a
        stand-in dict with those fields."""
        out = []
        for raw_format, sig, raw_event, e in items:
            fmt = raw_format or "unknown"
            if fmt == "ulpf_derived":
                continue
            family = "unparsed" if fmt in ("auto_detected", "raw_fallback") else fmt
            key = (input_name, source, family)
            w = self._win.get(key)
            if w is None:
                w = self._win[key] = self._new_window()
            w["sig"][sig] = w["sig"].get(sig, 0) + 1
            w["n"] += 1
            if len(w["lines"]) < 200:
                w["lines"].append(raw_event or "")
            if w["n"] < self.sample_lines:
                continue
            self._win[key] = self._new_window()
            dist = {s: c / w["n"] for s, c in w["sig"].items()}
            base = self._base.get(key)
            if base is None:
                self._base[key] = {"dist": dist, "lines": w["lines"]}
                continue
            now = time.monotonic()
            if now - self._last_check.get(key, 0.0) < self.min_interval:
                continue
            self._last_check[key] = now
            sim = _overlap(base["dist"], dist)
            if sim >= self.threshold:
                continue
            out.append(self._drift_event(key, base, dist, w["lines"], sim, e))
            self._base[key] = {"dist": dist, "lines": w["lines"]}
        return out

    def _drift_event(self, key: tuple, base: dict, dist: dict, lines: list[str], sim: float,
                     last_event: dict) -> dict:
        input_name, source, family = key
        details: dict = {"similarity": round(sim, 4), "input": input_name, "source": source,
                         "family": family,
                         "before": dict(sorted(base["dist"].items(), key=lambda kv: -kv[1])[:5]),
                         "after": dict(sorted(dist.items(), key=lambda kv: -kv[1])[:5])}
        changes = []
        try:  # detailed structural comparison, only when an alarm fires
            from ulpf.intelligence.log_dna import LogDNA
            dna = LogDNA(db_path=os.devnull if not self.data_dir else os.path.join(
                self.data_dir, "log_dna_db.json"))
            old = dna.fingerprint(base["lines"], source_label=f"{input_name}/{source}/{family}")
            dna.database[old.fingerprint_id] = old.to_dict()
            report = dna.detect_drift(old.fingerprint_id, lines)
            details["log_dna"] = report
            changes = [f"{c['field']}: {c.get('old')} -> {c.get('new')}" for c in report.get("changes", [])]
        except (ValueError, OSError):
            pass
        self.events_emitted += 1
        ev = last_event.get("evidence") or {}
        return derived_event(
            "drift", ev.get("node_id") or "node", str(ev.get("journal_seq") or 0), 0,
            message=(f"Format drift on {source} ({input_name}, {family}): structure overlap "
                     f"{sim:.0%}" + (f"; {', '.join(changes)}" if changes else "")),
            severity=6, category="audit", extensions=details,
            related=[last_event.get("event_id")], input_name=input_name, source=source)


class NativeDriftMonitor(DriftMonitor):
    """``DriftMonitor`` with its windows in the compiled core (``ulpf_core.DriftState``): native
    events are observed where they are, Python-path events as items; drift events are built
    here (``_drift_event``) as in ``DriftMonitor``. One instance serves every batch of a worker."""

    def __init__(self, state_cls, sample_lines: int = 500, min_interval_seconds: float = 5.0,
                 data_dir: str | None = None, threshold: float = 0.5):
        super().__init__(sample_lines, min_interval_seconds, data_dir, threshold)
        self.state = state_cls(sample_lines, float(min_interval_seconds), float(threshold))

    def observe(self, input_name: str, source: str, events: list[dict]) -> list[dict]:
        return self.observe_native(input_name, source, None, list(enumerate(events)))

    def observe_native(self, input_name: str, source: str, batch, py_events: list[tuple[int, dict]]) -> list[dict]:
        items = []
        for i, e in py_events:
            fmt = e.get("raw_format")
            sig = None if (fmt or "unknown") == "ulpf_derived" else structure_signature(e)
            items.append((i, fmt, sig, e.get("raw_event")))
        out = []
        by_idx = dict(py_events) if py_events else {}
        for i, family, bd, bl, d, lines, sim, eid, seq, node in self.state.observe(input_name, source, batch, items):
            if eid is None and i in by_idx:
                last = by_idx[i]                 # a Python-path event
            else:
                last = {"event_id": eid, "evidence": {"journal_seq": seq, "node_id": node}}
            out.append(self._drift_event((input_name, source, family), {"dist": dict(bd), "lines": bl}, dict(d),
                                         lines, sim, last))
        return out


_LEVEL_SEVERITY = {"informational": 1, "low": 3, "medium": 5, "high": 7, "critical": 9}


def detection_event(d, node: str) -> dict:
    """A Sigma detection as a derived event (kind ``detection``)."""
    info = d.to_dict()
    tech = ", ".join(d.rule.techniques)
    count = f" ({d.count} events)" if d.rule.aggregation is not None else ""
    ev = derived_event("detection", node, f"{d.rule.id}:{d.key}:{d.event_id}", 0,
                       message=f"Sigma: {d.rule.title}{count}" + (f" [{tech}]" if tech else ""),
                       severity=_LEVEL_SEVERITY.get(d.rule.level, 5), category="ids_ips", extensions=info,
                       related=[d.event_id] if d.event_id else [], timestamp=d.timestamp.isoformat())
    ev["rule"]["id"] = d.rule.id
    ev["rule"]["name"] = d.rule.title
    ev["threat"]["signature"] = d.rule.title
    ev["threat"]["signature_id"] = d.rule.id
    return ev


_YL_SEVERITY = {"INFORMATIONAL": 2, "LOW": 3, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}
_YL_SCORE = {"INFORMATIONAL": 5, "LOW": 15, "MEDIUM": 30, "HIGH": 50, "CRITICAL": 80}


def yaral_event(d, node: str) -> dict:
    """A YARA-L detection as a derived event (kind ``detection``)."""
    info = d.to_dict()
    key = "|".join(map(str, d.key))
    ev = derived_event("detection", node, f"yaral:{d.rule.name}:{key}:{int(d.start)}", 0,
                       message=f"YARA-L: {d.rule.name}" + (f" ({key})" if key else ""),
                       severity=_YL_SEVERITY.get(d.rule.severity, 5), category="ids_ips",
                       extensions={**info, "engine": "yara-l"}, related=[e for e in d.events if e],
                       timestamp=_dt.datetime.fromtimestamp(
                           d.end, _dt.timezone.utc).isoformat())
    ev["rule"]["id"] = f"yaral:{d.rule.name}"
    ev["rule"]["name"] = d.rule.name
    ev["threat"]["signature"] = d.rule.name
    return ev


def sigma_risk(d, risk) -> list:
    from ulpf.intelligence.risk import RiskEvent
    score = risk.level_scores.get(d.rule.level, 30)
    ts = d.timestamp.timestamp()
    return [RiskEvent(t, v, score, ts, d.rule.id, tuple(d.rule.tactics), tuple(d.rule.techniques), d.event_id)
            for t, v in d.entities]


def yaral_risk(d, risk) -> list:
    from ulpf.intelligence.risk import RiskEvent, classify_entity
    score = d.outcome.get("risk_score")
    try:
        score = float(score) if score is not None else float(_YL_SCORE.get(d.rule.severity, 30))
    except (TypeError, ValueError):
        score = float(_YL_SCORE.get(d.rule.severity, 30))
    tactics = tuple(str(x).lower() for x in str(d.rule.meta.get("tactic", "")).split(",") if x.strip())
    techniques = tuple(str(x).strip().upper() for x in str(d.rule.meta.get("technique", "")).split(",") if x.strip())
    out = []
    for name, value in zip(d.rule.match, d.key):
        for v in (value if isinstance(value, tuple) else (value,)):
            t = classify_entity(name, v)
            if t and v not in (None, ""):
                out.append(RiskEvent(t, str(v), score, d.end, f"yaral:{d.rule.name}", tactics, techniques,
                                     d.events[0] if d.events else None, "yara-l"))
    return out


_UEBA_TACTIC = {"impossible_travel": "initial_access", "token_reuse": "credential_access",
                "first_asset_access": "lateral_movement", "abnormal_privilege": "privilege_escalation",
                "privileged_api_first_use": "privilege_escalation", "egress_spike": "exfiltration",
                "rare_application": "execution", "unusual_hour": "initial_access"}


def ueba_event(a: dict, node: str) -> dict:
    """A UEBA anomaly as a derived event (kind ``anomaly``)."""
    ev = derived_event("anomaly", node, f"ueba:{a['kind']}:{a['actor']}:{int(a['time'])}", 0,
                       message=f"UEBA {a['kind'].replace('_', ' ')}: {a['display']}",
                       severity=min(10, 3 + int(a["score"] // 10)), category="authentication",
                       extensions={**a, "engine": "ueba"}, related=[a["event_id"]] if a.get("event_id") else [],
                       timestamp=_dt.datetime.fromtimestamp(a["time"], _dt.timezone.utc).isoformat())
    ev["user"]["name"] = a["display"]
    ev["source"]["ip"] = a.get("ip")
    ev["device"]["hostname"] = a.get("host")
    ev["rule"]["id"] = f"ueba:{a['kind']}"
    ev["rule"]["name"] = f"UEBA {a['kind']}"
    return ev


def ueba_risk(a: dict) -> list:
    from ulpf.intelligence.risk import RiskEvent
    tac = _UEBA_TACTIC.get(a["kind"])
    out = [RiskEvent("user", a["display"], float(a["score"]), a["time"], f"ueba:{a['kind']}",
                     (tac,) if tac else (), (), a.get("event_id"), "ueba")]
    if a.get("host"):
        out.append(RiskEvent("host", str(a["host"]), float(a["score"]) / 2, a["time"], f"ueba:{a['kind']}",
                             (tac,) if tac else (), (), a.get("event_id"), "ueba"))
    return out


def notable_event(n: dict, node: str) -> dict:
    """A Notable Incident (risk-based alerting) as a derived event (kind ``notable``)."""
    ev = derived_event("notable", node, f"notable:{n['entity_type']}:{n['entity']}:{int(n['time'])}", 0,
                       message=f"Notable: {n['entity_type']} {n['entity']} risk {n['score']:.0f} "
                               f"({'; '.join(n['reasons'])})",
                       severity=min(10, 6 + int(n["score"] // max(n["threshold"], 1))), category="ids_ips",
                       extensions=n, related=[r["event_id"] for r in n["recent"] if r.get("event_id")],
                       timestamp=_dt.datetime.fromtimestamp(
                           n["time"], _dt.timezone.utc).isoformat())
    ev["rule"]["id"] = "rba:notable"
    ev["rule"]["name"] = "Risk-based notable incident"
    return ev


class StreamCorrelator:
    """Host-side streaming correlation over worker projections."""

    def __init__(self, node: str, window_seconds: float = 60.0, emit=None, max_groups: int = 2_000,
                 max_group_events: int = 1_000, sigma=None, yaral=None, risk=None, risk_path: str | None = None,
                 ueba=None):
        from ulpf.intelligence.correlation import EventCorrelator
        self.node = node
        self.window = window_seconds
        # Memory is bounded by max_groups x max_group_events projections; groups are also
        # dropped once their window has closed and they have been emitted.
        # Sigma hits arrive with the projections (evaluated in the workers on full events);
        # the engine here runs the aggregation windows and supplies rule metadata.
        self.correlator = EventCorrelator(time_window_seconds=window_seconds, max_groups=max_groups,
                                          max_group_events=max_group_events, sigma=sigma)
        self.detections_emitted = 0
        self.evicted = 0
        self.emit = emit                     # fn(list[derived events])
        self._lock = threading.Lock()
        self._emitted: dict[str, int] = {}   # correlation_id -> event count when last emitted
        self._queue: deque = deque()
        self.events_seen = 0
        self.groups_emitted = 0
        self.yaral = yaral                   # YaraLCorrelator: joins worker candidates
        self.yaral_detections: deque = deque(maxlen=1000)
        self._yq: deque = deque()
        self.risk = risk                     # RiskEngine
        self.ueba = ueba                     # UebaEngine
        self.risk_path = risk_path
        self._risk_saved = time.monotonic()
        if risk is not None and risk_path:
            risk.load(risk_path)

    def submit(self, projections: list[dict]) -> None:
        self._queue.append(projections)

    def submit_yaral(self, candidates: list) -> None:
        self._yq.append(candidates)

    def step(self, now_wall: float | None = None) -> list[dict]:
        """Correlate queued projections; emit groups whose window has closed."""
        from ulpf.intelligence.correlation import parse_event_time
        with self._lock:
            eng = self.correlator.sigma
            seen = eng.detections if eng is not None else 0
            ueba_anomalies = []
            while self._queue:
                batch = self._queue.popleft()
                if self.ueba is not None:              # before correlation (it adds fields to the dicts)
                    ueba_anomalies += self.ueba.observe(batch)
                for p in batch:
                    self.correlator.correlate_event(p)
                self.events_seen += len(batch)
            out = []
            risk_events = []
            for a in ueba_anomalies:
                out.append(ueba_event(a, self.node))
                if self.risk is not None:
                    risk_events += ueba_risk(a)
            shutdown = now_wall is not None and now_wall - time.time() > 1e8   # the final flush
            if eng is not None and eng.detections > seen:
                new = list(self.correlator.detections)[-(eng.detections - seen):]
                out += [detection_event(d, self.node) for d in new]
                self.detections_emitted += len(new)
                if self.risk is not None:
                    risk_events += [r for d in new for r in sigma_risk(d, self.risk)]
            if self.yaral is not None:
                ydets = []
                while self._yq:
                    ydets += self.yaral.submit(self._yq.popleft())
                if shutdown:
                    ydets += self.yaral.tick(1e15)           # shutdown: decide every open window
                for d in ydets:
                    self.yaral_detections.append(d)
                    out.append(yaral_event(d, self.node))
                    if self.risk is not None:
                        risk_events += yaral_risk(d, self.risk)
            if risk_events:
                for n in self.risk.add(risk_events):
                    out.append(notable_event(n, self.node))
            if self.ueba is not None and shutdown:
                self.ueba.close()
            if self.risk is not None and self.risk_path and (time.monotonic() - self._risk_saved > 60 or shutdown):
                try:
                    self.risk.save(self.risk_path)
                except OSError:
                    logger.warning("risk state could not be saved", exc_info=True)
                self._risk_saved = time.monotonic()
            wm = self.correlator._watermark
            finished = []
            for g in self.correlator.groups:
                n = len(g.events)
                if g.last_seen is None:
                    continue
                closed = wm is not None and (wm - g.last_seen).total_seconds() >= self.window
                idle = now_wall is not None and now_wall - self._last_touch(g) >= self.window
                if closed or idle:
                    finished.append(g.correlation_id)   # nothing can join it any more
                if n < 2 or self._emitted.get(g.correlation_id) == n:
                    continue
                if not (closed or idle):
                    continue
                g.refresh()
                d = g.to_dict()
                version = self._emitted.get(g.correlation_id, 0)
                ev = derived_event(
                    "correlation", self.node, g.correlation_id, n,
                    message=d["summary"], severity=round(g.risk_score), category="ids_ips"
                    if g.kill_chain_stages else "system",
                    extensions={**d, "event_ids": d["event_ids"][:1000], "update_of_count": version or None},
                    related=d["event_ids"], timestamp=g.last_seen.isoformat() if g.last_seen else None)
                ev["correlation_id"] = g.correlation_id
                self._emitted[g.correlation_id] = n
                out.append(ev)
            # Drop finished groups (emitted above if they had 2+ events); later events about the
            # same entities start a new group
            groups = self.correlator._groups
            for gid in finished:
                if groups.pop(gid, None) is not None:
                    self.evicted += 1
                self._emitted.pop(gid, None)
            if len(self._emitted) > 50_000:
                live = {g.correlation_id for g in self.correlator.groups}
                self._emitted = {k: v for k, v in self._emitted.items() if k in live}
            self.groups_emitted += sum(1 for e in out if e["event_kind"] == "correlation")
        if out and self.emit:
            self.emit(out)
        return out

    def _last_touch(self, g) -> float:
        # Wall-clock idleness: a group nothing has joined for `window` seconds
        t = getattr(g, "_touched_wall", None)
        if t is None or len(g.events) != getattr(g, "_touched_n", -1):
            g._touched_wall = time.time()
            g._touched_n = len(g.events)
            return g._touched_wall
        return t
