"""
Security incident & case management.

Lifecycle (NIST SP 800-61 shaped)::

    new -> triaged -> investigating -> containment -> eradication -> closed -> post_incident
                 \\________________________________________________/  (closed may be reopened
                                                                         to investigating)

* Every case belongs to a tenant; every read and write is scoped by tenant.
* SLA timers per severity: time to triage, contain and close. MTTD is
  ``detected_at - first_event_at``; MTTR is ``closed_at - detected_at`` and
  time-to-contain ``contained_at - detected_at``. Breaches are computed on read.
* Evidence locker: artifacts (raw events, Merkle proofs, PCAP, files, notes)
  are stored content-addressed (SHA-256) under ``<dir>/locker``; each has a
  chain-of-custody log. An artifact whose bytes no longer match its digest is
  reported by ``verify_artifact``.
* Every change appends a timeline entry and a hash-chained audit record.

Storage is SQLite in WAL mode (a local file, never on a network share).
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid

from ulpf.runtime.audit import AuditLog

STATES = ("new", "triaged", "investigating", "containment", "eradication", "closed", "post_incident")
TRANSITIONS = {
    "new": {"triaged", "investigating", "closed"},
    "triaged": {"investigating", "containment", "closed"},
    "investigating": {"containment", "eradication", "closed"},
    "containment": {"eradication", "investigating", "closed"},
    "eradication": {"closed", "containment"},
    "closed": {"post_incident", "investigating"},
    "post_incident": {"closed"},
}
SEVERITIES = ("low", "medium", "high", "critical")
DEFAULT_SLA = {  # seconds: triage, contain, close
    "critical": {"triage": 15 * 60, "contain": 4 * 3600, "close": 24 * 3600},
    "high": {"triage": 3600, "contain": 12 * 3600, "close": 72 * 3600},
    "medium": {"triage": 4 * 3600, "contain": 48 * 3600, "close": 7 * 86400},
    "low": {"triage": 24 * 3600, "contain": 7 * 86400, "close": 30 * 86400},
}
ARTIFACT_KINDS = ("raw_event", "merkle_proof", "pcap", "file", "note", "ioc", "screenshot", "report")
MAX_ARTIFACT_BYTES = 512 * 2**20
MAX_TEXT = 100_000

_DDL = """
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, title TEXT NOT NULL, description TEXT, severity TEXT NOT NULL,
  state TEXT NOT NULL, assignee TEXT, source TEXT, source_ref TEXT, tags TEXT, mitre TEXT, entities TEXT,
  first_event_at REAL, detected_at REAL NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL,
  triaged_at REAL, contained_at REAL, closed_at REAL, resolution TEXT, version INTEGER NOT NULL DEFAULT 1);
CREATE INDEX IF NOT EXISTS cases_tenant_state ON cases(tenant, state);
CREATE UNIQUE INDEX IF NOT EXISTS cases_source_ref ON cases(tenant, source, source_ref) WHERE source_ref IS NOT NULL;
CREATE TABLE IF NOT EXISTS timeline (
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, tenant TEXT NOT NULL, at REAL NOT NULL,
  actor TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT);
CREATE INDEX IF NOT EXISTS timeline_case ON timeline(case_id, at);
CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL, tenant TEXT NOT NULL, kind TEXT NOT NULL, name TEXT,
  sha256 TEXT NOT NULL, bytes INTEGER NOT NULL, added_at REAL NOT NULL, added_by TEXT NOT NULL, meta TEXT,
  custody TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS artifacts_case ON artifacts(case_id);
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL, tenant TEXT NOT NULL, title TEXT NOT NULL, assignee TEXT,
  status TEXT NOT NULL, created_at REAL NOT NULL, done_at REAL);
"""


class CaseError(ValueError):
    pass


class NotFound(CaseError):
    pass


def _j(v) -> str:
    return json.dumps(v, sort_keys=True, default=str)


def _clip(s, n: int = MAX_TEXT):
    return None if s is None else str(s)[:n]


class CaseStore:
    def __init__(self, directory: str, sla: dict | None = None, audit: AuditLog | None = None):
        self.dir = directory
        os.makedirs(os.path.join(directory, "locker"), exist_ok=True)
        self.path = os.path.join(directory, "cases.db")
        self._local = threading.local()
        self._lock = threading.RLock()
        self.sla = {**DEFAULT_SLA, **(sla or {})}
        self.audit = audit or AuditLog(os.path.join(directory, "audit.log"))
        with self._conn() as c:
            c.executescript(_DDL)
        self.listeners: list = []          # fn(kind, case_dict) for live streams

    def _conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=FULL")
            c.execute("PRAGMA foreign_keys=ON")
            self._local.conn = c
        return c

    def _tx(self):
        store = self

        class _Tx:
            def __enter__(self_):
                store._lock.acquire()
                self_.c = store._conn()
                self_.c.execute("BEGIN IMMEDIATE")
                return self_.c

            def __exit__(self_, et, ev, tb):
                try:
                    self_.c.execute("ROLLBACK" if et else "COMMIT")
                finally:
                    store._lock.release()
        return _Tx()

    # ------------------------------------------------------------------
    def _notify(self, kind: str, case: dict) -> None:
        for fn in list(self.listeners):
            try:
                fn(kind, case)
            except Exception:
                pass

    def _timeline(self, c, case_id: str, tenant: str, actor: str, kind: str, detail: dict) -> None:
        c.execute("INSERT INTO timeline (case_id, tenant, at, actor, kind, detail) VALUES (?,?,?,?,?,?)",
                  (case_id, tenant, time.time(), actor, kind, _j(detail)))
        self.audit.record(f"case.{kind}", {"case": case_id, "tenant": tenant, **detail}, actor=actor)

    def create(self, tenant: str, title: str, severity: str = "medium", *, actor: str = "system",
               description: str | None = None, source: str | None = None, source_ref: str | None = None,
               tags: list | None = None, mitre: list | None = None, entities: dict | None = None,
               first_event_at: float | None = None, detected_at: float | None = None,
               assignee: str | None = None) -> dict:
        if severity not in SEVERITIES:
            raise CaseError(f"severity must be one of {', '.join(SEVERITIES)}")
        if not title or not tenant:
            raise CaseError("tenant and title are required")
        now = time.time()
        cid = "CASE-" + time.strftime("%Y%m%d", time.gmtime(now)) + "-" + uuid.uuid4().hex[:8].upper()
        with self._tx() as c:
            if source_ref is not None:
                row = c.execute("SELECT id FROM cases WHERE tenant=? AND source=? AND source_ref=?",
                                (tenant, source, source_ref)).fetchone()
                if row:                       # idempotent auto-creation from the same detection
                    return self.get(tenant, row["id"])
            c.execute("INSERT INTO cases (id, tenant, title, description, severity, state, assignee, source, source_ref,"
                      " tags, mitre, entities, first_event_at, detected_at, created_at, updated_at) "
                      "VALUES (?,?,?,?,?,'new',?,?,?,?,?,?,?,?,?,?)",
                      (cid, tenant, _clip(title, 500), _clip(description), severity, assignee, source, source_ref,
                       _j(tags or []), _j(mitre or []), _j(entities or {}), first_event_at,
                       detected_at or now, now, now))
            self._timeline(c, cid, tenant, actor, "created", {"title": title[:200], "severity": severity,
                                                              "source": source})
        case = self.get(tenant, cid)
        self._notify("created", case)
        return case

    def get(self, tenant: str, case_id: str) -> dict:
        row = self._conn().execute("SELECT * FROM cases WHERE id=? AND tenant=?", (case_id, tenant)).fetchone()
        if row is None:
            raise NotFound(f"case {case_id} not found")
        return self._decorate(dict(row))

    def _decorate(self, d: dict) -> dict:
        for k in ("tags", "mitre", "entities"):
            d[k] = json.loads(d[k]) if d.get(k) else ([] if k != "entities" else {})
        d.update(self.metrics(d))
        return d

    def metrics(self, d: dict, now: float | None = None) -> dict:
        now = now or time.time()
        sla = self.sla.get(d["severity"], DEFAULT_SLA["medium"])
        det = d["detected_at"]
        out = {"mttd_seconds": (det - d["first_event_at"]) if d.get("first_event_at") else None,
               "time_to_triage_seconds": (d["triaged_at"] - det) if d.get("triaged_at") else None,
               "time_to_contain_seconds": (d["contained_at"] - det) if d.get("contained_at") else None,
               "mttr_seconds": (d["closed_at"] - det) if d.get("closed_at") else None}
        breaches = []
        for name, field in (("triage", "triaged_at"), ("contain", "contained_at"), ("close", "closed_at")):
            done = d.get(field)
            if name == "contain" and d["state"] in ("closed", "post_incident") and not done:
                continue                    # closed without containment (false positive)
            elapsed = (done or now) - det
            if elapsed > sla[name]:
                breaches.append(name)
        out["sla"] = {"policy": sla, "breached": breaches,
                      "due": {n: det + sla[n] for n in sla}}
        return out

    def list(self, tenant: str, state: str | None = None, severity: str | None = None, assignee: str | None = None,
             limit: int = 200, offset: int = 0) -> list[dict]:
        q, p = "SELECT * FROM cases WHERE tenant=?", [tenant]
        for col, v in (("state", state), ("severity", severity), ("assignee", assignee)):
            if v:
                q += f" AND {col}=?"
                p.append(v)
        q += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        p += [max(1, min(int(limit), 1000)), max(0, int(offset))]
        return [self._decorate(dict(r)) for r in self._conn().execute(q, p).fetchall()]

    def transition(self, tenant: str, case_id: str, state: str, actor: str, note: str | None = None,
                   resolution: str | None = None) -> dict:
        if state not in STATES:
            raise CaseError(f"unknown state {state!r}")
        with self._tx() as c:
            row = c.execute("SELECT state, triaged_at, contained_at FROM cases WHERE id=? AND tenant=?",
                            (case_id, tenant)).fetchone()
            if row is None:
                raise NotFound(f"case {case_id} not found")
            cur = row["state"]
            if state not in TRANSITIONS[cur]:
                raise CaseError(f"cannot move a case from {cur} to {state} "
                                f"(allowed: {', '.join(sorted(TRANSITIONS[cur]))})")
            now = time.time()
            sets, params = ["state=?", "updated_at=?", "version=version+1"], [state, now]
            if state != "new" and not row["triaged_at"]:
                sets.append("triaged_at=?")
                params.append(now)
            if state == "eradication" and not row["contained_at"]:     # containment finished
                sets.append("contained_at=?")
                params.append(now)
            if state == "closed":
                sets.append("closed_at=?")
                params.append(now)
                if resolution:
                    sets.append("resolution=?")
                    params.append(_clip(resolution, 2000))
            if state == "investigating" and cur == "closed":
                sets.append("closed_at=NULL")
            c.execute(f"UPDATE cases SET {', '.join(sets)} WHERE id=? AND tenant=?", params + [case_id, tenant])
            self._timeline(c, case_id, tenant, actor, "state", {"from": cur, "to": state, "note": _clip(note, 2000)})
        case = self.get(tenant, case_id)
        self._notify("updated", case)
        return case

    def mark_contained(self, tenant: str, case_id: str, actor: str, detail: dict) -> None:
        with self._tx() as c:
            c.execute("UPDATE cases SET contained_at=COALESCE(contained_at, ?), updated_at=? WHERE id=? AND tenant=?",
                      (time.time(), time.time(), case_id, tenant))
            self._timeline(c, case_id, tenant, actor, "containment", detail)

    def update(self, tenant: str, case_id: str, actor: str, **fields) -> dict:
        allowed = {"title", "description", "severity", "assignee", "tags", "mitre", "entities"}
        bad = set(fields) - allowed
        if bad:
            raise CaseError(f"cannot update {', '.join(sorted(bad))}")
        if "severity" in fields and fields["severity"] not in SEVERITIES:
            raise CaseError("invalid severity")
        with self._tx() as c:
            if c.execute("SELECT 1 FROM cases WHERE id=? AND tenant=?", (case_id, tenant)).fetchone() is None:
                raise NotFound(f"case {case_id} not found")
            sets, params = ["updated_at=?", "version=version+1"], [time.time()]
            for k, v in fields.items():
                sets.append(f"{k}=?")
                params.append(_j(v) if k in ("tags", "mitre", "entities") else _clip(v, 2000))
            c.execute(f"UPDATE cases SET {', '.join(sets)} WHERE id=? AND tenant=?", params + [case_id, tenant])
            self._timeline(c, case_id, tenant, actor, "updated",
                           {k: (v if k != "description" else "(changed)") for k, v in fields.items()})
        case = self.get(tenant, case_id)
        self._notify("updated", case)
        return case

    def note(self, tenant: str, case_id: str, actor: str, text: str) -> dict:
        self.get(tenant, case_id)
        with self._tx() as c:
            self._timeline(c, case_id, tenant, actor, "note", {"text": _clip(text, 20_000)})
        return {"ok": True}

    def timeline(self, tenant: str, case_id: str, limit: int = 1000) -> list[dict]:
        rows = self._conn().execute("SELECT at, actor, kind, detail FROM timeline WHERE case_id=? AND tenant=? "
                                    "ORDER BY id LIMIT ?", (case_id, tenant, max(1, min(limit, 10_000)))).fetchall()
        return [{"at": r["at"], "actor": r["actor"], "kind": r["kind"], "detail": json.loads(r["detail"] or "{}")}
                for r in rows]

    # ------------------------------------------------------------------
    # Evidence locker
    # ------------------------------------------------------------------
    def _blob_path(self, digest: str) -> str:
        return os.path.join(self.dir, "locker", digest[:2], digest)

    def add_artifact(self, tenant: str, case_id: str, kind: str, data: bytes, actor: str, name: str | None = None,
                     meta: dict | None = None) -> dict:
        if kind not in ARTIFACT_KINDS:
            raise CaseError(f"artifact kind must be one of {', '.join(ARTIFACT_KINDS)}")
        if len(data) > MAX_ARTIFACT_BYTES:
            raise CaseError(f"artifact larger than {MAX_ARTIFACT_BYTES} bytes")
        self.get(tenant, case_id)
        digest = hashlib.sha256(data).hexdigest()
        path = self._blob_path(digest)
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + f".{uuid.uuid4().hex}.tmp"
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            try:
                os.chmod(path, 0o440)
            except OSError:
                pass
        aid = "ART-" + uuid.uuid4().hex[:12].upper()
        custody = [{"at": time.time(), "actor": actor, "action": "collected", "sha256": digest}]
        with self._tx() as c:
            c.execute("INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                      (aid, case_id, tenant, kind, _clip(name, 300), digest, len(data), time.time(), actor,
                       _j(meta or {}), _j(custody)))
            self._timeline(c, case_id, tenant, actor, "artifact",
                           {"artifact": aid, "kind": kind, "sha256": digest, "bytes": len(data), "name": name})
        return self.artifact(tenant, aid)

    def artifact(self, tenant: str, artifact_id: str) -> dict:
        r = self._conn().execute("SELECT * FROM artifacts WHERE id=? AND tenant=?", (artifact_id, tenant)).fetchone()
        if r is None:
            raise NotFound(f"artifact {artifact_id} not found")
        d = dict(r)
        d["meta"], d["custody"] = json.loads(d["meta"]), json.loads(d["custody"])
        return d

    def artifacts(self, tenant: str, case_id: str) -> list[dict]:
        rows = self._conn().execute("SELECT id FROM artifacts WHERE case_id=? AND tenant=? ORDER BY added_at",
                                    (case_id, tenant)).fetchall()
        return [self.artifact(tenant, r["id"]) for r in rows]

    def read_artifact(self, tenant: str, artifact_id: str, actor: str) -> bytes:
        a = self.artifact(tenant, artifact_id)
        with open(self._blob_path(a["sha256"]), "rb") as f:
            data = f.read()
        if hashlib.sha256(data).hexdigest() != a["sha256"]:
            raise CaseError(f"artifact {artifact_id}: stored bytes no longer match SHA-256 {a['sha256']}")
        with self._tx() as c:
            custody = a["custody"] + [{"at": time.time(), "actor": actor, "action": "accessed"}]
            c.execute("UPDATE artifacts SET custody=? WHERE id=?", (_j(custody[-1000:]), artifact_id))
        self.audit.record("case.artifact_access", {"artifact": artifact_id, "case": a["case_id"]}, actor=actor)
        return data

    def verify_artifact(self, tenant: str, artifact_id: str) -> dict:
        a = self.artifact(tenant, artifact_id)
        try:
            with open(self._blob_path(a["sha256"]), "rb") as f:
                ok = hashlib.sha256(f.read()).hexdigest() == a["sha256"]
        except OSError:
            ok = False
        return {"artifact": artifact_id, "sha256": a["sha256"], "intact": ok}

    # ------------------------------------------------------------------
    # Tasks
    # ------------------------------------------------------------------
    def add_task(self, tenant: str, case_id: str, title: str, actor: str, assignee: str | None = None) -> dict:
        self.get(tenant, case_id)
        tid = "TASK-" + uuid.uuid4().hex[:10].upper()
        with self._tx() as c:
            c.execute("INSERT INTO tasks VALUES (?,?,?,?,?,'open',?,NULL)",
                      (tid, case_id, tenant, _clip(title, 500), assignee, time.time()))
            self._timeline(c, case_id, tenant, actor, "task", {"task": tid, "title": title[:200]})
        return {"id": tid, "case_id": case_id, "title": title, "assignee": assignee, "status": "open"}

    def complete_task(self, tenant: str, task_id: str, actor: str) -> None:
        with self._tx() as c:
            r = c.execute("SELECT case_id FROM tasks WHERE id=? AND tenant=?", (task_id, tenant)).fetchone()
            if r is None:
                raise NotFound(f"task {task_id} not found")
            c.execute("UPDATE tasks SET status='done', done_at=? WHERE id=?", (time.time(), task_id))
            self._timeline(c, r["case_id"], tenant, actor, "task_done", {"task": task_id})

    def tasks(self, tenant: str, case_id: str) -> list[dict]:
        return [dict(r) for r in self._conn().execute(
            "SELECT * FROM tasks WHERE case_id=? AND tenant=? ORDER BY created_at", (case_id, tenant)).fetchall()]

    # ------------------------------------------------------------------
    def kpis(self, tenant: str, since: float | None = None) -> dict:
        since = since or time.time() - 30 * 86400
        rows = [self._decorate(dict(r)) for r in self._conn().execute(
            "SELECT * FROM cases WHERE tenant=? AND detected_at>=?", (tenant, since)).fetchall()]

        def avg(k):
            v = [r[k] for r in rows if r.get(k) is not None]
            return sum(v) / len(v) if v else None
        by_state: dict[str, int] = {}
        for r in rows:
            by_state[r["state"]] = by_state.get(r["state"], 0) + 1
        return {"cases": len(rows), "by_state": by_state, "mttd_seconds": avg("mttd_seconds"),
                "mttr_seconds": avg("mttr_seconds"), "time_to_contain_seconds": avg("time_to_contain_seconds"),
                "sla_breached": sum(1 for r in rows if r["sla"]["breached"])}
