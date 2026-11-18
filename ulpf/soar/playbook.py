"""
Directed-acyclic-graph playbook engine with human-in-the-loop gates.

A playbook is YAML or JSON::

    id: contain-brute-force
    name: Contain an external brute-force source
    version: 1
    inputs: {ip: {required: true}, user: {}}
    steps:
      - id: triage
        action: case.transition
        with: {state: triaged}
      - id: decide
        type: condition
        needs: [triage]
        if: "inputs.ip and not cidr_contains('10.0.0.0/8', inputs.ip)"
        then: [block]
        else: [note_internal]
      - id: block                       # destructive: an analyst approves first (HITL)
        connector: perimeter-fw
        action: block_ip
        with: {ip: "{{ inputs.ip }}"}
        retries: 3
      - id: disable
        connector: entra
        action: disable_user
        when: "inputs.user"
        needs: [triage]                 # runs in parallel with the branch above
        with: {user: "{{ inputs.user }}"}
      - id: hosts
        type: foreach
        items: "{{ inputs.hosts }}"
        max_parallel: 4
        do: {connector: edr, action: isolate_host, with: {machine_id: "{{ item }}"}}
      - id: notify
        type: playbook                  # sub-playbook
        playbook: notify-soc
        needs: [block, disable]
        trigger: all_done               # runs whether its needs succeeded, failed or were skipped
      - id: note_internal
        action: case.note
        with: {text: "internal source {{ inputs.ip }}: not blocked"}

Step types: ``action`` (default), ``condition``, ``approval``, ``foreach``,
``playbook``, ``set``. Common fields: ``needs``, ``when``, ``trigger``
(``all_success`` default | ``any_success`` | ``all_done``), ``retries``,
``retry_delay``, ``on_failure`` (``stop`` default | ``continue``).

Execution: ready steps run in parallel on a worker pool; the run's state is
persisted (SQLite) after every step, so a run waiting for approval, or one
interrupted by a restart, resumes where it stopped. Destructive connector
actions require an approval (``hitl.destructive``, default on) unless the run
is a dry run. Every step and every remediation command is written to the
hash-chained audit log; successful containments are recorded with their
inverse so ``rollback`` can undo them in reverse order.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from ulpf.runtime.audit import AuditLog
from ulpf.soar import expr
from ulpf.soar.connectors import ConnectorError

STEP_TYPES = ("action", "condition", "approval", "foreach", "playbook", "set")
TRIGGERS = ("all_success", "any_success", "all_done")
MAX_STEPS = 500
MAX_FOREACH = 1000
MAX_DEPTH = 5
MAX_RETRIES = 10
_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
DONE = ("succeeded", "failed", "skipped", "rejected")


class PlaybookError(ValueError):
    pass


def load_spec(text_or_path: str) -> dict:
    text = text_or_path
    if os.path.exists(text_or_path):
        with open(text_or_path, "r", encoding="utf-8") as f:
            text = f.read()
    if len(text) > 2 * 2**20:
        raise PlaybookError("playbook larger than 2 MiB")
    try:
        doc = json.loads(text)
    except ValueError:
        import yaml
        doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        raise PlaybookError("a playbook is a mapping")
    return doc


def validate(spec: dict, connectors: dict | None = None, builtins: set | None = None) -> dict:
    """Normalise and validate a spec; raises PlaybookError with every problem found."""
    errs: list[str] = []
    pid = spec.get("id")
    if not isinstance(pid, str) or not _ID.match(pid):
        errs.append("id: required, letters/digits/_/- (max 64)")
    steps = spec.get("steps")
    if not isinstance(steps, list) or not steps:
        raise PlaybookError("; ".join(errs + ["steps: a non-empty list is required"]))
    if len(steps) > MAX_STEPS:
        raise PlaybookError(f"at most {MAX_STEPS} steps")
    by_id: dict[str, dict] = {}
    for i, s in enumerate(steps):
        if not isinstance(s, dict):
            errs.append(f"steps[{i}]: must be a mapping")
            continue
        sid = s.get("id")
        if not isinstance(sid, str) or not _ID.match(sid):
            errs.append(f"steps[{i}].id invalid")
            continue
        if sid in by_id:
            errs.append(f"step {sid}: duplicate id")
        t = s.get("type") or ("action" if "action" in s else None)
        if t not in STEP_TYPES:
            errs.append(f"step {sid}: type must be one of {', '.join(STEP_TYPES)}")
        s = {**s, "type": t, "needs": list(s.get("needs") or [])}
        if s.get("trigger", "all_success") not in TRIGGERS:
            errs.append(f"step {sid}: trigger must be one of {', '.join(TRIGGERS)}")
        if not 0 <= int(s.get("retries", 0)) <= MAX_RETRIES:
            errs.append(f"step {sid}: retries must be 0..{MAX_RETRIES}")
        if s.get("on_failure", "stop") not in ("stop", "continue"):
            errs.append(f"step {sid}: on_failure must be stop or continue")
        for key in ("when", "if"):
            if s.get(key) is not None:
                try:
                    expr.compile_expr(str(s[key]))
                except expr.ExprError as e:
                    errs.append(f"step {sid}.{key}: {e}")
        if t == "condition" and not s.get("if"):
            errs.append(f"step {sid}: condition needs 'if'")
        if t == "foreach" and (not s.get("items") or not isinstance(s.get("do"), dict)):
            errs.append(f"step {sid}: foreach needs 'items' and a 'do' action")
        if t == "playbook" and not s.get("playbook"):
            errs.append(f"step {sid}: 'playbook' (id of the sub-playbook) is required")
        acts = [s] if t == "action" else [s["do"]] if t == "foreach" and isinstance(s.get("do"), dict) else []
        for a in acts:
            name = a.get("action")
            if not name:
                errs.append(f"step {sid}: 'action' is required")
            elif a.get("connector"):
                if connectors is not None and "{{" not in str(a["connector"]):
                    c = connectors.get(a["connector"])
                    if c is None:
                        errs.append(f"step {sid}: unknown connector {a['connector']!r}")
                    elif name not in c.actions:
                        errs.append(f"step {sid}: connector {a['connector']!r} ({c.type}) has no action {name!r}")
            elif builtins is not None and name not in builtins:
                errs.append(f"step {sid}: unknown built-in action {name!r} (or set 'connector')")
        by_id[sid] = s
    for sid, s in by_id.items():
        for n in s["needs"]:
            if n not in by_id:
                errs.append(f"step {sid}: needs unknown step {n!r}")
        if s["type"] == "condition":
            for br in ("then", "else"):
                for n in s.get(br) or []:
                    if n not in by_id:
                        errs.append(f"step {sid}.{br}: unknown step {n!r}")
                    elif sid not in by_id[n]["needs"]:
                        by_id[n]["needs"].append(sid)        # a branch target depends on its condition
                        by_id[n].setdefault("_branch_of", []).append((sid, br))
                    else:
                        by_id[n].setdefault("_branch_of", []).append((sid, br))
    # cycle check (iterative DFS)
    color = {k: 0 for k in by_id}
    for root in by_id:
        if color[root]:
            continue
        stack = [(root, iter(by_id[root]["needs"]))]
        color[root] = 1
        while stack:
            node, it = stack[-1]
            nxt = next((n for n in it if n in by_id), None)
            if nxt is None:
                color[node] = 2
                stack.pop()
            elif color[nxt] == 1:
                errs.append(f"cycle through step {nxt!r}")
                break
            elif color[nxt] == 0:
                color[nxt] = 1
                stack.append((nxt, iter(by_id[nxt]["needs"])))
    if not errs:       # HITL can only be waived below an explicit approval gate
        def ancestors(sid, seen):
            for n in by_id[sid]["needs"]:
                if n not in seen:
                    seen.add(n)
                    ancestors(n, seen)
            return seen
        for sid, s in by_id.items():
            if s.get("approval") is False and not any(by_id[a]["type"] == "approval" for a in ancestors(sid, set())):
                errs.append(f"step {sid}: 'approval: false' needs an approval step among its dependencies")
    if errs:
        raise PlaybookError("; ".join(errs))
    return {"id": pid, "name": spec.get("name", pid), "version": spec.get("version", 1),
            "description": spec.get("description", ""), "inputs": spec.get("inputs") or {},
            "triggers": spec.get("triggers") or {}, "steps": by_id, "order": list(by_id)}


_RUN_DDL = """
CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, playbook TEXT NOT NULL,
  case_id TEXT, parent TEXT, status TEXT NOT NULL, dry_run INTEGER NOT NULL, actor TEXT NOT NULL,
  created_at REAL NOT NULL, updated_at REAL NOT NULL, state TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS runs_tenant ON runs(tenant, created_at);
CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, run_id TEXT NOT NULL,
  step_id TEXT NOT NULL, status TEXT NOT NULL, summary TEXT, approvers TEXT, requested_at REAL NOT NULL,
  decided_at REAL, decided_by TEXT, reason TEXT, expires_at REAL);
CREATE INDEX IF NOT EXISTS approvals_tenant ON approvals(tenant, status);
"""


class PlaybookEngine:
    def __init__(self, directory: str, connectors: dict | None = None, cases=None, audit: AuditLog | None = None,
                 hitl_destructive: bool = True, approval_timeout: float = 24 * 3600, workers: int = 8):
        os.makedirs(directory, exist_ok=True)
        self.dir = directory
        self.connectors = connectors or {}
        self.cases = cases
        self.audit = audit or AuditLog(os.path.join(directory, "audit.log"))
        self.hitl_destructive = hitl_destructive
        self.approval_timeout = approval_timeout
        self.playbooks: dict[str, dict] = {}
        self.sources: dict[str, dict] = {}
        self._db_path = os.path.join(directory, "runs.db")
        self._local = threading.local()
        self._lock = threading.RLock()
        self._run_locks: dict[str, threading.Lock] = {}
        self._steps = ThreadPoolExecutor(workers, thread_name_prefix="ulpf-soar-step")
        self._runs = ThreadPoolExecutor(max(2, workers // 2), thread_name_prefix="ulpf-soar-run")
        self.listeners: list = []
        self.builtins = {"case.transition": self._b_case_transition, "case.note": self._b_case_note,
                         "case.add_artifact": self._b_case_artifact, "case.mark_contained": self._b_case_contained,
                         "case.add_task": self._b_case_task, "util.echo": lambda p, ctx: p,
                         "util.fail": self._b_fail}
        self._conn().executescript(_RUN_DDL)

    # ------------------------------------------------------------------
    def _conn(self):
        c = getattr(self._local, "c", None)
        if c is None:
            c = sqlite3.connect(self._db_path, timeout=30, isolation_level=None, check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=FULL")
            self._local.c = c
        return c

    def register(self, spec: dict) -> dict:
        pb = validate(spec, self.connectors, set(self.builtins))
        self.playbooks[pb["id"]] = pb
        self.sources[pb["id"]] = spec
        return pb

    def load_dir(self, path: str) -> list[str]:
        errors = []
        if not os.path.isdir(path):
            return errors
        for n in sorted(os.listdir(path)):
            if n.endswith((".yaml", ".yml", ".json")):
                try:
                    self.register(load_spec(os.path.join(path, n)))
                except (PlaybookError, ValueError, OSError) as e:
                    errors.append(f"{n}: {e}")
        return errors

    def close(self) -> None:
        self._steps.shutdown(wait=False, cancel_futures=True)
        self._runs.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------
    # Runs
    # ------------------------------------------------------------------
    def start(self, playbook_id: str, tenant: str, inputs: dict | None = None, actor: str = "system",
              case_id: str | None = None, dry_run: bool = False, wait: bool = False, parent: str | None = None,
              depth: int = 0) -> dict:
        pb = self.playbooks.get(playbook_id)
        if pb is None:
            raise PlaybookError(f"unknown playbook {playbook_id!r}")
        inputs = dict(inputs or {})
        missing = [k for k, v in pb["inputs"].items() if isinstance(v, dict) and v.get("required") and k not in inputs]
        if missing:
            raise PlaybookError(f"missing required input(s): {', '.join(missing)}")
        for k, v in pb["inputs"].items():
            if isinstance(v, dict) and "default" in v and k not in inputs:
                inputs[k] = v["default"]
        rid = "RUN-" + uuid.uuid4().hex[:12].upper()
        state = {"playbook": playbook_id, "version": pb["version"], "inputs": inputs, "depth": depth,
                 "steps": {sid: {"status": "pending", "attempts": 0} for sid in pb["order"]},
                 "containment": [], "errors": []}
        now = time.time()
        self._conn().execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                             (rid, tenant, playbook_id, case_id, parent, "running", int(dry_run), actor, now, now,
                              json.dumps(state, default=str)))
        self.audit.record("soar.run_started", {"run": rid, "playbook": playbook_id, "version": pb["version"],
                                               "tenant": tenant, "case": case_id, "dry_run": dry_run,
                                               "inputs": inputs}, actor=actor)
        if wait:
            self._advance(rid)
        else:
            self._runs.submit(self._advance_safe, rid)
        return self.get_run(tenant, rid)

    def _advance_safe(self, rid: str) -> None:
        try:
            self._advance(rid)
        except Exception as e:      # never lose a run silently
            self._finish(rid, "failed", error=f"engine error: {e}")

    def _load(self, rid: str) -> dict:
        r = self._conn().execute("SELECT * FROM runs WHERE id=?", (rid,)).fetchone()
        if r is None:
            raise PlaybookError(f"run {rid} not found")
        d = dict(r)
        d["state"] = json.loads(d["state"])
        d["dry_run"] = bool(d["dry_run"])
        return d

    def _save(self, run: dict, status: str | None = None) -> None:
        if status:
            run["status"] = status
        self._conn().execute("UPDATE runs SET state=?, status=?, updated_at=? WHERE id=?",
                             (json.dumps(run["state"], default=str), run["status"], time.time(), run["id"]))
        for fn in list(self.listeners):
            try:
                fn("run", {"id": run["id"], "tenant": run["tenant"], "status": run["status"],
                           "playbook": run["playbook"]})
            except Exception:
                pass

    def get_run(self, tenant: str, rid: str) -> dict:
        run = self._load(rid)
        if run["tenant"] != tenant:
            raise PlaybookError(f"run {rid} not found")
        return run

    def list_runs(self, tenant: str, limit: int = 100, case_id: str | None = None) -> list[dict]:
        q, p = "SELECT id FROM runs WHERE tenant=?", [tenant]
        if case_id:
            q += " AND case_id=?"
            p.append(case_id)
        q += " ORDER BY created_at DESC LIMIT ?"
        p.append(max(1, min(limit, 1000)))
        return [self._load(r["id"]) for r in self._conn().execute(q, p).fetchall()]

    def resume_pending(self) -> int:
        """After a restart: re-advance runs that were executing (steps marked running restart)."""
        rows = self._conn().execute("SELECT id FROM runs WHERE status='running'").fetchall()
        for r in rows:
            run = self._load(r["id"])
            for st in run["state"]["steps"].values():
                if st["status"] == "running":
                    st["status"] = "pending"
            self._save(run)
            self._runs.submit(self._advance_safe, r["id"])
        return len(rows)

    # ------------------------------------------------------------------
    def _ctx(self, run: dict, extra: dict | None = None) -> dict:
        st = run["state"]
        case = None
        if self.cases is not None and run.get("case_id"):
            try:
                case = self.cases.get(run["tenant"], run["case_id"])
            except Exception:
                case = None
        return {"inputs": st["inputs"], "case": case, "run": {"id": run["id"], "dry_run": run["dry_run"]},
                "steps": {k: {"status": v["status"], "output": v.get("output")} for k, v in st["steps"].items()},
                **(extra or {})}

    def _ready(self, pb: dict, run: dict) -> tuple[list[str], list[str]]:
        steps = run["state"]["steps"]
        ready, skip = [], []
        for sid in pb["order"]:
            if steps[sid]["status"] != "pending":
                continue
            spec = pb["steps"][sid]
            needs = [steps[n]["status"] for n in spec["needs"]]
            if any(s not in DONE for s in needs):
                continue
            branch_ok = True
            for cond, br in spec.get("_branch_of", []):
                if steps[cond]["status"] != "succeeded" or steps[cond].get("output", {}).get("branch") != br:
                    branch_ok = False
            trig = spec.get("trigger", "all_success")
            if not branch_ok:
                skip.append(sid)
            elif trig == "all_success" and any(s != "succeeded" for s in needs):
                skip.append(sid)
            elif trig == "any_success" and needs and not any(s == "succeeded" for s in needs):
                skip.append(sid)
            else:
                ready.append(sid)
        return ready, skip

    def _advance(self, rid: str) -> None:
        lock = self._run_locks.setdefault(rid, threading.Lock())
        if not lock.acquire(blocking=False):
            return                         # another thread is advancing this run
        try:
            while True:
                run = self._load(rid)
                if run["status"] not in ("running",):
                    return
                pb = self.playbooks.get(run["playbook"])
                if pb is None:
                    self._finish(rid, "failed", error=f"playbook {run['playbook']} is no longer loaded")
                    return
                ready, skip = self._ready(pb, run)
                for sid in skip:
                    run["state"]["steps"][sid].update(status="skipped", finished_at=time.time())
                    self.audit.record("soar.step", {"run": rid, "step": sid, "status": "skipped"}, actor=run["actor"])
                if skip:
                    self._save(run)
                    continue
                if not ready:
                    statuses = {s["status"] for s in run["state"]["steps"].values()}
                    if "waiting_approval" in statuses:
                        self._save(run, "waiting_approval")
                    elif statuses & {"pending", "running"}:
                        self._save(run)
                    else:
                        failed = any(s["status"] in ("failed", "rejected") and
                                     pb["steps"][k].get("on_failure", "stop") == "stop"
                                     for k, s in run["state"]["steps"].items())
                        self._finish(rid, "failed" if failed else "succeeded")
                    return
                for sid in ready:
                    run["state"]["steps"][sid].update(status="running", started_at=time.time())
                self._save(run)
                if threading.current_thread().name.startswith("ulpf-soar-step"):
                    # a sub-playbook advanced from a step thread: run inline (no nested pool waits)
                    results = {sid: self._exec_step(rid, pb, sid) for sid in ready}
                else:
                    futs = {sid: self._steps.submit(self._exec_step, rid, pb, sid) for sid in ready}
                    results = {sid: f.result() for sid, f in futs.items()}
                run = self._load(rid)
                stop = False
                for sid, (status, output, error, extra) in results.items():
                    st = run["state"]["steps"][sid]
                    st.update(status=status, finished_at=time.time())
                    st["attempts"] = extra.get("attempts", st.get("attempts", 0))
                    if output is not None:
                        st["output"] = output
                    if error:
                        st["error"] = error[:2000]
                    run["state"]["containment"].extend(extra.get("containment", []))
                    if extra.get("approval"):
                        st["approval"] = extra["approval"]
                    if status in ("failed", "rejected") and pb["steps"][sid].get("on_failure", "stop") == "stop":
                        stop = True
                    self.audit.record("soar.step", {"run": rid, "step": sid, "status": status,
                                                    "error": (error or "")[:500]}, actor=run["actor"])
                if stop:
                    for st in run["state"]["steps"].values():
                        if st["status"] == "pending":
                            st["status"] = "skipped"
                self._save(run)
        finally:
            lock.release()

    def _finish(self, rid: str, status: str, error: str | None = None) -> None:
        run = self._load(rid)
        if error:
            run["state"]["errors"].append(error)
        self._save(run, status)
        self.audit.record("soar.run_finished", {"run": rid, "status": status, "error": error,
                                                "containment": len(run["state"]["containment"])}, actor=run["actor"])
        if run.get("parent"):                  # wake the parent step that waits for this sub-run
            try:
                parent = self._load(run["parent"])
                for st in parent["state"]["steps"].values():
                    out = st.get("output")
                    if isinstance(out, dict) and out.get("run") == rid and st["status"] == "waiting_approval":
                        st["status"] = "pending"
                        parent["state"]["containment"].extend(run["state"]["containment"])
                        self._save(parent, "running")
                        self._runs.submit(self._advance_safe, parent["id"])
            except PlaybookError:
                pass

    # ------------------------------------------------------------------
    # Steps
    # ------------------------------------------------------------------
    def _exec_step(self, rid: str, pb: dict, sid: str):
        """Returns (status, output, error, extra)."""
        run = self._load(rid)
        spec = pb["steps"][sid]
        ctx = self._ctx(run)
        try:
            if spec.get("when") is not None and not expr.evaluate(str(spec["when"]), ctx):
                return "skipped", {"reason": "when is false"}, None, {}
            t = spec["type"]
            if t == "condition":
                taken = bool(expr.evaluate(str(spec["if"]), ctx))
                return "succeeded", {"result": taken, "branch": "then" if taken else "else"}, None, {}
            if t == "set":
                return "succeeded", expr.render(spec.get("values") or {}, ctx), None, {}
            if t == "approval":
                return self._approval_gate(run, sid, spec, ctx, summary=expr.render(spec.get("summary", ""), ctx))
            if t == "playbook":
                if run["state"]["depth"] + 1 > MAX_DEPTH:
                    return "failed", None, f"sub-playbook depth above {MAX_DEPTH}", {}
                prior = (run["state"]["steps"][sid].get("output") or {}).get("run")
                if prior:                       # resumed after the sub-run's approval was decided
                    sub = self._load(prior)
                else:
                    sub = self.start(spec["playbook"], run["tenant"], expr.render(spec.get("with") or {}, ctx),
                                     run["actor"], run.get("case_id"), run["dry_run"], wait=True, parent=rid,
                                     depth=run["state"]["depth"] + 1)
                st = sub["status"]
                if st in ("running", "waiting_approval"):
                    return "waiting_approval", {"run": sub["id"], "status": st}, None, {}
                if prior:
                    sub["state"]["containment"] = []     # already merged into this run by _finish
                status = "succeeded" if st == "succeeded" else "failed"
                return status, {"run": sub["id"], "status": st}, None if status == "succeeded" else \
                    f"sub-playbook {sub['id']} {st}", {"containment": sub["state"]["containment"]}
            if t == "foreach":
                return self._foreach(run, sid, spec, ctx)
            return self._action(run, sid, spec, ctx, spec)
        except (expr.ExprError, PlaybookError, ConnectorError, KeyError, ValueError, TypeError) as e:
            return "failed", None, f"{type(e).__name__}: {e}", {}

    def _approval_gate(self, run, sid, spec, ctx, summary=""):
        st = run["state"]["steps"][sid]
        appr = st.get("approval")
        if appr is None:
            aid = "APR-" + uuid.uuid4().hex[:10].upper()
            approvers = spec.get("approvers") or ["admin"]
            timeout = float(spec.get("timeout", self.approval_timeout))
            self._conn().execute("INSERT INTO approvals VALUES (?,?,?,?,'pending',?,?,?,NULL,NULL,NULL,?)",
                                 (aid, run["tenant"], run["id"], sid, str(summary)[:2000], json.dumps(approvers),
                                  time.time(), time.time() + timeout))
            self.audit.record("soar.approval_requested", {"run": run["id"], "step": sid, "approval": aid,
                                                          "summary": str(summary)[:500]}, actor=run["actor"])
            for fn in list(self.listeners):
                try:
                    fn("approval", {"id": aid, "tenant": run["tenant"], "run": run["id"], "step": sid,
                                    "summary": str(summary)[:500]})
                except Exception:
                    pass
            return "waiting_approval", None, None, {"approval": {"id": aid, "status": "pending"}}
        if appr["status"] == "approved":
            return "succeeded", {"approved_by": appr.get("by"), "reason": appr.get("reason")}, None, {}
        if appr["status"] in ("rejected", "expired"):
            return "rejected", None, f"approval {appr['status']} by {appr.get('by')}", {}
        return "waiting_approval", None, None, {"approval": appr}

    def _resolve(self, a: dict, ctx: dict | None = None):
        name = a["action"]
        if a.get("connector"):
            cname = expr.render(str(a["connector"]), ctx or {}) if "{{" in str(a["connector"]) else a["connector"]
            c = self.connectors.get(cname)
            if c is None:
                raise PlaybookError(f"connector {cname!r} is not configured")
            if name not in c.actions:
                raise PlaybookError(f"connector {cname!r} ({c.type}) has no action {name!r}")
            return c, name
        if name in self.builtins:
            return None, name
        raise PlaybookError(f"unknown action {name!r}")

    def _action(self, run, sid, spec, ctx, a, gate: bool = True):
        connector, name = self._resolve(a, ctx)
        params = expr.render(a.get("with") or {}, ctx)
        if connector is not None and gate and not run["dry_run"] and self.hitl_destructive \
                and name in connector.destructive and spec.get("approval", True) is not False:
            st, out, err, extra = self._approval_gate(
                run, sid, spec, ctx, summary=f"{connector.name}: {name} {json.dumps(params, default=str)[:300]}")
            if st != "succeeded":
                return st, out, err, extra
        retries = int(spec.get("retries", 0))
        delay = float(spec.get("retry_delay", 1.0))
        last = None
        for attempt in range(retries + 1):
            try:
                if connector is None:
                    out = self.builtins[name](params, {**ctx, "_run": run})
                    self.audit.record("soar.builtin", {"run": run["id"], "step": sid, "action": name},
                                      actor=run["actor"])
                    return "succeeded", out, None, {"attempts": attempt + 1}
                res = connector.execute(name, params, dry_run=run["dry_run"])
                self.audit.record("soar.command", {"run": run["id"], "step": sid, "connector": connector.name,
                                                   "type": connector.type, "action": name, "params": params,
                                                   "dry_run": run["dry_run"], "status": res.get("status"),
                                                   "requests": res.get("requests")}, actor=run["actor"])
                extra = {"attempts": attempt + 1}
                inv = connector.inverse(name)
                if inv and not run["dry_run"] and name in connector.destructive:
                    extra["containment"] = [{"connector": connector.name, "action": name, "inverse": inv,
                                             "params": params, "step": sid, "at": time.time()}]
                    if self.cases is not None and run.get("case_id"):
                        self.cases.mark_contained(run["tenant"], run["case_id"], run["actor"],
                                                  {"run": run["id"], "connector": connector.name, "action": name})
                return "succeeded", res, None, extra
            except (ConnectorError, OSError) as e:
                last = str(e)
                self.audit.record("soar.command_failed", {"run": run["id"], "step": sid, "action": name,
                                                          "attempt": attempt + 1, "error": last[:500]},
                                  actor=run["actor"])
                if attempt < retries:
                    time.sleep(min(delay * (2 ** attempt), 300))
        return "failed", None, last, {"attempts": retries + 1}

    def _foreach(self, run, sid, spec, ctx):
        items = expr.render(spec["items"], ctx)
        if items is None:
            items = []
        if not isinstance(items, list):
            items = [items]
        if len(items) > MAX_FOREACH:
            return "failed", None, f"foreach over {len(items)} items (max {MAX_FOREACH})", {}
        do = spec["do"]
        connector, name = self._resolve(do, ctx)
        if connector is not None and not run["dry_run"] and self.hitl_destructive and name in connector.destructive \
                and spec.get("approval", True) is not False:
            st, out, err, extra = self._approval_gate(run, sid, spec, ctx,
                                                      summary=f"{connector.name}: {name} x{len(items)}")
            if st != "succeeded":
                return st, out, err, extra
        par = max(1, min(int(spec.get("max_parallel", 4)), 16))
        with ThreadPoolExecutor(par, thread_name_prefix="ulpf-soar-foreach") as pool:
            futs = [pool.submit(self._action, run, f"{sid}[{i}]", {**spec, **do}, {**ctx, "item": it, "index": i},
                                do, False) for i, it in enumerate(items)]
            res = [f.result() for f in futs]
        out = [{"item": items[i], "status": r[0], "output": r[1], "error": r[2]} for i, r in enumerate(res)]
        cont = [c for r in res for c in r[3].get("containment", [])]
        failed = [o for o in out if o["status"] != "succeeded"]
        if failed and not spec.get("continue_on_item_failure", False):
            return "failed", out, f"{len(failed)} of {len(items)} items failed", {"containment": cont}
        return "succeeded", out, None, {"containment": cont}

    # ------------------------------------------------------------------
    # HITL
    # ------------------------------------------------------------------
    def approvals(self, tenant: str, status: str | None = "pending") -> list[dict]:
        self.expire_approvals()
        q, p = "SELECT * FROM approvals WHERE tenant=?", [tenant]
        if status:
            q += " AND status=?"
            p.append(status)
        rows = self._conn().execute(q + " ORDER BY requested_at DESC LIMIT 500", p).fetchall()
        return [{**dict(r), "approvers": json.loads(r["approvers"] or "[]")} for r in rows]

    def decide(self, tenant: str, approval_id: str, actor: str, approve: bool, reason: str = "",
               actor_roles: set | None = None) -> dict:
        with self._lock:
            r = self._conn().execute("SELECT * FROM approvals WHERE id=? AND tenant=?",
                                     (approval_id, tenant)).fetchone()
            if r is None:
                raise PlaybookError(f"approval {approval_id} not found")
            if r["status"] != "pending":
                raise PlaybookError(f"approval {approval_id} is already {r['status']}")
            approvers = set(json.loads(r["approvers"] or "[]"))
            if actor_roles is not None and approvers and not (approvers & (actor_roles | {actor})):
                raise PermissionError(f"approval needs one of: {', '.join(sorted(approvers))}")
            run = self._load(r["run_id"])
            if run["actor"] == actor and approve and os.environ.get("ULPF_SOAR_ALLOW_SELF_APPROVAL") != "1":
                raise PermissionError("four-eyes rule: the analyst who started the run cannot approve it")
            status = "approved" if approve else "rejected"
            self._conn().execute("UPDATE approvals SET status=?, decided_at=?, decided_by=?, reason=? WHERE id=?",
                                 (status, time.time(), actor, str(reason)[:2000], approval_id))
            st = run["state"]["steps"][r["step_id"]]
            st["approval"] = {"id": approval_id, "status": status, "by": actor, "reason": str(reason)[:500]}
            st["status"] = "pending"           # re-evaluated: runs (approved) or is rejected
            self._save(run, "running")
        self.audit.record("soar.approval_decided", {"approval": approval_id, "run": r["run_id"],
                                                    "step": r["step_id"], "decision": status,
                                                    "reason": str(reason)[:500]}, actor=actor)
        self._runs.submit(self._advance_safe, r["run_id"])
        return {"approval": approval_id, "status": status, "run": r["run_id"]}

    def expire_approvals(self) -> int:
        now = time.time()
        rows = self._conn().execute("SELECT id, tenant FROM approvals WHERE status='pending' AND expires_at < ?",
                                    (now,)).fetchall()
        for r in rows:
            try:
                self._conn().execute("UPDATE approvals SET status='expired', decided_at=?, decided_by='system' "
                                     "WHERE id=? AND status='pending'", (now, r["id"]))
                a = self._conn().execute("SELECT run_id, step_id FROM approvals WHERE id=?", (r["id"],)).fetchone()
                run = self._load(a["run_id"])
                st = run["state"]["steps"][a["step_id"]]
                st["approval"] = {"id": r["id"], "status": "expired", "by": "system"}
                st["status"] = "pending"
                self._save(run, "running")
                self._runs.submit(self._advance_safe, a["run_id"])
            except Exception:
                continue
        return len(rows)

    # ------------------------------------------------------------------
    # Rollback (bi-directional containment)
    # ------------------------------------------------------------------
    def rollback(self, tenant: str, rid: str, actor: str, dry_run: bool = False) -> dict:
        run = self.get_run(tenant, rid)
        done = []
        for c in reversed(run["state"]["containment"]):
            if c.get("rolled_back"):
                continue
            conn = self.connectors.get(c["connector"])
            if conn is None:
                done.append({**c, "rollback": "connector missing"})
                continue
            try:
                res = conn.execute(c["inverse"], c["params"], dry_run=dry_run)
                status = res.get("status")
                if not dry_run:
                    c["rolled_back"] = time.time()
            except ConnectorError as e:
                status = f"failed: {e}"
            self.audit.record("soar.rollback", {"run": rid, "connector": c["connector"], "action": c["inverse"],
                                                "params": c["params"], "dry_run": dry_run, "status": status},
                              actor=actor)
            done.append({"connector": c["connector"], "action": c["inverse"], "status": status})
        if not dry_run:
            self._save(run)
        return {"run": rid, "rolled_back": done}

    # ------------------------------------------------------------------
    # Built-in actions
    # ------------------------------------------------------------------
    def _case(self, ctx):
        run = ctx["_run"]
        if self.cases is None or not run.get("case_id"):
            raise PlaybookError("this action needs a run attached to a case")
        return run["tenant"], run["case_id"], run["actor"]

    def _b_case_transition(self, p, ctx):
        t, c, a = self._case(ctx)
        if ctx["run"]["dry_run"]:
            return {"simulated": f"case -> {p['state']}"}
        case = self.cases.get(t, c)
        if case["state"] == p["state"]:
            return {"state": case["state"]}
        return {"state": self.cases.transition(t, c, p["state"], f"playbook:{a}", p.get("note"))["state"]}

    def _b_case_note(self, p, ctx):
        t, c, a = self._case(ctx)
        if not ctx["run"]["dry_run"]:
            self.cases.note(t, c, f"playbook:{a}", str(p.get("text", "")))
        return {"noted": True}

    def _b_case_artifact(self, p, ctx):
        t, c, a = self._case(ctx)
        data = p.get("data")
        data = json.dumps(data, default=str).encode() if not isinstance(data, str) else data.encode()
        if ctx["run"]["dry_run"]:
            return {"simulated": True, "bytes": len(data)}
        return self.cases.add_artifact(t, c, p.get("kind", "note"), data, f"playbook:{a}", p.get("name"))

    def _b_case_contained(self, p, ctx):
        t, c, a = self._case(ctx)
        if not ctx["run"]["dry_run"]:
            self.cases.mark_contained(t, c, f"playbook:{a}", {"note": p.get("note")})
        return {"contained": True}

    def _b_case_task(self, p, ctx):
        t, c, a = self._case(ctx)
        if ctx["run"]["dry_run"]:
            return {"simulated": True}
        return self.cases.add_task(t, c, str(p.get("title", "task")), f"playbook:{a}", p.get("assignee"))

    def _b_fail(self, p, ctx):
        raise PlaybookError(str(p.get("message", "util.fail")))
