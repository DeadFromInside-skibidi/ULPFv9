"""
SOAR service: cases + playbook engine + connectors, wired to the runtime and the API.

Configuration (``soar:`` in the pipeline YAML)::

    soar:
      enabled: true
      tenant: default                       # tenant of auto-created cases
      auto_case_levels: [high, critical]    # Sigma levels that open a case
      playbooks_dir: /etc/ulpf/playbooks     # extra playbooks (the bundled ones always load)
      hitl: {destructive: true, approval_timeout_seconds: 86400}
      sla: {critical: {triage: 900, contain: 14400, close: 86400}}
      connectors:
        - {name: perimeter-fw, type: panos, url: https://fw.corp, api_key_env: PANOS_KEY}
        - {name: edr, type: defender, tenant_id: ..., client_id: ..., client_secret_env: MDE_SECRET}
"""
from __future__ import annotations

import logging
import os
import threading
import time

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response

from ulpf.api.rbac import Principal, need
from ulpf.runtime.audit import AuditLog, verify_audit_log
from ulpf.soar import connectors as conns
from ulpf.soar.cases import CaseError, CaseStore, NotFound
from ulpf.soar.playbook import PlaybookEngine, PlaybookError, load_spec, validate

logger = logging.getLogger(__name__)
_LEVEL_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "low"}
BUNDLED_PLAYBOOKS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "playbooks")  # shipped in the wheel


class SoarService:
    def __init__(self, data_dir: str, cfg: dict | None = None, transport=None, env=None):
        cfg = cfg or {}
        self.cfg = cfg
        self.dir = os.path.join(data_dir, "soar")
        os.makedirs(self.dir, exist_ok=True)
        self.audit = AuditLog(os.path.join(self.dir, "audit.log"))
        self.tenant = cfg.get("tenant", "default")
        self.cases = CaseStore(self.dir, cfg.get("sla"), self.audit)
        self.connectors = {}
        self.connector_errors: list[str] = []
        for c in cfg.get("connectors") or []:
            try:
                self.connectors[c["name"]] = conns.build(c, transport, env)
            except (conns.ConnectorError, KeyError) as e:
                self.connector_errors.append(f"{c.get('name')}: {e}")
        hitl = cfg.get("hitl") or {}
        self.engine = PlaybookEngine(self.dir, self.connectors, self.cases, self.audit,
                                     hitl_destructive=hitl.get("destructive", True),
                                     approval_timeout=float(hitl.get("approval_timeout_seconds", 86400)))
        self.playbook_errors = self.engine.load_dir(BUNDLED_PLAYBOOKS)
        if cfg.get("playbooks_dir"):
            self.playbook_errors += self.engine.load_dir(cfg["playbooks_dir"])
        self.auto_levels = set(cfg.get("auto_case_levels") or ["high", "critical"])
        self._seen = None             # last detection processed (identity cursor, see new_since)
        self._stop = threading.Event()
        self._thread = None
        self.engine.resume_pending()

    # ------------------------------------------------------------------
    def on_detections(self, detections: list[dict], tenant: str | None = None) -> list[dict]:
        """Open (or reuse) a case per detection at an auto-case level and run matching playbooks."""
        tenant = tenant or self.tenant
        opened = []
        for d in detections:
            level = str(d.get("level") or "medium").lower()
            if level not in self.auto_levels:
                continue
            bucket = int(time.time() // 3600)
            ref = f"{d.get('rule_id')}|{d.get('key')}|{bucket}"
            entities = {k: v for k, v in (d.get("entities") or {}).items()} if isinstance(d.get("entities"), dict) \
                else {}
            case = self.cases.create(tenant, f"[{level.upper()}] {d.get('title') or d.get('rule_id')}",
                                     _LEVEL_SEV.get(level, "medium"), actor="detection", source="sigma",
                                     source_ref=ref, mitre=d.get("techniques") or [], entities=entities,
                                     description=f"Sigma rule {d.get('rule_id')} matched (group {d.get('key')}, "
                                                 f"{d.get('count', 1)} event(s)).")
            if case["created_at"] >= time.time() - 5 and d.get("event_id"):
                try:
                    self.cases.add_artifact(tenant, case["id"], "raw_event",
                                            str(d.get("event_id")).encode(), "detection", "triggering event id",
                                            {"rule": d.get("rule_id")})
                except CaseError:
                    pass
            for pb in self.engine.playbooks.values():
                if _matches(pb.get("triggers") or {}, d, level):
                    try:
                        self.engine.start(pb["id"], tenant, {**entities, "detection": d}, "detection", case["id"],
                                          dry_run=bool((pb.get("triggers") or {}).get("dry_run", False)))
                    except PlaybookError as e:
                        logger.warning(f"SOAR: playbook {pb['id']} not started for {case['id']}: {e}")
            opened.append(case)
        return opened

    def attach_runtime(self, rt, interval: float = 5.0) -> None:
        """Poll the runtime's Sigma detections and turn new ones into cases."""
        def loop():
            while not self._stop.wait(interval):
                try:
                    corr = getattr(getattr(rt, "correlator", None), "correlator", None)
                    new, self._seen = new_since(getattr(corr, "detections", None), self._seen)
                    if new:
                        self.on_detections([_det_dict(x) for x in new])
                    self.engine.expire_approvals()
                except Exception:
                    logger.exception("SOAR detection poller")
        self._thread = threading.Thread(target=loop, name="ulpf-soar-poll", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        self.engine.close()

    def router(self) -> APIRouter:
        return build_router(self)


def new_since(seq, last) -> tuple[list, object]:
    """Items appended to a bounded deque (newest last) after ``last`` (an item, by identity).

    The correlator keeps detections in ``deque(maxlen=10_000)``: its length stops growing, so an
    index cursor would stop seeing new detections. Walking back from the newest item to the last
    one seen costs O(new items), never O(deque).
    """
    if not seq:
        return [], last
    newest = seq[-1]
    if last is None:                       # first poll: everything currently buffered is new
        return list(seq), newest
    out = []
    for x in reversed(seq):
        if x is last:
            break
        out.append(x)
        if len(out) >= len(seq):           # cursor evicted from the deque: all items are new
            break
    out.reverse()
    return out, newest


def _det_dict(x) -> dict:
    d = x.to_dict() if hasattr(x, "to_dict") else dict(x)
    ents = getattr(x, "entities", None) or []
    em: dict = {}
    for item in ents:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            k = {"ip": "ip", "src_ip": "ip", "user": "user", "host": "host"}.get(str(item[0]), str(item[0]))
            em.setdefault(k, item[1])
    d["entities"] = em
    return d


def _matches(trig: dict, d: dict, level: str) -> bool:
    if not trig:
        return False
    if trig.get("levels") and level not in trig["levels"]:
        return False
    if trig.get("rules") and d.get("rule_id") not in trig["rules"]:
        return False
    if trig.get("techniques"):
        if not set(trig["techniques"]) & set(d.get("techniques") or []):
            return False
    return bool(trig.get("levels") or trig.get("rules") or trig.get("techniques"))


def _err(e: Exception):
    if isinstance(e, NotFound):
        return JSONResponse({"error": str(e)}, 404)
    if isinstance(e, PermissionError):
        return JSONResponse({"error": str(e)}, 403)
    return JSONResponse({"error": str(e)}, 400)


def build_router(svc: SoarService) -> APIRouter:
    r = APIRouter(prefix="/api/v1/soar", tags=["SOAR"])

    @r.get("/cases")
    def list_cases(state: str | None = None, severity: str | None = None, assignee: str | None = None,
                   limit: int = Query(200, ge=1, le=1000), p: Principal = Depends(need("cases:read"))):
        return {"cases": svc.cases.list(p.tenant, state, severity, assignee, limit)}

    @r.post("/cases")
    def create_case(body: dict = Body(...), p: Principal = Depends(need("cases:write"))):
        try:
            return svc.cases.create(p.tenant, body.get("title", ""), body.get("severity", "medium"), actor=p.name,
                                    description=body.get("description"), tags=body.get("tags"),
                                    mitre=body.get("mitre"), entities=body.get("entities"),
                                    first_event_at=body.get("first_event_at"), assignee=body.get("assignee"))
        except CaseError as e:
            return _err(e)

    @r.get("/cases/{case_id}")
    def get_case(case_id: str, p: Principal = Depends(need("cases:read"))):
        try:
            c = svc.cases.get(p.tenant, case_id)
            return {**c, "timeline": svc.cases.timeline(p.tenant, case_id), "tasks": svc.cases.tasks(p.tenant, case_id),
                    "artifacts": svc.cases.artifacts(p.tenant, case_id),
                    "runs": [{"id": x["id"], "playbook": x["playbook"], "status": x["status"]}
                             for x in svc.engine.list_runs(p.tenant, 50, case_id)]}
        except CaseError as e:
            return _err(e)

    @r.patch("/cases/{case_id}")
    def update_case(case_id: str, body: dict = Body(...), p: Principal = Depends(need("cases:write"))):
        try:
            if "state" in body:
                svc.cases.transition(p.tenant, case_id, body.pop("state"), p.name, body.pop("note", None),
                                     body.pop("resolution", None))
            if body:
                return svc.cases.update(p.tenant, case_id, p.name, **body)
            return svc.cases.get(p.tenant, case_id)
        except CaseError as e:
            return _err(e)

    @r.post("/cases/{case_id}/notes")
    def add_note(case_id: str, body: dict = Body(...), p: Principal = Depends(need("cases:write"))):
        try:
            return svc.cases.note(p.tenant, case_id, p.name, str(body.get("text", "")))
        except CaseError as e:
            return _err(e)

    @r.post("/cases/{case_id}/tasks")
    def add_task(case_id: str, body: dict = Body(...), p: Principal = Depends(need("cases:write"))):
        try:
            return svc.cases.add_task(p.tenant, case_id, str(body.get("title", "")), p.name, body.get("assignee"))
        except CaseError as e:
            return _err(e)

    @r.post("/cases/{case_id}/artifacts")
    async def add_artifact(case_id: str, request: Request, kind: str = "file", name: str | None = None,
                           p: Principal = Depends(need("evidence:write"))):
        data = await request.body()
        try:
            return svc.cases.add_artifact(p.tenant, case_id, kind, data, p.name, name)
        except CaseError as e:
            return _err(e)

    @r.get("/artifacts/{artifact_id}")
    def get_artifact(artifact_id: str, p: Principal = Depends(need("evidence:read"))):
        try:
            data = svc.cases.read_artifact(p.tenant, artifact_id, p.name)
            return Response(data, media_type="application/octet-stream",
                            headers={"Content-Disposition": f'attachment; filename="{artifact_id}"'})
        except CaseError as e:
            return _err(e)

    @r.get("/kpis")
    def kpis(days: int = Query(30, ge=1, le=3650), p: Principal = Depends(need("metrics:read"))):
        return svc.cases.kpis(p.tenant, time.time() - days * 86400)

    @r.get("/playbooks")
    def playbooks(p: Principal = Depends(need("cases:read"))):
        return {"playbooks": [{"id": x["id"], "name": x["name"], "version": x["version"],
                               "description": x["description"], "inputs": x["inputs"], "triggers": x["triggers"],
                               "steps": [{k: v for k, v in s.items() if not k.startswith("_")}
                                         for s in x["steps"].values()]}
                              for x in svc.engine.playbooks.values()],
                "errors": svc.playbook_errors}

    @r.post("/playbooks/validate")
    def validate_pb(body: dict = Body(...), p: Principal = Depends(need("cases:read"))):
        try:
            spec = load_spec(body["source"]) if "source" in body else body
            pb = validate(spec, svc.connectors, set(svc.engine.builtins))
            return {"valid": True, "id": pb["id"], "steps": len(pb["order"])}
        except (PlaybookError, ValueError, KeyError) as e:
            return {"valid": False, "error": str(e)}

    @r.put("/playbooks")
    def save_pb(body: dict = Body(...), p: Principal = Depends(need("playbooks:write"))):
        try:
            spec = load_spec(body["source"]) if "source" in body else body
            pb = svc.engine.register(spec)
        except (PlaybookError, ValueError, KeyError) as e:
            return _err(e)
        d = svc.cfg.get("playbooks_dir") or os.path.join(svc.dir, "playbooks")
        os.makedirs(d, exist_ok=True)
        import json
        with open(os.path.join(d, f"{pb['id']}.json"), "w", encoding="utf-8") as f:
            json.dump(spec, f, indent=2)
        svc.audit.record("soar.playbook_saved", {"playbook": pb["id"], "version": pb["version"]}, actor=p.name)
        return {"saved": pb["id"]}

    @r.post("/playbooks/{playbook_id}/run")
    def run_pb(playbook_id: str, body: dict = Body(default={}), p: Principal = Depends(need("playbooks:run"))):
        try:
            return svc.engine.start(playbook_id, p.tenant, body.get("inputs") or {}, p.name, body.get("case_id"),
                                    bool(body.get("dry_run", False)), wait=bool(body.get("wait", False)))
        except PlaybookError as e:
            return _err(e)

    @r.get("/runs")
    def runs(case_id: str | None = None, limit: int = Query(100, ge=1, le=1000),
             p: Principal = Depends(need("cases:read"))):
        return {"runs": svc.engine.list_runs(p.tenant, limit, case_id)}

    @r.get("/runs/{run_id}")
    def run(run_id: str, p: Principal = Depends(need("cases:read"))):
        try:
            return svc.engine.get_run(p.tenant, run_id)
        except PlaybookError as e:
            return JSONResponse({"error": str(e)}, 404)

    @r.post("/runs/{run_id}/rollback")
    def rollback(run_id: str, body: dict = Body(default={}), p: Principal = Depends(need("playbooks:run"))):
        try:
            return svc.engine.rollback(p.tenant, run_id, p.name, bool(body.get("dry_run", False)))
        except PlaybookError as e:
            return _err(e)

    @r.get("/approvals")
    def approvals(status: str | None = "pending", p: Principal = Depends(need("cases:read"))):
        return {"approvals": svc.engine.approvals(p.tenant, status)}

    @r.post("/approvals/{approval_id}")
    def decide(approval_id: str, body: dict = Body(...), p: Principal = Depends(need("approvals:decide"))):
        try:
            return svc.engine.decide(p.tenant, approval_id, p.name, bool(body.get("approve")),
                                     str(body.get("reason", "")), p.roles)
        except (PlaybookError, PermissionError) as e:
            return _err(e)

    @r.get("/connectors")
    def connectors(p: Principal = Depends(need("cases:read"))):
        return {"configured": [{"name": c.name, "type": c.type, "category": c.category,
                                "actions": sorted(c.actions), "destructive": sorted(c.destructive)}
                               for c in svc.connectors.values()],
                "catalog": conns.catalog(), "errors": svc.connector_errors}

    @r.post("/connectors/{name}/dry-run")
    def connector_dry_run(name: str, body: dict = Body(...), p: Principal = Depends(need("playbooks:run"))):
        c = svc.connectors.get(name)
        if c is None:
            raise HTTPException(404, f"connector {name} not configured")
        try:
            return c.execute(body["action"], body.get("params") or {}, dry_run=True)
        except (conns.ConnectorError, KeyError) as e:
            return _err(e)

    @r.get("/audit/verify")
    def audit_verify(p: Principal = Depends(need("audit:read"))):
        return verify_audit_log(svc.audit.path)

    return r
