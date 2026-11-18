"""Copilot facade and REST endpoints (``copilot:`` config section, ``copilot:use`` permission)."""
from __future__ import annotations

import time

from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse

from ulpf.api.rbac import Principal, need
from ulpf.copilot import nl2query, triage
from ulpf.copilot.inference import load_backend


class Copilot:
    def __init__(self, cfg: dict | None = None, runtime=None):
        self.cfg = cfg or {}
        self.rt = runtime
        self.backend = load_backend(self.cfg)
        self.stats = {"nl2query": 0, "triage": 0, "explain": 0}

    def status(self) -> dict:
        return {**self.backend.info(), "errors": getattr(self.backend, "errors", []), "stats": self.stats,
                "network": "none (air-gapped: local weights, no outbound connections)"}

    def nl2query(self, question: str, language: str = "kql") -> dict:
        self.stats["nl2query"] += 1
        engine = getattr(self.rt, "query_engine", None) if self.rt is not None else None
        return nl2query.translate(question, language, self.backend, engine)

    def triage_case(self, tenant: str, case_id: str, soar, db=None) -> dict:
        self.stats["triage"] += 1
        case = soar.cases.get(tenant, case_id)
        case["timeline"] = soar.cases.timeline(tenant, case_id)
        ids = [a for a in (case.get("entities") or {}).get("event_ids", [])]
        for art in soar.cases.artifacts(tenant, case_id):
            if art["kind"] == "raw_event" and art["bytes"] < 200:
                try:
                    ids.append(soar.cases.read_artifact(tenant, art["id"], "copilot").decode())
                except Exception:
                    continue
        events = db.get_events(ids[:5000]) if db is not None and ids else []
        if db is not None and len(events) < 5 and (case.get("entities") or {}).get("ip"):
            events += db.query_events({"source_ip": case["entities"]["ip"]}, limit=500)
        return triage.investigate(case, events, [], self.backend)

    def explain(self, techniques: list[str]) -> dict:
        self.stats["explain"] += 1
        from ulpf.intelligence.sigma import TACTICS, TECHNIQUES
        out = []
        for t in techniques[:50]:
            t = str(t).upper()
            tac = triage.TECH_TACTIC.get(t) or triage.TECH_TACTIC.get(t.split(".")[0])
            out.append({"technique": t, "name": TECHNIQUES.get(t) or TECHNIQUES.get(t.split(".")[0]) or "unknown",
                        "tactic": TACTICS.get(tac, ("", tac or "unknown", ""))[1],
                        "containment": [{"kind": k, "recommendation": r} for k, r in triage.CONTAINMENT.get(tac, [])]})
        return {"techniques": out}


def build_router(cp: Copilot, runtime=None) -> APIRouter:
    r = APIRouter(prefix="/api/v1/copilot", tags=["Copilot"])

    @r.get("/status")
    def status(p: Principal = Depends(need("copilot:use"))):
        return cp.status()

    @r.post("/nl2query")
    def nl2q(body: dict = Body(...), p: Principal = Depends(need("copilot:use"))):
        t0 = time.monotonic()
        try:
            res = cp.nl2query(str(body.get("question", "")), str(body.get("language", "kql")))
        except ValueError as e:
            return JSONResponse({"error": str(e)}, 400)
        res["elapsed_ms"] = round((time.monotonic() - t0) * 1000, 1)
        return res

    @r.post("/triage")
    def tri(body: dict = Body(...), p: Principal = Depends(need("copilot:use"))):
        soar = getattr(runtime, "soar", None)
        if body.get("case_id"):
            if soar is None:
                return JSONResponse({"error": "SOAR is not enabled"}, 404)
            db = getattr(runtime, "db", None) or getattr(runtime, "database", None)
            try:
                return cp.triage_case(p.tenant, body["case_id"], soar, db)
            except Exception as e:
                return JSONResponse({"error": str(e)}, 404)
        return triage.investigate(body.get("case"), body.get("events") or [], body.get("detections") or [],
                                  cp.backend)

    @r.post("/explain")
    def explain(body: dict = Body(...), p: Principal = Depends(need("copilot:use"))):
        return cp.explain(list(body.get("techniques") or []))

    return r
