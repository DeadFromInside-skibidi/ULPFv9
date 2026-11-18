"""
Multi-tenant web console: static single-page app + console APIs + live WebSocket stream.

    /console/                       the SOC console (no CDN, no build step, strict CSP)
    GET  /api/v1/console/me         principal, role, permissions, tenants
    POST /api/v1/console/ws-ticket  single-use 60 s ticket for the WebSocket
    GET  /api/v1/console/overview   EPS, bandwidth, drops, buffer fill, totals, incidents
    GET  /api/v1/console/attack     ATT&CK matrix heat map (detections + cases)
    GET  /api/v1/console/graph      identity / lateral-movement graph (user, source -> destination)
    GET  /api/v1/console/flows      Sankey flows: source -> destination port -> action
    GET  /api/v1/console/schema     fields for the query editor's schema explorer and autocomplete
    POST /api/v1/compliance/matrix  run the compliance matrix (compliance:read)
    WS   /api/v1/console/stream     metrics every second + case / approval / run / detection events

The console works against the runtime (``ulpf run``) with every feature, and in
the standalone API (``ulpf serve``) with the features that need no runtime.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from collections import deque

from fastapi import Body, Depends, FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response

from ulpf.api import rbac
from ulpf.api.rbac import Principal, need

logger = logging.getLogger(__name__)
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' ws: wss:; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'")


class Telemetry:
    """Samples the runtime once a second: EPS, bytes/s, drops, buffer fill (bounded history)."""

    def __init__(self, rt):
        self.rt = rt
        self.history: deque = deque(maxlen=900)
        self._last = None
        self._lock = threading.Lock()

    def sample(self) -> dict:
        rt = self.rt
        now = time.time()
        js = rt.journal.stats() if rt is not None and getattr(rt, "journal", None) else {}
        rec, byt = js.get("records_written", 0), js.get("bytes_written", 0)
        fills, dropped = [], 0
        for b in (getattr(rt, "buffers", {}) or {}).values() if rt is not None else []:
            try:
                s = b.stats()
                fills.append(s.get("fill_ratio", 0.0))
                dropped += int(s.get("dropped_events", 0))
            except Exception:
                continue
        with self._lock:
            eps = bps = 0.0
            if self._last:
                dt = max(1e-3, now - self._last[0])
                eps = max(0.0, (rec - self._last[1]) / dt)
                bps = max(0.0, (byt - self._last[2]) / dt)
            self._last = (now, rec, byt)
            point = {"t": now, "eps": round(eps, 1), "bytes_per_s": round(bps, 1), "dropped": dropped,
                     "buffer_fill": round(max(fills) if fills else 0.0, 4), "records": rec}
            self.history.append(point)
        return point


class Hub:
    """Fan-out of live events to WebSocket clients, per tenant, with bounded queues."""

    def __init__(self):
        self.clients: dict[int, tuple[str, asyncio.Queue, asyncio.AbstractEventLoop]] = {}
        self._lock = threading.Lock()

    def publish(self, kind: str, payload: dict) -> None:
        tenant = payload.get("tenant", "default")
        msg = json.dumps({"type": kind, "data": payload}, default=str)
        with self._lock:
            targets = [(q, loop) for t, q, loop in self.clients.values() if t == tenant or kind == "metrics"]
        for q, loop in targets:
            def put(q=q):
                if q.full():
                    try:
                        q.get_nowait()          # slow client: drop the oldest message, never block publishers
                    except asyncio.QueueEmpty:
                        pass
                q.put_nowait(msg)
            try:
                loop.call_soon_threadsafe(put)
            except RuntimeError:
                continue


def mount_console(app: FastAPI, rt=None) -> None:
    hub = Hub()
    tele = Telemetry(rt)
    app.state.console_hub = hub
    soar = getattr(rt, "soar", None)
    copilot = getattr(rt, "copilot", None)

    if soar is not None:
        app.include_router(soar.router())
        soar.cases.listeners.append(lambda kind, case: hub.publish("case", {"event": kind, "tenant": case["tenant"],
                                                                            "id": case["id"], "title": case["title"],
                                                                            "severity": case["severity"],
                                                                            "state": case["state"]}))
        soar.engine.listeners.append(lambda kind, d: hub.publish(kind, d))
    from ulpf.copilot.service import Copilot, build_router as copilot_router
    if copilot is None:                 # the rules backend needs no model and is always available
        copilot = Copilot({}, rt)
    app.include_router(copilot_router(copilot, rt))
    fleet_cfg = ((getattr(rt, "cfg", None) and rt.cfg.data.get("fleet")) or {}) if rt is not None else {}
    if fleet_cfg.get("enabled"):
        from ulpf.fleet.api import build_router as fleet_router
        from ulpf.fleet.control import FleetControl
        app.include_router(fleet_router(FleetControl(rt.data_dir), rt))

    @app.middleware("http")
    async def _security_headers(request, call_next):
        resp = await call_next(request)
        if request.url.path.startswith("/console"):
            resp.headers["Content-Security-Policy"] = CSP
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Referrer-Policy"] = "no-referrer"
            resp.headers["X-Frame-Options"] = "DENY"
        return resp

    @app.get("/console", include_in_schema=False)
    def _console_root():
        return RedirectResponse("/console/")

    @app.get("/console/{path:path}", include_in_schema=False)
    def _console(path: str = ""):
        target = os.path.normpath(os.path.join(STATIC, path or "index.html"))
        if not target.startswith(STATIC) or not os.path.isfile(target):
            target = os.path.join(STATIC, "index.html")          # SPA routes
        return FileResponse(target, headers={"Cache-Control": "no-cache"})

    @app.get("/api/v1/console/me", tags=["Console"])
    def me(p: Principal = Depends(rbac.principal)):
        return {"name": p.name, "role": p.role, "tenant": p.tenant, "tenants": p.tenants,
                "permissions": sorted(p.perms),
                "features": {"runtime": rt is not None, "soar": soar is not None, "copilot": True,
                             "fleet": bool(fleet_cfg.get("enabled")), "cluster": bool(getattr(rt, "cluster", None))}}

    @app.post("/api/v1/console/ws-ticket", tags=["Console"])
    def ticket(p: Principal = Depends(need("metrics:read"))):
        return {"ticket": rbac.issue_ticket(p), "expires_in": rbac.TICKET_TTL}

    @app.get("/api/v1/console/overview", tags=["Console"])
    def overview(p: Principal = Depends(need("metrics:read"))):
        latest = tele.history[-1] if tele.history and time.time() - tele.history[-1]["t"] < 2.5 else tele.sample()
        out = {"node": getattr(rt, "node", None), "metrics": latest, "history": list(tele.history)[-300:]}
        if rt is not None:
            st = rt.stats()
            out.update(mode=st.get("mode"), uptime_seconds=st.get("uptime_seconds"),
                       inputs=list((st.get("inputs") or {}).keys()), outputs=st.get("outputs"),
                       evidence=st.get("evidence"), cluster=st.get("cluster"), dlq=st.get("dlq"),
                       egress={"mode": (st.get("egress") or {}).get("mode"),
                               "blocked": len((st.get("egress") or {}).get("blocked") or {})})
        if soar is not None:
            out["incidents"] = soar.cases.kpis(p.tenant)
            out["open_cases"] = [c for c in soar.cases.list(p.tenant, limit=50)
                                 if c["state"] not in ("closed", "post_incident")][:20]
            out["approvals"] = soar.engine.approvals(p.tenant)
        out["detections"] = _recent_detections(rt, 25)
        return out

    @app.get("/api/v1/console/attack", tags=["Console"])
    def attack(p: Principal = Depends(need("metrics:read"))):
        from ulpf.copilot.triage import TECH_TACTIC
        from ulpf.intelligence.sigma import TACTICS, TECHNIQUES
        counts: dict[str, int] = {}
        for d in _recent_detections(rt, 10_000):
            for t in d.get("techniques") or []:
                counts[str(t).upper()] = counts.get(str(t).upper(), 0) + 1
        if soar is not None:
            for c in soar.cases.list(p.tenant, limit=1000):
                for t in c.get("mitre") or []:
                    counts[str(t).upper()] = counts.get(str(t).upper(), 0) + 1
        cols = []
        for key, (tid, name, _stage) in TACTICS.items():
            techs = sorted({t for t, tac in TECH_TACTIC.items() if tac == key} |
                           {t for t in counts if (TECH_TACTIC.get(t) or TECH_TACTIC.get(t.split(".")[0])) == key})
            cols.append({"tactic": key, "id": tid, "name": name,
                         "techniques": [{"id": t, "name": TECHNIQUES.get(t) or TECHNIQUES.get(t.split(".")[0]) or t,
                                         "count": counts.get(t, 0) + sum(v for k, v in counts.items()
                                                                         if k.startswith(t + "."))} for t in techs]})
        return {"tactics": cols, "total": sum(counts.values())}

    def _db():
        return getattr(rt, "database", None) if rt is not None else None

    @app.get("/api/v1/console/graph", tags=["Console"])
    def graph(hours: float = Query(24, gt=0, le=24 * 90), limit: int = Query(300, ge=10, le=2000),
              p: Principal = Depends(need("query:run"))):
        db = _db()
        if db is None:
            return {"nodes": [], "edges": []}
        since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - hours * 3600))
        with db._conn_lock:
            rows = db.conn.execute(
                "SELECT json_extract_string(normalised_json, '$.user.name') u, source_ip, destination_ip, "
                "count(*) n, sum(CASE WHEN action IN ('failed','denied') THEN 1 ELSE 0 END) f FROM events "
                "WHERE timestamp >= ? AND source_ip IS NOT NULL AND destination_ip IS NOT NULL "
                "AND lower(coalesce(category,'')) LIKE '%auth%' GROUP BY 1, 2, 3 ORDER BY n DESC LIMIT ?",
                [since, limit]).fetchall()
        nodes, edges = {}, []
        for u, s, d, n, f in rows:
            for ip in (s, d):
                nodes.setdefault(ip, {"id": ip, "kind": "host", "weight": 0})
                nodes[ip]["weight"] += n
            if u:
                nodes.setdefault("user:" + u, {"id": "user:" + u, "label": u, "kind": "user", "weight": 0})
                nodes["user:" + u]["weight"] += n
                edges.append({"source": "user:" + u, "target": s, "kind": "uses", "count": n})
            edges.append({"source": s, "target": d, "kind": "auth", "count": n, "failed": f, "user": u})
        return {"nodes": list(nodes.values()), "edges": edges}

    @app.get("/api/v1/console/flows", tags=["Console"])
    def flows(hours: float = Query(24, gt=0, le=24 * 90), limit: int = Query(40, ge=5, le=200),
              p: Principal = Depends(need("query:run"))):
        db = _db()
        if db is None:
            return {"flows": []}
        since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - hours * 3600))
        with db._conn_lock:
            rows = db.conn.execute(
                "SELECT source_ip, CAST(destination_port AS VARCHAR), coalesce(action,'unknown'), count(*) n "
                "FROM events WHERE timestamp >= ? AND source_ip IS NOT NULL AND destination_port IS NOT NULL "
                "GROUP BY 1, 2, 3 ORDER BY n DESC LIMIT ?", [since, limit]).fetchall()
        return {"flows": [{"source": r[0], "port": r[1], "action": r[2], "count": r[3]} for r in rows]}

    @app.get("/api/v1/console/schema", tags=["Console"])
    def schema(p: Principal = Depends(need("query:run"))):
        from ulpf.storage.database import EVENT_COLUMNS
        nested = ["user.name", "user.domain", "process.name", "process.command_line", "file.path", "file.hash.sha256",
                  "dns.question", "url.full", "http.status", "rule.id", "rule.name", "event_kind", "threat.indicator"]
        return {"columns": [c for c in EVENT_COLUMNS if c not in ("row_mac", "normalised_json", "parsed_fields")],
                "nested": nested,
                "dialects": {"kql": ["where", "summarize", "project", "extend", "top", "take", "sort by", "count",
                                     "distinct", "bin", "ago", "has", "contains", "startswith", "in", "between",
                                     "make-series", "mv-expand", "join"],
                             "spl": ["search", "where", "stats", "count", "by", "sort", "head", "tail", "table",
                                     "fields", "rex", "eval", "timechart", "bin", "dedup", "rename", "top", "rare"],
                             "hql": ["groupBy", "count", "sort", "head", "tail", "timeChart", "select", "table",
                                     "regex", "eval", "in", "top", "sum", "avg", "max", "min"]}}

    @app.post("/api/v1/compliance/matrix", tags=["Compliance"])
    def compliance_matrix(body: dict = Body(default={}), p: Principal = Depends(need("compliance:read"))):
        from ulpf.compliance.matrix import FRAMEWORKS, Collector
        if rt is None:
            return JSONResponse({"error": "the compliance matrix needs the runtime (ulpf run)"}, 404)
        fws = [f for f in body.get("frameworks") or list(FRAMEWORKS) if f in FRAMEWORKS]
        col = Collector(rt.data_dir, rt.cfg.data, _db(), getattr(rt, "journal", None), soar,
                        body.get("since"), body.get("until"), ntp_result=body.get("ntp_result"))
        return col.run(fws)

    @app.post("/api/v1/compliance/matrix/export", tags=["Compliance"])
    def compliance_export(body: dict = Body(default={}), p: Principal = Depends(need("compliance:export"))):
        from ulpf.compliance.matrix import FRAMEWORKS, Collector, export_bundle
        if rt is None:
            return JSONResponse({"error": "the compliance export needs the runtime (ulpf run)"}, 404)
        fws = [f for f in body.get("frameworks") or list(FRAMEWORKS) if f in FRAMEWORKS]
        col = Collector(rt.data_dir, rt.cfg.data, _db(), getattr(rt, "journal", None), soar,
                        body.get("since"), body.get("until"))
        out = os.path.join(rt.data_dir, "compliance", "exports",
                           f"compliance-{p.tenant}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.zip")
        res = export_bundle(col, out, fws, str(body.get("organisation", "")))
        with open(out, "rb") as f:
            data = f.read()
        return Response(data, media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{os.path.basename(out)}"',
                                 "X-ULPF-Summary": json.dumps(res["summary"])})

    @app.websocket("/api/v1/console/stream")
    async def stream(ws: WebSocket, ticket: str = ""):
        try:
            p = rbac.resolve(ticket or None, ws.query_params.get("tenant"))
        except Exception:
            await ws.close(code=4401)
            return
        await ws.accept()
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        key = id(ws)
        with hub._lock:
            hub.clients[key] = (p.tenant, q, asyncio.get_running_loop())
        if bcast["task"] is None or bcast["task"].done():
            bcast["task"] = asyncio.create_task(broadcaster())
        try:
            while True:
                msg = await q.get()
                await ws.send_text(msg)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            with hub._lock:
                hub.clients.pop(key, None)

    bcast: dict = {"task": None, "last_det": None}

    async def broadcaster():
        """One sampler for every client: metrics each second, new detections as they appear.

        Sampling runs in a worker thread (buffer stats stat files) so the event loop never blocks;
        it stops when the last client leaves.
        """
        from ulpf.soar.service import new_since
        tenant = getattr(soar, "tenant", "default")
        while True:
            await asyncio.sleep(1.0)
            with hub._lock:
                if not hub.clients:
                    bcast["task"] = None
                    return
            point = await asyncio.to_thread(tele.sample)
            hub.publish("metrics", point)
            corr = getattr(getattr(rt, "correlator", None), "correlator", None) if rt is not None else None
            dets = getattr(corr, "detections", None)
            if dets:
                new, bcast["last_det"] = new_since(dets, bcast["last_det"])
                for d in new[-50:]:          # a burst is summarised by its newest 50
                    dd = d.to_dict() if hasattr(d, "to_dict") else dict(d)
                    hub.publish("detection", {**dd, "tenant": tenant})


def _recent_detections(rt, n: int) -> list[dict]:
    corr = getattr(getattr(rt, "correlator", None), "correlator", None) if rt is not None else None
    dets = list(getattr(corr, "detections", []) or [])[-n:]
    return [d.to_dict() if hasattr(d, "to_dict") else dict(d) for d in reversed(dets)]
