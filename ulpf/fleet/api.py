"""REST endpoints of the fleet control plane (agents authenticate with mTLS + agent token)."""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Header
from fastapi.responses import JSONResponse

from ulpf.api.rbac import Principal, need
from ulpf.fleet.control import FleetControl


def build_router(fc: FleetControl, runtime=None) -> APIRouter:
    r = APIRouter(prefix="/api/v1/fleet", tags=["Fleet"])

    def err(e: Exception):
        return JSONResponse({"error": str(e)}, 403 if isinstance(e, PermissionError) else 400)

    @r.post("/enroll")
    def enroll(body: dict = Body(...)):
        try:
            return fc.enroll(str(body.get("token", "")), str(body.get("agent_id", "")), body.get("info") or {},
                             body.get("csr"))
        except (PermissionError, ValueError) as e:
            return err(e)

    @r.post("/heartbeat")
    def heartbeat(body: dict = Body(default={}), x_agent_id: str = Header(...), x_agent_token: str = Header(...)):
        _health(fc, runtime)
        try:
            return fc.heartbeat(x_agent_id, x_agent_token, body)
        except PermissionError as e:
            return err(e)

    @r.get("/config")
    def config(x_agent_id: str = Header(...), x_agent_token: str = Header(...)):
        try:
            return fc.config_bundle(x_agent_id, x_agent_token)
        except PermissionError as e:
            return err(e)

    @r.post("/rotate")
    def rotate(body: dict = Body(default={}), x_agent_id: str = Header(...), x_agent_token: str = Header(...)):
        try:
            return fc.rotate_certificate(x_agent_id, x_agent_token, body.get("csr"))
        except (PermissionError, ValueError) as e:
            return err(e)

    @r.post("/tokens")
    def token(body: dict = Body(...), p: Principal = Depends(need("fleet:manage"))):
        return {"token": fc.create_enrollment_token(str(body.get("group", "default")),
                                                    float(body.get("ttl", 86400))),
                "ca": fc.ca_pem(), "config_signing_key": fc.public_key().hex()}

    @r.post("/configs/{group}")
    def publish(group: str, body: dict = Body(...), p: Principal = Depends(need("fleet:manage"))):
        return fc.publish_config(group, body, p.name)

    @r.get("/agents")
    def agents(group: str | None = None, p: Principal = Depends(need("metrics:read"))):
        return {"agents": fc.agents(group)}

    @r.post("/agents/{agent_id}/revoke")
    def revoke(agent_id: str, p: Principal = Depends(need("fleet:manage"))):
        fc.revoke(agent_id)
        return {"revoked": agent_id}

    @r.get("/summary")
    def summary(p: Principal = Depends(need("metrics:read"))):
        return fc.summary()

    @r.get("/route")
    def route(key: str, p: Principal = Depends(need("metrics:read"))):
        from ulpf.runtime.mesh import Mesh
        nodes = runtime.cluster.alive_nodes() if runtime is not None and getattr(runtime, "cluster", None) \
            else ["local"]
        m = Mesh(nodes)
        return {"key": key, "owner": m.route(key), "failover": m.ranked(key, 3), "nodes": nodes}

    return r


def _health(fc: FleetControl, rt) -> None:
    """Ingest health for backpressure: the fullest sink buffer of this node."""
    if rt is None:
        return
    try:
        fills = [b.stats().get("fill_ratio", 0.0) for b in getattr(rt, "buffers", {}).values()]
        fc.set_cluster_health(max(fills) if fills else 0.0)
    except Exception:
        pass
