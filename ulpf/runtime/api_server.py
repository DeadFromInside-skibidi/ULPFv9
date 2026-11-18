"""
REST API inside the runtime (``ulpf run``): the existing ULPF API plus
runtime endpoints, sharing the runtime's store and journal.

    POST /api/v1/ingest/stream/{source}   http input (write)
    POST /v1/logs                         otlp input (write)
    GET  /api/v1/runtime/status           (read)
    GET  /api/v1/events/{id}/raw          original bytes, verified against SHA-256 (read)
    GET  /api/v1/evidence/seals           (read)
    GET  /api/v1/evidence/pubkey          identity public key that anchors seal signatures (read)
    GET  /api/v1/evidence/proof/{seq}     Merkle inclusion proof (read)
    POST /api/v1/evidence/verify          recompute seals from the journal (read)
    GET  /api/v1/runtime/parsers          learned parsers and their states (read)
    POST /api/v1/runtime/parsers/{id}/approve|reject   (admin)
    GET  /api/v1/dlq                      dead-lettered events (read)
    GET  /api/v1/runtime/detections       recent Sigma detections (read)
    GET  /api/v1/runtime/sigma            loaded Sigma rules, load errors, counters (read)
    POST /api/v1/compliance/dpdp/scan     personal data in a text (read)
    POST /api/v1/compliance/dpdp/erase    right to erasure; Certificate of Erasure (admin)
    GET  /api/v1/compliance/dpdp/erasures issued certificates (read)
    POST /api/v1/compliance/dpdp/breach-pack   CERT-In / DPB breach notification pack (admin)
    POST /api/v1/compliance/cbam/export-pack   CBAM data pack for an installation and year (admin)
    POST /api/v1/runtime/reload           re-read the config file (admin)
    POST /api/v1/query                    KQL / SPL2 / HQL over the store or a lakehouse (read)
    POST /api/v1/query/validate           syntax check (line, column) and the compiled SQL (read)
    GET  /api/v1/query/governor           running / waiting queries per analyst (read)
    POST /api/v1/live                     open a live tail (read); GET /api/v1/live lists them
    GET  /api/v1/live/{id}                next matches (long poll: ?wait=seconds) (read)
    GET  /api/v1/live/{id}/stream         matches as server-sent events (read)
    DELETE /api/v1/live/{id}              close a live tail (read)
"""
from __future__ import annotations

import json
import logging
import os
import ssl
import threading
import time

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response

from ulpf.api.auth import ROLES, auth_configured, identity, require, role_of

logger = logging.getLogger(__name__)


def build_router(rt) -> APIRouter:
    r = APIRouter()

    def _input(kind: str):
        for inp in rt.inputs.values():
            if inp.opts.get("type") == kind:
                return inp
        return None

    def _authorize_ingest(request: Request, inp) -> JSONResponse | None:
        key = request.headers.get("x-api-key")
        own = inp.opts.get("api_key_env")
        if own and key and key == os.environ.get(own):
            return None
        if own or auth_configured():
            role = role_of(key)
            if role is None or ROLES[role] < ROLES["write"]:
                return JSONResponse({"error": "invalid or missing X-API-Key"}, 401)
        return None

    def _busy() -> JSONResponse | None:
        if rt.saturated():
            return JSONResponse({"error": "pipeline saturated, retry later"}, 429, headers={"Retry-After": "1"})
        return None

    async def _body(request: Request, inp) -> bytes | JSONResponse:
        from ulpf.runtime.inputs.http import decode_body
        limit = int(float(inp.opts.get("max_body_mb", 16)) * 2**20)
        body = await request.body()
        if len(body) > limit:
            return JSONResponse({"error": f"body exceeds {limit} bytes"}, 413)
        try:
            body = decode_body(body, request.headers.get("content-encoding"))
        except OSError:
            return JSONResponse({"error": "invalid gzip body"}, 400)
        if len(body) > limit * 10:
            return JSONResponse({"error": "decompressed body too large"}, 413)
        return body

    @r.post("/api/v1/ingest/stream/{source}", tags=["Runtime ingest"])
    async def ingest_stream(source: str, request: Request):
        from starlette.concurrency import run_in_threadpool
        from ulpf.runtime.inputs.http import split_records
        inp = _input("http")
        if inp is None:
            return JSONResponse({"error": "no http input is configured"}, 404)
        denied = _authorize_ingest(request, inp)
        if denied:
            return denied
        allowed = inp.opts.get("sources") or []
        if allowed and source not in allowed:
            return JSONResponse({"error": f"source {source!r} is not allowed"}, 403)
        busy = _busy()
        if busy:
            return busy
        body = await _body(request, inp)
        if isinstance(body, JSONResponse):
            return body
        records = split_records(body, request.headers.get("content-type"))
        n = await run_in_threadpool(inp.accept, source, records, None, True)
        return {"accepted": n, "records": len(records)}

    @r.post("/v1/logs", tags=["Runtime ingest"])
    async def otlp_logs(request: Request):
        from starlette.concurrency import run_in_threadpool
        from ulpf.runtime.inputs.http import otlp_json_records, otlp_protobuf_records, otlp_to_records
        inp = _input("otlp")
        if inp is None:
            return JSONResponse({"error": "no otlp input is configured"}, 404)
        denied = _authorize_ingest(request, inp)
        if denied:
            return denied
        busy = _busy()
        if busy:
            return busy
        body = await _body(request, inp)
        if isinstance(body, JSONResponse):
            return body
        ctype = (request.headers.get("content-type") or "").lower()
        try:
            pairs = otlp_json_records(json.loads(body)) if "json" in ctype else otlp_protobuf_records(body)
        except (ValueError, IndexError) as e:
            return JSONResponse({"error": f"invalid OTLP payload: {e}"}, 400)
        client = request.client.host if request.client else "otlp"
        total = 0
        for source, recs in otlp_to_records(pairs, client).items():
            total += await run_in_threadpool(inp.accept, source, recs, None, True)
        if "json" in ctype:
            return {"partialSuccess": {}}
        return Response(b"", media_type="application/x-protobuf")   # empty ExportLogsServiceResponse

    @r.get("/api/v1/runtime/status", tags=["Runtime"], dependencies=[Depends(require("read"))])
    def status():
        return {**rt.stats(), "config": rt.report}

    _dp = ((rt.cfg.data.get("compliance") or {}).get("dpdp") or {})
    # the journal keeps the bytes received; when the store holds redacted / tokenised
    # personal data, the original bytes are an admin-only view
    _raw_role = "admin" if _dp.get("enabled") and _dp.get("mode") in ("redact", "tokenize") else "read"

    @r.get("/api/v1/events/{event_id}/raw", tags=["Runtime"], dependencies=[Depends(require(_raw_role))])
    def raw(event_id: str, format: str = "bytes"):
        ev = rt.database.get_event(event_id) if rt.database is not None else None
        if not ev:
            return JSONResponse({"error": "event not found"}, 404)
        seq = (ev.get("evidence") or {}).get("journal_seq")
        if seq is None:
            return JSONResponse({"error": "event was not ingested through the journal"}, 404)
        rec = rt.journal.read(int(seq))
        if rec is None:
            return JSONResponse({"error": f"journal record {seq} expired (retention)"}, 410)
        if format == "json":
            return {"event_id": event_id, "seq": rec.seq, "received_at": rec.recv_ts, "source": rec.source,
                    "input": rec.input, "sha256": rec.sha256_hex,
                    "matches_event": rec.sha256_hex == (ev.get("evidence") or {}).get("raw_hash"),
                    "raw": rec.raw.decode("utf-8", "replace")}
        return Response(rec.raw, media_type="application/octet-stream",
                        headers={"X-ULPF-Seq": str(rec.seq), "X-ULPF-SHA256": rec.sha256_hex})

    @r.get("/api/v1/evidence/seals", tags=["Evidence"], dependencies=[Depends(require("read"))])
    def seals(limit: int = 50):
        from ulpf.runtime.evidence import load_seals
        d = os.path.join(rt.data_dir, "evidence", "seals")
        return {"seals": load_seals(d)[-limit:] if os.path.isdir(d) else []}

    @r.get("/api/v1/evidence/proof/{seq}", tags=["Evidence"], dependencies=[Depends(require("read"))])
    def proof(seq: int):
        from ulpf.runtime.evidence import inclusion_proof, leaf, load_seals
        d = os.path.join(rt.data_dir, "evidence", "seals")
        seal = next((s for s in load_seals(d) if s["first_seq"] <= seq <= s["last_seq"]), None) \
            if os.path.isdir(d) else None
        if seal is None:
            return JSONResponse({"error": f"record {seq} is not sealed yet"}, 404)
        leaves = [leaf(q, rt.journal.read(q).sha256) for q in range(seal["first_seq"], seal["last_seq"] + 1)]
        i = seq - seal["first_seq"]
        return {"seq": seq, "leaf": leaves[i].hex(), "merkle_root": seal["merkle_root"],
                "seal_hash": seal["seal_hash"], "proof": inclusion_proof(leaves, i)}

    @r.get("/api/v1/evidence/pubkey", tags=["Evidence"], dependencies=[Depends(require("read"))])
    def pubkey():
        from ulpf.runtime.keys import fingerprint, public_pem
        if rt.sealer is None:
            return JSONResponse({"error": "evidence sealing is not enabled"}, 404)
        ident = rt.sealer.identity()
        return {"algorithm": "ed25519", "fingerprint": fingerprint(rt.sealer.identity_pub),
                "public_key_pem": public_pem(ident).decode()}

    @r.post("/api/v1/evidence/verify", tags=["Evidence"], dependencies=[Depends(require("read"))])
    def verify(from_seq: int | None = None, to_seq: int | None = None, check_store: bool = True):
        from ulpf.runtime.evidence import verify_seals
        d = os.path.join(rt.data_dir, "evidence", "seals")
        if rt.sealer is None or not os.path.isdir(d):
            return JSONResponse({"error": "evidence sealing is not enabled"}, 404)
        # On the host only keys of uncommitted epochs remain (forward security): older row MACs
        # are counted in row_macs_unchecked; an off-box verifier checks them with K_0.
        res = verify_seals(d, rt.journal, rt.sealer.key, rt.database if check_store else None, from_seq, to_seq,
                           pubkey=rt.sealer.identity_pub)
        if rt.audit:
            rt.audit.record("evidence.verify", {"valid": res["valid"], "seals": res["seals"]}, actor="api")
        return res

    @r.get("/api/v1/runtime/parsers", tags=["Runtime"], dependencies=[Depends(require("read"))])
    def parsers():
        eng = rt.apg_engine
        return {"parsers": [{"parser_id": s.parser_id, "state": s.state, "family": s.source_family,
                             "template": s.template, "accuracy": s.metadata.get("validation_accuracy"),
                             "learned_from": s.metadata.get("learned_from")}
                            for s in eng.registry.list_parsers()]}

    @r.post("/api/v1/runtime/parsers/{parser_id}/{decision}", tags=["Runtime"],
            dependencies=[Depends(require("admin"))])
    def decide(parser_id: str, decision: str, request: Request):
        if decision not in ("approve", "reject"):
            return JSONResponse({"error": "decision must be approve or reject"}, 400)
        try:
            spec = rt.decide_parser(parser_id, decision, "api")
        except (KeyError, ValueError) as e:
            return JSONResponse({"error": str(e)}, 404 if isinstance(e, KeyError) else 409)
        if rt.audit:
            rt.audit.record(f"parser.{decision}", {"parser_id": parser_id, "state": spec.state},
                            actor=f"api:{request.client.host if request.client else '?'}")
        return {"parser_id": parser_id, "state": spec.state}

    @r.get("/api/v1/dlq", tags=["Runtime"], dependencies=[Depends(require("read"))])
    def dlq(sink: str | None = None, limit: int = 100):
        return {"stats": rt.dlq.stats(), "events": rt.dlq.read(sink, limit)}

    def _sigma():
        c = rt.correlator
        return c.correlator.sigma if c is not None else None

    @r.get("/api/v1/runtime/detections", tags=["Detections"], dependencies=[Depends(require("read"))])
    def detections(limit: int = 100, rule_id: str | None = None):
        eng = _sigma()
        if eng is None:
            return JSONResponse({"error": "Sigma detection is not enabled (analytics.sigma / correlation)"}, 404)
        dets = [d for d in rt.correlator.correlator.detections if rule_id is None or d.rule.id == rule_id]
        dets = dets[-max(1, min(limit, 10_000)):]
        return {"detections": [d.to_dict() for d in reversed(dets)], "stats": eng.stats()}

    @r.get("/api/v1/runtime/sigma", tags=["Detections"], dependencies=[Depends(require("read"))])
    def sigma_rules():
        eng = _sigma()
        if eng is None:
            return JSONResponse({"error": "Sigma detection is not enabled (analytics.sigma / correlation)"}, 404)
        return {"rules": [r.to_dict() for r in eng.rules], "errors": list(eng.errors), "stats": eng.stats()}

    @r.post("/api/v1/compliance/dpdp/scan", tags=["Compliance"], dependencies=[Depends(require("read"))])
    def dpdp_scan(body: dict):
        from ulpf.compliance.pii import PIIScanner
        s = PIIScanner(body.get("types") or None)
        found = s.scan(str(body.get("text") or ""))
        return {"matches": [{"type": m.type, "start": m.start, "end": m.end} for m in found],
                "redacted": s.redact(str(body.get("text") or ""))}

    @r.post("/api/v1/compliance/dpdp/erase", tags=["Compliance"], dependencies=[Depends(require("admin"))])
    def dpdp_erase(body: dict, request: Request):
        from ulpf.compliance.dpdp import erase_subject
        ids = [str(x) for x in body.get("subject_ids") or [] if str(x).strip()]
        if not ids:
            return JSONResponse({"error": "subject_ids is required"}, 400)
        if rt.database is None:
            return JSONResponse({"error": "no event store"}, 404)
        outputs = [o["name"] for o in rt.cfg.outputs() if o["type"] != "duckdb"]
        res = erase_subject(rt.data_dir, ids, db=rt.database, journal=rt.journal, node=rt.node,
                            reason=str(body.get("reason") or ""), requested_by=str(body.get("requested_by") or ""),
                            outputs=outputs, scan_whole_journal=bool(body.get("scan_journal")))
        if rt.audit:
            rt.audit.record("dpdp.erase", {"certificate_id": res["certificate_id"], **res["summary"]},
                            actor=f"api:{request.client.host if request.client else '?'}")
        with open(res["receipt"], "r", encoding="utf-8") as f:
            receipt = json.load(f)
        os.remove(res["receipt"])            # the salts go to the requester only
        return {**res, "receipt": receipt}

    @r.get("/api/v1/compliance/dpdp/erasures", tags=["Compliance"], dependencies=[Depends(require("read"))])
    def dpdp_erasures():
        d = os.path.join(rt.data_dir, "compliance", "erasures")
        out = []
        for n in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            if n.endswith(".json") and not n.endswith(".receipt.json"):
                with open(os.path.join(d, n), "r", encoding="utf-8") as f:
                    c = json.load(f)
                out.append({"certificate_id": c["certificate_id"], "issued_at": c["issued_at"], **c["summary"]})
        return {"certificates": out}

    @r.post("/api/v1/compliance/dpdp/breach-pack", tags=["Compliance"], dependencies=[Depends(require("admin"))])
    def dpdp_breach(body: dict):
        from ulpf.compliance.dpdp import breach_pack
        out = os.path.join(rt.data_dir, "compliance", "packs", f"dpdp_breach_{time.strftime('%Y%m%dT%H%M%S')}.zip")
        rep = breach_pack(rt.data_dir, out, db=rt.database, journal=rt.journal, since=body.get("since"),
                          until=body.get("until"), min_risk=float(body.get("min_risk", 6.0)),
                          organisation=str(body.get("organisation") or ""), contact=str(body.get("contact") or ""),
                          node=rt.node)
        return {"pack": out, "summary": rep["summary"], "deadlines": rep["deadlines"]}

    @r.post("/api/v1/compliance/cbam/export-pack", tags=["Compliance"], dependencies=[Depends(require("admin"))])
    def cbam_pack(body: dict):
        from ulpf.compliance.cbam import export_pack
        if not body.get("installation") or not body.get("period"):
            return JSONResponse({"error": "installation and period are required"}, 400)
        try:
            res = export_pack(os.path.join(rt.data_dir, "compliance", "packs"), str(body["installation"]),
                              str(body["period"]), data_dir=rt.data_dir, db=rt.database, journal=rt.journal,
                              price_eur=body.get("price_eur"))
        except ValueError as e:
            return JSONResponse({"error": str(e)}, 404)
        return {"pack": res["path"], "records": res["records"], "calculation": res["calculation"]}

    @r.post("/api/v1/runtime/reload", tags=["Runtime"], dependencies=[Depends(require("admin"))])
    def reload():
        return rt.reload()

    @r.get("/api/v1/cluster/status", tags=["Cluster"], dependencies=[Depends(require("read"))])
    def cluster_status():
        if rt.cluster is None:
            return JSONResponse({"error": "cluster mode is not enabled"}, 404)
        from ulpf.runtime.cluster import status as cluster_status_of
        return {"this_node": rt.node, **cluster_status_of(rt.cfg.data)}

    @r.get("/api/v1/cluster/events", tags=["Cluster"], dependencies=[Depends(require("read"))])
    async def cluster_events(request: Request, limit: int = 100, category: str | None = None,
                       source_ip: str | None = None, q: str | None = None):
        """Query every live node's store and merge the results (newest event time first)."""
        if rt.cluster is None:
            return JSONResponse({"error": "cluster mode is not enabled"}, 404)
        from starlette.concurrency import run_in_threadpool
        from ulpf.runtime.cluster import fan_out_events, status as cluster_status_of
        nodes = cluster_status_of(rt.cfg.data)["nodes"]
        return await run_in_threadpool(fan_out_events, nodes,
                                 {"category": category, "source_ip": source_ip, "q": q},
                                 request.headers.get("x-api-key"), max(1, min(limit, 1000)))

    # ---- risk-based alerting and YARA-L (host correlator)
    def _risk():
        c = rt.correlator
        return c.risk if c is not None else None

    @r.get("/api/v1/risk/entities", tags=["Detections"], dependencies=[Depends(require("read"))])
    def risk_entities(entity_type: str | None = None, min_score: float = 0.0, limit: int = 100):
        rk = _risk()
        if rk is None:
            return JSONResponse({"error": "risk-based alerting is not enabled (analytics.risk)"}, 404)
        return {"entities": rk.top(entity_type, min_score, max(1, min(limit, 10_000))), "stats": rk.stats}

    @r.get("/api/v1/risk/entities/{entity_type}/{value}", tags=["Detections"], dependencies=[Depends(require("read"))])
    def risk_entity(entity_type: str, value: str):
        rk = _risk()
        e = rk.entity(entity_type, value) if rk is not None else None
        if e is None:
            return JSONResponse({"error": "no risk recorded for this entity"}, 404)
        return e

    @r.get("/api/v1/risk/notables", tags=["Detections"], dependencies=[Depends(require("read"))])
    def risk_notables(limit: int = 100):
        rk = _risk()
        if rk is None:
            return JSONResponse({"error": "risk-based alerting is not enabled (analytics.risk)"}, 404)
        return {"notables": list(rk.notables)[-max(1, min(limit, 1000)):][::-1]}

    @r.get("/api/v1/runtime/yaral", tags=["Detections"], dependencies=[Depends(require("read"))])
    def yaral_status(limit: int = 100):
        c = rt.correlator
        if c is None or c.yaral is None:
            return JSONResponse({"error": "no YARA-L rules loaded (analytics.yaral.rules)"}, 404)
        return {"rules": [{"name": x.name, "meta": x.meta, "match": x.match, "window_s": x.window}
                          for x in c.yaral.rules], "detections": c.yaral.detections,
                "recent": [d.to_dict() for d in list(c.yaral_detections)[-max(1, min(limit, 1000)):]]}

    # ---- threat intelligence platform
    def _no_tip():
        return JSONResponse({"error": "threat intelligence is not enabled (intel.enabled)"}, 404)

    @r.get("/api/v1/intel/stats", tags=["Threat intelligence"], dependencies=[Depends(require("read"))])
    def intel_stats():
        t = rt.tip
        return t.stats() if t is not None else _no_tip()

    @r.get("/api/v1/intel/lookup", tags=["Threat intelligence"], dependencies=[Depends(require("read"))])
    def intel_lookup(value: str):
        t = rt.tip
        if t is None:
            return _no_tip()
        if len(value) > 2048:
            return JSONResponse({"error": "value too long"}, 400)
        return {"value": value, "indicators": t.store.lookup(value)}

    @r.post("/api/v1/intel/stix", tags=["Threat intelligence"], dependencies=[Depends(require("admin"))])
    async def intel_import_stix(request: Request, name: str = "api"):
        """Import a STIX 2.1 bundle (request body, at most 64 MiB) and rebuild the match set."""
        import asyncio
        import json as _json
        from ulpf.intelligence.tip.stix import parse_bundle
        t = rt.tip
        if t is None:
            return _no_tip()
        body = await request.body()
        if len(body) > 64 << 20:
            return JSONResponse({"error": "bundle larger than 64 MiB"}, 413)
        try:
            inds, stats = parse_bundle(_json.loads(body), f"stix:{name[:64]}")
        except (ValueError, RecursionError) as e:          # StixError is a ValueError
            return JSONResponse({"error": f"not a STIX 2.1 bundle: {e}"}, 400)
        revoked = stats.pop("revoked", [])

        def apply():
            res = t.store.upsert(inds, f"stix:{name[:64]}")
            res["revoked"] = t.store.revoke(stix_ids=revoked) if revoked else 0
            res["snapshot"] = t.build()
            return res
        return {**stats, **await asyncio.to_thread(apply)}

    @r.post("/api/v1/intel/sync", tags=["Threat intelligence"], dependencies=[Depends(require("admin"))])
    def intel_sync(feed: str | None = None):
        t = rt.tip
        if t is None:
            return _no_tip()
        res = t.sync(feed, force=True)
        res["snapshot"] = t.build()
        return res

    @r.post("/api/v1/intel/sight", tags=["Threat intelligence"], dependencies=[Depends(require("admin"))])
    def intel_sight(value: str, kind: str = "auto"):
        t = rt.tip
        if t is None:
            return _no_tip()
        return {"updated": t.store.sight(kind, value[:2048])}

    # ---- UEBA: actors, timelines, assets, peer groups, anomalies
    def _ueba():
        c = rt.correlator
        return c.ueba if c is not None else None

    def _no_ueba():
        return JSONResponse({"error": "UEBA is not enabled (analytics.ueba)"}, 404)

    @r.get("/api/v1/ueba/actors/{identifier}", tags=["UEBA"], dependencies=[Depends(require("read"))])
    def ueba_actor(identifier: str):
        u = _ueba()
        if u is None:
            return _no_ueba()
        v = u.actor_view(identifier)
        return v if v is not None else JSONResponse({"error": "unknown identity"}, 404)

    @r.get("/api/v1/ueba/timeline/{identifier}", tags=["UEBA"], dependencies=[Depends(require("read"))])
    def ueba_timeline(identifier: str, limit: int = 500):
        u = _ueba()
        if u is None:
            return _no_ueba()
        v = u.timeline(identifier, max(1, min(limit, 5000)))
        return v if v is not None else JSONResponse({"error": "unknown identity"}, 404)

    @r.get("/api/v1/ueba/assets/{ip}", tags=["UEBA"], dependencies=[Depends(require("read"))])
    def ueba_asset(ip: str, at: str | None = None):
        u = _ueba()
        if u is None:
            return _no_ueba()
        from ulpf.query.sqlgen import parse_datetime
        t = parse_datetime(at) if at else None
        return u.asset_view(ip, t.timestamp() if t else None)

    @r.get("/api/v1/ueba/peer-groups", tags=["UEBA"], dependencies=[Depends(require("read"))])
    def ueba_peers():
        u = _ueba()
        return _no_ueba() if u is None else {"groups": u.peers.summary()}

    @r.get("/api/v1/ueba/anomalies", tags=["UEBA"], dependencies=[Depends(require("read"))])
    def ueba_anomalies(limit: int = 100, kind: str | None = None):
        u = _ueba()
        if u is None:
            return _no_ueba()
        rows = [a for a in u.anomalies if kind is None or a["kind"] == kind]
        return {"anomalies": rows[-max(1, min(limit, 5000)):][::-1], "stats": u.stats}

    # ---- security query languages and live tail (ulpf.query)
    from ulpf.query import QuerySyntaxError
    from ulpf.query.engine import QueryError
    from ulpf.query.live import LiveError

    def _qerr(e):
        if isinstance(e, QuerySyntaxError):
            return JSONResponse(e.to_dict(), 400)
        if isinstance(e, (QueryError, LiveError)):
            return JSONResponse({"error": str(e)}, e.status, headers={"Retry-After": "1"} if e.status == 429 else None)
        if isinstance(e, ValueError):
            return JSONResponse({"error": str(e)}, 400)
        raise e

    def _body_of(payload) -> tuple[str, str]:
        if not isinstance(payload, dict) or not isinstance(payload.get("query"), str):
            raise ValueError("body must be {\"dialect\": \"kql|spl|hql\", \"query\": \"...\"}")
        return str(payload.get("dialect") or "kql"), payload["query"]

    @r.post("/api/v1/query", tags=["Query"], dependencies=[Depends(require("read"))])
    def run_query(payload: dict, who: str = Depends(identity)):
        try:
            dialect, text = _body_of(payload)
            return rt.query_engine.run(dialect, text, source=str(payload.get("source") or "store"), user=who,
                                       start=payload.get("start"), end=payload.get("end"),
                                       max_rows=max(1, min(int(payload.get("max_rows") or 1000), 100_000)),
                                       timeout_s=float(payload.get("timeout_seconds") or 0) or None)
        except Exception as e:
            return _qerr(e)

    @r.post("/api/v1/query/validate", tags=["Query"], dependencies=[Depends(require("read"))])
    def validate_query(payload: dict):
        try:
            dialect, text = _body_of(payload)
            plan, sql = rt.query_engine.compile(dialect, text, str(payload.get("source") or "store"))
            return {"ok": True, "dialect": plan.dialect, "stages": [type(s).__name__ for s in plan.stages],
                    "live_capable": plan.row_level(), "sql": sql}
        except Exception as e:
            return _qerr(e)

    @r.get("/api/v1/query/governor", tags=["Query"], dependencies=[Depends(require("read"))])
    def governor():
        return rt.query_engine.gov.snapshot()

    @r.post("/api/v1/live", tags=["Query"], dependencies=[Depends(require("read"))], status_code=201)
    def open_live(payload: dict, who: str = Depends(identity)):
        try:
            dialect, text = _body_of(payload)
            return rt.live.open(who, dialect, text)
        except Exception as e:
            return _qerr(e)

    @r.get("/api/v1/live", tags=["Query"], dependencies=[Depends(require("read"))])
    def list_live(who: str = Depends(identity)):
        return {"tails": rt.live.list(who)}

    @r.get("/api/v1/live/{tid}", tags=["Query"], dependencies=[Depends(require("read"))])
    def poll_live(tid: str, max_rows: int = 1000, wait: float = 0.0, who: str = Depends(identity)):
        try:
            return rt.live.poll(tid, who, max(1, min(max_rows, 10_000)), wait)
        except Exception as e:
            return _qerr(e)

    @r.get("/api/v1/live/{tid}/stream", tags=["Query"], dependencies=[Depends(require("read"))])
    def stream_live(tid: str, who: str = Depends(identity)):
        from fastapi.responses import StreamingResponse
        try:
            rt.live.poll(tid, who, 0, 0)            # exists and belongs to the caller
        except Exception as e:
            return _qerr(e)

        def events():
            idle = 0
            while True:
                try:
                    r_ = rt.live.poll(tid, who, 500, 1.0)
                except LiveError:
                    yield "event: closed\ndata: {}\n\n"
                    return
                if r_["rows"] or r_["error"]:
                    yield f"data: {json.dumps(r_, default=str)}\n\n"
                    idle = 0
                else:
                    idle += 1
                    if idle >= 15:
                        yield ": keep-alive\n\n"
                        idle = 0
                if r_["error"]:
                    return
        return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})

    @r.delete("/api/v1/live/{tid}", tags=["Query"], dependencies=[Depends(require("read"))])
    def close_live(tid: str, who: str = Depends(identity)):
        try:
            rt.live.close(tid, who)
            return {"closed": tid}
        except Exception as e:
            return _qerr(e)

    return r


class ApiServer:
    def __init__(self, runtime):
        self.rt = runtime
        api = runtime.cfg["api"]
        self.host, self.port = api["host"], api["port"]
        self.tls = api.get("tls") or {}
        self.server = None
        self.thread = None

    @property
    def url(self) -> str:
        scheme = "https" if self.tls.get("cert") else "http"
        return f"{scheme}://{self.host}:{self.bound_port or self.port}"

    @property
    def bound_port(self) -> int | None:
        try:
            return self.server.servers[0].sockets[0].getsockname()[1]
        except (AttributeError, IndexError, TypeError):
            return None

    def start(self, timeout: float = 20.0) -> None:
        import uvicorn
        from ulpf.api import routes
        from ulpf.api.app import create_app
        if self.rt.cfg.get("api.keys_file"):
            os.environ["ULPF_API_KEYS_FILE"] = self.rt.cfg.get("api.keys_file")
        routes.attach_runtime(self.rt)
        app = create_app(console=False)
        app.include_router(build_router(self.rt))
        from ulpf.console.server import mount_console
        mount_console(app, self.rt)
        kw = {}
        if self.tls.get("cert"):
            kw.update(ssl_certfile=self.tls["cert"], ssl_keyfile=self.tls.get("key"))
            if self.tls.get("client_ca"):
                kw.update(ssl_ca_certs=self.tls["client_ca"], ssl_cert_reqs=ssl.CERT_REQUIRED)
        config = uvicorn.Config(app, host=self.host, port=self.port, log_level="warning", **kw)
        self.server = uvicorn.Server(config)
        self.server.install_signal_handlers = lambda: None   # the runtime owns signals
        self.thread = threading.Thread(target=self.server.run, name="ulpf-api", daemon=True)
        self.thread.start()
        deadline = time.monotonic() + timeout
        while not self.server.started:
            if not self.thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError(f"API server did not start on {self.host}:{self.port}")
            time.sleep(0.05)
        logger.info(f"API listening on {self.url}")

    def stop(self) -> None:
        from ulpf.api import routes
        if self.server is not None:
            self.server.should_exit = True
        if self.thread is not None:
            self.thread.join(10)
        routes.detach_runtime(self.rt)    # module state must not outlive this runtime
