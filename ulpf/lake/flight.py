"""
Arrow Flight endpoint of a lakehouse output (gRPC; TLS and mutual TLS optional).

``do_get`` takes a JSON ticket ``{"sql", "tenant", "start", "end", "eq", "max_rows"}`` and
streams the federated result (hot + cold, see ``query.py``). ``list_flights`` lists the cold
partitions. Every call needs ``authorization: Bearer <token>`` (token from ``token_env``,
compared in constant time). Binds 127.0.0.1 unless configured otherwise.
"""
from __future__ import annotations

import datetime as _dt
import hmac
import json
import threading

import pyarrow as pa
import pyarrow.flight as fl

from ulpf.runtime.sinks.base import env_secret


class _Auth(fl.ServerMiddlewareFactory):
    def __init__(self, token: str):
        super().__init__()
        self.token = token.encode()

    def start_call(self, info, headers):
        got = (headers.get("authorization") or [""])[0]
        if isinstance(got, bytes):
            got = got.decode("latin-1")
        given = got[7:].encode() if got.lower().startswith("bearer ") else b""
        if not hmac.compare_digest(given, self.token):
            raise fl.FlightUnauthenticatedError("invalid or missing bearer token")
        return None


def _ts(v):
    return None if not v else _dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))


class LakeFlightServer(fl.FlightServerBase):
    def __init__(self, service, location, token: str, tls=None, verify_client=False, root_certificates=None):
        super().__init__(location, tls_certificates=tls, verify_client=verify_client,
                         root_certificates=root_certificates, middleware={"auth": _Auth(token)})
        self.service = service

    def list_flights(self, context, criteria):
        snap = self.service.table.snapshot()
        parts = {}
        for a in snap.files.values():
            pv = a["partitionValues"]
            k = (pv["tenant_id"], pv["date"], pv["hour"])
            n = json.loads(a["stats"])["numRecords"]
            parts[k] = parts.get(k, 0) + n
        for (t, d, h), n in sorted(parts.items()):
            ticket = json.dumps({"tenant": t, "start": f"{d}T{h}:00:00+00:00", "end": f"{d}T{h}:59:59.999999+00:00"})
            yield fl.FlightInfo(pa.schema([]), fl.FlightDescriptor.for_path(t, d, h),
                                [fl.FlightEndpoint(ticket.encode(), [])], n, -1)

    def do_get(self, context, ticket):
        try:
            req = json.loads(ticket.ticket)
            table, _stats = self.service.query.run(req.get("sql") or "SELECT * FROM events", req.get("tenant"),
                                                   _ts(req.get("start")), _ts(req.get("end")), req.get("eq") or {},
                                                   int(req.get("max_rows") or 100_000))
        except (ValueError, KeyError, TypeError) as e:
            raise fl.FlightServerError(f"bad ticket: {e}")
        return fl.RecordBatchStream(table)


def start_flight(service, opts: dict) -> LakeFlightServer:
    host, port = opts.get("host", "127.0.0.1"), int(opts.get("port", 8815))
    token = env_secret(opts.get("token_env"), "Flight bearer token")
    if not token:
        raise RuntimeError("lakehouse flight: token_env is required")
    tls = opts.get("tls") or {}
    certs, scheme, root = None, "grpc+tcp", None
    if tls.get("cert"):
        with open(tls["cert"], "rb") as c, open(tls["key"], "rb") as k:
            certs, scheme = [(c.read(), k.read())], "grpc+tls"
        if tls.get("client_ca"):
            with open(tls["client_ca"], "rb") as f:
                root = f.read()
    server = LakeFlightServer(service, f"{scheme}://{host}:{port}", token, certs, bool(root), root)
    threading.Thread(target=server.serve, name=f"lake-{service.name}-flight", daemon=True).start()
    return server
