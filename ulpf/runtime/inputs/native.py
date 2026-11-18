"""
Network inputs on the compiled core's Tokio runtime (``ulpf_core.NativeListener``).

The core frames and decodes (syslog UDP / TCP / TLS, NetFlow / IPFIX, SNMP
traps, OTLP over gRPC) with the same records as the Python inputs
(``tests/test_native_listeners.py``); this module hands its batches to
``Input.accept``, which rate-limits and journals them as for every input.
Flow control: a full hand-off queue stops TCP / TLS / gRPC reads in the core,
and UDP datagrams are counted as dropped.

``engine: auto`` (default) picks the core when it is built; ``python`` keeps
the Python input; ``native`` requires the core.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import threading

from ulpf.runtime.inputs.base import Input

logger = logging.getLogger(__name__)


def available() -> bool:
    try:
        from ulpf import ulpf_core
    except ImportError:
        return False
    return hasattr(ulpf_core, "NativeListener")


class NativeListenerInput(Input):
    kind = ""
    block = False         # UDP inputs cannot wait for rate-limit tokens

    def listener_config(self) -> dict:
        o = self.opts
        return {"kind": self.kind, "host": o.get("host", "0.0.0.0"), "port": o.get("port", 0),
                "allow_sources": o.get("allow_sources") or [], "threads": o.get("threads", 2)}

    def run(self, stop: threading.Event) -> None:
        from ulpf import ulpf_core
        lst = ulpf_core.NativeListener(json.dumps(self.listener_config()))
        self.listener = lst
        self.bound_port = lst.bound_port
        self.on_bound()
        logger.info(f"input {self.name}: native {self.kind} listener on {self.opts.get('host')}:{self.bound_port}")
        try:
            while not stop.is_set():
                b = lst.next_batch(200)
                if b is not None:
                    self._accept(b)
        finally:
            lst.stop()
            for b in lst.drain():
                self._accept(b)

    def on_bound(self) -> None:
        pass

    def _accept(self, batch) -> None:
        input_name, source, records, ts = batch
        self.accept(source, records, ts, block=self.block, input_name=input_name)

    def describe(self) -> dict:
        d = {**super().describe(), "engine": "native", "bound_port": getattr(self, "bound_port", None)}
        lst = getattr(self, "listener", None)
        if lst is not None:
            d["listener"] = lst.stats()
        return d


class NativeSyslogInput(NativeListenerInput):
    kind = "syslog"

    @property
    def block(self) -> bool:
        return self.opts.get("protocol", "tcp") != "udp"

    def listener_config(self) -> dict:
        o = self.opts
        cfg = {**super().listener_config(), "protocol": o.get("protocol", "tcp"), "framing": o.get("framing", "auto"),
               "telemetry": o.get("telemetry", "none")}
        if o.get("protocol") == "tls":
            cfg["tls"] = {k: v for k, v in (o.get("tls") or {}).items()
                          if k in ("cert", "key", "client_ca", "sni_certs", "sni_routes")}
        return cfg


class NativeNetflowInput(NativeListenerInput):
    kind = "netflow"

    def listener_config(self) -> dict:
        return {**super().listener_config(),
                "state_path": os.path.join(self.ctx.data_dir, f"netflow_templates_{self.name}.json"),
                "ipv6_mapped_dotted": sys.version_info >= (3, 13)}


class NativeSnmpTrapInput(NativeListenerInput):
    kind = "snmp"

    def listener_config(self) -> dict:
        o = self.opts
        users = []
        for u in o.get("v3_users") or []:
            e = {"name": u["name"], "auth_protocol": u.get("auth_protocol", "sha"),
                 "priv_protocol": u.get("priv_protocol", "none")}
            if e["auth_protocol"] != "none":
                e["auth_password"] = os.environ[u["auth_key_env"]]
            if e["priv_protocol"] != "none":
                e["priv_password"] = os.environ[u["priv_key_env"]]
            users.append(e)
        return {**super().listener_config(), "communities": o.get("communities") or [], "v3_users": users}

    def on_bound(self) -> None:
        from ulpf.runtime import egress
        guard = egress.current()
        if guard is not None:
            guard.listener_ports.add(self.bound_port)   # inform acknowledgements are replies, not egress

    def describe(self) -> dict:
        d = super().describe()
        d["auth_failures"] = (d.get("listener") or {}).get("auth_failures", 0)
        return d


class OtlpGrpcInput(NativeListenerInput):
    """OTLP logs over gRPC (port 4317): LogsService/Export, gzip accepted, optional API key
    (``authorization: Bearer``) and TLS (client certificates with ``tls.client_ca``)."""
    kind = "otlp_grpc"
    block = True

    def listener_config(self) -> dict:
        o = self.opts
        cfg = {**super().listener_config(), "max_body_mb": o.get("max_body_mb", 16)}
        if o.get("api_key_env"):
            cfg["api_key"] = os.environ[o["api_key_env"]]
        if (o.get("tls") or {}).get("cert"):
            cfg["tls"] = {k: v for k, v in o["tls"].items() if k in ("cert", "key", "client_ca")}
        return cfg


NATIVE = {"syslog": NativeSyslogInput, "netflow": NativeNetflowInput, "snmp_trap": NativeSnmpTrapInput}


def native_class(options: dict):
    """The native input class for these options, or None (Python input)."""
    engine = options.get("engine", "auto")
    cls = NATIVE.get(options.get("type"))
    if cls is None or engine == "python":
        return None
    if available():
        return cls
    if engine == "native":
        raise RuntimeError(f"input {options.get('name')}: engine native needs ulpf_core (scripts/build_native)")
    return None
