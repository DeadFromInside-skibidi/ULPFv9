"""
Forwarder fleet agent (``ulpf fleet agent``): enrolls, heartbeats, applies signed configs, honours throttling.

The agent keeps its identity in ``<state_dir>``: client certificate + key (0600),
agent token, the pinned fleet CA and configuration-signing key. Every config
bundle is verified against the pinned key before it is written to
``<state_dir>/pipeline.yaml`` and the ``on_config`` callback (runtime reload) runs.
"""
from __future__ import annotations

import json
import logging
import os
import random
import ssl
import time
import urllib.request

from ulpf.fleet.control import verify_bundle

logger = logging.getLogger(__name__)


class FleetAgent:
    def __init__(self, server: str, state_dir: str, agent_id: str, enroll_token: str | None = None,
                 on_config=None, on_throttle=None, stats=None, insecure_bootstrap_ca: str | None = None):
        self.server = server.rstrip("/")
        self.dir = state_dir
        os.makedirs(state_dir, exist_ok=True)
        self.agent_id = agent_id
        self.enroll_token = enroll_token
        self.on_config = on_config or (lambda cfg: None)
        self.on_throttle = on_throttle or (lambda eps: None)
        self.stats = stats or (lambda: {})
        self.bootstrap_ca = insecure_bootstrap_ca
        self.state_path = os.path.join(state_dir, "agent.json")
        self.state = self._load()
        self.config_version = int(self.state.get("config_version", 0))
        self.throttle = None

    def _load(self) -> dict:
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        tmp = self.state_path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.state, f)
        os.replace(tmp, self.state_path)

    def _write_secret(self, name: str, data: str) -> str:
        p = os.path.join(self.dir, name)
        fd = os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(p + ".tmp", p)
        return p

    def _ctx(self) -> ssl.SSLContext:
        ca = os.path.join(self.dir, "ca.pem")
        ctx = ssl.create_default_context(cafile=ca if os.path.exists(ca) else self.bootstrap_ca)
        cert, key = os.path.join(self.dir, "agent.pem"), os.path.join(self.dir, "agent.key")
        if os.path.exists(cert) and os.path.exists(key):
            ctx.load_cert_chain(cert, key)
        return ctx

    def _call(self, method: str, path: str, body: dict | None = None, auth: bool = True) -> dict:
        headers = {"Content-Type": "application/json"}
        if auth:
            headers.update({"X-Agent-Id": self.agent_id, "X-Agent-Token": self.state["agent_token"]})
        req = urllib.request.Request(self.server + path, method=method, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
        ctx = self._ctx() if self.server.startswith("https") else None
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            return json.loads(r.read(4 * 2**20))

    def enroll(self) -> None:
        if self.state.get("agent_token"):
            return
        if not self.enroll_token:
            raise RuntimeError("not enrolled: an enrollment token is required (ulpf fleet token)")
        res = self._call("POST", "/api/v1/fleet/enroll", {"token": self.enroll_token, "agent_id": self.agent_id,
                                                          "info": {"pid": os.getpid()}}, auth=False)
        self._write_secret("agent.pem", res["certificate"])
        self._write_secret("ca.pem", res["ca"])
        if res.get("private_key"):
            self._write_secret("agent.key", res["private_key"])
        self.state.update(agent_token=res["agent_token"], config_signing_key=res["config_signing_key"],
                          group=res["group"])
        self._save()

    def heartbeat_once(self) -> dict:
        resp = self._call("POST", "/api/v1/fleet/heartbeat", {**self.stats(), "config_version": self.config_version})
        if resp.get("config_version", 0) > self.config_version:
            bundle = self._call("GET", "/api/v1/fleet/config")
            if not verify_bundle(bundle, bytes.fromhex(self.state["config_signing_key"])):
                logger.error("fleet: configuration bundle signature invalid; refused")
            else:
                self.on_config(bundle["config"])
                self.config_version = bundle["version"]
                self.state["config_version"] = self.config_version
                self._save()
        if resp.get("throttle_eps") != self.throttle:
            self.throttle = resp.get("throttle_eps")
            self.on_throttle(self.throttle)
        if resp.get("rotate_certificate"):
            r = self._call("POST", "/api/v1/fleet/rotate", {})
            self._write_secret("agent.pem", r["certificate"])
            if r.get("private_key"):
                self._write_secret("agent.key", r["private_key"])
        return resp

    def run_forever(self, stop=None) -> None:
        self.enroll()
        interval = 30.0
        while stop is None or not stop.is_set():
            try:
                interval = float(self.heartbeat_once().get("heartbeat_seconds", 30))
            except Exception as e:      # the control plane being away never stops forwarding
                logger.warning(f"fleet heartbeat failed: {e}")
            delay = interval * random.uniform(0.8, 1.2)
            if stop is not None:
                stop.wait(delay)
            else:
                time.sleep(delay)
