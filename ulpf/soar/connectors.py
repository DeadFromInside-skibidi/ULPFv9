"""
Bi-directional remediation connectors.

Each connector turns an action (``block_ip``, ``isolate_host``, ``disable_user``...)
into one or more concrete requests (HTTP calls or local commands) and knows the
*inverse* action, so every containment can be rolled back from the case
(``unblock_ip``, ``unisolate_host``, ``enable_user``...).

=================  =====================================================================
Network/firewall   ``panos`` (User-ID dynamic address group tags), ``fortios`` (address +
                   address group), ``checkpoint`` (Web API host/network + group + publish),
                   ``cisco_asa`` (REST ``/api/cli`` shun), ``nftables`` / ``iptables`` (host)
Endpoint/EDR       ``wazuh`` (active response), ``defender`` (MDE machine actions),
                   ``crowdstrike`` (Falcon device actions, IOC prevent, RTR kill)
Identity/IAM       ``active_directory`` (PowerShell AD module), ``okta`` (suspend, sessions),
                   ``entra`` (Graph accountEnabled, revokeSignInSessions), ``aws_iam``
                   (inline deny policy, SigV4)
=================  =====================================================================

Safety:

* **Dry run**: ``execute(..., dry_run=True)`` returns the exact requests that
  would be sent, with secrets redacted, and touches nothing.
* Every target is validated (IP/CIDR via :mod:`ipaddress`, hostnames, user
  names) before it is placed in a URL, XML document or command line; commands
  are argv lists (never a shell).
* Credentials come from environment variables named in the connector config
  (``*_env``), never from files the config writes. Requests are vetted by the
  egress guard, bodies are capped at 1 MiB, TLS is verified by default.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

MAX_RESPONSE = 1 << 20
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
_USER_RE = re.compile(r"^[A-Za-z0-9._@\\-]{1,256}$")
_HASH_RE = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")
_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")


class ConnectorError(RuntimeError):
    pass


def _ip(v) -> str:
    try:
        return str(ipaddress.ip_network(str(v).strip(), strict=False))
    except ValueError:
        raise ConnectorError(f"not an IP address or CIDR: {v!r}") from None


def _ip_host(v) -> str:
    n = ipaddress.ip_network(_ip(v), strict=False)
    return str(n.network_address) if n.num_addresses == 1 else str(n)


def _check(regex, v, what) -> str:
    s = str(v or "").strip()
    if not regex.match(s):
        raise ConnectorError(f"invalid {what}: {v!r}")
    return s


def _xml(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&apos;"))


def _obj_name(prefix: str, value: str) -> str:
    return prefix + re.sub(r"[^A-Za-z0-9_.-]", "_", value)[:60]


@dataclass
class Request:
    kind: str                      # "http" | "command"
    method: str = "GET"
    url: str = ""
    headers: dict = field(default_factory=dict)
    body: bytes | None = None
    argv: list[str] = field(default_factory=list)
    secret_headers: tuple = ("authorization", "x-pan-key", "x-auth-token", "x-chkp-sid")

    def redacted(self) -> dict:
        if self.kind == "command":
            return {"kind": "command", "argv": self.argv}
        hdr = {k: ("***" if k.lower() in self.secret_headers else v) for k, v in self.headers.items()}
        body = None
        if self.body is not None:
            text = self.body.decode("utf-8", "replace")
            text = re.sub(r"(client_secret|password|secret|token)=([^&]+)", r"\1=***", text)
            body = text[:4000]
        return {"kind": "http", "method": self.method, "url": re.sub(r"(key|password)=[^&]+", r"\1=***", self.url),
                "headers": hdr, "body": body}


class HttpTransport:
    """urllib with verified TLS, egress vetting and bounded responses. Replaceable in tests."""

    def __init__(self, verify_tls: bool = True, ca_file: str | None = None, timeout: float = 30.0):
        self.ctx = ssl.create_default_context(cafile=ca_file) if verify_tls else ssl._create_unverified_context()
        self.timeout = timeout

    def send(self, req: Request) -> tuple[int, bytes]:
        if req.kind == "command":
            p = subprocess.run(req.argv, capture_output=True, timeout=self.timeout, check=False)
            if p.returncode != 0:
                raise ConnectorError(f"{req.argv[0]} exited {p.returncode}: "
                                     f"{p.stderr.decode('utf-8', 'replace')[:500]}")
            return 0, p.stdout[:MAX_RESPONSE]
        from ulpf.runtime.egress import vet_endpoints
        u = urllib.parse.urlsplit(req.url)
        vet_endpoints([f"{u.hostname}:{u.port or (443 if u.scheme == 'https' else 80)}"], "SOAR connector")
        r = urllib.request.Request(req.url, data=req.body, method=req.method, headers=req.headers)
        try:
            with urllib.request.urlopen(r, timeout=self.timeout, context=self.ctx) as resp:
                return resp.status, resp.read(MAX_RESPONSE)
        except urllib.error.HTTPError as e:
            body = e.read(4096).decode("utf-8", "replace")
            raise ConnectorError(f"HTTP {e.code} from {u.hostname}: {body[:300]}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise ConnectorError(f"{u.hostname}: {e}") from None


def _secret(cfg: dict, name: str, env) -> str:
    var = cfg.get(f"{name}_env")
    val = env.get(var) if var else None
    if not val:
        raise ConnectorError(f"connector {cfg.get('name')!r}: set {name}_env to an environment variable "
                             f"holding the {name}" + (f" ({var} is empty)" if var else ""))
    return val


class Connector:
    type = "base"
    category = "generic"
    actions: dict[str, str] = {}          # action -> inverse action ('' when none)
    destructive: set[str] = set()

    def __init__(self, cfg: dict, transport=None, env=None):
        import os
        self.cfg = cfg
        self.name = cfg.get("name") or self.type
        self.base = (cfg.get("url") or "").rstrip("/")
        self.transport = transport or HttpTransport(cfg.get("verify_tls", True), cfg.get("ca_file"),
                                                    float(cfg.get("timeout", 30)))
        self.env = env if env is not None else os.environ
        self._token: tuple[str, float] | None = None

    def inverse(self, action: str) -> str | None:
        return self.actions.get(action) or None

    def plan(self, action: str, params: dict) -> list[Request]:
        fn = getattr(self, "_" + action, None)
        if action not in self.actions or fn is None:
            raise ConnectorError(f"{self.type} does not support {action!r} "
                                 f"(supported: {', '.join(sorted(self.actions))})")
        return fn(params)

    def execute(self, action: str, params: dict, dry_run: bool = False) -> dict:
        plan = self.plan(action, params)
        out = {"connector": self.name, "type": self.type, "action": action, "dry_run": dry_run,
               "inverse": self.inverse(action), "requests": [r.redacted() for r in plan]}
        if dry_run:
            out["status"] = "simulated"
            return out
        results = []
        for r in plan:
            r = self.authorize(r)
            status, body = self.transport.send(r)
            results.append({"status": status, "body": body[:2000].decode("utf-8", "replace")})
            self.after(r, status, body)
        out.update(status="done", results=results)
        return out

    def authorize(self, r: Request) -> Request:
        return r

    def after(self, r: Request, status: int, body: bytes) -> None:
        pass

    def _json(self, method: str, path: str, body=None, headers=None) -> Request:
        h = {"Content-Type": "application/json", "Accept": "application/json", **(headers or {})}
        return Request("http", method, self.base + path, h, None if body is None else json.dumps(body).encode())

    def _oauth(self, token_url: str, form: dict) -> str:
        if self._token and self._token[1] > time.time() + 60:
            return self._token[0]
        r = Request("http", "POST", token_url, {"Content-Type": "application/x-www-form-urlencoded"},
                    urllib.parse.urlencode(form).encode())
        status, body = self.transport.send(r)
        doc = json.loads(body or b"{}")
        tok = doc.get("access_token")
        if not tok:
            raise ConnectorError(f"{self.name}: token endpoint returned no access_token")
        self._token = (tok, time.time() + float(doc.get("expires_in", 1800)))
        return tok


# ---------------------------------------------------------------------------
# Network / firewall
# ---------------------------------------------------------------------------

class PanOS(Connector):
    """PAN-OS: tag IPs into a Dynamic Address Group via the User-ID XML API (no commit needed)."""
    type, category = "panos", "network"
    actions = {"block_ip": "unblock_ip", "unblock_ip": "block_ip", "block_domain": "unblock_domain",
               "unblock_domain": "block_domain"}
    destructive = {"block_ip", "block_domain"}

    def authorize(self, r):
        r.headers["X-PAN-KEY"] = _secret(self.cfg, "api_key", self.env)
        return r

    def _uid(self, op: str, ip: str) -> Request:
        tag = _xml(self.cfg.get("tag", "ulpf-blocked"))
        ttl = int(self.cfg.get("timeout_seconds", 0))
        t = f' timeout="{ttl}"' if ttl and op == "register" else ""
        msg = (f"<uid-message><version>2.0</version><type>update</type><payload><{op}>"
               f'<entry ip="{_xml(ip)}"><tag><member{t}>{tag}</member></tag></entry></{op}></payload></uid-message>')
        return Request("http", "POST", self.base + "/api/", {"Content-Type": "application/x-www-form-urlencoded"},
                       urllib.parse.urlencode({"type": "user-id", "cmd": msg}).encode())

    def _block_ip(self, p):
        return [self._uid("register", _ip_host(p["ip"]))]

    def _unblock_ip(self, p):
        return [self._uid("unregister", _ip_host(p["ip"]))]

    def _url_cat(self, p, action):
        d = _check(_DOMAIN_RE, p["domain"], "domain")
        cat = _xml(self.cfg.get("url_category", "ulpf-blocked-domains"))
        vsys = _xml(self.cfg.get("vsys", "vsys1"))
        xpath = (f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']"
                 f"/profiles/custom-url-category/entry[@name='{cat}']/list")
        q = {"type": "config", "action": action, "xpath": xpath}
        if action == "set":
            q["element"] = f"<member>{_xml(d)}</member>"
        else:
            q["xpath"] = xpath + f"/member[text()='{_xml(d)}']"
        commit = {"type": "commit", "cmd": "<commit></commit>"}
        return [Request("http", "POST", self.base + "/api/", {"Content-Type": "application/x-www-form-urlencoded"},
                        urllib.parse.urlencode(x).encode()) for x in (q, commit)]

    def _block_domain(self, p):
        return self._url_cat(p, "set")

    def _unblock_domain(self, p):
        return self._url_cat(p, "delete")


class FortiOS(Connector):
    type, category = "fortios", "network"
    actions = {"block_ip": "unblock_ip", "unblock_ip": "block_ip"}
    destructive = {"block_ip"}

    def authorize(self, r):
        r.headers["Authorization"] = "Bearer " + _secret(self.cfg, "api_token", self.env)
        return r

    def _q(self) -> str:
        return "?vdom=" + urllib.parse.quote(self.cfg.get("vdom", "root"))

    def _block_ip(self, p):
        net = ipaddress.ip_network(_ip(p["ip"]), strict=False)
        name = _obj_name("ulpf-", str(net))
        grp = urllib.parse.quote(self.cfg.get("address_group", "ulpf-blocklist"), safe="")
        kind = "address6" if net.version == 6 else "address"
        body = {"name": name, "ip6": str(net)} if net.version == 6 else \
            {"name": name, "subnet": f"{net.network_address} {net.netmask}", "comment": "ULPF SOAR containment"}
        return [self._json("POST", f"/api/v2/cmdb/firewall/{kind}{self._q()}", body),
                self._json("POST", f"/api/v2/cmdb/firewall/addrgrp/{grp}/member{self._q()}", {"name": name})]

    def _unblock_ip(self, p):
        net = ipaddress.ip_network(_ip(p["ip"]), strict=False)
        name = urllib.parse.quote(_obj_name("ulpf-", str(net)), safe="")
        grp = urllib.parse.quote(self.cfg.get("address_group", "ulpf-blocklist"), safe="")
        kind = "address6" if net.version == 6 else "address"
        return [self._json("DELETE", f"/api/v2/cmdb/firewall/addrgrp/{grp}/member/{name}{self._q()}"),
                self._json("DELETE", f"/api/v2/cmdb/firewall/{kind}/{name}{self._q()}")]


class CheckPoint(Connector):
    """Check Point Management Web API: login -> add host/network -> add to group -> publish -> logout."""
    type, category = "checkpoint", "network"
    actions = {"block_ip": "unblock_ip", "unblock_ip": "block_ip", "block_domain": "unblock_domain",
               "unblock_domain": "block_domain"}
    destructive = {"block_ip", "block_domain"}

    def _call(self, cmd: str, body: dict) -> Request:
        return self._json("POST", f"/web_api/{cmd}", body)

    def _session(self, inner: list[Request]) -> list[Request]:
        login = self._call("login", {"user": "${user}", "password": "${password}"})
        return [login, *inner, self._call("publish", {}), self._call("logout", {})]

    def authorize(self, r):
        if r.url.endswith("/web_api/login"):
            r.body = json.dumps({"user": _secret(self.cfg, "user", self.env),
                                 "password": _secret(self.cfg, "password", self.env)}).encode()
        elif getattr(self, "_sid", None):
            r.headers["X-chkp-sid"] = self._sid
        return r

    def after(self, r, status, body):
        if r.url.endswith("/web_api/login"):
            self._sid = json.loads(body or b"{}").get("sid")
        elif r.url.endswith("/web_api/logout"):
            self._sid = None

    def _block_ip(self, p):
        net = ipaddress.ip_network(_ip(p["ip"]), strict=False)
        name = _obj_name("ulpf-", str(net))
        grp = self.cfg.get("group", "ulpf-blocklist")
        if net.num_addresses == 1:
            add = self._call("add-host", {"name": name, "ip-address": str(net.network_address),
                                          "groups": [grp], "comments": "ULPF SOAR containment"})
        else:
            add = self._call("add-network", {"name": name, "subnet": str(net.network_address),
                                             "mask-length": net.prefixlen, "groups": [grp]})
        return self._session([add])

    def _unblock_ip(self, p):
        net = ipaddress.ip_network(_ip(p["ip"]), strict=False)
        name = _obj_name("ulpf-", str(net))
        cmd = "delete-host" if net.num_addresses == 1 else "delete-network"
        return self._session([self._call(cmd, {"name": name, "ignore-warnings": True})])

    def _block_domain(self, p):
        d = _check(_DOMAIN_RE, p["domain"], "domain")
        return self._session([self._call("add-dns-domain", {"name": "." + d.lstrip("*."), "is-sub-domain": True,
                                                            "groups": [self.cfg.get("group", "ulpf-blocklist")]})])

    def _unblock_domain(self, p):
        d = _check(_DOMAIN_RE, p["domain"], "domain")
        return self._session([self._call("delete-dns-domain", {"name": "." + d.lstrip("*.")})])


class CiscoASA(Connector):
    type, category = "cisco_asa", "network"
    actions = {"block_ip": "unblock_ip", "unblock_ip": "block_ip"}
    destructive = {"block_ip"}

    def authorize(self, r):
        cred = f"{_secret(self.cfg, 'user', self.env)}:{_secret(self.cfg, 'password', self.env)}"
        r.headers["Authorization"] = "Basic " + base64.b64encode(cred.encode()).decode()
        r.headers["User-Agent"] = "REST API Agent"
        return r

    def _block_ip(self, p):
        net = ipaddress.ip_network(_ip(p["ip"]), strict=False)
        if net.num_addresses != 1:
            grp = self.cfg.get("object_group", "ulpf-blocklist")
            return [self._json("POST", "/api/cli", {"commands": [f"object-group network {grp}",
                                                                 f"network-object {net.network_address} {net.netmask}"]})]
        return [self._json("POST", "/api/cli", {"commands": [f"shun {net.network_address}"]})]

    def _unblock_ip(self, p):
        net = ipaddress.ip_network(_ip(p["ip"]), strict=False)
        if net.num_addresses != 1:
            grp = self.cfg.get("object_group", "ulpf-blocklist")
            return [self._json("POST", "/api/cli", {"commands": [f"object-group network {grp}",
                                                                 f"no network-object {net.network_address} {net.netmask}"]})]
        return [self._json("POST", "/api/cli", {"commands": [f"no shun {net.network_address}"]})]


class Nftables(Connector):
    """Host firewall: an ``inet ulpf_soar`` table with drop sets, created on first use."""
    type, category = "nftables", "network"
    actions = {"block_ip": "unblock_ip", "unblock_ip": "block_ip"}
    destructive = {"block_ip"}

    def _nft(self, *args) -> Request:
        return Request("command", argv=[self.cfg.get("binary", "nft"), *args])

    def _setup(self) -> list[Request]:
        return [self._nft("add", "table", "inet", "ulpf_soar"),
                self._nft("add", "set", "inet", "ulpf_soar", "block4", "{ type ipv4_addr; flags interval; }"),
                self._nft("add", "set", "inet", "ulpf_soar", "block6", "{ type ipv6_addr; flags interval; }"),
                self._nft("add", "chain", "inet", "ulpf_soar", "input",
                          "{ type filter hook input priority -10; policy accept; }"),
                self._nft("add", "chain", "inet", "ulpf_soar", "output",
                          "{ type filter hook output priority -10; policy accept; }"),
                self._nft("flush", "chain", "inet", "ulpf_soar", "input"),
                self._nft("flush", "chain", "inet", "ulpf_soar", "output"),
                self._nft("add", "rule", "inet", "ulpf_soar", "input", "ip", "saddr", "@block4", "drop"),
                self._nft("add", "rule", "inet", "ulpf_soar", "input", "ip6", "saddr", "@block6", "drop"),
                self._nft("add", "rule", "inet", "ulpf_soar", "output", "ip", "daddr", "@block4", "drop"),
                self._nft("add", "rule", "inet", "ulpf_soar", "output", "ip6", "daddr", "@block6", "drop")]

    def _block_ip(self, p):
        net = ipaddress.ip_network(_ip(p["ip"]), strict=False)
        s = "block6" if net.version == 6 else "block4"
        return self._setup() + [self._nft("add", "element", "inet", "ulpf_soar", s, "{ " + str(net) + " }")]

    def _unblock_ip(self, p):
        net = ipaddress.ip_network(_ip(p["ip"]), strict=False)
        s = "block6" if net.version == 6 else "block4"
        return [self._nft("delete", "element", "inet", "ulpf_soar", s, "{ " + str(net) + " }")]


class Iptables(Connector):
    type, category = "iptables", "network"
    actions = {"block_ip": "unblock_ip", "unblock_ip": "block_ip"}
    destructive = {"block_ip"}

    def _rules(self, op: str, p) -> list[Request]:
        net = ipaddress.ip_network(_ip(p["ip"]), strict=False)
        binary = "ip6tables" if net.version == 6 else self.cfg.get("binary", "iptables")
        c = ["-m", "comment", "--comment", "ulpf-soar"]
        return [Request("command", argv=[binary, op, "INPUT", "-s", str(net), *c, "-j", "DROP"]),
                Request("command", argv=[binary, op, "OUTPUT", "-d", str(net), *c, "-j", "DROP"])]

    def _block_ip(self, p):
        return self._rules("-I", p)

    def _unblock_ip(self, p):
        return self._rules("-D", p)


# ---------------------------------------------------------------------------
# Endpoint / EDR
# ---------------------------------------------------------------------------

class Wazuh(Connector):
    type, category = "wazuh", "endpoint"
    actions = {"isolate_host": "unisolate_host", "unisolate_host": "isolate_host", "kill_process": "",
               "quarantine_file": "", "block_ip": "unblock_ip", "unblock_ip": "block_ip"}
    destructive = {"isolate_host", "kill_process", "quarantine_file", "block_ip"}

    def authorize(self, r):
        if r.url.endswith("/security/user/authenticate"):
            cred = f"{_secret(self.cfg, 'user', self.env)}:{_secret(self.cfg, 'password', self.env)}"
            r.headers["Authorization"] = "Basic " + base64.b64encode(cred.encode()).decode()
        else:
            r.headers["Authorization"] = "Bearer " + self._jwt()
        return r

    def _jwt(self) -> str:
        if self._token and self._token[1] > time.time() + 30:
            return self._token[0]
        r = self.authorize(Request("http", "POST", self.base + "/security/user/authenticate"))
        _, body = self.transport.send(r)
        tok = json.loads(body or b"{}").get("data", {}).get("token")
        if not tok:
            raise ConnectorError("wazuh: authentication returned no token")
        self._token = (tok, time.time() + 800)
        return tok

    def _ar(self, agent, command: str, args: list, alert: dict | None = None) -> list[Request]:
        aid = _check(_ID_RE, agent, "agent id")
        body = {"command": command, "arguments": args, "alert": {"data": alert or {}}}
        return [self._json("PUT", f"/active-response?agents_list={urllib.parse.quote(aid)}", body)]

    def _cmd(self, key: str, default: str) -> str:
        return self.cfg.get("commands", {}).get(key, default)

    def _isolate_host(self, p):
        return self._ar(p["agent_id"], self._cmd("isolate", "!ulpf-isolate"), [])

    def _unisolate_host(self, p):
        return self._ar(p["agent_id"], self._cmd("unisolate", "!ulpf-unisolate"), [])

    def _kill_process(self, p):
        return self._ar(p["agent_id"], self._cmd("kill", "!ulpf-kill-process"), [str(int(p["pid"]))])

    def _quarantine_file(self, p):
        path = str(p["path"])
        if len(path) > 1024 or "\x00" in path:
            raise ConnectorError("invalid file path")
        return self._ar(p["agent_id"], self._cmd("quarantine", "!ulpf-quarantine"), [path])

    def _block_ip(self, p):
        return self._ar(p["agent_id"], self._cmd("block_ip", "!firewall-drop"), [], {"srcip": _ip_host(p["ip"])})

    def _unblock_ip(self, p):
        return self._ar(p["agent_id"], self._cmd("unblock_ip", "!firewall-drop"), ["delete"],
                        {"srcip": _ip_host(p["ip"])})


class Defender(Connector):
    """Microsoft Defender for Endpoint machine actions (OAuth2 client credentials)."""
    type, category = "defender", "endpoint"
    actions = {"isolate_host": "unisolate_host", "unisolate_host": "isolate_host",
               "quarantine_file": "", "kill_process": "", "run_av_scan": ""}
    destructive = {"isolate_host", "quarantine_file", "kill_process"}

    def __init__(self, cfg, transport=None, env=None):
        cfg = {"url": "https://api.securitycenter.microsoft.com", **cfg}
        super().__init__(cfg, transport, env)

    def authorize(self, r):
        tenant = _check(_ID_RE, self.cfg.get("tenant_id"), "tenant_id")
        login = self.cfg.get("login_url", "https://login.microsoftonline.com")
        tok = self._oauth(f"{login}/{tenant}/oauth2/v2.0/token",
                          {"client_id": self.cfg.get("client_id", ""), "grant_type": "client_credentials",
                           "client_secret": _secret(self.cfg, "client_secret", self.env),
                           "scope": self.base + "/.default"})
        r.headers["Authorization"] = "Bearer " + tok
        return r

    def _m(self, p) -> str:
        return urllib.parse.quote(_check(_ID_RE, p["machine_id"], "machine id"))

    def _comment(self, p) -> str:
        return str(p.get("comment") or "ULPF SOAR containment")[:900]

    def _isolate_host(self, p):
        return [self._json("POST", f"/api/machines/{self._m(p)}/isolate",
                           {"Comment": self._comment(p), "IsolationType": p.get("isolation_type", "Full")})]

    def _unisolate_host(self, p):
        return [self._json("POST", f"/api/machines/{self._m(p)}/unisolate", {"Comment": self._comment(p)})]

    def _quarantine_file(self, p):
        return [self._json("POST", f"/api/machines/{self._m(p)}/StopAndQuarantineFile",
                           {"Comment": self._comment(p), "Sha1": _check(_HASH_RE, p["sha1"], "SHA-1")})]

    _kill_process = _quarantine_file

    def _run_av_scan(self, p):
        return [self._json("POST", f"/api/machines/{self._m(p)}/runAntiVirusScan",
                           {"Comment": self._comment(p), "ScanType": p.get("scan_type", "Quick")})]


class CrowdStrike(Connector):
    type, category = "crowdstrike", "endpoint"
    actions = {"isolate_host": "unisolate_host", "unisolate_host": "isolate_host", "quarantine_file": "",
               "block_hash": "unblock_hash", "unblock_hash": "block_hash", "kill_process": ""}
    destructive = {"isolate_host", "quarantine_file", "block_hash", "kill_process"}

    def __init__(self, cfg, transport=None, env=None):
        super().__init__({"url": "https://api.crowdstrike.com", **cfg}, transport, env)

    def authorize(self, r):
        if r.url.endswith("/oauth2/token"):
            return r
        tok = self._oauth(self.base + "/oauth2/token", {"client_id": self.cfg.get("client_id", ""),
                                                         "client_secret": _secret(self.cfg, "client_secret", self.env)})
        r.headers["Authorization"] = "Bearer " + tok
        return r

    def after(self, r, status, body):
        if "/real-time-response/entities/sessions/" in r.url:
            self._rtr_session = (json.loads(body or b"{}").get("resources") or [{}])[0].get("session_id")

    def _dev(self, action: str, p) -> list[Request]:
        aid = _check(_ID_RE, p["device_id"], "device id")
        return [self._json("POST", f"/devices/entities/devices-actions/v2?action_name={action}", {"ids": [aid]})]

    def _isolate_host(self, p):
        return self._dev("contain", p)

    def _unisolate_host(self, p):
        return self._dev("lift_containment", p)

    def _block_hash(self, p):
        h = _check(_HASH_RE, p["sha256"], "SHA-256")
        return [self._json("POST", "/iocs/entities/indicators/v1", {"indicators": [{
            "type": "sha256", "value": h.lower(), "action": "prevent", "severity": "high",
            "platforms": ["windows", "mac", "linux"], "applied_globally": True,
            "description": "ULPF SOAR containment"}]})]

    _quarantine_file = _block_hash

    def _unblock_hash(self, p):
        h = _check(_HASH_RE, p["sha256"], "SHA-256")
        return [self._json("DELETE", "/iocs/entities/indicators/v1?filter=" +
                           urllib.parse.quote(f"value:'{h.lower()}'"))]

    def _kill_process(self, p):
        aid = _check(_ID_RE, p["device_id"], "device id")
        pid = int(p["pid"])
        session = self._json("POST", "/real-time-response/entities/sessions/v1", {"device_id": aid})
        cmd = self._json("POST", "/real-time-response/entities/active-responder-command/v1",
                         {"base_command": "kill", "command_string": f"kill {pid}", "session_id": "${session}"})
        return [session, cmd]

    def execute(self, action, params, dry_run=False):
        if action != "kill_process" or dry_run:
            return super().execute(action, params, dry_run)
        plan = self.plan(action, params)
        out = {"connector": self.name, "type": self.type, "action": action, "dry_run": False, "inverse": None,
               "requests": [r.redacted() for r in plan], "results": []}
        for r in plan:
            if r.body and b"${session}" in r.body:
                r.body = r.body.replace(b"${session}", str(getattr(self, "_rtr_session", "")).encode())
            r = self.authorize(r)
            status, body = self.transport.send(r)
            self.after(r, status, body)
            out["results"].append({"status": status, "body": body[:2000].decode("utf-8", "replace")})
        out["status"] = "done"
        return out


# ---------------------------------------------------------------------------
# Identity / IAM
# ---------------------------------------------------------------------------

class ActiveDirectory(Connector):
    """Windows ActiveDirectory PowerShell module (RSAT) on the ULPF host or via a jump host."""
    type, category = "active_directory", "identity"
    actions = {"disable_user": "enable_user", "enable_user": "disable_user", "reset_password_required": ""}
    destructive = {"disable_user", "reset_password_required"}

    def _ps(self, cmdlet: str, user: str, extra: list[str] | None = None) -> list[Request]:
        u = _check(_USER_RE, user, "account name")
        server = self.cfg.get("server")
        script = f"Import-Module ActiveDirectory; {cmdlet} -Identity '{u}'"
        if server:
            script += f" -Server '{_check(_HOST_RE, server, 'server')}'"
        script += " " + " ".join(extra or []) + " -Confirm:$false"
        exe = self.cfg.get("powershell", "powershell.exe" if sys.platform == "win32" else "pwsh")
        return [Request("command", argv=[exe, "-NoProfile", "-NonInteractive", "-Command", script])]

    def _disable_user(self, p):
        return self._ps("Disable-ADAccount", p["user"])

    def _enable_user(self, p):
        return self._ps("Enable-ADAccount", p["user"])

    def _reset_password_required(self, p):
        return self._ps("Set-ADUser", p["user"], ["-ChangePasswordAtLogon $true"])


class Okta(Connector):
    type, category = "okta", "identity"
    actions = {"disable_user": "enable_user", "enable_user": "disable_user", "revoke_sessions": ""}
    destructive = {"disable_user", "revoke_sessions"}

    def authorize(self, r):
        r.headers["Authorization"] = "SSWS " + _secret(self.cfg, "api_token", self.env)
        return r

    def _u(self, p) -> str:
        return urllib.parse.quote(_check(_USER_RE, p["user"], "user"), safe="")

    def _disable_user(self, p):
        return [self._json("POST", f"/api/v1/users/{self._u(p)}/lifecycle/suspend"),
                self._json("DELETE", f"/api/v1/users/{self._u(p)}/sessions?oauthTokens=true")]

    def _enable_user(self, p):
        return [self._json("POST", f"/api/v1/users/{self._u(p)}/lifecycle/unsuspend")]

    def _revoke_sessions(self, p):
        return [self._json("DELETE", f"/api/v1/users/{self._u(p)}/sessions?oauthTokens=true")]


class Entra(Connector):
    """Microsoft Entra ID through Microsoft Graph."""
    type, category = "entra", "identity"
    actions = {"disable_user": "enable_user", "enable_user": "disable_user", "revoke_sessions": ""}
    destructive = {"disable_user", "revoke_sessions"}

    def __init__(self, cfg, transport=None, env=None):
        super().__init__({"url": "https://graph.microsoft.com", **cfg}, transport, env)

    def authorize(self, r):
        tenant = _check(_ID_RE, self.cfg.get("tenant_id"), "tenant_id")
        login = self.cfg.get("login_url", "https://login.microsoftonline.com")
        tok = self._oauth(f"{login}/{tenant}/oauth2/v2.0/token",
                          {"client_id": self.cfg.get("client_id", ""), "grant_type": "client_credentials",
                           "client_secret": _secret(self.cfg, "client_secret", self.env),
                           "scope": self.base + "/.default"})
        r.headers["Authorization"] = "Bearer " + tok
        return r

    def _u(self, p) -> str:
        return urllib.parse.quote(_check(_USER_RE, p["user"], "user"), safe="@")

    def _disable_user(self, p):
        return [self._json("PATCH", f"/v1.0/users/{self._u(p)}", {"accountEnabled": False}),
                self._json("POST", f"/v1.0/users/{self._u(p)}/revokeSignInSessions")]

    def _enable_user(self, p):
        return [self._json("PATCH", f"/v1.0/users/{self._u(p)}", {"accountEnabled": True})]

    def _revoke_sessions(self, p):
        return [self._json("POST", f"/v1.0/users/{self._u(p)}/revokeSignInSessions")]


class AwsIam(Connector):
    """Attach an inline explicit-deny policy to an IAM user or role (SigV4); revokes older role sessions."""
    type, category = "aws_iam", "identity"
    actions = {"disable_user": "enable_user", "enable_user": "disable_user"}
    destructive = {"disable_user"}
    POLICY = "ULPF-SOAR-Deny-All"

    def __init__(self, cfg, transport=None, env=None):
        super().__init__({"url": "https://iam.amazonaws.com", **cfg}, transport, env)

    def authorize(self, r):
        from ulpf.runtime.net import sigv4_headers
        hdr = sigv4_headers(r.method, r.url, "us-east-1", "iam", _secret(self.cfg, "access_key", self.env),
                            _secret(self.cfg, "secret_key", self.env), body=r.body or b"",
                            session_token=self.env.get(self.cfg.get("session_token_env") or "") or None,
                            headers={"content-type": r.headers["Content-Type"]}, content_sha_header=False)
        r.headers.update(hdr)
        return r

    def _form(self, params: dict) -> Request:
        return Request("http", "POST", self.base + "/", {"Content-Type": "application/x-www-form-urlencoded"},
                       urllib.parse.urlencode({**params, "Version": "2010-05-08"}).encode())

    def _target(self, p) -> tuple[str, str]:
        if p.get("role"):
            return "Role", _check(re.compile(r"^[\w+=,.@-]{1,64}$"), p["role"], "role name")
        return "User", _check(re.compile(r"^[\w+=,.@-]{1,64}$"), p["user"], "user name")

    def _disable_user(self, p):
        kind, name = self._target(p)
        # An explicit Deny on everything overrides every Allow, including for sessions already issued
        doc = json.dumps({"Version": "2012-10-17",
                          "Statement": [{"Sid": "UlpfSoarContainment", "Effect": "Deny", "Action": "*",
                                         "Resource": "*"}]})
        return [self._form({"Action": f"Put{kind}Policy", f"{kind}Name": name, "PolicyName": self.POLICY,
                            "PolicyDocument": doc})]

    def _enable_user(self, p):
        kind, name = self._target(p)
        return [self._form({"Action": f"Delete{kind}Policy", f"{kind}Name": name, "PolicyName": self.POLICY})]


CONNECTORS = {c.type: c for c in (PanOS, FortiOS, CheckPoint, CiscoASA, Nftables, Iptables, Wazuh, Defender,
                                  CrowdStrike, ActiveDirectory, Okta, Entra, AwsIam)}


def build(cfg: dict, transport=None, env=None) -> Connector:
    t = cfg.get("type")
    if t not in CONNECTORS:
        raise ConnectorError(f"unknown connector type {t!r} (known: {', '.join(sorted(CONNECTORS))})")
    return CONNECTORS[t](cfg, transport, env)


def catalog() -> list[dict]:
    return [{"type": t, "category": c.category, "actions": sorted(c.actions), "destructive": sorted(c.destructive),
             "inverse": {a: i for a, i in c.actions.items() if i}} for t, c in sorted(CONNECTORS.items())]
