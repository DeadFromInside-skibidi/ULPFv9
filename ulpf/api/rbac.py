"""
Multi-tenant role-based access control.

Roles (MSSP-ready)::

    auditor   read cases, evidence, audit logs and compliance reports (no changes)
    hunter    auditor + run queries, threat intel, copilot
    analyst   hunter + work cases, run playbooks, decide approvals (four-eyes rule)
    admin     everything, incl. connectors, playbook authoring, keys, tenants

Legacy key roles map onto them: ``read`` -> hunter, ``write`` -> analyst,
``admin`` -> admin. A key entry may restrict tenants::

    - {name: acme-soc, sha256: <hex>, role: analyst, tenants: [acme]}
    - {name: mssp-lead, sha256: <hex>, role: admin, tenants: ["*"]}

The tenant of a request is the ``X-ULPF-Tenant`` header (default: the key's
first tenant, else ``default``). A key never sees another tenant's data.
With no keys configured the API is local-only and the caller is ``local`` /
admin on any tenant.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field

from fastapi import Header, HTTPException

from ulpf.api import auth

ROLE_PERMS: dict[str, set[str]] = {
    "auditor": {"cases:read", "evidence:read", "audit:read", "compliance:read", "metrics:read"},
    "hunter": {"cases:read", "evidence:read", "metrics:read", "query:run", "intel:read", "copilot:use",
               "compliance:read"},
}
ROLE_PERMS["analyst"] = ROLE_PERMS["hunter"] | {"cases:write", "playbooks:run", "approvals:decide",
                                                "evidence:write", "audit:read"}
ROLE_PERMS["admin"] = ROLE_PERMS["analyst"] | {"playbooks:write", "connectors:manage", "admin",
                                               "compliance:export", "fleet:manage"}
LEGACY = {"read": "hunter", "write": "analyst", "admin": "admin"}
ROLES = tuple(ROLE_PERMS)
_TENANT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


@dataclass
class Principal:
    name: str
    role: str
    tenants: list[str] = field(default_factory=lambda: ["default"])
    tenant: str = "default"

    @property
    def perms(self) -> set[str]:
        return ROLE_PERMS.get(self.role, set())

    def can(self, perm: str) -> bool:
        return perm in self.perms

    @property
    def roles(self) -> set[str]:
        """The role plus every role it includes (for approver lists)."""
        order = ["auditor", "hunter", "analyst", "admin"]
        return set(order[:order.index(self.role) + 1]) if self.role in order else {self.role}


def _entry_for(key: str | None):
    if not key:
        return None
    admin = os.environ.get("ULPF_API_KEY")
    if admin and hmac.compare_digest(key, admin):
        return {"name": "admin", "role": "admin", "tenants": ["*"]}
    digest = hashlib.sha256(key.encode()).hexdigest()
    return _entries(auth.keys_file()).get(digest)


_ecache: dict = {"path": None, "mtime": None, "entries": {}}
_elock = threading.Lock()


def _entries(path: str | None) -> dict:
    """{sha256 hex: key entry}, re-read only when the keys file changes."""
    if not path or not os.path.exists(path):
        return {}
    mtime = os.path.getmtime(path)
    with _elock:
        if _ecache["path"] == path and _ecache["mtime"] == mtime:
            return _ecache["entries"]
        import json
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        try:
            entries = json.loads(text)
        except ValueError:
            import yaml
            entries = yaml.safe_load(text) or []
        out = {str(e.get("sha256", "")).lower(): e for e in entries if isinstance(e, dict)}
        _ecache.update(path=path, mtime=mtime, entries=out)
        return out


def resolve(key: str | None, tenant_header: str | None) -> Principal:
    if not auth.auth_configured():
        p = Principal("local", "admin", ["*"])
    else:
        e = _entry_for(key) or _ticket_entry(key)
        if e is None:
            raise HTTPException(401, "Invalid or missing X-API-Key")
        role = LEGACY.get(e.get("role", "read"), e.get("role", "read"))
        if role not in ROLE_PERMS:
            raise HTTPException(403, f"unknown role {role!r}")
        tenants = [str(t) for t in (e.get("tenants") or ["default"])]
        p = Principal(e.get("name") or "key", role, tenants)
    want = (tenant_header or "").strip().lower() or (p.tenants[0] if p.tenants[0] != "*" else "default")
    if not _TENANT.match(want):
        raise HTTPException(400, "invalid tenant id")
    if "*" not in p.tenants and want not in p.tenants:
        raise HTTPException(403, f"no access to tenant {want!r}")
    p.tenant = want
    return p


def principal(x_api_key: str | None = Header(default=None), x_ulpf_tenant: str | None = Header(default=None)):
    return resolve(x_api_key, x_ulpf_tenant)


def need(perm: str):
    """FastAPI dependency: a principal holding ``perm`` in the requested tenant."""

    def dep(x_api_key: str | None = Header(default=None), x_ulpf_tenant: str | None = Header(default=None)):
        p = resolve(x_api_key, x_ulpf_tenant)
        if not p.can(perm):
            raise HTTPException(403, f"role {p.role!r} lacks permission {perm!r}")
        return p
    return dep


# ---------------------------------------------------------------------------
# Short-lived tickets (WebSocket auth: browsers cannot set headers on a WebSocket)
# ---------------------------------------------------------------------------
_tickets: dict[str, tuple[float, dict]] = {}
_tlock = threading.Lock()
TICKET_TTL = 60.0


def issue_ticket(p: Principal) -> str:
    t = "wst_" + secrets.token_urlsafe(24)
    with _tlock:
        now = time.time()
        for k in [k for k, (exp, _) in _tickets.items() if exp < now]:
            _tickets.pop(k, None)
        if len(_tickets) > 10_000:
            raise HTTPException(429, "too many open tickets")
        _tickets[t] = (now + TICKET_TTL, {"name": p.name, "role": p.role, "tenants": [p.tenant]})
    return t


def _ticket_entry(t: str | None):
    if not t or not t.startswith("wst_"):
        return None
    with _tlock:
        v = _tickets.pop(t, None)          # single use
    if v is None or v[0] < time.time():
        return None
    return v[1]
