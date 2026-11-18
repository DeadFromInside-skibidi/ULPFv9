"""
API keys with roles: ``read`` < ``write`` < ``admin``.

Keys come from
* ``ULPF_API_KEY`` — one admin key (backwards compatible), and/or
* a keys file (``api.keys_file`` or ``ULPF_API_KEYS_FILE``), JSON or YAML::

      - {name: soc-dashboard, sha256: <hex of the key>, role: read}
      - {name: log-shipper,   sha256: <hex>,            role: write}

  Only SHA-256 digests are stored, never the keys. Create an entry with
  ``ulpf apikey new --name NAME --role ROLE``.

With no key configured at all, the API is open (it binds to 127.0.0.1 by default).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading

from fastapi import Header, HTTPException

ROLES = {"read": 1, "auditor": 1, "hunter": 1, "write": 2, "analyst": 2, "admin": 3}   # see ulpf.api.rbac
_lock = threading.Lock()
_cache: dict = {"path": None, "mtime": None, "keys": {}}


def keys_file() -> str | None:
    return os.environ.get("ULPF_API_KEYS_FILE") or None


def _load(path: str | None) -> dict[str, tuple[str, str]]:
    """{sha256 hex: (role, name)}"""
    if not path or not os.path.exists(path):
        return {}
    mtime = os.path.getmtime(path)
    with _lock:
        if _cache["path"] == path and _cache["mtime"] == mtime:
            return _cache["keys"]
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        try:
            entries = json.loads(text)
        except ValueError:
            import yaml
            entries = yaml.safe_load(text) or []
        keys = {}
        for e in entries:
            role = e.get("role", "read")
            if role not in ROLES:
                raise ValueError(f"{path}: unknown role {role!r}")
            keys[str(e["sha256"]).lower()] = (role, e.get("name", ""))
        _cache.update(path=path, mtime=mtime, keys=keys)
        return keys


def role_of(key: str | None) -> str | None:
    """Role for a presented key, or None if it is not valid."""
    if not key:
        return None
    admin = os.environ.get("ULPF_API_KEY")
    if admin and hmac.compare_digest(key, admin):
        return "admin"
    digest = hashlib.sha256(key.encode()).hexdigest()
    entry = _load(keys_file()).get(digest)
    return entry[0] if entry else None


def auth_configured() -> bool:
    return bool(os.environ.get("ULPF_API_KEY")) or bool(_load(keys_file()))


def require(min_role: str):
    """FastAPI dependency: the request needs a key with at least ``min_role``."""

    def dep(x_api_key: str | None = Header(default=None)) -> str:
        if not auth_configured():
            return "admin"
        role = role_of(x_api_key)
        if role is None:
            raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")
        if ROLES[role] < ROLES[min_role]:
            raise HTTPException(status_code=403, detail=f"This action needs the {min_role!r} role")
        return role

    return dep


def identity(x_api_key: str | None = Header(default=None)) -> str:
    """FastAPI dependency: who is calling (the key's name), for per-analyst limits and fair
    share. Combine with ``require`` for authorisation; this never authorises anything."""
    if not auth_configured():
        return "local"
    if not x_api_key:
        return "anonymous"
    admin = os.environ.get("ULPF_API_KEY")
    if admin and hmac.compare_digest(x_api_key, admin):
        return "admin"
    digest = hashlib.sha256(x_api_key.encode()).hexdigest()
    entry = _load(keys_file()).get(digest)
    return (entry[1] or f"key-{digest[:12]}") if entry else "anonymous"


def new_key(path: str, name: str, role: str) -> str:
    """Append a new key's digest to the keys file and return the key (shown once)."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")
    key = "ulpf_" + secrets.token_urlsafe(32)
    entries = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            entries = json.load(f)
    entries.append({"name": name, "role": role, "sha256": hashlib.sha256(key.encode()).hexdigest()})
    tmp = path + ".tmp"
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)
    os.replace(tmp, path)
    return key
