"""
Third-party parser plugins, installed as Python packages.

A plugin package declares an entry point in the ``ulpf.parsers`` group that
names a ``BaseParser`` subclass::

    # pyproject.toml of the plugin
    [project.entry-points."ulpf.parsers"]
    acme_plc = "acme_ulpf.parser:AcmePlcParser"

Installed plugins are tried before the built-in parsers, in name order, for
the lines their ``can_parse`` accepts (a vendor-specific parser is more
specific than a generic syslog or KV parser).

Trust: the package hash is the SHA-256 over the distribution's installed
files (sorted by path, as listed in its RECORD). In defence mode a plugin
loads only when that hash is in ``plugins.allow``; in industry mode every
installed plugin loads unless ``plugins.enabled`` is false or an allow-list
is given. ``ulpf plugins list`` prints each plugin's hash for the allow-list.
"""
from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

GROUP = "ulpf.parsers"


@dataclass
class PluginInfo:
    name: str
    target: str
    distribution: str | None
    version: str | None
    sha256: str | None
    allowed: bool = False
    loaded: bool = False
    error: str | None = None
    parser: object = field(default=None, repr=False)

    def to_dict(self) -> dict:
        return {"name": self.name, "target": self.target, "distribution": self.distribution,
                "version": self.version, "sha256": self.sha256, "allowed": self.allowed,
                "loaded": self.loaded, "error": self.error}


def distribution_sha256(dist) -> str | None:
    """SHA-256 over the distribution's files: path NUL content NUL, sorted by path."""
    files = sorted((str(f) for f in (dist.files or [])), key=str)
    if not files:
        return None
    h = hashlib.sha256()
    for rel in files:
        if rel.endswith(".pyc") or "__pycache__" in rel or rel.endswith("RECORD"):
            continue          # caches and the RECORD (which lists hashes) vary per install
        path = dist.locate_file(rel)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            continue
        h.update(rel.replace(os.sep, "/").encode() + b"\0" + data + b"\0")
    return h.hexdigest()


def _entry_points():
    from importlib.metadata import entry_points
    try:
        return list(entry_points(group=GROUP))
    except TypeError:                       # Python < 3.10 API
        return list(entry_points().get(GROUP, []))


def discover(policy: dict | None = None) -> list[PluginInfo]:
    """Installed plugins, loaded according to ``policy`` = {"enabled": bool, "allow": [sha256] | None}."""
    from ulpf.parsers.base import BaseParser
    policy = policy or {}
    enabled = policy.get("enabled", True)
    allow = policy.get("allow")
    allow = {a.lower() for a in allow} if allow is not None else None
    out: list[PluginInfo] = []
    for ep in sorted(_entry_points(), key=lambda e: e.name):
        dist = getattr(ep, "dist", None)
        info = PluginInfo(ep.name, ep.value, getattr(dist, "name", None) if dist else None,
                          getattr(dist, "version", None) if dist else None,
                          distribution_sha256(dist) if dist else None)
        info.allowed = bool(enabled) and (allow is None or (info.sha256 or "") in allow)
        if not info.allowed:
            info.error = "plugins disabled" if not enabled else "package hash not in plugins.allow"
            out.append(info)
            continue
        try:
            cls = ep.load()
            if not (isinstance(cls, type) and issubclass(cls, BaseParser)):
                raise TypeError(f"{ep.value} is not a BaseParser subclass")
            info.parser = cls()
            info.loaded = True
        except Exception as e:
            info.error = f"{type(e).__name__}: {e}"
            logger.warning(f"parser plugin {ep.name} failed to load: {info.error}")
        out.append(info)
    return out


def policy_from_config(cfg: dict) -> dict:
    """Plugin policy from a pipeline config (dict form): defence requires an allow-list."""
    p = cfg.get("plugins") or {}
    allow = p.get("allow")
    if cfg.get("mode") == "defence" and allow is None:
        allow = []                          # nothing loads until hashes are listed
    return {"enabled": p.get("enabled", True), "allow": allow}
