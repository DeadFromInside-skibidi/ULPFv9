"""
Threat Intelligence Platform service (host side): feeds -> store -> decayed match set -> snapshot.

Feeds (``intel.feeds``):

  {"name": "local-stix", "type": "stix_file", "path": "/feeds/bundle.json"}       files (any mode)
  {"name": "misp-export", "type": "misp_file", "path": ...}  {"type": "otx_file", "path": ...}
  {"name": "x", "type": "taxii", "url": "https://.../api/v1/collections/<id>/", "token_env": "X_TOKEN"}
  {"name": "y", "type": "misp", "url": "https://misp.local", "key_env": "MISP_KEY"}
  {"name": "z", "type": "otx", "key_env": "OTX_KEY"}

Network feeds pull from their cursor every ``interval_minutes``. In ``defence`` mode a network feed is
refused unless its host is on the air-gap allow-list (``airgap.allow``); file feeds re-import when the
file changes. After any change, and every ``rebuild_minutes`` (decay), the indicators in force are
written to ``<data dir>/intel/matcher.snap`` and ``on_snapshot`` is called (the runtime broadcasts
``reload_intel`` to its workers).
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.parse

from ulpf.intelligence.tip import feeds as feedmod
from ulpf.intelligence.tip.indicators import Indicator
from ulpf.intelligence.tip.matcher import write_snapshot
from ulpf.intelligence.tip.stix import TaxiiClient, load_bundle_file, parse_bundle
from ulpf.intelligence.tip.store import TipStore

logger = logging.getLogger(__name__)
NETWORK_FEEDS = ("taxii", "misp", "otx")
FILE_FEEDS = ("stix_file", "misp_file", "otx_file")
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
BUILTIN_IOCS = os.path.join(_ROOT, "config", "iocs.json")


class FeedRefused(PermissionError):
    pass


def tip_dir(data_dir: str) -> str:
    return os.path.join(data_dir, "intel")


def snapshot_path(data_dir: str) -> str:
    return os.path.join(tip_dir(data_dir), "matcher.snap")


def builtin_indicators(path: str = BUILTIN_IOCS) -> list[Indicator]:
    """``config/iocs.json`` ({ip: {cat, conf}}): matched on source / destination IP only, never decays."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    out = []
    for ip, info in data.items():
        if ip.startswith("_") or not isinstance(info, dict):
            continue
        try:
            conf = float(info.get("conf", 0.5))
        except (TypeError, ValueError):
            continue
        out.append(Indicator(kind="ip", value=ip, confidence=conf, category=str(info.get("cat", "Unknown")),
                             source="builtin", flags=1))
    return out


def import_file(store: TipStore, typ: str, path: str, name: str | None = None) -> dict:
    """One feed file into the store (``ulpf intel import-stix | import-misp | import-otx``)."""
    if typ == "stix_file":
        inds, stats = load_bundle_file(path, name)
        revoked = stats.pop("revoked", [])
        res = store.upsert(inds, name or f"stix:{os.path.basename(path)}")
        res["revoked"] = store.revoke(stix_ids=revoked) if revoked else 0
        return {**stats, **res}
    if os.path.getsize(path) > 1 << 30:
        raise ValueError(f"{path}: larger than 1 GiB")
    with open(path, "rb") as f:
        data = json.loads(f.read())
    if typ == "misp_file":
        inds, stats = feedmod.parse_misp(data, name or f"misp:{os.path.basename(path)}")
    elif typ == "otx_file":
        inds, stats = feedmod.parse_otx(data, name or f"otx:{os.path.basename(path)}")
    else:
        raise ValueError(f"unknown feed file type {typ}")
    return {**stats, **store.upsert(inds, name or (inds[0].source if inds else typ))}


class TipService:
    def __init__(self, data_dir: str, cfg: dict | None = None, mode: str = "standard", airgap_allow=None,
                 on_snapshot=None):
        cfg = cfg or {}
        self.cfg = cfg
        self.mode = mode
        self.allow = list(airgap_allow or [])
        self.min_conf = float(cfg.get("min_confidence", 0.2))
        self.rebuild_s = float(cfg.get("rebuild_minutes", 60)) * 60
        self.store = TipStore(os.path.join(tip_dir(data_dir), "tip.db"), cfg.get("half_life_days"),
                              int(cfg.get("max_indicators", 10_000_000)))
        self.snap = snapshot_path(data_dir)
        self.on_snapshot = on_snapshot
        self.feeds = [f for f in cfg.get("feeds") or [] if isinstance(f, dict)]
        for f in self.feeds:
            self.check_feed(f)
        self._next: dict[str, float] = {}
        self._mtimes: dict[str, float] = {}
        self._built = 0.0
        self._dirty = True
        self._stop = threading.Event()
        self._thread = None
        self.last: dict = {"indicators": 0, "built": None, "seconds": None}
        if cfg.get("builtin", True):
            self.store.upsert(builtin_indicators(), "builtin", no_decay=True)

    # ---- policy
    def check_feed(self, f: dict) -> None:
        typ = f.get("type")
        if typ not in NETWORK_FEEDS + FILE_FEEDS:
            raise ValueError(f"intel feed {f.get('name')}: unknown type {typ!r}")
        if not f.get("name"):
            raise ValueError("intel feed without a name")
        if typ in FILE_FEEDS and not f.get("path"):
            raise ValueError(f"intel feed {f['name']}: path required")
        if typ in NETWORK_FEEDS:
            url = f.get("url") or ("https://otx.alienvault.com" if typ == "otx" else "")
            if not url:
                raise ValueError(f"intel feed {f['name']}: url required")
            if urllib.parse.urlsplit(url).scheme != "https" and not f.get("allow_http"):
                raise ValueError(f"intel feed {f['name']}: https required (allow_http to override)")
            if self.mode == "defence":
                host = urllib.parse.urlsplit(url).hostname or ""
                if not self._allowed(host):
                    raise FeedRefused(f"intel feed {f['name']}: network feeds are off in defence mode unless "
                                      f"{host} is on airgap.allow")

    def _allowed(self, host: str) -> bool:
        from ulpf.runtime import egress
        pol = egress.current()
        if pol is not None:
            return pol.allowed(host)
        try:
            pol = egress.EgressPolicy(self.allow, True)
            return pol.allowed(host)
        except Exception:
            return host in self.allow

    # ---- feeds
    def sync(self, name: str | None = None, now: float | None = None, force: bool = False) -> dict:
        """Pull due feeds (or the named one). Returns {feed: result}."""
        now = now or time.time()
        out = {}
        for f in self.feeds:
            fname = f["name"]
            if name and fname != name:
                continue
            try:
                if f["type"] in FILE_FEEDS:
                    path = f["path"]
                    mt = os.path.getmtime(path)
                    if not force and self._mtimes.get(fname) == mt:
                        continue
                    res = import_file(self.store, f["type"], path, fname)
                    if f.get("replace", True):
                        res["retired"] = self._retire(fname, path, f["type"])
                    self._mtimes[fname] = mt
                    self.store.set_feed_state(fname, f["type"], str(mt), None, res.get("added", 0))
                else:
                    if not force and now < self._next.get(fname, 0):
                        continue
                    self._next[fname] = now + float(f.get("interval_minutes", 60)) * 60
                    self.check_feed(f)
                    res = self._pull(f)
                out[fname] = res
                self._dirty = True
            except Exception as e:                  # one bad feed never stops the others
                logger.warning(f"intel feed {fname}: {e}")
                self.store.set_feed_state(fname, f["type"], None, str(e))
                out[fname] = {"error": str(e)}
        return out

    def _retire(self, fname: str, path: str, typ: str) -> int:
        """A file feed is the whole feed: indicators gone from the file are revoked."""
        from ulpf.intelligence.tip.indicators import normalize
        if typ == "stix_file":
            inds, _ = load_bundle_file(path, fname)
        else:
            with open(path, "rb") as fh:
                data = json.loads(fh.read())
            inds, _ = (feedmod.parse_misp if typ == "misp_file" else feedmod.parse_otx)(data, fname)
        keep = {kv for kv in (normalize(i.kind, i.value) for i in inds) if kv}
        return self.store.revoke(source=fname, keep=keep)

    def _pull(self, f: dict) -> dict:
        st = self.store.feed_state(f["name"])
        cursor = st.get("cursor")
        if f["type"] == "taxii":
            objs, cursor = TaxiiClient(f).pull(cursor)
            inds, stats = parse_bundle(objs, f["name"])
            revoked = stats.pop("revoked", [])
            res = {**stats, **self.store.upsert(inds, f["name"])}
            if revoked:
                res["revoked"] = self.store.revoke(stix_ids=revoked)
        elif f["type"] == "misp":
            inds, cursor = feedmod.pull_misp(f, cursor)
            res = self.store.upsert(inds, f["name"])
        else:
            inds, cursor = feedmod.pull_otx(f, cursor)
            res = self.store.upsert(inds, f["name"])
        self.store.set_feed_state(f["name"], f["type"], cursor, None, res.get("added", 0))
        return res

    # ---- match set
    def build(self, now: float | None = None) -> dict:
        """Write the snapshot of indicators in force now; returns its stats."""
        t0 = time.time()
        rows = self.store.active(self.min_conf, now)
        write_snapshot(rows, self.snap)
        self._built = time.time()
        self._dirty = False
        self.last = {"indicators": len(rows), "built": self._built, "seconds": round(time.time() - t0, 3)}
        if self.on_snapshot:
            try:
                self.on_snapshot(self.snap)
            except Exception:
                logger.warning("intel snapshot callback failed", exc_info=True)
        return self.last

    def step(self, now: float | None = None) -> None:
        now = now or time.time()
        self.sync(now=now)
        if self._dirty or now - self._built >= self.rebuild_s:
            if now - self._built >= self.rebuild_s:
                self.store.purge(self.min_conf, now)
            self.build(now)

    def start(self, interval: float = 30.0) -> None:
        if self._thread is not None:
            return

        def loop():
            while not self._stop.wait(interval):
                try:
                    self.step()
                except Exception:
                    logger.warning("intel service step failed", exc_info=True)

        self._thread = threading.Thread(target=loop, name="ulpf-intel", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        self.store.close()

    def stats(self) -> dict:
        return {**self.store.stats(self.min_conf), "snapshot": self.last, "min_confidence": self.min_conf}
