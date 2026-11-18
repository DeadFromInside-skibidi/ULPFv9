"""
MISP events and AlienVault OTX pulses -> ``Indicator`` rows, and their network connectors.

MISP: an event export (``{"Event": {...}}``, ``{"response": [{"Event": ...}, ...]}`` or a list of
events). Attributes with ``to_ids`` false are context, not indicators, and are skipped unless
``include_non_ids``. Galaxy / tag ``misp-galaxy:threat-actor="X"`` names the actor,
``kill-chain:<phase>`` the phase; the event ``info`` is the campaign; ``threat_level_id`` (1 high ..
4 undefined) sets the confidence.

OTX: a pulse (``{"name", "adversary", "indicators": [...]}``) or ``{"results": [pulses]}``.

Credentials come from environment variables named in the feed config (``key_env``), never the config.
"""
from __future__ import annotations

import json
import urllib.parse

from ulpf.intelligence.tip.indicators import Indicator
from ulpf.intelligence.tip.stix import http_get, ts

MAX_EVENTS = 100_000
MAX_ATTRS = 5_000_000

_MISP_KIND = {
    "ip-src": "ip", "ip-dst": "ip", "ip-src|port": "ip", "ip-dst|port": "ip", "domain": "domain",
    "hostname": "domain", "domain|ip": "domain", "url": "url", "uri": "url", "link": None, "md5": "md5",
    "sha1": "sha1", "sha256": "sha256", "filename|md5": "md5", "filename|sha1": "sha1",
    "filename|sha256": "sha256", "email-src": "email", "email": "email", "email-dst": "email",
    "mutex": "mutex", "regkey": "registry", "regkey|value": "registry", "x509-fingerprint-sha1": None,
}
_MISP_CONF = {"1": 0.9, "2": 0.7, "3": 0.5, "4": 0.4}

_OTX_KIND = {"IPv4": "ip", "IPv6": "ip", "CIDR": "cidr", "domain": "domain", "hostname": "domain", "URL": "url",
             "URI": "url", "FileHash-MD5": "md5", "FileHash-SHA1": "sha1", "FileHash-SHA256": "sha256",
             "email": "email", "Mutex": "mutex"}


def _misp_value(typ: str, value: str) -> str:
    if "|" in typ:
        left, _, right = value.partition("|")
        if typ.startswith("filename|"):
            return right
        if typ.endswith("|port"):
            return left
        if typ == "domain|ip":
            return left
        if typ == "regkey|value":
            return left
    return value


def _tags(obj) -> list[str]:
    out = []
    for t in obj.get("Tag") or []:
        if isinstance(t, dict) and isinstance(t.get("name"), str):
            out.append(t["name"])
    return out


def _galaxy(tags: list[str], *names: str) -> str:
    for t in tags:
        for n in names:
            pre = f"misp-galaxy:{n}="
            if t.startswith(pre):
                return t[len(pre):].strip('"')[:256]
    return ""


def _phase(tags: list[str]) -> str:
    for t in tags:
        low = t.lower()
        if low.startswith("kill-chain:"):
            return t.split(":", 1)[1].strip('"')[:128]
        if low.startswith('misp-galaxy:mitre-attack-pattern='):
            continue
    return ""


def parse_misp(data, source: str = "misp", include_non_ids: bool = False) -> tuple[list[Indicator], dict]:
    if isinstance(data, dict) and "response" in data:
        data = data["response"]
    events = data if isinstance(data, list) else [data]
    if len(events) > MAX_EVENTS:
        raise ValueError(f"more than {MAX_EVENTS} MISP events")
    out: list[Indicator] = []
    stats = {"events": 0, "attributes": 0, "skipped": 0}
    for ev in events:
        ev = ev.get("Event", ev) if isinstance(ev, dict) else None
        if not isinstance(ev, dict):
            continue
        stats["events"] += 1
        tags = _tags(ev)
        actor = _galaxy(tags, "threat-actor", "microsoft-activity-group", "mitre-intrusion-set")
        capability = _galaxy(tags, "malpedia", "mitre-malware", "ransomware", "tool")
        conf = _MISP_CONF.get(str(ev.get("threat_level_id")), 0.5)
        cat = capability or next((t.split(":", 1)[1].strip('"') for t in tags if t.startswith("type:")), "") \
            or "MISP"
        stamp = ev.get("timestamp")
        last = float(stamp) if isinstance(stamp, (int, str)) and str(stamp).isdigit() else None
        first = ts(ev.get("date") + "T00:00:00Z") if isinstance(ev.get("date"), str) else None
        attrs = list(ev.get("Attribute") or [])
        for obj in ev.get("Object") or []:
            if isinstance(obj, dict):
                attrs.extend(obj.get("Attribute") or [])
        for a in attrs:
            if stats["attributes"] >= MAX_ATTRS:
                break
            if not isinstance(a, dict):
                continue
            stats["attributes"] += 1
            typ = str(a.get("type") or "")
            kind = _MISP_KIND.get(typ)
            value = a.get("value")
            if kind is None or not isinstance(value, str) or (not a.get("to_ids", True) and not include_non_ids) \
                    or a.get("deleted"):
                stats["skipped"] += 1
                continue
            atags = _tags(a)
            a_stamp = a.get("timestamp")
            a_last = float(a_stamp) if isinstance(a_stamp, (int, str)) and str(a_stamp).isdigit() else last
            out.append(Indicator(kind=kind, value=_misp_value(typ, value), confidence=conf, category=cat[:128],
                                 threat_actor=actor or _galaxy(atags, "threat-actor"),
                                 campaign=str(ev.get("info") or "")[:256], kill_chain_phase=_phase(atags + tags),
                                 diamond={k: v for k, v in (("adversary", actor), ("capability", capability),
                                                            ("infrastructure", value)) if v},
                                 first_seen=ts(a.get("first_seen")) or first,
                                 last_seen=ts(a.get("last_seen")) or a_last,
                                 stix_id=str(a.get("uuid") or ""), source=source))
    return out, stats


def parse_otx(data, source: str = "otx") -> tuple[list[Indicator], dict]:
    pulses = data.get("results") if isinstance(data, dict) and "results" in data else data
    pulses = pulses if isinstance(pulses, list) else [pulses]
    if len(pulses) > MAX_EVENTS:
        raise ValueError(f"more than {MAX_EVENTS} OTX pulses")
    out: list[Indicator] = []
    stats = {"pulses": 0, "indicators": 0, "skipped": 0}
    for p in pulses:
        if not isinstance(p, dict):
            continue
        stats["pulses"] += 1
        actor = str(p.get("adversary") or "")[:256]
        fams = p.get("malware_families") or []
        capability = str(fams[0].get("display_name") if fams and isinstance(fams[0], dict) else (fams[0] if fams else ""))
        tags = [str(t) for t in p.get("tags") or []]
        phase = next((t.split(":", 1)[1] for t in tags if t.lower().startswith("kill-chain:")), "")
        cat = capability or (tags[0] if tags else "") or "OTX"
        modified = ts(p.get("modified"))
        for ind in p.get("indicators") or []:
            if not isinstance(ind, dict) or stats["indicators"] >= MAX_ATTRS:
                continue
            stats["indicators"] += 1
            kind = _OTX_KIND.get(str(ind.get("type") or ""))
            value = ind.get("indicator")
            if kind is None or not isinstance(value, str) or ind.get("is_active") == 0:
                stats["skipped"] += 1
                continue
            out.append(Indicator(kind=kind, value=value, confidence=0.6, category=cat[:128], threat_actor=actor,
                                 campaign=str(p.get("name") or "")[:256], kill_chain_phase=phase,
                                 diamond={k: v for k, v in (("adversary", actor), ("capability", capability),
                                                            ("infrastructure", value)) if v},
                                 first_seen=ts(ind.get("created")) or ts(p.get("created")),
                                 last_seen=modified or ts(ind.get("created")),
                                 valid_until=ts(ind.get("expiration")),
                                 stix_id=f"otx:{ind.get('id')}" if ind.get("id") is not None else "", source=source))
    return out, stats


# ------------------------------------------------------------------------------- connectors

def _key(cfg: dict) -> str:
    import os
    env = cfg.get("key_env")
    key = os.environ.get(env, "") if env else ""
    if not key:
        raise ValueError(f"feed {cfg.get('name')}: set the API key in the environment variable named by key_env")
    return key


def pull_misp(cfg: dict, cursor: str | None, get=http_get):
    """MISP ``/attributes/restSearch`` since the cursor (epoch seconds). Returns (indicators, cursor)."""
    url = cfg["url"].rstrip("/") + "/events/restSearch"
    body = {"returnFormat": "json", "to_ids": True, "published": True, "limit": int(cfg.get("page_size", 500)),
            "page": 1}
    if cursor:
        body["timestamp"] = cursor
    headers = {"Authorization": _key(cfg), "Accept": "application/json", "Content-Type": "application/json"}
    inds: list[Indicator] = []
    newest = int(cursor) if cursor and str(cursor).isdigit() else 0
    for page in range(1, int(cfg.get("max_pages", 200)) + 1):
        body["page"] = page
        status, _h, raw = get(url, headers, data=json.dumps(body).encode())
        if status != 200:
            raise ValueError(f"MISP {url}: HTTP {status}")
        data = json.loads(raw or b"{}")
        events = data.get("response", data) if isinstance(data, dict) else data
        if not events:
            break
        got, _ = parse_misp(events, cfg.get("name", "misp"), bool(cfg.get("include_non_ids")))
        inds.extend(got)
        for ev in events:
            e = ev.get("Event", ev) if isinstance(ev, dict) else {}
            t = e.get("timestamp")
            if isinstance(t, (int, str)) and str(t).isdigit():
                newest = max(newest, int(t))
        if len(events) < body["limit"]:
            break
    return inds, str(newest) if newest else cursor


def pull_otx(cfg: dict, cursor: str | None, get=http_get):
    """OTX ``/api/v1/pulses/subscribed?modified_since=cursor``. Returns (indicators, cursor)."""
    base = cfg.get("url") or "https://otx.alienvault.com"
    q = {"limit": str(int(cfg.get("page_size", 50)))}
    if cursor:
        q["modified_since"] = cursor
    url = base.rstrip("/") + "/api/v1/pulses/subscribed?" + urllib.parse.urlencode(q)
    headers = {"X-OTX-API-KEY": _key(cfg), "Accept": "application/json"}
    inds: list[Indicator] = []
    newest = cursor
    for _ in range(int(cfg.get("max_pages", 200))):
        status, _h, raw = get(url, headers)
        if status != 200:
            raise ValueError(f"OTX: HTTP {status}")
        data = json.loads(raw or b"{}")
        got, _ = parse_otx(data, cfg.get("name", "otx"))
        inds.extend(got)
        for p in data.get("results") or []:
            m = p.get("modified") if isinstance(p, dict) else None
            if isinstance(m, str) and (newest is None or m > newest):
                newest = m
        url = data.get("next")
        if not url or not str(url).startswith(base.rstrip("/")):
            break
    return inds, newest
