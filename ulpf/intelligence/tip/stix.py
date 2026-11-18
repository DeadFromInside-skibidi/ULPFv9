"""
STIX 2.1 bundles and TAXII 2.1 collections.

``parse_bundle`` turns a bundle (``indicator`` objects with STIX patterns, plus the threat actors,
intrusion sets, campaigns, malware and identities their ``indicates`` / ``attributed-to`` /
``targets`` relationships point at) into ``Indicator`` rows. Pattern comparisons understood:

  [ipv4-addr:value = '1.2.3.4']  [ipv6-addr:value = '..']  [ipv4-addr:value ISSUBSET '10.0.0.0/8']
  [domain-name:value = 'evil.com']  [domain-name:value LIKE '%.evil.com']  [url:value = '..']
  [file:hashes.MD5 | 'SHA-1' | 'SHA-256' = '..']  [email-addr:value = '..']
  [email-message:from_ref.value = '..']  [mutex:name = '..']  [windows-registry-key:key = '..']
  [network-traffic:dst_ref.value = '..']  [x-...:value = '..'] (kind guessed)

joined by OR / AND (every equality becomes an indicator; an AND of different observables is
over-broad, so only its file hashes are taken), FOLLOWEDBY and qualifiers are ignored.
Patterns are parsed by a linear scanner (no regular expressions on feed input).

``TaxiiClient`` pulls a collection's objects page by page from a cursor (``added_after`` = the last
``X-TAXII-Date-Added-Last``), as TAXII 2.1 section 3.4 / 5.4 describe.
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.parse
from datetime import datetime, timezone

from ulpf.intelligence.tip.indicators import Indicator

MAX_PATTERN = 8192
MAX_OBJECTS = 2_000_000
TAXII_MEDIA = "application/taxii+json;version=2.1"

_OBJECT_KIND = {
    ("ipv4-addr", "value"): "ip", ("ipv6-addr", "value"): "ip", ("domain-name", "value"): "domain",
    ("url", "value"): "url", ("email-addr", "value"): "email", ("email-message", "from_ref.value"): "email",
    ("email-message", "sender_ref.value"): "email", ("mutex", "name"): "mutex",
    ("windows-registry-key", "key"): "registry", ("network-traffic", "dst_ref.value"): "ip",
    ("network-traffic", "src_ref.value"): "ip", ("file", "hashes.md5"): "md5", ("file", "hashes.sha-1"): "sha1",
    ("file", "hashes.sha1"): "sha1", ("file", "hashes.sha-256"): "sha256", ("file", "hashes.sha256"): "sha256",
}


class StixError(ValueError):
    pass


def ts(s) -> float | None:
    """RFC 3339 timestamp -> epoch seconds (None when absent / invalid)."""
    if not s or not isinstance(s, str):
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()
    except ValueError:
        return None


# ------------------------------------------------------------------------------- patterns

def _comparisons(pattern: str):
    """(object type, property path, operator, value, joiner before it) of each comparison."""
    if len(pattern) > MAX_PATTERN:
        raise StixError("pattern too long")
    out = []
    i, n = 0, len(pattern)
    joiner = None
    while i < n:
        c = pattern[i]
        if c in " \t\r\n[]()":
            i += 1
            continue
        if c == "'":                                   # stray literal (qualifier argument)
            j = i + 1
            while j < n and pattern[j] != "'":
                j += 2 if pattern[j] == "\\" else 1
            i = j + 1
            continue
        j = i
        while j < n:
            if pattern[j] == "'" and j > i and pattern[j - 1] == ".":     # hashes.'SHA-256'
                k = pattern.find("'", j + 1)
                if k < 0:
                    break
                j = k + 1
                continue
            if pattern[j] in " \t\r\n[]()'=!<>":
                break
            j += 1
        if j == i:                                     # a lone operator character
            i += 1
            continue
        word = pattern[i:j]
        i = j
        up = word.upper()
        if up in ("OR", "AND", "FOLLOWEDBY"):
            joiner = up
            continue
        if up in ("WITHIN", "REPEATS", "TIMES", "START", "STOP", "SECONDS"):
            continue
        if ":" not in word:
            continue
        obj, _, path = word.partition(":")
        while i < n and pattern[i] in " \t":
            i += 1
        k = i
        if k < n and pattern[k] in "=!<>":
            while k < n and pattern[k] in "=!<>":
                k += 1
        else:
            while k < n and pattern[k] not in " \t'":
                k += 1
        op = pattern[i:k].upper()
        i = k
        if op == "NOT":                                # NOT = / NOT LIKE: negative, never an indicator
            while i < n and pattern[i] in " \t":
                i += 1
            k = i
            while k < n and pattern[k] not in " \t'":
                k += 1
            i = k
            op = "NOT"
        while i < n and pattern[i] in " \t":
            i += 1
        if i >= n or pattern[i] != "'":
            continue                                   # (IN (...) lists, numbers: not indicators)
        j = i + 1
        buf = []
        while j < n and pattern[j] != "'":
            if pattern[j] == "\\" and j + 1 < n:
                j += 1
            buf.append(pattern[j])
            j += 1
        i = j + 1
        out.append((obj.lower(), path, op, "".join(buf), joiner))
        joiner = None
    return out


def _prop_key(path: str) -> str:
    """hashes.'SHA-256' -> hashes.sha-256"""
    return path.replace("'", "").replace('"', "").lower()


def pattern_indicators(pattern: str) -> list[tuple[str, str]]:
    """(kind, value) of each indicator a STIX pattern names."""
    comps = _comparisons(pattern)
    has_and = any(c[4] == "AND" for c in comps)
    out = []
    for obj, path, op, value, _j in comps:
        kind = _OBJECT_KIND.get((obj, _prop_key(path)))
        if kind is None and obj.startswith("x-") and _prop_key(path) == "value":
            kind = "auto"
        if kind is None or op == "NOT":
            continue
        if has_and and kind not in ("md5", "sha1", "sha256"):
            continue
        if op == "=":
            out.append((kind, value))
        elif op == "ISSUBSET" and kind == "ip":
            out.append(("cidr", value))
        elif op == "LIKE" and kind == "domain" and value.startswith("%.") and "%" not in value[2:] \
                and "_" not in value[2:]:
            out.append(("domain_wildcard", value[2:]))
    return out


# ------------------------------------------------------------------------------- bundles

def _name(obj) -> str:
    return str(obj.get("name") or "")[:256] if isinstance(obj, dict) else ""


def parse_bundle(bundle, source: str = "stix") -> tuple[list[Indicator], dict]:
    """Indicators of a STIX 2.1 bundle (dict, or a list of objects). Returns (indicators, stats)."""
    objs = bundle.get("objects") if isinstance(bundle, dict) else bundle
    if not isinstance(objs, list):
        raise StixError("not a STIX bundle (no objects list)")
    if len(objs) > MAX_OBJECTS:
        raise StixError(f"bundle has more than {MAX_OBJECTS} objects")
    by_id = {o["id"]: o for o in objs if isinstance(o, dict) and isinstance(o.get("id"), str)}
    rel: dict[str, list] = {}
    for o in objs:
        if isinstance(o, dict) and o.get("type") == "relationship":
            s, t = o.get("source_ref"), o.get("target_ref")
            if isinstance(s, str) and isinstance(t, str):
                rel.setdefault(s, []).append((str(o.get("relationship_type") or ""), t))
    stats = {"objects": len(objs), "indicators": 0, "patterns_skipped": 0, "revoked": []}

    def context(ind_id: str) -> dict:
        ctx = {"actor": "", "campaign": "", "capability": "", "victim": ""}
        seen = set()
        todo = [(ind_id, 0)]
        while todo:                                     # indicator -> malware / campaign -> actor (depth 3)
            ref, depth = todo.pop()
            if ref in seen or depth > 3:
                continue
            seen.add(ref)
            for rtype, tgt in rel.get(ref, ()):
                t = by_id.get(tgt)
                if t is None:
                    continue
                typ = t.get("type")
                if typ in ("threat-actor", "intrusion-set") and not ctx["actor"]:
                    ctx["actor"] = _name(t)
                elif typ == "campaign" and not ctx["campaign"]:
                    ctx["campaign"] = _name(t)
                elif typ in ("malware", "tool") and not ctx["capability"]:
                    ctx["capability"] = _name(t)
                elif typ == "identity" and rtype == "targets" and not ctx["victim"]:
                    ctx["victim"] = _name(t)
                if rtype in ("indicates", "attributed-to", "uses", "related-to", "targets"):
                    todo.append((tgt, depth + 1))
        return ctx

    out: list[Indicator] = []
    for o in objs:
        if not isinstance(o, dict) or o.get("type") != "indicator":
            continue
        if o.get("revoked"):
            stats["revoked"].append(o.get("id"))
            continue
        pat = o.get("pattern")
        if not isinstance(pat, str) or (o.get("pattern_type") or "stix") != "stix":
            stats["patterns_skipped"] += 1
            continue
        try:
            pairs = pattern_indicators(pat)
        except StixError:
            stats["patterns_skipped"] += 1
            continue
        if not pairs:
            stats["patterns_skipped"] += 1
            continue
        ctx = context(o["id"]) if isinstance(o.get("id"), str) else {}
        conf = o.get("confidence")
        conf = min(1.0, max(0.0, conf / 100.0)) if isinstance(conf, (int, float)) and not isinstance(conf, bool) \
            else 0.5
        types = o.get("indicator_types") or o.get("labels") or []
        cat = (str(types[0]) if isinstance(types, list) and types else "") or ctx.get("capability") or "Unknown"
        phases = o.get("kill_chain_phases") or []
        phase = str(phases[0].get("phase_name") or "") if isinstance(phases, list) and phases and \
            isinstance(phases[0], dict) else ""
        first = ts(o.get("valid_from")) or ts(o.get("created"))
        last = ts(o.get("modified")) or first
        for kind, value in pairs:
            out.append(Indicator(kind=kind, value=value, confidence=conf, category=cat[:128],
                                 threat_actor=ctx.get("actor", ""), campaign=ctx.get("campaign", ""),
                                 kill_chain_phase=phase,
                                 diamond={k: v for k, v in (("adversary", ctx.get("actor")),
                                                            ("capability", ctx.get("capability")),
                                                            ("infrastructure", value),
                                                            ("victim", ctx.get("victim"))) if v},
                                 first_seen=first, last_seen=last, valid_until=ts(o.get("valid_until")),
                                 stix_id=str(o.get("id") or ""), source=source))
    stats["indicators"] = len(out)
    return out, stats


def load_bundle_file(path: str, source: str | None = None, max_bytes: int = 1 << 30):
    size = os.path.getsize(path)
    if size > max_bytes:
        raise StixError(f"{path}: {size} bytes is more than the {max_bytes} byte limit")
    with open(path, "rb") as f:
        try:
            data = json.loads(f.read())
        except (ValueError, RecursionError) as e:
            raise StixError(f"{path}: not JSON ({e})") from None
    return parse_bundle(data, source or "stix:" + os.path.basename(path))


# ------------------------------------------------------------------------------- TAXII 2.1

def http_get(url: str, headers: dict, timeout: float = 60, max_bytes: int = 256 << 20, data: bytes | None = None):
    """GET (or POST with ``data``) with a bounded response body. Returns (status, headers, body)."""
    import urllib.request
    if urllib.parse.urlsplit(url).scheme not in ("https", "http"):
        raise ValueError(f"unsupported URL scheme: {url}")
    req = urllib.request.Request(url, headers=headers, data=data, method="POST" if data is not None else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 (scheme checked above)
        body = r.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise ValueError(f"{url}: response larger than {max_bytes} bytes")
        return r.status, dict(r.headers), body


def auth_headers(cfg: dict) -> dict:
    """Credentials come from environment variables named in the config, never the config itself."""
    h = {}
    tok = os.environ.get(cfg.get("token_env") or "", "") if cfg.get("token_env") else ""
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    user_env, pass_env = cfg.get("username_env"), cfg.get("password_env")
    if user_env and pass_env and os.environ.get(user_env):
        cred = f"{os.environ[user_env]}:{os.environ.get(pass_env, '')}".encode()
        h["Authorization"] = "Basic " + base64.b64encode(cred).decode()
    return h


class TaxiiClient:
    """One TAXII 2.1 collection: ``url`` = .../{api-root}/collections/{id}/"""

    def __init__(self, cfg: dict, get=http_get):
        self.url = cfg["url"].rstrip("/") + "/"
        self.cfg = cfg
        self.page = int(cfg.get("page_size", 1000))
        self.max_pages = int(cfg.get("max_pages", 1000))
        self.get = get

    def pull(self, cursor: str | None):
        """Objects added after ``cursor``; returns (objects, new cursor)."""
        headers = {"Accept": TAXII_MEDIA, **auth_headers(self.cfg)}
        objs: list = []
        nxt = None
        for _ in range(self.max_pages):
            q = {"limit": str(self.page)}
            if cursor:
                q["added_after"] = cursor
            if nxt:
                q["next"] = nxt
            if self.cfg.get("match_type"):
                q["match[type]"] = self.cfg["match_type"]
            status, h, body = self.get(self.url + "objects/?" + urllib.parse.urlencode(q), headers)
            if status != 200:
                raise StixError(f"TAXII {self.url}: HTTP {status}")
            env = json.loads(body or b"{}")
            page = env.get("objects") or []
            if not isinstance(page, list):
                raise StixError("TAXII envelope without an objects list")
            objs.extend(page)
            if len(objs) > MAX_OBJECTS:
                raise StixError(f"TAXII {self.url}: more than {MAX_OBJECTS} objects in one sync")
            last = {k.lower(): v for k, v in h.items()}.get("x-taxii-date-added-last")
            if last:
                cursor = last
            elif page:
                stamps = [o.get("modified") or o.get("created") for o in page if isinstance(o, dict)]
                stamps = [s for s in stamps if isinstance(s, str)]
                if stamps:
                    cursor = max(stamps)
            nxt = env.get("next")
            if not env.get("more") or not page:
                break
        return objs, cursor


def utc_now_iso() -> str:
    return datetime.fromtimestamp(time.time(), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
