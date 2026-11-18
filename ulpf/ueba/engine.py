"""
The UEBA engine: identity and asset resolution, smart timelines and behaviour anomalies over
the event projections the workers send the host.

``observe(projections)`` -> anomalies. For every event: the actor (all user identifiers of the
event, resolved and linked), the assets (IP bindings learned, CMDB context), the session the
event belongs to (a gap longer than ``session_gap`` starts a new one), and the detectors:

* impossible_travel: consecutive geolocated logons farther apart than ``travel_min_km`` at more
  than ``travel_max_kmh`` (pairs of a batch computed in one vector operation);
* unusual_hour: a logon at an hour rare for the actor (after ``warmup_logons``) and for the peer group;
* egress_spike: today's bytes out above the actor's mean + 3 sigma of the last 14 days and 10x
  the peer-group median (at least ``egress_min_bytes``);
* rare_application: an application the actor never used and fewer than 5% of the peers use;
* first_asset_access: a first access (after warmup) to an asset of criticality >= 3;
* abnormal_privilege: privilege use (sudo / runas / special privileges) above the actor's
  daily baseline, or the first ever after warmup;
* privileged_api_first_use: a first IAM / role / policy API call by the actor;
* token_reuse: one session token used from addresses in different /16 networks or countries.

Each anomaly fires once per key (actor + kind + subject [+ day]). Profiles, identities, asset
bindings and timelines are bounded in memory and persisted in SQLite (``<data dir>/ueba``).
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import math
import os
import re
import time
import uuid

from ulpf.ueba.assets import AssetCMDB
from ulpf.ueba.identity import IdentityGraph, parse_identity
from ulpf.ueba.models import LOGON, PeerGroups, Profile, _bounded_add, activity, travel
from ulpf.ueba.store import LRU, Store, dumps


def _ts(p: dict) -> float | None:
    t = p.get("timestamp")
    if isinstance(t, (int, float)):
        return float(t)
    if not t:
        return None
    try:
        v = _dt.datetime.fromisoformat(str(t).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (v if v.tzinfo else v.replace(tzinfo=_dt.timezone.utc)).timestamp()


def _day(ts: float) -> str:
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%d")


def _net16(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return ".".join(ip.split(".")[:2]) if a.version == 4 else ip.split(":")[0]


_MSG_USER = [re.compile(x) for x in (
    r"^\s*(?:sudo:\s*)?([\w.\@-]+) : (?:TTY|PWD|USER)=",          # sudo
    r"for (?:invalid user )?([\w.\@-]+) from \d",              # sshd
    r"(?:user|account|login)[=:]\s*\"?([\w.\@-]+)")]


def identifiers(p: dict) -> list:
    u = p.get("user") or {}
    if not (u.get("name") or u.get("email") or u.get("id")):
        msg = p.get("message") or ""
        for rx in _MSG_USER:                       # identity only in the text (sudo, sshd, key=value)
            m = rx.search(msg)
            if m:
                return [m.group(1)]
        return []
    out = [u.get("name"), u.get("email"), u.get("id")]
    if u.get("domain") and u.get("name") and "\\" not in str(u["name"]) and "@" not in str(u["name"]):
        out[0] = f"{u['domain']}\\{u['name']}"
    src = u.get("source") or {}
    out.append(src.get("name") if isinstance(src, dict) else None)
    return [x for x in out if x]


class UebaEngine:
    def __init__(self, data_dir: str | None = None, opts: dict | None = None):
        o = opts or {}
        path = os.path.join(data_dir, "ueba", "ueba.db") if data_dir else None
        self.store = Store(path)
        self.ident = IdentityGraph(self.store, o.get("realm_aliases"), o.get("identity_cache", 100_000))
        self.assets = AssetCMDB(self.store, o.get("zones"), o.get("asset_cache", 50_000))
        self.profiles = LRU(o.get("profile_cache", 50_000), self._save_profile)
        self.peers = PeerGroups()
        self.gap = float(o.get("session_gap_minutes", 30)) * 60
        self.warm_logons = int(o.get("warmup_logons", 30))
        self.warm_events = int(o.get("warmup_events", 100))
        self.max_kmh = float(o.get("travel_max_kmh", 900))
        self.min_km = float(o.get("travel_min_km", 500))
        self.egress_min = float(o.get("egress_min_bytes", 100 * 2**20))
        self.timeline_rows = int(o.get("timeline_rows_per_actor", 2000))
        self.recluster_s = float(o.get("recluster_minutes", 15)) * 60
        self.anomalies: list = []
        self.stats = {"events": 0, "actors_seen": 0, "anomalies": 0, "sessions": 0}
        self._last_maint = 0.0
        for f, imp in ((o.get("directory"), self._import_dir), (o.get("cmdb"), self.assets.import_csv)):
            if f and os.path.exists(f):
                imp(f)

    def _import_dir(self, path: str) -> int:
        with open(path, encoding="utf-8") as f:
            if path.endswith(".csv"):
                import csv
                rows = []
                for r in csv.DictReader(f):
                    r["aliases"] = [x.strip() for x in (r.get("aliases") or "").replace(";", ",").split(",") if x.strip()]
                    rows.append(r)
            else:
                rows = json.load(f)
        return self.ident.import_directory(rows)

    # ---- profiles
    def _save_profile(self, actor, prof: Profile) -> None:
        self.store.queue("INSERT OR REPLACE INTO profiles VALUES (?, ?)", (actor, dumps(prof.to_doc())))

    def profile(self, actor: str) -> Profile:
        p = self.profiles.get(actor)
        if p is None:
            row = self.store.one("SELECT doc FROM profiles WHERE actor = ?", (actor,))
            p = Profile.from_doc(json.loads(row[0])) if row else Profile(actor)
            if not row:
                self.stats["actors_seen"] += 1
            self.profiles.put(actor, p)
        return p

    # ---- observe
    def observe(self, projections: list[dict]) -> list[dict]:
        out: list[dict] = []
        travel_prev, travel_cur, travel_ctx = [], [], []
        for p in projections:
            ts = _ts(p)
            if ts is None:
                continue
            self.stats["events"] += 1
            src, dev = p.get("source") or {}, p.get("device") or {}
            for ip, host, mac in ((src.get("ip"), src.get("hostname"), src.get("mac")),
                                  (dev.get("ip"), dev.get("hostname"), None)):
                if ip and (host or mac):
                    self.assets.observe(ip, ts, mac=mac, hostname=host, source=p.get("raw_format") or "")
            ids = identifiers(p)
            if not ids:
                continue
            actor = self.ident.resolve(ids, ts)
            if actor is None:
                continue
            prof = self.profile(actor)
            if not prof.first:
                prof.first = ts
            prof.events += 1
            act = activity(p)
            self._session(prof, p, ts, act)
            host = (dev.get("hostname") or (p.get("destination") or {}).get("hostname") or "")
            host = str(host).lower()
            warm = prof.events > self.warm_events
            # first access to a critical asset
            if host and _bounded_add(prof.assets, host, ts, 2000) and warm:
                ctx = self.assets.resolve(dev.get("ip"), host, ts)
                crit = ctx.get("criticality") or 0
                if crit >= 3:
                    out += self._flag(prof, "first_asset_access", host, ts, 20 * crit, p,
                                      {"asset": host, "criticality": crit, "owner": ctx.get("owner"),
                                       "zone": ctx.get("zone")})
            # applications
            app = str(dev.get("product") or "").lower()
            if app:
                if app not in prof.apps and warm and self.peers.group_of.get(actor):
                    prev = self.peers.app_prevalence(actor, app)
                    if prev is not None and prev < 0.05:
                        out += self._flag(prof, "rare_application", app, ts, 25, p,
                                          {"application": app, "peer_prevalence": round(prev, 3),
                                           "peer_group": self.peers.group_of.get(actor)})
                prof.apps[app] = prof.apps.get(app, 0) + 1
                if len(prof.apps) > 300:
                    prof.apps.pop(min(prof.apps, key=prof.apps.get))
            day = _day(ts)
            # logons: hours, geography
            if act in LOGON:
                hour = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).hour
                if prof.logons >= self.warm_logons:
                    mine = (prof.hours[hour] + 1) / (prof.logons + 24)
                    peer = self.peers.hour_share(actor, hour)
                    if mine < 0.02 and (peer is None or peer < 0.05):
                        out += self._flag(prof, "unusual_hour", f"{day}:{hour}", ts, 20, p,
                                          {"hour_utc": hour, "actor_share": round(mine, 4),
                                           "peer_share": None if peer is None else round(peer, 4)})
                prof.hours[hour] += 1
                prof.logons += 1
                geo = p.get("geo") or {}
                lat, lon = geo.get("src_latitude"), geo.get("src_longitude")
                if lat is not None and lon is not None:
                    cur = [float(lat), float(lon), ts, src.get("ip"), geo.get("src_country_code")]
                    if prof.last_geo and ts >= prof.last_geo[2]:
                        travel_prev.append(prof.last_geo)
                        travel_cur.append(cur)
                        travel_ctx.append((prof, p))
                    prof.last_geo = cur
            # privilege use
            if act == "privilege":
                hist = [v for d, v in prof.sudo.items() if d != day][-14:]
                today = prof.sudo.get(day, 0) + 1
                prof.sudo[day] = today
                while len(prof.sudo) > 30:
                    prof.sudo.pop(next(iter(prof.sudo)))
                if warm:
                    if not hist and today == 1 and prof.events > self.warm_events * 2:
                        out += self._flag(prof, "abnormal_privilege", f"first:{day}", ts, 30, p,
                                          {"reason": "first privilege use", "count_today": today})
                    elif len(hist) >= 3:
                        mean = sum(hist) / len(hist)
                        sd = math.sqrt(sum((x - mean) ** 2 for x in hist) / len(hist))
                        if today > mean + 3 * max(sd, 1.0):
                            out += self._flag(prof, "abnormal_privilege", day, ts, 35, p,
                                              {"reason": "privilege use above baseline", "count_today": today,
                                               "baseline_mean": round(mean, 2)})
            if act == "cloud_api":
                api = str(p.get("event_type") or p.get("message") or "")[:120]
                if _bounded_add(prof.apis, api, ts, 500) and prof.events > 1:
                    out += self._flag(prof, "privileged_api_first_use", api, ts, 40, p, {"api": api})
            # egress
            b = (p.get("network") or {}).get("bytes_out")
            try:
                b = float(b) if b is not None else 0.0
            except (TypeError, ValueError):
                b = 0.0
            if b > 0:
                prof.egress[day] = prof.egress.get(day, 0.0) + b
                while len(prof.egress) > 30:
                    prof.egress.pop(next(iter(prof.egress)))
                hist = [v for d, v in prof.egress.items() if d != day][-14:]
                today = prof.egress[day]
                if len(hist) >= 3 and today >= self.egress_min:
                    mean = sum(hist) / len(hist)
                    sd = math.sqrt(sum((x - mean) ** 2 for x in hist) / len(hist))
                    med = self.peers.egress_median.get(self.peers.group_of.get(actor, ""), 0.0)
                    if today > mean + 3 * sd and today > 10 * max(med, mean / 10):
                        out += self._flag(prof, "egress_spike", day, ts, 40, p,
                                          {"bytes_today": int(today), "baseline_mean": int(mean),
                                           "peer_median": int(med)})
            # token reuse from distant places
            tok = (p.get("network") or {}).get("session_id")
            ip = src.get("ip")
            if tok and ip:
                ips = prof.tokens.setdefault(str(tok), [])
                if ip not in ips:
                    ips.append(ip)
                    country = (p.get("geo") or {}).get("src_country_code")
                    nets = {_net16(x) for x in ips}
                    if len(nets) > 1:
                        out += self._flag(prof, "token_reuse", str(tok), ts, 45, p,
                                          {"token": str(tok)[:64], "addresses": ips[:10], "country": country})
                if len(prof.tokens) > 200:
                    prof.tokens.pop(next(iter(prof.tokens)))
        # impossible travel: every pair of this batch in one vector computation
        for (km, kmh), prev, cur, (prof, p) in zip(travel(travel_prev, travel_cur), travel_prev, travel_cur, travel_ctx):
            if km >= self.min_km and kmh > self.max_kmh:
                out += self._flag(prof, "impossible_travel", f"{prev[3]}->{cur[3]}:{int(cur[2])}", cur[2], 60, p,
                                  {"distance_km": round(km, 1), "speed_kmh": round(kmh, 1),
                                   "from": {"ip": prev[3], "country": prev[4], "time": prev[2]},
                                   "to": {"ip": cur[3], "country": cur[4], "time": cur[2]}})
        self.maintenance(time.time())
        return out

    def _session(self, prof: Profile, p: dict, ts: float, act: str) -> None:
        s = prof.session
        if s is None or ts - s[2] > self.gap or ts < s[1] - self.gap:
            s = prof.session = [uuid.uuid4().hex[:12], ts, ts, []]
            self.stats["sessions"] += 1
        s[2] = max(s[2], ts)
        if not s[3] or s[3][-1] != act:
            s[3].append(act)
            if len(s[3]) > 50:
                s[3].pop(0)
        src, dev = p.get("source") or {}, p.get("device") or {}
        row = {"event_id": p.get("event_id"), "activity": act, "action": p.get("action"),
               "category": p.get("category"), "host": dev.get("hostname"), "ip": src.get("ip"),
               "app": dev.get("product"), "message": (p.get("message") or "")[:200]}
        self.store.queue("INSERT INTO timeline VALUES (?, ?, ?, ?, ?)", (prof.actor, ts, s[0], act, dumps(row)))

    def _flag(self, prof: Profile, kind: str, subject: str, ts: float, score: float, p: dict, detail: dict) -> list:
        key = f"{kind}:{subject}"
        if key in prof.flagged:
            return []
        prof.flagged[key] = ts
        if len(prof.flagged) > 1000:
            prof.flagged.pop(next(iter(prof.flagged)))
        attrs = self.ident.attributes(prof.actor)
        a = {"kind": kind, "actor": prof.actor, "display": attrs.get("display_name") or _display(prof.actor),
             "score": score, "time": ts, "event_id": p.get("event_id"), "session": (prof.session or [None])[0],
             "peer_group": self.peers.group_of.get(prof.actor), "detail": detail,
             "host": (p.get("device") or {}).get("hostname"), "ip": (p.get("source") or {}).get("ip")}
        self.anomalies.append(a)
        if len(self.anomalies) > 5000:
            del self.anomalies[:1000]
        self.stats["anomalies"] += 1
        self.store.queue("INSERT INTO anomalies VALUES (?, ?, ?, ?, ?)", (ts, prof.actor, kind, score, dumps(a)))
        return [a]

    # ---- maintenance
    def maintenance(self, now: float, force: bool = False) -> None:
        if not force and now - self._last_maint < 30:
            return
        self._last_maint = now
        for actor, prof in self.profiles.items():
            self._save_profile(actor, prof)
        self.store.flush()
        if force or now - self.peers.built_at > self.recluster_s:
            profs = list(self.profiles.values())
            self.peers.build(profs, self.ident.attributes, now=now)
        with self.store.lock:                      # bounded timelines
            self.store.db.execute(
                "DELETE FROM timeline WHERE rowid IN (SELECT rowid FROM (SELECT rowid, row_number() OVER "
                "(PARTITION BY actor ORDER BY ts DESC) AS n FROM timeline) WHERE n > ?)", (self.timeline_rows,))
            self.store.db.execute("DELETE FROM anomalies WHERE rowid NOT IN (SELECT rowid FROM anomalies "
                                  "ORDER BY ts DESC LIMIT 100000)")

    def close(self) -> None:
        self.maintenance(time.time(), force=True)
        self.store.close()

    # ---- views
    def actor_view(self, identifier: str) -> dict | None:
        i = parse_identity(identifier)
        actor = self.ident.actor_of(i.key) if i else None
        if actor is None and identifier.startswith(("plain:", "ad:", "upn:", "kerberos:", "dn:", "aws_", "linux:")):
            actor = self.ident.actor_of(identifier)
        if actor is None:
            return None
        prof = self.profile(actor)
        return {"actor": actor, "display": self.ident.attributes(actor).get("display_name") or _display(actor),
                "aliases": self.ident.aliases(actor), "attributes": self.ident.attributes(actor),
                "peer_group": self.peers.group_of.get(actor), "events": prof.events, "logons": prof.logons,
                "logon_hours_utc": prof.hours, "assets": list(prof.assets)[-50:],
                "applications": dict(sorted(prof.apps.items(), key=lambda kv: -kv[1])[:30]),
                "last_geo": prof.last_geo, "session": prof.session}

    def timeline(self, identifier: str, limit: int = 500) -> dict | None:
        v = self.actor_view(identifier)
        if v is None:
            return None
        self.store.flush()
        rows = self.store.all("SELECT ts, session, activity, doc FROM timeline WHERE actor = ? ORDER BY ts DESC LIMIT ?",
                              (v["actor"], int(limit)))
        sessions: dict[str, dict] = {}
        for ts, sid, act, doc in reversed(rows):
            s = sessions.setdefault(sid, {"session": sid, "start": ts, "end": ts, "steps": [], "events": []})
            s["end"] = ts
            if not s["steps"] or s["steps"][-1] != act:
                s["steps"].append(act)
            s["events"].append({"ts": ts, **json.loads(doc)})
        anomalies = [a for a in self.anomalies if a["actor"] == v["actor"]][-100:]
        for a in anomalies:
            if a["session"] in sessions:
                sessions[a["session"]].setdefault("anomalies", []).append(a["kind"])
        return {"actor": v["actor"], "display": v["display"], "sessions": list(sessions.values()), "anomalies": anomalies}

    def asset_view(self, ip: str, ts: float | None = None) -> dict:
        return {**self.assets.resolve(ip, None, ts), "history": self.assets.history(ip)}


def _display(actor: str) -> str:
    return actor.split(":")[-1]
