"""
Behaviour models: activity classes, geo velocity, per-actor profiles and peer groups.

* ``activity(projection)``: the step an event is in a session (vpn_logon, mfa, ssh_logon, logon,
  logon_failure, privilege, db_query, cloud_storage, cloud_api, process, network, web, other).
* ``haversine_km`` / ``travel``: great-circle distance and speed over pyarrow arrays
  (vectorised over a batch of logons).
* ``Profile``: an actor's baseline (logon hours, assets, applications, daily egress and sudo
  counts, tokens) with bounded sets.
* ``PeerGroups``: actors grouped by directory department / role where known, else by k-means
  (k-means++ seeding, fixed seed: deterministic) over their behaviour vectors; per group the
  hour distribution, application prevalence and egress median.
"""
from __future__ import annotations

import math
import random
import re
from dataclasses import dataclass, field

import pyarrow as pa
import pyarrow.compute as pc

EARTH_KM = 6371.0088

_MFA = re.compile(r"(?i)\b(mfa|2fa|multi-?factor|duo|okta verify|push (?:approved|sent)|authenticator|otp)\b")
_VPN = re.compile(r"(?i)\b(vpn|globalprotect|anyconnect|openvpn|wireguard|fortisslvpn|pulse)\b")
_DB = re.compile(r"(?i)\b(mysql|mariadb|postgres(?:ql)?|mssql|sqlserver|oracle|mongodb|snowflake|redshift)\b")
_DB_STMT = re.compile(r"(?i)\b(select|insert|update|delete)\b.+\b(from|into|set)\b")
_STORAGE = re.compile(r"(?i)\b(s3|getobject|putobject|listbucket|copyobject|blob|gcs|storage\.objects|"
                      r"sharepoint|onedrive|dropbox|box\.com|aws s3 sync)\b")
_PRIV_API = re.compile(r"(?i)(createaccesskey|attachuserpolicy|attachrolepolicy|putuserpolicy|putrolepolicy|"
                       r"createuser|createloginprofile|updateassumerolepolicy|assumerole|addusertogroup|"
                       r"putbucketpolicy|deletetrail|stoplogging|setiampolicy|addmembertorole|"
                       r"add member to role|consent to application|reset user password)")
_SUDO = re.compile(r"(?i)(\bsudo\b|\bsu\[|\bsu:|runas|USER=root|privilege(?:d)? (?:use|escalat)|"
                   r"special privileges assigned)")
_SUCCESS = {"success", "allowed", "allow", "accepted", "permit", "login", "logon", "succeeded"}
_FAILURE = {"failure", "failed", "fail", "denied", "deny", "blocked", "rejected"}


def activity(p: dict) -> str:
    cat = (p.get("category") or "").lower()
    act = (p.get("action") or "").lower()
    prod = str((p.get("device") or {}).get("product") or "")
    text = f"{prod} {p.get('event_type') or ''} {p.get('message') or ''}"
    if _PRIV_API.search(text):
        return "cloud_api"
    if _SUDO.search(text):
        return "privilege"
    if _MFA.search(text):
        return "mfa"
    if cat == "vpn" or _VPN.search(prod) or (cat == "authentication" and _VPN.search(text)):
        return "vpn_logon" if act not in _FAILURE else "logon_failure"
    if cat == "authentication":
        if act in _FAILURE:
            return "logon_failure"
        return "ssh_logon" if "ssh" in prod.lower() else "logon"
    if _DB.search(prod) or _DB_STMT.search(text):
        return "db_query"
    if _STORAGE.search(text):
        return "cloud_storage"
    if cat in ("endpoint",):
        return "process"
    if cat in ("web", "proxy"):
        return "web"
    if cat in ("network", "firewall", "dns"):
        return "network"
    return "other"


LOGON = frozenset({"vpn_logon", "logon", "ssh_logon"})


def haversine_km(lat1, lon1, lat2, lon2) -> pa.Array:
    """Great-circle distance (km) element-wise over arrays of degrees."""
    r = math.pi / 180
    la1, lo1, la2, lo2 = (pc.multiply(pa.array(x, pa.float64()), r) for x in (lat1, lon1, lat2, lon2))
    dlat = pc.subtract(la2, la1)
    dlon = pc.subtract(lo2, lo1)
    a = pc.add(pc.power(pc.sin(pc.divide(dlat, 2)), 2),
               pc.multiply(pc.multiply(pc.cos(la1), pc.cos(la2)), pc.power(pc.sin(pc.divide(dlon, 2)), 2)))
    a = pc.min_element_wise(pc.max_element_wise(a, 0.0), 1.0)
    return pc.multiply(pc.multiply(pc.asin(pc.sqrt(a)), 2.0), EARTH_KM)


def travel(prev: list, cur: list) -> list[tuple[float, float]]:
    """[(km, km/h)] between paired (lat, lon, epoch) logons, computed as one vector operation."""
    if not prev:
        return []
    km = haversine_km([p[0] for p in prev], [p[1] for p in prev], [c[0] for c in cur], [c[1] for c in cur])
    hours = pc.divide(pc.max_element_wise(pc.abs(pc.subtract(pa.array([c[2] for c in cur], pa.float64()),
                                                            pa.array([p[2] for p in prev], pa.float64()))), 1.0),
                      3600.0)
    speed = pc.divide(km, hours)
    return list(zip(km.to_pylist(), speed.to_pylist()))


def _bounded_add(d: dict, k, v, cap: int) -> bool:
    """Add k (False if already there); the oldest entry goes when full."""
    if k in d:
        return False
    if len(d) >= cap:
        d.pop(next(iter(d)))
    d[k] = v
    return True


@dataclass
class Profile:
    actor: str
    first: float = 0.0
    events: int = 0
    logons: int = 0
    hours: list = field(default_factory=lambda: [0] * 24)
    last_geo: list | None = None              # [lat, lon, ts, ip, country]
    assets: dict = field(default_factory=dict)        # host -> first seen
    apps: dict = field(default_factory=dict)          # application -> count
    egress: dict = field(default_factory=dict)        # day -> bytes out
    sudo: dict = field(default_factory=dict)          # day -> privilege events
    apis: dict = field(default_factory=dict)          # privileged API -> first seen
    tokens: dict = field(default_factory=dict)        # session token -> [ips]
    session: list | None = None               # [id, start, last, steps]
    flagged: dict = field(default_factory=dict)       # anomaly key -> time (once per key)

    def to_doc(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}

    @classmethod
    def from_doc(cls, d: dict) -> "Profile":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def vector(self) -> list[float]:
        tot = sum(self.hours) or 1
        days = list(self.egress.values())[-14:]
        eg = math.log10(1 + (sum(days) / len(days) if days else 0))
        return [h / tot for h in self.hours] + [eg / 10, min(len(self.assets), 50) / 50, min(len(self.apps), 50) / 50]


def _dist2(a, b) -> float:
    return sum((x - y) ** 2 for x, y in zip(a, b))


def kmeans(vectors: list[list[float]], k: int, iters: int = 25, seed: int = 7) -> list[int]:
    """k-means with k-means++ seeding (deterministic); returns the cluster of each vector."""
    n = len(vectors)
    if n == 0:
        return []
    k = max(1, min(k, n))
    rnd = random.Random(seed)
    centers = [vectors[rnd.randrange(n)]]
    while len(centers) < k:
        d = [min(_dist2(v, c) for c in centers) for v in vectors]
        tot = sum(d)
        if tot == 0:
            break
        r, acc = rnd.random() * tot, 0.0
        for i, w in enumerate(d):
            acc += w
            if acc >= r:
                centers.append(vectors[i])
                break
    assign = [0] * n
    for _ in range(iters):
        changed = False
        for i, v in enumerate(vectors):
            j = min(range(len(centers)), key=lambda c: _dist2(v, centers[c]))
            if j != assign[i]:
                assign[i], changed = j, True
        for c in range(len(centers)):
            members = [vectors[i] for i in range(n) if assign[i] == c]
            if members:
                centers[c] = [sum(col) / len(members) for col in zip(*members)]
        if not changed:
            break
    return assign


class PeerGroups:
    def __init__(self):
        self.group_of: dict[str, str] = {}
        self.hours: dict[str, list] = {}
        self.apps: dict[str, dict] = {}
        self.size: dict[str, int] = {}
        self.egress_median: dict[str, float] = {}
        self.built_at = 0.0

    def build(self, profiles: list[Profile], attrs_of, min_events: int = 20, now: float = 0.0) -> None:
        """Directory groups (department / role) first; the rest clustered by behaviour."""
        group_of: dict[str, str] = {}
        rest = []
        for p in profiles:
            a = attrs_of(p.actor) or {}
            dept = a.get("department") or a.get("role") or a.get("title")
            if dept:
                group_of[p.actor] = f"dept:{str(dept).lower()}"
            elif p.events >= min_events:
                rest.append(p)
        if rest:
            k = max(1, min(20, int(math.sqrt(len(rest) / 2)) or 1))
            for p, c in zip(rest, kmeans([p.vector() for p in rest], k)):
                group_of[p.actor] = f"cluster:{c}"
        hours, apps, size, egress = {}, {}, {}, {}
        by = {p.actor: p for p in profiles}
        for actor, g in group_of.items():
            p = by[actor]
            h = hours.setdefault(g, [0] * 24)
            for i, x in enumerate(p.hours):
                h[i] += x
            for app in p.apps:
                apps.setdefault(g, {})[app] = apps.get(g, {}).get(app, 0) + 1
            size[g] = size.get(g, 0) + 1
            days = list(p.egress.values())[-14:]
            if days:
                egress.setdefault(g, []).append(sum(days) / len(days))
        self.group_of, self.hours, self.apps, self.size = group_of, hours, apps, size
        self.egress_median = {g: sorted(v)[len(v) // 2] for g, v in egress.items()}
        self.built_at = now

    def hour_share(self, actor: str, hour: int) -> float | None:
        g = self.group_of.get(actor)
        if g is None:
            return None
        h = self.hours[g]
        tot = sum(h)
        return (h[hour] + 1) / (tot + 24) if tot else None

    def app_prevalence(self, actor: str, app: str) -> float | None:
        g = self.group_of.get(actor)
        if g is None or not self.size.get(g):
            return None
        return self.apps.get(g, {}).get(app, 0) / self.size[g]

    def summary(self) -> list[dict]:
        return [{"group": g, "actors": n, "egress_median": self.egress_median.get(g),
                 "busiest_hours": sorted(range(24), key=lambda i: -self.hours[g][i])[:3]}
                for g, n in sorted(self.size.items())]
