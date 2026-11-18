"""
Asset context: what an IP address was at a given time.

* **Bindings** learned from events: IP -> MAC, hostname, OS, each valid over a time range.
  A changed binding (DHCP lease, rename) closes the old range and opens a new one, so a
  lookup at a past time returns what the address was then.
* **CMDB** records imported from a CSV / list (``import_cmdb``): matched by IP, CIDR or
  hostname, with owner, business criticality (1-5 or low / medium / high / critical),
  department, OS and any other column.
* **Subnet zones** (``zones``: [{cidr, name, criticality}]): the zone an address is in.

Lookups are cached (bounded LRU); bindings live in SQLite (``asset_bindings``).
"""
from __future__ import annotations

import csv
import ipaddress
import time

from ulpf.ueba.store import LRU, Store

CRITICALITY = {"low": 1, "medium": 2, "high": 3, "critical": 4, "mission_critical": 5}


def _crit(v) -> int | None:
    if v in (None, ""):
        return None
    try:
        return max(1, min(5, int(v)))
    except (TypeError, ValueError):
        return CRITICALITY.get(str(v).strip().lower().replace(" ", "_"))


class AssetCMDB:
    def __init__(self, store: Store, zones: list | None = None, cache: int = 50_000):
        self.store = store
        self.zones = []
        for z in zones or []:
            self.zones.append((ipaddress.ip_network(str(z["cidr"]), strict=False), str(z.get("name") or z["cidr"]),
                               _crit(z.get("criticality"))))
        self.zones.sort(key=lambda z: -z[0].prefixlen)          # most specific first
        self.by_ip: dict[str, dict] = {}
        self.by_host: dict[str, dict] = {}
        self.by_net: list[tuple] = []
        self.current = LRU(cache, self._flush_binding)          # ip -> open binding [mac, host, os, first, last]
        self.stats = {"bindings": 0, "rebinds": 0, "cmdb": 0}

    # ---- CMDB import
    def import_cmdb(self, rows) -> int:
        n = 0
        for r in rows:
            rec = {k.strip().lower(): (v.strip() if isinstance(v, str) else v) for k, v in r.items() if k}
            rec = {k: v for k, v in rec.items() if v not in (None, "")}
            if "criticality" in rec:
                rec["criticality"] = _crit(rec["criticality"])
            key = rec.get("ip") or rec.get("cidr")
            if key and "/" in str(key):
                self.by_net.append((ipaddress.ip_network(str(key), strict=False), rec))
            elif key:
                self.by_ip[str(key)] = rec
            if rec.get("hostname"):
                self.by_host[str(rec["hostname"]).lower()] = rec
            n += 1
        self.by_net.sort(key=lambda x: -x[0].prefixlen)
        self.stats["cmdb"] += n
        return n

    def import_csv(self, path: str) -> int:
        with open(path, newline="", encoding="utf-8") as f:
            return self.import_cmdb(list(csv.DictReader(f)))

    # ---- bindings from events
    def _flush_binding(self, ip, b) -> None:
        self.store.queue("UPDATE asset_bindings SET last_seen = ? WHERE ip = ? AND first_seen = ?", (b[4], ip, b[3]))

    def observe(self, ip, ts: float, mac=None, hostname=None, os=None, source: str = "") -> None:
        """An event showed ``ip`` with this MAC / hostname / OS at ``ts``."""
        if not ip or not (mac or hostname or os):
            return
        ip = str(ip)
        mac = str(mac).lower() if mac else None
        hostname = str(hostname).lower() if hostname else None
        b = self.current.get(ip)
        if b is None:
            row = self.store.one("SELECT mac, hostname, os, first_seen, last_seen FROM asset_bindings WHERE ip = ? "
                                 "ORDER BY first_seen DESC LIMIT 1", (ip,))
            b = list(row) if row else None
        if b is not None:
            changed = (mac and b[0] and mac != b[0]) or (hostname and b[1] and hostname != b[1])
            if not changed:
                b[0], b[1], b[2] = b[0] or mac, b[1] or hostname, b[2] or os
                b[4] = max(b[4], ts)
                self.current.put(ip, b)
                self.store.queue("UPDATE asset_bindings SET mac = ?, hostname = ?, os = ?, last_seen = ? "
                                 "WHERE ip = ? AND first_seen = ?", (b[0], b[1], b[2], b[4], ip, b[3]))
                return
            self.stats["rebinds"] += 1
            self.store.queue("UPDATE asset_bindings SET last_seen = ? WHERE ip = ? AND first_seen = ?",
                             (max(b[4], ts - 1e-6) if ts > b[3] else b[4], ip, b[3]))
        nb = [mac, hostname, os, ts, ts]
        self.current.put(ip, nb)
        self.stats["bindings"] += 1
        self.store.queue("INSERT INTO asset_bindings VALUES (?, ?, ?, ?, ?, ?, ?)", (ip, mac, hostname, os, ts, ts, source))

    # ---- lookups
    def binding_at(self, ip: str, ts: float | None = None) -> dict | None:
        self.store.flush()
        ts = time.time() if ts is None else ts
        row = self.store.one("SELECT mac, hostname, os, first_seen, last_seen FROM asset_bindings WHERE ip = ? "
                             "AND first_seen <= ? ORDER BY first_seen DESC LIMIT 1", (str(ip), ts))
        if not row:
            return None
        return {"mac": row[0], "hostname": row[1], "os": row[2], "from": row[3], "to": row[4]}

    def history(self, ip: str) -> list[dict]:
        self.store.flush()
        return [{"mac": r[0], "hostname": r[1], "os": r[2], "from": r[3], "to": r[4]} for r in
                self.store.all("SELECT mac, hostname, os, first_seen, last_seen FROM asset_bindings WHERE ip = ? "
                               "ORDER BY first_seen", (str(ip),))]

    def zone(self, ip: str) -> tuple[str | None, int | None]:
        try:
            a = ipaddress.ip_address(str(ip))
        except ValueError:
            return None, None
        for net, name, crit in self.zones:
            if a.version == net.version and a in net:
                return name, crit
        return None, None

    def resolve(self, ip=None, hostname=None, ts: float | None = None) -> dict:
        """Everything known about an asset (by IP and / or hostname) at ``ts``."""
        out: dict = {}
        b = self.binding_at(ip, ts) if ip else None
        if b:
            out.update({k: v for k, v in b.items() if v is not None})
        host = (hostname or out.get("hostname") or "").lower()
        rec = None
        if ip and str(ip) in self.by_ip:
            rec = self.by_ip[str(ip)]
        elif host and host in self.by_host:
            rec = self.by_host[host]
        elif ip:
            try:
                a = ipaddress.ip_address(str(ip))
                rec = next((r for net, r in self.by_net if a.version == net.version and a in net), None)
            except ValueError:
                rec = None
        if rec:
            out.update({k: v for k, v in rec.items() if k not in ("ip", "cidr")})
        if ip:
            out["ip"] = str(ip)
            z, zc = self.zone(ip)
            if z:
                out["zone"] = z
                if out.get("criticality") is None and zc is not None:
                    out["criticality"] = zc
        if host and "hostname" not in out:
            out["hostname"] = host
        return out
