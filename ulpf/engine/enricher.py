"""
Event Enrichment Engine
========================
Offline GeoIP lookup and threat IOC matching, plus auto-tagging.

GeoIP order: private/CGNAT and special-purpose ranges are labelled (never
geolocated); then MaxMind-format ``.mmdb`` databases (GeoLite2, GeoIP2,
DB-IP Lite) found in ``$ULPF_GEOIP_DIR``, ``config/geoip/`` or
``<data dir>/geoip/``; then the small bundled prefix table
(config/geoip.json), which only covers the demo data sets.

The enricher accepts a configurable `config_dir` so it can be embedded
by the plugin without relying on relative filesystem paths.
"""
from __future__ import annotations

import functools
import ipaddress
import logging
import os
import sys
from typing import Any

from ulpf.intelligence.intel_db import get_intel_db
from ulpf.intelligence.tip import runtime as tip_runtime
from ulpf.intelligence.tip.matcher import apply_hit

logger = logging.getLogger(__name__)

# Well-known backdoor / proxy / C2 listener ports (destination side)
_SUSPICIOUS_PORTS = frozenset({4444, 5555, 6666, 6667, 8888, 9999, 31337, 12345, 27374, 1080, 9050, 9150})

_ROOT = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
_DEFAULT_DATA_DIR = os.path.join(_ROOT, "config")
_DATA_DIR = _DEFAULT_DATA_DIR

_PRIVATE = {"country": "Private", "cc": "XX", "city": "Internal"}
_UNKNOWN = {"country": "Unknown", "cc": "??", "city": "Unknown"}


def configure_enrichment(config_dir: str | None = None) -> None:
    """
    (Re-)configure the enrichment engine with a custom config directory.

    Call this before processing events if the config files (geoip.json, iocs.json)
    live in a non-default location (e.g. inside a plugin bundle).
    """
    global _DATA_DIR
    if config_dir and os.path.isdir(config_dir):
        _DATA_DIR = config_dir
    _load_enrichment_data()


def _load_enrichment_data() -> None:
    """Load GeoIP and IOC feeds into the embedded IntelDB when new or modified."""
    db = get_intel_db()
    geo_path = os.path.join(_DATA_DIR, "geoip.json")
    if os.path.isfile(geo_path) and not (db._geo_prefixes and db.feed_is_current(geo_path)):
        db.ingest_geoip_json(geo_path)
    ioc_path = os.path.join(_DATA_DIR, "iocs.json")
    if os.path.isfile(ioc_path) and not (db._ioc_keys and db.feed_is_current(ioc_path)):
        db.ingest_iocs_json(ioc_path)
    _lookup_geo.cache_clear()


def _is_private(ip: str) -> bool:
    if ":" in ip:
        low = ip.lower()
        return low == "::1" or low.startswith(("fc", "fd", "fe80:"))
    if ip.startswith(("10.", "192.168.", "127.", "169.254.")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".", 2)[1]) <= 31
        except (ValueError, IndexError):
            return False
    if ip.startswith("100."):
        # RFC 6598 carrier-grade NAT 100.64.0.0/10
        try:
            return 64 <= int(ip.split(".", 2)[1]) <= 127
        except (ValueError, IndexError):
            return False
    return False


_SPECIAL_NETS = [(ipaddress.ip_network(n), label) for n, label in (
    ("192.0.2.0/24", "Documentation (RFC 5737)"), ("198.51.100.0/24", "Documentation (RFC 5737)"),
    ("203.0.113.0/24", "Documentation (RFC 5737)"), ("2001:db8::/32", "Documentation (RFC 3849)"),
    ("198.18.0.0/15", "Benchmarking (RFC 2544)"), ("0.0.0.0/8", "This network (RFC 791)"),
    ("240.0.0.0/4", "Reserved (RFC 1112)"), ("224.0.0.0/4", "Multicast"), ("ff00::/8", "Multicast"),
    ("192.0.0.0/24", "IETF protocol assignments"))]


def _special(ip: str) -> dict[str, Any] | None:
    """Special-purpose ranges have no location: label them instead of guessing one."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, label in _SPECIAL_NETS:
        if a.version == net.version and a in net:
            return {"country": "Reserved", "cc": "ZZ", "city": label}
    if a.is_private or a.is_loopback or a.is_link_local:
        return _PRIVATE
    return None


_mmdb_readers: list | None = None


def _mmdb() -> list:
    """Offline MaxMind-format databases: $ULPF_GEOIP_DIR, <config>/geoip, <data dir>/geoip."""
    global _mmdb_readers
    if _mmdb_readers is None:
        from ulpf.intelligence.mmdb import MMDBError, MMDBReader, find_databases
        dirs = [os.environ.get("ULPF_GEOIP_DIR", ""), os.path.join(_DATA_DIR, "geoip")]
        try:
            from ulpf.platform.paths import get_data_dir
            dirs.append(os.path.join(str(get_data_dir()), "geoip"))
        except Exception:
            pass
        readers = []
        for path in find_databases(*dirs):
            try:
                readers.append(MMDBReader(path))
                logger.info(f"GeoIP: using {path} ({readers[-1].database_type})")
            except (MMDBError, OSError) as e:
                logger.warning(f"GeoIP: cannot read {path}: {e}")
        _mmdb_readers = readers
    return _mmdb_readers


@functools.lru_cache(maxsize=16384)
def _lookup_geo(ip: str | None) -> dict[str, Any]:
    if not ip or not isinstance(ip, str):
        return {}
    if _is_private(ip):
        return _PRIVATE
    special = _special(ip)
    if special is not None:
        return special
    readers = _mmdb()
    if readers:
        from ulpf.intelligence.mmdb import MMDBError, geo_from_record
        geo: dict[str, Any] = {}
        for r in readers:
            try:
                rec, _ = r.lookup(ip)
            except (MMDBError, ValueError):
                continue
            if rec:
                for k, v in geo_from_record(rec).items():
                    geo.setdefault(k, v)
        if geo.get("cc"):
            return geo
    return get_intel_db().lookup_geo(ip) or _UNKNOWN


def reset_geoip() -> None:
    """Re-scan for GeoIP databases (after one was added or replaced)."""
    global _mmdb_readers
    for r in _mmdb_readers or []:
        r.close()
    _mmdb_readers = None
    _lookup_geo.cache_clear()


_load_enrichment_data()


def enrich_event(event: dict) -> dict:
    """Enrich with GeoIP, threat intel, auto-tags."""
    src_ip = event["source"]["ip"]
    dst_ip = event["destination"]["ip"]
    sg = _lookup_geo(src_ip)
    dg = _lookup_geo(dst_ip)
    geo = event["geo"]
    geo["src_country"] = sg.get("country")
    geo["src_country_code"] = sg.get("cc")
    geo["src_city"] = sg.get("city")
    geo["src_latitude"] = sg.get("lat")
    geo["src_longitude"] = sg.get("lon")
    geo["dst_country"] = dg.get("country")
    geo["dst_country_code"] = dg.get("cc")
    geo["dst_city"] = dg.get("city")
    geo["dst_latitude"] = dg.get("lat")
    geo["dst_longitude"] = dg.get("lon")

    tags = event["tags"]
    tip = tip_runtime.active()
    if tip is not None:                     # threat-intelligence platform: every indicator kind
        hit = tip.match_event(src_ip if isinstance(src_ip, str) and src_ip else None,
                              dst_ip if isinstance(dst_ip, str) and dst_ip else None,
                              event.get("raw_event") if isinstance(event.get("raw_event"), str) else None)
        if hit is not None:
            apply_hit(event, hit, tags)
    db = get_intel_db()
    for ip_val in (src_ip, dst_ip):
        if ip_val and tip is None:
            ioc = db.lookup_ioc(ip_val)
            if ioc:
                threat = event["threat"]
                threat["category"] = ioc["cat"]
                threat["confidence"] = float(ioc["conf"])
                threat["ioc_type"] = "ip"
                threat["ioc_value"] = ip_val
                tags.append("threat:" + ioc["cat"].lower().replace(" ", "_"))
                tags.append("ioc_match")
                break

    severity = event["severity"]
    if severity >= 9:
        tags.append("critical_severity")
    elif severity >= 7:
        tags.append("high_severity")

    action = event["action"]
    if action in ("blocked", "dropped", "denied"):
        tags.append("blocked_traffic")
    elif action in ("detected", "alerted"):
        tags.append("security_alert")

    port = event["destination"]["port"]
    if port in _SUSPICIOUS_PORTS:
        tags.append(f"suspicious_port:{port}")

    if event["category"]:
        tags.append(f"category:{event['category']}")

    src_cc = geo["src_country_code"]
    dst_cc = geo["dst_country_code"]
    if src_cc and dst_cc and src_cc != dst_cc and not {src_cc, dst_cc} & {"XX", "??", "ZZ"}:
        tags.append("cross_border")

    if len(tags) > 1:
        event["tags"] = list(dict.fromkeys(tags))
    return event
