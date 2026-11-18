"""
Output views of the unified event (U3).

The canonical event is produced once; an output may ask for

* ``unified`` — the ULPF schema as-is (default),
* ``ecs``     — Elastic Common Schema 8.x field names,
* ``ocsf``    — Open Cybersecurity Schema Framework 1.3.0 (``standards/ocsf.py``),
* ``udm``     — Google Security Operations (Chronicle) UDM events (``standards/udm.py``),
* ``asim``    — Microsoft Sentinel ASIM rows (``standards/asim.py``).

Views are pure functions of the event. Anything without a standard home in
the target schema is kept under a ``ulpf`` namespace (ECS), or under
``x_<vendor>`` (vendor fields) and ``x_ulpf`` (unified fields) in OCSF's
``unmapped``, UDM's ``additional`` and ASIM's ``AdditionalFields``, so no
information is lost by choosing a view: ``from_view(apply_view(e, v), v)``
gives the event back (OCSF, UDM, ASIM).
"""
from __future__ import annotations

from ulpf.engine.standards import asim as _asim, ocsf as _ocsf, udm as _udm

ECS_VERSION = "8.11.0"
OCSF_VERSION = _ocsf.VERSION
STANDARD_VIEWS = ("ocsf", "udm", "asim")

_ECS_CATEGORY = {
    "network": ["network"], "firewall": ["network"], "ids_ips": ["intrusion_detection", "network"],
    "authentication": ["authentication"], "web": ["web"], "dns": ["network"],
    "proxy": ["network", "web"], "vpn": ["network"], "endpoint": ["host"], "system": ["host"],
    "audit": ["configuration"], "other": [],
}
_SUCCESS = {"allowed", "success", "accepted", "login", "logon", "permitted", "created", "connected"}
_FAILURE = {"blocked", "denied", "dropped", "failure", "failed", "rejected", "reset", "quarantined"}


def _outcome(action: str | None) -> str:
    a = (action or "").lower()
    if a in _SUCCESS:
        return "success"
    if a in _FAILURE:
        return "failure"
    return "unknown"


def _clean(d):
    """Drop None / empty containers recursively."""
    if isinstance(d, dict):
        out = {}
        for k, v in d.items():
            v = _clean(v)
            if v is None or v == {} or v == []:
                continue
            out[k] = v
        return out
    if isinstance(d, list):
        return [x for x in (_clean(v) for v in d) if x not in (None, {}, [])]
    return d


def _geo(geo: dict, side: str) -> dict:
    return {"country_name": geo.get(f"{side}_country"), "country_iso_code": geo.get(f"{side}_country_code"),
            "city_name": geo.get(f"{side}_city"),
            "location": ({"lat": geo.get(f"{side}_latitude"), "lon": geo.get(f"{side}_longitude")}
                         if geo.get(f"{side}_latitude") is not None else None)}


def _ecs_endpoint(ep: dict, geo: dict, side: str, nbytes) -> dict:
    return {"ip": ep.get("ip"), "port": ep.get("port"), "mac": ep.get("mac"),
            "domain": ep.get("hostname"), "address": ep.get("ip") or ep.get("hostname"),
            "bytes": nbytes, "geo": _geo(geo, side)}


def to_ecs(e: dict) -> dict:
    net = e.get("network") or {}
    dev = e.get("device") or {}
    rule = e.get("rule") or {}
    thr = e.get("threat") or {}
    user = e.get("user") or {}
    geo = e.get("geo") or {}
    meta = e.get("metadata") or {}
    ev = e.get("evidence") or {}
    kind = e.get("event_kind") or "log"
    src, dst = e.get("source") or {}, e.get("destination") or {}
    ips = [x for x in (src.get("ip"), dst.get("ip"), dev.get("ip")) if x]
    doc = {
        "@timestamp": e.get("timestamp"),
        "message": e.get("message"),
        "tags": e.get("tags") or None,
        "ecs": {"version": ECS_VERSION},
        "event": {
            "id": e.get("event_id"), "kind": "alert" if kind in ("anomaly", "correlation") else "event",
            "category": _ECS_CATEGORY.get(e.get("category") or "other", []),
            "action": e.get("action"), "outcome": _outcome(e.get("action")),
            "severity": e.get("severity"), "dataset": e.get("raw_format"),
            "created": meta.get("ingestion_time"), "original": e.get("raw_event"),
            "hash": ev.get("raw_hash"), "type": [e["event_type"]] if e.get("event_type") else None,
        },
        "source": _ecs_endpoint(src, geo, "src", net.get("bytes_out")),
        "destination": _ecs_endpoint(dst, geo, "dst", net.get("bytes_in")),
        "network": {"transport": (net.get("protocol") or "").lower() or None,
                    "iana_number": str(net["protocol_number"]) if net.get("protocol_number") is not None else None,
                    "direction": net.get("direction"), "bytes": net.get("bytes_total"),
                    "application": net.get("application"),
                    "packets": (net.get("packets_in") or 0) + (net.get("packets_out") or 0)
                    if (net.get("packets_in") or net.get("packets_out")) else None,
                    "vlan": {"id": str(net["vlan_id"])} if net.get("vlan_id") is not None else None},
        "observer": {"vendor": dev.get("vendor"), "product": dev.get("product"), "version": dev.get("version"),
                     "hostname": dev.get("hostname"), "ip": [dev["ip"]] if dev.get("ip") else None,
                     "type": dev.get("type"), "serial_number": dev.get("serial")},
        "rule": {"id": rule.get("id"), "name": rule.get("name") or thr.get("signature"),
                 "description": rule.get("description"), "category": rule.get("category")},
        "threat": {"indicator": {"type": thr.get("ioc_type"), "name": thr.get("ioc_value"),
                                 "confidence": thr.get("confidence")}},
        "vulnerability": {"id": thr.get("cve")[0]} if thr.get("cve") else None,
        "user": {"name": user.get("name"), "domain": user.get("domain"), "id": user.get("id"),
                 "email": user.get("email"),
                 "group": {"name": user.get("group")} if user.get("group") else None,
                 "target": user.get("target")},
        "related": {"ip": sorted(set(ips)) or None,
                    "user": [user["name"]] if user.get("name") else None,
                    "hosts": [h for h in (src.get("hostname"), dst.get("hostname"), dev.get("hostname")) if h] or None},
        "ulpf": {"event_kind": kind, "raw_format": e.get("raw_format"), "category": e.get("category"),
                 "severity_label": e.get("severity_label"), "timestamp_original": e.get("timestamp_original"),
                 "parsed_fields": e.get("parsed_fields"), "extensions": e.get("extensions"),
                 "correlation_id": e.get("correlation_id"), "related_events": e.get("related_events"),
                 "evidence": ev, "metadata": meta, "threat_category": thr.get("category"),
                 "signature_id": thr.get("signature_id")},
    }
    return _clean(doc)


# ---------------------------------------------------------------------------
# OCSF, UDM, ASIM (ulpf/engine/standards)
# ---------------------------------------------------------------------------

def to_ocsf(e: dict) -> dict:
    return _ocsf.to_ocsf(e)


def to_udm(e: dict) -> dict:
    return _udm.to_udm(e)


def to_asim(e: dict) -> dict:
    return _asim.to_asim(e)


def apply_view(event: dict, view: str) -> dict:
    if view == "ecs":
        return to_ecs(event)
    if view == "ocsf":
        return to_ocsf(event)
    if view == "udm":
        return to_udm(event)
    if view == "asim":
        return to_asim(event)
    if view == "cbam":
        from ulpf.compliance.cbam import to_cbam_view
        return to_cbam_view(event)
    return event


def from_view(doc: dict, view: str) -> dict:
    """A unified event from a document of a standard view (OCSF, UDM, ASIM)."""
    if view in STANDARD_VIEWS:
        return {"ocsf": _ocsf.from_ocsf, "udm": _udm.from_udm, "asim": _asim.from_asim}[view](doc)
    raise ValueError(f"no inverse for view {view!r}")
