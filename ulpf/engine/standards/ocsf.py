"""
OCSF 1.3.0 view of the unified event, its inverse, and a conformance check.

``to_ocsf(event)`` picks the class from ``facets.classify`` (all 72 classes of
1.3.0 are known; ULPF maps its activities onto 27 of them, including the
Windows extension's Registry Key / Value and Windows Service Activity) and fills
the class's required and recommended attributes. Profiles are declared in
``metadata.profiles`` when one of their attributes is written (``host``,
``security_control``, ``cloud``). Vendor fields without a standard home go to
``unmapped["x_<vendor>"]``; the unified fields OCSF cannot hold exactly go to
``unmapped["x_ulpf"]``, so ``from_ocsf(to_ocsf(e))`` gives ``e`` back (with
``parsed_fields`` reduced to the facets and vendor-only fields).

``validate(doc)`` checks a document against the bundled schema
(``ocsf_1_3_0.json``, built from https://schema.ocsf.io by
``scripts/build_ocsf_schema.py``): known attributes only, required attributes,
enum values, sibling captions, types, profiles.
"""
from __future__ import annotations

import functools
import json
import os
from typing import Any

from ulpf.engine.standards import common as C
from ulpf.engine.standards.facets import Activity, CANDIDATES, classify, facets, unmapped_vendor_fields, \
    vendor_namespace

VERSION = "1.3.0"
_HERE = os.path.dirname(os.path.abspath(__file__))


@functools.lru_cache(maxsize=1)
def schema() -> dict:
    with open(os.path.join(_HERE, "ocsf_1_3_0.json"), encoding="utf-8") as f:
        return json.load(f)


def class_info(uid: int) -> dict:
    return schema()["classes"][str(uid)]


def enum_caption(attrs: dict, name: str, value) -> str | None:
    e = attrs.get(name)
    if not e or not e[3]:
        return None
    return e[3].get(str(value))


# ---------------------------------------------------------------------------
# Class and activity
# ---------------------------------------------------------------------------

KIND_CLASS = {
    "finding": 2004, "network": 4001, "http": 4002, "dns": 4003, "dhcp": 4004, "rdp": 4005, "smb": 4006,
    "ssh": 4007, "ftp": 4008, "email": 4009, "ntp": 4013, "tunnel": 4014, "authentication": 3002,
    "account": 3001, "group": 3006, "process": 1007, "file": 1001, "registry_key": 201001,
    "registry_value": 201002, "kernel_extension": 1002, "module": 1005, "scheduled_job": 1006,
    "service": 201004, "application": 6002, "event_log": 1008, "api": 6003, "config": 5019, "base": 0,
}
_NETLIKE = {4001, 4005, 4006, 4007, 4008, 4013}

# (class, verb) -> activity_id; anything else is 99 (Other) with the verb as activity_name
_ACTIVITY = {
    3002: {"logon": 1, "logoff": 2, "ticket": 3, "service_ticket": 4, "service_ticket_renew": 5, "preauth": 6},
    3001: {"create": 1, "enable": 2, "password_change": 3, "password_reset": 4, "disable": 5, "delete": 6,
           "lock": 9},
    3006: {"add_member": 3, "remove_member": 4, "delete": 5, "create": 6},
    1007: {"launch": 1, "terminate": 2, "open": 3, "inject": 4},
    1001: {"create": 1, "read": 2, "modify": 3, "delete": 4, "rename": 5, "open": 14},
    201001: {"create": 1, "read": 2, "modify": 3, "delete": 4, "rename": 5},
    201002: {"read": 1, "modify": 2, "delete": 4, "create": 2},
    1002: {"load": 1, "unload": 2}, 1005: {"load": 1, "unload": 2},
    1006: {"create": 1, "modify": 2, "delete": 3, "enable": 4, "disable": 5, "start": 6},
    6002: {"install": 1, "remove": 2, "start": 3, "stop": 4, "restart": 5, "enable": 6, "disable": 7, "update": 8},
    1008: {"clear": 1, "delete": 2, "start": 6, "stop": 7},
    6003: {"create": 1, "read": 2, "modify": 3, "delete": 4},
    4003: {"query": 1, "response": 2, "traffic": 6},
    4009: {"send": 1, "receive": 2, "scan": 3},
    4014: {"open": 1, "close": 2, "renew": 3},
    2004: {"create": 1, "update": 2, "close": 3},
    201004: {"install": 1, "create": 1, "modify": 2, "start": 3, "launch": 3, "stop": 4, "terminate": 4,
             "delete": 7},
    4004: {},    # DHCP activities are message types (Discover, Offer, ...), not known from the event
}
_HTTP_METHODS = {"CONNECT": 1, "DELETE": 2, "GET": 3, "HEAD": 4, "OPTIONS": 5, "POST": 6, "PUT": 7, "TRACE": 8}
_SEVERITY = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def _activity_id(cls: int, act: Activity, event: dict) -> int:
    action = (event.get("action") or "").lower()
    if cls in _NETLIKE:
        if action in ("blocked", "denied", "dropped", "rejected"):
            return 5
        if action == "reset":
            return 3
        if action in ("failed", "failure"):
            return 4
        if action in ("disconnected", "closed"):
            return 2
        return 1 if act.verb == "open" and (event.get("raw_format") == "xml") else 6
    if cls == 4002:
        m = str(act.facets.get("http.method") or "").upper()
        return _HTTP_METHODS.get(m, 99 if m else 0)
    if cls == 0:
        return 0
    return _ACTIVITY.get(cls, {}).get(act.verb, 99)


# ---------------------------------------------------------------------------
# Objects
# ---------------------------------------------------------------------------

def _location(geo: dict, side: str) -> dict | None:
    loc = {"country": geo.get(f"{side}_country_code"), "city": geo.get(f"{side}_city"),
           "lat": geo.get(f"{side}_latitude"), "long": geo.get(f"{side}_longitude")}
    return loc if any(v is not None for v in loc.values()) else None


def _port(v) -> int | None:
    p = C.as_int(v)
    return p if p is not None and 0 <= p <= 65535 else None   # port_t; other values stay in x_ulpf


def _endpoint(ep: dict, geo: dict, side: str) -> dict:
    return {"ip": ep.get("ip"), "port": _port(ep.get("port")), "hostname": ep.get("hostname"),
            "mac": ep.get("mac"), "interface_name": ep.get("interface"), "zone": ep.get("zone"),
            "location": _location(geo, side)}


def _user(name=None, domain=None, uid=None, email=None) -> dict | None:
    u = {"name": name, "domain": domain, "uid": uid, "email_addr": email}
    return u if any(v is not None for v in u.values()) else None


_DEVICE_TYPE = {"server": 1, "desktop": 2, "laptop": 3, "tablet": 4, "mobile": 5, "virtual": 6, "iot": 7,
                "browser": 8, "firewall": 9, "switch": 10, "hub": 11, "router": 12, "ids": 13, "ips": 14,
                "load balancer": 15}


def _device(event: dict) -> dict | None:
    dev = event.get("device") or {}
    if not any(dev.get(k) for k in ("hostname", "ip", "serial", "type")):
        return None
    t = str(dev.get("type") or "").lower()
    tid = _DEVICE_TYPE.get(t)
    if tid is None:
        tid = {"firewall": 9, "ids_ips": 13}.get(event.get("category") or "", 0 if not t else 99)
    caps = schema()["objects"]["device"]["attributes"]["type_id"][3]
    return {"hostname": dev.get("hostname"), "ip": dev.get("ip"), "uid": dev.get("serial"), "type_id": tid,
            "type": caps.get(str(tid)) if tid != 99 else (dev.get("type") or "Other")}


def _hashes(f) -> list | None:
    out = []
    for name, alg in (("file.md5", 1), ("file.sha1", 2), ("file.sha256", 3)):
        v = f.take(name)
        if v:
            out.append({"algorithm_id": alg, "algorithm": {1: "MD5", 2: "SHA-1", 3: "SHA-256"}[alg], "value": str(v)})
    raw = f.get("file.hashes")
    if raw and isinstance(raw, str) and "=" in raw:      # Sysmon: "SHA256=...,MD5=..."
        f.take("file.hashes")
        algs = {"MD5": 1, "SHA1": 2, "SHA256": 3, "SHA512": 4}
        for part in raw.split(","):
            k, _, v = part.partition("=")
            a = algs.get(k.strip().upper())
            if a and v and not any(h["algorithm_id"] == a for h in out):
                out.append({"algorithm_id": a, "algorithm": {1: "MD5", 2: "SHA-1", 3: "SHA-256", 4: "SHA-512"}[a],
                            "value": v.strip()})
    return out or None


def _file(f, prefix: str = "file") -> dict | None:
    path = f.take(f"{prefix}.path")
    if path is None:
        return None
    return {"path": str(path), "name": C.basename(path) or str(path), "parent_folder": C.parent_dir(path),
            "type_id": 1, "type": "Regular File", "size": C.as_int(f.take(f"{prefix}.size")),
            "hashes": _hashes(f) if prefix == "file" else None}


def _process(f, prefix: str, user: dict | None = None) -> dict | None:
    name = f.take(f"{prefix}.name")
    path = f.take(f"{prefix}.path") if prefix == "process" else None
    pid = C.as_int(f.take(f"{prefix}.pid"))
    cmd = f.take(f"{prefix}.cmd_line")
    uid = f.take(f"{prefix}.uid")
    if name is None and pid is None and cmd is None and path is None:
        return None
    p = {"name": C.basename(name) or name, "pid": pid, "cmd_line": cmd, "uid": uid, "user": user}
    full = path or name
    if full and ("\\" in str(full) or "/" in str(full)):
        p["file"] = {"path": str(full), "name": C.basename(full) or str(full), "type_id": 1, "type": "Regular File",
                     "hashes": _hashes(f) if prefix == "process" else None}
    if prefix == "process":
        integ = f.take("process.integrity")
        if integ:
            p["integrity"] = str(integ)
    return p


# ---------------------------------------------------------------------------
# to_ocsf
# ---------------------------------------------------------------------------

def _put(doc: dict, attrs: dict, profiles: list, name: str, value) -> None:
    """Set a class attribute, declaring its profile; values the class does not define are refused."""
    if value is None or value == {} or value == []:
        return
    spec = attrs.get(name)
    if spec is None:
        raise KeyError(f"OCSF class {doc['class_uid']} has no attribute {name}")
    prof = spec[4]
    if prof and prof not in profiles:
        profiles.append(prof)
    doc[name] = value


def _to_ocsf(event: dict):
    f = facets(event)
    act = classify(event, f)
    cls = KIND_CLASS[act.kind]
    info = class_info(cls)
    attrs = info["attributes"]
    aid = _activity_id(cls, act, event)
    if str(aid) not in info["activities"]:
        aid = 99
    act_name = info["activities"].get(str(aid))
    if aid == 99 and act.verb not in ("other", ""):
        act_name = act.verb.replace("_", " ").title()
    out = C.outcome(event)
    eid = f.get("win.event_id")
    if cls == 3002 and eid in (4624, 4625):
        out = "success" if eid == 4624 else "failure"
    if cls == 6003:
        out = "failure" if f.take("api.error") else "success"
    label = event.get("severity_label") or "unknown"
    sev_id = _SEVERITY.get(label, 0)
    dev = event.get("device") or {}
    net = event.get("network") or {}
    geo = event.get("geo") or {}
    user = event.get("user") or {}
    meta = event.get("metadata") or {}
    ev = event.get("evidence") or {}
    profiles: list[str] = []
    doc: dict[str, Any] = {
        "class_uid": cls, "class_name": info["caption"], "category_uid": info["category_uid"],
        "category_name": info["category_name"] or "Uncategorized", "activity_id": aid, "activity_name": act_name,
        "type_uid": cls * 100 + aid, "type_name": enum_caption(attrs, "type_uid", cls * 100 + aid)
        or f"{info['caption']}: {info['activities'].get(str(aid), 'Other')}",
        "severity_id": sev_id, "severity": schema()["classes"]["0"]["attributes"]["severity_id"][3][str(sev_id)],
        "time": C.epoch_ms(event.get("timestamp")),
    }
    # status_id is the outcome (Success / Failure) except in findings, where it is the finding's state
    if out != "unknown" and enum_caption(attrs, "status_id", 1) == "Success":
        doc["status_id"] = 1 if out == "success" else 2
        doc["status"] = "Success" if out == "success" else "Failure"
    put = functools.partial(_put, doc, attrs, profiles)
    put("message", event.get("message"))
    put("raw_data", event.get("raw_event"))
    if f.get("auth.failure") is not None and out == "failure":
        put("status_detail", str(f.take("auth.failure")))
    if f.get("api.error") is not None:
        put("status_code", str(f.take("api.error")))

    src = _endpoint(event.get("source") or {}, geo, "src")
    dst = _endpoint(event.get("destination") or {}, geo, "dst")
    has_src = any(v is not None for k, v in src.items() if k != "location")
    has_dst = any(v is not None for k, v in dst.items() if k != "location")
    actor_user = None
    if user.get("source", {}).get("name") or user.get("source", {}).get("id"):
        su = user.get("source") or {}
        actor_user = _user(su.get("name"), su.get("domain"), su.get("id"))
    target_user = None
    tu = user.get("target") or {}
    if tu.get("name") or tu.get("id"):
        target_user = _user(tu.get("name"), tu.get("domain"), tu.get("id"))
    primary_user = _user(user.get("name"), user.get("domain"), user.get("id"), user.get("email"))

    # network-shaped classes
    if cls in _NETLIKE | {4002, 4003, 4004, 4009, 4014}:
        if "src_endpoint" in attrs and (has_src or src.get("location")):
            put("src_endpoint", src)
        if "dst_endpoint" in attrs:
            put("dst_endpoint", dst if (has_dst or dst.get("location") or attrs["dst_endpoint"][0] == "r")
                else None)
            if attrs["dst_endpoint"][0] == "r" and "dst_endpoint" not in doc:
                doc["dst_endpoint"] = {}
        direction = {"inbound": 1, "outbound": 2, "internal": 3}.get(str(net.get("direction") or "").lower(), 0)
        conn = {"protocol_name": (net.get("protocol") or "").lower() or None,
                "protocol_num": net.get("protocol_number"), "direction_id": direction,
                "direction": {1: "Inbound", 2: "Outbound", 3: "Lateral", 0: "Unknown"}[direction],
                "uid": str(net["session_id"]) if net.get("session_id") is not None else None}
        if "connection_info" in attrs and any(conn[k] is not None for k in ("protocol_name", "protocol_num", "uid")) \
                or direction:
            if "connection_info" in attrs:
                put("connection_info", conn)
        traffic = {"bytes_in": net.get("bytes_in"), "bytes_out": net.get("bytes_out"), "bytes": net.get("bytes_total"),
                   "packets_in": net.get("packets_in"), "packets_out": net.get("packets_out")}
        if net.get("packets_in") is not None or net.get("packets_out") is not None:
            traffic["packets"] = (net.get("packets_in") or 0) + (net.get("packets_out") or 0)
        if "traffic" in attrs and any(v is not None for v in traffic.values()):
            put("traffic", traffic)
        if "app_name" in attrs:
            put("app_name", net.get("application"))
        if "actor" in attrs:       # the process behind a connection or a query (Sysmon 3 / 22)
            ap = _process(f, "process") or _process(f, "actor.process")
            if ap:
                put("actor", {"process": ap})
        if cls == 4002:
            url = f.take("http.url")
            req = {"http_method": str(f.get("http.method")).upper() if f.get("http.method") else None,
                   "user_agent": f.take("http.user_agent"), "referrer": f.take("http.referrer"),
                   "url": {"url_string": str(url) if url else None, "query_string": f.take("http.query"),
                           "hostname": f.take("http.host") or (event.get("destination") or {}).get("hostname")}}
            if req["http_method"] not in _HTTP_METHODS:
                req["http_method"] = None
            else:
                f.take("http.method")
            put("http_request", req)
            code = C.as_int(f.take("http.status"))
            put("http_response", {"code": code if code is not None else 0})
            if code is not None:
                put("http_status", code)
        if cls == 4003:
            q = f.take("dns.query")
            if q:
                put("query", {"hostname": str(q), "type": f.take("dns.qtype")})
            ans = f.take("dns.answer")
            if ans:
                put("answers", [{"rdata": str(a)} for a in (ans if isinstance(ans, list) else [ans])])
            rc = f.take("dns.rcode")
            if rc is not None:
                caps = {v.lower(): int(k) for k, v in attrs["rcode_id"][3].items()}
                num = C.as_int(rc)
                rid = num if num is not None and str(num) in attrs["rcode_id"][3] else \
                    caps.get(str(rc).lower().replace("_", ""), 99)
                put("rcode_id", rid)
                put("rcode", attrs["rcode_id"][3][str(rid)] if rid != 99 else str(rc))
        if cls == 4009:
            put("direction_id", 0)
            put("direction", "Unknown")
            put("email", {"from": f.take("email.from"), "to": [f.take("email.to")] if f.get("email.to") else [],
                          "subject": f.take("email.subject")})
            if "email" in doc and not doc["email"].get("from"):
                doc["email"]["from"] = ""
        if cls == 4014:
            put("user", primary_user)
            put("session", {"uid": str(net["session_id"])} if net.get("session_id") else None)
    elif cls in (3002, 3001, 3006):
        put("src_endpoint", src if (has_src or src.get("location")) else None)
        if cls == 3002:
            put("dst_endpoint", dst if (has_dst or dst.get("location")) else None)
            put("user", target_user or primary_user or {})
            if actor_user:
                put("actor", {"user": actor_user})
            lt = C.as_int(f.take("auth.logon_type"))
            if lt is not None:
                caps = attrs["logon_type_id"][3]
                put("logon_type_id", lt if str(lt) in caps else 99)
                put("logon_type", caps.get(str(lt), str(lt)))
                if lt in (3, 8, 10, 12):
                    put("is_remote", True)
            proto = f.take("auth.protocol")
            if proto is not None:
                caps = {v.lower(): int(k) for k, v in attrs["auth_protocol_id"][3].items()}
                key = str(proto).strip().lower()
                pid_ = caps.get(key) or 99      # "Negotiate" (SPNEGO) names no single protocol: Other
                put("auth_protocol_id", pid_)
                put("auth_protocol", attrs["auth_protocol_id"][3][str(pid_)] if pid_ != 99 else str(proto))
            if net.get("application"):
                put("service", {"name": net.get("application")})
        elif cls == 3001:
            put("user", target_user or primary_user or {})
            if actor_user:
                put("actor", {"user": actor_user})
        else:
            gname = f.take("group.name") or (target_user or {}).get("name")
            put("group", {"name": gname} if gname else {"name": None})
            if doc.get("group") is None:
                doc["group"] = {}
            member = f.take("group.member")
            if member:
                put("user", {"name": str(member)})
            if actor_user or primary_user:
                put("actor", {"user": actor_user or primary_user})
    elif cls in (1007, 1001, 201001, 201002, 1002, 1005, 1006, 201004, 1008, 5019, 6002):
        proc_user = primary_user
        actor: dict[str, Any] = {}
        if cls == 1007:
            target = _process(f, "process", user=proc_user)
            parent = _process(f, "actor.process")
            if target and parent:
                target["parent_process"] = parent
            put("process", target or {})
            actor = {"process": parent or target or {}, "user": actor_user or proc_user}
        else:
            ap = _process(f, "actor.process") or _process(f, "process")
            actor = {"process": ap, "user": actor_user or proc_user}
        if cls == 1001:
            put("file", _file(f) or {"name": "", "type_id": 0})
        elif cls == 201001:
            put("reg_key", {"path": str(f.take("registry.key") or "")})
        elif cls == 201002:
            key = f.take("registry.key") or ""
            vname = f.take("registry.value")
            rv: dict[str, Any] = {"path": str(key), "name": str(vname) if vname is not None else "(Default)",
                                  "is_default": vname is None or None, "data": f.take("registry.data")}
            rtype = f.take("registry.type")
            caps = schema()["objects"]["win/reg_value"]["attributes"]["type_id"][3]
            if rtype:
                tid = next((int(k) for k, v in caps.items() if v == str(rtype).upper()), 99)
                rv["type_id"], rv["type"] = tid, caps[str(tid)] if tid != 99 else str(rtype)
            put("reg_value", rv)
        elif cls in (1002, 1005):
            fobj = _file(f) or ({"path": str(f.get("process.path")), "name": C.basename(f.get("process.path")),
                                 "type_id": 1, "type": "Regular File"} if f.get("process.path") else None)
            if cls == 1002:
                put("driver", {"file": fobj or {"name": "", "type_id": 0}})
            else:
                put("module", {"file": fobj, "load_type_id": 0, "load_type": "Unknown"})
        elif cls == 1006:
            job_name = f.take("service.name") or f.take("app.name") or event.get("event_type") or ""
            put("job", {"name": str(job_name), "file": {"name": "", "type_id": 0}})
        elif cls == 201004:
            put("win_service", {"name": str(f.take("service.name") or event.get("event_type") or "")}
                if "win_service" in attrs else None)
        elif cls == 1008:
            put("log_name", f.take("win.channel"))
            put("log_provider", f.take("win.provider"))
        elif cls == 6002:
            put("app", {"name": f.take("service.name") or f.take("app.name") or (event.get("rule") or {}).get("name")
                        or dev.get("product"), "vendor_name": dev.get("vendor") or "Unknown",
                        "version": dev.get("version")})
        if "actor" in attrs:
            actor = C.clean(actor)
            if actor or attrs["actor"][0] == "r":
                put("actor", actor or {})
                if "actor" not in doc:
                    doc["actor"] = {}
    elif cls == 6003:
        put("api", {"operation": str(f.take("api.operation")),
                    "service": {"name": f.take("api.service")} if f.get("api.service") else None,
                    "request": {"uid": str(f.take("api.request_id"))} if f.get("api.request_id") else None})
        cu = f.take("cloud.actor_uid")
        put("actor", {"user": C.clean({**(primary_user or {}), "uid": cu, "type": f.take("cloud.actor_type")})
                      or {}})
        if not has_src and f.get("api.src_ip"):
            src = {**src, "ip": str(f.take("api.src_ip"))}
            has_src = True
        put("src_endpoint", src if has_src else {})
        provider = f.take("cloud.provider") or "Unknown"
        put("cloud", {"provider": str(provider), "region": f.take("cloud.region"),
                      "account": {"uid": str(f.take("cloud.account"))} if f.get("cloud.account") else None})
        ua = f.take("http.user_agent")
        if ua:
            put("http_request", {"user_agent": ua})
    elif cls == 2004:
        thr = event.get("threat") or {}
        rule = event.get("rule") or {}
        ext = (event.get("extensions") or {})
        det = ext.get("detection") if isinstance(ext.get("detection"), dict) else {}
        attacks = []
        for t in det.get("techniques") or []:
            attacks.append({"technique": {"uid": t}, "version": "15"})
        put("finding_info", {"title": str(rule.get("name") or thr.get("signature") or event.get("message")
                                          or event.get("event_type") or "finding"),
                             "uid": str(rule.get("id") or thr.get("signature_id") or event.get("event_id")),
                             "types": [thr["category"]] if thr.get("category") else None,
                             "attacks": attacks or None,
                             "related_events": [{"uid": u} for u in event.get("related_events") or []][:100] or None})
        if "src_endpoint" in attrs:
            put("src_endpoint", src if has_src else None)
        if has_src or has_dst:
            put("evidences", [C.clean({"src_endpoint": src if has_src else None,
                                       "dst_endpoint": dst if has_dst else None})])
        if thr.get("confidence") is not None:
            conf = float(thr["confidence"])
            put("confidence_score", int(round(conf * 100)) if conf <= 1 else int(conf))
    if "device" in attrs:
        d = _device(event)
        if d is not None or attrs["device"][0] == "r":
            put("device", d or {"type_id": 0, "type": "Unknown"})
            if "device" not in doc:
                doc["device"] = {"type_id": 0, "type": "Unknown"}

    # security_control: the outcome a control applied (declared for traffic, and wherever the
    # event reports what a control did)
    action = (event.get("action") or "").lower()
    if "action_id" in attrs and attrs["action_id"][4] == "security_control" and \
            (cls in _NETLIKE | {4002, 4003, 4009, 4014} or action not in ("", "other")):
        action = (event.get("action") or "").lower()
        aid2 = 1 if action in C.SUCCESS else 2 if action in C.BLOCKED else 0
        put("action_id", aid2)
        doc["action"] = attrs["action_id"][3][str(aid2)]
        disp = {"allowed": 1, "permitted": 1, "accepted": 1, "success": 1, "blocked": 2, "denied": 2,
                "quarantined": 3, "dropped": 6, "reset": 21, "rejected": 25, "detected": 15, "alerted": 19,
                "logged": 17}.get(action)
        if disp is not None:
            doc["disposition_id"] = disp
            doc["disposition"] = attrs["disposition_id"][3][str(disp)]
        rule = event.get("rule") or {}
        if rule.get("id") or rule.get("name"):
            doc["firewall_rule"] = C.clean({"uid": None if rule.get("id") is None else str(rule["id"]),
                                            "name": rule.get("name"), "desc": rule.get("description"),
                                            "category": rule.get("category")})

    observables = []
    for path, val, tid in (("src_endpoint.ip", src.get("ip"), 2), ("dst_endpoint.ip", dst.get("ip"), 2),
                           ("src_endpoint.hostname", src.get("hostname"), 1),
                           ("dst_endpoint.hostname", dst.get("hostname"), 1),
                           ("user.name", (doc.get("user") or {}).get("name") if isinstance(doc.get("user"), dict)
                            else None, 4),
                           ("query.hostname", (doc.get("query") or {}).get("hostname"), 1),
                           ("process.name", (doc.get("process") or {}).get("name"), 9),
                           ("file.name", (doc.get("file") or {}).get("name"), 7),
                           ("reg_key.path", (doc.get("reg_key") or {}).get("path"), 28)):
        if val:
            observables.append({"name": path, "type_id": tid,
                                "type": schema()["objects"]["observable"]["attributes"]["type_id"][3][str(tid)],
                                "value": str(val)})
    put("observables", observables)

    md: dict[str, Any] = {
        "version": VERSION, "uid": event.get("event_id"),
        "product": {"name": dev.get("product"), "vendor_name": dev.get("vendor") or "Unknown",
                    "version": dev.get("version")},
        "log_name": event.get("raw_format"),
        "original_time": event.get("timestamp_original"),
        "logged_time": C.epoch_ms(meta.get("ingestion_time")),
        "labels": event.get("tags") or None, "correlation_uid": event.get("correlation_id"),
        "event_code": str(eid) if eid is not None else None,
        "sequence": ev.get("journal_seq") if isinstance(ev.get("journal_seq"), int) else None,
    }
    if eid is not None:
        f.take("win.event_id")
    if f.get("win.provider") is not None and "log_provider" not in doc:
        md["log_provider"] = str(f.take("win.provider"))
    doc["metadata"] = md
    if profiles:
        md["profiles"] = sorted(profiles)
    doc = C.clean(doc)
    _fill_required(doc, attrs, set(profiles))
    # after clean(): the residual keeps its None values (they are part of the event)
    vendor = unmapped_vendor_fields(event, f)
    doc["unmapped"] = {**({vendor_namespace(event): vendor} if vendor else {}), "x_ulpf": C.residual(event)}
    return doc, f


def to_ocsf(event: dict) -> dict:
    return _to_ocsf(event)[0]


def _fill_required(doc: dict, attrs: dict, profiles: set) -> None:
    """Required objects the event has nothing for are present and empty (their own required
    attributes filled the same way), as the schema asks."""
    for name, spec in attrs.items():
        if spec[0] != "r" or name in doc or (spec[4] and spec[4] not in profiles):
            continue
        if spec[1] == "object_t" and spec[2]:
            obj: dict = {}
            _fill_required(obj, schema()["objects"].get(spec[2], {}).get("attributes", {}), profiles)
            doc[name] = [obj] if spec[5] else obj
        elif spec[3]:                       # an enum: Unknown
            doc[name] = 0 if spec[1] in ("integer_t", "long_t") else next(iter(spec[3]))
            sib = spec[6]
            if sib and sib in attrs and sib not in doc:
                doc[sib] = spec[3].get(str(doc[name]), "Unknown")
        elif spec[1] in ("string_t", "file_name_t", "hostname_t", "username_t", "email_t") or \
                _base_type(spec[1]) == "string_t":
            doc[name] = ""


# ---------------------------------------------------------------------------
# from_ocsf
# ---------------------------------------------------------------------------

_CLASS_CATEGORY = {4001: "network", 4002: "web", 4003: "dns", 4014: "vpn", 3002: "authentication",
                   3001: "authentication", 3006: "authentication", 2004: "ids_ips", 1007: "endpoint",
                   1001: "endpoint", 201001: "endpoint", 201002: "endpoint", 1002: "endpoint", 1005: "endpoint",
                   1006: "endpoint", 201004: "system", 6002: "system", 1008: "audit", 6003: "audit",
                   5019: "audit", 0: "other"}
_LABEL = {0: "unknown", 1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "critical"}
_LABEL_SCORE = {"unknown": 0, "info": 1, "low": 3, "medium": 5, "high": 7, "critical": 9}


def _facet_fields(doc: dict) -> dict:
    """OCSF objects back to the facets' canonical parsed-field names."""
    p: dict[str, Any] = {}
    canon = {k: v[0] for k, v in CANDIDATES.items()}

    def put(facet, value):
        if value not in (None, "", [], {}):
            p[canon[facet]] = value
    def proc_fields(prefix: str, pr: dict) -> None:
        path = (pr.get("file") or {}).get("path")
        put(f"{prefix}.name", path or pr.get("name"))
        if prefix == "process":
            put("process.path", path)
            put("process.integrity", pr.get("integrity"))
        put(f"{prefix}.pid", pr.get("pid"))
        put(f"{prefix}.cmd_line", pr.get("cmd_line"))
        put(f"{prefix}.uid", pr.get("uid"))
        for h in (pr.get("file") or {}).get("hashes") or []:
            put({1: "file.md5", 2: "file.sha1", 3: "file.sha256"}.get(h.get("algorithm_id"), "file.hashes"),
                h.get("value"))

    # Process Activity: the target process and its parent (the actor). Other classes: the
    # acting process is the event's process (to_ocsf reads the process facets first there)
    if doc.get("class_uid") == 1007:
        proc = doc.get("process") or {}
        proc_fields("process", proc)
        proc_fields("actor.process", proc.get("parent_process") or {})
    else:
        proc_fields("process", (doc.get("actor") or {}).get("process") or {})
    f = doc.get("file") or ((doc.get("driver") or {}).get("file")) or ((doc.get("module") or {}).get("file")) or {}
    put("file.path", f.get("path"))
    put("file.size", f.get("size"))
    for h in f.get("hashes") or []:
        put({1: "file.md5", 2: "file.sha1", 3: "file.sha256"}.get(h.get("algorithm_id"), "file.hashes"), h.get("value"))
    rk = doc.get("reg_key") or {}
    rv = doc.get("reg_value") or {}
    put("registry.key", rk.get("path") or rv.get("path"))
    if rv and not rv.get("is_default"):
        put("registry.value", rv.get("name"))
    put("registry.data", rv.get("data"))
    if rv.get("type_id") not in (None, 99) or rv.get("type"):
        put("registry.type", rv.get("type"))
    req = doc.get("http_request") or {}
    url = req.get("url") or {}
    if doc.get("class_uid") == 4002:
        put("http.method", req.get("http_method"))
        put("http.url", url.get("url_string"))
        put("http.query", url.get("query_string"))
        put("http.host", url.get("hostname"))
        put("http.referrer", req.get("referrer"))
        code = (doc.get("http_response") or {}).get("code")
        if "http_status" in doc or code:
            put("http.status", code)
    put("http.user_agent", req.get("user_agent"))
    q = doc.get("query") or {}
    put("dns.query", q.get("hostname"))
    put("dns.qtype", q.get("type"))
    if doc.get("rcode") is not None:
        put("dns.rcode", doc.get("rcode"))
    answers = [a.get("rdata") for a in doc.get("answers") or [] if a.get("rdata")]
    put("dns.answer", answers[0] if len(answers) == 1 else answers or None)
    em = doc.get("email") or {}
    put("email.from", em.get("from"))
    put("email.to", (em.get("to") or [None])[0])
    put("email.subject", em.get("subject"))
    if "logon_type_id" in doc:
        put("auth.logon_type", doc["logon_type_id"] if doc["logon_type_id"] != 99 else doc.get("logon_type"))
    if "auth_protocol" in doc:
        put("auth.protocol", doc.get("auth_protocol"))
    if doc.get("status_detail") and doc.get("class_uid") == 3002:
        put("auth.failure", doc["status_detail"])
    md = doc.get("metadata") or {}
    if md.get("event_code"):
        put("win.event_id", md["event_code"])
    grp = doc.get("group") or {}
    if doc.get("class_uid") == 3006:
        put("group.name", grp.get("name"))
        put("group.member", (doc.get("user") or {}).get("name"))
    api = doc.get("api") or {}
    put("api.operation", api.get("operation"))
    put("api.service", (api.get("service") or {}).get("name"))
    put("api.request_id", (api.get("request") or {}).get("uid"))
    if doc.get("status_code"):           # to_ocsf writes status_code only from an API error code
        put("api.error", doc["status_code"])
    if doc.get("class_uid") == 6003:
        restored = (C.restore((doc.get("unmapped") or {}).get("x_ulpf")) or {}).get("source") or {}
        if not restored.get("ip"):
            put("api.src_ip", (doc.get("src_endpoint") or {}).get("ip"))
    cloud = doc.get("cloud") or {}
    put("cloud.provider", cloud.get("provider") if cloud.get("provider") != "Unknown" else None)
    put("cloud.region", cloud.get("region"))
    put("cloud.account", (cloud.get("account") or {}).get("uid"))
    if doc.get("class_uid") == 6003:
        au = (doc.get("actor") or {}).get("user") or {}
        put("cloud.actor_uid", au.get("uid"))
        put("cloud.actor_type", au.get("type"))
    if doc.get("class_uid") == 6002:
        put("service.name", (doc.get("app") or {}).get("name"))
    if doc.get("class_uid") == 1006:
        put("service.name", (doc.get("job") or {}).get("name"))
    if doc.get("class_uid") == 201004:
        put("service.name", (doc.get("win_service") or {}).get("name"))
    if doc.get("class_uid") == 1008:
        put("win.channel", doc.get("log_name"))
    put("win.provider", doc.get("log_provider") or md.get("log_provider"))
    return p


def from_ocsf(doc: dict) -> dict:
    """A unified event from an OCSF document (lossless for ULPF's own documents)."""
    from ulpf.engine.schema import new_unified_event, severity_label
    md = doc.get("metadata") or {}
    unm = doc.get("unmapped") or {}
    parsed: dict[str, Any] = {}
    for k, v in unm.items():
        if k.startswith("x_") and k != "x_ulpf" and isinstance(v, dict):
            parsed.update(v)
    parsed.update(_facet_fields(doc))
    base = C.restore(unm.get("x_ulpf"))
    e = new_unified_event(event_id=md.get("uid"), timestamp=C.iso_from_ms(doc.get("time")))
    if base is not None:
        for k, v in base.items():
            e[k] = v
    else:
        cls = doc.get("class_uid", 0)
        e["category"] = _CLASS_CATEGORY.get(cls, "other")
        label = _LABEL.get(doc.get("severity_id", 0), "unknown")
        e["severity_label"] = label
        e["severity"] = _LABEL_SCORE[label]
        e["severity_label"] = severity_label(e["severity"])
        e["event_type"] = doc.get("type_name")
        e["timestamp_original"] = md.get("original_time")
        e["raw_format"] = "ocsf"
        e["tags"] = list(md.get("labels") or [])
        e["correlation_id"] = md.get("correlation_uid")
        prod = md.get("product") or {}
        e["device"].update({"vendor": prod.get("vendor_name"), "product": prod.get("name"),
                            "version": prod.get("version")})
        dev = doc.get("device") or {}
        e["device"].update({"hostname": dev.get("hostname"), "ip": dev.get("ip"), "serial": dev.get("uid"),
                            "type": dev.get("type")})
        for side, key in (("source", "src_endpoint"), ("destination", "dst_endpoint")):
            ep = doc.get(key) or {}
            e[side].update({"ip": ep.get("ip"), "port": ep.get("port"), "hostname": ep.get("hostname"),
                            "mac": ep.get("mac"), "interface": ep.get("interface_name"), "zone": ep.get("zone")})
            loc = ep.get("location") or {}
            pre = "src" if side == "source" else "dst"
            e["geo"].update({f"{pre}_country_code": loc.get("country"), f"{pre}_city": loc.get("city"),
                             f"{pre}_latitude": loc.get("lat"), f"{pre}_longitude": loc.get("long")})
        ci = doc.get("connection_info") or {}
        tr = doc.get("traffic") or {}
        e["network"].update({"protocol": (ci.get("protocol_name") or "").upper() or None,
                             "protocol_number": ci.get("protocol_num"),
                             "direction": {1: "inbound", 2: "outbound", 3: "internal"}.get(ci.get("direction_id")),
                             "session_id": ci.get("uid"), "bytes_in": tr.get("bytes_in"),
                             "bytes_out": tr.get("bytes_out"), "bytes_total": tr.get("bytes"),
                             "packets_in": tr.get("packets_in"), "packets_out": tr.get("packets_out"),
                             "application": doc.get("app_name")})
        u = doc.get("user") or ((doc.get("actor") or {}).get("user")) or {}
        e["user"].update({"name": u.get("name"), "domain": u.get("domain"), "id": u.get("uid"),
                          "email": u.get("email_addr")})
        disp = (doc.get("disposition") or "").lower()
        e["action"] = {"allowed": "allowed", "blocked": "blocked", "dropped": "dropped", "rejected": "rejected",
                       "reset": "reset", "quarantined": "quarantined", "detected": "detected", "alert": "alerted",
                       "logged": "logged"}.get(disp) or ("success" if doc.get("status_id") == 1 else
                                                         "failed" if doc.get("status_id") == 2 else "other")
        fr = doc.get("firewall_rule") or {}
        fi = doc.get("finding_info") or {}
        e["rule"].update({"id": fr.get("uid") or fi.get("uid"), "name": fr.get("name") or fi.get("title"),
                          "description": fr.get("desc"), "category": fr.get("category")})
    e["event_id"] = md.get("uid") or e["event_id"]
    e["message"] = doc.get("message")
    e["raw_event"] = doc.get("raw_data")
    e["parsed_fields"] = parsed
    if base is None:
        e["metadata"]["parser_id"] = "ocsf"
        e["metadata"]["parser_name"] = "OCSF import"
    return e


# ---------------------------------------------------------------------------
# Conformance
# ---------------------------------------------------------------------------

_BASE = {"string_t": str, "integer_t": int, "long_t": int, "float_t": (int, float), "boolean_t": bool,
         "timestamp_t": int, "object_t": dict, "json_t": object}


def _base_type(t: str) -> str:
    types = schema()["types"]
    seen = 0
    while t not in _BASE and types.get(t) and seen < 5:
        t = types[t]
        seen += 1
    return t if t in _BASE else "string_t"


def _check_value(spec: list, v, path: str, profiles: set, errors: list) -> None:
    req, typ, obj, enum, prof, is_array, _sib = spec
    if is_array:
        if not isinstance(v, list):
            errors.append(f"{path}: expected an array")
            return
        for i, x in enumerate(v):
            _check_value([req, typ, obj, enum, prof, False, None], x, f"{path}[{i}]", profiles, errors)
        return
    base = _base_type(typ)
    py = _BASE[base]
    if base in ("integer_t", "long_t", "timestamp_t") and isinstance(v, bool):
        errors.append(f"{path}: expected {typ}, got bool")
        return
    if py is not object and not isinstance(v, py):
        errors.append(f"{path}: expected {typ}, got {type(v).__name__}")
        return
    if typ == "port_t" and not 0 <= v <= 65535:
        errors.append(f"{path}: port out of range")
    if enum and base in ("integer_t", "long_t") and str(v) not in enum:
        errors.append(f"{path}: {v} is not one of {sorted(enum, key=int)}")
    if obj and base == "object_t" and obj != "object":
        _check_object(schema()["objects"].get(obj, {}).get("attributes"), v, path, profiles, errors)


def _check_object(attrs: dict | None, v: dict, path: str, profiles: set, errors: list) -> None:
    if attrs is None:
        return
    for k, x in v.items():
        spec = attrs.get(k)
        if spec is None:
            errors.append(f"{path}.{k}: not an attribute of this object")
            continue
        if spec[4] and spec[4] not in profiles:
            errors.append(f"{path}.{k}: belongs to profile {spec[4]}, not declared")
        _check_value(spec, x, f"{path}.{k}", profiles, errors)
    for k, spec in attrs.items():
        if spec[0] == "r" and k not in v and (not spec[4] or spec[4] in profiles):
            errors.append(f"{path}.{k}: required attribute missing")
    for k, spec in attrs.items():     # enum siblings carry the caption of their _id
        sib = spec[6]
        if sib and k in v and sib in v and spec[3] and v[k] != 99 and str(v[k]) in spec[3]:
            if v[sib] != spec[3][str(v[k])]:
                errors.append(f"{path}.{sib}: {v[sib]!r} is not the caption of {k}={v[k]}")


def validate(doc: dict) -> list[str]:
    """Problems of an OCSF 1.3.0 document ([] when it conforms)."""
    errors: list[str] = []
    cls = doc.get("class_uid")
    info = schema()["classes"].get(str(cls))
    if info is None:
        return [f"unknown class_uid {cls!r}"]
    profiles = set((doc.get("metadata") or {}).get("profiles") or [])
    _check_object(info["attributes"], doc, info["name"], profiles, errors)
    if doc.get("type_uid") != cls * 100 + doc.get("activity_id", -1):
        errors.append("type_uid is not class_uid * 100 + activity_id")
    if doc.get("category_uid") != info["category_uid"]:
        errors.append("category_uid does not match the class")
    if (doc.get("metadata") or {}).get("version") != VERSION:
        errors.append("metadata.version is not " + VERSION)
    return errors
