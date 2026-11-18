"""
Google Security Operations (Chronicle) UDM view of the unified event, its
inverse, entity records, and a conformance check.

Events follow UDM's noun-verb model: ``metadata.event_type`` is the verb
(``NETWORK_CONNECTION``, ``USER_LOGIN``, ``PROCESS_LAUNCH`` ...); ``principal``
is the acting machine / user / process, ``target`` what was acted on,
``observer`` the reporting device; ``network`` and ``extensions.auth`` the
connection and authentication; ``security_result`` what a control or a
detection concluded. JSON follows the proto3 JSON mapping (field names as in
the field list, enums as names, timestamps as RFC 3339 strings, 64-bit
integers as numbers).

Vendor fields without a UDM home go to ``additional["x_<vendor>"]``; the
unified fields UDM cannot hold exactly go to ``additional["x_ulpf"]``, so
``from_udm(to_udm(e))`` gives ``e`` back (``parsed_fields`` reduced to facets
and vendor-only fields).

``validate(doc)`` checks field names and enum values against the UDM field list
(``udm_catalog.json``, built by ``scripts/build_standards_catalog.py``) and the
required fields of each event type in the UDM usage guide
(https://cloud.google.com/chronicle/docs/unified-data-model/udm-usage).
"""
from __future__ import annotations

import functools
import json
import os
from typing import Any

from ulpf.engine.standards import common as C
from ulpf.engine.standards.facets import CANDIDATES, Activity, classify, facets, unmapped_vendor_fields, \
    vendor_namespace

_HERE = os.path.dirname(os.path.abspath(__file__))


@functools.lru_cache(maxsize=1)
def catalog() -> dict:
    with open(os.path.join(_HERE, "udm_catalog.json"), encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------

_TYPES: dict[str, dict[str, str]] = {
    "network": {"": "NETWORK_CONNECTION"}, "ssh": {"": "NETWORK_CONNECTION"}, "rdp": {"": "NETWORK_CONNECTION"},
    "smb": {"": "NETWORK_CONNECTION"}, "ntp": {"": "NETWORK_CONNECTION"}, "tunnel": {"": "NETWORK_CONNECTION"},
    "dhcp": {"": "NETWORK_CONNECTION"},   # NETWORK_DHCP needs network.dhcp.opcode, unknown here
    "ftp": {"": "NETWORK_FTP"}, "http": {"": "NETWORK_HTTP"}, "dns": {"": "NETWORK_DNS"},
    "email": {"": "EMAIL_TRANSACTION"},
    "authentication": {"logoff": "USER_LOGOUT", "": "USER_LOGIN"},
    "account": {"create": "USER_CREATION", "delete": "USER_DELETION", "password_change": "USER_CHANGE_PASSWORD",
                "password_reset": "USER_CHANGE_PASSWORD", "": "USER_UNCATEGORIZED"},
    "group": {"create": "GROUP_CREATION", "delete": "GROUP_DELETION", "": "GROUP_MODIFICATION"},
    "process": {"launch": "PROCESS_LAUNCH", "terminate": "PROCESS_TERMINATION", "open": "PROCESS_OPEN",
                "inject": "PROCESS_INJECTION", "": "PROCESS_UNCATEGORIZED"},
    "file": {"create": "FILE_CREATION", "delete": "FILE_DELETION", "modify": "FILE_MODIFICATION",
             "read": "FILE_READ", "open": "FILE_OPEN", "": "FILE_UNCATEGORIZED"},
    "registry_key": {"create": "REGISTRY_CREATION", "delete": "REGISTRY_DELETION", "modify": "REGISTRY_MODIFICATION",
                     "rename": "REGISTRY_MODIFICATION", "": "REGISTRY_UNCATEGORIZED"},
    "registry_value": {"create": "REGISTRY_CREATION", "delete": "REGISTRY_DELETION",
                       "modify": "REGISTRY_MODIFICATION", "": "REGISTRY_UNCATEGORIZED"},
    "kernel_extension": {"": "PROCESS_MODULE_LOAD"}, "module": {"": "PROCESS_MODULE_LOAD"},
    "scheduled_job": {"create": "SCHEDULED_TASK_CREATION", "delete": "SCHEDULED_TASK_DELETION",
                      "enable": "SCHEDULED_TASK_ENABLE", "disable": "SCHEDULED_TASK_DISABLE",
                      "modify": "SCHEDULED_TASK_MODIFICATION", "": "SCHEDULED_TASK_UNCATEGORIZED"},
    "service": {"install": "SERVICE_CREATION", "create": "SERVICE_CREATION", "delete": "SERVICE_DELETION",
                "launch": "SERVICE_START", "start": "SERVICE_START", "terminate": "SERVICE_STOP", "stop": "SERVICE_STOP",
                "modify": "SERVICE_MODIFICATION", "": "SERVICE_UNSPECIFIED"},
    "application": {"start": "STATUS_STARTUP", "stop": "STATUS_SHUTDOWN", "": "STATUS_UPDATE"},
    "event_log": {"clear": "SYSTEM_AUDIT_LOG_WIPE", "": "SYSTEM_AUDIT_LOG_UNCATEGORIZED"},
    "api": {"create": "RESOURCE_CREATION", "delete": "RESOURCE_DELETION", "modify": "RESOURCE_WRITTEN",
            "read": "RESOURCE_READ", "": "USER_RESOURCE_ACCESS"},
    "config": {"": "SETTING_MODIFICATION"},
    "finding": {"": "GENERIC_EVENT"}, "base": {"": "GENERIC_EVENT"},
}


def event_type(act: Activity) -> str:
    t = _TYPES[act.kind]
    return t.get(act.verb) or t[""]


_SEVERITY = {"info": "INFORMATIONAL", "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}
_ACTION = {"allowed": "ALLOW", "permitted": "ALLOW", "accepted": "ALLOW", "success": "ALLOW",
           "blocked": "BLOCK", "denied": "BLOCK", "dropped": "BLOCK", "rejected": "BLOCK", "reset": "BLOCK",
           "quarantined": "QUARANTINE", "failed": "FAIL", "failure": "FAIL"}
_IP_PROTO = {"TCP": "TCP", "UDP": "UDP", "ICMP": "ICMP", "IPV6-ICMP": "ICMP6", "ICMP6": "ICMP6", "GRE": "GRE",
             "ESP": "ESP", "SCTP": "SCTP", "IGMP": "IGMP", "EIGRP": "EIGRP", "PIM": "PIM", "VRRP": "VRRP"}
_LOGON_MECH = {2: "INTERACTIVE", 3: "NETWORK", 4: "BATCH", 5: "SERVICE", 7: "UNLOCK", 8: "NETWORK_CLEAR_TEXT",
               9: "NEW_CREDENTIALS", 10: "REMOTE_INTERACTIVE", 11: "CACHED_INTERACTIVE",
               12: "CACHED_REMOTE_INTERACTIVE", 13: "CACHED_UNLOCK"}
_CLOUD = {"AWS": "AMAZON_WEB_SERVICES", "GCP": "GOOGLE_CLOUD_PLATFORM", "Azure": "MICROSOFT_AZURE"}
_REG_TYPE = {"REG_SZ": "SZ", "REG_EXPAND_SZ": "EXPAND_SZ", "REG_BINARY": "BINARY", "REG_DWORD": "DWORD",
             "REG_DWORD_BIG_ENDIAN": "DWORD_BIG_ENDIAN", "REG_LINK": "LINK", "REG_MULTI_SZ": "MULTI_SZ",
             "REG_QWORD": "QWORD", "REG_NONE": "NONE"}


def _app_protocol(name) -> str | None:
    if not name:
        return None
    n = str(name).upper().replace("-", "_")
    return n if n in catalog()["enums"]["Network.ApplicationProtocol"] else None


# ---------------------------------------------------------------------------
# Nouns
# ---------------------------------------------------------------------------

def _location(geo: dict, side: str) -> dict | None:
    loc = {"country_or_region": geo.get(f"{side}_country"), "city": geo.get(f"{side}_city"),
           "region_latitude": geo.get(f"{side}_latitude"), "region_longitude": geo.get(f"{side}_longitude")}
    return loc if any(v is not None for v in loc.values()) else None


def _machine(ep: dict, geo: dict | None = None, side: str = "") -> dict:
    port = C.as_int(ep.get("port"))
    return {"hostname": ep.get("hostname"), "ip": [str(ep["ip"])] if ep.get("ip") else None,
            "mac": [str(ep["mac"])] if ep.get("mac") else None,
            "port": port if port is not None and 0 <= port <= 65535 else None,
            "location": _location(geo or {}, side) if side else None}


def _user(name=None, domain=None, uid=None, email=None) -> dict | None:
    u = {"userid": name, "windows_sid": uid if uid and str(uid).startswith("S-1-") else None,
         "product_object_id": uid if uid and not str(uid).startswith("S-1-") else None,
         "email_addresses": [email] if email else None,
         "group_identifiers": None}
    if domain:
        u["user_display_name"] = f"{domain}\\{name}" if name else None
    return u if any(v for v in u.values()) else None


def _process(f, prefix: str) -> dict | None:
    name = f.take(f"{prefix}.name")
    path = f.take(f"{prefix}.path") if prefix == "process" else None
    pid = f.take(f"{prefix}.pid")
    cmd = f.take(f"{prefix}.cmd_line")
    uid = f.take(f"{prefix}.uid")
    if name is None and pid is None and cmd is None and path is None:
        return None
    pidn = C.as_int(pid)
    p: dict[str, Any] = {"pid": str(pidn) if pidn is not None else None, "command_line": cmd,
                         "product_specific_process_id": uid}
    full = path or name
    if full:
        p["file"] = {"full_path": str(full)}
        if prefix == "process":
            p["file"].update(_hashes(f))
    return p


def _hashes(f) -> dict:
    out = {}
    for name, key in (("file.md5", "md5"), ("file.sha1", "sha1"), ("file.sha256", "sha256")):
        v = f.take(name)
        if v:
            out[key] = str(v)
    raw = f.get("file.hashes")
    if raw and isinstance(raw, str) and "=" in raw:
        f.take("file.hashes")
        for part in raw.split(","):
            k, _, v = part.partition("=")
            key = {"MD5": "md5", "SHA1": "sha1", "SHA256": "sha256", "SHA512": "sha512"}.get(k.strip().upper())
            if key and v and key not in out:
                out[key] = v.strip()
    return out


# ---------------------------------------------------------------------------
# to_udm
# ---------------------------------------------------------------------------

def _to_udm(event: dict, lossless: bool = True):
    f = facets(event)
    act = classify(event, f)
    etype = event_type(act)
    geo = event.get("geo") or {}
    dev = event.get("device") or {}
    net = event.get("network") or {}
    user = event.get("user") or {}
    thr = event.get("threat") or {}
    rule = event.get("rule") or {}
    meta = event.get("metadata") or {}
    src = event.get("source") or {}
    dst = event.get("destination") or {}

    principal = _machine(src, geo, "src")
    target = _machine(dst, geo, "dst")
    observer = {"hostname": dev.get("hostname"), "ip": [str(dev["ip"])] if dev.get("ip") else None,
                "asset_id": f"{dev.get('vendor') or 'device'}:{dev['serial']}" if dev.get("serial") else None}
    su, tu = user.get("source") or {}, user.get("target") or {}
    primary = _user(user.get("name"), user.get("domain"), user.get("id"), user.get("email"))
    actor_user = _user(su.get("name"), su.get("domain"), su.get("id"))
    target_user = _user(tu.get("name"), tu.get("domain"), tu.get("id"))
    k = act.kind
    endpoint_kinds = {"process", "file", "registry_key", "registry_value", "kernel_extension", "module",
                      "scheduled_job", "service", "application", "event_log", "config", "account", "group"}
    if k in endpoint_kinds and not (principal["hostname"] or principal["ip"]):
        # events about one host: the host is the principal machine
        principal["hostname"] = dev.get("hostname")
        principal["ip"] = [str(dev["ip"])] if dev.get("ip") else principal["ip"]

    doc: dict[str, Any] = {"metadata": {
        "event_timestamp": C.iso_utc(event.get("timestamp")),
        "collected_timestamp": C.iso_utc(meta.get("ingestion_time")),
        "event_type": etype,
        "vendor_name": dev.get("vendor"), "product_name": dev.get("product"), "product_version": dev.get("version"),
        "product_event_type": None if event.get("event_type") is None else str(event["event_type"]),
        "product_log_id": event.get("event_id"), "description": event.get("message"),
        "log_type": (event.get("raw_format") or "").upper() or None,
    }}
    network: dict[str, Any] = {
        "ip_protocol": _IP_PROTO.get(str(net.get("protocol") or "").upper()),
        "application_protocol": _app_protocol(net.get("application")),
        "direction": {"inbound": "INBOUND", "outbound": "OUTBOUND"}.get(str(net.get("direction") or "").lower()),
        "sent_bytes": net.get("bytes_out") if isinstance(net.get("bytes_out"), int) and net["bytes_out"] >= 0 else None,
        "received_bytes": net.get("bytes_in") if isinstance(net.get("bytes_in"), int) and net["bytes_in"] >= 0 else None,
        "sent_packets": net.get("packets_out"), "received_packets": net.get("packets_in"),
        "total_bytes": net.get("bytes_total"),
        "session_id": None if net.get("session_id") is None else str(net["session_id"]),
    }
    if k in ("authentication",):
        target["user"] = target_user or primary
        if actor_user:
            principal["user"] = actor_user
        lt = C.as_int(f.take("auth.logon_type"))
        auth = {"type": "VPN" if event.get("category") == "vpn" else "MACHINE",
                "mechanism": [_LOGON_MECH[lt]] if lt in _LOGON_MECH else None,
                "auth_details": f.take("auth.protocol")}
        doc["extensions"] = {"auth": auth}
        if not principal["ip"] and f.get("api.src_ip"):         # cloud console sign-in
            principal["ip"] = [str(f.take("api.src_ip"))]
        if f.get("api.service"):
            target["application"] = str(f.take("api.service"))
        if not (principal["hostname"] or principal["ip"]):
            target["hostname"] = target["hostname"] or dev.get("hostname")
            target["ip"] = target["ip"] or ([str(dev["ip"])] if dev.get("ip") else None)
    elif k == "account":
        target["user"] = target_user or primary
        if actor_user:
            principal["user"] = actor_user
    elif k == "group":
        gname = f.take("group.name") or (target_user or {}).get("userid")
        target["group"] = {"group_display_name": gname} if gname else None
        member = f.take("group.member")
        if member:
            target["user"] = {"userid": str(member)}
        principal["user"] = actor_user or primary
    elif k == "process":
        tp = _process(f, "process")
        pp = _process(f, "actor.process")
        if tp is not None and pp is not None:
            tp["parent_process"] = pp
        target["process"] = tp
        principal["process"] = pp
        principal["user"] = actor_user or primary
    elif k in ("file", "registry_key", "registry_value", "kernel_extension", "module", "scheduled_job",
               "service", "event_log", "config", "application", "api"):
        principal["process"] = _process(f, "process") or _process(f, "actor.process")
        principal["user"] = actor_user or primary
        if k == "file":
            path = f.take("file.path")
            target["file"] = {"full_path": str(path) if path else None,
                              "size": C.as_int(f.take("file.size")), **_hashes(f)}
        elif k in ("registry_key", "registry_value"):
            rtype = f.take("registry.type")
            target["registry"] = {"registry_key": str(f.take("registry.key") or ""),
                                  "registry_value_name": f.take("registry.value"),
                                  "registry_value_data": None if f.get("registry.data") is None
                                  else str(f.take("registry.data")),
                                  "registry_value_type": _REG_TYPE.get(str(rtype or "").upper())}
            if rtype and target["registry"]["registry_value_type"] is None:
                f.emitted.discard("registry.type")
        elif k in ("kernel_extension", "module"):
            mod = f.take("file.path") or f.get("process.path")
            target["process"] = {"file": {"full_path": str(mod)}} if mod else {"file": {"full_path": ""}}
            if principal.get("process") is None:
                principal["process"] = {"file": {"full_path": ""}}
        elif k == "scheduled_job":
            target["resource"] = {"name": str(f.take("service.name") or event.get("event_type") or ""),
                                  "resource_type": "TASK"}
        elif k == "service":
            target["application"] = str(f.take("service.name") or event.get("event_type") or "")
            target["user"] = target_user or primary or {"userid": ""}
        elif k == "event_log":
            target["resource"] = {"name": f.take("win.channel")} if f.get("win.channel") else None
        elif k == "config":
            target["resource"] = {"resource_type": "SETTING", "name": event.get("event_type")}
        elif k == "application":
            target["application"] = f.take("service.name") or f.take("app.name")
        elif k == "api":
            op = f.take("api.operation")
            svc = f.take("api.service")
            target["application"] = svc
            target["resource"] = {"name": str(op), "type": "API_OPERATION"}
            region = f.take("cloud.region")
            acct = f.take("cloud.account")
            provider = f.take("cloud.provider")
            target["cloud"] = C.clean({"environment": _CLOUD.get(str(provider)) if provider else None,
                                       "availability_zone": region,
                                       "project": {"product_object_id": str(acct)} if acct else None})
            uid = f.take("cloud.actor_uid")
            principal["user"] = C.clean({**(primary or {}), "product_object_id": uid,
                                         "attribute": None}) or None
            if f.get("cloud.actor_type"):
                principal.setdefault("user", {})
                principal["user"] = {**(principal["user"] or {}),
                                     "role_name": str(f.take("cloud.actor_type"))}
            if not principal["ip"] and f.get("api.src_ip"):
                principal["ip"] = [str(f.take("api.src_ip"))]
            ua = f.take("http.user_agent")
            if ua:
                network["http"] = {"user_agent": ua}
            if f.get("api.request_id"):
                doc["metadata"]["product_deployment_id"] = None
                network["session_id"] = network["session_id"] or str(f.take("api.request_id"))
            if f.get("api.error"):
                doc["metadata"]["product_event_type"] = doc["metadata"]["product_event_type"]
    if k in ("network", "ssh", "rdp", "smb", "ntp", "tunnel", "dhcp", "ftp", "http", "dns", "email"):
        principal["process"] = _process(f, "process") or _process(f, "actor.process")
        if primary:
            principal["user"] = primary
    if k == "http":
        url = f.take("http.url")
        target["url"] = str(url) if url else None
        if not target.get("hostname"):
            target["hostname"] = f.take("http.host")
        code = C.as_int(f.take("http.status"))
        network["http"] = {"method": str(f.take("http.method")).upper() if f.get("http.method") else None,
                           "user_agent": f.take("http.user_agent"), "referral_url": f.take("http.referrer"),
                           "response_code": code}
        network["application_protocol"] = network["application_protocol"] or "HTTP"
        q = f.take("http.query")
        if q:
            target["url"] = (target["url"] or "") + ("" if str(q).startswith("?") else "?") + str(q)
    if k == "dns":
        q = f.take("dns.query")
        ans = f.take("dns.answer")
        rc = f.take("dns.rcode")
        dns: dict[str, Any] = {"questions": [{"name": str(q or "")}],
                               "answers": [{"data": str(a)} for a in (ans if isinstance(ans, list) else [ans])]
                               if ans else None}
        qtype = f.get("dns.qtype")
        qt = _QTYPE.get(str(qtype).upper()) if qtype is not None else None
        if qt is not None:
            dns["questions"][0]["type"] = qt
            f.take("dns.qtype")
        rcn = C.as_int(rc) if rc is not None else None
        if rcn is None and rc is not None:
            rcn = _RCODE.get(str(rc).upper().replace("_", ""))
        if rcn is not None:
            dns["response_code"] = rcn
            dns["response"] = True
        elif rc is not None:
            f.emitted.discard("dns.rcode")
        network["dns"] = dns
        network["application_protocol"] = "DNS"
    if k == "email":
        to = f.take("email.to")
        network["email"] = {"from": f.take("email.from"), "to": [str(to)] if to else None,
                            "subject": [str(f.take("email.subject"))] if f.get("email.subject") else None}
    if k == "tunnel" and primary:
        principal["user"] = primary

    # security_result: what a control applied or a detection concluded
    action = (event.get("action") or "").lower()
    sev = _SEVERITY.get(event.get("severity_label") or "")
    sr: dict[str, Any] = {
        "action": [_ACTION[action]] if action in _ACTION else None,
        "severity": sev, "rule_id": None if rule.get("id") is None else str(rule["id"]), "rule_name": rule.get("name"),
        "description": rule.get("description"),
        "threat_name": thr.get("signature"), "threat_id": None if thr.get("signature_id") is None
        else str(thr["signature_id"]),
        "category_details": [thr["category"]] if thr.get("category") else None,
        "confidence_score": float(thr["confidence"]) if thr.get("confidence") is not None else None,
        "summary": event.get("message") if k == "finding" else None,
        "alert_state": "ALERTING" if k == "finding" else None,
    }
    if thr.get("ioc_value"):
        sr["category"] = ["NETWORK_MALICIOUS"]
        sr["about"] = {"ip": [str(thr["ioc_value"])]} if thr.get("ioc_type") == "ip" else None
    elif k == "authentication" and action in ("failed", "failure", "denied"):
        sr["category"] = ["AUTH_VIOLATION"]
    elif event.get("category") == "firewall" and action in C.BLOCKED:
        sr["category"] = ["ACL_VIOLATION"]
    ext = event.get("extensions") or {}
    det = ext.get("detection") if isinstance(ext.get("detection"), dict) else {}
    if det.get("techniques") or det.get("tactics"):
        sr["attack_details"] = {"techniques": [{"id": t} for t in det.get("techniques") or []] or None,
                                "tactics": [{"name": t} for t in det.get("tactics") or []] or None}
    eid = f.get("win.event_id")
    if eid is not None:
        f.take("win.event_id")
        doc["metadata"]["product_event_type"] = str(eid)
        if f.get("win.provider"):
            doc["metadata"]["product_name"] = doc["metadata"]["product_name"] or None
            observer["application"] = str(f.take("win.provider"))
    doc.update({"principal": principal, "target": target, "observer": observer, "network": network,
                "security_result": [sr]})
    doc = C.clean(doc)
    _fit(doc, observer)
    vendor = unmapped_vendor_fields(event, f)
    doc["additional"] = {**({vendor_namespace(event): vendor} if vendor else {}),
                         **({"x_ulpf": C.residual(event, raw=True)} if lossless else {})}
    return doc, f


def to_udm(event: dict, lossless: bool = True) -> dict:
    """The UDM event. ``lossless=False`` leaves out ``additional.x_ulpf`` (what ``from_udm``
    needs to restore the ULPF event exactly) — for evaluating rules, about half the cost."""
    return _to_udm(event, lossless)[0]


def _fit(doc: dict, observer: dict) -> None:
    """When the event lacks what its type requires, use the type UDM prescribes for that case:
    NETWORK_CONNECTION for protocol events without protocol details, STATUS_UPDATE (the
    device as principal) for device messages without endpoints, else GENERIC_EVENT."""
    md = doc["metadata"]
    for _ in range(3):
        if not requirements(doc):
            return
        et = md["event_type"]
        machines = _has_machine(doc.get("principal")) or _has_machine(doc.get("target"))
        if et.startswith("NETWORK_") and et != "NETWORK_CONNECTION" and machines:
            md["event_type"] = "NETWORK_CONNECTION"
        elif et == "NETWORK_CONNECTION" and not machines and _has_machine(observer):
            md["event_type"] = "STATUS_UPDATE"
            doc["principal"] = {**(doc.get("principal") or {}),
                                **{k: v for k, v in observer.items() if k in ("hostname", "ip") and v}}
        else:
            md["event_type"] = "GENERIC_EVENT"


_QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255}
_RCODE = {"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "NOTIMP": 4, "REFUSED": 5}


# ---------------------------------------------------------------------------
# Entities
# ---------------------------------------------------------------------------

def to_udm_entities(event: dict) -> list[dict]:
    """Entity context records for what the event observed: the reporting asset, users,
    addresses and files (``metadata.entity_type`` ASSET, USER, IP_ADDRESS, FILE)."""
    dev = event.get("device") or {}
    ts = C.iso_utc(event.get("timestamp"))
    meta = {"collected_timestamp": ts, "vendor_name": dev.get("vendor"), "product_name": dev.get("product"),
            "product_version": dev.get("version"), "source_type": "ENTITY_CONTEXT"}
    out = []

    def add(etype: str, noun: dict, pid: str | None = None):
        noun = C.clean(noun)
        if noun:
            out.append({"metadata": C.clean({**meta, "entity_type": etype, "product_entity_id": pid}), "entity": noun})
    if dev.get("hostname") or dev.get("ip"):
        add("ASSET", {"hostname": dev.get("hostname"), "ip": [dev["ip"]] if dev.get("ip") else None,
                      "asset": {"hostname": dev.get("hostname"), "ip": [dev["ip"]] if dev.get("ip") else None,
                                "product_object_id": dev.get("serial")}}, dev.get("serial"))
    user = event.get("user") or {}
    for u in (user, user.get("source") or {}, user.get("target") or {}):
        if u.get("name"):
            add("USER", {"user": _user(u.get("name"), u.get("domain"), u.get("id"), u.get("email"))})
    seen = set()
    for side in ("source", "destination"):
        ip = (event.get(side) or {}).get("ip")
        if ip and ip not in seen:
            seen.add(ip)
            add("IP_ADDRESS", {"ip": [str(ip)]})
    f = facets(event)
    hashes = _hashes(f)
    path = f.get("file.path") or f.get("process.path")
    if hashes or path:
        add("FILE", {"file": {"full_path": None if path is None else str(path), **hashes}})
    return out


# ---------------------------------------------------------------------------
# from_udm
# ---------------------------------------------------------------------------

_TYPE_CATEGORY = {"NETWORK": "network", "USER_LOGIN": "authentication", "USER_LOGOUT": "authentication",
                  "USER": "authentication", "GROUP": "authentication", "PROCESS": "endpoint", "FILE": "endpoint",
                  "REGISTRY": "endpoint", "SCHEDULED": "endpoint", "SERVICE": "system", "STATUS": "system",
                  "SYSTEM": "audit", "RESOURCE": "audit", "SETTING": "audit", "EMAIL": "network",
                  "NETWORK_HTTP": "web", "NETWORK_DNS": "dns"}


def _facet_fields(doc: dict) -> dict:
    p: dict[str, Any] = {}
    canon = {k: v[0] for k, v in CANDIDATES.items()}

    def put(facet, value):
        if value not in (None, "", [], {}):
            p[canon[facet]] = value
    etype = (doc.get("metadata") or {}).get("event_type") or ""
    pr, tg = doc.get("principal") or {}, doc.get("target") or {}
    net = doc.get("network") or {}

    def proc_fields(prefix: str, pr_: dict) -> None:
        path = (pr_.get("file") or {}).get("full_path")
        put(f"{prefix}.name", path)
        if prefix == "process":
            put("process.path", path)
        put(f"{prefix}.pid", pr_.get("pid"))
        put(f"{prefix}.cmd_line", pr_.get("command_line"))
        put(f"{prefix}.uid", pr_.get("product_specific_process_id"))
        fi = pr_.get("file") or {}
        if prefix == "process":
            for h in ("md5", "sha1", "sha256"):
                put(f"file.{h}", fi.get(h))
    if etype.startswith("PROCESS_") and etype != "PROCESS_MODULE_LOAD":
        proc_fields("process", tg.get("process") or {})
        proc_fields("actor.process", pr.get("process") or {})
    else:
        proc_fields("process", pr.get("process") or {})
    if etype == "PROCESS_MODULE_LOAD":
        put("file.path", ((tg.get("process") or {}).get("file") or {}).get("full_path"))
    fi = tg.get("file") or {}
    put("file.path", fi.get("full_path"))
    put("file.size", fi.get("size"))
    for h in ("md5", "sha1", "sha256"):
        put(f"file.{h}", fi.get(h))
    rg = tg.get("registry") or {}
    put("registry.key", rg.get("registry_key"))
    put("registry.value", rg.get("registry_value_name"))
    put("registry.data", rg.get("registry_value_data"))
    if rg.get("registry_value_type"):
        put("registry.type", "REG_" + rg["registry_value_type"])
    http = net.get("http") or {}
    # to_udm writes target.url and network.http only from HTTP details (whatever type the
    # event ended up with)
    put("http.method", http.get("method"))
    put("http.url", tg.get("url"))      # one field in UDM: path and query string together
    put("http.referrer", http.get("referral_url"))
    put("http.status", http.get("response_code"))
    put("http.user_agent", http.get("user_agent"))
    dns = net.get("dns") or {}
    qs = dns.get("questions") or []
    if qs:
        put("dns.query", qs[0].get("name"))
        if qs[0].get("type") is not None:
            put("dns.qtype", {v: k for k, v in _QTYPE.items()}.get(qs[0]["type"], qs[0]["type"]))
    if dns.get("response_code") is not None:
        put("dns.rcode", {v: k for k, v in _RCODE.items()}.get(dns["response_code"], dns["response_code"]))
    answers = [a.get("data") for a in dns.get("answers") or [] if a.get("data")]
    put("dns.answer", answers[0] if len(answers) == 1 else answers or None)
    em = net.get("email") or {}
    put("email.from", em.get("from"))
    put("email.to", (em.get("to") or [None])[0])
    put("email.subject", (em.get("subject") or [None])[0])
    auth = (doc.get("extensions") or {}).get("auth") or {}
    mech = auth.get("mechanism") or []
    if mech:
        put("auth.logon_type", {v: k for k, v in _LOGON_MECH.items()}.get(mech[0]))
    put("auth.protocol", auth.get("auth_details"))
    grp = tg.get("group") or {}
    if etype.startswith("GROUP_"):
        put("group.name", grp.get("group_display_name"))
        put("group.member", (tg.get("user") or {}).get("userid"))
    if etype in ("SCHEDULED_TASK_CREATION", "SCHEDULED_TASK_DELETION", "SCHEDULED_TASK_ENABLE",
                 "SCHEDULED_TASK_DISABLE", "SCHEDULED_TASK_MODIFICATION", "SCHEDULED_TASK_UNCATEGORIZED"):
        put("service.name", (tg.get("resource") or {}).get("name"))
    if etype.startswith("SERVICE_") or etype.startswith("STATUS_"):
        put("service.name", tg.get("application"))
    if etype.startswith("SYSTEM_AUDIT_LOG"):
        put("win.channel", (tg.get("resource") or {}).get("name"))
    if etype.startswith("RESOURCE_") or etype == "USER_RESOURCE_ACCESS":
        res = tg.get("resource") or {}
        if res.get("type") == "API_OPERATION":
            put("api.operation", res.get("name"))
            put("api.service", tg.get("application"))
            cloud = tg.get("cloud") or {}
            put("cloud.provider", {v: k for k, v in _CLOUD.items()}.get(cloud.get("environment")))
            put("cloud.region", cloud.get("availability_zone"))
            put("cloud.account", (cloud.get("project") or {}).get("product_object_id"))
            u = pr.get("user") or {}
            put("cloud.actor_uid", u.get("product_object_id"))
            put("cloud.actor_type", u.get("role_name"))
            put("api.request_id", net.get("session_id"))
            restored = (C.restore((doc.get("additional") or {}).get("x_ulpf")) or {})
            if not (restored.get("source") or {}).get("ip"):
                put("api.src_ip", (pr.get("ip") or [None])[0])
    if etype in ("USER_LOGIN", "USER_LOGOUT") and tg.get("application"):
        put("api.service", tg.get("application"))
        restored = (C.restore((doc.get("additional") or {}).get("x_ulpf")) or {})
        if not (restored.get("source") or {}).get("ip"):
            put("api.src_ip", (pr.get("ip") or [None])[0])
    md = doc.get("metadata") or {}
    obs = doc.get("observer") or {}
    if obs.get("application"):
        put("win.provider", obs["application"])
        put("win.event_id", md.get("product_event_type"))
    return p


def from_udm(doc: dict) -> dict:
    """A unified event from a UDM event (lossless for ULPF's own documents)."""
    from ulpf.engine.schema import new_unified_event, severity_label
    md = doc.get("metadata") or {}
    add = doc.get("additional") or {}
    parsed: dict[str, Any] = {}
    for k, v in add.items():
        if k.startswith("x_") and k != "x_ulpf" and isinstance(v, dict):
            parsed.update(v)
    parsed.update(_facet_fields(doc))
    base = C.restore(add.get("x_ulpf"))
    e = new_unified_event(event_id=md.get("product_log_id"), timestamp=md.get("event_timestamp"))
    if base is not None:
        e.update(base)
    else:
        et = md.get("event_type") or "GENERIC_EVENT"
        e["category"] = _TYPE_CATEGORY.get(et) or _TYPE_CATEGORY.get(et.split("_", 1)[0], "other")
        sr = (doc.get("security_result") or [{}])[0]
        label = {v: k for k, v in _SEVERITY.items()}.get(sr.get("severity"), "unknown")
        e["severity"] = {"unknown": 0, "info": 1, "low": 3, "medium": 5, "high": 7, "critical": 9}[label]
        e["severity_label"] = severity_label(e["severity"])
        e["event_type"] = md.get("product_event_type") or et
        e["raw_format"] = "udm"
        e["device"].update({"vendor": md.get("vendor_name"), "product": md.get("product_name"),
                            "version": md.get("product_version"),
                            "hostname": (doc.get("observer") or {}).get("hostname")})
        for side, key in (("source", "principal"), ("destination", "target")):
            n = doc.get(key) or {}
            e[side].update({"ip": (n.get("ip") or [None])[0], "port": n.get("port"), "hostname": n.get("hostname"),
                            "mac": (n.get("mac") or [None])[0]})
        net = doc.get("network") or {}
        e["network"].update({"protocol": net.get("ip_protocol"), "direction": (net.get("direction") or "").lower()
                             or None, "bytes_out": net.get("sent_bytes"), "bytes_in": net.get("received_bytes"),
                             "packets_out": net.get("sent_packets"), "packets_in": net.get("received_packets"),
                             "session_id": net.get("session_id")})
        tu = (doc.get("target") or {}).get("user") or (doc.get("principal") or {}).get("user") or {}
        e["user"]["name"] = tu.get("userid")
        act = (sr.get("action") or [None])[0]
        e["action"] = {"ALLOW": "allowed", "BLOCK": "blocked", "QUARANTINE": "quarantined",
                       "FAIL": "failed"}.get(act, "other")
        e["rule"].update({"id": sr.get("rule_id"), "name": sr.get("rule_name")})
        e["threat"].update({"signature": sr.get("threat_name"), "signature_id": sr.get("threat_id")})
        e["metadata"]["parser_id"] = "udm"
        e["metadata"]["parser_name"] = "UDM import"
    e["event_id"] = md.get("product_log_id") or e["event_id"]
    e["message"] = md.get("description")
    if base is None:
        e["raw_event"] = None
    e["parsed_fields"] = parsed
    return e


# ---------------------------------------------------------------------------
# Conformance
# ---------------------------------------------------------------------------

_SCALARS = {"string": str, "bool": bool, "float": (int, float), "double": (int, float), "int32": int, "int64": int,
            "uint32": int, "uint64": int, "Int64": int, "bytes": str, "google.protobuf.Timestamp": str,
            "google.protobuf.Struct": dict, "google.protobuf.Duration": str}
_MACHINE = ("hostname", "ip", "mac", "asset_id", "asset")


def _check(msg: str, v: Any, path: str, errors: list) -> None:
    cat = catalog()
    fields = cat["messages"].get(msg)
    if fields is None:
        return
    if not isinstance(v, dict):
        errors.append(f"{path}: expected a {msg} object")
        return
    for k, x in v.items():
        spec = fields.get(k)
        if spec is None:
            errors.append(f"{path}.{k}: not a field of {msg}")
            continue
        typ, label = spec
        if label == "repeated":
            if not isinstance(x, list):
                errors.append(f"{path}.{k}: repeated field must be a list")
                continue
            items = x
        else:
            items = [x]
        for i, it in enumerate(items):
            p = f"{path}.{k}" + (f"[{i}]" if label == "repeated" else "")
            if typ.endswith("(Enumerated list)"):
                enum = typ.replace(" (Enumerated list)", "")
                values = cat["enums"].get(enum)
                if values is not None and it not in values:
                    errors.append(f"{p}: {it!r} is not a {enum} value")
            elif typ in _SCALARS:
                if not isinstance(it, _SCALARS[typ]) or (typ != "bool" and isinstance(it, bool)):
                    errors.append(f"{p}: expected {typ}")
                elif typ.startswith("uint") and it < 0:
                    errors.append(f"{p}: negative {typ}")
            elif typ in cat["messages"]:
                _check(typ, it, p, errors)


def _has_machine(n: dict | None) -> bool:
    return bool(n) and any(n.get(k) for k in _MACHINE)


def validate(doc: dict) -> list[str]:
    """Problems of a UDM event ([] when it conforms): field names and enum values of the
    field list, the metadata every event needs, and each event type's required nouns."""
    errors: list[str] = []
    _check("UDM Event data model", doc, "event", errors)
    return errors + requirements(doc)


def requirements(doc: dict) -> list[str]:
    """What the event type requires and the event lacks (UDM usage guide)."""
    errors: list[str] = []
    md = doc.get("metadata") or {}
    et = md.get("event_type")
    if not md.get("event_timestamp"):
        errors.append("metadata.event_timestamp is required")
    if not et:
        errors.append("metadata.event_type is required")
        return errors
    pr, tg, net = doc.get("principal"), doc.get("target") or {}, doc.get("network") or {}
    need = []
    if et.startswith(("NETWORK_CONNECTION", "NETWORK_FLOW", "NETWORK_FTP", "NETWORK_SMTP", "NETWORK_HTTP")):
        need += [("principal machine", _has_machine(pr) or _has_machine(tg))]
    if et == "NETWORK_DNS":
        need += [("network.application_protocol DNS", net.get("application_protocol") == "DNS"),
                 ("network.dns.questions.name", any(q.get("name") for q in (net.get("dns") or {}).get("questions") or []))]
    if et.startswith("NETWORK_HTTP"):
        need += [("network.http", bool(net.get("http")))]
    if et in ("USER_LOGIN", "USER_LOGOUT"):
        need += [("target.user", bool(tg.get("user"))),
                 ("a machine in principal or target", _has_machine(pr) or _has_machine(tg)),
                 ("extensions.auth.type", bool(((doc.get("extensions") or {}).get("auth") or {}).get("type")))]
    if et in ("USER_CREATION", "USER_DELETION", "USER_CHANGE_PASSWORD", "USER_UNCATEGORIZED"):
        need += [("target.user", bool(tg.get("user")))]
    if et.startswith("PROCESS_"):
        need += [("principal machine", _has_machine(pr)), ("target.process", bool(tg.get("process")))]
    if et == "PROCESS_MODULE_LOAD":
        need += [("principal.process", bool((pr or {}).get("process"))),
                 ("target.process.file", bool((tg.get("process") or {}).get("file")))]
    if et.startswith("FILE_"):
        need += [("principal machine", _has_machine(pr)), ("target.file", bool(tg.get("file")))]
    if et.startswith("REGISTRY_"):
        need += [("principal machine", _has_machine(pr)),
                 ("target.registry.registry_key", "registry_key" in (tg.get("registry") or {}))]
    if et.startswith("SCHEDULED_TASK_"):
        need += [("principal machine", _has_machine(pr)),
                 ("target.resource TASK", (tg.get("resource") or {}).get("resource_type") == "TASK")]
    if et.startswith("SERVICE_"):
        need += [("principal machine", _has_machine(pr)),
                 ("target application or process", bool(tg.get("application") or tg.get("process")))]
    if et.startswith(("STATUS_", "SYSTEM_AUDIT_LOG", "SETTING_")):
        need += [("principal machine", _has_machine(pr))]
    if et.startswith("SETTING_"):
        need += [("target.resource SETTING", (tg.get("resource") or {}).get("resource_type") == "SETTING")]
    if et.startswith("RESOURCE_") or et == "USER_RESOURCE_ACCESS":
        need += [("target.resource", bool(tg.get("resource")))]
    if et.startswith("GROUP_"):
        need += [("target.group or target.user", bool(tg.get("group") or tg.get("user")))]
    for what, ok in need:
        if not ok:
            errors.append(f"{et} requires {what}")
    return errors


def validate_entity(ent: dict) -> list[str]:
    errors: list[str] = []
    _check("Entity", ent, "entity", errors)
    if not (ent.get("metadata") or {}).get("entity_type"):
        errors.append("metadata.entity_type is required")
    return errors
