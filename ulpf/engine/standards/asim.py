"""
Microsoft Sentinel ASIM view of the unified event, its inverse, and a
conformance check.

An event becomes one row of the ASIM schema its activity belongs to:
Authentication, NetworkSession, Dns, WebSession, ProcessEvent, FileEvent,
RegistryEvent, UserManagement, AlertEvent, and AuditEvent for the remaining
audited operations (scheduled tasks, services, drivers, log clearing, cloud API
calls, configuration). When the event lacks what its schema cannot do without
(a DNS query name, a URL, a registry key, a file path), it is reported in the
schema it still fits: NetworkSession, then AuditEvent.

Columns are named as in the schemas (common fields + the schema's fields);
mandatory columns are always present (empty when the source does not say).
Vendor fields without an ASIM column go to ``AdditionalFields["x_<vendor>"]``;
the unified fields ASIM cannot hold exactly go to ``AdditionalFields["x_ulpf"]``,
so ``from_asim(to_asim(e))`` gives ``e`` back.

``validate(row)`` checks column names against the ASIM reference pages
(``asim_catalog.json``, built by ``scripts/build_standards_catalog.py``),
mandatory columns and enumerated values.
"""
from __future__ import annotations

import functools
import json
import os
import re
from typing import Any

from ulpf.engine.standards import common as C
from ulpf.engine.standards.facets import CANDIDATES, classify, facets, unmapped_vendor_fields, vendor_namespace

_HERE = os.path.dirname(os.path.abspath(__file__))


@functools.lru_cache(maxsize=1)
def catalog() -> dict:
    with open(os.path.join(_HERE, "asim_catalog.json"), encoding="utf-8") as f:
        return json.load(f)


SCHEMA_NAME = {"Alert": "AlertEvent"}         # catalog key -> EventSchema value (the rest are equal)

# Enumerated values from the schema reference pages
ENUMS: dict[str, dict[str, tuple[str, ...]]] = {
    "*": {"EventResult": ("Success", "Partial", "Failure", "NA"),
          "EventSeverity": ("Informational", "Low", "Medium", "High"),
          "DvcIdType": ("AzureResourceId", "MDEid", "MD4IoTid", "VMConnectionId", "AwsVpcId", "VectraId",
                        "AppGateId", "FQDN", "Other")},
    "Authentication": {"EventType": ("Logon", "Logoff", "Elevate"),
                       "EventSubType": ("System", "Interactive", "RemoteInteractive", "Service", "RemoteService",
                                        "Remote", "AssumeRole"),
                       "EventResultDetails": ("No such user or password", "No such user", "Incorrect password",
                                              "Incorrect key", "Account expired", "Password expired", "User locked",
                                              "User disabled", "Logon violates policy", "Session expired", "Other"),
                       "TargetUserIdType": ("SID", "UID", "AADID", "OktaId", "AWSId", "PUID", "SalesforceId",
                                            "Other")},
    "NetworkSession": {"EventType": ("EndpointNetworkSession", "NetworkSession", "L2NetworkSession", "IDS", "Flow"),
                       "EventSubType": ("Start", "End"),
                       "DvcAction": ("Allow", "Deny", "Drop", "Drop ICMP", "Reset", "Reset Source",
                                     "Reset Destination", "Encrypt", "Decrypt", "VPNroute"),
                       "NetworkDirection": ("Inbound", "Outbound", "Local", "External", "NA", "Listen")},
    "Dns": {"EventType": ("Query",), "EventSubType": ("request", "response")},
    "WebSession": {"EventType": ("HTTPsession", "WebServerSession", "ApiRequest"),
                   "DvcAction": ("Allow", "Deny", "Drop", "Drop ICMP", "Reset", "Reset Source", "Reset Destination",
                                 "Encrypt", "Decrypt", "VPNroute")},
    "ProcessEvent": {"EventType": ("ProcessCreated", "ProcessTerminated")},
    "FileEvent": {"EventType": ("FileAccessed", "FileCreated", "FileModified", "FileDeleted", "FileRenamed",
                                "FileCopied", "FileMoved", "FolderCreated", "FolderDeleted", "FolderMoved",
                                "FolderModified", "FileCreatedOrModified"),
                  "TargetFilePathType": ("Windows Local", "Windows Share", "Unix", "URL")},
    "RegistryEvent": {"EventType": ("RegistryKeyCreated", "RegistryKeyDeleted", "RegistryKeyRenamed",
                                    "RegistryValueDeleted", "RegistryValueSet"),
                      "RegistryValueType": ("Reg_None", "Reg_Sz", "Reg_Expand_Sz", "Reg_Binary", "Reg_DWord",
                                            "Reg_DWord_Big_Endian", "Reg_Link", "Reg_Multi_Sz", "Reg_Resource_List",
                                            "Reg_Full_Resource_Descriptor", "Reg_Resource_Requirements_List",
                                            "Reg_QWord")},
    "UserManagement": {"EventType": ("UserCreated", "UserDeleted", "UserModified", "UserLocked", "UserUnlocked",
                                     "UserDisabled", "UserEnabled", "PasswordChanged", "PasswordReset", "GroupCreated",
                                     "GroupDeleted", "GroupModified", "UserAddedToGroup", "UserRemovedFromGroup",
                                     "GroupEnumerated", "UserRead", "GroupRead")},
    "AuditEvent": {"EventType": ("Set", "Read", "Create", "Delete", "Execute", "Install", "Clear", "Enable",
                                 "Disable", "Initialize", "Start", "Stop", "Other"),
                   "ObjectType": ("Cloud Resource", "Configuration Atom", "Policy Rule", "Event Log",
                                  "Scheduled Task", "Service", "Directory Service Object", "Other")},
    "Alert": {"EventType": ("Alert",), "AlertStatus": ("Active", "Closed"),
              "AlertVerdict": ("True Positive", "False Positive", "Benign Positive", "Unknown")},
}

_LOG_ANALYTICS = ("TimeGenerated", "Type")    # columns every Log Analytics table has


def _fields(schema: str) -> dict[str, str]:
    cat = catalog()
    out = dict(cat["Common"]["fields"])
    if schema == "WebSession":                # an extension of NetworkSession
        out.update(cat["NetworkSession"]["fields"])
    out.update(cat[schema]["fields"])
    return out


_SEVERITY = {"info": "Informational", "low": "Low", "medium": "Medium", "high": "High", "critical": "High"}
_DVC_ACTION = {"allowed": "Allow", "permitted": "Allow", "accepted": "Allow", "success": "Allow", "blocked": "Deny",
               "denied": "Deny", "rejected": "Deny", "dropped": "Drop", "reset": "Reset"}
_LOGON_SUBTYPE = {0: "System", 1: "System", 2: "Interactive", 3: "Remote", 4: "Service", 5: "Service",
                  7: "Interactive", 8: "Remote", 9: "Interactive", 10: "RemoteInteractive", 11: "Interactive",
                  12: "RemoteInteractive", 13: "Interactive"}
_FAILURE = {"0xc000006a": "Incorrect password", "0xc0000064": "No such user", "0xc0000234": "User locked",
            "0xc0000072": "User disabled", "0xc0000193": "Account expired", "0xc0000071": "Password expired",
            "0xc0000224": "Password expired", "0xc000006f": "Logon violates policy",
            "0xc0000070": "Logon violates policy", "0xc0000133": "Logon violates policy",
            "%%2313": "No such user or password"}
_RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN",
          7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE"}
_QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255}
_REG_ROOTS = (("\\REGISTRY\\MACHINE", "HKEY_LOCAL_MACHINE"), ("\\REGISTRY\\USER", "HKEY_USERS"),
              ("HKLM", "HKEY_LOCAL_MACHINE"), ("HKCU", "HKEY_CURRENT_USER"), ("HKCR", "HKEY_CLASSES_ROOT"),
              ("HKU", "HKEY_USERS"), ("HKCC", "HKEY_CURRENT_CONFIG"))


def registry_key(key: str) -> str:
    """A registry key with its root in the standard form ASIM asks for (HKEY_LOCAL_MACHINE\\...)."""
    for short, full in _REG_ROOTS:
        if key.upper() == short or key.upper().startswith(short + "\\"):
            return full + key[len(short):]
    return key


def _reg_type(t) -> str | None:
    if not t:
        return None
    s = str(t).upper()
    s = s[4:] if s.startswith("REG_") else s
    for v in ENUMS["RegistryEvent"]["RegistryValueType"]:
        if v[4:].upper() == s:
            return v
    return None


def _path_type(p: str) -> str:
    if p.startswith("\\\\"):
        return "Windows Share"
    if re.match(r"^[A-Za-z]:\\", p) or "\\" in p:
        return "Windows Local"
    if "://" in p:
        return "URL"
    return "Unix"


# ---------------------------------------------------------------------------
# to_asim
# ---------------------------------------------------------------------------

def _schema_for(act) -> tuple[str, str]:
    k, v, f = act.kind, act.verb, act.facets
    if k == "authentication":
        return "Authentication", "Logoff" if v == "logoff" else "Logon"
    if k == "dns" and f.get("dns.query") is not None:
        return "Dns", "Query"
    if k == "http" and f.get("http.url") is not None:
        return "WebSession", "HTTPsession"
    if k in ("network", "ssh", "rdp", "smb", "ftp", "dhcp", "ntp", "tunnel", "email", "dns", "http"):
        return "NetworkSession", "NetworkSession"
    if k == "process" and v in ("launch", "terminate") and f.get("process.name") is not None:
        return "ProcessEvent", "ProcessCreated" if v == "launch" else "ProcessTerminated"
    if k == "file" and f.get("file.path") is not None:
        t = {"create": "FileCreated", "delete": "FileDeleted", "modify": "FileModified", "read": "FileAccessed",
             "open": "FileAccessed", "rename": "FileRenamed"}.get(v)
        if t:
            return "FileEvent", t
    if k in ("registry_key", "registry_value") and f.get("registry.key") is not None:
        t = {("registry_key", "create"): "RegistryKeyCreated", ("registry_key", "delete"): "RegistryKeyDeleted",
             ("registry_key", "rename"): "RegistryKeyRenamed", ("registry_value", "modify"): "RegistryValueSet",
             ("registry_value", "create"): "RegistryValueSet", ("registry_value", "delete"): "RegistryValueDeleted",
             ("registry_key", "modify"): "RegistryValueSet" if f.get("registry.value") is not None else None}.get((k, v))
        if t:
            return "RegistryEvent", t
    if k == "account":
        return "UserManagement", {"create": "UserCreated", "delete": "UserDeleted", "lock": "UserLocked",
                                  "unlock": "UserUnlocked", "disable": "UserDisabled", "enable": "UserEnabled",
                                  "password_change": "PasswordChanged",
                                  "password_reset": "PasswordReset"}.get(v, "UserModified")
    if k == "group":
        return "UserManagement", {"create": "GroupCreated", "delete": "GroupDeleted", "add_member": "UserAddedToGroup",
                                  "remove_member": "UserRemovedFromGroup"}.get(v, "GroupModified")
    if k == "finding":
        return "Alert", "Alert"
    return "AuditEvent", {"create": "Create", "delete": "Delete", "modify": "Set", "read": "Read",
                          "install": "Install", "clear": "Clear", "enable": "Enable", "disable": "Disable",
                          "start": "Start", "launch": "Start", "stop": "Stop", "terminate": "Stop",
                          "load": "Execute", "inject": "Execute", "open": "Read"}.get(v, "Other")


def _to_asim(event: dict):
    f = facets(event)
    act = classify(event, f)
    schema, etype = _schema_for(act)
    fields = _fields(schema)
    dev = event.get("device") or {}
    net = event.get("network") or {}
    geo = event.get("geo") or {}
    user = event.get("user") or {}
    thr = event.get("threat") or {}
    rule = event.get("rule") or {}
    src = event.get("source") or {}
    dst = event.get("destination") or {}
    ts = C.iso_utc(event.get("timestamp"))
    out = C.outcome(event)
    eid = f.get("win.event_id")
    if schema == "Authentication" and eid in (4624, 4625):
        out = "success" if eid == 4624 else "failure"
    if act.kind == "api":
        out = "failure" if f.get("api.error") else "success"
    sev = _SEVERITY.get(event.get("severity_label") or "")
    row: dict[str, Any] = {
        "TimeGenerated": ts, "EventStartTime": ts, "EventEndTime": ts, "EventCount": 1,
        "EventType": etype, "EventResult": {"success": "Success", "failure": "Failure"}.get(out, "NA"),
        "EventSeverity": sev, "EventOriginalSeverity": None if event.get("severity") is None else str(event["severity"]),
        "EventProduct": dev.get("product") or "", "EventVendor": dev.get("vendor") or "",
        "EventProductVersion": dev.get("version"), "EventSchema": SCHEMA_NAME.get(schema, schema),
        "EventSchemaVersion": catalog()[schema]["version"], "EventUid": event.get("event_id"),
        "EventMessage": event.get("message"),
        "EventOriginalType": str(eid) if eid is not None else (None if event.get("event_type") is None
                                                                else str(event["event_type"])),
        "Dvc": dev.get("hostname") or dev.get("ip") or "", "DvcHostname": dev.get("hostname"), "DvcIpAddr": dev.get("ip"),
        "DvcId": None if dev.get("serial") is None else str(dev["serial"]),
    }
    if eid is not None:
        f.take("win.event_id")
    if row["DvcId"]:
        row["DvcIdType"] = "Other"
    if fields.get("EventSeverity") == "Mandatory" and not sev:
        row["EventSeverity"] = "Informational"
    action = (event.get("action") or "").lower()
    if "DvcAction" in fields and action in _DVC_ACTION:
        row["DvcAction"] = _DVC_ACTION[action]
        row["DvcOriginalAction"] = event.get("action")

    def endpoint(prefix: str, ep: dict, side: str):
        port = C.as_int(ep.get("port"))
        cols = {f"{prefix}IpAddr": ep.get("ip"), f"{prefix}PortNumber": port if port is not None and 0 <= port <= 65535
                else None, f"{prefix}Hostname": ep.get("hostname"), f"{prefix}MacAddr": ep.get("mac"),
                f"{prefix}Zone": ep.get("zone"), f"{prefix}InterfaceName": ep.get("interface"),
                f"{prefix}GeoCountry": geo.get(f"{side}_country"), f"{prefix}GeoCity": geo.get(f"{side}_city"),
                f"{prefix}GeoLatitude": geo.get(f"{side}_latitude"), f"{prefix}GeoLongitude": geo.get(f"{side}_longitude")}
        for k, v in cols.items():
            if v is not None and k in fields:
                row[k] = v

    su, tu = user.get("source") or {}, user.get("target") or {}
    if schema in ("NetworkSession", "WebSession", "Dns", "Authentication", "UserManagement", "AuditEvent"):
        endpoint("Src", src, "src")
    if schema in ("NetworkSession", "WebSession", "Dns"):
        endpoint("Dst", dst, "dst")
    if schema in ("NetworkSession", "WebSession"):
        row.update({"NetworkProtocol": (net.get("protocol") or None) and str(net["protocol"]).upper(),
                    "NetworkDirection": {"inbound": "Inbound", "outbound": "Outbound", "internal": "Local",
                                         "external": "External"}.get(str(net.get("direction") or "").lower()),
                    "NetworkApplicationProtocol": str(net["application"]).upper() if net.get("application") else None,
                    "SrcBytes": net.get("bytes_out"), "DstBytes": net.get("bytes_in"), "NetworkBytes": net.get("bytes_total"),
                    "SrcPackets": net.get("packets_out"), "DstPackets": net.get("packets_in"),
                    "NetworkSessionId": None if net.get("session_id") is None else str(net["session_id"]),
                    "SrcUsername": user.get("name"), "NetworkRuleName": rule.get("name"),
                    "NetworkRuleNumber": C.as_int(rule.get("id"))})
        if net.get("vlan_id") is not None:
            row["SrcVlanId"] = str(net["vlan_id"])
        if row.get("NetworkDirection") is None:
            row.pop("NetworkDirection")
        if row.get("NetworkRuleNumber") is None and rule.get("id") is not None:
            row["NetworkRuleName"] = row["NetworkRuleName"] or str(rule["id"])
        pname = f.take("process.name") or f.take("actor.process.name")
        if pname:
            row["SrcProcessName"] = str(pname)
            pid = C.as_int(f.take("process.pid") or f.take("actor.process.pid"))
            if pid is not None:
                row["SrcProcessId"] = str(pid)
    if schema == "WebSession":
        code = f.take("http.status")
        row.update({"Url": str(f.take("http.url")), "HttpRequestMethod": f.take("http.method"),
                    "HttpUserAgent": f.take("http.user_agent"), "HttpReferrer": f.take("http.referrer"),
                    "HttpHost": f.take("http.host"),
                    "HttpStatusCode": None if C.as_int(code) is None else C.as_int(code),
                    "EventResultDetails": None if code is None else str(code)})
        q = f.take("http.query")
        if q:
            row["Url"] = row["Url"] + ("" if str(q).startswith("?") else "?") + str(q)
    if schema == "Dns":
        rc = f.take("dns.rcode")
        rcn = C.as_int(rc) if rc is not None else None
        name = _RCODE.get(rcn) if rcn is not None else (str(rc).upper().replace("_", "") if rc is not None else None)
        qtype = f.take("dns.qtype")
        ans = f.take("dns.answer")
        row.update({"DnsQuery": str(f.take("dns.query")), "DnsQueryTypeName": None if qtype is None else str(qtype).upper(),
                    "DnsQueryType": _QTYPE.get(str(qtype).upper()) if qtype is not None else None,
                    "DnsResponseCodeName": name, "DnsResponseCode": rcn if rcn is not None else
                    {v: k for k, v in _RCODE.items()}.get(name or ""),
                    "EventResultDetails": name or "NA", "EventSubType": "response" if name else "request",
                    "DnsResponseName": ",".join(map(str, ans)) if isinstance(ans, list) else (None if ans is None
                                                                                            else str(ans)),
                    "SrcUsername": user.get("name"),
                    "NetworkProtocol": str(net["protocol"]).upper() if net.get("protocol") else None})
        pname = f.take("process.name") or f.take("actor.process.name")
        if pname:
            row["SrcProcessName"] = str(pname)
    if schema == "Authentication":
        target = tu if (tu.get("name") or tu.get("id")) else user
        sid = target.get("id")
        row.update({"TargetUsername": target.get("name"), "TargetDomain": target.get("domain"),
                    "TargetUserId": None if sid is None else str(sid),
                    "TargetUserIdType": ("SID" if str(sid).startswith("S-1-") else "Other") if sid else None,
                    "ActorUsername": su.get("name"), "TargetHostname": dst.get("hostname") or dev.get("hostname"),
                    "TargetIpAddr": dst.get("ip"), "LogonProtocol": f.take("auth.protocol")})
        if row["TargetUsername"]:
            row["TargetUsernameType"] = "Windows" if target.get("domain") else "Simple"
        lt = C.as_int(f.take("auth.logon_type"))
        if lt in _LOGON_SUBTYPE:
            row["EventSubType"] = _LOGON_SUBTYPE[lt]
        if out == "failure":
            reason = f.get("auth.failure")
            detail = _FAILURE.get(str(reason).lower()) if reason is not None else None
            if detail:
                f.take("auth.failure")
            row["EventResultDetails"] = detail or "Other"
        if f.get("api.service"):
            row["TargetAppName"] = str(f.take("api.service"))
        if not row.get("SrcIpAddr") and f.get("api.src_ip"):
            row["SrcIpAddr"] = str(f.take("api.src_ip"))
    if schema in ("ProcessEvent", "FileEvent", "RegistryEvent", "UserManagement", "AuditEvent"):
        row["ActorUsername"] = su.get("name") or user.get("name") or ""
        if su.get("domain") or user.get("domain"):
            row["ActorUsernameType"] = "Windows"
    if schema == "ProcessEvent":
        name = f.take("process.name")
        path = f.take("process.path")
        pid = C.as_int(f.take("process.pid"))
        row.update({"TargetProcessName": str(path or name or ""), "TargetProcessId": "" if pid is None else str(pid),
                    "TargetProcessCommandLine": f.take("process.cmd_line") or "",
                    "TargetProcessGuid": f.take("process.uid"), "TargetProcessIntegrityLevel": f.take("process.integrity")})
        for alg, col in (("md5", "TargetProcessMD5"), ("sha1", "TargetProcessSHA1"), ("sha256", "TargetProcessSHA256")):
            v = f.take(f"file.{alg}")
            if v:
                row[col] = str(v)
        raw_h = f.get("file.hashes")
        if raw_h and isinstance(raw_h, str) and "=" in raw_h:
            f.take("file.hashes")
            for part in raw_h.split(","):
                k_, _, v_ = part.partition("=")
                col = {"MD5": "TargetProcessMD5", "SHA1": "TargetProcessSHA1", "SHA256": "TargetProcessSHA256",
                       "SHA512": "TargetProcessSHA512"}.get(k_.strip().upper())
                if col and v_:
                    row.setdefault(col, v_.strip())
        apid = C.as_int(f.take("actor.process.pid"))
        row.update({"ActingProcessName": f.take("actor.process.name"), "ActingProcessId": "" if apid is None else str(apid),
                    "ActingProcessCommandLine": f.take("actor.process.cmd_line"),
                    "ActingProcessGuid": f.take("actor.process.uid")})
    if schema in ("FileEvent", "RegistryEvent"):
        pname = f.take("process.name") or f.take("actor.process.name")
        pid = C.as_int(f.take("process.pid") or f.take("actor.process.pid"))
        row.update({"ActingProcessName": None if pname is None else str(pname),
                    "ActingProcessId": "" if pid is None else str(pid)})
    if schema == "FileEvent":
        path = str(f.take("file.path"))
        name = C.basename(path)
        row.update({"TargetFilePath": path, "TargetFilePathType": _path_type(path), "TargetFileName": name,
                    "TargetFileDirectory": C.parent_dir(path),
                    "TargetFileExtension": name.rsplit(".", 1)[1] if name and "." in name else None,
                    "TargetFileSize": C.as_int(f.take("file.size"))})
        for alg, col in (("md5", "TargetFileMD5"), ("sha1", "TargetFileSHA1"), ("sha256", "TargetFileSHA256")):
            v = f.take(f"file.{alg}")
            if v:
                row[col] = str(v)
    if schema == "RegistryEvent":
        key = str(f.take("registry.key"))
        vname = f.take("registry.value")
        rtype = f.get("registry.type")
        row.update({"RegistryKey": registry_key(key), "RegistryValue": vname,
                    "RegistryValueData": None if f.get("registry.data") is None else str(f.take("registry.data")),
                    "RegistryValueType": _reg_type(rtype), "ParentProcessId": ""})
        if row["RegistryValueType"]:
            f.take("registry.type")
        if registry_key(key) != key:
            row["RegistryKeyOriginal"] = key          # kept for the inverse (AdditionalFields)
    if schema == "UserManagement":
        target = tu if (tu.get("name") or tu.get("id")) else user
        row.update({"TargetUsername": target.get("name"),
                    "TargetUserId": None if target.get("id") is None else str(target["id"]),
                    "SrcIpAddr": row.get("SrcIpAddr")})
        if row["TargetUserId"]:
            row["TargetUserIdType"] = "SID" if row["TargetUserId"].startswith("S-1-") else "Other"
        if act.kind == "group":
            row["GroupName"] = f.take("group.name") or target.get("name")
            member = f.take("group.member")
            if member:
                row["TargetUsername"] = str(member)
    if schema == "AuditEvent":
        k = act.kind
        obj, otype, operation = "", "Other", str(event.get("event_type") or event.get("action") or k)
        if k == "api":
            operation = str(f.take("api.operation"))
            svc = f.take("api.service")
            obj, otype = str(svc or operation), "Cloud Resource"
            row["TargetAppName"] = svc
            region, acct = f.take("cloud.region"), f.take("cloud.account")
            if acct:
                row["TargetDvcScopeId"] = str(acct)
            if region:
                row["TargetGeoRegion"] = str(region)
            uid = f.take("cloud.actor_uid")
            if uid:
                row["ActorUserId"] = str(uid)
                row["ActorUserIdType"] = "AWSId" if str(uid).startswith("arn:aws") else "Other"
            if f.get("cloud.actor_type"):
                row["ActorOriginalUserType"] = str(f.take("cloud.actor_type"))
            if f.get("api.provider"):
                pass
            if not row.get("SrcIpAddr") and f.get("api.src_ip"):
                row["SrcIpAddr"] = str(f.take("api.src_ip"))
            ua = f.take("http.user_agent")
            if ua:
                row["HttpUserAgent"] = ua
            err = f.take("api.error")
            if err:
                row["EventResultDetails"] = str(err)
            prov = f.take("cloud.provider")
            if prov:
                row["TargetAppType"] = None
                row["TargetDescription"] = str(prov)
            rid = f.take("api.request_id")
            if rid:
                row["EventOriginalUid"] = str(rid)
        elif k == "scheduled_job":
            obj, otype = str(f.take("service.name") or operation), "Scheduled Task"
        elif k == "service":
            obj, otype = str(f.take("service.name") or operation), "Service"
        elif k == "application":
            obj, otype = str(f.take("service.name") or f.take("app.name") or operation), "Service"
        elif k == "event_log":
            obj, otype = str(f.take("win.channel") or "Security"), "Event Log"
        elif k == "config":
            obj, otype = operation, "Configuration Atom"
        elif k in ("kernel_extension", "module"):
            obj = str(f.take("file.path") or f.take("process.path") or operation)
        elif k in ("process",):
            obj = str(f.take("process.path") or f.take("process.name") or operation)
        elif k in ("registry_key", "registry_value"):
            obj, otype = registry_key(str(f.take("registry.key") or operation)), "Configuration Atom"
        elif k == "file":
            obj = str(f.take("file.path") or operation)
        row.update({"Operation": operation, "Object": obj, "ObjectType": otype})
        pname = f.take("actor.process.name") if k != "process" else None
        if pname:
            row["ActingAppName"] = str(pname)
    if schema == "Alert":
        ext = event.get("extensions") or {}
        det = ext.get("detection") if isinstance(ext.get("detection"), dict) else {}
        row.update({"AlertName": rule.get("name") or thr.get("signature") or event.get("message") or "",
                    "AlertDescription": event.get("message"), "AlertStatus": "Active",
                    "AlertId": None if (rule.get("id") or thr.get("signature_id")) is None
                    else str(rule.get("id") or thr.get("signature_id")),
                    "AttackTechniques": ", ".join(det.get("techniques") or []) or None,
                    "AttackTactics": ", ".join(det.get("tactics") or []) or None,
                    "IpAddr": src.get("ip"), "Hostname": dev.get("hostname"), "Username": user.get("name"),
                    "RuleName": rule.get("name")})
    if "ThreatName" in fields:
        row.update({"ThreatName": thr.get("signature"), "ThreatId": None if thr.get("signature_id") is None
                    else str(thr["signature_id"]), "ThreatOriginalCategory" if "ThreatOriginalCategory" in fields
                    else "ThreatCategory": thr.get("category"),
                    "ThreatConfidence": int(round(float(thr["confidence"]) * 100)) if thr.get("confidence") is not None
                    and float(thr["confidence"]) <= 1 else None,
                    "ThreatIpAddr": thr.get("ioc_value") if thr.get("ioc_type") == "ip" and "ThreatIpAddr" in fields
                    else None})
    if "RuleName" in fields and schema not in ("NetworkSession", "WebSession"):
        row.setdefault("RuleName", rule.get("name"))
    # mandatory columns are present, empty when unknown
    for col, cls in fields.items():
        if cls == "Mandatory" and row.get(col) is None:
            row[col] = ""
    key_orig = row.pop("RegistryKeyOriginal", None)
    row = {k: v for k, v in row.items() if v is not None}
    vendor = unmapped_vendor_fields(event, f)
    add = {**({vendor_namespace(event): vendor} if vendor else {}), "x_ulpf": C.residual(event, raw=True)}
    if key_orig is not None:
        add["x_ulpf"]["registry_key"] = key_orig
    if eid is not None:
        add["x_ulpf"]["windows_event_id"] = True     # EventOriginalType holds a Windows event ID
    row["AdditionalFields"] = add
    return row, f


def to_asim(event: dict) -> dict:
    return _to_asim(event)[0]


# ---------------------------------------------------------------------------
# from_asim
# ---------------------------------------------------------------------------

_SCHEMA_CATEGORY = {"Authentication": "authentication", "NetworkSession": "network", "Dns": "dns",
                    "WebSession": "web", "ProcessEvent": "endpoint", "FileEvent": "endpoint",
                    "RegistryEvent": "endpoint", "UserManagement": "authentication", "AlertEvent": "ids_ips",
                    "AuditEvent": "audit"}


def _facet_fields(row: dict) -> dict:
    p: dict[str, Any] = {}
    canon = {k: v[0] for k, v in CANDIDATES.items()}

    def put(facet, value):
        if value not in (None, "", [], {}):
            p[canon[facet]] = value
    schema = row.get("EventSchema")
    if schema in ("NetworkSession", "WebSession", "Dns"):
        put("process.name", row.get("SrcProcessName"))
        put("process.pid", row.get("SrcProcessId"))
    if schema == "WebSession":
        put("http.url", row.get("Url"))
        put("http.method", row.get("HttpRequestMethod"))
        put("http.user_agent", row.get("HttpUserAgent"))
        put("http.referrer", row.get("HttpReferrer"))
        put("http.host", row.get("HttpHost"))
        put("http.status", row.get("HttpStatusCode"))
    if schema == "Dns":
        put("dns.query", row.get("DnsQuery"))
        put("dns.qtype", row.get("DnsQueryTypeName"))
        put("dns.rcode", row.get("DnsResponseCodeName"))
        ans = row.get("DnsResponseName")
        if ans:
            parts = ans.split(",")
            put("dns.answer", parts[0] if len(parts) == 1 else parts)
    if schema == "Authentication":
        put("auth.protocol", row.get("LogonProtocol"))
        sub = row.get("EventSubType")
        if sub:
            put("auth.logon_type", {v: k for k, v in reversed(list(_LOGON_SUBTYPE.items()))}.get(sub))
        if row.get("EventResultDetails") and row["EventResultDetails"] != "Other":
            put("auth.failure", {v: k for k, v in _FAILURE.items()}.get(row["EventResultDetails"]))
        put("api.service", row.get("TargetAppName"))
    if schema == "ProcessEvent":
        put("process.name", row.get("TargetProcessName"))
        put("process.path", row.get("TargetProcessName"))
        put("process.pid", row.get("TargetProcessId"))
        put("process.cmd_line", row.get("TargetProcessCommandLine"))
        put("process.uid", row.get("TargetProcessGuid"))
        put("process.integrity", row.get("TargetProcessIntegrityLevel"))
        for alg, col in (("md5", "TargetProcessMD5"), ("sha1", "TargetProcessSHA1"), ("sha256", "TargetProcessSHA256")):
            put(f"file.{alg}", row.get(col))
        put("actor.process.name", row.get("ActingProcessName"))
        put("actor.process.pid", row.get("ActingProcessId"))
        put("actor.process.cmd_line", row.get("ActingProcessCommandLine"))
        put("actor.process.uid", row.get("ActingProcessGuid"))
    if schema in ("FileEvent", "RegistryEvent"):
        put("process.name", row.get("ActingProcessName"))
        put("process.pid", row.get("ActingProcessId"))
    if schema == "FileEvent":
        put("file.path", row.get("TargetFilePath"))
        put("file.size", row.get("TargetFileSize"))
        for alg, col in (("md5", "TargetFileMD5"), ("sha1", "TargetFileSHA1"), ("sha256", "TargetFileSHA256")):
            put(f"file.{alg}", row.get(col))
    if schema == "RegistryEvent":
        orig = ((row.get("AdditionalFields") or {}).get("x_ulpf") or {}).get("registry_key")
        put("registry.key", orig or row.get("RegistryKey"))
        put("registry.value", row.get("RegistryValue"))
        put("registry.data", row.get("RegistryValueData"))
        if row.get("RegistryValueType"):
            put("registry.type", row["RegistryValueType"].upper())
    if schema == "UserManagement" and row.get("GroupName") is not None:
        put("group.name", row.get("GroupName"))
        if row.get("EventType") in ("UserAddedToGroup", "UserRemovedFromGroup"):
            put("group.member", row.get("TargetUsername"))
    if schema == "AuditEvent":
        otype = row.get("ObjectType")
        if otype == "Cloud Resource":
            put("api.operation", row.get("Operation"))
            put("api.service", row.get("TargetAppName"))
            put("cloud.account", row.get("TargetDvcScopeId"))
            put("cloud.region", row.get("TargetGeoRegion"))
            put("cloud.actor_uid", row.get("ActorUserId"))
            put("cloud.actor_type", row.get("ActorOriginalUserType"))
            put("api.error", row.get("EventResultDetails"))
            put("cloud.provider", row.get("TargetDescription"))
            put("api.request_id", row.get("EventOriginalUid"))
            put("http.user_agent", row.get("HttpUserAgent"))
        elif otype in ("Scheduled Task", "Service"):
            put("service.name", row.get("Object"))
        elif otype == "Event Log":
            put("win.channel", row.get("Object"))
        elif row.get("EventType") == "Execute":      # driver / module loads: the loaded file
            put("file.path", row.get("Object"))
        put("actor.process.name", row.get("ActingAppName"))
    restored = C.restore((row.get("AdditionalFields") or {}).get("x_ulpf")) or {}
    if schema in ("Authentication", "AuditEvent") and not (restored.get("source") or {}).get("ip"):
        put("api.src_ip", row.get("SrcIpAddr"))
    # ULPF's rows say whether EventOriginalType is a Windows event ID; for others a number is one
    x = (row.get("AdditionalFields") or {}).get("x_ulpf") or {}
    if row.get("EventOriginalType") and (x.get("windows_event_id") if "v" in x
                                         else str(row["EventOriginalType"]).isdigit()):
        put("win.event_id", row["EventOriginalType"])
    return p


def from_asim(row: dict) -> dict:
    """A unified event from an ASIM row (lossless for ULPF's own rows)."""
    from ulpf.engine.schema import new_unified_event, severity_label
    add = row.get("AdditionalFields") or {}
    if isinstance(add, str):
        add = json.loads(add)
        row = {**row, "AdditionalFields": add}
    parsed: dict[str, Any] = {}
    for k, v in add.items():
        if k.startswith("x_") and k != "x_ulpf" and isinstance(v, dict):
            parsed.update(v)
    parsed.update(_facet_fields(row))
    base = C.restore(add.get("x_ulpf"))
    e = new_unified_event(event_id=row.get("EventUid"), timestamp=row.get("TimeGenerated"))
    if base is not None:
        e.update(base)
    else:
        e["category"] = _SCHEMA_CATEGORY.get(row.get("EventSchema"), "other")
        label = {"Informational": "info", "Low": "low", "Medium": "medium", "High": "high"}.get(
            row.get("EventSeverity"), "unknown")
        e["severity"] = {"unknown": 0, "info": 1, "low": 3, "medium": 5, "high": 7}[label]
        e["severity_label"] = severity_label(e["severity"])
        e["event_type"] = row.get("EventOriginalType") or row.get("EventType")
        e["raw_format"] = "asim"
        e["device"].update({"vendor": row.get("EventVendor") or None, "product": row.get("EventProduct") or None,
                            "version": row.get("EventProductVersion"), "hostname": row.get("DvcHostname"),
                            "ip": row.get("DvcIpAddr")})
        for side, pre in (("source", "Src"), ("destination", "Dst")):
            e[side].update({"ip": row.get(f"{pre}IpAddr"), "port": row.get(f"{pre}PortNumber"),
                            "hostname": row.get(f"{pre}Hostname"), "mac": row.get(f"{pre}MacAddr")})
        e["network"]["protocol"] = row.get("NetworkProtocol")
        e["user"]["name"] = row.get("TargetUsername") or row.get("SrcUsername") or row.get("ActorUsername")
        e["action"] = {"Allow": "allowed", "Deny": "denied", "Drop": "dropped", "Reset": "reset"}.get(
            row.get("DvcAction")) or {"Success": "success", "Failure": "failed"}.get(row.get("EventResult"), "other")
        e["metadata"]["parser_id"] = "asim"
        e["metadata"]["parser_name"] = "ASIM import"
    e["event_id"] = row.get("EventUid") or e["event_id"]
    e["message"] = row.get("EventMessage")
    if base is None:
        e["raw_event"] = None
    e["parsed_fields"] = parsed
    return e


# ---------------------------------------------------------------------------
# Conformance
# ---------------------------------------------------------------------------

def validate(row: dict) -> list[str]:
    """Problems of an ASIM row ([] when it conforms): known columns of its schema, mandatory
    columns present, enumerated values."""
    errors: list[str] = []
    name = row.get("EventSchema")
    schema = {v: k for k, v in SCHEMA_NAME.items()}.get(name, name)
    if schema not in catalog() or schema == "Common":
        return [f"unknown EventSchema {name!r}"]
    fields = _fields(schema)
    for col in row:
        if col not in fields and col not in _LOG_ANALYTICS:
            errors.append(f"{col}: not a column of {name}")
    for col, cls in fields.items():
        if cls == "Mandatory" and col not in row:
            errors.append(f"{col}: mandatory column missing")
    for scope in ("*", schema):
        for col, values in ENUMS.get(scope, {}).items():
            if col in row and row[col] not in values and not (row[col] == "" and fields.get(col) == "Mandatory"):
                errors.append(f"{col}: {row[col]!r} is not one of {values}")
    if row.get("EventSchemaVersion") != catalog()[schema]["version"]:
        errors.append("EventSchemaVersion is not " + str(catalog()[schema]["version"]))
    if row.get("EventResultDetails") is not None and name == "Dns" and row["EventResultDetails"] == "":
        errors.append("EventResultDetails: Dns needs the response code name (or NA)")
    return errors
