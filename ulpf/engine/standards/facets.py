"""
What a unified event describes, for the standard views (OCSF, UDM, ASIM).

The unified schema has endpoints, network, user, device, rule and threat
groups; process, file, registry, HTTP, DNS, e-mail, account and cloud-API
details stay in ``parsed_fields`` under vendor names. ``facets(event)``
collects them under one vocabulary (``Facets``), and ``classify(event)``
decides the activity: a Windows / Sysmon event ID when there is one, then the
shape of cloud audit records, then the facets present, then the category.

Each facet remembers the parsed field it came from, and a view marks the facets
it writes (``Facets.take``); ``unmapped_vendor_fields`` then returns exactly the
fields that no unified field and no written facet carries. The views keep those
under ``x_<vendor>`` (sorted keys: deterministic output), so nothing is lost.

``FACET_KEYS`` are the names the reverse mappings (``from_ocsf`` ...) write into
``parsed_fields``; they are the first candidates here, so a view of an imported
event finds them again.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# facet attribute -> parsed-field candidates (lower case; matched against the whole key
# and against its last dotted component). The first entry is the canonical import key.
CANDIDATES: dict[str, tuple[str, ...]] = {
    # target process (the process an activity is about: created, terminated, opened)
    "process.name": ("process.name", "process_name", "processname", "newprocessname", "image", "process",
                     "deviceprocessname", "sproc", "exe", "comm", "targetimage"),
    "process.path": ("process.executable", "process_path", "processpath", "image", "newprocessname", "targetimage"),
    "process.pid": ("process.pid", "process_id", "processid", "newprocessid", "spid", "targetprocessid"),
    "process.cmd_line": ("process.command_line", "commandline", "command_line", "cmdline", "cmd", "process_cmdline"),
    "process.uid": ("process.entity_id", "processguid", "process_guid", "targetprocessguid"),
    "process.integrity": ("process.integrity_level", "integritylevel", "mandatorylabel"),
    # the acting process (parent for creations, the source for accesses)
    "actor.process.name": ("process.parent.name", "parentimage", "parent_process", "parentprocessname",
                           "parent_process_name", "sourceimage", "creatorprocessname"),
    "actor.process.pid": ("process.parent.pid", "parentprocessid", "parent_pid", "ppid", "sourceprocessid",
                          "creatorprocessid"),
    "actor.process.cmd_line": ("process.parent.command_line", "parentcommandline", "parent_command_line"),
    "actor.process.uid": ("process.parent.entity_id", "parentprocessguid", "sourceprocessguid"),
    # file
    "file.path": ("file.path", "targetfilename", "imageloaded", "file_path", "filepath", "fname", "filename", "file.name",
                  "objectname", "path", "target_file"),
    "file.hashes": ("file.hashes", "hashes", "hash", "filehash"),
    "file.md5": ("file.hash.md5", "md5", "filehash_md5"),
    "file.sha1": ("file.hash.sha1", "sha1"),
    "file.sha256": ("file.hash.sha256", "sha256", "filehash_sha256"),
    "file.size": ("file.size", "fsize", "file_size", "filesize"),
    # registry (Sysmon 12-14, Security 4657)
    "registry.key": ("registry.key", "targetobject", "registry_key", "registrykey", "reg_key", "objectname",
                     "keyname"),
    "registry.value": ("registry.value", "valuename", "objectvaluename", "registry_value", "value_name"),
    "registry.data": ("registry.data", "details", "newvalue", "registry_data", "value_data"),
    "registry.type": ("registry.data.type", "newvaluetype", "valuetype", "registry_value_type"),
    # HTTP
    "http.method": ("http.request.method", "method", "requestmethod", "http_method", "cs-method", "verb"),
    "http.url": ("url.full", "url", "requesturl", "request", "http.url", "uri", "cs-uri-stem", "request_url",
                 "full_url"),
    "http.query": ("url.query", "cs-uri-query", "query_string", "querystring"),
    "http.host": ("url.domain", "http_host", "cs-host", "host_header", "requesthost"),
    "http.status": ("http.response.status_code", "status_code", "sc-status", "http_status", "response_code",
                    "statuscode", "httpstatus"),
    "http.user_agent": ("user_agent.original", "user_agent", "useragent", "requestclientapplication", "http_user_agent",
                        "cs(user-agent)", "ua"),
    "http.referrer": ("http.request.referrer", "referer", "referrer", "requestcontext", "cs(referer)"),
    # DNS
    "dns.query": ("dns.question.name", "query", "qname", "dns_query", "query_name", "queryname", "domain"),
    "dns.qtype": ("dns.question.type", "qtype", "query_type", "querytype", "record_type", "qtype_name"),
    "dns.rcode": ("dns.response_code", "rcode", "rcode_name", "responsecode", "response", "dns_rcode",
                  "querystatus"),
    "dns.answer": ("dns.answers.data", "answers", "answer", "responseip", "resolved_ip", "rdata", "queryresults"),
    # e-mail
    "email.from": ("email.from.address", "from", "sender", "mail_from", "smtp_from"),
    "email.to": ("email.to.address", "to", "recipient", "rcpt", "rcpt_to", "recipients"),
    "email.subject": ("email.subject", "subject", "mail_subject"),
    # authentication / Windows
    "auth.logon_type": ("auth.logon_type", "logontype", "logon_type"),
    "auth.protocol": ("auth.protocol", "authenticationpackagename", "auth_protocol", "authpackage",
                      "logonprocessname", "auth_method", "method_auth"),
    "auth.failure": ("auth.failure_reason", "failurereason", "failure_reason", "substatus", "reason"),
    "win.event_id": ("event.code", "eventid", "eventcode", "winlog.event_id", "event.system.eventid"),
    "win.provider": ("event.provider", "provider.name", "providername", "source_name", "event.system.provider.name"),
    "win.channel": ("winlog.channel", "channel", "event.system.channel"),
    # group management
    "group.name": ("group.name", "groupname", "group_name", "targetusername_group", "membergroup"),
    "group.member": ("group.member", "membername", "membersid", "member"),
    # cloud audit (CloudTrail, GCP audit, Azure activity)
    "cloud.provider": ("cloud.provider", "cloud_provider"),
    "api.operation": ("api.operation", "eventname", "protopayload.methodname", "methodname", "operationname",
                      "operation", "api_operation", "action_name"),
    "api.service": ("api.service", "eventsource", "protopayload.servicename", "servicename", "resourceprovidername",
                    "api_service"),
    "api.error": ("api.error", "errorcode", "error_code", "protopayload.status.code", "resultsignature"),
    "api.request_id": ("api.request_id", "requestid", "request_id", "correlationid"),
    "api.src_ip": ("api.src_ip", "sourceipaddress", "callerip", "calleripaddress", "requestmetadata.callerip",
                   "protopayload.requestmetadata.callerip"),
    "cloud.region": ("cloud.region", "awsregion", "region", "location_region"),
    "cloud.account": ("cloud.account", "recipientaccountid", "useridentity.accountid", "accountid", "subscriptionid",
                      "project_id", "resource.labels.project_id"),
    "cloud.actor_type": ("useridentity.type", "principal_type", "identity_type"),
    "cloud.actor_uid": ("useridentity.arn", "useridentity.principalid", "protopayload.authenticationinfo.principalemail",
                        "caller", "principal_id"),
    # service / application lifecycle
    "service.name": ("service.name", "servicename", "service_name", "unit"),
    "app.name": ("app.name", "application_name", "appname"),
}

_REGISTRY_ROOT = re.compile(r"^(HK(LM|CU|CR|U|CC)|HKEY_|\\REGISTRY\\)", re.I)
_CLOUD_SOURCE = re.compile(r"\.amazonaws\.com$|\.googleapis\.com$|^microsoft\.", re.I)


@dataclass
class Facets:
    values: dict[str, Any] = field(default_factory=dict)
    src: dict[str, str] = field(default_factory=dict)    # facet -> the parsed_fields key it came from
    emitted: set = field(default_factory=set)            # facets a view has written

    def get(self, name: str, default=None):
        return self.values.get(name, default)

    def take(self, name: str, default=None):
        """The facet's value, recorded as written by the view (its source field is then not
        repeated under x_<vendor>)."""
        if name in self.values:
            self.emitted.add(name)
            return self.values[name]
        return default

    def _set(self, name: str, value, key: str) -> None:
        self.values[name] = value
        self.src[name] = key

    def _drop(self, name: str) -> None:
        self.values.pop(name, None)
        self.src.pop(name, None)

    def has(self, prefix: str) -> bool:
        return any(k == prefix or k.startswith(prefix + ".") for k in self.values)


def _index(parsed: dict) -> tuple[dict, dict]:
    full: dict[str, str] = {}
    last: dict[str, str] = {}
    for k in parsed:
        lk = str(k).lower()
        full.setdefault(lk, k)
        last.setdefault(lk.rsplit(".", 1)[-1], k)
    return full, last


def _present(v) -> bool:
    return v not in (None, "", [], {}, "-")


def facets(event: dict) -> Facets:
    parsed = event.get("parsed_fields") or {}
    full, last = _index(parsed)
    f = Facets()
    for name, cands in CANDIDATES.items():
        for c in cands:
            k = full.get(c)
            if k is None and "." not in c:
                k = last.get(c)
            if k is not None and _present(parsed[k]):
                f._set(name, parsed[k], k)
                break
    # registry keys and file paths share vendor fields (Security 4657/4663 "ObjectName")
    key = f.values.get("registry.key")
    if key is not None and not _REGISTRY_ROOT.match(str(key)):
        f._drop("registry.key")
    if f.values.get("file.path") is not None and _REGISTRY_ROOT.match(str(f.values["file.path"])):
        f._drop("file.path")
    # a syslog line names the program that logged it: that is the actor, not a target
    if event.get("raw_format") == "syslog":
        app = parsed.get("app_name")
        for k in [k for k in f.values if k.startswith("process.")]:
            f._drop(k)
        if app:
            f._set("actor.process.name", app, "app_name")
            if parsed.get("pid"):
                f._set("actor.process.pid", parsed["pid"], "pid")
    if "win.event_id" in f.values:
        try:
            f.values["win.event_id"] = int(str(f.values["win.event_id"]).strip())
        except ValueError:
            f._drop("win.event_id")
    if "api.service" in f.values and "cloud.provider" not in f.values:
        svc = str(f.values["api.service"])
        if svc.endswith(".amazonaws.com"):
            f.values["cloud.provider"] = "AWS"
        elif svc.endswith(".googleapis.com"):
            f.values["cloud.provider"] = "GCP"
        elif svc.lower().startswith("microsoft."):
            f.values["cloud.provider"] = "Azure"
    return f


# ---------------------------------------------------------------------------
# Activity classification
# ---------------------------------------------------------------------------

@dataclass
class Activity:
    kind: str          # see KINDS
    verb: str          # create, delete, modify, read, launch, terminate, logon, logoff, ...
    facets: Facets


KINDS = ("finding", "network", "http", "dns", "dhcp", "ssh", "rdp", "smb", "ftp", "email", "ntp", "tunnel",
         "authentication", "account", "group", "process", "file", "registry_key", "registry_value",
         "kernel_extension", "module", "scheduled_job", "service", "application", "event_log", "api",
         "config", "base")

# Windows Security and Sysmon event IDs (provider decides between them where they collide)
_SECURITY_IDS = {
    4624: ("authentication", "logon"), 4625: ("authentication", "logon"), 4634: ("authentication", "logoff"),
    4647: ("authentication", "logoff"), 4648: ("authentication", "logon"), 4768: ("authentication", "ticket"),
    4769: ("authentication", "service_ticket"), 4770: ("authentication", "service_ticket_renew"),
    4771: ("authentication", "preauth"), 4776: ("authentication", "logon"), 4778: ("authentication", "logon"),
    4779: ("authentication", "logoff"),
    4720: ("account", "create"), 4722: ("account", "enable"), 4723: ("account", "password_change"),
    4724: ("account", "password_reset"), 4725: ("account", "disable"), 4726: ("account", "delete"),
    4738: ("account", "modify"), 4740: ("account", "lock"), 4767: ("account", "unlock"),
    4727: ("group", "create"), 4731: ("group", "create"), 4754: ("group", "create"),
    4728: ("group", "add_member"), 4732: ("group", "add_member"), 4756: ("group", "add_member"),
    4729: ("group", "remove_member"), 4733: ("group", "remove_member"), 4757: ("group", "remove_member"),
    4730: ("group", "delete"), 4734: ("group", "delete"), 4758: ("group", "delete"),
    4735: ("group", "modify"), 4737: ("group", "modify"), 4755: ("group", "modify"),
    4688: ("process", "launch"), 4689: ("process", "terminate"),
    4663: ("file", "read"), 4660: ("file", "delete"), 4656: ("file", "open"),
    4657: ("registry_value", "modify"),
    4698: ("scheduled_job", "create"), 4699: ("scheduled_job", "delete"), 4700: ("scheduled_job", "enable"),
    4701: ("scheduled_job", "disable"), 4702: ("scheduled_job", "modify"),
    4697: ("service", "install"), 7045: ("service", "install"), 7036: ("service", "state"),
    7040: ("service", "modify"),
    1102: ("event_log", "clear"), 104: ("event_log", "clear"),
    5156: ("network", "open"), 5157: ("network", "refuse"), 5158: ("network", "open"),
    4719: ("config", "modify"), 4739: ("config", "modify"),
}
_SYSMON_IDS = {
    1: ("process", "launch"), 5: ("process", "terminate"), 8: ("process", "inject"), 10: ("process", "open"),
    25: ("process", "modify"), 3: ("network", "open"), 22: ("dns", "query"), 6: ("kernel_extension", "load"),
    7: ("module", "load"), 2: ("file", "modify"), 11: ("file", "create"), 15: ("file", "create"),
    23: ("file", "delete"), 26: ("file", "delete"), 29: ("file", "create"),
    12: ("registry_key", "create"), 13: ("registry_value", "modify"), 14: ("registry_key", "rename"),
    4: ("service", "state"), 16: ("config", "modify"), 17: ("process", "open"), 18: ("process", "open"),
    19: ("process", "open"), 20: ("process", "open"), 21: ("process", "open"),
}

_WORDS = {
    "create": ("creat", "added", "new ", "install", "upload", "write", "wrote"),
    "delete": ("delet", "remov", "purg", "erase", "unlink"),
    "modify": ("modif", "chang", "updat", "set ", "rename", "edit"),
    "read": ("read", "access", "open", "download", "view"),
    "launch": ("start", "launch", "spawn", "exec", "creat"),
    "terminate": ("terminat", "exit", "kill", "stop", "ended"),
}


def _verb_from_text(text: str, choices: tuple[str, ...], default: str) -> str:
    t = text.lower()
    for v in choices:
        if any(w in t for w in _WORDS[v]):
            return v
    return default


# Cloud API operation names start with their verb: CloudTrail "DeleteBucket", GCP
# "storage.buckets.delete", Azure "Microsoft.Compute/virtualMachines/delete"
_API_VERBS = (("create", ("create", "add", "insert", "new", "run", "start", "launch", "register", "import")),
              ("delete", ("delete", "remove", "terminate", "destroy", "deregister", "purge")),
              ("modify", ("update", "put", "modify", "set", "patch", "attach", "detach", "change", "enable",
                          "disable", "replace", "write", "action", "assign", "stop", "reboot", "restart")),
              ("read", ("get", "list", "describe", "read", "head", "lookup", "search", "view", "query", "assume")))


def api_verb(operation: str) -> str:
    op = operation.replace("/", ".").rsplit(".", 1)[-1] if ("/" in operation or "." in operation) else operation
    low = op.lower()
    for verb, prefixes in _API_VERBS:
        if any(low.startswith(p) for p in prefixes):
            return verb
    return "other"


def classify(event: dict, f: Facets | None = None) -> Activity:
    f = f or facets(event)
    kind_ = event.get("event_kind") or "log"
    if kind_ in ("anomaly", "correlation", "detection", "drift", "notable"):
        return Activity("finding", "create", f)
    text = " ".join(str(x) for x in (event.get("event_type"), event.get("message")) if x)
    eid = f.get("win.event_id")
    if eid is not None:
        provider = str(f.get("win.provider") or "").lower()
        table = _SYSMON_IDS if "sysmon" in provider else _SECURITY_IDS
        if eid in table:
            k, v = table[eid]
            if k == "registry_key" and v == "create" and f.get("registry.value") is not None:
                k = "registry_value"
            if k == "service" and v == "state":
                v = _verb_from_text(text, ("terminate", "launch"), "state")
            return Activity(k, v, f)
    if f.get("api.operation") is not None and (f.get("api.service") is not None or f.get("cloud.provider")):
        if str(f.get("api.operation")).lower() in ("consolelogin", "signin", "login"):
            return Activity("authentication", "logon", f)     # CloudTrail / console sign-in
        return Activity("api", api_verb(str(f.get("api.operation"))), f)
    cat = event.get("category") or "other"
    if cat == "ids_ips" or (cat in ("endpoint", "web") and (event.get("threat") or {}).get("signature")
                            and not f.has("http")):
        return Activity("finding", "create", f)
    if f.get("registry.key") is not None:
        k = "registry_value" if f.get("registry.value") is not None or f.get("registry.data") is not None \
            else "registry_key"
        return Activity(k, _verb_from_text(text, ("delete", "create", "modify", "read"), "modify"), f)
    if cat in ("endpoint", "system", "audit", "other") and f.get("process.name") is not None \
            and f.get("file.path") is None:
        return Activity("process", _verb_from_text(text, ("terminate", "launch"), "launch"), f)
    if cat in ("endpoint", "system", "audit", "other") and f.get("file.path") is not None:
        return Activity("file", _verb_from_text(text, ("delete", "create", "modify", "read"), "other"), f)
    if cat == "dns" or f.get("dns.query") is not None and cat in ("network", "other"):
        return Activity("dns", "query" if f.get("dns.rcode") is None else "response", f)
    if cat in ("web", "proxy") or f.has("http"):
        return Activity("http", str(f.get("http.method") or "other").lower(), f)
    if cat == "authentication":
        low = text.lower()
        if any(w in low for w in ("password change", "password reset", "account created", "user created",
                                  "account deleted", "user deleted", "account locked", "account disabled")):
            return Activity("account", _verb_from_text(low, ("create", "delete", "modify"), "modify"), f)
        logoff = (event.get("action") or "") in ("logout", "logoff") or "logoff" in low or "logout" in low
        return Activity("authentication", "logoff" if logoff else "logon", f)
    if cat == "vpn":
        return Activity("tunnel", "open", f)
    if cat in ("network", "firewall"):
        app = str((event.get("network") or {}).get("application") or "").lower()
        for k, names in (("ssh", ("ssh",)), ("rdp", ("rdp", "ms-rdp", "ms-wbt-server")),
                         ("smb", ("smb", "cifs", "microsoft-ds")), ("ftp", ("ftp",)), ("dhcp", ("dhcp", "bootps")),
                         ("ntp", ("ntp",)), ("email", ("smtp", "smtps", "imap", "pop3"))):
            if app in names:
                return Activity(k, "open", f)
        if f.has("email"):
            return Activity("email", "send", f)
        return Activity("network", "open", f)
    low = text.lower()
    if cat in ("system", "audit") and any(w in low for w in ("config", "setting", "policy")):
        return Activity("config", "modify", f)
    if cat == "system" and (f.get("service.name") is not None
                            or any(w in low for w in ("systemd", "service", "daemon"))):
        v = _verb_from_text(low, ("terminate", "launch"), "other")
        return Activity("application", {"launch": "start", "terminate": "stop"}.get(v, v), f)
    src, dst = event.get("source") or {}, event.get("destination") or {}
    if (src.get("ip") or dst.get("ip")) and (src.get("port") is not None or dst.get("port") is not None
                                             or (event.get("network") or {}).get("protocol")):
        return Activity("network", "open", f)    # any category: a connection between two endpoints
    return Activity("base", "other", f)


# ---------------------------------------------------------------------------
# Vendor extension namespace
# ---------------------------------------------------------------------------

_VENDOR_RE = re.compile(r"[^a-z0-9]+")


def vendor_namespace(event: dict) -> str:
    """``x_<vendor>``: the device vendor in lower case, non-alphanumerics as '_' ("x_unknown")."""
    v = str((event.get("device") or {}).get("vendor") or "").strip().lower()
    v = _VENDOR_RE.sub("_", v).strip("_")
    return f"x_{v or 'unknown'}"


def unmapped_vendor_fields(event: dict, f: Facets | None = None) -> dict:
    """Parsed fields that neither a unified field nor a facet carries, in sorted key order."""
    from ulpf.engine.normalizer import _resolve_field
    f = f or facets(event)
    parsed = event.get("parsed_fields") or {}
    written = {f.src[n] for n in f.emitted if n in f.src}
    out = {}
    for k in sorted(parsed, key=str):
        if k in written:
            continue
        if _resolve_field(str(k)) is not None:
            continue
        v = parsed[k]
        if v is None:
            continue
        out[str(k)] = v
    return out
