"""
Sigma rule compiler and evaluator.

Compiles Sigma detection rules (https://sigmahq.io, rule specification v1/v2)
into Python closures over ULPF events. No ``eval``/``exec``: conditions are
parsed into an expression tree and selections into matcher functions.

Supported
    detection   named selections (maps: AND across fields; lists of maps: OR),
                keyword lists (searched in ``raw_event`` and ``message``),
                ``null`` / empty values, lists of values (OR, or AND with ``|all``)
    modifiers   contains, startswith, endswith, all, re (+ i, m, s), cidr, exists,
                lt, lte, gt, gte, base64, base64offset, utf16le/utf16be/utf16/wide
                (with base64), windash, cased, fieldref
    condition   and / or / not / parentheses, ``1 of sel*``, ``all of sel*``,
                ``N of ...``, ``1 of them``, ``all of them``; a list of conditions
                (OR); aggregation ``| count([field]) [by group] <op> N`` over the
                rule's ``timeframe`` (default 1 hour)
    tags        ``attack.tNNNN[.NNN]`` techniques and ``attack.<tactic>`` tactics
                (MITRE ATT&CK), mapped onto ULPF's kill-chain stages
    logsource   categories and products mapped to ULPF categories / formats;
                unknown ones do not filter (the rule is evaluated on every event)

    correlation Sigma correlation rules (``correlation:`` documents): event_count,
                value_count, temporal and temporal_ordered over referenced rules (by
                ``name`` or ``id``), ``group-by`` with ``aliases``, ``timespan``,
                conditions gt / gte / lt / lte / eq / neq (several are ANDed),
                ``generate``

Not supported (the rule is rejected with a reason, never half-applied):
``expand`` placeholders, aggregation functions other than ``count``, ``near``,
and correlations of correlations.

Every compiled matcher also carries ``ir``: a JSON-able description the
compiled core (``ulpf_core.Analytics``) evaluates on its native events with
the same results. ``ir`` is None where the core cannot reproduce Python's
semantics exactly (Python-only regex syntax, case folding of non-ASCII
patterns); an engine with such a rule is evaluated in Python.

Field names resolve, in order, to: a unified-schema dotted path
(``source.ip``), the Sigma/Windows/ECS names in ``FIELD_MAP``
(``SourceIp``, ``TargetUserName``, ``event.action``), ULPF's vendor field
aliases (``src_ip``, ``dstport``, ...), then the event's original vendor
fields (``parsed_fields``, case-insensitive) — so a rule written for raw
Windows / Sysmon / Zeek field names also works on the normalised events.
"""
from __future__ import annotations

import base64
import glob
import ipaddress
import logging
import os
import re
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable

logger = logging.getLogger(__name__)

BUILTIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sigma_rules")

LEVELS = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# MITRE ATT&CK Enterprise tactics (x-mitre-tactic short names) -> ULPF kill-chain stage
TACTICS = {
    "reconnaissance": ("TA0043", "Reconnaissance", "reconnaissance"),
    "resource_development": ("TA0042", "Resource Development", "weaponization"),
    "initial_access": ("TA0001", "Initial Access", "delivery"),
    "execution": ("TA0002", "Execution", "exploitation"),
    "persistence": ("TA0003", "Persistence", "installation"),
    "privilege_escalation": ("TA0004", "Privilege Escalation", "exploitation"),
    "defense_evasion": ("TA0005", "Defense Evasion", "installation"),
    "credential_access": ("TA0006", "Credential Access", "exploitation"),
    "discovery": ("TA0007", "Discovery", "reconnaissance"),
    "lateral_movement": ("TA0008", "Lateral Movement", "exploitation"),
    "collection": ("TA0009", "Collection", "exfiltration"),
    "command_and_control": ("TA0011", "Command and Control", "command_and_control"),
    "exfiltration": ("TA0010", "Exfiltration", "exfiltration"),
    "impact": ("TA0040", "Impact", "exfiltration"),
}

# Technique names (the subset ULPF's rules and common Sigma packs use) and the
# kill-chain stage a technique implies when its tactic alone is too coarse
TECHNIQUES = {
    "T1003": "OS Credential Dumping", "T1005": "Data from Local System", "T1018": "Remote System Discovery",
    "T1021": "Remote Services", "T1021.004": "Remote Services: SSH", "T1027": "Obfuscated Files or Information",
    "T1041": "Exfiltration Over C2 Channel", "T1046": "Network Service Discovery",
    "T1048": "Exfiltration Over Alternative Protocol", "T1053": "Scheduled Task/Job",
    "T1059": "Command and Scripting Interpreter", "T1059.001": "PowerShell", "T1059.003": "Windows Command Shell",
    "T1059.004": "Unix Shell", "T1070": "Indicator Removal", "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols", "T1071.004": "DNS", "T1078": "Valid Accounts", "T1090": "Proxy",
    "T1098": "Account Manipulation", "T1105": "Ingress Tool Transfer", "T1110": "Brute Force",
    "T1110.001": "Password Guessing", "T1110.003": "Password Spraying", "T1133": "External Remote Services",
    "T1136": "Create Account", "T1190": "Exploit Public-Facing Application", "T1203": "Exploitation for Client Execution",
    "T1486": "Data Encrypted for Impact", "T1490": "Inhibit System Recovery", "T1498": "Network Denial of Service",
    "T1505.003": "Server Software Component: Web Shell", "T1543": "Create or Modify System Process",
    "T1547": "Boot or Logon Autostart Execution", "T1548": "Abuse Elevation Control Mechanism",
    "T1562": "Impair Defenses", "T1566": "Phishing", "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link", "T1567": "Exfiltration Over Web Service", "T1568": "Dynamic Resolution",
    "T1571": "Non-Standard Port", "T1572": "Protocol Tunneling", "T1573": "Encrypted Channel",
    "T1595": "Active Scanning", "T1595.001": "Scanning IP Blocks", "T1595.002": "Vulnerability Scanning",
}
TECHNIQUE_STAGE = {
    "T1190": "exploitation", "T1203": "exploitation", "T1110": "exploitation", "T1078": "exploitation",
    "T1566": "delivery", "T1105": "delivery", "T1505.003": "installation", "T1059": "exploitation",
    "T1071": "command_and_control", "T1572": "command_and_control", "T1048": "exfiltration",
    "T1041": "exfiltration", "T1567": "exfiltration", "T1046": "reconnaissance", "T1595": "reconnaissance",
}

# Sigma / Windows / Sysmon / Zeek / ECS field names -> unified-schema path
FIELD_MAP = {
    # endpoints
    "sourceip": "source.ip", "src_ip": "source.ip", "src": "source.ip", "ipaddress": "source.ip",
    "client_ip": "source.ip", "c-ip": "source.ip", "id.orig_h": "source.ip",
    "sourceport": "source.port", "src_port": "source.port", "ipport": "source.port", "id.orig_p": "source.port",
    "sourcehostname": "source.hostname", "workstationname": "source.hostname", "workstation": "source.hostname",
    "destinationip": "destination.ip", "dst_ip": "destination.ip", "dst": "destination.ip", "id.resp_h": "destination.ip",
    "destinationport": "destination.port", "dst_port": "destination.port", "id.resp_p": "destination.port",
    "destinationhostname": "destination.hostname", "dest_hostname": "destination.hostname",
    # network
    "protocol": "network.protocol", "proto": "network.protocol", "network.transport": "network.protocol",
    "network.direction": "network.direction", "sent_bytes": "network.bytes_out", "received_bytes": "network.bytes_in",
    "source.bytes": "network.bytes_out", "destination.bytes": "network.bytes_in",
    # identities
    "user": "user.name", "username": "user.name", "accountname": "user.name", "user.name": "user.name",
    "targetusername": "user.target.name", "targetdomainname": "user.target.domain",
    "subjectusername": "user.source.name", "subjectdomainname": "user.source.domain",
    # host / device
    "computer": "device.hostname", "computername": "device.hostname", "hostname": "device.hostname",
    "host.name": "device.hostname", "host.hostname": "device.hostname", "dvc": "device.ip",
    "observer.vendor": "device.vendor", "observer.product": "device.product",
    # event
    "event.action": "action", "event.category": "category", "event.severity": "severity",
    "event.kind": "event_kind", "event.dataset": "raw_format", "message": "message", "msg": "message",
    "rule.name": "rule.name", "rule.id": "rule.id", "signature": "threat.signature",
    "alert.signature": "threat.signature", "threat.indicator.ip": "threat.ioc_value",
}

_CATEGORY_LOGSOURCE = {
    "firewall": {"firewall"}, "proxy": {"proxy", "web"}, "webserver": {"web"}, "dns": {"dns"},
    "authentication": {"authentication"}, "antivirus": {"endpoint", "ids_ips"}, "ids": {"ids_ips"},
    "network_connection": {"network", "firewall"}, "vpn": {"vpn"}, "application": None,
    "process_creation": {"endpoint", "system"},
}
_PRODUCT_FORMATS = {"linux": {"syslog"}, "zeek": {"json", "kv"}}

# Logsource -> the events it means, as a Sigma selection ANDed with the rule (so it compiles
# for the core like any selection). Windows categories are Sysmon event IDs (the field names
# SigmaHQ uses are Sysmon's); a Channel, when the event has one, must be Sysmon's.
_SYSMON_IDS = {
    "process_creation": [1], "network_connection": [3], "process_termination": [5], "driver_load": [6],
    "image_load": [7], "create_remote_thread": [8], "raw_access_thread": [9], "process_access": [10],
    "file_event": [11], "registry_add": [12], "registry_delete": [12], "registry_set": [13],
    "registry_rename": [14], "registry_event": [12, 13, 14], "create_stream_hash": [15],
    "pipe_created": [17, 18], "wmi_event": [19, 20, 21], "dns_query": [22], "file_delete": [23, 26],
    "clipboard_capture": [24], "process_tampering": [25], "file_block_executable": [27],
    "file_block_shredding": [28], "file_executable_detected": [29], "sysmon_status": [4, 16],
    "sysmon_error": [255], "file_delete_detected": [26],
}
_PS_IDS = {"ps_script": ("Microsoft-Windows-PowerShell/Operational", [4104]),
           "ps_module": ("Microsoft-Windows-PowerShell/Operational", [4103]),
           "ps_classic_start": ("Windows PowerShell", [400]),
           "ps_classic_provider_start": ("Windows PowerShell", [600]),
           "ps_classic_script": ("Windows PowerShell", [800])}
_WIN_CHANNELS = {
    "security": "Security", "system": "System", "application": "Application", "sysmon": "sysmon",
    "powershell": "Microsoft-Windows-PowerShell/Operational", "powershell-classic": "Windows PowerShell",
    "taskscheduler": "Microsoft-Windows-TaskScheduler", "wmi": "Microsoft-Windows-WMI-Activity",
    "dns-server": "DNS Server", "driver-framework": "Microsoft-Windows-DriverFrameworks",
    "ntlm": "Microsoft-Windows-NTLM", "codeintegrity-operational": "Microsoft-Windows-CodeIntegrity",
    "firewall-as": "Microsoft-Windows-Windows Firewall With Advanced Security", "bits-client": "Microsoft-Windows-Bits-Client",
    "windefend": "Microsoft-Windows-Windows Defender", "applocker": "Microsoft-Windows-AppLocker",
    "msexchange-management": "MSExchange Management", "printservice-admin": "Microsoft-Windows-PrintService",
    "smbclient-security": "Microsoft-Windows-SmbClient", "terminalservices-localsessionmanager":
    "Microsoft-Windows-TerminalServices-LocalSessionManager", "openssh": "OpenSSH",
    "dns-client": "Microsoft-Windows-DNS-Client", "ldap_debug": "Microsoft-Windows-LDAP-Client",
    "appxdeployment-server": "Microsoft-Windows-AppXDeploymentServer", "shell-core": "Microsoft-Windows-Shell-Core",
    "vhdmp": "Microsoft-Windows-VHDMP", "diagnosis-scripted": "Microsoft-Windows-Diagnosis-Scripted",
    "lsa-server": "Microsoft-Windows-LSA", "kernel-shimengine": "Microsoft-Windows-Kernel-ShimEngine",
}
_CLOUD_FIELDS = {"aws": "eventSource", "azure": "operationName", "gcp": "methodName", "okta": "eventType",
                 "github": "action", "m365": "Workload", "google_workspace": "methodName", "onelogin": "event_type"}


def logsource_guard(ls: dict) -> Any:
    """The selection a rule's logsource adds (None: no restriction beyond ULPF categories)."""
    product = str(ls.get("product") or "").lower()
    category = str(ls.get("category") or "").lower()
    service = str(ls.get("service") or "").lower()
    if product == "windows":
        if category in _SYSMON_IDS:
            ids = _SYSMON_IDS[category]
            return [{"EventID": ids, "Channel|contains": "sysmon"}, {"EventID": ids, "Channel": None}]
        if category in _PS_IDS:
            ch, ids = _PS_IDS[category]
            return [{"EventID": ids, "Channel": ch}, {"EventID": ids, "Channel": None}]
        if service:
            return {"Channel|contains": _WIN_CHANNELS.get(service, service)}
        return {"EventID|exists": True}
    if product in _CLOUD_FIELDS:
        return {f"{_CLOUD_FIELDS[product]}|exists": True}
    if product == "zeek":
        return {"uid|exists": True}
    if product in ("linux", "macos") and category == "process_creation":
        return [{"EventID": 1}, {"type": "EXECVE"}, {"syscall": ["execve", "59"]}]
    return None


class SigmaError(ValueError):
    """A rule that cannot be compiled (with the reason)."""


# ---------------------------------------------------------------------------
# Event field access
# ---------------------------------------------------------------------------

def _walk(event: dict, path: str) -> Any:
    cur: Any = event
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


_SCHEMA_GROUPS = ("source", "destination", "network", "device", "rule", "threat", "user", "geo", "metadata",
                  "evidence")


class EventView:
    """Field lookups on one event, cached (rules share the work)."""
    __slots__ = ("event", "_cache", "_text", "_lower_parsed", "_leaf")

    def __init__(self, event: dict):
        self.event = event
        self._cache: dict[str, Any] = {}
        self._text: str | None = None
        self._lower_parsed: dict[str, Any] | None = None
        self._leaf: dict[str, Any] | None = None

    def get(self, name: str) -> Any:
        try:
            return self._cache[name]
        except KeyError:
            pass
        v = self._resolve(name)
        self._cache[name] = v
        return v

    def _resolve(self, name: str) -> Any:
        ev = self.event
        if "." in name and name.split(".", 1)[0] in _SCHEMA_GROUPS:
            v = _walk(ev, name)
            if v is not None:
                return v
        if name in ev and not isinstance(ev[name], dict):
            return ev[name]
        low = name.lower()
        target = FIELD_MAP.get(low)
        if target is None:
            from ulpf.engine.normalizer import _resolve_field
            t = _resolve_field(name)
            target = ".".join(t) if t else None
        if target is not None:
            v = _walk(ev, target)
            if v is not None:
                return v
        parsed = ev.get("parsed_fields") or {}
        if name in parsed:
            return parsed[name]
        if self._lower_parsed is None:
            self._lower_parsed, self._leaf = {}, {}
            for k, val in parsed.items():
                kl = str(k).lower()
                self._lower_parsed.setdefault(kl, val)
                if "." in kl:
                    # flattened documents (Windows XML event.eventdata.image): the last segment
                    self._leaf.setdefault(kl.rsplit(".", 1)[1], val)
        if low in self._lower_parsed:
            return self._lower_parsed[low]
        return self._leaf.get(low)

    def text(self) -> str:
        if self._text is None:
            ev = self.event
            self._text = f"{ev.get('raw_event') or ''}\n{ev.get('message') or ''}"
        return self._text


def field_ir(name: str) -> dict:
    """How ``EventView.get(name)`` resolves, for the compiled core (same lookups, same order)."""
    low = name.lower()
    target = FIELD_MAP.get(low)
    if target is None:
        from ulpf.engine.normalizer import _resolve_field
        t = _resolve_field(name)
        target = ".".join(t) if t else None
    return {"name": name, "low": low,
            "dotted": "." in name and name.split(".", 1)[0] in _SCHEMA_GROUPS,
            "target": target.split(".") if target is not None else None}


# ---------------------------------------------------------------------------
# Value matchers
# ---------------------------------------------------------------------------

def _ir(fn: Callable, node: dict | None) -> Callable:
    """Attach the compiled-core description of a matcher. None (semantics only Python
    reproduces) becomes a "py" node: the core leaves an event that reaches it to Python,
    so one such matcher does not take the whole rule set off the compiled path."""
    fn.ir = node if node is not None else {"t": "py"}  # type: ignore[attr-defined]
    return fn


def _irs(fns) -> list | None:
    nodes = [getattr(f, "ir", None) for f in fns]
    return None if any(n is None for n in nodes) else nodes


def _glob_tokens(value: str) -> list:
    """A wildcard pattern as tokens: ["lit", text], ["*"] (any run) or ["?"] (one character)."""
    out: list = []
    lit: list[str] = []
    i = 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            lit.append(value[i + 1])
            i += 2
            continue
        if c in "*?":
            if lit:
                out.append(["lit", "".join(lit)])
                lit = []
            out.append([c])
        else:
            lit.append(c)
        i += 1
    if lit:
        out.append(["lit", "".join(lit)])
    return out


# Characters Python's re.IGNORECASE folds onto ASCII letters (Kelvin sign, long s, dotted /
# dotless i): a needle with one of them may match ASCII text, so it cannot be an anchor
_ASCII_FOLDS = set("KſİıÅ")


def _glob_ir(value: str, mode: str, cased: bool) -> dict | None:
    if not cased and not value.isascii():
        # re.IGNORECASE folds single characters (U+0130 matches "i"): the core leaves such
        # events to Python, but a literal of the pattern still anchors the rule (an ASCII text
        # cannot contain it)
        lits = [t[1] for t in _glob_tokens(value) if t[0] == "lit"]
        lit = max(lits, key=len).lower() if lits else ""
        if lit and not (_ASCII_FOLDS & set(lit)):
            return {"t": "py", "needles": [lit]}
        return None
    toks = _glob_tokens(value if cased else value.lower())
    if mode in ("contains", "endswith"):
        toks.insert(0, ["*"])
    if mode in ("contains", "startswith"):
        toks.append(["*"])
    return {"t": "glob", "tok": toks, "cased": cased}


# Syntax the core's regex engine reads differently from Python's re (nested classes,
# class set operations, verbose mode): such patterns stay in Python. Syntax only
# one of them accepts fails to compile in the core, which then leaves the engine
# to Python as well.
_RE_RISKY = ("[[", "&&", "--", "~~")


def _class_risky(pattern: str) -> bool:
    """A character class containing syntax the core's engine reads as set operations or nesting
    ([[, &&, --, ~~). The same characters outside a class mean the same in both engines."""
    i, depth = 0, 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if depth:
            if pattern.startswith(("[", "&&", "--", "~~"), i) and not (c == "[" and pattern.startswith("[:", i)):
                return True
            if c == "]":
                depth = 0
        elif c == "[":
            depth = 1
            i += 1
            if i < len(pattern) and pattern[i] == "^":
                i += 1
            if i < len(pattern) and pattern[i] == "]":     # a leading ] is literal
                i += 1
            continue
        i += 1
    return False


def _re_ir(pattern: str, flags: str) -> dict | None:
    if not pattern.isascii() or _class_risky(pattern) or re.search(r"\(\?[a-zA-Z]*x", pattern):
        return None   # verbose mode differs too: the core ignores whitespace inside classes
    return {"t": "re", "pat": pattern, "flags": flags}


def _wildcard_regex(value: str, mode: str, cased: bool) -> re.Pattern:
    """Sigma string semantics: * and ? wildcards, backslash escapes, whole-value match."""
    out = []
    i = 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    body = "".join(out)
    if mode in ("contains", "endswith"):
        body = ".*" + body
    if mode in ("contains", "startswith"):
        body = body + ".*"
    return re.compile(body, re.DOTALL if cased else re.DOTALL | re.IGNORECASE)


def _plain(value: str) -> bool:
    return "*" not in value and "?" not in value and "\\" not in value


def _windash(value: str) -> list[str]:
    dashes = ("-", "/", "–", "—", "―")
    positions = [i for i, c in enumerate(value) if c in "-/" and (i == 0 or value[i - 1] == " ")]
    if not positions:
        return [value]
    out = []
    for d in dashes:
        chars = list(value)
        for i in positions:
            chars[i] = d
        out.append("".join(chars))
    return out


def _encode(value: str, mods: list[str]) -> list[str]:
    """base64 / base64offset (optionally after a UTF-16 transform)."""
    raw = value.encode("utf-8")
    if "utf16le" in mods or "wide" in mods:
        raw = value.encode("utf-16-le")
    elif "utf16be" in mods:
        raw = value.encode("utf-16-be")
    elif "utf16" in mods:
        raw = value.encode("utf-16")
    if "base64" in mods:
        return [base64.b64encode(raw).decode()]
    out = []
    for i in range(3):   # base64offset: the three alignments, without the edge characters they depend on
        enc = base64.b64encode(b"\0" * i + raw).decode()
        start = (0, 2, 3)[i]
        end = len(enc) - (0, 3, 2)[(len(raw) + i) % 3]
        out.append(enc[start:end])
    return out


def _as_number(v: Any) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None


def _value_matcher(value: Any, mods: list[str]) -> Callable[[Any], bool]:
    """Matcher for one Sigma value against one event value."""
    cased = "cased" in mods
    if "exists" in mods:
        want = bool(value) if not isinstance(value, str) else value.lower() == "true"
        return _ir(lambda v: (v is not None and v != "") == want, {"t": "exists", "want": want})
    for op in ("lt", "lte", "gt", "gte"):
        if op in mods:
            ref = _as_number(value)
            if ref is None:
                raise SigmaError(f"|{op} needs a number, got {value!r}")
            cmp = {"lt": lambda a: a < ref, "lte": lambda a: a <= ref,
                   "gt": lambda a: a > ref, "gte": lambda a: a >= ref}[op]
            return _ir(lambda v: (n := _as_number(v)) is not None and cmp(n), {"t": "num", "op": op, "ref": ref})
    if value is None:
        return _ir(lambda v: v is None or v == "", {"t": "null"})
    if "cidr" in mods:
        try:
            net = ipaddress.ip_network(str(value), strict=False)
        except ValueError as e:
            raise SigmaError(f"|cidr: {e}") from None

        def in_net(v: Any) -> bool:
            try:
                return ipaddress.ip_address(str(v).split("%")[0]) in net
            except ValueError:
                return False
        return _ir(in_net, {"t": "cidr", "net": str(net)})
    if "re" in mods:
        flags = (re.IGNORECASE if "i" in mods else 0) | (re.MULTILINE if "m" in mods else 0) | \
                (re.DOTALL if "s" in mods else 0)
        try:
            rx = re.compile(str(value), flags)
        except re.error as e:
            raise SigmaError(f"|re: {e}") from None
        return _ir(lambda v: v is not None and rx.search(str(v)) is not None,
                   _re_ir(str(value), "".join(f for f in "ims" if f in mods)))
    if isinstance(value, bool):
        return _ir(lambda v: v is value or (isinstance(v, str) and v.lower() == str(value).lower()),
                   {"t": "bool", "v": value})
    if isinstance(value, (int, float)):
        ref = str(value)
        return _ir(lambda v: v is not None and not isinstance(v, (dict, list)) and str(v) == ref,
                   {"t": "numstr", "ref": ref})
    s = str(value)
    if "base64" in mods or "base64offset" in mods:
        variants = _encode(s, mods)
        mode = "contains" if "base64offset" in mods else next((m for m in ("contains", "startswith", "endswith")
                                                               if m in mods), "")
        subs = [_value_matcher(x, [mode, "cased"] if mode else ["cased"]) for x in variants]
        ir = _irs(subs)
        return _ir(lambda v: any(m(v) for m in subs), None if ir is None else {"t": "any", "of": ir})
    if "windash" in mods:
        rest = [m for m in mods if m != "windash"]
        subs = [_value_matcher(x, rest) for x in _windash(s)]
        ir = _irs(subs)
        return _ir(lambda v: any(m(v) for m in subs), None if ir is None else {"t": "any", "of": ir})
    mode = next((m for m in ("contains", "startswith", "endswith") if m in mods), "")
    if _plain(s):
        needle = s if cased else s.lower()

        def norm(v: Any) -> str | None:
            if v is None or isinstance(v, (dict, list)):
                return None
            t = v if isinstance(v, str) else str(v)
            return t if cased else t.lower()
        ir = {"t": "str", "mode": mode or "eq", "needle": needle, "cased": cased}
        if mode == "contains":
            return _ir(lambda v: (t := norm(v)) is not None and needle in t, ir)
        if mode == "startswith":
            return _ir(lambda v: (t := norm(v)) is not None and t.startswith(needle), ir)
        if mode == "endswith":
            return _ir(lambda v: (t := norm(v)) is not None and t.endswith(needle), ir)
        return _ir(lambda v: (t := norm(v)) is not None and t == needle, ir)
    rx = _wildcard_regex(s, mode, cased)
    return _ir(lambda v: v is not None and not isinstance(v, (dict, list)) and rx.fullmatch(str(v)) is not None,
               _glob_ir(s, mode, cased))


_KNOWN_MODS = {"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cidr", "exists", "lt", "lte",
               "gt", "gte", "base64", "base64offset", "utf16le", "utf16be", "utf16", "wide", "windash", "cased",
               "fieldref"}


def _field_matcher(key: str, value: Any) -> Callable[[EventView], bool]:
    name, *mods = key.split("|")
    unknown = [m for m in mods if m not in _KNOWN_MODS]
    if unknown:
        raise SigmaError(f"unsupported modifier(s) {', '.join(unknown)} on {name!r}")
    values = value if isinstance(value, list) else [value]
    if "fieldref" in mods:
        refs = [str(v) for v in values]
        return _ir(lambda ev: any(ev.get(name) is not None and ev.get(name) == ev.get(r) for r in refs),
                   {"t": "fieldref", "f": field_ir(name), "refs": [field_ir(r) for r in refs]})
    matchers = [_value_matcher(v, mods) for v in values]
    if not matchers:
        return _ir(lambda ev: False, {"t": "false"})
    ir = _irs(matchers)
    if "all" in mods:
        return _ir(lambda ev: all(m(ev.get(name)) for m in matchers),
                   None if ir is None else {"t": "field", "f": field_ir(name), "all": True, "m": ir})

    def match(ev: EventView) -> bool:
        v = ev.get(name)
        if isinstance(v, list):    # multi-valued field: any element
            return any(m(x) for x in v for m in matchers)
        return any(m(v) for m in matchers)
    return _ir(match, None if ir is None else {"t": "field", "f": field_ir(name), "all": False, "m": ir})


def _keyword_matcher(words: list) -> Callable[[EventView], bool]:
    ms = []
    irs: list | None = []
    for w in words:
        s = str(w)
        if _plain(s):
            low = s.lower()
            ms.append(lambda t, low=low: low in t.lower())
            node = {"t": "str", "mode": "contains", "needle": low, "cased": False}
        else:
            rx = _wildcard_regex(s, "contains", False)
            ms.append(lambda t, low=rx: low.fullmatch(t) is not None)
            node = _glob_ir(s, "contains", False)
        irs = None if irs is None or node is None else irs + [node]
    return _ir(lambda ev: any(m(ev.text()) for m in ms), None if irs is None else {"t": "kw", "m": irs})


def _selection(definition: Any) -> Callable[[EventView], bool]:
    if isinstance(definition, dict):
        if not definition:
            raise SigmaError("empty selection")
        parts = [_field_matcher(k, v) for k, v in definition.items()]
        ir = _irs(parts)
        return _ir(lambda ev: all(p(ev) for p in parts), None if ir is None else {"t": "and", "of": ir})
    if isinstance(definition, list):
        if all(isinstance(x, dict) for x in definition):
            alts = [_selection(x) for x in definition]
            ir = _irs(alts)
            return _ir(lambda ev: any(a(ev) for a in alts), None if ir is None else {"t": "or", "of": ir})
        if all(not isinstance(x, (dict, list)) for x in definition):
            return _keyword_matcher(definition)
        raise SigmaError("a selection list mixes maps and keywords")
    if isinstance(definition, str):
        return _keyword_matcher([definition])
    raise SigmaError(f"unsupported selection type {type(definition).__name__}")


# ---------------------------------------------------------------------------
# Conditions
# ---------------------------------------------------------------------------

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*.\-]+)")
_AGG = re.compile(r"^\s*count\(\s*([\w.\-]*)\s*\)\s*(?:by\s+([\w.\-]+(?:\s*,\s*[\w.\-]+)*))?\s*(<=|>=|==|=|<|>)\s*(\d+)\s*$",
                  re.I)


@dataclass
class Aggregation:
    field: str | None       # count(field): distinct values of the field; count(): events
    group_by: tuple[str, ...]
    op: str
    threshold: int

    def holds(self, n: int) -> bool:
        return {"<": n < self.threshold, "<=": n <= self.threshold, ">": n > self.threshold,
                ">=": n >= self.threshold, "=": n == self.threshold, "==": n == self.threshold}[self.op]


def _parse_condition(text: str, selections: dict[str, Callable]) -> Callable[[EventView], bool]:
    tokens = _TOKEN.findall(text)
    if "".join(tokens).replace(" ", "") != re.sub(r"\s+", "", text):
        raise SigmaError(f"cannot parse condition {text!r}")
    pos = 0

    def peek() -> str | None:
        return tokens[pos].lower() if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def names(pattern: str) -> list[Callable]:
        if pattern.lower() == "them":
            found = [f for n, f in selections.items() if not n.startswith("_")]
        else:
            rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
            found = [f for n, f in selections.items() if rx.match(n)]
        if not found:
            raise SigmaError(f"condition refers to {pattern!r}, which matches no selection")
        return found

    def primary() -> Callable:
        t = peek()
        if t is None:
            raise SigmaError(f"condition {text!r} ends early")
        if t == "(":
            take()
            e = expr()
            if peek() != ")":
                raise SigmaError(f"missing ) in {text!r}")
            take()
            return e
        if t == "all" or t.isdigit():
            take()
            if peek() != "of":
                raise SigmaError(f"expected 'of' after {t!r} in {text!r}")
            take()
            group = names(take())
            ir = _irs(group)
            if t == "all":
                return _ir(lambda ev: all(f(ev) for f in group), None if ir is None else {"t": "and", "of": ir})
            k = int(t)
            return _ir(lambda ev: sum(1 for f in group if f(ev)) >= k, None if ir is None else {"t": "atleast", "k": k, "of": ir})
        name = take()
        if name not in selections:
            raise SigmaError(f"condition refers to undefined selection {name!r}")
        return selections[name]

    def unary() -> Callable:
        if peek() == "not":
            take()
            inner = unary()
            ir = getattr(inner, "ir", None)
            return _ir(lambda ev: not inner(ev), None if ir is None else {"t": "not", "x": ir})
        return primary()

    def conj() -> Callable:
        parts = [unary()]
        while peek() == "and":
            take()
            parts.append(unary())
        if len(parts) == 1:
            return parts[0]
        ir = _irs(parts)
        return _ir(lambda ev: all(p(ev) for p in parts), None if ir is None else {"t": "and", "of": ir})

    def expr() -> Callable:
        parts = [conj()]
        while peek() == "or":
            take()
            parts.append(conj())
        if len(parts) == 1:
            return parts[0]
        ir = _irs(parts)
        return _ir(lambda ev: any(p(ev) for p in parts), None if ir is None else {"t": "or", "of": ir})

    out = expr()
    if pos != len(tokens):
        raise SigmaError(f"unexpected {tokens[pos]!r} in condition {text!r}")
    return out


def _seconds(tf: Any) -> float:
    if tf is None:
        return 3600.0
    m = re.fullmatch(r"\s*(\d+)\s*([smhdM])\s*", str(tf))
    if not m:
        raise SigmaError(f"bad timeframe {tf!r}")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400, "M": 2_592_000}[m.group(2)]


# ---------------------------------------------------------------------------
# Anchors: literals a rule cannot match without (the core's Aho-Corasick prefilter)
# ---------------------------------------------------------------------------

def _vm_needles(vm: dict) -> list[str] | None:
    """Lower-case substrings any value this matcher accepts must contain (None: no such set)."""
    t = vm.get("t")
    if t == "str":
        return [vm["needle"].lower()] if vm["needle"] else None
    if t == "numstr":
        return [vm["ref"].lower()]
    if t == "glob":
        lits = [tok[1] for tok in vm["tok"] if tok[0] == "lit"]
        return [max(lits, key=len).lower()] if lits else None
    if t == "py":
        return vm.get("needles")
    if t == "any":
        out: list = []
        for x in vm["of"]:
            n = _vm_needles(x)
            if n is None:
                return None
            out += n
        return out
    return None


def _score(anchors: list) -> tuple:
    """Prefer needles of at least 2 bytes, then longer shortest needles, then fewer of them."""
    shortest = min(len(n.encode()) for _, n in anchors)
    return (shortest >= 2, shortest, -len(anchors))


def anchors(node: dict) -> list | None:
    """[(field ir or None for the keyword text, needle)]: the rule can only match an event in
    which some needle is a substring of the lower-cased field (or text). None: no such set."""
    t = node.get("t")
    if t == "field":
        sets = [_vm_needles(m) for m in node["m"]]
        if node.get("all"):
            best = [s for s in sets if s]
            return [(node["f"], n) for n in max(best, key=lambda s: min(map(len, s)))] if best else None
        if not sets or any(s is None for s in sets):
            return None
        return [(node["f"], n) for s in sets for n in s]
    if t == "kw":
        sets = [_vm_needles(m) for m in node["m"]]
        if not sets or any(s is None for s in sets):
            return None
        return [(None, n) for s in sets for n in s]
    if t == "and":
        cands = [a for a in (anchors(x) for x in node["of"]) if a]
        return max(cands, key=_score) if cands else None
    if t in ("or", "atleast"):
        out: list = []
        for x in node["of"]:
            a = anchors(x)
            if not a:
                return None
            out += a
        return out
    return None


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    tags: list[str]
    techniques: list[str]
    tactics: list[str]
    logsource: dict
    timeframe: float
    aggregation: Aggregation | None
    source: str = ""
    description: str = ""
    _match: Callable[[EventView], bool] = field(default=lambda ev: False, repr=False)
    _categories: set | None = field(default=None, repr=False)
    _guard_ir: dict | None = field(default=None, repr=False)     # the logsource guard, evaluated first
    name: str = ""                                                # Sigma ``name`` (correlations refer to it)
    corr_fields: list = field(default_factory=list)               # values a hit carries for correlations
    _formats: set | None = field(default=None, repr=False)

    @property
    def level_score(self) -> int:
        return LEVELS.get(self.level, 2)

    @property
    def stages(self) -> list[str]:
        """Kill-chain stages this rule's ATT&CK tags imply."""
        out = []
        for t in self.techniques:
            stage = TECHNIQUE_STAGE.get(t) or TECHNIQUE_STAGE.get(t.split(".")[0])
            if stage and stage not in out:
                out.append(stage)
        if not out:
            for tac in self.tactics:
                stage = TACTICS[tac][2]
                if stage not in out:
                    out.append(stage)
        return out

    def applies(self, ev: EventView) -> bool:
        e = ev.event
        if self._categories is not None and e.get("category") not in self._categories:
            return False
        if self._formats is not None and e.get("raw_format") not in self._formats:
            return False
        return True

    def matches(self, ev: EventView) -> bool:
        return self.applies(ev) and self._match(ev)

    def group_key(self, ev: EventView) -> str:
        if self.aggregation is None:
            # plain rules: the entity, so repeated hits from one source collapse into one detection
            return str(ev.get("source.ip") or ev.get("device.hostname") or "")
        if not self.aggregation.group_by:
            return ""
        return "|".join(str(ev.get(g)) for g in self.aggregation.group_by)

    @property
    def ir(self) -> dict | None:
        """The rule for the compiled core (None: Python only)."""
        cond = getattr(self._match, "ir", None)
        if cond is None:
            return None
        if self._guard_ir is not None:
            cond = getattr(self._match, "cond_ir", cond)  # the core evaluates the guard separately
        agg = self.aggregation
        anc = anchors(cond)
        if anc is not None and any(len(n.encode()) < 2 for _, n in anc):
            anc = None                     # one-character needles prefilter nothing
        return {"id": self.id, "cond": cond, "anchors": anc, "guard": self._guard_ir,
                "corr_fields": [field_ir(f) for f in self.corr_fields] or None,
                "categories": sorted(self._categories) if self._categories is not None else None,
                "formats": sorted(self._formats) if self._formats is not None else None,
                "group_by": None if agg is None else [field_ir(g) for g in agg.group_by],
                "agg_field": field_ir(agg.field) if agg is not None and agg.field else None}

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "level": self.level, "techniques": self.techniques,
                "tactics": self.tactics, "stages": self.stages, "aggregation": bool(self.aggregation),
                "source": self.source}


def compile_rule(doc: dict, source: str = "") -> SigmaRule:
    if not isinstance(doc, dict):
        raise SigmaError("a rule must be a mapping")
    if "correlation" in doc:
        raise SigmaError("a correlation document: compile it with compile_correlation")
    det = doc.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        raise SigmaError("detection with a condition is required")
    title = str(doc.get("title") or "untitled")
    selections = {}
    for name, definition in det.items():
        if name in ("condition", "timeframe"):
            continue
        selections[name] = _selection(definition)
    conds = det["condition"] if isinstance(det["condition"], list) else [det["condition"]]
    aggregation = None
    parts = []
    for c in conds:
        c = str(c)
        if "|" in c:
            search, _, agg = c.partition("|")
            m = _AGG.match(agg)
            if not m:
                raise SigmaError(f"unsupported aggregation {agg.strip()!r} (only count() is supported)")
            if aggregation is not None:
                raise SigmaError("only one aggregation per rule is supported")
            group = tuple(g.strip() for g in m.group(2).split(",")) if m.group(2) else ()
            aggregation = Aggregation(m.group(1) or None, group, m.group(3), int(m.group(4)))
            c = search
        if " near " in f" {c.lower()} ":
            raise SigmaError("the near operator is not supported")
        parts.append(_parse_condition(c, selections))
    if len(parts) == 1:
        match = parts[0]
    else:
        ir = _irs(parts)
        match = _ir(lambda ev: any(p(ev) for p in parts), None if ir is None else {"t": "or", "of": ir})
    tags = [str(t).lower() for t in doc.get("tags") or []]
    techniques, tactics = [], []
    for t in tags:
        if not t.startswith("attack."):
            continue
        v = t[len("attack."):]
        if re.fullmatch(r"t\d{4}(?:\.\d{3})?", v):
            techniques.append(v.upper())
        elif v in TACTICS:
            tactics.append(v)
    ls = doc.get("logsource") or {}
    guard = logsource_guard(ls)
    guard_ir = None
    if guard is not None:
        g = _selection(guard)
        inner = match
        guard_ir = g.ir
        match = _ir(lambda ev: g(ev) and inner(ev), {"t": "and", "of": [g.ir, inner.ir]})
        match.cond_ir = inner.ir       # type: ignore[attr-defined]  the condition without the guard
    cats = _CATEGORY_LOGSOURCE.get(str(ls.get("category") or "").lower())
    product = str(ls.get("product") or "").lower()
    if guard is not None and product not in ("ulpf",):
        cats = None                    # the guard identifies the events; ULPF's category is not needed
    if product == "ulpf" and ls.get("category"):
        cats = {str(ls["category"]).lower()}
    rule = SigmaRule(
        id=str(doc.get("id") or title), title=title, level=str(doc.get("level") or "medium").lower(),
        tags=tags, techniques=techniques, tactics=tactics, logsource=dict(ls),
        timeframe=_seconds(det.get("timeframe", doc.get("timeframe"))), aggregation=aggregation,
        source=source, description=str(doc.get("description") or ""), _match=match,
        _categories=cats, _formats=_PRODUCT_FORMATS.get(product), _guard_ir=guard_ir,
        name=str(doc.get("name") or ""))
    if rule.level not in LEVELS:
        raise SigmaError(f"unknown level {rule.level!r}")
    return rule


_CORR_TYPES = ("event_count", "value_count", "temporal", "temporal_ordered")
_CORR_OPS = {"gt": lambda n, x: n > x, "gte": lambda n, x: n >= x, "lt": lambda n, x: n < x,
             "lte": lambda n, x: n <= x, "eq": lambda n, x: n == x, "neq": lambda n, x: n != x}


@dataclass
class CorrelationRule:
    """A Sigma correlation (``correlation:`` document) over the hits of other rules."""
    id: str
    title: str
    level: str
    tags: list[str]
    techniques: list[str]
    tactics: list[str]
    type: str
    refs: list[str]                 # referenced rule names / ids, in order
    group_by: list[str]
    aliases: dict                   # alias -> {rule name/id: field}
    timespan: float
    condition: dict                 # op -> number (value_count: also "field")
    generate: bool
    source: str = ""
    description: str = ""
    rules: list = field(default_factory=list)    # resolved SigmaRule objects (same order as refs)
    aggregation = None              # detections from correlations are not count-aggregations

    @property
    def level_score(self) -> int:
        return LEVELS.get(self.level, 2)

    @property
    def stages(self) -> list[str]:
        return SigmaRule.stages.fget(self)       # type: ignore[attr-defined]

    def field_for(self, rule, name: str) -> str:
        """The field of ``rule`` a group-by name (or alias) means."""
        a = self.aliases.get(name)
        if a:
            for key in (rule.name, rule.id):
                if key and key in a:
                    return str(a[key])
        return name

    def holds(self, n: float) -> bool:
        return all(_CORR_OPS[op](n, float(v)) for op, v in self.condition.items() if op in _CORR_OPS)

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "level": self.level, "techniques": self.techniques,
                "tactics": self.tactics, "stages": self.stages, "correlation": self.type,
                "rules": self.refs, "source": self.source}


def compile_correlation(doc: dict, source: str = "") -> CorrelationRule:
    c = doc.get("correlation")
    if not isinstance(c, dict):
        raise SigmaError("correlation must be a mapping")
    typ = str(c.get("type") or "")
    if typ not in _CORR_TYPES:
        raise SigmaError(f"unknown correlation type {typ!r} ({', '.join(_CORR_TYPES)})")
    refs = c.get("rules")
    refs = [refs] if isinstance(refs, str) else refs
    if not refs or not all(isinstance(r, str) for r in refs):
        raise SigmaError("correlation.rules must name one or more rules")
    group = c.get("group-by") or []
    group = [group] if isinstance(group, str) else [str(g) for g in group]
    cond = c.get("condition") or {}
    if typ in ("event_count", "value_count"):
        if not isinstance(cond, dict) or not any(k in _CORR_OPS for k in cond):
            raise SigmaError("correlation.condition needs gt / gte / lt / lte / eq / neq")
        for k in cond:
            if k not in _CORR_OPS and k != "field":
                raise SigmaError(f"unknown correlation condition {k!r}")
        if typ == "value_count" and not cond.get("field"):
            raise SigmaError("value_count needs condition.field")
    elif cond and not isinstance(cond, dict):
        raise SigmaError("correlation.condition must be a mapping")
    title = str(doc.get("title") or "untitled correlation")
    tags = [str(t).lower() for t in doc.get("tags") or []]
    techniques = [t[7:].upper() for t in tags if re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", t)]
    tactics = [t[7:] for t in tags if t.startswith("attack.") and t[7:] in TACTICS]
    level = str(doc.get("level") or "medium").lower()
    if level not in LEVELS:
        raise SigmaError(f"unknown level {level!r}")
    ts = c.get("timespan") or c.get("timeframe")
    if ts is None:
        raise SigmaError("correlation.timespan is required")
    return CorrelationRule(
        id=str(doc.get("id") or title), title=title, level=level, tags=tags, techniques=techniques, tactics=tactics,
        type=typ, refs=list(refs), group_by=group, aliases=dict(c.get("aliases") or {}), timespan=_seconds(ts),
        condition={k: v for k, v in (cond or {}).items()}, generate=bool(c.get("generate", doc.get("generate", False))),
        source=source, description=str(doc.get("description") or ""))


def link_correlations(rules: list[SigmaRule], correlations: list[CorrelationRule]) -> list[str]:
    """Resolve each correlation's rule references; give the referenced rules the fields their
    hits must carry. Returns errors (a correlation with a dangling reference is dropped)."""
    by_ref: dict[str, SigmaRule] = {}
    for r in rules:
        by_ref[r.id] = r
        if r.name:
            by_ref[r.name] = r
    errors, keep = [], []
    for c in correlations:
        missing = [x for x in c.refs if x not in by_ref]
        if missing:
            corr_ids = {x.id for x in correlations} | {x.title for x in correlations}
            why = "correlations of correlations are not supported" if any(m in corr_ids for m in missing) \
                else f"refers to unknown rule(s) {', '.join(missing)}"
            errors.append(f"{c.source}: {c.title}: {why}")
            continue
        c.rules = [by_ref[x] for x in c.refs]
        for r in c.rules:
            wanted = [c.field_for(r, g) for g in c.group_by]
            if c.type == "value_count":
                wanted.append(str(c.condition["field"]))
            for f in wanted:
                if f not in r.corr_fields:
                    r.corr_fields.append(f)
        keep.append(c)
    correlations[:] = keep
    return errors


def load_rules(paths: Iterable[str] = (), builtin: bool = True, with_correlations: bool = False):
    """Compile every rule in the given files/directories. Returns (rules, errors), or
    (rules, correlations, errors) with ``with_correlations``."""
    import yaml
    files: list[str] = []
    if builtin:
        files += sorted(glob.glob(os.path.join(BUILTIN_DIR, "*.yml")))
    for p in paths:
        if os.path.isdir(p):
            files += sorted(glob.glob(os.path.join(p, "**", "*.yml"), recursive=True) +
                            glob.glob(os.path.join(p, "**", "*.yaml"), recursive=True))
        else:
            files.append(p)
    rules: list[SigmaRule] = []
    correlations: list[CorrelationRule] = []
    errors: list[str] = []
    seen: set[str] = set()
    for f in files:
        try:
            path = f
            if os.name == "nt" and len(os.path.abspath(f)) >= 248:
                path = "\\\\?\\" + os.path.abspath(f)          # Windows long-path prefix
            with open(path, "r", encoding="utf-8") as fh:
                docs = list(yaml.safe_load_all(fh))
        except (OSError, yaml.YAMLError) as e:
            errors.append(f"{f}: {e}")
            continue
        base: dict = {}
        for i, doc in enumerate(docs):
            if doc is None:
                continue
            # rule collections: action: global / reset / repeat
            action = doc.get("action") if isinstance(doc, dict) else None
            if action == "global":
                base = {k: v for k, v in doc.items() if k != "action"}
                continue
            if action == "reset":
                base = {}
                continue
            merged = {**base, **{k: v for k, v in doc.items() if k != "action"}} if isinstance(doc, dict) else doc
            if isinstance(merged, dict) and isinstance(base.get("detection"), dict) and isinstance(doc.get("detection"), dict):
                merged["detection"] = {**base["detection"], **doc["detection"]}
            if isinstance(merged, dict) and "correlation" in merged:
                try:
                    correlations.append(compile_correlation(merged, f"{os.path.basename(f)}#{i}"))
                except SigmaError as e:
                    errors.append(f"{f}: {merged.get('title', f'document {i}')}: {e}")
                continue
            try:
                rule = compile_rule(merged, f"{os.path.basename(f)}#{i}")
            except SigmaError as e:
                title = merged.get("title", f"document {i}") if isinstance(merged, dict) else f"document {i}"
                errors.append(f"{f}: {title}: {e}")
                continue
            if rule.id in seen:
                errors.append(f"{f}: duplicate rule id {rule.id}")
                continue
            seen.add(rule.id)
            rules.append(rule)
    errors += link_correlations(rules, correlations)
    if with_correlations:
        return rules, correlations, errors
    return rules, errors


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

@dataclass
class Detection:
    rule: SigmaRule
    key: str
    count: int
    event_id: str | None
    timestamp: datetime
    entities: list = field(default_factory=list)      # (type, value) of the event, for risk scoring

    def to_dict(self) -> dict:
        return {"rule_id": self.rule.id, "title": self.rule.title, "level": self.rule.level,
                "techniques": self.rule.techniques, "tactics": self.rule.tactics, "key": self.key,
                "count": self.count, "event_id": self.event_id, "timestamp": self.timestamp.isoformat()}


class SigmaEngine:
    """Compiled rules plus the sliding windows of aggregation rules.

    ``match(event)`` is stateless: [(rule_id, group_key)] for every rule whose
    condition the event satisfies (workers send these with the event's
    projection). ``observe(hits, ts, event_id)`` is stateful: it turns hits into
    detections — immediately for plain rules, when the count crosses the
    threshold inside the timeframe for aggregation rules.
    """

    def __init__(self, rules: list[SigmaRule], max_keys_per_rule: int = 10_000, dedupe_seconds: float = 60.0,
                 correlations: list[CorrelationRule] | None = None):
        self.rules = rules
        self.correlations = list(correlations or [])
        self._corr_of: dict[str, list[CorrelationRule]] = {}
        for c in self.correlations:
            for r in c.rules:
                self._corr_of.setdefault(r.id, []).append(c)
        self._suppressed = {r.id for c in self.correlations if not c.generate for r in c.rules}
        self._corr_windows: dict[str, OrderedDict] = {c.id: OrderedDict() for c in self.correlations}
        self.dedupe_seconds = float(dedupe_seconds)
        self.by_id = {r.id: r for r in rules}
        self.max_keys = max_keys_per_rule
        self._windows: dict[str, OrderedDict[str, deque]] = {r.id: OrderedDict() for r in rules if r.aggregation}
        self._fired: dict[tuple[str, str], datetime] = {}
        self.matches = 0
        self.detections = 0

    @classmethod
    def load(cls, paths: Iterable[str] = (), builtin: bool = True) -> "SigmaEngine":
        rules, corrs, errors = load_rules(paths, builtin, with_correlations=True)
        for e in errors:
            logger.warning(f"sigma: {e}")
        engine = cls(rules, correlations=corrs)
        engine.errors = errors
        return engine

    errors: list[str] = []

    def match(self, event: dict) -> list[list]:
        ev = EventView(event)
        hits = []
        for r in self.rules:
            try:
                if r.matches(ev):
                    hit = [r.id, r.group_key(ev), ev.get(r.aggregation.field)
                           if r.aggregation and r.aggregation.field else None]
                    if r.corr_fields:
                        hit.append([_jsonable(ev.get(f)) for f in r.corr_fields])
                    hits.append(hit)
            except Exception:
                logger.debug(f"sigma rule {r.id} failed on an event", exc_info=True)
        self.matches += len(hits)
        return hits

    def observe(self, hits: list, ts: datetime, event_id: str | None = None) -> list[Detection]:
        out = []
        for hit in hits or []:
            rule_id, key = hit[0], hit[1] if len(hit) > 1 else ""
            value = hit[2] if len(hit) > 2 else None
            rule = self.by_id.get(rule_id)
            if rule is None:
                continue
            if rule.id in self._corr_of:
                out += self._correlate(rule, hit[3] if len(hit) > 3 else [], ts, event_id)
                if rule.id in self._suppressed:
                    continue                # referenced by a correlation with generate: false
            if rule.aggregation is None:
                last = self._fired.get((rule.id, key))
                if last is None or (ts - last).total_seconds() > self.dedupe_seconds or ts < last:
                    self._fired[(rule.id, key)] = ts
                    out.append(Detection(rule, key, 1, event_id, ts))
                continue
            wins = self._windows[rule.id]
            dq = wins.get(key)
            if dq is None:
                dq = wins[key] = deque()
                if len(wins) > self.max_keys:
                    wins.popitem(last=False)
            else:
                wins.move_to_end(key)
            dq.append((ts, value))
            while dq and (ts - dq[0][0]).total_seconds() > rule.timeframe:
                dq.popleft()
            agg = rule.aggregation
            n = len({v for _, v in dq}) if agg.field else len(dq)
            if agg.holds(n):
                last = self._fired.get((rule.id, key))
                # once per window per group: a burst is one detection, not one per event
                if last is None or (ts - last).total_seconds() > rule.timeframe:
                    self._fired[(rule.id, key)] = ts
                    if len(self._fired) > 100_000:
                        self._fired.clear()
                    out.append(Detection(rule, key, n, event_id, ts))
        self.detections += len(out)
        return out

    def _correlate(self, rule: SigmaRule, values: list, ts: datetime, event_id) -> list[Detection]:
        out = []
        vals = dict(zip(rule.corr_fields, values))
        for c in self._corr_of[rule.id]:
            key = "|".join("None" if vals.get(c.field_for(rule, g)) is None else str(vals.get(c.field_for(rule, g)))
                           for g in c.group_by)
            wins = self._corr_windows[c.id]
            dq = wins.get(key)
            if dq is None:
                dq = wins[key] = deque()
                if len(wins) > self.max_keys:
                    wins.popitem(last=False)
            else:
                wins.move_to_end(key)
            value = vals.get(str(c.condition.get("field"))) if c.type == "value_count" else None
            dq.append((ts, rule.id, value))
            while dq and (ts - dq[0][0]).total_seconds() > c.timespan:
                dq.popleft()
            if len(dq) > 100_000:
                dq.popleft()
            if c.type == "event_count":
                n, fire = len(dq), c.holds(len(dq))
            elif c.type == "value_count":
                n = len({str(v) for _, _, v in dq if v is not None})
                fire = c.holds(n)
            elif c.type == "temporal":
                n = len({rid for _, rid, _ in dq})
                fire = n == len({r.id for r in c.rules})
            else:                                       # temporal_ordered: the rules in order
                want, k = [r.id for r in c.rules], 0
                for _, rid, _ in dq:
                    if k < len(want) and rid == want[k]:
                        k += 1
                n, fire = k, k == len(want)
            if not fire:
                continue
            last = self._fired.get((c.id, key))
            if last is None or (ts - last).total_seconds() > c.timespan or ts < last:
                self._fired[(c.id, key)] = ts
                out.append(Detection(c, key, n, event_id, ts))
        return out

    def detect(self, event: dict, ts: datetime | None = None) -> list[Detection]:
        """match + observe for a full event (batch correlation, API)."""
        from ulpf.intelligence.correlation import parse_event_time
        return self.observe(self.match(event), ts or parse_event_time(event), event.get("event_id"))

    def ir(self) -> dict | None:
        """Every rule for the compiled core, in order; None if any rule needs Python."""
        out = [r.ir for r in self.rules]
        if any(x is None for x in out):
            return None
        return {"rules": out, "entity": [field_ir("source.ip"), field_ir("device.hostname")]}

    def stats(self) -> dict:
        return {"rules": len(self.rules), "aggregation_rules": len(self._windows),
                "correlation_rules": len(self.correlations), "matches": self.matches,
                "detections": self.detections, "load_errors": len(self.errors)}


def _jsonable(v):
    """A hit value as JSON carries it (workers send hits to the host)."""
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    return str(v)


_builtin: SigmaEngine | None = None


def builtin_engine(dedupe_seconds: float = 60.0) -> SigmaEngine:
    """A fresh engine with the bundled rule pack (rules are compiled once per process)."""
    global _builtin
    if _builtin is None:
        _builtin = SigmaEngine.load()
    return SigmaEngine(_builtin.rules, dedupe_seconds=dedupe_seconds)


def engine_from_config(cfg: dict) -> SigmaEngine | None:
    """The engine ``analytics.sigma`` describes (None when disabled)."""
    s = ((cfg.get("analytics") or {}).get("sigma") or {})
    if not s.get("enabled", True):
        return None
    if s.get("builtin", True) and not s.get("rules"):
        return builtin_engine(s.get("dedupe_seconds", 60))
    rules, corrs, errors = load_rules(s.get("rules") or [], builtin=s.get("builtin", True), with_correlations=True)
    for e in errors:
        logger.warning(f"sigma: {e}")
    eng = SigmaEngine(rules, dedupe_seconds=s.get("dedupe_seconds", 60), correlations=corrs)
    eng.errors = errors
    return eng
