"""Syslog Parser — RFC 3164 / RFC 5424."""
from __future__ import annotations
import re
from typing import Optional
from ulpf.engine.normalizer import build_normalized_event
from ulpf.parsers.base import BaseParser

FACILITY = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
    6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

_RFC3164 = re.compile(
    r"^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+"
    r"(?:(\S+?)(?:\[(\d+)\])?:\s*)?(.*)", re.DOTALL)

# STRUCTURED-DATA is "-" or one or more [id param="value"...] elements (']' may be escaped)
_RFC5424 = re.compile(
    r"^<(\d{1,3})>(\d{1,2})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*"
    r"(-|(?:\[(?:[^\]\\]|\\.)*\])+)?\s*(.*)", re.DOTALL)

_PLAIN = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+"
    r"(?:(\S+?)(?:\[(\d+)\])?:\s*)?(.*)", re.DOTALL)

_IP = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_PORT = re.compile(r"(?:port|pt)\s*[=:]\s*(\d+)", re.I)
_CISCO_PAIR = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\((\d+)\)")
# OpenSSH: "Failed password for [invalid user ]root from 203.0.113.9 port 51234 ssh2"
_SSH = re.compile(r"\bfor (?:invalid user )?(\S+) from ([0-9A-Fa-f.:]+) port (\d+)")
_SD_PARAM = re.compile(r'([\w.-]+)=(?:"((?:[^"\\]|\\.)*)"|(\S+))')
# Cisco IOS/ASA mnemonic: %FACILITY-SEVERITY-MNEMONIC
_CISCO_MNEMONIC = re.compile(r"%[A-Z0-9_]+-([0-7])-[A-Z0-9_]+")


class SyslogParser(BaseParser):
    parser_id = "syslog"
    parser_name = "Syslog Parser"
    supported_formats = ["syslog", "rfc3164", "rfc5424"]
    description = "RFC 3164 / RFC 5424 syslog parser"
    version = "1.1.0"

    def can_parse(self, raw_line: str) -> bool:
        s = raw_line.strip()
        return bool(s.startswith("<") and s[1:4].replace(">", "").isdigit()) or bool(_PLAIN.match(s))

    def parse(self, raw_line: str, **kwargs) -> Optional[dict]:
        s = raw_line.strip()
        m = _RFC5424.match(s)
        if m: return self._rfc5424(raw_line, m, **kwargs)
        m = _RFC3164.match(s)
        if m: return self._rfc3164(raw_line, m, **kwargs)
        m = _PLAIN.match(s)
        if m: return self._plain(raw_line, m, **kwargs)
        return None

    def _rfc3164(self, raw, m, **kwargs):
        pri, ts, host, app, pid, msg = int(m[1]), m[2], m[3], m[4] or "", m[5] or "", m[6] or ""
        fac, sev = pri >> 3, pri & 7
        p = self._build(pri, fac, sev, ts, host, app, pid, msg)
        return build_normalized_event(**kwargs,
            raw_line=raw, raw_format="syslog", parsed_fields=p,
            parser_id=self.parser_id, parser_name=self.parser_name, parser_version=self.version,
            timestamp_str=ts, severity_raw=sev, severity_source="syslog",
            category=_cat(app, msg), event_type="syslog_rfc3164",
            device_vendor="Generic", device_product=app or "syslog", message=msg)

    def _rfc5424(self, raw, m, **kwargs):
        pri, ver, ts, host = int(m[1]), m[2], m[3], m[4]
        app, procid, msgid, sd, msg = m[5], m[6], m[7], m[8] or "", m[9] or ""
        if sd == "-":
            sd = ""
        fac, sev = pri >> 3, pri & 7
        p = self._build(pri, fac, sev, ts, host, app, procid, msg, sd)
        p["syslog_version"] = ver
        p["msgid"] = msgid
        if sd:
            for m_sd in _SD_PARAM.finditer(sd):
                v = m_sd.group(2) if m_sd.group(2) is not None else m_sd.group(3)
                p[m_sd.group(1).lower()] = v.replace('\\"', '"').replace("\\]", "]")
        return build_normalized_event(**kwargs,
            raw_line=raw, raw_format="syslog", parsed_fields=p,
            parser_id=self.parser_id, parser_name=self.parser_name, parser_version=self.version,
            timestamp_str=ts if ts != "-" else None,
            severity_raw=sev, severity_source="syslog",
            category=_cat(app, msg), event_type="syslog_rfc5424",
            device_vendor="Generic", device_product=app if app != "-" else "syslog", message=msg)

    def _plain(self, raw, m, **kwargs):
        ts, host, app, pid, msg = m[1], m[2], m[3] or "", m[4] or "", m[5] or ""
        # Without a PRI header, a Cisco mnemonic is the only severity signal
        mn = _CISCO_MNEMONIC.search(f"{app} {msg}")
        sev = int(mn.group(1)) if mn else 6
        p = self._build(0, 0, sev, ts, host, app, pid, msg)
        return build_normalized_event(**kwargs,
            raw_line=raw, raw_format="syslog", parsed_fields=p,
            parser_id=self.parser_id, parser_name=self.parser_name, parser_version=self.version,
            timestamp_str=ts, severity_raw=sev, severity_source="syslog",
            category=_cat(app, msg), event_type="syslog_plain",
            device_vendor="Generic", device_product=app or "syslog", message=msg)

    def _build(self, pri, fac, sev, ts, host, app, pid, msg, sd=""):
        p = {"pri": str(pri), "facility": str(fac), "facility_name": FACILITY.get(fac, "unknown"),
             "syslog_severity": str(sev), "timestamp": ts, "hostname": host,
             "app_name": app, "pid": pid, "message": msg, "devname": host}
        search_text = f"{sd} {msg}" if sd else msg

        # 0. OpenSSH authentication messages name user, address and port
        if " from " in msg and " port " in msg:
            ssh = _SSH.search(msg)
            if ssh:
                p["user"], p["src_ip"], p["src_port"] = ssh.group(1), ssh.group(2), ssh.group(3)

        # 1. Cisco / firewall IP(PORT) -> IP(PORT) pattern
        cisco_pairs = _CISCO_PAIR.findall(search_text)
        if len(cisco_pairs) >= 1:
            p["src_ip"] = cisco_pairs[0][0]
            p["src_port"] = cisco_pairs[0][1]
        if len(cisco_pairs) >= 2:
            p["dst_ip"] = cisco_pairs[1][0]
            p["dst_port"] = cisco_pairs[1][1]

        # 2. General IP fallback if not extracted by Cisco pattern
        if "src_ip" not in p or "dst_ip" not in p:
            ips = _IP.findall(search_text)
            if ips and "src_ip" not in p:
                p["src_ip"] = ips[0]
            if len(ips) >= 2 and "dst_ip" not in p:
                p["dst_ip"] = ips[1]

        # 3. General Port fallback
        if "src_port" not in p or "dst_port" not in p:
            ports = _PORT.findall(search_text)
            if ports and "src_port" not in p:
                p["src_port"] = ports[0]
            if len(ports) >= 2 and "dst_port" not in p:
                p["dst_port"] = ports[1]

        # Infer security action from syslog message content
        ml = msg.lower()
        if any(w in ml for w in ("failed password", "authentication failure", "invalid user", "fail")):
            p["action"] = "failed"
        elif any(w in ml for w in ("denied", "deny")):
            p["action"] = "denied"
        elif any(w in ml for w in ("drop", "dropped")):
            p["action"] = "dropped"
        elif any(w in ml for w in ("blocked", "block")):
            p["action"] = "blocked"
        elif any(w in ml for w in ("accepted", "permit", "success", "established", "allowed")):
            p["action"] = "allowed"

        return p


def _cat(app: str, msg: str) -> str:
    c = f"{app} {msg}".lower()
    if "%sec" in c or "%fw" in c or "iptables" in c or "firewall" in c or "acl" in c: return "firewall"
    if "%ids" in c or "intrusion" in c or "attack" in c or "exploit" in c: return "ids_ips"
    if "sshd" in c or "login" in c or "auth" in c or "pam" in c: return "authentication"
    if "%lineproto" in c or "%link" in c or "%ospf" in c or "%bgp" in c: return "network"
    if "dns" in c or "named" in c or "bind" in c: return "dns"
    if "%sys" in c or "kernel" in c or "systemd" in c: return "system"
    return "network"
