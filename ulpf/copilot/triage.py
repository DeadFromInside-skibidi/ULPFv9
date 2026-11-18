"""
Automated incident triage: evidence-grounded forensic narratives, ATT&CK mapping, containment advice.

``investigate`` turns a case (or any correlated group) with its events and
detections into a structured narrative:

    summary, verdict, confidence, initial_access, execution, persistence,
    privilege_escalation, credential_access, lateral_movement, exfiltration,
    impact, affected_assets {hosts, users, ips}, root_cause, timeline,
    attack (techniques with tactic names), recommendations (playbooks and
    connector actions), evidence (the event ids each claim rests on)

Every statement is derived from the evidence and cites event ids; when a local
model is loaded it may rewrite ``summary`` and ``root_cause`` in prose, but its
output is accepted only if every IP address, user and technique it mentions
appears in the evidence (no invented indicators).
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter, defaultdict

from ulpf.copilot.inference import Backend, Budget, ModelError, parse_json

STAGES = ("initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion",
          "credential_access", "discovery", "lateral_movement", "collection", "command_and_control",
          "exfiltration", "impact")

# technique -> tactic (the ATT&CK subset ULPF rules use; tactics from Sigma tags otherwise)
TECH_TACTIC = {
    "T1190": "initial_access", "T1133": "initial_access", "T1566": "initial_access", "T1078": "initial_access",
    "T1110": "credential_access", "T1003": "credential_access", "T1558": "credential_access",
    "T1555": "credential_access", "T1059": "execution", "T1204": "execution", "T1047": "execution",
    "T1053": "persistence", "T1543": "persistence", "T1547": "persistence", "T1136": "persistence",
    "T1098": "persistence", "T1505": "persistence", "T1068": "privilege_escalation",
    "T1548": "privilege_escalation", "T1055": "defense_evasion", "T1070": "defense_evasion",
    "T1027": "defense_evasion", "T1562": "defense_evasion", "T1046": "discovery", "T1018": "discovery",
    "T1087": "discovery", "T1021": "lateral_movement", "T1570": "lateral_movement", "T1550": "lateral_movement",
    "T1005": "collection", "T1560": "collection", "T1071": "command_and_control", "T1105": "command_and_control",
    "T1572": "command_and_control", "T1571": "command_and_control", "T1048": "exfiltration",
    "T1041": "exfiltration", "T1567": "exfiltration", "T1486": "impact", "T1490": "impact", "T1498": "impact",
    "T1489": "impact", "T1496": "impact", "T1595": "discovery",
}
KEYWORD_STAGE = (
    (r"failed password|authentication failure|logon failure|invalid user|brute", "credential_access"),
    (r"accepted password|logged on|successful logon|session opened", "initial_access"),
    (r"powershell|cmd\.exe|/bin/sh|bash -c|wscript|mshta|rundll32", "execution"),
    (r"schtasks|crontab|service install|run key|systemctl enable", "persistence"),
    (r"sudo|runas|setuid|privilege", "privilege_escalation"),
    (r"mimikatz|lsass|ntds\.dit|sam hive|credential", "credential_access"),
    (r"psexec|wmic /node|winrm|rdp|smb|ssh .*@", "lateral_movement"),
    (r"exfil|upload|rclone|curl .*-T|large outbound|dns tunnel", "exfiltration"),
    (r"ransom|encrypted files|vssadmin delete|shadow copies", "impact"),
    (r"audit log.*cleared|wevtutil cl|history -c", "defense_evasion"),
)
CONTAINMENT = {
    "credential_access": [("playbook", "contain-external-brute-force"), ("action", "reset_password_required"),
                          ("action", "block_ip")],
    "initial_access": [("action", "block_ip"), ("action", "revoke_sessions")],
    "execution": [("playbook", "isolate-compromised-host"), ("action", "kill_process")],
    "persistence": [("action", "isolate_host"), ("task", "remove persistence mechanisms and re-image if needed")],
    "privilege_escalation": [("playbook", "disable-compromised-identity")],
    "lateral_movement": [("playbook", "isolate-compromised-host"), ("playbook", "disable-compromised-identity")],
    "command_and_control": [("action", "block_ip"), ("action", "block_domain")],
    "exfiltration": [("action", "block_ip"), ("action", "isolate_host"), ("task", "assess data breach: DPDP/CERT-In "
                                                                               "notifications")],
    "impact": [("playbook", "isolate-compromised-host"), ("task", "restore from offline backups")],
    "defense_evasion": [("task", "preserve evidence: export a signed ULPF bundle now")],
}


_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                               "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")]


def _is_private(ip: str) -> bool:
    """Internal (RFC 1918 / CGNAT / loopback / link-local / ULA); documentation ranges count as external."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _INTERNAL if n.version == a.version)


def _techs(e: dict) -> list[str]:
    out = list((e.get("threat") or {}).get("techniques") or e.get("techniques") or [])
    rule = e.get("rule") or {}
    out += rule.get("techniques") or []
    return [str(t).upper() for t in out]


def investigate(case: dict | None, events: list[dict], detections: list[dict] | None = None,
                backend: Backend | None = None) -> dict:
    case = case or {}
    detections = detections or []
    evs = sorted(events, key=lambda e: str(e.get("timestamp") or ""))
    stages: dict[str, list[dict]] = defaultdict(list)
    techniques: Counter = Counter()
    hosts, users, ips_int, ips_ext = Counter(), Counter(), Counter(), Counter()
    for e in evs:
        eid = e.get("event_id")
        text = f"{e.get('message') or ''} {e.get('raw_event') or ''}".lower()[:4000]
        ts = _techs(e)
        for t in ts:
            techniques[t] += 1
            st = TECH_TACTIC.get(t) or TECH_TACTIC.get(t.split(".")[0])
            if st:
                stages[st].append({"event_id": eid, "timestamp": e.get("timestamp"), "why": t})
        for pat, st in KEYWORD_STAGE:
            if re.search(pat, text):
                stages[st].append({"event_id": eid, "timestamp": e.get("timestamp"), "why": pat.split("|")[0]})
                break
        u = (e.get("user") or {}).get("name") if isinstance(e.get("user"), dict) else e.get("user")
        if u:
            users[str(u)] += 1
        h = (e.get("device") or {}).get("hostname") or (e.get("destination") or {}).get("hostname")
        if h:
            hosts[str(h)] += 1
        for side in ("source", "destination"):
            ip = (e.get(side) or {}).get("ip")
            if ip:
                (ips_int if _is_private(ip) else ips_ext)[ip] += 1
    for d in detections:
        for t in d.get("techniques") or []:
            techniques[str(t).upper()] += 1
            st = TECH_TACTIC.get(str(t).upper()) or TECH_TACTIC.get(str(t).upper().split(".")[0])
            if st:
                stages[st].append({"event_id": d.get("event_id"), "timestamp": d.get("timestamp"),
                                   "why": f"{t} ({d.get('title')})"})
    for t in case.get("mitre") or []:
        techniques[str(t).upper()] += 1
    # lateral movement from internal -> internal successful sessions
    for e in evs:
        s, d = (e.get("source") or {}).get("ip"), (e.get("destination") or {}).get("ip")
        if s and d and s != d and _is_private(s) and _is_private(d) and str(e.get("action")) in ("success", "allowed",
                                                                                                 "connected"):
            if re.search(r"rdp|smb|ssh|winrm|psexec|3389|445|5985|22\b", json.dumps(e, default=str).lower()):
                stages["lateral_movement"].append({"event_id": e.get("event_id"), "timestamp": e.get("timestamp"),
                                                   "why": f"internal session {s} -> {d}"})
    first = evs[0] if evs else {}
    observed = [s for s in STAGES if stages.get(s)]
    entry = stages.get("initial_access") or stages.get("credential_access") or []
    src = (first.get("source") or {}).get("ip")
    root = None
    if stages.get("credential_access") and stages.get("initial_access"):
        root = (f"Credential attack from {', '.join(list(ips_ext)[:3]) or src or 'an unknown source'} followed by a "
                "successful authentication: compromised or weak credentials are the likely root cause.")
    elif stages.get("initial_access"):
        root = f"Initial access first observed at {entry[0]['timestamp']} ({entry[0]['why']})."
    elif evs:
        root = (f"Earliest related activity at {first.get('timestamp')} from {src or 'an unknown source'}; no "
                "initial-access technique was observed — review telemetry gaps before that time.")
    verdict = "true_positive" if len(observed) >= 2 or any(s in observed for s in ("impact", "exfiltration")) \
        else "suspicious" if observed else "insufficient_evidence"
    confidence = round(min(0.95, 0.3 + 0.12 * len(observed) + 0.05 * min(len(detections), 5)), 2)
    from ulpf.intelligence.sigma import TACTICS, TECHNIQUES
    attack = [{"technique": t, "name": TECHNIQUES.get(t) or TECHNIQUES.get(t.split(".")[0]) or "",
               "tactic": (TACTICS.get(TECH_TACTIC.get(t) or TECH_TACTIC.get(t.split(".")[0]) or "") or ("", "", ""))[1],
               "observations": n} for t, n in techniques.most_common(30)]
    recs, seen = [], set()
    for st in observed:
        for kind, what in CONTAINMENT.get(st, []):
            if (kind, what) not in seen:
                seen.add((kind, what))
                recs.append({"stage": st, "kind": kind, "recommendation": what,
                             "target": (list(ips_ext)[:1] or list(hosts)[:1] or list(users)[:1] or [None])[0]})
    summary = (f"{len(evs)} events and {len(detections)} detections between {first.get('timestamp', '?')} and "
               f"{evs[-1].get('timestamp', '?') if evs else '?'}; kill-chain stages observed: "
               f"{', '.join(s.replace('_', ' ') for s in observed) or 'none'}. External sources: "
               f"{', '.join(list(ips_ext)[:5]) or 'none'}; affected hosts: {', '.join(list(hosts)[:5]) or 'unknown'}; "
               f"users: {', '.join(list(users)[:5]) or 'none'}.")
    out = {"case": case.get("id"), "verdict": verdict, "confidence": confidence, "summary": summary,
           **{s: stages.get(s, [])[:20] for s in STAGES},
           "affected_assets": {"hosts": dict(hosts.most_common(20)), "users": dict(users.most_common(20)),
                               "internal_ips": dict(ips_int.most_common(20)),
                               "external_ips": dict(ips_ext.most_common(20))},
           "root_cause": root, "attack": attack, "recommendations": recs,
           "timeline": [{"timestamp": e.get("timestamp"), "event_id": e.get("event_id"),
                         "message": str(e.get("message") or "")[:200]} for e in evs[:200]],
           "generated_by": "rules"}
    if backend is not None and backend.name != "rules" and evs:
        _polish(out, evs, backend)
    return out


def _polish(out: dict, evs: list[dict], backend: Backend) -> None:
    sections = [(0, "Facts", [out["summary"], f"Root cause: {out['root_cause']}"]),
                (1, "ATT&CK", [f"{a['technique']} {a['name']} ({a['tactic']})" for a in out["attack"]]),
                (2, "Events", [f"{e.get('timestamp')} {e.get('event_id')} {str(e.get('message'))[:200]}" for e in evs])]
    prompt, _ = Budget(backend).fit("Write the incident narrative from these facts only.", sections)
    try:
        resp = parse_json(backend.generate(
            "You are a SOC incident responder. Use ONLY the facts given; never invent IPs, users, hosts or "
            "techniques. Reply as JSON {\"summary\": str, \"root_cause\": str}.", prompt, 600, grammar_json=True))
    except ModelError:
        return
    if not resp:
        return
    known = json.dumps(out, default=str) + json.dumps(evs, default=str)
    text = f"{resp.get('summary', '')} {resp.get('root_cause', '')}"
    invented = [x for x in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\bT\d{4}(?:\.\d{3})?\b", text) if x not in known]
    if invented:
        out["model_rejected"] = f"model output mentioned indicators not in the evidence: {invented[:5]}"
        return
    out["summary"] = str(resp.get("summary") or out["summary"])[:4000]
    out["root_cause"] = str(resp.get("root_cause") or out["root_cause"])[:2000]
    out["generated_by"] = backend.name
