"""
CERT-In Directions under section 70B(6) of the IT Act, 2000 (28 April 2022).

* **Incident reporting within 6 hours** of noticing, for the 20 incident types of
  Annexure I. ``incident_report`` fills the CERT-In incident reporting form
  fields from a case / correlated incident (organisation, contact, times of
  occurrence and detection, type, affected systems, description, symptoms,
  actions taken) and computes the 6-hour deadline.
* **Clock synchronisation** (Direction (i)) to the NTP servers of the National
  Informatics Centre (NIC) or the National Physical Laboratory (NPL), or to
  servers traceable to them: ``ntp_check`` queries them with SNTP (RFC 4330) and
  reports offset, stratum and reference id.
* **Logs for a rolling 180 days within Indian jurisdiction** (Direction (iv)):
  ``retention_audit`` checks the journal retention setting, the age of the
  oldest raw journal segment and stored partition, and the data residency
  attestation of the deployment.

The form fields and lists follow the published Directions and CERT-In's incident
reporting form; review them with counsel before filing (see docs/DEFERRED_WORK.md).
"""
from __future__ import annotations

import os
import socket
import struct
import time

CERT_IN_TYPES = [
    "Targeted scanning/probing of critical networks/systems",
    "Compromise of critical systems/information",
    "Unauthorised access of IT systems/data",
    "Defacement of website or intrusion into a website and unauthorised changes such as inserting malicious "
    "code, links to external websites etc.",
    "Malicious code attacks such as spreading of virus/worm/Trojan/Bots/Spyware/Ransomware/Cryptominers",
    "Attack on servers such as Database, Mail and DNS and network devices such as Routers",
    "Identity Theft, spoofing and phishing attacks",
    "Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks",
    "Attacks on Critical infrastructure, SCADA and operational technology systems and Wireless networks",
    "Attacks on Application such as E-Governance, E-Commerce etc.",
    "Data Breach",
    "Data Leak",
    "Attacks on Internet of Things (IoT) devices and associated systems, networks, software, servers",
    "Attacks or incident affecting Digital Payment systems",
    "Attacks through Malicious mobile Apps",
    "Fake mobile Apps",
    "Unauthorised access to social media accounts",
    "Attacks or malicious/suspicious activities affecting Cloud computing systems/servers/software/applications",
    "Attacks or malicious/suspicious activities affecting systems/servers/networks/software/applications related "
    "to Big Data, Block chain, virtual assets, virtual asset exchanges, custodian wallets, Robotics, 3D and 4D "
    "Printing, additive manufacturing, Drones",
    "Attacks or malicious/suspicious activities affecting systems/servers/software/applications related to "
    "Artificial Intelligence and Machine Learning",
]
REPORT_HOURS = 6
RETENTION_DAYS = 180
NTP_SERVERS = ("samay1.nic.in", "samay2.nic.in", "time.nplindia.org", "time.nplindia.in")

# ATT&CK technique (or prefix) -> Annexure I index; keyword fallbacks below
TECHNIQUE_TYPES = {
    "T1046": 0, "T1595": 0, "T1590": 0, "T1018": 0, "T1210": 1, "T1068": 1, "T1003": 1, "T1070": 1,
    "T1110": 2, "T1078": 2, "T1136": 2, "T1098": 2, "T1021": 2, "T1505.003": 3, "T1491": 3,
    "T1059": 4, "T1204": 4, "T1486": 4, "T1496": 4, "T1105": 4, "T1071": 4, "T1571": 4, "T1572": 4,
    "T1190": 9, "T1566": 6, "T1598": 6, "T1557": 6, "T1498": 7, "T1499": 7, "T1048": 11, "T1041": 11,
    "T1567": 11, "T1530": 17, "T1537": 17, "T1078.004": 17, "T0800": 8, "T0831": 8, "T0855": 8,
}
KEYWORD_TYPES = (
    ("scada", 8), ("modbus", 8), ("dnp3", 8), ("plc", 8), ("ransom", 4), ("cryptomin", 4), ("phish", 6),
    ("ddos", 7), ("flood", 7), ("defac", 3), ("upi", 13), ("payment", 13), ("swift", 13), ("iot", 12),
    ("mqtt", 12), ("s3", 17), ("azure", 17), ("aws", 17), ("gcp", 17), ("drone", 18), ("mavlink", 18),
    ("blockchain", 18), ("wallet", 18), ("model", 19), ("llm", 19), ("exfil", 11), ("leak", 11),
)


def classify(techniques: list[str], text: str = "") -> list[str]:
    idx = set()
    for t in techniques or []:
        if t in TECHNIQUE_TYPES:
            idx.add(TECHNIQUE_TYPES[t])
        elif t.split(".")[0] in TECHNIQUE_TYPES:
            idx.add(TECHNIQUE_TYPES[t.split(".")[0]])
    low = (text or "").lower()
    for kw, i in KEYWORD_TYPES:
        if kw in low:
            idx.add(i)
    return [CERT_IN_TYPES[i] for i in sorted(idx)]


def _iso(t: float | None) -> str | None:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)) if t else None


def incident_report(case: dict, org: dict, *, actions: list[str] | None = None,
                    affected: list[dict] | None = None, now: float | None = None) -> dict:
    """CERT-In incident reporting form for a SOAR case (``ulpf.soar.cases``) or an equivalent dict."""
    now = now or time.time()
    noticed = case.get("detected_at") or case.get("created_at") or now
    due = noticed + REPORT_HOURS * 3600
    types = case.get("cert_in_types") or classify(case.get("mitre") or [],
                                                  f"{case.get('title', '')} {case.get('description', '')}")
    ents = case.get("entities") or {}
    systems = affected or [{"ip": v} for k, v in ents.items() if k in ("ip", "host", "src_ip", "dst_ip")]
    return {
        "form": "CERT-In Incident Reporting Form", "directions": "CERT-In Directions 70B(6), 28 April 2022",
        "reporting_organisation": {k: org.get(k) for k in ("name", "sector", "address", "poc_name",
                                                           "poc_designation", "poc_email", "poc_phone")},
        "incident_reference": case.get("id"),
        "time_of_occurrence": _iso(case.get("first_event_at")) or "unknown",
        "time_of_detection": _iso(noticed),
        "report_due_by": _iso(due),
        "hours_remaining": round((due - now) / 3600, 2),
        "overdue": now > due,
        "incident_types": types or ["(classify: no automatic match)"],
        "severity": case.get("severity"),
        "affected_systems": systems,
        "description": case.get("description") or case.get("title"),
        "symptoms_observed": case.get("symptoms") or [t for t in case.get("mitre") or []],
        "mitre_attack": case.get("mitre") or [],
        "actions_taken": actions or [t["detail"].get("to") and f"case moved to {t['detail']['to']}"
                                     for t in case.get("timeline") or [] if t.get("kind") == "state"],
        "status": case.get("state"),
        "submission": {"email": "incident@cert-in.org.in", "portal": "https://www.cert-in.org.in",
                       "note": "submit within 6 hours of noticing the incident"},
    }


# ---------------------------------------------------------------------------
# NTP (SNTP, RFC 4330) — Direction (i)
# ---------------------------------------------------------------------------
_NTP_DELTA = 2208988800          # 1900-01-01 -> 1970-01-01


def ntp_query(server: str, port: int = 123, timeout: float = 2.0) -> dict:
    pkt = bytearray(48)
    pkt[0] = (0 << 6) | (4 << 3) | 3            # LI 0, version 4, client mode
    t1 = time.time()
    sec = int(t1) + _NTP_DELTA
    struct.pack_into(">II", pkt, 40, sec, int((t1 % 1) * 2**32))
    infos = socket.getaddrinfo(server, port, type=socket.SOCK_DGRAM)
    fam, _, _, _, addr = infos[0]
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(bytes(pkt), addr)
        data, _ = s.recvfrom(512)
    t4 = time.time()
    if len(data) < 48:
        raise ValueError("short NTP reply")
    li_vn_mode, stratum = data[0], data[1]
    if (li_vn_mode & 7) not in (4, 5):
        raise ValueError("not an NTP server reply")
    if struct.unpack(">II", data[24:32]) != struct.unpack(">II", bytes(pkt[40:48])):
        raise ValueError("originate timestamp mismatch (spoofed or stale reply)")

    def ts(off):
        s_, f_ = struct.unpack(">II", data[off:off + 8])
        return s_ - _NTP_DELTA + f_ / 2**32
    t2, t3 = ts(32), ts(40)
    offset = ((t2 - t1) + (t3 - t4)) / 2
    delay = (t4 - t1) - (t3 - t2)
    refid = data[12:16]
    ref = refid.decode("ascii", "replace").strip("\x00") if stratum <= 1 else socket.inet_ntoa(refid)
    return {"server": server, "offset_ms": round(offset * 1000, 3), "delay_ms": round(delay * 1000, 3),
            "stratum": stratum, "reference": ref, "leap": li_vn_mode >> 6}


def ntp_check(servers=NTP_SERVERS, max_offset_ms: float = 1000.0, timeout: float = 2.0) -> dict:
    results, errors = [], []
    for s in servers:
        host, _, port = str(s).partition(":")
        try:
            results.append(ntp_query(host, int(port or 123), timeout))
        except (OSError, ValueError, PermissionError) as e:
            errors.append({"server": s, "error": str(e)})
    best = min(results, key=lambda r: abs(r["offset_ms"]), default=None)
    ok = best is not None and abs(best["offset_ms"]) <= max_offset_ms and best["stratum"] not in (0, 16)
    return {"requirement": "CERT-In Direction (i): synchronise ICT clocks to NIC/NPL NTP or traceable servers",
            "compliant": ok, "best": best, "results": results, "errors": errors, "max_offset_ms": max_offset_ms}


# ---------------------------------------------------------------------------
# 180-day retention within India — Direction (iv)
# ---------------------------------------------------------------------------

def retention_audit(data_dir: str, cfg: dict, db=None, now: float | None = None) -> dict:
    now = now or time.time()
    j = cfg.get("journal") or {}
    jdir = os.path.join(data_dir, "journal")
    oldest_seg = None
    if os.path.isdir(jdir):
        mt = [os.path.getmtime(os.path.join(jdir, n)) for n in os.listdir(jdir) if n.endswith(".ulj")]
        oldest_seg = min(mt) if mt else None
    oldest_event = None
    if db is not None:
        try:
            with db._conn_lock:
                row = db.conn.execute("SELECT MIN(TRY_CAST(timestamp AS TIMESTAMP)) FROM events").fetchone()
            oldest_event = row[0].timestamp() if row and row[0] else None
        except Exception:
            oldest_event = None
    retention = float(j.get("retention_days") or 0)
    residency = (cfg.get("compliance") or {}).get("data_residency") or os.environ.get("ULPF_DATA_RESIDENCY")
    checks = {
        "journal_retention_days>=180": retention >= RETENTION_DAYS or retention == 0,
        "data_residency_india_attested": str(residency or "").upper() in ("IN", "INDIA"),
        "raw_journal_present": oldest_seg is not None,
    }
    age_days = (now - oldest_seg) / 86400 if oldest_seg else 0.0
    return {"requirement": "CERT-In Direction (iv): maintain logs securely for a rolling 180 days within "
                           "Indian jurisdiction",
            "compliant": all(checks.values()), "checks": checks, "journal_retention_days": retention or "unlimited",
            "oldest_raw_record_age_days": round(age_days, 1),
            "oldest_event": _iso(oldest_event), "covers_180_days_now": age_days >= RETENTION_DAYS,
            "data_residency": residency or "not attested (set compliance.data_residency: IN)"}
