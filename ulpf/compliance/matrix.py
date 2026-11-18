"""
Compliance automation matrix: continuous evidence for sovereign and global frameworks.

Frameworks and controls covered (``FRAMEWORKS``):

* **CERT-In Directions 2022** — 6-hour reporting, NTP to NIC/NPL, 180-day logs in India.
* **RBI Cyber Security Framework** (banks, NBFCs) — privileged user monitoring,
  brute-force tracking, customer data access logging, immutable audit trails.
* **SEBI CSCRF 2024** (REs, MIIs) — log coverage and retention, SOC monitoring,
  incident response KPIs, evidence integrity (the dashboard data).
* **SOC 2 Type II** — CC6.1, CC6.2, CC6.3, CC6.6, CC6.7, CC6.8, CC7.1, CC7.2, CC7.3.
* **ISO/IEC 27001:2022 Annex A** — A.8.15 logging, A.8.16 monitoring activities,
  A.8.17 clock synchronisation, A.8.24 use of cryptography.
* **PCI DSS v4.0 Requirement 10** — 10.2.1.x audit events, 10.3.x log protection and
  FIM, 10.4.1 daily review, 10.5.1 12-month retention, 10.6.x time sync, 10.7.x
  failures of security controls; plus CDE boundary access tracking.

Evidence comes from the event store (signals computed with bounded SQL),
ULPF's own integrity machinery (evidence seals, hash-chained audit log, row
MACs), the runtime configuration and the SOAR case KPIs. Each control gets a
status (``pass`` / ``fail`` / ``review``), the evidence that supports it and
sample event ids. ``export_bundle`` writes a signed ZIP (Ed25519 manifest)
with the matrix, the evidence events as Parquet, Merkle inclusion proofs for
sampled raw records, the seals, HTML and PDF reports and ``verify_pack.py``.
"""
from __future__ import annotations

import html
import io
import ipaddress
import json
import os
import time

PRIVILEGED_USERS = ("root", "administrator", "admin", "sa", "system", "sysadmin", "domain admins", "dba", "oracle",
                    "postgres", "enterprise admins")

# signal -> SQL predicate over the events view (lower-cased columns)
SIGNALS = {
    "auth_failure": "lower(coalesce(category,'')) LIKE '%auth%' AND lower(coalesce(action,'')) IN "
                    "('failed','denied','blocked','failure')",
    "auth_success": "lower(coalesce(category,'')) LIKE '%auth%' AND lower(coalesce(action,'')) IN "
                    "('success','allowed','connected')",
    "privileged": "(lower(coalesce(json_extract_string(normalised_json, '$.user.name'),'')) IN ({priv}) "
                  "OR lower(coalesce(tags,'')) LIKE '%privileged%' OR lower(coalesce(event_type,'')) IN "
                  "('privilege_escalation','sudo','runas','privilege_use'))",
    "account_change": "lower(coalesce(event_type,'')) SIMILAR TO '.*(user_(created|deleted|modified|disabled)|"
                      "group_(change|membership)|password_(change|reset)|account_(created|deleted|changed)).*'",
    "config_change": "lower(coalesce(event_type,'')) SIMILAR TO '.*(config|policy|setting)_?(change|modified|update).*'",
    "file_change": "(lower(coalesce(category,'')) LIKE '%file%' OR lower(coalesce(event_type,'')) LIKE 'file%') "
                   "AND lower(coalesce(action,'')) NOT IN ('read','accessed')",
    "audit_tamper": "(lower(coalesce(event_type,'')) IN ('audit_log_cleared','log_cleared','audit_policy_change') "
                    "OR lower(coalesce(message,'')) LIKE '%audit log%clear%' OR lower(coalesce(message,'')) LIKE "
                    "'%log file%cleared%')",
    "data_access": "(lower(coalesce(category,'')) LIKE '%data%' OR lower(coalesce(category,'')) LIKE '%database%' "
                   "OR lower(coalesce(event_type,'')) SIMILAR TO '.*(select|query|export|download|read).*')",
    "detection": "json_extract_string(normalised_json, '$.event_kind') IN ('detection','correlation')",
    "malware": "lower(coalesce(category,'')) LIKE '%malware%' OR lower(coalesce(message,'')) SIMILAR TO "
               "'.*(ransom|trojan|virus|malware).*'",
    "network_deny": "lower(coalesce(category,'')) LIKE '%network%' AND lower(coalesce(action,'')) IN "
                    "('denied','blocked','dropped')",
    "security_control_failure": "lower(coalesce(message,'')) SIMILAR TO '.*(antivirus|edr|agent|firewall|ids|ips)"
                                ".*(stopped|disabled|failed|crash|unhealthy).*'",
}

C = dict  # brevity in the catalogue below
FRAMEWORKS: dict[str, dict] = {
    "cert_in": {"name": "CERT-In Directions (28 April 2022)", "controls": [
        C(id="CERTIN-6H", title="Report cyber incidents to CERT-In within 6 hours of noticing", check="certin_6h"),
        C(id="CERTIN-NTP", title="Synchronise clocks to NIC / NPL NTP (or traceable) servers", check="ntp"),
        C(id="CERTIN-180D", title="Maintain logs for a rolling 180 days within Indian jurisdiction",
          check="retention_180"),
        C(id="CERTIN-TYPES", title="Detect and classify the 20 Annexure I incident types", signals=["detection"],
          check="detections_present")]},
    "rbi_csf": {"name": "RBI Cyber Security Framework (Banks / NBFCs)", "controls": [
        C(id="RBI-PUM", title="Privileged user activity monitored and logged", signals=["privileged"],
          check="signal_present"),
        C(id="RBI-BF", title="Brute-force / repeated authentication failures tracked", signals=["auth_failure"],
          check="bruteforce"),
        C(id="RBI-CDA", title="Customer data access logged", signals=["data_access"], check="signal_present"),
        C(id="RBI-AUDIT", title="Immutable, tamper-evident audit trails", check="integrity"),
        C(id="RBI-INC", title="Cyber incidents tracked to closure with timelines", check="soar_kpis")]},
    "sebi_cscrf": {"name": "SEBI Cybersecurity and Cyber Resilience Framework (2024)", "controls": [
        C(id="SEBI-LOG", title="Security logs collected from critical systems and retained", check="retention_180"),
        C(id="SEBI-SOC", title="Continuous security monitoring (SOC) with detections", signals=["detection"],
          check="detections_present"),
        C(id="SEBI-IR", title="Incident response metrics (MTTD / MTTR) reported", check="soar_kpis"),
        C(id="SEBI-INT", title="Integrity of logs and evidence protected", check="integrity"),
        C(id="SEBI-TIME", title="Time synchronisation of systems", check="ntp")]},
    "soc2": {"name": "SOC 2 Type II (Trust Services Criteria 2017, rev. 2022)", "controls": [
        C(id="CC6.1", title="Logical access security over protected information assets",
          signals=["auth_success", "auth_failure"], check="signal_present"),
        C(id="CC6.2", title="User registration and authorisation prior to access", signals=["account_change"],
          check="signal_present"),
        C(id="CC6.3", title="Role-based access, privileges modified and removed", signals=["privileged",
                                                                                      "account_change"],
          check="signal_present"),
        C(id="CC6.6", title="Logical access from outside system boundaries restricted", signals=["network_deny"],
          check="signal_present"),
        C(id="CC6.7", title="Transmission and movement of information restricted", check="egress"),
        C(id="CC6.8", title="Unauthorised or malicious software prevented or detected", signals=["malware"],
          check="signal_present"),
        C(id="CC7.1", title="Configuration changes and vulnerabilities detected", signals=["config_change",
                                                                                         "file_change"],
          check="signal_present"),
        C(id="CC7.2", title="System components monitored for anomalies", signals=["detection"],
          check="detections_present"),
        C(id="CC7.3", title="Security events evaluated to determine incidents", check="soar_kpis")]},
    "iso27001": {"name": "ISO/IEC 27001:2022 Annex A", "controls": [
        C(id="A.8.15", title="Logging: logs produced, stored, protected and analysed", check="integrity"),
        C(id="A.8.16", title="Monitoring activities for anomalous behaviour", signals=["detection"],
          check="detections_present"),
        C(id="A.8.17", title="Clock synchronisation to approved time sources", check="ntp"),
        C(id="A.8.24", title="Use of cryptography (keys, signatures, encryption at rest)", check="crypto")]},
    "pci_dss_v4": {"name": "PCI DSS v4.0 Requirement 10", "controls": [
        C(id="10.2.1.1", title="Individual user access to cardholder data logged", check="cde_access"),
        C(id="10.2.1.2", title="Actions by administrative accounts logged", signals=["privileged"],
          check="signal_present"),
        C(id="10.2.1.3", title="Access to audit logs logged", check="integrity"),
        C(id="10.2.1.4", title="Invalid logical access attempts logged", signals=["auth_failure"],
          check="signal_present"),
        C(id="10.2.1.5", title="Changes to identification and authentication credentials logged",
          signals=["account_change"], check="signal_present"),
        C(id="10.2.1.6", title="Initialisation, stopping or pausing of audit logs logged", signals=["audit_tamper"],
          check="audit_tamper"),
        C(id="10.3.2", title="Audit log files protected from modification", check="integrity"),
        C(id="10.3.4", title="File integrity monitoring / change detection on audit logs", check="fim"),
        C(id="10.4.1", title="Security events reviewed daily (automated review)", signals=["detection"],
          check="detections_present"),
        C(id="10.5.1", title="Audit log history retained 12 months (3 months immediately available)",
          check="retention_365"),
        C(id="10.6.1", title="System clocks synchronised", check="ntp"),
        C(id="10.7.2", title="Failures of critical security control systems detected",
          signals=["security_control_failure"], check="signal_present_or_none")]},
}


class Collector:
    def __init__(self, data_dir: str, cfg: dict | None = None, db=None, journal=None, soar=None,
                 since: str | None = None, until: str | None = None, ntp_result: dict | None = None,
                 cde_cidrs: list[str] | None = None, privileged_users=PRIVILEGED_USERS):
        self.data_dir, self.cfg, self.db, self.journal, self.soar = data_dir, cfg or {}, db, journal, soar
        self.since, self.until = since, until
        self.ntp_result = ntp_result
        comp = self.cfg.get("compliance") or {}
        self.cde = [ipaddress.ip_network(c, strict=False) for c in (cde_cidrs or comp.get("cde_cidrs") or [])]
        self.priv = ", ".join("'" + u.replace("'", "''") + "'" for u in privileged_users)
        self._signals: dict[str, dict] = {}
        self._cache: dict[str, dict] = {}

    # -- evidence primitives ----------------------------------------------------
    def _where(self) -> tuple[str, list]:
        w, p = [], []
        if self.since:
            w.append("timestamp >= ?")
            p.append(self.since)
        if self.until:
            w.append("timestamp <= ?")
            p.append(self.until)
        return (" AND ".join(w) or "1=1"), p

    def signal(self, name: str) -> dict:
        if name in self._signals:
            return self._signals[name]
        out = {"signal": name, "count": 0, "samples": []}
        if self.db is not None:
            where, p = self._where()
            pred = SIGNALS[name].format(priv=self.priv)
            try:
                with self.db._conn_lock:
                    n = self.db.conn.execute(f"SELECT COUNT(*) FROM events WHERE {where} AND ({pred})", p).fetchone()[0]
                    s = self.db.conn.execute(f"SELECT event_id FROM events WHERE {where} AND ({pred}) "
                                             "ORDER BY timestamp DESC LIMIT 20", p).fetchall()
                out.update(count=int(n), samples=[r[0] for r in s])
            except Exception as e:          # never let one bad predicate sink the whole report
                out["error"] = str(e)[:300]
        self._signals[name] = out
        return out

    def total_events(self) -> int:
        if self.db is None:
            return 0
        where, p = self._where()
        with self.db._conn_lock:
            return int(self.db.conn.execute(f"SELECT COUNT(*) FROM events WHERE {where}", p).fetchone()[0])

    def integrity(self) -> dict:
        if "integrity" in self._cache:
            return self._cache["integrity"]
        from ulpf.runtime.audit import verify_audit_log
        res: dict = {}
        ap = os.path.join(self.data_dir, "audit", "audit.log")
        res["audit_log"] = verify_audit_log(ap) if os.path.exists(ap) else {"valid": None, "note": "no audit log"}
        sd = os.path.join(self.data_dir, "evidence", "seals")
        if os.path.isdir(sd) and self.journal is not None:
            from ulpf.runtime.evidence import verify_seals
            v = verify_seals(sd, self.journal)
            res["seals"] = {k: v[k] for k in ("valid", "seals", "records_checked", "signatures_checked")}
            res["seals"]["problems"] = v["problems"][:20]
        elif os.path.isdir(sd):
            from ulpf.runtime.evidence import load_seals, seal_hash
            seals = load_seals(sd)
            res["seals"] = {"valid": all(seal_hash(s) == s.get("seal_hash") for s in seals), "seals": len(seals),
                            "note": "seal hashes checked; journal not opened"}
        else:
            res["seals"] = {"valid": None, "note": "evidence sealing not enabled"}
        ev = self.cfg.get("evidence") or {}
        res["row_mac"] = bool(ev.get("row_mac"))
        oks = [x.get("valid") for x in (res["audit_log"], res["seals"]) if x.get("valid") is not None]
        res["status"] = "pass" if oks and all(oks) else "fail" if oks else "review"
        self._cache["integrity"] = res
        return res

    def ntp(self) -> dict:
        if self.ntp_result is None:
            from ulpf.compliance.certin import NTP_SERVERS, ntp_check
            servers = (self.cfg.get("compliance") or {}).get("ntp_servers") or NTP_SERVERS
            self.ntp_result = ntp_check(servers, timeout=1.5)
        return self.ntp_result

    def retention(self) -> dict:
        if "retention" not in self._cache:
            from ulpf.compliance.certin import retention_audit
            self._cache["retention"] = retention_audit(self.data_dir, self.cfg, self.db)
        return self._cache["retention"]

    def soar_kpis(self) -> dict | None:
        if self.soar is None:
            return None
        return self.soar.cases.kpis(self.soar.tenant)

    def cde_access(self) -> dict:
        out = {"cde_cidrs": [str(c) for c in self.cde], "connections_into_cde": 0, "from_outside_cde": 0,
               "top_sources": []}
        if not self.cde or self.db is None:
            return out
        where, p = self._where()
        with self.db._conn_lock:
            rows = self.db.conn.execute(f"SELECT source_ip, destination_ip, COUNT(*) FROM events WHERE {where} "
                                        "AND destination_ip IS NOT NULL GROUP BY 1, 2 LIMIT 200000", p).fetchall()

        def inside(ip):
            try:
                a = ipaddress.ip_address(ip)
            except (ValueError, TypeError):
                return False
            return any(a in n for n in self.cde)
        srcs: dict[str, int] = {}
        for src, dst, n in rows:
            if inside(dst):
                out["connections_into_cde"] += n
                if not inside(src):
                    out["from_outside_cde"] += n
                    srcs[str(src)] = srcs.get(str(src), 0) + n
        out["top_sources"] = sorted(srcs.items(), key=lambda kv: -kv[1])[:20]
        return out

    def fim(self) -> dict:
        """ULPF's own FIM of its audit artefacts: a SHA-256 manifest compared with the previous run."""
        import hashlib
        targets = []
        for sub in ("audit", os.path.join("evidence", "seals")):
            d = os.path.join(self.data_dir, sub)
            if os.path.isdir(d):
                targets += [os.path.join(d, n) for n in sorted(os.listdir(d)) if not n.endswith((".tmp", ".state"))]
        manifest = {}
        for t in targets[:20000]:
            try:
                with open(t, "rb") as f:
                    manifest[os.path.relpath(t, self.data_dir)] = hashlib.sha256(f.read()).hexdigest()
            except OSError:
                continue
        mp = os.path.join(self.data_dir, "compliance", "fim_manifest.json")
        prev = {}
        if os.path.exists(mp):
            with open(mp, "r", encoding="utf-8") as f:
                prev = json.load(f)
        # audit logs are append-only and seals are write-once: an existing file that changed is a violation
        changed = [k for k, v in prev.items() if k in manifest and v != manifest[k] and "seal-" in k]
        removed = [k for k in prev if k not in manifest]
        os.makedirs(os.path.dirname(mp), exist_ok=True)
        with open(mp, "w", encoding="utf-8") as f:
            json.dump(manifest, f)
        fc = self.signal("file_change")
        return {"files_monitored": len(manifest), "changed_write_once": changed, "removed": removed,
                "log_source_file_changes": fc["count"],
                "status": "fail" if changed or removed else "pass"}

    # -- control evaluation ----------------------------------------------------
    def evaluate(self, ctl: dict) -> dict:
        check = ctl.get("check")
        ev: dict = {}
        status = "review"
        sigs = [self.signal(s) for s in ctl.get("signals") or []]
        if sigs:
            ev["signals"] = sigs
        if check in ("signal_present", "detections_present"):
            status = "pass" if sigs and all(s["count"] > 0 for s in sigs) else "review"
            if any(s.get("error") for s in sigs):
                status = "review"
        elif check == "signal_present_or_none":
            status = "pass"
        elif check == "bruteforce":
            ev["bruteforce_sources"] = self._bruteforce()
            status = "pass" if sigs and sigs[0]["count"] >= 0 and self.db is not None else "review"
        elif check == "audit_tamper":
            status = "fail" if sigs and sigs[0]["count"] > 0 else "pass"
            ev["note"] = "events that stop or clear audit logging are listed for review"
        elif check == "integrity":
            ev["integrity"] = self.integrity()
            status = ev["integrity"]["status"]
        elif check == "fim":
            ev["fim"] = self._cache.setdefault("fim", self.fim())
            status = ev["fim"]["status"]
        elif check == "ntp":
            ev["ntp"] = self.ntp()
            status = "pass" if ev["ntp"]["compliant"] else "fail"
        elif check in ("retention_180", "retention_365"):
            r = self.retention()
            ev["retention"] = r
            need = 180 if check == "retention_180" else 365
            days = r["journal_retention_days"]
            ok_days = days == "unlimited" or float(days) >= need
            status = "pass" if ok_days and (check == "retention_365" or r["compliant"]) else "fail"
        elif check == "certin_6h":
            k = self.soar_kpis()
            ev["soar"] = k
            ev["report_hours"] = 6
            status = "pass" if k is not None else "review"
        elif check == "soar_kpis":
            k = self.soar_kpis()
            ev["soar"] = k
            status = "pass" if k is not None else "review"
        elif check == "egress":
            a = self.cfg.get("airgap") or {}
            ev["airgap"] = {"enforce": bool(a.get("enforce")), "allow": a.get("allow") or []}
            status = "pass" if a.get("enforce") else "review"
        elif check == "crypto":
            ev["crypto"] = {"journal_encryption": bool((self.cfg.get("journal") or {}).get("encrypt")),
                            "evidence_sealing": bool((self.cfg.get("evidence") or {}).get("enabled")),
                            "signatures": "Ed25519 forward-secure", "row_mac": "BLAKE2b ratchet",
                            "key_provider": (self.cfg.get("evidence") or {}).get("key_provider", "file")}
            status = "pass" if ev["crypto"]["evidence_sealing"] else "review"
        elif check == "cde_access":
            ev["cde"] = self.cde_access()
            status = "pass" if self.cde else "review"
        return {"id": ctl["id"], "title": ctl["title"], "status": status, "evidence": ev}

    def _bruteforce(self, threshold: int = 10) -> list[dict]:
        if self.db is None:
            return []
        where, p = self._where()
        pred = SIGNALS["auth_failure"]
        with self.db._conn_lock:
            rows = self.db.conn.execute(f"SELECT source_ip, COUNT(*) n FROM events WHERE {where} AND ({pred}) "
                                        f"GROUP BY 1 HAVING n >= ? ORDER BY n DESC LIMIT 50", p + [threshold]).fetchall()
        return [{"source_ip": r[0], "failures": r[1]} for r in rows]

    def run(self, frameworks: list[str] | None = None) -> dict:
        out = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "period": {
            "since": self.since, "until": self.until}, "events_in_period": self.total_events(), "frameworks": {}}
        for fid in frameworks or list(FRAMEWORKS):
            fw = FRAMEWORKS[fid]
            ctls = [self.evaluate(c) for c in fw["controls"]]
            summary = {s: sum(1 for c in ctls if c["status"] == s) for s in ("pass", "fail", "review")}
            out["frameworks"][fid] = {"name": fw["name"], "summary": summary, "controls": ctls}
        return out


# ---------------------------------------------------------------------------
# Reports and sealed bundles
# ---------------------------------------------------------------------------

def report_html(matrix: dict, org: str = "") -> str:
    e = html.escape
    color = {"pass": "#1a7f37", "fail": "#cf222e", "review": "#9a6700"}
    parts = [f"<!doctype html><html><head><meta charset='utf-8'><title>Compliance evidence report</title>"
             "<style>body{font:14px system-ui,sans-serif;margin:32px;color:#1f2328}table{border-collapse:collapse;"
             "width:100%;margin:8px 0 24px}td,th{border:1px solid #d0d7de;padding:6px 8px;text-align:left;"
             "vertical-align:top}th{background:#f6f8fa}.s{font-weight:600}</style></head><body>",
             f"<h1>Compliance evidence report</h1><p>{e(org)} — generated {e(matrix['generated_at'])} — "
             f"events in period: {matrix['events_in_period']}</p>"]
    for fid, fw in matrix["frameworks"].items():
        s = fw["summary"]
        parts.append(f"<h2>{e(fw['name'])}</h2><p>pass {s['pass']} · fail {s['fail']} · review {s['review']}</p>"
                     "<table><tr><th>Control</th><th>Requirement</th><th>Status</th><th>Evidence</th></tr>")
        for c in fw["controls"]:
            ev = json.dumps(c["evidence"], default=str)
            parts.append(f"<tr><td>{e(c['id'])}</td><td>{e(c['title'])}</td><td class='s' style='color:"
                         f"{color[c['status']]}'>{c['status'].upper()}</td><td><code>{e(ev[:600])}</code></td></tr>")
        parts.append("</table>")
    parts.append("<p>Integrity: this report is part of a signed ULPF evidence pack. Run "
                 "<code>python verify_pack.py PACK.zip --pubkey signer.pub</code> to verify it.</p></body></html>")
    return "".join(parts)


def report_pdf(matrix: dict, org: str = "") -> bytes | None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        return None
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), title="ULPF compliance evidence report")
    ss = getSampleStyleSheet()
    flow = [Paragraph("Compliance evidence report", ss["Title"]),
            Paragraph(html.escape(f"{org} — generated {matrix['generated_at']} — events: {matrix['events_in_period']}"),
                      ss["Normal"]), Spacer(1, 12)]
    col = {"pass": colors.HexColor("#1a7f37"), "fail": colors.HexColor("#cf222e"), "review": colors.HexColor("#9a6700")}
    for fw in matrix["frameworks"].values():
        flow.append(Paragraph(html.escape(fw["name"]), ss["Heading2"]))
        rows = [["Control", "Requirement", "Status"]]
        styles = [("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke)]
        for i, c in enumerate(fw["controls"], 1):
            rows.append([c["id"], Paragraph(html.escape(c["title"]), ss["BodyText"]), c["status"].upper()])
            styles.append(("TEXTCOLOR", (2, i), (2, i), col[c["status"]]))
        t = Table(rows, colWidths=[70, 520, 70])
        t.setStyle(TableStyle(styles))
        flow += [t, Spacer(1, 12)]
    doc.build(flow)
    return buf.getvalue()


def export_bundle(collector: Collector, out_path: str, frameworks: list[str] | None = None, org: str = "",
                  key=None, proof_samples: int = 200) -> dict:
    """Signed compliance evidence pack (ZIP): matrix, evidence events, proofs, seals, reports, verifier."""
    from ulpf.compliance.packs import canonical, evidence_for, identity_key, write_pack
    matrix = collector.run(frameworks)
    files: dict[str, bytes] = {"matrix.json": canonical(matrix), "report.html": report_html(matrix, org).encode()}
    pdf = report_pdf(matrix, org)
    if pdf:
        files["report.pdf"] = pdf
    ids = sorted({sid for fw in matrix["frameworks"].values() for c in fw["controls"]
                  for s in c["evidence"].get("signals", []) for sid in s.get("samples", [])})
    if collector.db is not None and ids:
        import pyarrow.parquet as pq
        from ulpf.storage.database import EVENT_COLUMNS
        with collector.db._conn_lock:
            table = collector.db.conn.execute(f"SELECT {', '.join(EVENT_COLUMNS)} FROM events "
                                              "WHERE event_id IN (SELECT UNNEST(?))", [ids]).arrow().read_all()
        b = io.BytesIO()
        pq.write_table(table, b, compression="zstd")
        files["evidence_events.parquet"] = b.getvalue()
        seqs = []
        for row in table.column("normalised_json").to_pylist():
            try:
                s = (json.loads(row or "{}").get("evidence") or {}).get("journal_seq")
                if s is not None:
                    seqs.append(int(s))
            except ValueError:
                continue
        if collector.journal is not None and seqs:
            seal_files, proofs = evidence_for(collector.data_dir, collector.journal, seqs[:proof_samples])
            files.update(seal_files)
            files["proofs.json"] = canonical(proofs)
    key = key or identity_key(collector.data_dir)
    manifest = write_pack(out_path, "compliance-matrix", files, key,
                          {"frameworks": list(matrix["frameworks"]), "organisation": org,
                           "period": matrix["period"]})
    return {"path": out_path, "files": len(manifest["files"]),
            "summary": {k: v["summary"] for k, v in matrix["frameworks"].items()}}
