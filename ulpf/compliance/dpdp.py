"""
India Digital Personal Data Protection (DPDP) Act, 2023: personal-data controls for log stores.

1. Discovery and minimisation (``compliance.dpdp`` in the pipeline config):
   every event's text is scanned for personal data (``ulpf.compliance.pii``)
   and tagged (``detect``), redacted (``redact``) or replaced by keyed tokens
   (``tokenize``) before it reaches the store and the outputs. The journal
   keeps the exact bytes received (evidence); ``erase`` removes them.

2. Verifiable erasure (``erase``), for a Data Principal's request:
   * every stored event and journal record that contains one of the
     subject's identifiers is found (identifier variants: spacing of Aadhaar
     and phone numbers, ``+91`` prefixes, case of e-mail addresses, tokens);
   * journal records: the raw bytes are destroyed and replaced by a tombstone
     ``commitment = SHA-256(salt || original bytes)``; the record keeps its
     original SHA-256, so the Merkle seals that cover it still verify;
   * store rows: raw text, message, vendor fields and every personal field of
     the normalised event are removed; ``raw_hash`` (the journal digest) stays;
   * a Certificate of Erasure (JSON + HTML) signed with the evidence identity
     key (Ed25519) lists every record (event id, journal sequence, original
     digest, commitment, seal). It is also the ledger ``ulpf evidence verify``
     uses to accept the erased rows, whose row MACs can no longer verify.
   * a receipt for the Data Principal holds the salts: with their own copy of
     a record they can check ``SHA-256(salt || record) == commitment``. The
     salts are not kept anywhere else, so the commitments reveal nothing.
   Copies already delivered to other outputs (SIEM, lake, archives) are
   listed as residual locations: they must be erased there too.

3. Breach notification pack (``breach_pack``): correlated incidents and
   high-severity detections in a period, packaged for CERT-In (incident report
   within 6 hours of noticing, CERT-In Directions of 28 April 2022) and the Data
   Protection Board of India (intimation without delay and a detailed report
   within 72 hours under the DPDP Rules, 2025): timeline, deadlines, suggested
   CERT-In incident types, affected Data Principals by category of personal
   data (counts, no identities), root-cause techniques, and redacted event
   evidence with the seals and Merkle inclusion proofs that prove it is
   unaltered. Classification and counts are suggestions for the person filing.
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import time
import uuid
from datetime import datetime, timedelta, timezone

from ulpf.compliance.pii import CATEGORY, PIIScanner, normalize, token, transform_event
from ulpf.compliance.packs import canonical, evidence_for, identity_key, write_pack

MODES = ("detect", "redact", "tokenize")


# ---------------------------------------------------------------------------
# 1. Pipeline stage
# ---------------------------------------------------------------------------

class DPDPStage:
    """Applied by the workers to every log event before routing (``compliance.dpdp``)."""

    def __init__(self, cfg: dict, data_dir: str):
        self.mode = cfg.get("mode", "detect")
        if self.mode not in MODES:
            raise ValueError(f"compliance.dpdp.mode must be one of {', '.join(MODES)}")
        self.scanner = PIIScanner(cfg.get("types") or None)
        self.key = load_token_key(data_dir) if self.mode == "tokenize" else None
        self.events_with_pii = 0

    def apply(self, event: dict) -> set[str]:
        found = transform_event(event, self.scanner, self.mode, self.key)
        if found:
            self.events_with_pii += 1
        return found


def load_token_key(data_dir: str) -> bytes:
    """The tokenisation key (``<data dir>/compliance/token.key``; created on first use)."""
    from ulpf.runtime.journal import load_or_create_key
    return load_or_create_key(os.path.join(data_dir, "compliance", "token.key"))


# ---------------------------------------------------------------------------
# 2. Erasure
# ---------------------------------------------------------------------------

def identifier_variants(identifier: str) -> list[tuple[str, str]]:
    """[(type, text)] forms an identifier may take in logs."""
    s = identifier.strip()
    digits = re.sub(r"\D", "", s)
    out: list[tuple[str, str]] = [("raw", s)]
    if "@" in s:
        out.append(("email", s.lower()))
    if len(digits) == 12 and digits == re.sub(r"[\s-]", "", s):
        a = digits
        out += [("aadhaar", a), ("aadhaar", f"{a[:4]} {a[4:8]} {a[8:]}"), ("aadhaar", f"{a[:4]}-{a[4:8]}-{a[8:]}")]
    if len(digits) >= 10 and digits[-10] in "6789" and len(digits) in (10, 11, 12):
        p = digits[-10:]
        out += [("phone_in", p), ("phone_in", f"+91{p}"), ("phone_in", f"+91 {p}"), ("phone_in", f"+91-{p}"),
                ("phone_in", f"0{p}"), ("phone_in", f"{p[:5]} {p[5:]}"), ("phone_in", f"+91 {p[:5]} {p[5:]}")]
    if re.fullmatch(r"[A-Za-z]{5}\d{4}[A-Za-z]", s):
        out.append(("pan", s.upper()))
    seen, uniq = set(), []
    for t, v in out:
        if v and v not in seen:
            seen.add(v)
            uniq.append((t, v))
    return uniq


def subject_digest(identifier: str) -> str:
    """Stored in certificates instead of the identifier itself."""
    return hashlib.sha256(f"ulpf-dpdp-subject:{identifier.strip().lower()}".encode()).hexdigest()


def _like(v: str) -> str:
    return "%" + v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def find_subject_events(db, identifiers: list[str], token_key: bytes | None = None) -> dict[str, dict]:
    """{event_id: {"journal_seq", "event_kind"}} of stored events mentioning any identifier."""
    terms = []
    for ident in identifiers:
        for t, v in identifier_variants(ident):
            terms.append(v)
            if token_key is not None and t != "raw":
                terms.append(token(t, v, token_key))
    found: dict[str, dict] = {}
    cols = ("raw_event", "message", "normalised_json", "parsed_fields")
    for term in dict.fromkeys(terms):
        where = " OR ".join(f"{c} ILIKE ? ESCAPE '\\'" for c in cols)
        with db._conn_lock:
            rows = db.conn.execute(
                "SELECT event_id, CAST(json_extract(normalised_json, '$.evidence.journal_seq') AS BIGINT), "
                f"json_extract_string(normalised_json, '$.event_kind') FROM events WHERE {where}",
                [_like(term)] * len(cols)).fetchall()
        for eid, seq, kind in rows:
            found.setdefault(eid, {"journal_seq": seq, "event_kind": kind or "log"})
    return found


def scan_journal(journal, identifiers: list[str]) -> set[int]:
    """Journal sequences whose raw bytes contain an identifier (for records not in the store)."""
    needles = [v.lower().encode() for ident in identifiers for _, v in identifier_variants(ident)]
    hits = set()
    for block in journal.iter_from(1):
        for r in block:
            if r.seq > journal.committed_seq:
                continue
            low = r.raw.lower()
            if any(n in low for n in needles):
                hits.add(r.seq)
    return hits


_PERSONAL = {"source": ("ip", "hostname", "mac"), "destination": ("ip", "hostname", "mac"),
             "device": ("ip", "hostname"), "user": ("name", "domain", "id", "email", "group")}


def _erased_json(norm: str, cert_id: str, commitment: str | None, when: str) -> str:
    e = json.loads(norm)
    e["message"] = "[erased]"
    for group, keys in _PERSONAL.items():
        g = e.get(group)
        if isinstance(g, dict):
            for k in keys:
                if k in g:
                    g[k] = None
            if group == "user":
                for side in ("source", "target"):
                    if isinstance(g.get(side), dict):
                        g[side] = {k: None for k in g[side]}
    geo = e.get("geo")
    if isinstance(geo, dict):
        e["geo"] = {k: None for k in geo}
    if isinstance(e.get("threat"), dict):
        e["threat"]["ioc_value"] = None
    e["extensions"] = {}
    e["erasure"] = {"certificate_id": cert_id, "erased_at": when, "commitment": commitment}
    return json.dumps(e, separators=(",", ":"))


def erase_subject(data_dir: str, identifiers: list[str], *, db, journal, node: str, reason: str = "",
                  requested_by: str = "", outputs: list[str] | None = None, scan_whole_journal: bool = False,
                  out_dir: str | None = None, passphrase_env: str | None = None) -> dict:
    """Erase a Data Principal's personal data from the store and the journal.

    Returns {"certificate": path, "certificate_html": path, "receipt": path, "summary": {...}}.
    """
    if not identifiers:
        raise ValueError("at least one subject identifier is required")
    import pyarrow as pa
    token_key = None
    tk = os.path.join(data_dir, "compliance", "token.key")
    if os.path.exists(tk):
        token_key = load_token_key(data_dir)
    events = find_subject_events(db, identifiers, token_key)
    seqs = {v["journal_seq"] for v in events.values() if v["journal_seq"] is not None}
    if scan_whole_journal and journal is not None:
        seqs |= scan_journal(journal, identifiers)
    cert_id = "ER-" + time.strftime("%Y%m%d", time.gmtime()) + "-" + uuid.uuid4().hex[:12]
    when = datetime.now(timezone.utc).isoformat()
    # one salt + commitment per journal record; the salts go to the Data Principal only
    salts: dict[int, bytes] = {}
    commitments: dict[int, str] = {}
    digests: dict[int, str] = {}
    for seq in sorted(seqs):
        rec = journal.read(seq) if journal is not None else None
        if rec is None or rec.erased:
            continue
        salt = os.urandom(16)
        salts[seq] = salt
        commitments[seq] = hashlib.sha256(salt + rec.raw).hexdigest()
        digests[seq] = rec.sha256_hex
    journal_erased = 0
    if journal is not None and commitments:
        journal_erased = journal.erase({s: f"{cert_id}:{c}".encode() for s, c in commitments.items()})
    # store rows
    store_erased = 0
    if events:
        ids = list(events)
        with db._conn_lock:
            rows = db.conn.execute("SELECT event_id, normalised_json FROM events WHERE event_id IN (SELECT UNNEST(?))",
                                   [ids]).fetchall()
        upd = {"event_id": [], "raw_event": [], "normalised_json": []}
        for eid, norm in rows:
            seq = events[eid]["journal_seq"]
            c = commitments.get(seq)
            upd["event_id"].append(eid)
            upd["raw_event"].append(f"[erased: certificate {cert_id}" + (f", commitment {c}]" if c else "]"))
            upd["normalised_json"].append(_erased_json(norm, cert_id, c, when))
        table = pa.table(upd)
        with db._conn_lock:
            db.conn.register("ulpf_erasure", table)
            try:
                store_erased = db.execute_on_partitions(
                    "UPDATE {events} SET raw_event = u.raw_event, message = '[erased]', parsed_fields = '{{}}', "
                    "normalised_json = u.normalised_json, source_ip = NULL, destination_ip = NULL, row_mac = NULL "
                    "FROM ulpf_erasure u WHERE {events}.event_id = u.event_id",
                    probe="event_id IN (SELECT event_id FROM ulpf_erasure)")
            finally:
                db.conn.unregister("ulpf_erasure")
            db.conn.execute("CHECKPOINT")
    seal_of = _seal_index(data_dir)
    records = []
    for eid, info in sorted(events.items(), key=lambda kv: (kv[1]["journal_seq"] or 0, kv[0])):
        seq = info["journal_seq"]
        records.append({"event_id": eid, "event_kind": info["event_kind"], "journal_seq": seq,
                        "raw_sha256": digests.get(seq), "commitment": commitments.get(seq),
                        "seal_hash": seal_of(seq), "store": True, "journal": seq in commitments})
    stored_seqs = {r["journal_seq"] for r in records}
    for seq in sorted(set(commitments) - stored_seqs):
        records.append({"event_id": None, "event_kind": "log", "journal_seq": seq, "raw_sha256": digests[seq],
                        "commitment": commitments[seq], "seal_hash": seal_of(seq), "store": False, "journal": True})
    residual = [{"location": f"output:{o}",
                 "note": "events delivered to this output before the erasure must be erased there"}
                for o in (outputs or [])]
    cert = {"type": "ulpf.dpdp.erasure_certificate", "version": 1, "certificate_id": cert_id, "issued_at": when,
            "node": node, "law": "Digital Personal Data Protection Act, 2023 (India): right to erasure",
            "reason": reason, "requested_by": requested_by,
            "subject": {"identifier_digests": [subject_digest(i) for i in identifiers],
                        "identifier_count": len(identifiers)},
            "records": records,
            "summary": {"records": len(records), "store_rows_erased": store_erased,
                        "journal_records_erased": journal_erased},
            "method": {"journal": "raw bytes replaced by a tombstone holding SHA-256(salt || original bytes); "
                                  "the original SHA-256 is kept, so the evidence seals still verify",
                       "store": "raw text, message, vendor fields and personal fields removed; raw_hash kept"},
            "residual": residual}
    key = identity_key(data_dir, passphrase_env)
    from ulpf.runtime.keys import raw_public
    cert["signer_pub"] = raw_public(key).hex()
    cert["signature"] = key.sign(canonical(cert)).hex()
    out_dir = out_dir or os.path.join(data_dir, "compliance", "erasures")
    os.makedirs(out_dir, exist_ok=True)
    ledger_dir = os.path.join(data_dir, "compliance", "erasures")
    os.makedirs(ledger_dir, exist_ok=True)
    cert_path = os.path.join(out_dir, f"{cert_id}.json")
    with open(cert_path, "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=1)
    if os.path.abspath(out_dir) != os.path.abspath(ledger_dir):
        with open(os.path.join(ledger_dir, f"{cert_id}.json"), "w", encoding="utf-8") as f:
            json.dump(cert, f, indent=1)
    html_path = os.path.join(out_dir, f"{cert_id}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(certificate_html(cert))
    receipt = {"type": "ulpf.dpdp.erasure_receipt", "certificate_id": cert_id, "issued_at": when,
               "how_to_verify": "For a record you hold, SHA-256(bytes.fromhex(salt) + record bytes) equals the "
                                "certificate's commitment for that journal sequence.",
               "records": [{"journal_seq": s, "commitment": commitments[s], "salt": salts[s].hex()}
                           for s in sorted(salts)]}
    receipt_path = os.path.join(out_dir, f"{cert_id}.receipt.json")
    with open(receipt_path, "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=1)
    salts.clear()
    return {"certificate": cert_path, "certificate_html": html_path, "receipt": receipt_path,
            "certificate_id": cert_id, "summary": cert["summary"]}


def _seal_index(data_dir: str):
    from ulpf.runtime.evidence import load_seals
    d = os.path.join(data_dir, "evidence", "seals")
    seals = load_seals(d) if os.path.isdir(d) else []

    def find(seq):
        if seq is None:
            return None
        s = next((x for x in seals if x["first_seq"] <= seq <= x["last_seq"]), None)
        return s["seal_hash"] if s else None
    return find


def verify_certificate(cert: dict, pubkey: bytes | None = None) -> bool:
    from ulpf.runtime.keys import verify_signature
    body = {k: v for k, v in cert.items() if k != "signature"}
    signer = bytes.fromhex(cert.get("signer_pub", ""))
    if pubkey is not None and signer != pubkey:
        return False
    return verify_signature(signer, cert.get("signature", ""), canonical(body))


def erasure_ledger(data_dir: str, pubkey: bytes | None = None) -> tuple[dict[str, dict], list[str]]:
    """{event_id: record} from every validly signed certificate; plus problems found."""
    d = os.path.join(data_dir, "compliance", "erasures")
    ledger: dict[str, dict] = {}
    problems: list[str] = []
    if not os.path.isdir(d):
        return ledger, problems
    for n in sorted(os.listdir(d)):
        if not n.endswith(".json") or n.endswith(".receipt.json"):
            continue
        with open(os.path.join(d, n), "r", encoding="utf-8") as f:
            cert = json.load(f)
        if cert.get("type") != "ulpf.dpdp.erasure_certificate":
            continue
        if not verify_certificate(cert, pubkey):
            problems.append(f"erasure certificate {n}: signature invalid")
            continue
        for r in cert["records"]:
            if r.get("event_id"):
                ledger[r["event_id"]] = {**r, "certificate_id": cert["certificate_id"]}
    return ledger, problems


def certificate_html(cert: dict) -> str:
    e = html.escape
    rows = "".join(
        f"<tr><td>{e(str(r['journal_seq']))}</td><td>{e(str(r['event_id'] or '-'))}</td>"
        f"<td><code>{e(str(r['raw_sha256'] or '-'))[:16]}…</code></td><td><code>{e(str(r['commitment'] or '-'))[:16]}…</code></td>"
        f"<td>{'yes' if r['journal'] else '-'}</td><td>{'yes' if r['store'] else '-'}</td></tr>"
        for r in cert["records"][:5000])
    residual = "".join(f"<li>{e(x['location'])}: {e(x['note'])}</li>" for x in cert["residual"]) or "<li>none</li>"
    s = cert["summary"]
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Certificate of Erasure {e(cert['certificate_id'])}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:960px;margin:2em auto;padding:0 1em;color:#111}}
table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border:1px solid #ccc;padding:4px 6px;text-align:left}}
code{{font-size:12px}}.k{{color:#555}}</style></head><body>
<h1>Certificate of Erasure</h1>
<p><b>{e(cert['certificate_id'])}</b> · issued {e(cert['issued_at'])} · node {e(cert['node'])}</p>
<p class="k">{e(cert['law'])}</p>
<p>Reason: {e(cert['reason'] or '-')} · Requested by: {e(cert['requested_by'] or '-')}</p>
<h2>Summary</h2><ul><li>Records: {s['records']}</li><li>Journal records erased: {s['journal_records_erased']}</li>
<li>Store rows erased: {s['store_rows_erased']}</li></ul>
<h2>Method</h2><p>Journal: {e(cert['method']['journal'])}.</p><p>Store: {e(cert['method']['store'])}.</p>
<h2>Residual locations</h2><ul>{residual}</ul>
<h2>Records</h2><table><tr><th>Journal seq</th><th>Event</th><th>Original SHA-256</th><th>Commitment</th><th>Journal</th><th>Store</th></tr>{rows}</table>
<h2>Signature</h2><p>Ed25519 by <code>{e(cert['signer_pub'])}</code></p><p><code>{e(cert['signature'])}</code></p>
<p class="k">Verify: <code>ulpf compliance dpdp verify-certificate {e(cert['certificate_id'])}.json --pubkey evidence.pub</code></p>
</body></html>"""


# ---------------------------------------------------------------------------
# 3. Breach notification pack
# ---------------------------------------------------------------------------

CERT_IN_TYPES = [
    "Targeted scanning/probing of critical networks/systems",
    "Compromise of critical systems/information",
    "Unauthorised access of IT systems/data",
    "Defacement of website or intrusion into a website and unauthorised changes",
    "Malicious code attacks (virus/worm/Trojan/bots/spyware/ransomware/cryptominers)",
    "Attack on servers such as database, mail and DNS and network devices such as routers",
    "Identity theft, spoofing and phishing attacks",
    "Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks",
    "Attacks on critical infrastructure, SCADA and operational technology systems and wireless networks",
    "Attacks on applications such as e-governance, e-commerce etc.",
    "Data breach",
    "Data leak",
    # v10: the remaining Annexure I types (full wording in ulpf.compliance.certin.CERT_IN_TYPES)
    "Attacks on Internet of Things (IoT) devices and associated systems, networks, software, servers",
    "Attacks or incident affecting Digital Payment systems",
    "Attacks through Malicious mobile Apps",
    "Fake mobile Apps",
    "Unauthorised access to social media accounts",
    "Attacks or malicious/suspicious activities affecting Cloud computing systems/servers/software/applications",
    "Attacks affecting Big Data, Block chain, virtual assets and exchanges, custodian wallets, Robotics, "
    "3D/4D Printing, additive manufacturing, Drones",
    "Attacks or malicious/suspicious activities affecting Artificial Intelligence and Machine Learning systems",
]
_TECHNIQUE_CERT_IN = {
    "T1046": 0, "T1595": 0, "T1595.002": 0, "T1110": 2, "T1110.001": 2, "T1110.003": 2, "T1078": 2,
    "T1190": 9, "T1505.003": 3, "T1059": 1, "T1071": 4, "T1105": 4, "T1571": 4, "T1572": 4, "T1071.004": 4,
    "T1566": 6, "T1498": 7, "T1048": 11, "T1041": 11, "T1567": 11, "T1136": 2, "T1070": 1,
}


def _ts(s) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def breach_pack(data_dir: str, out_path: str, *, db, journal, since: str | None = None, until: str | None = None,
                min_risk: float = 6.0, organisation: str = "", contact: str = "", node: str = "",
                passphrase_env: str | None = None) -> dict:
    """Write a signed breach notification pack; returns the report."""
    now = datetime.now(timezone.utc)
    until_dt = _ts(until) or now
    since_dt = _ts(since) or (until_dt - timedelta(days=7))
    with db._conn_lock:
        rows = db.conn.execute(
            "SELECT normalised_json FROM events WHERE json_extract_string(normalised_json, '$.event_kind') "
            "IN ('correlation', 'detection') AND timestamp >= ? AND timestamp <= ? ORDER BY timestamp",
            [since_dt.isoformat(), until_dt.isoformat()]).fetchall()
    derived = [json.loads(r[0]) for r in rows]
    groups = {}
    for d in derived:
        if d["event_kind"] == "correlation":
            g = d["extensions"]["correlation"]
            if g.get("risk_score", 0) >= min_risk:
                groups[g["correlation_id"]] = g      # the latest version of each group wins
    detections = [d for d in derived if d["event_kind"] == "detection" and d.get("severity", 0) >= 7]
    grouped_ids = {eid for g in groups.values() for eid in g.get("event_ids", [])}
    incidents = []
    for g in groups.values():
        incidents.append(_incident(g["correlation_id"], g.get("event_ids", []), g, db))
    for d in detections:
        rel = d.get("related_events") or []
        if not set(rel) & grouped_ids:
            det = d["extensions"]["detection"]
            fake = {"risk_score": d.get("severity", 0), "first_seen": d["timestamp"], "last_seen": d["timestamp"],
                    "kill_chain_stages": [], "mitre": {"techniques": [{"id": t, "name": ""} for t in det["techniques"]],
                                                       "tactics": [{"id": "", "name": t} for t in det["tactics"]]},
                    "sigma_rules": [{"id": det["rule_id"], "title": det["title"], "level": det["level"], "hits": det["count"]}],
                    "summary": d["message"]}
            incidents.append(_incident(d["event_id"], rel, fake, db))
    seqs = sorted({s for inc in incidents for s in inc.pop("_seqs")})
    events_lines = [line for inc in incidents for line in inc.pop("_events")]
    seal_files, proofs = evidence_for(data_dir, journal, seqs)
    principals: dict[str, set] = {}
    for inc in incidents:
        for cat, ids in inc.pop("_principals").items():
            principals.setdefault(cat, set()).update(ids)
    detected = min((t for t in (_ts(i["detected_at"]) for i in incidents) if t is not None), default=None)
    report = {
        "type": "ulpf.dpdp.breach_report", "version": 1, "generated_at": now.isoformat(), "node": node,
        "organisation": organisation, "contact": contact,
        "period": {"from": since_dt.isoformat(), "to": until_dt.isoformat()},
        "deadlines": {
            "cert_in": {"authority": "CERT-In", "rule": "report within 6 hours of noticing (CERT-In Directions, "
                                                        "28 April 2022)",
                        "due": (detected + timedelta(hours=6)).isoformat() if detected else None},
            "dpb_detailed_report": {"authority": "Data Protection Board of India",
                                    "rule": "intimation without delay; detailed report within 72 hours (DPDP Rules, 2025)",
                                    "due": (detected + timedelta(hours=72)).isoformat() if detected else None},
            "data_principals": {"rule": "intimate each affected Data Principal without delay"}},
        "summary": {"incidents": len(incidents),
                    "affected_data_principals_estimate": max((len(v) for v in principals.values()), default=0),
                    "personal_data_categories": {k: len(v) for k, v in sorted(principals.items())},
                    "events": len(events_lines), "sealed_records": sum(1 for p in proofs if p.get("sealed")),
                    "unsealed_records": sum(1 for p in proofs if not p.get("sealed"))},
        "incidents": incidents,
        "notes": ["Incident types and counts are suggestions computed from the logs; review them before filing.",
                  "Affected Data Principals are counted from distinct personal identifiers seen in the incident's "
                  "events (largest category); identities are not included in this pack.",
                  "events.jsonl is redacted; proofs.json and seals/ prove the underlying records are unaltered."],
    }
    files = {"report.json": json.dumps(report, indent=1, default=str).encode(),
             "report.html": breach_html(report).encode(),
             "events.jsonl": "\n".join(events_lines).encode(),
             "proofs.json": json.dumps(proofs, indent=1).encode(), **seal_files}
    key = identity_key(data_dir, passphrase_env)
    write_pack(out_path, "dpdp.breach", files, key, {"period": report["period"], "incidents": len(incidents)})
    return report


def _incident(incident_id: str, event_ids: list[str], g: dict, db) -> dict:
    events = db.get_events(list(event_ids)) if event_ids else []
    scanner = PIIScanner()
    principals: dict[str, set] = {}
    lines, seqs = [], []
    hosts, sources, users = set(), set(), set()
    for ev in events:
        seq = (ev.get("evidence") or {}).get("journal_seq")
        if seq is not None:
            seqs.append(seq)
        text = f"{ev.get('raw_event') or ''} {ev.get('message') or ''} {json.dumps(ev.get('parsed_fields') or {})}"
        for m in scanner.scan(text):
            principals.setdefault(CATEGORY.get(m.type, m.type), set()).add(
                hashlib.sha256(normalize(m.type, m.value).encode()).hexdigest())
        uname = (ev.get("user") or {}).get("name")
        if uname:
            principals.setdefault("account", set()).add(hashlib.sha256(str(uname).lower().encode()).hexdigest())
            users.add(str(uname))
        dst = (ev.get("destination") or {}).get("ip") or (ev.get("device") or {}).get("hostname")
        if dst:
            hosts.add(str(dst))
        src = (ev.get("source") or {}).get("ip")
        if src:
            sources.add(str(src))
        lines.append(json.dumps({
            "event_id": ev.get("event_id"), "timestamp": ev.get("timestamp"), "journal_seq": seq,
            "raw_sha256": (ev.get("evidence") or {}).get("raw_hash"), "category": ev.get("category"),
            "action": ev.get("action"), "severity": ev.get("severity"), "raw_format": ev.get("raw_format"),
            "message": scanner.redact(str(ev.get("message") or ""))[:1000],
            "raw_event": scanner.redact(str(ev.get("raw_event") or ""))[:2000]}))
    techniques = [t["id"] for t in (g.get("mitre") or {}).get("techniques", [])]
    types = sorted({_TECHNIQUE_CERT_IN[t] for t in techniques if t in _TECHNIQUE_CERT_IN} |
                   {_TECHNIQUE_CERT_IN[t.split(".")[0]] for t in techniques if t.split(".")[0] in _TECHNIQUE_CERT_IN})
    # personal data beyond addresses/accounts in an incident that reached exfiltration: a data breach
    if principals.keys() - {"online_identifier", "account"} and "exfiltration" in g.get("kill_chain_stages", []):
        types.append(CERT_IN_TYPES.index("Data breach"))
    return {
        "incident_id": incident_id, "risk_score": g.get("risk_score"),
        "first_seen": g.get("first_seen"), "last_seen": g.get("last_seen"), "detected_at": g.get("last_seen"),
        "kill_chain_stages": g.get("kill_chain_stages", []), "mitre": g.get("mitre", {}),
        "sigma_rules": g.get("sigma_rules", []), "summary": g.get("summary"),
        "cert_in_types_suggested": [CERT_IN_TYPES[i] for i in sorted(set(types))],
        "affected_assets": sorted(hosts)[:100], "attacker_sources": sorted(sources)[:100],
        "accounts_involved": len(users),
        "personal_data_categories": {k: len(v) for k, v in sorted(principals.items())},
        "event_count": len(events),
        "_seqs": seqs, "_events": lines, "_principals": principals,
    }


def breach_html(r: dict) -> str:
    e = html.escape
    inc = ""
    for i in r["incidents"]:
        tech = ", ".join(f"{t['id']} {t.get('name', '')}" for t in i["mitre"].get("techniques", [])) or "-"
        inc += (f"<h3>{e(str(i['incident_id']))} · risk {e(str(i['risk_score']))}</h3>"
                f"<p>{e(str(i.get('summary') or ''))}</p><ul>"
                f"<li>First seen: {e(str(i['first_seen']))} · last seen: {e(str(i['last_seen']))}</li>"
                f"<li>Kill chain: {e(', '.join(i['kill_chain_stages']) or '-')}</li><li>ATT&amp;CK: {e(tech)}</li>"
                f"<li>CERT-In type (suggested): {e('; '.join(i['cert_in_types_suggested']) or 'review')}</li>"
                f"<li>Affected assets: {e(', '.join(i['affected_assets'][:10]) or '-')}</li>"
                f"<li>Personal data categories: {e(json.dumps(i['personal_data_categories']))}</li>"
                f"<li>Events: {i['event_count']}</li></ul>")
    d = r["deadlines"]
    s = r["summary"]
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Personal data breach report</title>
<style>body{{font-family:system-ui,sans-serif;max-width:960px;margin:2em auto;padding:0 1em;color:#111}}
.k{{color:#555}}</style></head><body><h1>Personal data breach report</h1>
<p>{e(r['organisation'] or '-')} · contact {e(r['contact'] or '-')} · generated {e(r['generated_at'])}</p>
<p>Period {e(r['period']['from'])} to {e(r['period']['to'])}</p>
<h2>Deadlines</h2><ul><li>CERT-In: {e(str(d['cert_in']['due']))} ({e(d['cert_in']['rule'])})</li>
<li>Data Protection Board: {e(str(d['dpb_detailed_report']['due']))} ({e(d['dpb_detailed_report']['rule'])})</li>
<li>Data Principals: {e(d['data_principals']['rule'])}</li></ul>
<h2>Summary</h2><ul><li>Incidents: {s['incidents']}</li>
<li>Affected Data Principals (estimate): {s['affected_data_principals_estimate']}</li>
<li>Categories of personal data: {e(json.dumps(s['personal_data_categories']))}</li>
<li>Evidence: {s['events']} events, {s['sealed_records']} with Merkle proofs</li></ul>
<h2>Incidents</h2>{inc or '<p>None in this period.</p>'}
<h2>Notes</h2><ul>{''.join(f'<li>{e(n)}</li>' for n in r['notes'])}</ul>
<p class="k">Verify this pack: <code>python verify_pack.py PACK.zip --pubkey evidence.pub</code></p></body></html>"""
