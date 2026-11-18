"""Phase 6: DPDP (India) personal-data discovery, verifiable erasure and breach packs; EU CBAM data packs."""
from __future__ import annotations

import glob
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401

from tests.test_usp import free_port, q, runtime, send_tcp, wait_for  # noqa: E402


def aadhaar(prefix: str = "23456789012") -> str:
    from ulpf.compliance.pii import verhoeff_valid
    return prefix + next(str(d) for d in range(10) if verhoeff_valid(prefix + str(d)))


class TestPII(unittest.TestCase):
    def test_detectors_validate(self):
        from ulpf.compliance.pii import PIIScanner
        a = aadhaar()
        s = PIIScanner()
        text = (f"mail ravi.k@example.in ph +91 98765 43210 uid {a[:4]} {a[4:8]} {a[8:]} pan ABCPE1234F "
                "card 4111 1111 1111 1111 ifsc HDFC0001234 upi ravi@okhdfcbank ip 103.21.244.7 "
                "gst 27ABCPE1234F1Z5")
        types = {m.type for m in s.scan(text)}
        self.assertEqual(types, {"email", "phone_in", "aadhaar", "pan", "card", "ifsc", "upi", "ipv4", "gstin"})
        # look-alikes are not personal data
        for neg in ("order 234567890123 total", "card 4111 1111 1111 1112", "PAN ABCDE1234F", "ip 999.1.1.1",
                    "ticket 1234-5678-9012"):
            self.assertEqual([m.type for m in s.scan(neg) if m.type in ("aadhaar", "card", "pan", "ipv4")], [], neg)

    def test_redact_and_tokenize(self):
        from ulpf.compliance.pii import PIIScanner, token
        s = PIIScanner(["email", "phone_in"])
        self.assertEqual(s.redact("a@b.co called 9876543210"), "[REDACTED:email] called [REDACTED:phone_in]")
        k = os.urandom(32)
        t1 = s.tokenize("call +91-98765-43210", k)
        t2 = s.tokenize("call 09876543210", k)
        self.assertEqual(t1.split()[-1], t2.split()[-1])           # same number, same token
        self.assertEqual(t1.split()[-1], token("phone_in", "9876543210", k))
        self.assertNotEqual(t1, s.tokenize("call 9876543210", os.urandom(32)))

    def test_transform_event_tags(self):
        from ulpf.compliance.pii import PIIScanner, transform_event
        ev = {"event_id": "x", "message": "login a@b.co", "raw_event": "login a@b.co from 10.0.0.1",
              "parsed_fields": {"user": "a@b.co"}, "tags": [], "evidence": {"raw_hash": "ab" * 32},
              "source": {"ip": "10.0.0.1"}}
        found = transform_event(ev, PIIScanner(), "redact")
        self.assertEqual(found, {"email", "ipv4"})
        self.assertNotIn("a@b.co", json.dumps(ev))
        self.assertEqual(ev["evidence"]["raw_hash"], "ab" * 32)       # evidence untouched
        self.assertIn("pii:email", ev["tags"])


def _sshd(user_mail: str, i: int, ip: str = "185.220.101.44") -> str:
    return f"<38>Oct 21 11:00:{i:02d} bastion sshd[901]: Failed password for {user_mail} from {ip} port {40000 + i} ssh2"


class TestDPDPRuntime(unittest.TestCase):
    def test_redaction_stage_keeps_the_journal_exact(self):
        d = tempfile.mkdtemp(prefix="ulpf_dpdp_")
        port = free_port()
        rt = runtime(d, {"inputs": [{"type": "syslog", "name": "t", "protocol": "tcp", "host": "127.0.0.1",
                                     "port": port}],
                         "evidence": {"enabled": False},
                         "compliance": {"dpdp": {"enabled": True, "mode": "redact"}}})
        try:
            send_tcp(port, [f"<38>Oct 21 11:00:00 app1 web[1]: order by priya@example.in phone 9876543210"])
            self.assertTrue(wait_for(lambda: q(rt, "SELECT COUNT(*) FROM events")[0][0] >= 1, 30))
            raw, norm = q(rt, "SELECT raw_event, normalised_json FROM events")[0]
            self.assertNotIn("priya@example.in", raw + norm)
            self.assertIn("[REDACTED:email]", raw)
            self.assertIn("pii:phone_in", json.loads(norm)["tags"])
            seq = json.loads(norm)["evidence"]["journal_seq"]
            self.assertIn(b"priya@example.in", rt.journal.read(seq).raw)   # the evidence keeps the bytes
        finally:
            rt.stop()

    def test_erasure_end_to_end(self):
        from ulpf.compliance import dpdp
        from ulpf.runtime.evidence import verify_seals
        from ulpf.runtime.journal import Journal
        from ulpf.runtime.keys import load_public_key
        from ulpf.storage.database import Database
        d = tempfile.mkdtemp(prefix="ulpf_erase_")
        port = free_port()
        subject = "meera.iyer@example.in"
        a = aadhaar()
        lines = [_sshd(subject, i) for i in range(3)] + \
                [f"<38>Oct 21 11:01:00 app1 kyc[7]: verified {subject} aadhaar {a[:4]} {a[4:8]} {a[8:]}"] + \
                [_sshd("other.user@example.in", 10 + i, "10.9.9.9") for i in range(3)]
        rt = runtime(d, {"inputs": [{"type": "syslog", "name": "t", "protocol": "tcp", "host": "127.0.0.1",
                                     "port": port}],
                         "evidence": {"enabled": True, "seal_every_events": 4, "seal_every_seconds": 600,
                                      "row_mac": True},
                         "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["store"]}]})
        try:
            send_tcp(port, lines)
            self.assertTrue(wait_for(lambda: q(rt, "SELECT COUNT(*) FROM events")[0][0] >= len(lines), 30))
            time.sleep(0.5)
        finally:
            rt.stop()
        db = Database(os.path.join(d, "s.duckdb"))
        j = Journal(os.path.join(d, "journal"), sync="always")
        res = dpdp.erase_subject(d, [subject, a], db=db, journal=j, node="node-t", reason="Data Principal request",
                                 requested_by="DPO", outputs=["siem"])
        self.assertEqual(res["summary"]["journal_records_erased"], 4)
        self.assertEqual(res["summary"]["store_rows_erased"], 4)
        # personal data is gone from the store and from every journal file on disk
        self.assertFalse(db.conn.execute("SELECT COUNT(*) FROM events WHERE normalised_json ILIKE ? OR "
                                         "raw_event ILIKE ?", [f"%{subject}%"] * 2).fetchone()[0])
        for seg in glob.glob(os.path.join(d, "journal", "*.ulj")):
            with open(seg, "rb") as f:
                blob = f.read()
            self.assertNotIn(subject.encode(), blob)
            self.assertNotIn(a[4:8].encode() + b" " + a[8:].encode(), blob)
        # other Data Principals are untouched
        self.assertEqual(db.conn.execute("SELECT COUNT(*) FROM events WHERE raw_event ILIKE '%other.user%'")
                         .fetchone()[0], 3)
        # the evidence still verifies: seals over the original digests, row MACs via the signed ledger
        with open(os.path.join(d, "evidence", "row_key.k0"), "rb") as f:
            k0 = f.read()
        v = verify_seals(os.path.join(d, "evidence", "seals"), j, None, db, row_key=k0)
        self.assertTrue(v["valid"], v["problems"])
        self.assertEqual(v["rows_erased"], 4)
        # the certificate is signed by the identity key; the receipt's salts open the commitments
        with open(res["certificate"]) as f:
            cert = json.load(f)
        pub = load_public_key(os.path.join(d, "evidence", "evidence.pub"))
        self.assertTrue(dpdp.verify_certificate(cert, pub))
        self.assertNotIn(subject, json.dumps(cert))
        with open(res["receipt"]) as f:
            receipt = json.load(f)
        originals = {i + 1: l.encode() for i, l in enumerate(lines)}
        for r in receipt["records"]:
            self.assertEqual(hashlib.sha256(bytes.fromhex(r["salt"]) + originals[r["journal_seq"]]).hexdigest(),
                             r["commitment"])
        self.assertEqual(cert["residual"][0]["location"], "output:siem")
        forged = {**cert, "summary": {**cert["summary"], "records": 0}}
        self.assertFalse(dpdp.verify_certificate(forged, pub))
        # a tampered ledger entry is not honoured: that row's missing MAC is reported again
        ledger = os.path.join(d, "compliance", "erasures", f"{cert['certificate_id']}.json")
        with open(ledger, "w") as f:
            json.dump(forged, f)
        v = verify_seals(os.path.join(d, "evidence", "seals"), j, None, db, row_key=k0)
        self.assertFalse(v["valid"])
        self.assertTrue(any("signature invalid" in p for p in v["problems"]))
        db.close()
        j.close()

    def test_breach_pack(self):
        from ulpf.compliance import dpdp, verify_pack
        from ulpf.runtime.journal import Journal
        from ulpf.storage.database import Database
        d = tempfile.mkdtemp(prefix="ulpf_breach_")
        port = free_port()
        rt = runtime(d, {"inputs": [{"type": "syslog", "name": "t", "protocol": "tcp", "host": "127.0.0.1",
                                     "port": port}],
                         "evidence": {"enabled": True, "seal_every_events": 5, "seal_every_seconds": 600},
                         "analytics": {"correlation": {"window_seconds": 30}}})
        victim = "victim.user@example.in"
        try:
            send_tcp(port, [_sshd(victim, i) for i in range(8)] +
                     ["<38>Oct 21 11:00:30 bastion sshd[901]: Accepted password for root from 185.220.101.44 port 1 ssh2"])
            time.sleep(1.0)
            send_tcp(port, ["<38>Oct 21 11:05:00 web01 cron[77]: job backup finished"])
            self.assertTrue(wait_for(lambda: q(rt, "SELECT COUNT(*) FROM events WHERE json_extract_string("
                                                   "normalised_json, '$.event_kind') = 'correlation'")[0][0] >= 1, 30))
        finally:
            rt.stop()
        db = Database(os.path.join(d, "s.duckdb"), read_only=True)
        j = Journal(os.path.join(d, "journal"), read_only=True)
        out = os.path.join(d, "breach.zip")
        rep = dpdp.breach_pack(d, out, db=db, journal=j, since="2000-01-01T00:00:00+00:00",
                               until="2100-01-01T00:00:00+00:00", min_risk=5, organisation="Acme",
                               contact="dpo@acme.example")
        db.close()
        j.close()
        self.assertGreaterEqual(rep["summary"]["incidents"], 1)
        inc = rep["incidents"][0]
        self.assertIn("T1110", {t["id"] for t in inc["mitre"]["techniques"]})
        self.assertIn("Unauthorised access of IT systems/data", inc["cert_in_types_suggested"])
        self.assertGreaterEqual(rep["summary"]["personal_data_categories"].get("contact", 0), 1)
        self.assertIsNotNone(rep["deadlines"]["cert_in"]["due"])
        with zipfile.ZipFile(out) as z:
            for n in z.namelist():
                self.assertNotIn(victim.encode(), z.read(n), n)      # no identities in the pack
        res = verify_pack.verify(out)
        self.assertTrue(res["valid"], res["problems"])
        self.assertGreater(res["proofs_checked"], 0)
        # the verifier also runs standalone from inside the pack
        x = tempfile.mkdtemp()
        with zipfile.ZipFile(out) as z:
            z.extract("verify_pack.py", x)
        p = subprocess.run([sys.executable, "-I", os.path.join(x, "verify_pack.py"), out], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)


# ---------------------------------------------------------------------------
# CBAM
# ---------------------------------------------------------------------------

def _write(path: str, rows: list[list]) -> str:
    import csv
    with open(path, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(rows)
    return path


def _cbam_files(d: str) -> list[str]:
    from ulpf.compliance.cbam import TEMPLATES
    t = TEMPLATES
    return [
        _write(os.path.join(d, "production.csv"), [t["production.csv"],
               ["production", "IN-PUNE-01", "2027", "72083900", "iron_steel", "BF-BOF", "1000", "1800", "true", "VER-1", "B1"],
               ["production", "IN-PUNE-01", "2027", "76011000", "aluminium", "electrolysis", "200", "300", "false", "", "B2"]]),
        _write(os.path.join(d, "electricity.csv"), [t["electricity.csv"],
               ["electricity", "IN-PUNE-01", "2027", "M1", "1200", "0.7", "grid", ""],
               ["electricity", "IN-PUNE-01", "2027", "M2", "1000", "0.8", "grid", "76011000"]]),
        _write(os.path.join(d, "precursors.csv"), [t["precursors.csv"],
               ["precursor", "IN-PUNE-01", "2027", "72083900", "72011000", "100", "2.0", "Supplier A", "IN", "SUP-9"],
               ["precursor", "IN-PUNE-01", "2027", "76011000", "28182000", "50", "", "Supplier B", "IN", ""]]),
        _write(os.path.join(d, "shipments.csv"), [t["shipments.csv"],
               ["shipment", "IN-PUNE-01", "2027", "72083900", "400", "DE123456789", "Stahl GmbH", "DE"],
               ["shipment", "IN-PUNE-01", "2027", "76011000", "30", "NL987654321", "Alu BV", "NL"]]),
    ]


class TestCBAM(unittest.TestCase):
    def test_calculation(self):
        from ulpf.compliance import cbam
        d = tempfile.mkdtemp()
        recs = cbam.records_from_files(_cbam_files(d))
        defaults = os.path.join(d, "defaults.csv")
        _write(defaults, [["cn_code", "see_direct", "see_indirect"], ["72083900", "2.5", "0.4"],
                          ["76011000", "2.0", "6.0"], ["28182000", "1.2", "0"]])
        c = cbam.calculate(recs, "IN-PUNE-01", "2027", cbam.load_defaults(defaults), price_eur=80.0)
        self.assertEqual((c["chargeable_share"], c["default_value_markup"]), (0.05, 0.20))
        steel, alu = (next(g for g in c["goods"] if g["cn_code"] == cn) for cn in ("72083900", "76011000"))
        # steel: (1800 + 100*2.0) / 1000 direct; meter M1 split by mass 1000:200
        self.assertAlmostEqual(steel["see_direct_tco2e_per_t"], 2.0)
        self.assertAlmostEqual(steel["see_indirect_tco2e_per_t"], 840 * 1000 / 1200 / 1000)
        self.assertAlmostEqual(steel["see_chargeable_tco2e_per_t"], 2.0)          # direct only for steel
        self.assertAlmostEqual(steel["default_see_with_markup_tco2e_per_t"], 2.5 * 1.2)
        # aluminium: unverified precursor at its default + 20 %
        self.assertAlmostEqual(alu["precursor_default_emissions_tco2e"], 50 * 1.2 * 1.2)
        self.assertAlmostEqual(alu["see_direct_tco2e_per_t"], (300 + 72) / 200)
        self.assertIn("unverified", alu["basis"])
        de, nl = c["importers"]
        self.assertIn("above", de["threshold"])
        self.assertIn("below", nl["threshold"])
        self.assertAlmostEqual(de["certificates_estimate"], 400 * 2.0 * 0.05)
        self.assertAlmostEqual(de["cost_estimate_eur"], round(400 * 2.0 * 0.05 * 80, 2))
        self.assertEqual(cbam.phase_in(2026), 0.025)
        self.assertEqual(cbam.phase_in(2034), 1.0)
        self.assertEqual(cbam.markup(2031), 0.30)

    def test_sealed_data_pack_from_the_store(self):
        from ulpf.compliance import cbam, verify_pack
        from ulpf.runtime.journal import Journal
        from ulpf.storage.database import Database
        d = tempfile.mkdtemp(prefix="ulpf_cbam_")
        jsonl = os.path.join(d, "cbam.jsonl")
        files = _cbam_files(d)
        n = sum(cbam.csv_to_jsonl(f, jsonl) for f in files)
        rt = runtime(d, {"inputs": [{"type": "file", "name": "cbam", "paths": [jsonl], "start_from": "beginning",
                                     "poll_interval_ms": 50}],
                         "evidence": {"enabled": True, "seal_every_events": 3, "seal_every_seconds": 600}})
        try:
            self.assertTrue(wait_for(lambda: q(rt, "SELECT COUNT(*) FROM events WHERE json_extract_string("
                                                   "parsed_fields, '$.cbam_record_type') IS NOT NULL")[0][0] >= n, 30))
        finally:
            rt.stop()
        db = Database(os.path.join(d, "s.duckdb"), read_only=True)
        j = Journal(os.path.join(d, "journal"), read_only=True)
        res = cbam.export_pack(d, "IN-PUNE-01", "2027", data_dir=d, db=db, journal=j, price_eur=80.0)
        db.close()
        j.close()
        self.assertTrue(res["path"].endswith("cbam_datapack_IN-PUNE-01_2027.zip"))
        self.assertEqual(res["records"], n)
        v = verify_pack.verify(res["path"])
        self.assertTrue(v["valid"], v["problems"])
        self.assertEqual(v["proofs_checked"], n)
        with zipfile.ZipFile(res["path"]) as z:
            recs = json.loads(z.read("records.json"))
            src = {s["sha256"] for s in json.loads(z.read("sources.json"))}
        with open(files[0], "rb") as f:
            self.assertIn(hashlib.sha256(f.read()).hexdigest(), src)   # figures trace back to the source file
        self.assertTrue(all(r["journal_seq"] for r in recs))
        # any edit to a figure breaks the pack
        tampered = res["path"].replace(".zip", "_t.zip")
        with zipfile.ZipFile(res["path"]) as zin, zipfile.ZipFile(tampered, "w") as zout:
            for item in zin.namelist():
                data = zin.read(item)
                if item == "records.json":
                    data = data.replace(b'"1800"', b'"1200"')
                zout.writestr(item, data)
        self.assertFalse(verify_pack.verify(tampered)["valid"])

    def test_cbam_view(self):
        from ulpf.engine.views import apply_view
        ev = {"event_id": "e", "timestamp": "t", "evidence": {"journal_seq": 3, "raw_hash": "aa", "node_id": "n"},
              "parsed_fields": {"cbam_record_type": "shipment", "installation_id": "I", "period": "2026",
                                "cn_code": "72", "quantity_t": "5"}}
        v = apply_view(ev, "cbam")
        self.assertEqual(v["cbam"]["quantity_t"], "5")
        self.assertEqual(v["journal_seq"], 3)


# ---------------------------------------------------------------------------
# Tactical edge appliance profile
# ---------------------------------------------------------------------------

class TestTacticalEdge(unittest.TestCase):
    def test_profile_defaults_and_explicit_settings_win(self):
        from ulpf.config import load_pipeline_config
        base = {"profile": "tactical_edge", "api": {"enabled": False}, "inputs": [],
                "outputs": [{"type": "duckdb", "name": "s"}, {"type": "file", "name": "f", "path": "x"}]}
        c = load_pipeline_config(data=base)
        self.assertEqual(c.mode, "defence")
        self.assertEqual(c["workers"], 1)
        self.assertEqual(c["limits"]["max_rss_mb"], 450)
        self.assertEqual(c["outputs"][0]["partition"], "hourly")
        self.assertTrue(all(o["buffer"]["max_mb"] == 64 for o in c["outputs"]))
        c2 = load_pipeline_config(data={**base, "workers": 2, "limits": {"max_rss_mb": 300}})
        self.assertEqual((c2["workers"], c2["limits"]["max_rss_mb"], c2["limits"]["duckdb_memory_mb"]), (2, 300, 128))

    def test_mavlink_and_ccsds_decoders(self):
        import struct
        from ulpf.runtime.telemetry import decode_ccsds, decode_mavlink, mavlink_frame
        txt, meta = decode_mavlink(mavlink_frame(33, (1000, 189000000, 727000000, 560000, 12000, 1, 2, 3, 9000),
                                                 sysid=7, seq=5))
        self.assertIn("mavlink_msg=GLOBAL_POSITION_INT", txt)
        self.assertIn("lat=18.9", txt)
        self.assertIn("crc=ok", txt)
        self.assertEqual(meta["mavlink"]["sysid"], 7)
        f = bytearray(mavlink_frame(0, (0, 2, 3, 81, 4, 3), v2=False))
        f[7] ^= 0xFF
        self.assertIn("crc=bad", decode_mavlink(bytes(f))[0])
        self.assertIn("decode_error", decode_mavlink(b"hello")[0])
        pkt = struct.pack(">HHH", (1 << 12) | 0x7FF, (3 << 14) | 99, 1) + bytes([0xAA, 0xBB])
        t = decode_ccsds(pkt)[0]
        for part in ("packet_type=tc", "apid=2047", "idle=true", "seq_count=99", "length_ok=true", "data=aabb"):
            self.assertIn(part, t)

    def test_mavlink_over_udp_into_the_store(self):
        import socket
        from ulpf.runtime.telemetry import mavlink_frame
        d = tempfile.mkdtemp(prefix="ulpf_mav_")
        port = free_port()
        rt = runtime(d, {"inputs": [{"type": "syslog", "name": "gcs", "protocol": "udp", "host": "127.0.0.1",
                                     "port": port, "telemetry": "mavlink"}], "evidence": {"enabled": False}})
        try:
            # the 50-byte zero-padded text makes this frame contain no newline, so also prove
            # a frame with 0x0A bytes stays one record (binary telemetry is never line-split)
            frame = mavlink_frame(253, (2, b"EKF failsafe\nreset"), sysid=3)
            self.assertIn(bytes([0x0A]), frame)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                for _ in range(5):
                    s.sendto(frame, ("127.0.0.1", port))
                    if wait_for(lambda: q(rt, "SELECT COUNT(*) FROM events")[0][0] >= 1, 2):
                        break
            row = q(rt, "SELECT raw_format, severity, normalised_json FROM events LIMIT 1")[0]
            ev = json.loads(row[2])
            self.assertEqual(row[0], "kv")
            self.assertEqual(row[1], 9)                                 # MAV_SEVERITY_CRITICAL
            self.assertEqual(ev["message"], "EKF failsafe reset")
            self.assertEqual(ev["extensions"]["container"]["mavlink"]["sysid"], 3)
            seq = ev["evidence"]["journal_seq"]
            self.assertEqual(rt.journal.read(seq).raw, frame)            # exact bytes kept
        finally:
            rt.stop()

    def test_disk_quota_retires_oldest_partitions_and_bundle_verifies(self):
        from ulpf.compliance import verify_pack
        from ulpf.compliance.bundle import write_bundle
        from ulpf.storage.database import Database
        d = tempfile.mkdtemp(prefix="ulpf_bundle_")
        db = Database(os.path.join(d, "s.duckdb"), partition="daily")
        db._current_period = lambda: "20200101"
        db.store_events_bulk([{"event_id": f"a{i}", "timestamp": "2020-01-01T00:00:00+00:00", "raw_event": "x",
                               "raw_format": "raw", "message": "m"} for i in range(5)])
        db._current_period = lambda: "20200102"
        db.store_events_bulk([{"event_id": "b", "timestamp": "2020-01-02T00:00:00+00:00", "raw_event": "y",
                               "raw_format": "raw", "message": "m"}])
        n_parts = len(db.partitions())
        self.assertTrue(db.retire_oldest())
        self.assertEqual(len(db.partitions()), n_parts - 1)
        out = os.path.join(d, "bundle.zip")
        res = write_bundle(d, out, db=db)
        db.close()
        self.assertGreaterEqual(res["events"], 1)
        v = verify_pack.verify(out)
        self.assertTrue(v["valid"], v["problems"])
        self.assertEqual(v["kind"], "forensic.bundle")


if __name__ == "__main__":
    unittest.main()
