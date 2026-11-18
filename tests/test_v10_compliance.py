"""v10 compliance matrix: CERT-In, RBI, SEBI, SOC 2, ISO 27001, PCI DSS v4 and sealed bundles."""
from __future__ import annotations

import os
import shutil
import socket
import struct
import tempfile
import threading
import time
import unittest
import zipfile


def _events():
    base = {"raw_format": "syslog", "evidence": {"raw_hash": "00" * 32}, "tags": []}
    out = []
    for i in range(15):
        out.append({**base, "event_id": f"bf{i}", "timestamp": f"2026-01-02T00:00:{i:02d}Z", "category": "authentication",
                    "event_type": "logon", "action": "failed", "severity": 5, "source": {"ip": "203.0.113.5"},
                    "destination": {"ip": "10.50.0.10"}, "message": "Failed password for root"})
    out.append({**base, "event_id": "pa1", "timestamp": "2026-01-02T00:01:00Z", "category": "authentication",
                "event_type": "logon", "action": "success", "severity": 3, "user": {"name": "root"},
                "source": {"ip": "10.0.0.5"}, "destination": {"ip": "10.50.0.11"}, "message": "Accepted for root"})
    out.append({**base, "event_id": "cl1", "timestamp": "2026-01-02T00:02:00Z", "category": "system",
                "event_type": "audit_log_cleared", "action": "success", "severity": 8, "message": "The audit log was cleared"})
    return out


class FakeNtp(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", 0))
        self.port = self.s.getsockname()[1]

    def run(self):
        data, addr = self.s.recvfrom(512)
        now = time.time() + 2208988800
        reply = bytearray(48)
        reply[0], reply[1] = (0 << 6) | (4 << 3) | 4, 2
        reply[12:16] = socket.inet_aton("14.139.60.103")
        reply[24:32] = data[40:48]
        struct.pack_into(">II", reply, 32, int(now), int((now % 1) * 2**32))
        struct.pack_into(">II", reply, 40, int(now), int((now % 1) * 2**32))
        self.s.sendto(bytes(reply), addr)


class Compliance(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_certin_20_types_report_and_classification(self):
        from ulpf.compliance.certin import CERT_IN_TYPES, classify, incident_report
        self.assertEqual(len(CERT_IN_TYPES), 20)
        self.assertIn(CERT_IN_TYPES[2], classify(["T1110.003"]))
        self.assertIn(CERT_IN_TYPES[18], classify([], "unauthenticated MAVLink command to drone"))
        now = time.time()
        rep = incident_report({"id": "CASE-1", "title": "Ransomware on file server", "severity": "critical",
                               "mitre": ["T1486"], "detected_at": now - 3600, "first_event_at": now - 7200,
                               "entities": {"ip": "10.1.1.1"}}, {"name": "Acme Bank", "poc_email": "soc@acme"},
                              now=now)
        self.assertAlmostEqual(rep["hours_remaining"], 5.0, delta=0.01)
        self.assertFalse(rep["overdue"])
        self.assertIn(CERT_IN_TYPES[4], rep["incident_types"])

    def test_ntp_check_against_local_server(self):
        from ulpf.compliance.certin import ntp_check
        srv = FakeNtp()
        srv.start()
        res = ntp_check([f"127.0.0.1:{srv.port}"], timeout=2)
        self.assertTrue(res["compliant"], res)
        self.assertLess(abs(res["best"]["offset_ms"]), 200)
        self.assertEqual(res["best"]["reference"], "14.139.60.103")

    def test_matrix_and_sealed_bundle(self):
        from ulpf.compliance.matrix import Collector, FRAMEWORKS, export_bundle
        from ulpf.compliance.verify_pack import verify
        from ulpf.storage.database import Database
        from ulpf.runtime.audit import AuditLog
        AuditLog(os.path.join(self.d, "audit", "audit.log")).record("start", {})
        db = Database(os.path.join(self.d, "s.duckdb"))
        db.store_events(_events())
        cfg = {"journal": {"retention_days": 400, "encrypt": True}, "evidence": {"enabled": True},
               "airgap": {"enforce": True}, "compliance": {"data_residency": "IN", "cde_cidrs": ["10.50.0.0/24"]}}
        col = Collector(self.d, cfg, db, ntp_result={"compliant": True, "best": {"offset_ms": 1}})
        m = col.run()
        self.assertEqual(set(m["frameworks"]), set(FRAMEWORKS))
        ctl = {c["id"]: c for fw in m["frameworks"].values() for c in fw["controls"]}
        self.assertEqual(ctl["RBI-BF"]["evidence"]["bruteforce_sources"][0]["failures"], 15)
        self.assertEqual(ctl["10.2.1.4"]["status"], "pass")
        self.assertEqual(ctl["10.2.1.6"]["status"], "fail")              # audit log cleared
        self.assertEqual(ctl["10.2.1.1"]["evidence"]["cde"]["from_outside_cde"], 16)
        self.assertEqual(ctl["10.5.1"]["status"], "pass")
        self.assertEqual(ctl["CERTIN-180D"]["status"], "fail")           # no raw journal on disk here
        out = os.path.join(self.d, "pack.zip")
        res = export_bundle(col, out, org="Acme Bank")
        db.close()
        v = verify(out)
        self.assertTrue(v["valid"], v["problems"])
        with zipfile.ZipFile(out) as z:
            names = set(z.namelist())
        for f in ("matrix.json", "report.html", "evidence_events.parquet", "verify_pack.py", "manifest.sig"):
            self.assertIn(f, names)
        self.assertIn("report.pdf", names)


if __name__ == "__main__":
    unittest.main()
