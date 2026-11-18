import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import tests._isolation  # noqa: E402,F401  (temp data dir; never touches the user's store)

from ulpf.gui.service import ULPFService


class TestAuditFixes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PySide6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication(sys.argv)
        cls.temp_dir = tempfile.mkdtemp(prefix="ulpf_audit_test_")
        cls.service = ULPFService(data_dir=cls.temp_dir)
        cls.service.initialize(start_listener=False)

        # Ingest sample logs to seed the DB
        sample_path = os.path.join(REPO_ROOT, "demo_data", "firewall_cef.log")
        if os.path.exists(sample_path):
            cls.service.ingest_file(sample_path)

    @classmethod
    def tearDownClass(cls):
        cls.service.shutdown()

    def test_parsers_page_table_mapping(self):
        from ulpf.gui.pages.parsers import ParsersPage, ParserInventoryModel
        page = ParsersPage(self.service)
        model = page.model
        parsers = self.service.list_parsers()
        self.assertGreater(len(parsers), 0)
        self.assertGreater(model.rowCount(), 0)

        # Ensure col 0 (ID), col 1 (NAME), col 2 (FORMATS) are not empty/broken
        idx0 = model.index(0, 0)
        idx1 = model.index(0, 1)
        idx2 = model.index(0, 2)
        idx3 = model.index(0, 3)
        idx4 = model.index(0, 4)

        val0 = model.data(idx0)
        val1 = model.data(idx1)
        val2 = model.data(idx2)
        val3 = model.data(idx3)
        val4 = model.data(idx4)

        self.assertTrue(len(val0) > 0, "Parser ID should not be blank")
        self.assertNotIn("PARSER", val0)
        self.assertTrue(len(val1) > 0, "Parser Name should not be blank")
        self.assertNotEqual(val1.strip(), "PARSER", "Parser Name should not be just 'PARSER'")
        self.assertTrue(val3.startswith("1."), f"Expected 1.x semver, got {val3}")
        self.assertTrue(len(val4) > 0, "Description should not be blank")

    def test_anomalies_dynamic_baseline(self):
        from ulpf.gui.pages.anomalies import AnomaliesPage
        page = AnomaliesPage(self.service)
        page.refresh()

        # Ensure card baseline subtitle and value reflect actual data
        baseline_val = page.c_baseline.value
        baseline_sub = page.c_baseline.subtitle
        self.assertIn("±", baseline_val)
        self.assertIn("Samples:", baseline_sub)

    def test_correlation_filtering_and_custom_window(self):
        from ulpf.gui.pages.correlation import CorrelationPage
        page = CorrelationPage(self.service)
        page.window_combo.setCurrentText("120 Seconds")
        page.limit_spin.setValue(50)
        
        # Test service.correlate with target_ids
        events = self.service.query_events(limit=5)
        if events:
            ev_id = events[0].get("event_id")
            res = self.service.correlate(limit=10, window=120.0, target_ids=[ev_id])
            self.assertIsInstance(res, list)

    def test_explorer_severity_min_filter(self):
        from ulpf.gui.pages.explorer import ExplorerPage
        page = ExplorerPage(self.service)
        page.combo_sev.setCurrentText("Medium (4+)")
        page._apply_filters()
        # Ensure pause toggle
        page._toggle_pause()
        self.assertTrue(page._is_paused)
        page._toggle_pause()
        self.assertFalse(page._is_paused)


    def test_telemetry_extraction_and_field_normalization(self):
        from ulpf.engine.pipeline import Pipeline
        p = Pipeline()

        # 1. Syslog RFC5424 unquoted structured data
        res1 = p.process_line("<134>1 2026-09-30T12:00:00Z fw-01 kernel - - [drop src=10.0.0.15 dst=192.168.1.1 proto=TCP spt=54122 dpt=443] Connection denied")
        self.assertTrue(res1["success"])
        ev1 = res1["event"]
        self.assertEqual(ev1["source"]["ip"], "10.0.0.15")
        self.assertEqual(ev1["source"]["port"], 54122)
        self.assertEqual(ev1["destination"]["ip"], "192.168.1.1")
        self.assertEqual(ev1["destination"]["port"], 443)
        self.assertEqual(ev1["network"]["protocol"], "TCP")
        self.assertIn("2026-09-30T12:00:00", ev1["timestamp"])

        # 2. Cisco IP(PORT) -> IP(PORT)
        res2 = p.process_line("<131>Aug 28 10:15:05 edge-fw-01 %SEC-6-IPACCESSLOGP: list OUTSIDE-IN denied tcp 45.33.32.156(12345) -> 10.0.1.50(445), 1 packet")
        self.assertTrue(res2["success"])
        ev2 = res2["event"]
        self.assertEqual(ev2["source"]["ip"], "45.33.32.156")
        self.assertEqual(ev2["source"]["port"], 12345)
        self.assertEqual(ev2["destination"]["ip"], "10.0.1.50")
        self.assertEqual(ev2["destination"]["port"], 445)

        # 3. Suricata EVE JSON with dest_ip and dest_port
        res3 = p.process_line('{"timestamp":"2026-09-30T12:00:04Z","source":"Suricata EVE","src_ip":"198.51.100.8","dest_ip":"10.0.0.5","dest_port":80}')
        self.assertTrue(res3["success"])
        ev3 = res3["event"]
        self.assertEqual(ev3["source"]["ip"], "198.51.100.8")
        self.assertEqual(ev3["destination"]["ip"], "10.0.0.5")
        self.assertEqual(ev3["destination"]["port"], 80)

        # 4. XML SourceIP and DestIP
        res4 = p.process_line("<DNSEvent><Timestamp>2024-08-28T10:15:01Z</Timestamp><SourceIP>192.168.1.100</SourceIP><DestIP>10.0.0.1</DestIP></DNSEvent>")
        self.assertTrue(res4["success"])
        ev4 = res4["event"]
        self.assertEqual(ev4["source"]["ip"], "192.168.1.100")
        self.assertEqual(ev4["destination"]["ip"], "10.0.0.1")

        # 5. W3C without header
        res5 = p.process_line("2024-08-28 10:15:20 192.168.1.105 CONNECT tunnel.xyz:443 200 0 Mozilla/5.0 - 45.33.32.156 443 5000")
        self.assertTrue(res5["success"])
        ev5 = res5["event"]
        self.assertEqual(ev5["source"]["ip"], "192.168.1.105")
        self.assertEqual(ev5["destination"]["ip"], "45.33.32.156")
        self.assertEqual(ev5["destination"]["port"], 443)

        # 6. CEF with syslog prefix
        res6 = p.process_line("<134>Sep 30 12:00:00 fw-01 CEF:0|Check Point|VPN-1|R81|Drop|Rule Drop|8|src=45.33.32.156 dst=10.0.1.50")
        self.assertTrue(res6["success"])
        ev6 = res6["event"]
        self.assertEqual(ev6["source"]["ip"], "45.33.32.156")
        self.assertEqual(ev6["destination"]["ip"], "10.0.1.50")
        self.assertEqual(ev6["timestamp_original"], "Sep 30 12:00:00")

        # 7. FortiGate VPN remip and locip
        res7 = p.process_line('date=2024-08-28 time=10:15:15 devname="FGT-EDGE-01" type="event" subtype="vpn" remip=203.0.113.15 locip=10.0.0.1')
        self.assertTrue(res7["success"])
        ev7 = res7["event"]
        self.assertEqual(ev7["source"]["ip"], "203.0.113.15")
        self.assertEqual(ev7["destination"]["ip"], "10.0.0.1")
        self.assertEqual(ev7["timestamp_original"], "2024-08-28 10:15:15")

        # 8. Unclassified raw fallback log
        res8 = p.process_line("2026-09-30 14:10:05.123 ERROR [TurbineSensor] reading anomaly from 10.20.30.40 to controller 10.20.30.1")
        self.assertTrue(res8["success"])
        ev8 = res8["event"]
        self.assertEqual(ev8["source"]["ip"], "10.20.30.40")
        self.assertEqual(ev8["destination"]["ip"], "10.20.30.1")
        self.assertEqual(ev8["timestamp_original"], "2026-09-30 14:10:05.123")

    def test_auto_learn_generation_persistence_and_gui(self):
        from ulpf.gui.pages.autolearn import AutoLearnPage
        # A proprietary format no built-in parser handles
        sample_lines = AutoLearnPage.SAMPLE_PROPRIETARY.splitlines()
        res = self.service.auto_learn(sample_lines)
        self.assertTrue(res.get("success"), f"Auto-learn failed: {res}")
        self.assertIn("parser_id", res)
        self.assertTrue(os.path.exists(res.get("saved_to", "")))

        # The learned parser is live: an unseen line of the format is now parsed by it
        out = self.service.test_parser("[2026-10-01 08:00:00] [AUTH] [ERROR] Login failed for user mallory from 203.0.113.9")
        self.assertTrue(out.get("auto_parsed"), out)
        self.assertEqual(out["event"]["source"]["ip"], "203.0.113.9")
        self.assertEqual(out["event"]["user"]["name"], "mallory")

        # KV lines are already handled by the built-in KV parser: nothing to learn
        known = self.service.auto_learn(["2026-09-27 10:00:01 [AUTH] user=jdoe client=192.168.1.50 status=FAIL"] * 3)
        self.assertFalse(known["success"])
        self.assertEqual(known["known_lines"], 3)

        # Verify service listing
        learned = self.service.list_learned_parsers()
        self.assertGreater(len(learned), 0)
        found = any(p["parser_id"] == res["parser_id"] for p in learned)
        self.assertTrue(found, "Newly learned parser should be present in service.list_learned_parsers()")

        # Verify GUI page refresh
        page = AutoLearnPage(self.service)
        page.refresh()
        self.assertGreater(page.saved_layout.count(), 0)


if __name__ == "__main__":
    unittest.main()
