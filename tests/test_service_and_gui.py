"""
End-to-End Test Suite for ULPF Application Service and GUI Components
======================================================================
Tests all backend integrations via ULPFService without needing a display server,
and verifies Qt GUI component instantiation.
"""
import os
import sys
import tempfile
import unittest

# Ensure repo root is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import tests._isolation  # noqa: E402,F401
from ulpf.gui.service import ULPFService


class TestULPFService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="ulpf_test_")
        cls.service = ULPFService(data_dir=cls.temp_dir)
        success = cls.service.initialize()
        assert success, f"Failed to initialize service: {cls.service.error}"

    @classmethod
    def tearDownClass(cls):
        cls.service.shutdown()

    def test_01_health_and_state(self):
        self.assertEqual(self.service.state, "RUNNING")
        h = self.service.health()
        self.assertIn("status", h)
        self.assertEqual(h["status"], "healthy")

    def test_02_parsers_list(self):
        parsers = self.service.list_parsers()
        self.assertIsInstance(parsers, list)
        self.assertGreater(len(parsers), 0)

    def test_03_test_parser(self):
        sample = '<134>1 2023-10-12T14:32:00Z myhost myapp 1234 ID47 - Bom'
        res = self.service.test_parser(sample)
        self.assertTrue(res.get("success"), f"Parser test failed: {res}")
        self.assertIn("event", res)

    def test_04_ingest_file(self):
        sample_path = os.path.join(REPO_ROOT, "demo_data", "firewall_cef.log")
        if os.path.exists(sample_path):
            res = self.service.ingest_file(sample_path)
            self.assertTrue(res.get("success"), f"Ingestion failed: {res}")
            self.assertGreater(res.get("events_accepted", 0), 0)
            self.assertGreater(res.get("stored", 0), 0)

    def test_05_ingest_text(self):
        text = (
            '{"timestamp": "2023-10-12T14:32:00Z", "src_ip": "192.168.1.100", "action": "blocked"}\n'
            '{"timestamp": "2023-10-12T14:33:00Z", "src_ip": "192.168.1.101", "action": "allowed"}'
        )
        res = self.service.ingest_text(text)
        self.assertTrue(res.get("success"), f"Text ingestion failed: {res}")
        self.assertEqual(res.get("total_lines"), 2)

    def test_06_query_and_search_events(self):
        events = self.service.query_events(limit=10)
        self.assertIsInstance(events, list)
        self.assertGreater(len(events), 0)

        first_id = events[0].get("event_id")
        self.assertIsNotNone(first_id)

        single = self.service.get_event(first_id)
        self.assertIsNotNone(single)
        self.assertEqual(single.get("event_id"), first_id)

        search_res = self.service.search_events("192.168", limit=10)
        self.assertIsInstance(search_res, list)

    def test_07_storage_info(self):
        info = self.service.get_storage_info()
        self.assertEqual(info.get("backend"), "DuckDB")
        self.assertGreater(info.get("total_events", 0), 0)

    def test_08_forensics(self):
        chain_res = self.service.forensic_build_from_events(limit=5, description="Automated Test Chain")
        self.assertIn("chain_id", chain_res)
        chain_id = chain_res["chain_id"]

        chains = self.service.forensic_list_chains()
        self.assertIsInstance(chains, list)

        verification = self.service.forensic_verify(chain_id)
        self.assertTrue(verification.get("valid", False))

        export_res = self.service.forensic_export(chain_id)
        self.assertTrue(export_res.get("success", False))
        self.assertTrue(os.path.exists(export_res.get("filepath", "")))

    def test_09_correlation(self):
        groups = self.service.correlate(limit=50, window=300.0)
        self.assertIsInstance(groups, list)

    def test_10_log_dna(self):
        lines = [
            "Oct 11 22:14:15 server1 sshd[1234]: Failed password for invalid user admin from 10.0.0.1 port 22",
            "Oct 11 22:14:16 server1 sshd[1235]: Failed password for invalid user root from 10.0.0.2 port 22",
        ]
        fp_res = self.service.log_dna_fingerprint(lines, label="ssh_test")
        self.assertTrue(fp_res.get("success"))
        fid = fp_res.get("fingerprint_id")
        self.assertIsNotNone(fid)

        known = self.service.log_dna_list()
        self.assertIsInstance(known, list)

        match_res = self.service.log_dna_match(lines)
        self.assertTrue(match_res.get("matched"))

    def test_11_schema(self):
        schema = self.service.get_schema()
        self.assertIn("event_id", schema)
        self.assertIn("timestamp", schema)
        self.assertIn("evidence", schema)

    def test_12_exports(self):
        json_path = os.path.join(self.temp_dir, "export.json")
        csv_path = os.path.join(self.temp_dir, "export.csv")

        j_res = self.service.export_events_json(json_path)
        self.assertTrue(j_res.get("success"))
        self.assertTrue(os.path.exists(json_path))

        c_res = self.service.export_events_csv(csv_path)
        self.assertTrue(c_res.get("success"))
        self.assertTrue(os.path.exists(csv_path))


class TestGUIComponents(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PySide6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication(sys.argv)
        cls.temp_dir = tempfile.mkdtemp(prefix="ulpf_gui_test_")
        cls.service = ULPFService(data_dir=cls.temp_dir)
        cls.service.initialize()

    @classmethod
    def tearDownClass(cls):
        cls.service.shutdown()

    def test_widgets(self):
        from ulpf.gui.widgets import (
            MetricCard, StatusBadge, PageHeader, SectionCard,
            DataTable, SearchBar, KeyValueRow
        )
        card = MetricCard("Total Events", 1234, "▲ 12%", "neutral")
        self.assertEqual(card.title, "Total Events")

        badge = StatusBadge("running")
        self.assertEqual(badge.status, "running")

        header = PageHeader("Test Page", "Page description")
        sec = SectionCard("Section")
        table = DataTable(["ID", "Name"])
        search = SearchBar("Search...")
        kv = KeyValueRow("Key", "Value")

    def test_all_pages_instantiation(self):
        from ulpf.gui.pages.overview import OverviewPage
        from ulpf.gui.pages.ingestion import IngestionPage
        from ulpf.gui.pages.explorer import ExplorerPage
        from ulpf.gui.pages.parsers import ParsersPage
        from ulpf.gui.pages.autolearn import AutoLearnPage
        from ulpf.gui.pages.logdna import LogDNAPage
        from ulpf.gui.pages.correlation import CorrelationPage
        from ulpf.gui.pages.anomalies import AnomaliesPage
        from ulpf.gui.pages.forensics import ForensicsPage
        from ulpf.gui.pages.schema import SchemaPage
        from ulpf.gui.pages.pipeline import PipelinePage
        from ulpf.gui.pages.listener import ListenerPage
        from ulpf.gui.pages.storage import StoragePage
        from ulpf.gui.pages.settings import SettingsPage
        from ulpf.gui.main_window import MainWindow

        pages = [
            OverviewPage(self.service),
            IngestionPage(self.service),
            ExplorerPage(self.service),
            ParsersPage(self.service),
            AutoLearnPage(self.service),
            LogDNAPage(self.service),
            CorrelationPage(self.service),
            AnomaliesPage(self.service),
            ForensicsPage(self.service),
            SchemaPage(self.service),
            PipelinePage(self.service),
            ListenerPage(self.service),
            StoragePage(self.service),
            SettingsPage(self.service),
        ]
        for p in pages:
            self.assertIsNotNone(p)
            if hasattr(p, "refresh"):
                p.refresh()

        window = MainWindow(self.service)
        self.assertIsNotNone(window)
        # Test navigation
        window.navigate_to("overview")
        window.navigate_to("ingestion")
        window.navigate_to("events")
        window.navigate_to("parsers")
        window.navigate_to("autolearn")
        window.navigate_to("logdna")
        window.navigate_to("correlation")
        window.navigate_to("anomalies")
        window.navigate_to("forensics")
        window.navigate_to("schema")
        window.navigate_to("pipeline")
        window.navigate_to("listener")
        window.navigate_to("storage_pg")
        window.navigate_to("settings")
        window.close()


if __name__ == "__main__":
    unittest.main()
