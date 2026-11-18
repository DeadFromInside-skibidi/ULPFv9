"""
Platform Abstraction & Network Listener Verification Suite
===========================================================
Verifies:
  1. Platform abstraction layer across host OS types
  2. Air-gap compliance and offline directory resolution
  3. UDP Syslog RFC 5426 atomic datagram handling (with & without newlines)
  4. TCP Syslog newline and RFC 5425 octet-counting framing
  5. Backpressure and drop tracking metrics
  6. Multi-format log source compatibility across host OS origins
"""
from __future__ import annotations

import asyncio
import os
from queue import Queue
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import tests._isolation  # noqa: E402,F401

from ulpf.platform.base import PlatformAdapter
from ulpf.platform.paths import (
    get_adapter,
    get_cache_dir,
    get_config_dir,
    get_data_dir,
    get_default_log_sources,
    get_system_info,
)
from ulpf.ingestion.listener import (
    ListenerStats,
    SyslogUDPProtocol,
    SyslogTCPProtocol,
)
from ulpf.parsers.registry import ParserRegistry


class TestPlatformAbstraction(unittest.TestCase):
    def test_active_adapter(self):
        adapter = get_adapter()
        self.assertIsInstance(adapter, PlatformAdapter)
        self.assertIn(adapter.name, ("windows", "linux", "macos"))

    def test_platform_paths(self):
        data_dir = get_data_dir()
        config_dir = get_config_dir()
        cache_dir = get_cache_dir()

        self.assertIsInstance(data_dir, Path)
        self.assertIsInstance(config_dir, Path)
        self.assertIsInstance(cache_dir, Path)
        # ULPF_DATA_DIR (set by the test isolation) overrides the platform default
        self.assertEqual(str(data_dir), os.environ["ULPF_DATA_DIR"])
        native = get_adapter().get_data_dir()
        self.assertTrue(str(native).endswith("ULPF") or str(native).endswith("ulpf"))

    def test_system_info(self):
        info = get_system_info()
        self.assertIn("os_name", info)
        self.assertIn("os_release", info)
        self.assertIn("architecture", info)
        # Reports the host's real posture (True only without an outbound route)
        self.assertIsInstance(info["is_air_gapped"], bool)

    def test_default_log_sources(self):
        sources = get_default_log_sources()
        self.assertIsInstance(sources, list)
        for src in sources:
            self.assertIn("name", src)
            self.assertIn("path", src)
            self.assertIn("format", src)


class TestNetworkListenerProtocols(unittest.IsolatedAsyncioTestCase):
    async def test_listener_stats(self):
        stats = ListenerStats()
        stats.record_packet(128)
        stats.record_queued(1)
        stats.record_error()
        stats.record_dropped(2)

        data = stats.to_dict()
        self.assertEqual(data["packets_received"], 1)
        self.assertEqual(data["bytes_received"], 128)
        self.assertEqual(data["messages_queued"], 1)
        self.assertEqual(data["messages_dropped"], 2)
        self.assertEqual(data["errors"], 1)
        self.assertGreaterEqual(data["uptime_seconds"], 0.0)

    async def test_udp_protocol_atomic_datagram_without_newline(self):
        """RFC 5426 specifies discrete datagrams without trailing newlines."""
        q = Queue()
        stats = ListenerStats()
        protocol = SyslogUDPProtocol(q, stats)
        protocol._loop = asyncio.get_running_loop()

        # Send datagram WITHOUT \n
        raw_msg = b"<134>1 2026-09-30T12:00:00Z firewall01 app 1001 ID1 - Attack blocked"
        protocol.datagram_received(raw_msg, ("127.0.0.1", 5514))

        # Explicitly flush
        protocol._flush_batch()

        self.assertFalse(q.empty(), "UDP message without newline should be queued")
        batch = q.get_nowait()
        self.assertEqual(len(batch), 1)
        self.assertIn("Attack blocked", batch[0])
        self.assertEqual(stats.messages_queued, 1)

    async def test_udp_protocol_multiline_datagram(self):
        q = Queue()
        stats = ListenerStats()
        protocol = SyslogUDPProtocol(q, stats)
        protocol._loop = asyncio.get_running_loop()

        raw_data = (
            b"<134>1 2026-09-30T12:00:01Z host01 app 1 - Event 1\n"
            b"<134>1 2026-09-30T12:00:02Z host01 app 2 - Event 2\n"
        )
        protocol.datagram_received(raw_data, ("127.0.0.1", 5514))
        protocol._flush_batch()

        self.assertFalse(q.empty())
        batch = q.get_nowait()
        self.assertEqual(len(batch), 2)
        self.assertEqual(stats.messages_queued, 2)

    async def test_tcp_protocol_newline_framing(self):
        q = Queue()
        stats = ListenerStats()
        protocol = SyslogTCPProtocol(q, stats)
        protocol._loop = asyncio.get_running_loop()

        data = b"<14>Oct 11 22:14:15 host su: 'su root' failed for lonvick\n"
        protocol.data_received(data)
        protocol._flush_msg_batch()

        self.assertFalse(q.empty())
        batch = q.get_nowait()
        self.assertEqual(len(batch), 1)
        self.assertIn("su root", batch[0])

    async def test_tcp_protocol_octet_counting_framing(self):
        """RFC 5425 octet counting: <LEN> <MSG>"""
        q = Queue()
        stats = ListenerStats()
        protocol = SyslogTCPProtocol(q, stats)
        protocol._loop = asyncio.get_running_loop()

        msg = "<165>1 2026-09-30T12:00:00Z mymachine.example.com evits - - - An application event"
        payload = f"{len(msg)} {msg}".encode("utf-8")
        protocol.data_received(payload)
        protocol._flush_msg_batch()

        self.assertFalse(q.empty())
        batch = q.get_nowait()
        self.assertEqual(len(batch), 1)
        self.assertEqual(batch[0], msg)


class TestCrossPlatformLogSourceParsers(unittest.TestCase):
    """Verifies that logs from any OS/origin can be parsed regardless of host OS."""

    def setUp(self):
        self.registry = ParserRegistry()

    def test_all_expected_formats_registered(self):
        formats = set(self.registry.list_formats())
        expected = {"cef", "leef", "syslog", "rfc3164", "rfc5424", "w3c", "iis", "json", "xml", "csv", "kv"}
        missing = expected - formats
        self.assertEqual(missing, set(), f"Missing parser formats: {missing}")

    def test_parse_windows_event_xml(self):
        xml_log = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID>"
            "<TimeCreated SystemTime='2026-09-30T10:00:00.000Z'/><Level>Information</Level></System>"
            "<EventData><Data Name='TargetUserName'>SYSTEM</Data></EventData></Event>"
        )
        parser = self.registry.get_parser_for_format("xml")
        self.assertIsNotNone(parser)
        self.assertTrue(parser.can_parse(xml_log))
        res = parser.parse(xml_log)
        self.assertIsNotNone(res)
        self.assertIn("event_id", res)
        self.assertEqual(res.get("parsed_fields", {}).get("event.system.eventid"), "4624")

    def test_parse_linux_auth_syslog(self):
        line = "Oct 11 22:14:15 server-01 sshd[2412]: Failed password for invalid user admin from 192.168.1.50 port 45123 ssh2"
        parser = self.registry.get_parser_for_format("syslog")
        self.assertIsNotNone(parser)
        self.assertTrue(parser.can_parse(line))
        res = parser.parse(line)
        self.assertIsNotNone(res)
        self.assertEqual(res.get("device", {}).get("product"), "sshd")

    def test_parse_network_firewall_cef(self):
        line = "CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|drop|Drop|High|src=10.0.0.1 dst=192.168.1.1 proto=TCP spt=443 dpt=80"
        parser = self.registry.get_parser_for_format("cef")
        self.assertIsNotNone(parser)
        self.assertTrue(parser.can_parse(line))
        res = parser.parse(line)
        self.assertIsNotNone(res)
        self.assertEqual(res.get("device", {}).get("vendor"), "Check Point")

    def test_parse_cloud_json(self):
        line = '{"timestamp": "2026-09-30T12:00:00Z", "src_ip": "1.2.3.4", "dest_ip": "10.0.0.1", "action": "blocked", "message": "WAF SQLi block"}'
        parser = self.registry.get_parser_for_format("json")
        self.assertIsNotNone(parser)
        self.assertTrue(parser.can_parse(line))
        res = parser.parse(line)
        self.assertIsNotNone(res)
        self.assertEqual(res.get("action"), "blocked")


if __name__ == "__main__":
    unittest.main()
