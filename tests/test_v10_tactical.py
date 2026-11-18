"""v10 tactical edge: MAVLink v2 signing, CCSDS PUS, hard memory ceilings, eBPF / WFP egress."""
from __future__ import annotations

import os
import struct
import subprocess
import sys
import unittest


class Mavlink(unittest.TestCase):
    KEY = bytes(range(32))

    def _auth(self, **kw):
        from ulpf.runtime.telemetry import MavlinkAuth
        return MavlinkAuth({"*": self.KEY.hex()}, **kw)

    def _cmd(self, seq=0):
        from ulpf.runtime.telemetry import mavlink_frame
        return mavlink_frame(76, (0, 0, 0, 0, 0, 0, 0, 400, 1, 1, 0), sysid=1, compid=1, seq=seq)  # arm/disarm

    def test_valid_signature_verified(self):
        from ulpf.runtime.telemetry import decode_mavlink, sign_mavlink
        line, meta = decode_mavlink(sign_mavlink(self._cmd(), self.KEY), self._auth())
        self.assertIn("signature=valid", line)
        self.assertIn("auth=verified", line)
        self.assertIn("crc=ok", line)

    def test_forged_replayed_and_unsigned_commands_rejected(self):
        from ulpf.runtime.telemetry import decode_mavlink, sign_mavlink
        auth = self._auth()
        forged = sign_mavlink(self._cmd(), b"\x01" * 32)
        line, meta = decode_mavlink(forged, auth)
        self.assertIn("signature=invalid", line)
        self.assertIn("auth=rejected", line)
        self.assertIn("severity=critical", line)
        ok = sign_mavlink(self._cmd(1), self.KEY)
        self.assertIn("signature=valid", decode_mavlink(ok, auth)[0])
        self.assertIn("signature=replay", decode_mavlink(ok, auth)[0])        # same timestamp again
        line, _ = decode_mavlink(self._cmd(2), auth)                          # unsigned command
        self.assertIn("signature=missing", line)
        self.assertIn("auth=rejected", line)
        old = sign_mavlink(self._cmd(3), self.KEY, link_id=9, timestamp=1000)
        self.assertIn("signature=stale", decode_mavlink(old, auth)[0])

    def test_unsigned_telemetry_accepted_without_require(self):
        from ulpf.runtime.telemetry import decode_mavlink, mavlink_frame
        hb = mavlink_frame(0, (0, 2, 3, 81, 4, 3))
        line, _ = decode_mavlink(hb, self._auth())
        self.assertIn("signature=missing", line)
        self.assertNotIn("auth=rejected", line)
        line, _ = decode_mavlink(hb, self._auth(require_signed=True))
        self.assertIn("auth=rejected", line)

    def test_decoder_from_input_config(self):
        from ulpf.runtime.telemetry import TelemetryDecoder, sign_mavlink
        os.environ["ULPF_TEST_MAV_KEY"] = self.KEY.hex()
        try:
            d = TelemetryDecoder("mavlink", {"mavlink": {"keys": {"1": "env:ULPF_TEST_MAV_KEY"}}})
            self.assertIn("signature=valid", d.decode(sign_mavlink(self._cmd(), self.KEY), "uav")[0])
        finally:
            os.environ.pop("ULPF_TEST_MAV_KEY", None)


class Ccsds(unittest.TestCase):
    @staticmethod
    def packet(ptype, apid, sec_hdr: bytes, app: bytes, pec=False):
        from ulpf.runtime.telemetry import crc16_ccitt
        data = sec_hdr + app
        ln = len(data) + (2 if pec else 0) - 1
        hdr = struct.pack(">HHH", (ptype << 12) | (1 << 11) | apid, (3 << 14) | 42, ln)
        pkt = hdr + data
        if pec:
            pkt += crc16_ccitt(pkt).to_bytes(2, "big")
        return pkt

    def test_pus_c_tm_event_with_time_and_pec(self):
        from ulpf.runtime.telemetry import decode_ccsds
        sec = bytes([0x20, 5, 4]) + struct.pack(">HH", 7, 1) + (1_000_000_000).to_bytes(4, "big") + bytes(3)
        pkt = self.packet(0, 0x123, sec, b"\x00\x2a" + b"payload", pec=True)
        line, meta = decode_ccsds(pkt, {"pec": True})
        for want in ("pus_service=5", "pus_subtype=4", "pus_report=high_severity_anomaly", "severity=high",
                     "event_id=42", "pec=ok", "onboard_time=1989-09-09T01:46:40", "msg_counter=7"):
            self.assertIn(want, line)
        self.assertEqual(meta["ccsds"]["pus_service"], 5)
        bad = bytearray(pkt)
        bad[-5] ^= 1
        self.assertIn("pec=bad", decode_ccsds(bytes(bad), {"pec": True})[0])

    def test_pus_c_tc_and_verification_failure(self):
        from ulpf.runtime.telemetry import decode_ccsds
        tc = self.packet(1, 0x55, bytes([0x2f, 8, 1]) + struct.pack(">H", 99), b"\x01\x02")
        line, _ = decode_ccsds(tc)
        for want in ("packet_type=tc", "pus_service=8", "pus_service_name=function_management", "source_id=99",
                     "ack_flags=1111"):
            self.assertIn(want, line)
        tm = self.packet(0, 0x55, bytes([0x20, 1, 8]) + bytes(4) + bytes(7), b"")
        self.assertIn("pus_report=completion_failure", decode_ccsds(tm)[0])

    def test_truncated_secondary_header_does_not_raise(self):
        from ulpf.runtime.telemetry import decode_ccsds
        line, _ = decode_ccsds(self.packet(0, 1, b"\x20", b""))
        self.assertIn("decode_error", line)


class Egress(unittest.TestCase):
    def test_complement_covers_everything_but_allowlist(self):
        import ipaddress
        from ulpf.runtime.egress_os import complement
        ranges = complement(["10.0.0.0/8", "192.0.2.10/32", "127.0.0.0/8"], 4)
        blocked = 0
        for r in ranges:
            a, b = (int(ipaddress.ip_address(x)) for x in r.split("-"))
            blocked += b - a + 1
            for allowed in ("10.1.2.3", "192.0.2.10", "127.0.0.1"):
                self.assertFalse(a <= int(ipaddress.ip_address(allowed)) <= b)
        self.assertEqual(blocked, 2**32 - 2**24 - 1 - 2**24)

    def test_render_ebpf_and_wfp(self):
        from ulpf.runtime.egress_os import EBPF_SOURCE, render_ebpf, render_wfp
        self.assertTrue(os.path.exists(EBPF_SOURCE))
        sh = render_ebpf(["10.20.0.0/16", "2001:db8::/32"])
        self.assertIn("key hex 10 00 00 00 0a 14 00 00 value hex 01", sh)          # /16 10.20.0.0
        self.assertIn("allow6", sh)
        self.assertIn("cgroup attach", sh)
        ps = render_wfp(["10.20.0.0/16"], program="C:\\ulpf\\python.exe")
        self.assertIn("-Direction Outbound -Action Block", ps)
        self.assertIn("'0.0.0.0-10.19.255.255', '10.21.0.0-126.255.255.255'", ps)


@unittest.skipUnless(sys.platform == "win32", "Job Objects are Windows-only")
class HardMemoryCeiling(unittest.TestCase):
    def test_job_object_stops_allocation_beyond_ceiling(self):
        code = ("import sys; sys.path.insert(0, %r)\n"
                "from ulpf.runtime.limits_os import windows_job_limit\n"
                "r = windows_job_limit(150)\n"
                "assert r['applied'], r\n"
                "try:\n"
                "    b = bytearray(400 * 2**20)\n"
                "    print('ALLOCATED')\n"
                "except MemoryError:\n"
                "    print('CEILING')\n" % os.getcwd())
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
        self.assertIn("CEILING", out.stdout, out.stderr[-500:])


if __name__ == "__main__":
    unittest.main()
