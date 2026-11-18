"""
ULPF Benchmark — Deterministic Synthetic Log Generator
=========================================================
Generates reproducible datasets for consistent benchmarking.
Each dataset is deterministic given a seed, ensuring benchmarks
are reproducible across runs and machines.

Key properties:
  - Fixed random seed → identical output across runs
  - Covers all 9 ULPF-supported log formats
  - Realistic field distributions (IPs, ports, timestamps, severities)
  - Includes threat IOCs, anomaly-triggering patterns, and multi-format noise
  - Configurable event counts: 1K, 10K, 50K, 100K, 500K, 1M
"""
from __future__ import annotations

import json
import os
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union


# ── Deterministic Pools ──────────────────────────────────────────────────

THREAT_IPS = [
    "45.33.32.156", "185.220.101.1", "91.121.87.10", "103.224.182.250",
    "177.54.150.200", "198.51.100.99", "23.129.64.100", "171.25.193.77",
    "62.210.105.116", "185.56.83.83", "89.248.167.131", "5.188.206.22",
]
INTERNAL_IPS = [
    "192.168.1.100", "10.0.2.15", "10.0.1.50", "192.168.10.5",
    "10.0.0.25", "192.168.5.100", "10.0.1.100", "192.168.1.50",
    "172.16.0.10", "172.16.0.20", "10.10.10.1", "10.10.10.2",
]
HOSTNAMES = [
    "fw-01", "fw-02", "rtr-core-01", "rtr-edge-01", "ids-01", "ids-02",
    "waf-prod-01", "proxy-01", "vpn-gw-01", "srv-dc-01", "srv-web-01",
    "sw-access-01", "honeypot-01", "siem-collector-01",
]
PORTS = [22, 53, 80, 443, 445, 993, 1433, 3306, 3389, 5432, 8080, 8443, 4444, 31337]
PROTOCOLS = ["TCP", "UDP", "ICMP", "GRE", "ESP"]
ACTIONS = ["allow", "deny", "drop", "block", "accept", "reset", "detect", "alert"]
ATTACK_MSGS = [
    "Failed password for root from {src} port {spt} ssh2",
    "Blocked SQL injection attempt from {src}",
    "Port scan detected from {src} -- {n} ports in 10s",
    "Exploit attempt EternalBlue blocked from {src}",
    "Suspicious C2 beacon detected to {dst}:{dpt}",
    "Data exfiltration attempt: {bytes} bytes to {dst}",
    "Brute force authentication attack from {src} -- {n} failures",
    "Malware download blocked: {src} -> {dst} (payload.exe)",
    "DNS tunneling detected: {src} -> {dst}",
    "Privilege escalation attempt by user admin from {src}",
    "Lateral movement detected: {src} -> {dst} via SMB",
    "Ransomware indicator: file encryption pattern from {src}",
]


class DeterministicGenerator:
    """Generate reproducible synthetic log lines for benchmarking."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.rng = random.Random(seed)
        # Fixed base timestamp for reproducibility
        self._base_ts = datetime(2025, 9, 15, 12, 0, 0, tzinfo=timezone.utc)

    def _ip(self, threat_bias: float = 0.3) -> str:
        if self.rng.random() < threat_bias:
            return self.rng.choice(THREAT_IPS)
        return self.rng.choice(INTERNAL_IPS)

    def _port(self) -> int:
        return self.rng.choice(PORTS)

    def _ts(self) -> str:
        offset = timedelta(seconds=self.rng.randint(0, 3600))
        dt = self._base_ts - offset
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def _ts_syslog(self) -> str:
        offset = timedelta(seconds=self.rng.randint(0, 3600))
        dt = self._base_ts - offset
        return dt.strftime("%b %d %H:%M:%S")

    def _host(self) -> str:
        return self.rng.choice(HOSTNAMES)

    def _proto(self) -> str:
        return self.rng.choice(PROTOCOLS)

    def _act(self) -> str:
        return self.rng.choice(ACTIONS)

    def _sev(self) -> int:
        return self.rng.choices(range(0, 11), weights=[1, 1, 2, 2, 3, 3, 4, 5, 6, 7, 8])[0]

    def _msg(self) -> str:
        src, dst = self._ip(0.5), self._ip(0.1)
        return self.rng.choice(ATTACK_MSGS).format(
            src=src, dst=dst, spt=self._port(), dpt=self._port(),
            bytes=self.rng.randint(10000, 5000000), n=self.rng.randint(50, 5000)
        )

    # ── Benchmark ID Helpers ──────────────────────────────────────────
    @staticmethod
    def extract_bench_id(item: Any) -> str | None:
        """Extract deterministic benchmark ID (BID_XXXXXXXX) from raw text, dict, or row."""
        import re
        if item is None:
            return None
        if isinstance(item, str):
            m = re.search(r"\b(BID_\d+)\b", item)
            return m.group(1) if m else None
        if isinstance(item, dict):
            if "bench_id" in item and item["bench_id"]:
                return str(item["bench_id"])
            for key in ("raw_event", "raw_line", "message", "raw"):
                val = item.get(key)
                if isinstance(val, str):
                    m = re.search(r"\b(BID_\d+)\b", val)
                    if m:
                        return m.group(1)
            parsed = item.get("parsed_fields")
            if isinstance(parsed, dict):
                return DeterministicGenerator.extract_bench_id(parsed)
        return None

    # ── Format Generators ────────────────────────────────────────────

    def gen_syslog3164(self, bench_id: str | None = None) -> str:
        pri = self.rng.randint(0, 191)
        bid = f"bench_id={bench_id} " if bench_id else ""
        return f"<{pri}>{self._ts_syslog()} {self._host()} sshd[{self.rng.randint(100, 65535)}]: {bid}{self._msg()}"

    def gen_syslog5424(self, bench_id: str | None = None) -> str:
        pri = self.rng.randint(0, 191)
        bid = f"bench_id={bench_id} " if bench_id else ""
        return f"<{pri}>1 {self._ts()} {self._host()} auditd {self.rng.randint(100, 65535)} ID{self.rng.randint(1, 999)} - {bid}{self._msg()}"

    def gen_cef(self, bench_id: str | None = None) -> str:
        src, dst = self._ip(0.4), self._ip(0.1)
        sev = self._sev()
        vendors = [
            ("Check Point", "VPN-1 & FireWall-1", "R81.20"),
            ("Palo Alto Networks", "PAN-OS", "11.0"),
            ("Fortinet", "FortiGate", "7.4"),
        ]
        v = self.rng.choice(vendors)
        bid = f"bench_id={bench_id} " if bench_id else ""
        return (
            f"CEF:0|{v[0]}|{v[1]}|{v[2]}|{self.rng.randint(100, 999)}|"
            f"{self._msg()[:50]}|{sev}|{bid}src={src} spt={self._port()} dst={dst} dpt={self._port()} "
            f"proto={self._proto()} act={self._act()} in={self.rng.randint(64, 50000)} "
            f"out={self.rng.randint(64, 50000)}"
        )

    def gen_leef(self, bench_id: str | None = None) -> str:
        src, dst = self._ip(0.4), self._ip(0.1)
        bid = f"bench_id={bench_id}\t" if bench_id else ""
        return (
            f"LEEF:1.0|SecurityVendor|IDS|1.0|{self.rng.randint(100, 999)}|"
            f"{bid}src={src}\tsrcPort={self._port()}\tdst={dst}\t"
            f"dstPort={self._port()}\tproto={self._proto()}\t"
            f"action={self._act()}\tsev={self._sev()}\tmsg={self._msg()[:80]}"
        )

    def gen_json(self, bench_id: str | None = None) -> str:
        src, dst = self._ip(0.4), self._ip(0.1)
        d = {
            "timestamp": self._ts(), "source_ip": src, "source_port": self._port(),
            "destination_ip": dst, "destination_port": self._port(),
            "action": self._act(), "protocol": self._proto(), "severity": self._sev(),
            "message": self._msg(), "device": self._host(),
            "category": self.rng.choice(["firewall", "ids_ips", "authentication", "network", "threat"]),
            "bytes_in": self.rng.randint(64, 50000), "bytes_out": self.rng.randint(64, 50000),
        }
        if bench_id:
            d["bench_id"] = bench_id
        return json.dumps(d)

    def gen_xml(self, bench_id: str | None = None) -> str:
        src, dst = self._ip(0.4), self._ip(0.1)
        bid = f' bench_id="{bench_id}"' if bench_id else ""
        return (
            f'<Event timestamp="{self._ts()}" severity="{self._sev()}"{bid}>'
            f'<Source ip="{src}" port="{self._port()}"/>'
            f'<Destination ip="{dst}" port="{self._port()}"/>'
            f'<Action>{self._act()}</Action>'
            f'<Protocol>{self._proto()}</Protocol>'
            f'<Message>{self._msg()[:60]}</Message>'
            f'</Event>'
        )

    def gen_csv(self, bench_id: str | None = None) -> str:
        src, dst = self._ip(0.4), self._ip(0.1)
        bid = f",{bench_id}" if bench_id else ""
        return (
            f"{self._ts()},{src},{self._port()},{dst},{self._port()},"
            f"{self._proto()},{self._act()},{self._sev()},{self._host()},"
            f"{self.rng.randint(64, 50000)},{self.rng.randint(64, 50000)}{bid}"
        )

    def gen_kv(self, bench_id: str | None = None) -> str:
        src, dst = self._ip(0.4), self._ip(0.1)
        bid = f"bench_id={bench_id} " if bench_id else ""
        return (
            f"date={self._ts()} devname={self._host()} "
            f"{bid}srcip={src} srcport={self._port()} "
            f"dstip={dst} dstport={self._port()} "
            f"proto={self._proto()} action={self._act()} "
            f'policyid={self.rng.randint(1, 100)} sentbyte={self.rng.randint(100, 500000)} '
            f'rcvdbyte={self.rng.randint(100, 500000)} '
            f'msg="{self._msg()[:60]}"'
        )

    def gen_w3c(self, bench_id: str | None = None) -> str:
        offset = timedelta(seconds=self.rng.randint(0, 3600))
        dt = self._base_ts - offset
        methods = ["GET", "POST", "PUT", "DELETE", "HEAD"]
        paths = ["/api/v1/data", "/login", "/admin", "/index.html", "/search?q=test",
                 "/wp-admin", "/shell.php", "/cmd.exe", "/.env", "/etc/passwd"]
        codes = [200, 200, 200, 301, 403, 404, 500, 503]
        base_path = self.rng.choice(paths)
        p = f"{base_path}&bench_id={bench_id}" if "?" in base_path else f"{base_path}?bench_id={bench_id}" if bench_id else base_path
        return (
            f"{dt.strftime('%Y-%m-%d')} {dt.strftime('%H:%M:%S')} "
            f"{self._ip(0.4)} {self.rng.choice(methods)} {p} "
            f"{self.rng.choice(codes)} {self.rng.randint(100, 500000)} "
            f"{self._ip(0.1)} Mozilla/5.0 -"
        )

    # ── Bulk Generation (100% Authentic Enterprise & Loghub Data) ────

    def generate(self, count: int, format_filter: str | None = None,
                 with_ids: bool = True, start_id: int = 0) -> List[str]:
        """Generate `count` authentic enterprise log lines with embedded deterministic IDs.

        Pulls from 100% actual enterprise log files (Cisco, Check Point, ModSecurity,
        FortiGate, W3C, QRadar, Windows DNS, and Loghub datasets).
        """
        from benchmarks.real_data_feeder import get_real_data_pool
        pool = get_real_data_pool()
        lines, _ = pool.get_real_stream(
            count=count,
            seed=self.seed,
            with_ids=with_ids,
            start_id=start_id,
            format_filter=format_filter,
        )
        return lines

    def generate_with_ids(self, count: int, start_id: int = 0,
                          format_filter: str | None = None) -> tuple[List[str], List[str]]:
        """Generate real lines and return (lines, expected_ids) for zero-loss accounting."""
        from benchmarks.real_data_feeder import get_real_data_pool
        pool = get_real_data_pool()
        return pool.get_real_stream(
            count=count,
            seed=self.seed,
            with_ids=True,
            start_id=start_id,
            format_filter=format_filter,
        )

    def generate_to_file(self, count: int, filepath: str,
                          format_filter: str | None = None) -> dict:
        """Generate log lines and write them to a file.

        Returns:
            Summary dict with count, file size, generation time.
        """
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        t0 = time.perf_counter()
        lines = self.generate(count, format_filter)
        gen_time = time.perf_counter() - t0

        t_write = time.perf_counter()
        with open(filepath, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")
        write_time = time.perf_counter() - t_write

        file_size = os.path.getsize(filepath)

        return {
            "count": count,
            "filepath": os.path.abspath(filepath),
            "file_size_bytes": file_size,
            "file_size_mb": round(file_size / (1024 * 1024), 2),
            "generation_time_sec": round(gen_time, 3),
            "write_time_sec": round(write_time, 3),
            "seed": self.seed,
            "format_filter": format_filter or "mixed",
        }
