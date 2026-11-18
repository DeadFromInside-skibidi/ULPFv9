#!/usr/bin/env python3
"""
ULPF Flood Log Generator
===========================
Generates high-volume synthetic log data for stress testing.

Features:
  - All 9 ULPF formats (syslog3164, syslog5424, CEF, LEEF, JSON, XML, CSV, KV, W3C)
  - Realistic attack scenarios (brute force, port scan, exfiltration, C2, SQLi)
  - Configurable volume (10K to 1M+ lines)
  - Can output to file or stream to stdout for pipe to netcat
  - Includes threat IOCs, high-severity events, and anomaly-triggering patterns

Usage:
  python3 generate_flood_logs.py --count 100000 --output ../live_output/flood_100k.log
  python3 generate_flood_logs.py --count 50000 --stream | nc -u 127.0.0.1 5514
  python3 generate_flood_logs.py --count 500000 --scenario brute_force --output ../live_output/brute_force.log
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime, timezone, timedelta

# ── Randomisers ──────────────────────────────────────────────────────────

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
    "Port scan detected from {src} — {n} ports in 10s",
    "Exploit attempt EternalBlue blocked from {src}",
    "Suspicious C2 beacon detected to {dst}:{dpt}",
    "Data exfiltration attempt: {bytes} bytes to {dst}",
    "Brute force authentication attack from {src} — {n} failures",
    "Malware download blocked: {src} → {dst} (payload.exe)",
    "DNS tunneling detected: {src} → {dst}",
    "Privilege escalation attempt by user admin from {src}",
    "Lateral movement detected: {src} → {dst} via SMB",
    "Ransomware indicator: file encryption pattern from {src}",
    "Spyware callback detected from compromised host {src}",
    "Critical RCE vulnerability exploit attempt from {src}",
    "Firewall rule violation: {src} → {dst}:{dpt}",
]


def _ip(threat_bias=0.3):
    if random.random() < threat_bias:
        return random.choice(THREAT_IPS)
    return random.choice(INTERNAL_IPS)

def _port():
    return random.choice(PORTS)

def _ts():
    dt = datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 3600))
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def _ts_syslog():
    dt = datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 3600))
    return dt.strftime("%b %d %H:%M:%S")

def _host():
    return random.choice(HOSTNAMES)

def _proto():
    return random.choice(PROTOCOLS)

def _act():
    return random.choice(ACTIONS)

def _sev():
    # Bias towards higher severity for stress testing
    return random.choices(range(0, 11), weights=[1,1,2,2,3,3,4,5,6,7,8])[0]

def _msg():
    src, dst = _ip(0.5), _ip(0.1)
    return random.choice(ATTACK_MSGS).format(
        src=src, dst=dst, spt=_port(), dpt=_port(),
        bytes=random.randint(10000, 5000000), n=random.randint(50, 5000)
    )

# ── Format Generators ────────────────────────────────────────────────────

def gen_syslog3164():
    pri = random.randint(0, 191)
    return f"<{pri}>{_ts_syslog()} {_host()} sshd[{random.randint(100,65535)}]: {_msg()}"

def gen_syslog5424():
    pri = random.randint(0, 191)
    return f"<{pri}>1 {_ts()} {_host()} auditd {random.randint(100,65535)} ID{random.randint(1,999)} - {_msg()}"

def gen_cef():
    src, dst = _ip(0.4), _ip(0.1)
    sev = _sev()
    vendors = [("Check Point", "VPN-1 & FireWall-1", "R81.20"),
               ("Palo Alto Networks", "PAN-OS", "11.0"),
               ("Fortinet", "FortiGate", "7.4")]
    v = random.choice(vendors)
    return (f"CEF:0|{v[0]}|{v[1]}|{v[2]}|{random.randint(100,999)}|"
            f"{_msg()[:50]}|{sev}|src={src} spt={_port()} dst={dst} dpt={_port()} "
            f"proto={_proto()} act={_act()} in={random.randint(64,50000)} "
            f"out={random.randint(64,50000)}")

def gen_leef():
    src, dst = _ip(0.4), _ip(0.1)
    return (f"LEEF:1.0|SecurityVendor|IDS|1.0|{random.randint(100,999)}|"
            f"src={src}\tsrcPort={_port()}\tdst={dst}\t"
            f"dstPort={_port()}\tproto={_proto()}\t"
            f"action={_act()}\tsev={_sev()}\tmsg={_msg()[:80]}")

def gen_json():
    src, dst = _ip(0.4), _ip(0.1)
    return json.dumps({
        "timestamp": _ts(), "source_ip": src, "source_port": _port(),
        "destination_ip": dst, "destination_port": _port(),
        "action": _act(), "protocol": _proto(), "severity": _sev(),
        "message": _msg(), "device": _host(),
        "category": random.choice(["firewall", "ids_ips", "authentication", "network", "threat"]),
        "bytes_in": random.randint(64, 50000), "bytes_out": random.randint(64, 50000),
    })

def gen_xml():
    src, dst = _ip(0.4), _ip(0.1)
    return (f'<Event timestamp="{_ts()}" severity="{_sev()}">'
            f'<Source ip="{src}" port="{_port()}"/>'
            f'<Destination ip="{dst}" port="{_port()}"/>'
            f'<Action>{_act()}</Action>'
            f'<Protocol>{_proto()}</Protocol>'
            f'<Message>{_msg()[:60]}</Message>'
            f'</Event>')

def gen_csv():
    src, dst = _ip(0.4), _ip(0.1)
    return (f"{_ts()},{src},{_port()},{dst},{_port()},"
            f"{_proto()},{_act()},{_sev()},{_host()},"
            f"{random.randint(64,50000)},{random.randint(64,50000)}")

def gen_kv():
    src, dst = _ip(0.4), _ip(0.1)
    return (f"date={_ts()} devname={_host()} "
            f"srcip={src} srcport={_port()} "
            f"dstip={dst} dstport={_port()} "
            f"proto={_proto()} action={_act()} "
            f"policyid={random.randint(1,100)} sentbyte={random.randint(100,500000)} "
            f"rcvdbyte={random.randint(100,500000)} "
            f"msg=\"{_msg()[:60]}\"")

def gen_w3c():
    dt = datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 3600))
    methods = ["GET", "POST", "PUT", "DELETE", "HEAD"]
    paths = ["/api/v1/data", "/login", "/admin", "/index.html", "/search?q=test",
             "/wp-admin", "/shell.php", "/cmd.exe", "/.env", "/etc/passwd"]
    codes = [200, 200, 200, 301, 403, 404, 500, 503]
    return (f"{dt.strftime('%Y-%m-%d')} {dt.strftime('%H:%M:%S')} "
            f"{_ip(0.4)} {random.choice(methods)} {random.choice(paths)} "
            f"{random.choice(codes)} {random.randint(100, 500000)} "
            f"{_ip(0.1)} Mozilla/5.0 -")

GENERATORS = {
    "syslog3164": gen_syslog3164, "syslog5424": gen_syslog5424,
    "cef": gen_cef, "leef": gen_leef, "json": gen_json,
    "xml": gen_xml, "csv": gen_csv, "kv": gen_kv, "w3c": gen_w3c,
}

# ── Scenario Generators (produce bursts with specific attack patterns) ───

def scenario_brute_force(count):
    """Generate brute-force attack pattern: many auth failures from same IP."""
    attacker = random.choice(THREAT_IPS)
    target = random.choice(INTERNAL_IPS)
    lines = []
    for i in range(count):
        ts = _ts_syslog()
        if random.random() < 0.8:  # 80% are brute force
            lines.append(f"<34>{ts} {_host()} sshd[{random.randint(1000,9999)}]: "
                        f"Failed password for root from {attacker} port {random.randint(30000,65000)} ssh2")
        else:
            lines.append(random.choice(list(GENERATORS.values()))())
    return lines

def scenario_port_scan(count):
    """Generate port scan pattern: one IP hitting many ports."""
    scanner = random.choice(THREAT_IPS)
    target = random.choice(INTERNAL_IPS)
    lines = []
    for i in range(count):
        if random.random() < 0.7:
            port = random.randint(1, 65535)
            sev = 5 if port < 1024 else 3
            lines.append(f"CEF:0|Palo Alto Networks|PAN-OS|11.0|scan|Port Scan|{sev}|"
                        f"src={scanner} dst={target} dpt={port} proto=TCP act=drop "
                        f"msg=Port scan attempt on port {port}")
        else:
            lines.append(random.choice(list(GENERATORS.values()))())
    return lines

def scenario_exfiltration(count):
    """Generate data exfiltration pattern: large outbound transfers."""
    insider = random.choice(INTERNAL_IPS)
    c2_server = random.choice(THREAT_IPS)
    lines = []
    for i in range(count):
        if random.random() < 0.6:
            big_bytes = random.randint(500000, 50000000)
            lines.append(json.dumps({
                "timestamp": _ts(), "source_ip": insider, "source_port": random.randint(30000,65000),
                "destination_ip": c2_server, "destination_port": random.choice([443, 8443, 4444]),
                "action": "allow", "protocol": "TCP", "severity": 9,
                "message": f"Large outbound transfer: {big_bytes} bytes to {c2_server}",
                "bytes_out": big_bytes, "bytes_in": random.randint(64, 500),
                "category": "threat", "device": _host(),
            }))
        else:
            lines.append(random.choice(list(GENERATORS.values()))())
    return lines

def scenario_kill_chain(count):
    """Generate full kill-chain attack: recon → exploit → install → C2 → exfil."""
    attacker = random.choice(THREAT_IPS)
    target = random.choice(INTERNAL_IPS)
    lines = []
    stages = [
        ("scan", "reconnaissance", 3, "Port scan detected — enumeration in progress"),
        ("probe", "reconnaissance", 4, "Service enumeration on target"),
        ("exploit", "exploitation", 8, "Exploit attempt CVE-2024-1234"),
        ("overflow", "exploitation", 9, "Buffer overflow attack on {target}"),
        ("install", "installation", 8, "Backdoor installation detected"),
        ("persist", "installation", 7, "Persistence mechanism established"),
        ("beacon", "command_and_control", 9, "C2 beacon callback to {attacker}"),
        ("c2", "command_and_control", 8, "Command and control channel active"),
        ("exfil", "exfiltration", 10, "Data exfiltration in progress — {bytes} bytes"),
        ("dump", "exfiltration", 10, "Database dump detected"),
    ]
    per_stage = max(count // len(stages), 1)
    for keyword, stage, sev, msg_tpl in stages:
        for _ in range(per_stage):
            msg = msg_tpl.format(target=target, attacker=attacker,
                                bytes=random.randint(100000, 5000000))
            fmt = random.choice(["cef", "syslog5424", "json", "kv"])
            if fmt == "cef":
                lines.append(f"CEF:0|SecurityVendor|IDS|1.0|{random.randint(100,999)}|"
                           f"{msg[:50]}|{sev}|src={attacker} dst={target} "
                           f"spt={_port()} dpt={_port()} proto=TCP act=detect")
            elif fmt == "syslog5424":
                lines.append(f"<{sev*16}>1 {_ts()} {_host()} ids {random.randint(100,9999)} "
                           f"ID{random.randint(1,999)} - {keyword} {msg}")
            elif fmt == "json":
                lines.append(json.dumps({
                    "timestamp": _ts(), "source_ip": attacker, "destination_ip": target,
                    "severity": sev, "message": f"{keyword}: {msg}",
                    "action": "detect", "category": "threat",
                    "source_port": _port(), "destination_port": _port(),
                }))
            else:
                lines.append(f"date={_ts()} devname={_host()} srcip={attacker} "
                           f"dstip={target} action=detect level={sev} msg=\"{keyword}: {msg[:60]}\"")
        # Add some noise between stages
        for _ in range(per_stage // 5 + 1):
            lines.append(random.choice(list(GENERATORS.values()))())
    return lines[:count]

SCENARIOS = {
    "mixed": None,  # default random mix
    "brute_force": scenario_brute_force,
    "port_scan": scenario_port_scan,
    "exfiltration": scenario_exfiltration,
    "kill_chain": scenario_kill_chain,
}


def generate_logs(count, scenario="mixed", seed=42):
    random.seed(seed)
    if scenario != "mixed" and scenario in SCENARIOS and SCENARIOS[scenario]:
        return SCENARIOS[scenario](count)
    # Default mixed: all formats randomly
    gens = list(GENERATORS.values())
    return [random.choice(gens)() for _ in range(count)]


def main():
    parser = argparse.ArgumentParser(description="ULPF Flood Log Generator")
    parser.add_argument("--count", "-n", type=int, default=100000,
                        help="Number of log lines to generate (default: 100000)")
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    parser.add_argument("--scenario", "-s", choices=list(SCENARIOS.keys()),
                        default="mixed", help="Attack scenario (default: mixed)")
    parser.add_argument("--stream", action="store_true",
                        help="Stream to stdout with slight delay (for piping to nc)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    start = time.time()
    lines = generate_logs(args.count, args.scenario, args.seed)
    gen_time = time.time() - start

    if args.stream:
        # Stream mode: write to stdout line by line (for piping to netcat)
        for line in lines:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
    elif args.output:
        os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")
        elapsed = time.time() - start
        print(f"Generated {len(lines):,} log lines in {gen_time:.2f}s", file=sys.stderr)
        print(f"Written to: {args.output}", file=sys.stderr)
        print(f"File size: {os.path.getsize(args.output) / 1048576:.2f} MB", file=sys.stderr)
        print(f"Scenario: {args.scenario}", file=sys.stderr)
    else:
        for line in lines:
            print(line)
        print(f"\n# Generated {len(lines):,} lines in {gen_time:.2f}s (scenario: {args.scenario})",
              file=sys.stderr)

if __name__ == "__main__":
    main()
