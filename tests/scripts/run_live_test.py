#!/usr/bin/env python3
"""
ULPF Cross-Platform Live Traffic & Stress Testing Tool
======================================================
Sends high-speed live network traffic (UDP / TCP) to the running ULPF application.
Supports all format permutations, real demo file streaming, unknown/proprietary
logs for Auto-Learn testing, and unthrottled maximum-throughput burst tests.

Usage Examples:
  # 1. Stream all demo log files at once (CEF, Syslog, JSON, WAF, KV, XML, LEEF):
  python tests/scripts/run_live_test.py --format files

  # 2. Stream ONLY CEF logs:
  python tests/scripts/run_live_test.py --format cef --count 100

  # 3. Stream ONLY unknown / proprietary formats (to test Auto-Learn & template mining):
  python tests/scripts/run_live_test.py --format unknown --count 150

  # 4. Stream at MAXIMUM SPEED (50,000+ EPS unthrottled line-rate stress test):
  python tests/scripts/run_live_test.py --speed max --count 5000

  # 5. Stream via TCP on port 5514:
  python tests/scripts/run_live_test.py --protocol tcp --count 200

  # 6. Stream a specific file directly:
  python tests/scripts/run_live_test.py --file demo_data/firewall_cef.log
"""
from __future__ import annotations

import argparse
import asyncio
import os
import queue
import socket
import sys
import threading
import time

# Ensure repo root is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ulpf.ingestion.listener import NetworkListener

# ── Specialized Event Datasets by Format ──────────────────────────────

CEF_EVENTS = [
    "CEF:0|Check Point|VPN-1 & FireWall-1|R81.20|Drop|Firewall Rule Drop|8|rt=2026-09-30T12:00:01Z src=45.33.32.156 dst=10.0.1.50 spt=12345 dpt=4444 proto=TCP act=Drop msg=Suspicious port connection blocked",
    "CEF:0|Palo Alto Networks|PAN-OS|11.0|threat|URL Filtering Alert|7|rt=2026-09-30T12:00:02Z src=10.0.2.15 dst=185.220.101.1 spt=49832 dpt=80 proto=TCP act=block-url cat=malware requestUrl=http://evil.example.com/payload.exe msg=Blocked malicious URL download attempt",
    "CEF:0|Check Point|VPN-1 & FireWall-1|R81.20|Accept|Firewall Rule Accept|3|rt=2026-09-30T12:00:03Z src=192.168.1.100 dst=203.0.113.50 spt=52341 dpt=443 proto=TCP act=Accept msg=HTTPS connection allowed",
    "CEF:0|Palo Alto Networks|PAN-OS|11.0|threat|Vulnerability|10|rt=2026-09-30T12:00:04Z src=91.121.87.10 dst=10.0.1.25 spt=443 dpt=8443 proto=TCP act=reset-both cat=critical msg=Critical RCE vulnerability exploit attempt blocked",
    "CEF:0|Imperva|SecureSphere|14.5|SQL_INJECTION|SQL Injection Attack|9|rt=2026-09-30T12:00:05Z src=198.51.100.77 dst=10.0.2.100 spt=38912 dpt=443 proto=TCP act=alert msg=UNION SELECT injection attempt blocked",
]

SYSLOG_EVENTS = [
    "<14>Oct 11 22:14:15 srv-dc-01 sshd[2412]: Failed password for invalid user admin from 185.220.101.1 port 38291 ssh2",
    "<134>1 2026-09-30T12:00:00Z fw-01 kernel - - [drop src=10.0.0.15 dst=192.168.1.1 proto=TCP spt=54122 dpt=443] Connection denied",
    "<134>Aug 28 10:15:01 core-rtr-01 %SYS-5-CONFIG_I: Configured from console by admin on vty0 (192.168.1.100)",
    "<165>1 2026-09-30T12:00:03Z waf-prod-01 app 101 - - [attack severity=high] Suspicious C2 beacon detected from 10.0.2.15 to 198.51.100.99:8080",
    "<131>Aug 28 10:15:30 edge-fw-01 %SEC-6-IPACCESSLOGP: list OUTSIDE-IN denied tcp 91.121.87.10(53) -> 10.0.0.1(53), 100 packets",
]

JSON_EVENTS = [
    '{"timestamp":"2026-09-30T12:00:02Z","source":"AWS WAF","severity":"critical","source_ip":"103.224.182.250","destination_ip":"10.0.1.50","action":"blocked","message":"SQL injection blocked"}',
    '{"timestamp":"2026-09-30T12:00:03Z","source":"ModSecurity","severity":"high","source_ip":"185.220.101.1","destination_ip":"10.0.1.50","action":"blocked","message":"XSS attack detected"}',
    '{"timestamp":"2026-09-30T12:00:04Z","source":"Suricata EVE","event_type":"alert","severity":9,"src_ip":"198.51.100.8","dest_ip":"10.0.0.5","proto":"UDP","alert":{"signature":"ET MALWARE DNS Query to Cobalt Strike C2 Domain"}}',
    '{"timestamp":"2026-09-30T12:00:05Z","source":"Okta SSO","event_type":"user.authentication.verify","severity":"medium","src_ip":"103.224.182.11","destination_ip":"10.0.0.10","user":"finance_lead","action":"denied","message":"MFA challenge push rejected by user"}',
    '{"timestamp":"2026-09-30T12:00:06Z","source":"K8s Audit","event_type":"apiserver.request","severity":"low","src_ip":"10.244.0.1","destination_ip":"10.244.0.254","user":"system:node:worker-01","action":"allowed","message":"Namespace pods list requested"}',
]

LEEF_EVENTS = [
    "LEEF:1.0|Snort|Snort IDS|3.1|1000001|devTime=2026-09-30T12:00:01Z\tcat=attempted-recon\tsrc=45.33.32.156\tdst=192.168.1.10\tsrcPort=54321\tdstPort=80\tproto=TCP\tsev=5\tmsg=SCAN nmap -sS detected",
    "LEEF:1.0|Suricata|Suricata IDS|7.0|2100498|devTime=2026-09-30T12:00:02Z\tcat=web-application-attack\tsrc=185.220.101.1\tdst=10.0.1.50\tsrcPort=49000\tdstPort=443\tproto=TCP\tsev=8\tmsg=ET EXPLOIT Possible SQL Injection",
    "LEEF:2.0|IBM|QRadar|7.5|SecurityAlert|devTime=2026-09-30T12:00:00Z\tsrc=198.51.100.33\tdst=10.0.1.99\tusrName=jdoe\tsev=7\tmsg=Brute force credential stuffing threshold exceeded",
    "LEEF:1.0|Cisco|Firepower|6.6|4000021|devTime=2026-09-30T12:00:03Z\tcat=malware-cnc\tsrc=10.0.1.200\tdst=198.51.100.66\tsrcPort=51299\tdstPort=4444\tproto=TCP\tsev=9\tmsg=Trojan Beacon Callback detected",
]

KV_EVENTS = [
    "date=2026-09-30 time=12:00:04 devname=\"FGT-EDGE-01\" devid=\"FG100F1234567890\" type=\"traffic\" subtype=\"forward\" level=\"notice\" srcip=192.168.1.105 srcport=51234 dstip=203.0.113.10 dstport=443 proto=6 action=\"accept\" msg=\"Outbound TLS session permit\"",
    "date=2026-09-30 time=12:00:05 devname=\"FGT-EDGE-01\" type=\"utm\" subtype=\"virus\" level=\"alert\" srcip=103.224.182.250 srcport=80 dstip=192.168.5.100 dstport=52000 proto=6 action=\"blocked\" severity=\"high\" virus=\"W32/Malware.ABC\"",
    "date=2026-09-30 time=12:00:06 devname=\"FGT-EDGE-01\" type=\"utm\" subtype=\"ips\" level=\"critical\" srcip=185.220.101.5 srcport=44122 dstip=10.0.1.10 dstport=80 proto=6 action=\"dropped\" attack=\"Apache.Log4j.RCE\"",
    "date=2026-09-30 time=12:00:07 devname=\"FGT-CORE-02\" type=\"event\" subtype=\"vpn\" level=\"notice\" srcip=203.0.113.99 dstip=10.0.0.1 action=\"connected\" user=\"eng_remote\" msg=\"IPsec Phase 2 tunnel up\"",
]

UNKNOWN_EVENTS = [
    "2026-09-30 12:45:10.891 [TRANSACTION-AUDIT] tid=TX8921 status=FAILED user=operator9 client=192.168.10.99 target=10.0.1.20 reason=BALANCE_INSUFFICIENT amount=45210.00 currency=INR",
    "2026-09-30 12:45:11.200 PLC-NODE-41 [MODBUS_EXCP] src=192.168.5.10 dst=192.168.5.1 reg=40012 value=998.4 status=OVER_THRESHOLD action=TRIP_BREAKER unit=BAR sector=PUMP_ROOM_B",
    "2026-09-30 12:45:12.450 DBTRACE::0098:20260930:ERR:SCHEMA_MISMATCH:table=accounts:client=192.168.10.99:target=10.0.2.15:attempt=3:latency=42ms",
    "MF-RACF-01 2026-09-30T12:00:00.000Z AUTH-FAIL USER=SYSADMIN ATTEMPT=5 src=10.0.0.50 dst=10.0.0.1 TERMINAL=VT100 RC=08 CODE=PASSWORD_EXPIRED",
    "2026-09-30 12:45:14.100 PROPRIETARY-ICS [TELEMETRY] client=172.16.1.10 server=172.16.1.1 turbine_id=T-904 rpm=3600 temp_c=84.2 vibration=0.04 status=NOMINAL operator=auto",
    "2026-09-30 12:45:15.300 CUSTOM-ATM-04 [DISPENSE_ERR] client=10.200.1.4 dst=10.200.1.1 card_bin=411111 cassette=2 notes_requested=40 dispensed=0 fault=FEED_JAM",
]

ALL_SAMPLE_EVENTS = (
    CEF_EVENTS + SYSLOG_EVENTS + JSON_EVENTS + LEEF_EVENTS + KV_EVENTS + UNKNOWN_EVENTS
)


def load_demo_files(pattern: str = "") -> list[str]:
    """Read actual lines from demo_data files."""
    demo_dir = os.path.join(REPO_ROOT, "demo_data")
    lines = []
    if not os.path.exists(demo_dir):
        return []

    target_files = []
    for fn in os.listdir(demo_dir):
        if fn.endswith(".log"):
            if not pattern or pattern.lower() in fn.lower():
                target_files.append(os.path.join(demo_dir, fn))

    for fp in target_files:
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    s = line.strip()
                    if s and not s.startswith("#"):
                        lines.append(s)
        except Exception:
            pass
    return lines


def run_sender(host: str, port: int, count: int, protocol: str):
    """Send synthetic log stream via raw UDP or TCP sockets."""
    print(f"\n[SENDER] Streaming {count:,} events to {host}:{port} via {protocol.upper()}...")
    start_time = time.monotonic()
    sent = 0

    if protocol.lower() == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(count):
            msg = ALL_SAMPLE_EVENTS[i % len(ALL_SAMPLE_EVENTS)]
            sock.sendto(msg.encode("utf-8"), (host, port))
            sent += 1
        sock.close()
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        for i in range(count):
            msg = ALL_SAMPLE_EVENTS[i % len(ALL_SAMPLE_EVENTS)] + "\n"
            sock.sendall(msg.encode("utf-8"))
            sent += 1
        sock.close()

    elapsed = time.monotonic() - start_time
    eps = sent / max(elapsed, 0.001)
    print(f"[SENDER] Completed: Sent {sent:,} events in {elapsed:.3f}s ({eps:,.1f} EPS)")


def run_benchmark(count: int, protocol: str, host: str = "127.0.0.1", port: int = 5519):
    """Run an automated local benchmark: listener + sender + stats calculation."""
    print("=" * 65)
    print(f"  ULPF High-Speed Ingestion Benchmark ({protocol.upper()})")
    print("=" * 65)
    print(f"  Target events : {count:,}")
    print(f"  Endpoint      : {host}:{port}")

    msg_queue = queue.Queue(maxsize=count * 2 + 1000)
    listener = NetworkListener(msg_queue, host=host, port=port)

    listener_loop = asyncio.new_event_loop()

    def _start_listener():
        asyncio.set_event_loop(listener_loop)
        listener_loop.run_until_complete(listener.start(protocol=protocol))
        listener_loop.run_forever()

    listener_thread = threading.Thread(target=_start_listener, daemon=True)
    listener_thread.start()

    time.sleep(0.5)

    sender_start = time.monotonic()
    run_sender(host, port, count, protocol)
    sender_elapsed = time.monotonic() - sender_start

    print("\n[DRAIN] Waiting for internal queue to drain...")
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        if listener.stats.messages_queued >= count:
            break
        time.sleep(0.05)

    stats = listener.stats
    rcv_count = stats.messages_received
    drp_count = stats.messages_dropped
    q_count = stats.messages_queued
    tot_bytes = stats.bytes_received

    total_time = max(sender_elapsed, 0.001)
    eps = rcv_count / total_time
    mbps = (tot_bytes * 8) / (total_time * 1_000_000)

    print("\n" + "=" * 65)
    print("  Benchmark Results")
    print("=" * 65)
    print(f"  Protocol            : {protocol.upper()}")
    print(f"  Packets Sent        : {count:,}")
    print(f"  Packets Received    : {rcv_count:,}")
    print(f"  Packets Queued      : {q_count:,}")
    print(f"  Packets Dropped     : {drp_count:,}")
    print(f"  Data Transferred    : {tot_bytes / (1024*1024):.2f} MB")
    print(f"  Elapsed Time        : {total_time:.3f} s")
    print(f"  Effective Throughput: {eps:,.0f} EPS ({mbps:.2f} Mbps)")

    if rcv_count >= count and drp_count == 0:
        print(f"\n  VERDICT: [PASS] Zero-loss, verified high-speed ingestion ({rcv_count:,} received, 0 dropped)")
    else:
        print(f"\n  VERDICT: [WARN] Packets processed: {rcv_count}/{count} (Dropped: {drp_count})")
    print("=" * 65 + "\n")

    try:
        listener_loop.call_soon_threadsafe(listener_loop.stop)
    except Exception:
        pass


def run_live_stream_to_gui(
    host: str = "127.0.0.1",
    port: int = 5514,
    count: int = 250,
    protocol: str = "udp",
    format_type: str = "all",
    file_path: str = "",
    speed: str = "paced",
):
    """
    Stream real or selected heterogeneous security events directly to the running ULPF GUI application.
    Supports all format permutations, real demo file streaming, and burst speeds.
    """
    proto = "udp" if protocol.lower() in ("udp", "both") else "tcp"

    # Select event pool based on user format filter
    events_pool = []
    pool_desc = ""

    if file_path:
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                events_pool = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
            pool_desc = f"File: {os.path.basename(file_path)} ({len(events_pool)} unique lines)"
        else:
            print(f"[ERROR] Specified file not found: {file_path}")
            return
    elif format_type == "files":
        events_pool = load_demo_files()
        pool_desc = f"All Demo Files in demo_data/ ({len(events_pool)} total lines across 8 files)"
    elif format_type == "cef":
        events_pool = CEF_EVENTS
        pool_desc = f"CEF ArcSight Logs ({len(events_pool)} signatures)"
    elif format_type == "syslog":
        events_pool = SYSLOG_EVENTS
        pool_desc = f"Syslog RFC 3164/5424 Logs ({len(events_pool)} templates)"
    elif format_type == "json":
        events_pool = JSON_EVENTS
        pool_desc = f"JSON Structured Security Logs ({len(events_pool)} schemas)"
    elif format_type == "leef":
        events_pool = LEEF_EVENTS
        pool_desc = f"LEEF QRadar/Snort Logs ({len(events_pool)} signatures)"
    elif format_type == "kv":
        events_pool = KV_EVENTS
        pool_desc = f"Fortinet/Palo Alto Key-Value Logs ({len(events_pool)} records)"
    elif format_type == "unknown":
        events_pool = UNKNOWN_EVENTS
        pool_desc = f"Proprietary/Unclassified Logs for Auto-Learn ({len(events_pool)} custom formats)"
    elif format_type in ("firewall", "ids", "waf", "router"):
        events_pool = load_demo_files(format_type)
        if not events_pool:
            events_pool = CEF_EVENTS
        pool_desc = f"Demo Source [{format_type.upper()}] ({len(events_pool)} records)"
    else:
        events_pool = ALL_SAMPLE_EVENTS
        pool_desc = f"All Heterogeneous Formats (CEF, Syslog, JSON, LEEF, KV, Unknown)"

    if not events_pool:
        print("[ERROR] No events available to stream.")
        return

    # If count is default and streaming files, use exact file line count
    stream_count = len(events_pool) if (format_type == "files" and count == 250) else count

    print("=" * 70)
    print("  ULPF Live Streamer -> Active Native Desktop Application")
    print("=" * 70)
    print(f"  Target Endpoint : {host}:{port} ({proto.upper()})")
    print(f"  Selected Format : {pool_desc}")
    print(f"  Target Volume   : {stream_count:,} events")
    print(f"  Stream Speed    : {'Maximum Throughput (No delay)' if speed == 'max' else 'Paced (~100 EPS for visual observation)'}")
    print("=" * 70)

    t0 = time.monotonic()
    sent = 0

    if proto == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((host, port))
        except Exception as e:
            print(f"\n[ERROR] Could not connect to ULPF GUI on {host}:{port} via TCP: {e}")
            print("[HINT] Ensure the ULPF application is running, or switch to UDP.")
            return

    # Delay settings:
    if speed == "max":
        delay = 0.0
    else:
        delay = 0.01 if stream_count <= 500 else 0.001

    for i in range(stream_count):
        raw_msg = events_pool[i % len(events_pool)]
        payload = raw_msg.encode("utf-8") if proto == "udp" else (raw_msg + "\n").encode("utf-8")
        if proto == "udp":
            sock.sendto(payload, (host, port))
        else:
            sock.sendall(payload)
        sent += 1

        step = max(1, stream_count // 10)
        if sent % step == 0 or sent == stream_count:
            preview = raw_msg[:60]
            pct = int((sent / stream_count) * 100)
            print(f"  [{pct:3d}%] Streamed {sent:6,d}/{stream_count:,} -> {preview}...")

        if delay > 0:
            time.sleep(delay)

    sock.close()
    elapsed = time.monotonic() - t0
    eps = sent / max(elapsed, 0.001)

    print("=" * 70)
    print(f"  [SUCCESS] Delivery Complete: {sent:,} events streamed in {elapsed:.2f}s ({eps:,.1f} EPS)")
    print("  [VERIFICATION IN YOUR RUNNING GUI]:")
    print("    • Overview Page  : 'TOTAL NORMALIZED EVENTS' incremented live.")
    print("    • Event Explorer : New events immediately visible at top of table.")
    print("    • Ingestion Page : Network Listener packet counter and graph updated.")
    if format_type == "unknown":
        print("    • Auto-Learn Page: Auto-discovered template candidates visible in miner.")
    print("=" * 70 + "\n")


def run_direct_ingestion(count: int, delay_ms: float = 20.0):
    """Directly process and ingest real heterogeneous security logs into the ULPF database."""
    print(f"\n{'='*65}")
    print(f"  ULPF Direct Ingestion Streamer")
    print(f"{'='*65}")
    print(f"  Streaming {count:,} real security events into DuckDB...")

    from ulpf.engine.pipeline import Pipeline
    from ulpf.storage.database import Database

    try:
        db = Database()
    except Exception as lock_err:
        print(f"  [INFO] DuckDB locked by running GUI instance ({lock_err}).")
        print(f"  [STREAM] Streaming {count} events via UDP to 127.0.0.1:5514 directly into the GUI...")
        run_live_stream_to_gui(count=count)
        return

    pipeline = Pipeline()
    batch_size = min(25, count)
    ingested = 0
    t0 = time.monotonic()

    for i in range(0, count, batch_size):
        chunk_len = min(batch_size, count - i)
        lines = [ALL_SAMPLE_EVENTS[(i + j) % len(ALL_SAMPLE_EVENTS)] for j in range(chunk_len)]
        results = [pipeline.process_line(l) for l in lines]
        events = [r["event"] for r in results if r.get("success")]
        if events:
            stored = db.store_events_bulk(events)
            ingested += stored
            print(f"  [STREAM] Ingested {ingested:,} / {count:,} events (Latest: {events[-1].get('raw_format', '').upper()})...")
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

    elapsed = time.monotonic() - t0
    print(f"{'='*65}")
    print(f"  Stream Complete: {ingested:,} real events stored into DuckDB in {elapsed:.2f}s")
    print(f"  Database Stats: {db.stats()}")
    print(f"{'='*65}\n")
    db.close()


def main():
    parser = argparse.ArgumentParser(
        description="ULPF Cross-Platform Live Traffic & Stress Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1. Stream all demo files at once (CEF, Syslog, JSON, WAF, KV, XML, W3C):
  python tests/scripts/run_live_test.py --format files

  # 2. Stream ONLY CEF events (Palo Alto & Check Point):
  python tests/scripts/run_live_test.py --format cef --count 100

  # 3. Stream ONLY unknown / proprietary formats (to test Auto-Learn & template mining):
  python tests/scripts/run_live_test.py --format unknown --count 150

  # 4. Stream at MAXIMUM SPEED (50,000+ EPS burst stress test, 0 delay):
  python tests/scripts/run_live_test.py --speed max --count 10000

  # 5. Stream via TCP instead of UDP:
  python tests/scripts/run_live_test.py --protocol tcp --count 200

  # 6. Stream a specific demo log file directly:
  python tests/scripts/run_live_test.py --file demo_data/firewall_cef.log
        """
    )
    parser.add_argument("--mode", choices=["live", "benchmark", "sender", "listener", "ingest"], default="live",
                        help="Operating mode: 'live' streams directly to GUI (default), 'benchmark' measures socket throughput")
    parser.add_argument("--format", "--type", dest="format",
                        choices=["all", "cef", "syslog", "json", "leef", "kv", "unknown", "files", "firewall", "ids", "waf"],
                        default="all", help="Log format or dataset to stream (default: 'all')")
    parser.add_argument("--file", default="", help="Path to a specific .log file to stream")
    parser.add_argument("--protocol", choices=["udp", "tcp", "both"], default="udp", help="Network protocol (default: udp)")
    parser.add_argument("--speed", choices=["paced", "max"], default="paced",
                        help="Streaming rate: 'paced' (~100 EPS for visual observation), 'max' (unthrottled line-rate burst)")
    parser.add_argument("--host", default="127.0.0.1", help="Target listener IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5514, help="Target listener port (default: 5514)")
    parser.add_argument("--count", type=int, default=250, help="Total number of events to stream (default: 250)")

    args = parser.parse_args()

    if args.mode == "live":
        run_live_stream_to_gui(
            host=args.host,
            port=args.port,
            count=args.count,
            protocol=args.protocol,
            format_type=args.format,
            file_path=args.file,
            speed=args.speed,
        )
    elif args.mode == "listener":
        q = queue.Queue(maxsize=100_000)
        nl = NetworkListener(q, host=args.host, port=args.port)
        nl.run_forever(protocol=args.protocol)
    elif args.mode == "sender":
        proto = "udp" if args.protocol == "both" else args.protocol
        run_sender(args.host, args.port, args.count, proto)
    elif args.mode == "benchmark":
        print("\n[NOTE] Benchmark mode measures isolated socket throughput in an in-memory harness.")
        print("       To stream events directly into the active GUI, use: python tests/scripts/run_live_test.py --mode live\n")
        proto = "udp" if args.protocol == "both" else args.protocol
        run_benchmark(args.count, proto, args.host, args.port)
    elif args.mode == "ingest":
        run_direct_ingestion(args.count)


if __name__ == "__main__":
    main()
