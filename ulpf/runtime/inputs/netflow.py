"""
NetFlow v5 / v9 and IPFIX (v10) collector over UDP.

Flow records have no textual "original line": a UDP packet carries many
binary flows. Each decoded flow is journaled as compact JSON (exporter,
version, template, every field by its standard name), so it is hashed,
sealed and retrievable like any other record.

Templates (v9 / IPFIX) are kept per (exporter, observation domain, template
ID) and persisted, so data sets that arrive right after a restart decode
without waiting for the exporter to resend its templates. Data that arrives
for an unknown template is counted, not guessed.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import struct
import threading
import time

import orjson

from ulpf.runtime.inputs.base import Input, udp_socket

logger = logging.getLogger(__name__)

PROTO = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 51: "ah", 58: "ipv6-icmp", 132: "sctp"}

# IANA IPFIX information elements (and the NetFlow v9 ids they share)
IE = {
    1: "bytes", 2: "packets", 3: "flows", 4: "protocol", 5: "tos", 6: "tcp_flags", 7: "src_port",
    8: "src_ip", 9: "src_mask", 10: "input_if", 11: "dst_port", 12: "dst_ip", 13: "dst_mask",
    14: "output_if", 15: "next_hop", 16: "src_as", 17: "dst_as", 18: "bgp_next_hop",
    21: "last_switched", 22: "first_switched", 23: "bytes_out", 24: "packets_out", 27: "src_ip",
    28: "dst_ip", 29: "src_mask", 30: "dst_mask", 32: "icmp_type", 34: "sampling_interval",
    35: "sampling_algorithm", 52: "min_ttl", 53: "max_ttl", 56: "src_mac", 57: "dst_mac",
    58: "vlan_id", 59: "post_vlan_id", 60: "ip_version", 61: "direction", 62: "next_hop",
    80: "dst_mac", 81: "src_mac", 85: "bytes_total", 86: "packets_total", 136: "flow_end_reason",
    148: "flow_id", 150: "flow_start_seconds", 151: "flow_end_seconds",
    152: "flow_start_ms", 153: "flow_end_ms", 154: "flow_start_us", 155: "flow_end_us",
    176: "icmp_type", 177: "icmp_code", 225: "nat_src_ip", 226: "nat_dst_ip",
    227: "nat_src_port", 228: "nat_dst_port", 233: "firewall_event",
}
_MAX_TIME = 32536850400       # 3001-01-01T00:00:00Z: the end of Windows' gmtime range
_ADDR4 = {8, 12, 15, 18, 225, 226}
_ADDR6 = {27, 28, 62, 63}
_MAC = {56, 57, 80, 81}


def _value(ie: int, data: bytes):
    if ie in _ADDR4 and len(data) == 4:
        return str(ipaddress.IPv4Address(data))
    if ie in _ADDR6 and len(data) == 16:
        return str(ipaddress.IPv6Address(data))
    if ie in _MAC and len(data) == 6:
        return ":".join(f"{b:02x}" for b in data)
    if len(data) <= 8:
        return int.from_bytes(data, "big")
    return data.hex()


def _finish(rec: dict, unix_secs: int, sys_uptime_ms: int | None) -> dict:
    """Absolute ISO times, protocol name."""
    def iso(sec: float) -> str:
        # time.gmtime's range differs by platform (Windows: 1970..3000); one range everywhere,
        # and a packet with a time outside it is rejected, not a crash of the input
        if not 0 <= sec < _MAX_TIME:
            raise ValueError(f"flow time {sec} out of range")
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(sec)) + f".{int(sec % 1 * 1000):03d}Z"
    for a, b in (("first_switched", "start"), ("last_switched", "end")):
        if a in rec and sys_uptime_ms is not None:
            rec[b] = iso(unix_secs - (sys_uptime_ms - rec.pop(a)) / 1000.0)
    for a, b, div in (("flow_start_seconds", "start", 1), ("flow_end_seconds", "end", 1),
                      ("flow_start_ms", "start", 1000), ("flow_end_ms", "end", 1000),
                      ("flow_start_us", "start", 1e6), ("flow_end_us", "end", 1e6)):
        if a in rec:
            rec[b] = iso(rec.pop(a) / div)
    if isinstance(rec.get("protocol"), int):
        rec["protocol_number"] = rec["protocol"]
        rec["protocol"] = PROTO.get(rec["protocol"], str(rec["protocol"]))
    rec.setdefault("timestamp", rec.get("end") or iso(unix_secs))
    return rec


class FlowDecoder:
    def __init__(self, state_path: str | None = None):
        self.templates: dict[str, list[tuple[int, int]]] = {}
        self.state_path = state_path
        self.unknown_template = 0
        self._dirty = False
        if state_path and os.path.exists(state_path):
            try:
                with open(state_path, "r", encoding="utf-8") as f:
                    self.templates = {k: [tuple(x) for x in v] for k, v in json.load(f).items()}
            except (OSError, ValueError):
                self.templates = {}

    def save(self) -> None:
        if self.state_path and self._dirty:
            tmp = self.state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.templates, f)
            os.replace(tmp, self.state_path)
            self._dirty = False

    def decode(self, data: bytes, exporter: str) -> list[dict]:
        if len(data) < 4:
            return []
        version = struct.unpack("!H", data[:2])[0]
        if version == 5:
            return self._v5(data, exporter)
        if version == 9:
            return self._v9(data, exporter)
        if version == 10:
            return self._ipfix(data, exporter)
        raise ValueError(f"unsupported NetFlow version {version}")

    # ---- v5 ----------------------------------------------------------
    def _v5(self, data: bytes, exporter: str) -> list[dict]:
        count, uptime, secs = struct.unpack("!HII", data[2:12])
        out = []
        for i in range(count):
            off = 24 + i * 48
            r = data[off:off + 48]
            if len(r) < 48:
                break
            (src, dst, nh, inp, outp, pkts, octets, first, last, sport, dport, _p1, flags, prot, tos,
             sas, das, smask, dmask) = struct.unpack("!4s4s4sHHIIIIHHBBBBHHBB", r[:46])
            rec = {"netflow_version": 5, "exporter": exporter, "src_ip": str(ipaddress.IPv4Address(src)),
                   "dst_ip": str(ipaddress.IPv4Address(dst)), "next_hop": str(ipaddress.IPv4Address(nh)),
                   "input_if": inp, "output_if": outp, "packets": pkts, "bytes": octets,
                   "first_switched": first, "last_switched": last, "src_port": sport, "dst_port": dport,
                   "tcp_flags": flags, "protocol": prot, "tos": tos, "src_as": sas, "dst_as": das,
                   "src_mask": smask, "dst_mask": dmask}
            out.append(_finish(rec, secs, uptime))
        return out

    # ---- v9 ----------------------------------------------------------
    def _v9(self, data: bytes, exporter: str) -> list[dict]:
        _count, uptime, secs, _seq, source_id = struct.unpack("!HIIII", data[2:20])
        off, out = 20, []
        while off + 4 <= len(data):
            fs_id, length = struct.unpack("!HH", data[off:off + 4])
            if length < 4:
                break
            body = data[off + 4:off + length]
            if fs_id == 0:
                p = 0
                while p + 4 <= len(body):
                    tid, n = struct.unpack("!HH", body[p:p + 4])
                    fields = [struct.unpack("!HH", body[p + 4 + 4 * k:p + 8 + 4 * k]) for k in range(n)]
                    self._set_template(f"{exporter}|{source_id}|{tid}", fields)
                    p += 4 + 4 * n
            elif fs_id == 1:
                p = 0
                while p + 6 <= len(body):     # options template: scope + option fields, kept for decoding
                    tid, scope_len, opt_len = struct.unpack("!HHH", body[p:p + 6])
                    n = (scope_len + opt_len) // 4
                    fields = [struct.unpack("!HH", body[p + 6 + 4 * k:p + 10 + 4 * k]) for k in range(n)]
                    self._set_template(f"{exporter}|{source_id}|{tid}", fields, options=True)
                    p += 6 + scope_len + opt_len
            elif fs_id >= 256:
                out += self._data(body, f"{exporter}|{source_id}|{fs_id}", exporter, 9, secs, uptime)
            off += length
        return out

    # ---- IPFIX -------------------------------------------------------
    def _ipfix(self, data: bytes, exporter: str) -> list[dict]:
        _length, export_time, _seq, domain = struct.unpack("!HIII", data[2:16])
        off, out = 16, []
        while off + 4 <= len(data):
            set_id, length = struct.unpack("!HH", data[off:off + 4])
            if length < 4:
                break
            body = data[off + 4:off + length]
            if set_id in (2, 3):
                p = 0
                while p + 4 <= len(body):
                    tid, n = struct.unpack("!HH", body[p:p + 4])
                    p += 4
                    if set_id == 3:
                        p += 2               # scope field count
                    fields = []
                    for _ in range(n):
                        ie, ln = struct.unpack("!HH", body[p:p + 4])
                        p += 4
                        if ie & 0x8000:      # enterprise-specific element: skip the PEN
                            p += 4
                            ie = 0x10000 | (ie & 0x7FFF)
                        fields.append((ie, ln))
                    self._set_template(f"{exporter}|{domain}|{tid}", fields, options=set_id == 3)
                    if len(body) - p < 4:
                        break
            elif set_id >= 256:
                out += self._data(body, f"{exporter}|{domain}|{set_id}", exporter, 10, export_time, None)
            off += length
        return out

    def _set_template(self, key: str, fields: list, options: bool = False) -> None:
        fields = [(int(a), int(b)) for a, b in fields]
        if self.templates.get(key) != fields:
            self.templates[key] = fields
            self._dirty = True

    def _data(self, body: bytes, key: str, exporter: str, version: int, secs: int, uptime) -> list[dict]:
        tpl = self.templates.get(key)
        if tpl is None:
            self.unknown_template += 1
            return []
        out = []
        fixed = sum(ln for _, ln in tpl if ln != 65535)
        p = 0
        while len(body) - p >= max(fixed, 1):
            rec = {"netflow_version": version, "exporter": exporter, "template_id": int(key.rsplit("|", 1)[1])}
            for ie, ln in tpl:
                if ln == 65535:      # IPFIX variable length
                    ln = body[p]
                    p += 1
                    if ln == 255:
                        ln = struct.unpack("!H", body[p:p + 2])[0]
                        p += 2
                raw = body[p:p + ln]
                p += ln
                name = IE.get(ie, f"ie_{ie}" if ie < 0x10000 else f"pen_ie_{ie & 0xFFFF}")
                rec[name] = _value(ie, raw)
            out.append(_finish(rec, secs, uptime))
            if fixed == 0:
                break
        return out


class NetflowInput(Input):
    def run(self, stop: threading.Event) -> None:
        o = self.opts
        dec = FlowDecoder(os.path.join(self.ctx.data_dir, f"netflow_templates_{self.name}.json"))
        sock = udp_socket(o["host"], o["port"])
        self.bound_port = sock.getsockname()[1]
        last_save = time.monotonic()
        try:
            while not stop.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                except (socket.timeout, ConnectionResetError):
                    data = None
                if data:
                    if not self.filter.allowed(addr[0]):
                        self.stats.dropped_denied += 1
                        continue
                    try:
                        flows = dec.decode(data, addr[0])
                    except (ValueError, struct.error, IndexError, OverflowError, OSError, TypeError) as e:
                        self.stats.errors += 1
                        self.stats.last_error = f"{addr[0]}: {e}"
                        continue
                    if flows:
                        self.accept(addr[0], [orjson.dumps(f) for f in flows], block=False)
                if time.monotonic() - last_save > 5:
                    dec.save()
                    last_save = time.monotonic()
        finally:
            dec.save()
            sock.close()

    def describe(self) -> dict:
        return {**super().describe(), "bound_port": getattr(self, "bound_port", None)}
