"""
Binary telemetry decoders for UAV / space / defence appliances (``telemetry`` on a syslog UDP input).

* ``mavlink``  MAVLink v1 (0xFE) and v2 (0xFD) frames: header, X.25 checksum with
               the message's CRC_EXTRA, and field decoding for HEARTBEAT,
               SYS_STATUS, GPS_RAW_INT, ATTITUDE, GLOBAL_POSITION_INT,
               COMMAND_LONG and STATUSTEXT; other messages keep their header
               and the payload as hex.
               v10: SET_MODE, PARAM_SET, COMMAND_INT and COMMAND_ACK, and **MAVLink v2
               message signing**: the 13-byte signature block is authenticated
               (SHA-256 over secret key + header + payload + CRC + link id +
               timestamp, first 48 bits) with per-system keys taken from environment
               variables, with per-stream timestamp replay protection. Unsigned,
               forged or replayed *command* messages (COMMAND_LONG/INT, SET_MODE,
               PARAM_SET) are flagged ``auth=rejected`` at critical severity.
* ``ccsds``    CCSDS Space Packet primary header (CCSDS 133.0-B): version, packet
               type, secondary-header flag, APID, sequence flags and count, and the
               data field (hex), with a length check. v10: the secondary header as
               ECSS PUS-C (ECSS-E-ST-70-41C) or PUS-A: service/subtype with names,
               message counter, source/destination id, CUC on-board time (TAI epoch
               1958 by default) and the CRC-16 packet error control.

Each frame becomes one ``key=value`` line for the pipeline (the key=value
parser maps it to the unified schema); the journal keeps the bytes received.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import os
import struct
import threading
import time

# msgid: (name, CRC_EXTRA, wire-order struct, field names)
_MAVLINK = {
    0: ("HEARTBEAT", 50, "<IBBBBB", ("custom_mode", "mav_type", "autopilot", "base_mode", "system_status",
                                     "mavlink_version")),
    1: ("SYS_STATUS", 124, "<IIIHHhHHHHHHb", ("sensors_present", "sensors_enabled", "sensors_health", "load",
                                             "voltage_battery_mv", "current_battery_ca", "drop_rate_comm",
                                             "errors_comm", "errors_count1", "errors_count2", "errors_count3",
                                             "errors_count4", "battery_remaining")),
    24: ("GPS_RAW_INT", 24, "<QiiiHHHHBB", ("time_usec", "lat_e7", "lon_e7", "alt_mm", "eph", "epv", "vel_cms",
                                            "cog_cdeg", "fix_type", "satellites_visible")),
    30: ("ATTITUDE", 39, "<Iffffff", ("time_boot_ms", "roll", "pitch", "yaw", "rollspeed", "pitchspeed",
                                      "yawspeed")),
    33: ("GLOBAL_POSITION_INT", 104, "<IiiiihhhH", ("time_boot_ms", "lat_e7", "lon_e7", "alt_mm", "relative_alt_mm",
                                                    "vx_cms", "vy_cms", "vz_cms", "hdg_cdeg")),
    76: ("COMMAND_LONG", 152, "<fffffffHBBB", ("param1", "param2", "param3", "param4", "param5", "param6", "param7",
                                              "command", "target_system", "target_component", "confirmation")),
    253: ("STATUSTEXT", 83, "<B50s", ("mav_severity", "text")),
    11: ("SET_MODE", 89, "<IBB", ("custom_mode", "target_system", "base_mode")),
    23: ("PARAM_SET", 168, "<fBB16sB", ("param_value", "target_system", "target_component", "param_id",
                                         "param_type")),
    75: ("COMMAND_INT", 158, "<ffffiifHBBBBB", ("param1", "param2", "param3", "param4", "x", "y", "z", "command",
                                                "target_system", "target_component", "frame", "current",
                                                "autocontinue")),
    77: ("COMMAND_ACK", 143, "<HBBiBB", ("command", "result", "progress", "result_param2", "target_system",
                                         "target_component")),
}
COMMAND_MSGS = frozenset((11, 23, 75, 76))     # messages that change vehicle state
_MAV_EPOCH = 1420070400                         # 2015-01-01T00:00:00Z: MAVLink signing timestamp epoch
_MAV_SEVERITY = ("emergency", "alert", "critical", "error", "warning", "notice", "info", "debug")


def x25_crc(data: bytes, crc: int = 0xFFFF) -> int:
    for b in data:
        tmp = b ^ (crc & 0xFF)
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


def _kv(pairs: list[tuple[str, object]]) -> str:
    out = []
    for k, v in pairs:
        if isinstance(v, float):
            v = f"{v:.6g}"
        # one frame is one line: control characters in decoded text become spaces
        s = "".join(c if c.isprintable() else " " for c in str(v)).strip()
        if any(c in s for c in " \t,;=\"") or s == "":
            s = '"' + s.replace('"', "'") + '"'
        out.append(f"{k}={s}")
    return " ".join(out)


class MavlinkAuth:
    """MAVLink v2 signature verification with per-stream replay protection.

    ``keys``: {sysid (int) or "*": 32-byte secret | 64 hex chars | "env:VAR"}. Secrets
    are never written by ULPF; give them as environment variables. ``require_signed``:
    unsigned frames are rejected (commands always are once a key is configured).
    """

    MAX_STREAMS = 4096

    def __init__(self, keys: dict | None = None, require_signed: bool = False, max_age_seconds: float = 60.0):
        self.keys: dict = {}
        for k, v in (keys or {}).items():
            if isinstance(v, str) and v.startswith("env:"):
                v = os.environ.get(v[4:], "")
            if isinstance(v, str):
                v = bytes.fromhex(v) if len(v) == 64 else v.encode()
            if len(v) != 32:
                raise ValueError(f"MAVLink signing key for {k}: 32 bytes required")
            self.keys["*" if k == "*" else int(k)] = bytes(v)
        self.require_signed = require_signed
        self.max_age = max_age_seconds
        self._streams: dict[tuple, int] = {}
        self._lock = threading.Lock()

    def key_for(self, sysid: int) -> bytes | None:
        return self.keys.get(sysid) or self.keys.get("*")

    def check(self, frame: bytes, end: int, sysid: int, compid: int, signed: bool) -> str:
        """'valid' | 'invalid' | 'replay' | 'stale' | 'missing' | 'unsigned' | 'nokey'."""
        key = self.key_for(sysid)
        if not signed:
            return "missing" if key is not None or self.require_signed else "unsigned"
        if key is None:
            return "nokey"
        sig_block = frame[end + 2:end + 15]
        if len(sig_block) < 13:
            return "invalid"
        link_id = sig_block[0]
        ts = int.from_bytes(sig_block[1:7], "little")
        want = hashlib.sha256(key + frame[:end + 2] + sig_block[:7]).digest()[:6]
        if not hmac.compare_digest(want, sig_block[7:13]):
            return "invalid"
        stream = (sysid, compid, link_id)
        with self._lock:
            last = self._streams.get(stream)
            if last is not None and ts <= last:
                return "replay"
            if last is None:
                now10us = int((time.time() - _MAV_EPOCH) * 100_000)
                if ts < now10us - int(self.max_age * 100_000):
                    return "stale"
            if len(self._streams) >= self.MAX_STREAMS and stream not in self._streams:
                self._streams.pop(next(iter(self._streams)))
            self._streams[stream] = ts
        return "valid"


def decode_mavlink(raw: bytes, auth: MavlinkAuth | None = None) -> tuple[str, dict]:
    if not raw:
        return "", {}
    stx = raw[0]
    if stx == 0xFE and len(raw) >= 8:
        plen = raw[1]
        seq, sysid, compid, msgid = raw[2], raw[3], raw[4], raw[5]
        header_len, version, signed = 6, 1, False
    elif stx == 0xFD and len(raw) >= 12:
        plen = raw[1]
        incompat = raw[2]
        seq, sysid, compid = raw[4], raw[5], raw[6]
        msgid = raw[7] | raw[8] << 8 | raw[9] << 16
        header_len, version, signed = 10, 2, bool(incompat & 1)
    else:
        return _kv([("telemetry", "mavlink"), ("decode_error", "not a MAVLink frame"), ("bytes", len(raw)),
                    ("data", raw[:64].hex())]), {"telemetry": "mavlink"}
    end = header_len + plen
    if len(raw) < end + 2:
        return _kv([("telemetry", "mavlink"), ("decode_error", "truncated frame"), ("msgid", msgid),
                    ("bytes", len(raw))]), {"telemetry": "mavlink"}
    payload = raw[header_len:end]
    crc_rx = raw[end] | raw[end + 1] << 8
    spec = _MAVLINK.get(msgid)
    pairs: list[tuple[str, object]] = [("telemetry", "mavlink"), ("mavlink_protocol", version),
                                       ("mavlink_msg", spec[0] if spec else f"MSG_{msgid}"), ("msgid", msgid),
                                       ("sysid", sysid), ("compid", compid), ("seq", seq), ("len", plen)]
    severity = None
    if spec is None:
        pairs += [("crc", "unchecked"), ("payload", payload.hex())]
    else:
        name, extra, fmt, fields = spec
        ok = x25_crc(bytes([extra]), x25_crc(raw[1:end])) == crc_rx
        pairs.append(("crc", "ok" if ok else "bad"))
        size = struct.calcsize(fmt)
        body = payload[:size].ljust(size, b"\0")     # v2 trims trailing zero bytes
        values = dict(zip(fields, struct.unpack(fmt, body)))
        if name == "STATUSTEXT":
            text = values.pop("text").split(b"\0", 1)[0].decode("utf-8", "replace")
            sev = values.pop("mav_severity")
            pairs += [("severity", _MAV_SEVERITY[sev] if sev < 8 else sev), ("message", text)]
        if name == "PARAM_SET":
            values["param_id"] = values["param_id"].split(b"\0", 1)[0].decode("ascii", "replace")
        for k, v in values.items():
            if k.endswith("_e7"):
                pairs.append((k[:-3], v / 1e7))
            else:
                pairs.append((k, v))
        if not ok:
            severity = "warning"
    meta = {"telemetry": "mavlink", "mavlink": {"msgid": msgid, "sysid": sysid, "compid": compid}}
    if signed:
        pairs.append(("signed", "true"))
    if auth is not None and version == 2:
        verdict = auth.check(raw, end, sysid, compid, signed)
        pairs.append(("signature", verdict))
        meta["mavlink"]["signature"] = verdict
        is_cmd = msgid in COMMAND_MSGS
        bad = verdict in ("invalid", "replay", "stale") or (verdict == "missing" and (is_cmd or auth.require_signed))
        if bad:
            pairs += [("auth", "rejected"), ("action", "blocked"),
                      ("message", f"{'spoofed command' if is_cmd else 'unauthenticated frame'} "
                                  f"({verdict} signature) from sysid {sysid}")]
            severity = "critical" if is_cmd else "high"
            meta["mavlink"]["rejected"] = True
        elif verdict == "valid":
            pairs.append(("auth", "verified"))
    if severity:
        pairs.append(("severity", severity))
    return _kv(pairs), meta


def sign_mavlink(frame: bytes, key: bytes, link_id: int = 0, timestamp: int | None = None) -> bytes:
    """Sign a MAVLink v2 frame (sets the signed flag, recomputes the CRC; tests and simulators)."""
    if frame[0] != 0xFD:
        raise ValueError("only MAVLink v2 frames can be signed")
    msgid = frame[7] | frame[8] << 8 | frame[9] << 16
    extra = _MAVLINK[msgid][1]
    body = bytearray(frame[:-2])
    body[2] |= 1
    crc = x25_crc(bytes([extra]), x25_crc(bytes(body[1:])))
    signed = bytes(body) + bytes([crc & 0xFF, crc >> 8])
    ts = timestamp if timestamp is not None else int((time.time() - _MAV_EPOCH) * 100_000)
    head = bytes([link_id]) + ts.to_bytes(6, "little")
    return signed + head + hashlib.sha256(key + signed + head).digest()[:6]


# ---------------------------------------------------------------------------
# CCSDS space packets + ECSS PUS
# ---------------------------------------------------------------------------
_SEQ_FLAGS = ("continuation", "first", "last", "standalone")
PUS_SERVICES = {1: "request_verification", 2: "device_access", 3: "housekeeping", 4: "parameter_statistics",
                5: "event_reporting", 6: "memory_management", 8: "function_management", 9: "time_management",
                11: "time_based_scheduling", 12: "onboard_monitoring", 13: "large_packet_transfer",
                14: "realtime_forwarding_control", 15: "onboard_storage_retrieval", 17: "test",
                18: "onboard_control_procedure", 19: "event_action", 20: "onboard_parameter_management",
                21: "request_sequencing", 22: "position_based_scheduling", 23: "file_management"}
_PUS_1 = {1: "acceptance_success", 2: "acceptance_failure", 3: "start_success", 4: "start_failure",
          5: "progress_success", 6: "progress_failure", 7: "completion_success", 8: "completion_failure"}
_PUS_5 = {1: ("informative_event", "info"), 2: ("low_severity_anomaly", "low"),
          3: ("medium_severity_anomaly", "medium"), 4: ("high_severity_anomaly", "high")}
_TAI_1958 = -378691200            # 1958-01-01T00:00:00 as a Unix time (CCSDS CUC default epoch, leap seconds ignored)


def crc16_ccitt(data: bytes, crc: int = 0xFFFF) -> int:
    """CRC-16/CCITT-FALSE, the PUS packet error control."""
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def decode_ccsds(raw: bytes, options: dict | None = None) -> tuple[str, dict]:
    """``options``: pus ('c' default | 'a' | 'none'), time_coarse (4), time_fine (3), epoch_unix
    (CCSDS 1958 epoch), pec (true: the last 2 bytes are a CRC-16/CCITT packet error control)."""
    o = options or {}
    if len(raw) < 6:
        return _kv([("telemetry", "ccsds"), ("decode_error", "shorter than a primary header"),
                    ("bytes", len(raw))]), {"telemetry": "ccsds"}
    w0, w1, ln = struct.unpack(">HHH", raw[:6])
    version, ptype, sec, apid = w0 >> 13, (w0 >> 12) & 1, (w0 >> 11) & 1, w0 & 0x7FF
    flags, count = w1 >> 14, w1 & 0x3FFF
    total = 6 + ln + 1
    data = raw[6:total]
    pairs: list[tuple[str, object]] = [
        ("telemetry", "ccsds"), ("ccsds_version", version), ("packet_type", "tc" if ptype else "tm"),
        ("secondary_header", "true" if sec else "false"), ("apid", apid),
        ("idle", "true" if apid == 0x7FF else "false"), ("seq_flags", _SEQ_FLAGS[flags]),
        ("seq_count", count), ("data_length", ln + 1), ("length_ok", "true" if len(raw) >= total else "false")]
    meta: dict = {"telemetry": "ccsds", "ccsds": {"apid": apid, "seq_count": count}}
    body = data
    if o.get("pec") and len(data) >= 2:
        pec_rx = int.from_bytes(data[-2:], "big")
        ok = crc16_ccitt(raw[:total - 2]) == pec_rx
        pairs.append(("pec", "ok" if ok else "bad"))
        body = data[:-2]
        if not ok:
            pairs.append(("severity", "warning"))
    pus = str(o.get("pus", "c")).lower()
    if sec and pus in ("a", "c") and apid != 0x7FF:
        pairs += _pus(body, ptype, pus, o, meta)
    else:
        pairs.append(("data", body[:64].hex()))
    if len(raw) > total:
        pairs.append(("trailing_bytes", len(raw) - total))
    return _kv(pairs), meta


def _pus(body: bytes, ptype: int, pus: str, o: dict, meta: dict) -> list[tuple[str, object]]:
    out: list[tuple[str, object]] = []
    coarse, fine = int(o.get("time_coarse", 4)), int(o.get("time_fine", 3))
    try:
        if ptype == 0:        # telemetry
            if pus == "c":
                if len(body) < 7:
                    raise ValueError("TM secondary header truncated")
                ver, svc, sub = body[0] >> 4, body[1], body[2]
                counter, dest = struct.unpack(">HH", body[3:7])
                pos = 7
                out += [("pus_version", ver), ("time_ref_status", body[0] & 0xF), ("msg_counter", counter),
                        ("destination_id", dest)]
            else:
                if len(body) < 3:
                    raise ValueError("TM secondary header truncated")
                ver, svc, sub = (body[0] >> 4) & 7, body[1], body[2]
                pos = 3
                out.append(("pus_version", ver))
            if coarse and len(body) >= pos + coarse + fine:
                c = int.from_bytes(body[pos:pos + coarse], "big")
                f = int.from_bytes(body[pos + coarse:pos + coarse + fine], "big") / (1 << (8 * fine)) if fine else 0.0
                t = float(o.get("epoch_unix", _TAI_1958)) + c + f
                ts = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc) + _dt.timedelta(seconds=t)
                out.append(("onboard_time", ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")))
                pos += coarse + fine
        else:                 # telecommand
            if len(body) < 3:
                raise ValueError("TC secondary header truncated")
            ver, svc, sub = (body[0] >> 4) & (0xF if pus == "c" else 7), body[1], body[2]
            pos = 3
            out += [("pus_version", ver), ("ack_flags", f"{body[0] & 0xF:04b}")]
            if pus == "c" and len(body) >= 5:
                out.append(("source_id", int.from_bytes(body[3:5], "big")))
                pos = 5
    except ValueError as e:
        return [("decode_error", str(e)), ("data", body[:64].hex())]
    out += [("pus_service", svc), ("pus_subtype", sub),
            ("pus_service_name", PUS_SERVICES.get(svc, f"mission_{svc}"))]
    if svc == 1 and sub in _PUS_1:
        out.append(("pus_report", _PUS_1[sub]))
        if sub % 2 == 0:
            out.append(("severity", "medium"))
    elif svc == 5 and sub in _PUS_5:
        name, sev = _PUS_5[sub]
        out += [("pus_report", name), ("severity", sev)]
        if len(body) >= pos + 2:
            out.append(("event_id", int.from_bytes(body[pos:pos + 2], "big")))
    out.append(("app_data", body[pos:pos + 64].hex()))
    meta["ccsds"].update(pus_service=svc, pus_subtype=sub)
    return out


class TelemetryDecoder:
    """``options`` is the input's config: ``mavlink: {keys, require_signed, max_age_seconds}`` /
    ``ccsds: {pus, time_coarse, time_fine, epoch_unix, pec}``."""

    def __init__(self, kind: str, options: dict | None = None):
        o = options or {}
        if kind == "mavlink":
            m = o.get("mavlink") or {}
            auth = MavlinkAuth(m.get("keys"), bool(m.get("require_signed", False)),
                               float(m.get("max_age_seconds", 60))) \
                if (m.get("keys") or m.get("require_signed")) else None
            self.fn = lambda raw: decode_mavlink(raw, auth)
        elif kind == "ccsds":
            c = o.get("ccsds") or {}
            self.fn = lambda raw: decode_ccsds(raw, c)
        else:
            raise ValueError(f"unknown telemetry {kind!r}")

    def decode(self, raw: bytes, source: str) -> tuple[str, dict]:
        return self.fn(raw)


def mavlink_frame(msgid: int, values: tuple, sysid: int = 1, compid: int = 1, seq: int = 0, v2: bool = True) -> bytes:
    """Build a MAVLink frame (tests, simulators)."""
    name, extra, fmt, _fields = _MAVLINK[msgid]
    payload = struct.pack(fmt, *values)
    if v2:
        header = bytes([len(payload), 0, 0, seq, sysid, compid, msgid & 0xFF, (msgid >> 8) & 0xFF, msgid >> 16])
        body = bytes([0xFD]) + header + payload
    else:
        body = bytes([0xFE, len(payload), seq, sysid, compid, msgid]) + payload
    crc = x25_crc(bytes([extra]), x25_crc(body[1:]))
    return body + bytes([crc & 0xFF, crc >> 8])
