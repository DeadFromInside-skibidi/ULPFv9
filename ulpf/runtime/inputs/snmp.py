"""
SNMP trap receiver (v1, v2c, v3 USM) over UDP — no SNMP library needed.

* v1 / v2c: the community must be in ``communities``; v2c InformRequests are
  acknowledged with a Response PDU.
* v3: users from ``v3_users`` with HMAC-MD5-96, HMAC-SHA-96 (RFC 3414) or
  the HMAC-SHA-2 protocols of RFC 7860 (SHA-224, -256, -384, -512) and
  AES-CFB privacy: AES-128 (RFC 3826), AES-192 / AES-256 with the key
  extension of draft-blumenthal-aes-usm-04 (as net-snmp: the localised key
  is extended with the hash of what it is so far). Keys are localised to the
  sender's engine ID. Messages that fail authentication are counted and
  dropped.

Each trap is journaled as compact JSON: version, agent, community or user,
trap OID, uptime and every variable binding.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import os
import socket
import threading

import orjson

from ulpf.runtime.inputs.base import Input, udp_socket

logger = logging.getLogger(__name__)

# Well-known trap OIDs (RFC 3418 / RFC 1907)
TRAP_NAMES = {
    "1.3.6.1.6.3.1.1.5.1": ("coldStart", "system"), "1.3.6.1.6.3.1.1.5.2": ("warmStart", "system"),
    "1.3.6.1.6.3.1.1.5.3": ("linkDown", "network"), "1.3.6.1.6.3.1.1.5.4": ("linkUp", "network"),
    "1.3.6.1.6.3.1.1.5.5": ("authenticationFailure", "authentication"),
    "1.3.6.1.6.3.1.1.5.6": ("egpNeighborLoss", "network"),
}
_V1_GENERIC = ["1.3.6.1.6.3.1.1.5.1", "1.3.6.1.6.3.1.1.5.2", "1.3.6.1.6.3.1.1.5.3",
               "1.3.6.1.6.3.1.1.5.4", "1.3.6.1.6.3.1.1.5.5", "1.3.6.1.6.3.1.1.5.6"]
SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"


# ---------------------------------------------------------------------------
# BER
# ---------------------------------------------------------------------------

def ber_read(b: bytes, i: int = 0) -> tuple[int, bytes, int]:
    """(tag, value, next_index)"""
    tag = b[i]
    i += 1
    ln = b[i]
    i += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[i:i + n], "big")
        i += n
    return tag, b[i:i + ln], i + ln


def ber_items(b: bytes) -> list[tuple[int, bytes]]:
    out, i = [], 0
    while i < len(b):
        tag, val, i = ber_read(b, i)
        out.append((tag, val))
    return out


def ber_int(v: bytes) -> int:
    return int.from_bytes(v, "big", signed=True) if v else 0


def ber_oid(v: bytes) -> str:
    if not v:
        return ""
    parts = [v[0] // 40, v[0] % 40]
    n = 0
    for c in v[1:]:
        n = (n << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(n)
            n = 0
    return ".".join(map(str, parts))


def ber_value(tag: int, v: bytes):
    if tag == 0x02:
        return ber_int(v)
    if tag == 0x04:
        try:
            s = v.decode("utf-8")
            return s if s.isprintable() else v.hex()
        except UnicodeDecodeError:
            return v.hex()
    if tag == 0x06:
        return ber_oid(v)
    if tag == 0x40 and len(v) == 4:
        return str(ipaddress.IPv4Address(v))
    if tag in (0x41, 0x42, 0x43, 0x46, 0x47):   # Counter32, Gauge32, TimeTicks, Counter64, UInteger32
        return int.from_bytes(v, "big")
    if tag in (0x05, 0x80, 0x81, 0x82):         # NULL, noSuchObject, noSuchInstance, endOfMibView
        return None
    return v.hex()


def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(value)) + value


def ber_enc_int(n: int) -> bytes:
    length = max(1, (n.bit_length() + 8) // 8)
    return ber_tlv(0x02, n.to_bytes(length, "big", signed=True))


def ber_enc_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    out = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        stack = [p & 0x7F]
        p >>= 7
        while p:
            stack.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(stack))
    return ber_tlv(0x06, bytes(out))


# ---------------------------------------------------------------------------
# USM (SNMPv3)
# ---------------------------------------------------------------------------

_AUTH = {"md5": (hashlib.md5, 12), "sha": (hashlib.sha1, 12), "sha224": (hashlib.sha224, 16),
         "sha256": (hashlib.sha256, 24), "sha384": (hashlib.sha384, 32), "sha512": (hashlib.sha512, 48)}
_PRIV = {"aes": 16, "aes128": 16, "aes192": 24, "aes256": 32}     # AES key bytes


def password_to_key(password: str, algo: str) -> bytes:
    """RFC 3414 A.2: hash 1 MiB of the repeated password."""
    h = _AUTH[algo][0]()
    pw = password.encode()
    data = (pw * (1048576 // len(pw) + 1))[:1048576]
    h.update(data)
    return h.digest()


def localize_key(key: bytes, engine_id: bytes, algo: str) -> bytes:
    return _AUTH[algo][0](key + engine_id + key).digest()


def extend_key(key: bytes, size: int, algo: str) -> bytes:
    """draft-blumenthal-aes-usm-04 3.1.2.1: Kul' = Kul || H(Kul) || H(Kul || H(Kul)) ..."""
    while len(key) < size:
        key += _AUTH[algo][0](key).digest()
    return key[:size]


def _aes_cfb(key: bytes, iv: bytes, data: bytes, encrypt: bool = False) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if len(key) not in (16, 24, 32):
        key = key[:16]          # AES-128: the first 16 bytes of a localised key (RFC 3826)
    c = Cipher(algorithms.AES(key), modes.CFB(iv))
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(data) + op.finalize()


class SnmpError(ValueError):
    pass


def parse_message(data: bytes, communities: set[str], users: dict) -> tuple[dict, bytes | None]:
    """Decode one SNMP message. Returns (trap record, response bytes or None)."""
    tag, msg, _ = ber_read(data)
    if tag != 0x30:
        raise SnmpError("not an SNMP message")
    items = ber_items(msg)
    version = ber_int(items[0][1])
    if version in (0, 1):
        community = items[1][1].decode("utf-8", "replace")
        if communities and community not in communities:
            raise SnmpError(f"unknown community {community!r}")
        rec = _pdu(items[2][0], items[2][1], version)
        rec.update(version=f"v{version + 1}c" if version else "v1", community=community)
        resp = None
        if items[2][0] == 0xA6:         # InformRequest: acknowledge with a Response PDU
            req_id, _status, _index, binds = ber_items(items[2][1])[:4]
            resp_pdu = ber_tlv(0xA2, ber_tlv(0x02, req_id[1]) + ber_enc_int(0) + ber_enc_int(0)
                               + ber_tlv(0x30, binds[1]))
            resp = ber_tlv(0x30, ber_enc_int(version) + ber_tlv(0x04, items[1][1]) + resp_pdu)
        return rec, resp
    if version == 3:
        return _v3(data, items, users), None
    raise SnmpError(f"unsupported SNMP version {version}")


def _v3(data: bytes, items, users: dict) -> dict:
    gd = ber_items(items[1][1])
    flags = gd[2][1][0] if gd[2][1] else 0
    sp = ber_items(ber_read(items[2][1])[1])
    engine_id, boots, etime = sp[0][1], ber_int(sp[1][1]), ber_int(sp[2][1])
    user_name, auth_params, priv_params = sp[3][1].decode("utf-8", "replace"), sp[4][1], sp[5][1]
    user = users.get(user_name)
    if user is None:
        raise SnmpError(f"unknown SNMPv3 user {user_name!r}")
    if flags & 0x01:   # authenticated
        algo = user["auth_protocol"]
        if algo == "none":
            raise SnmpError(f"user {user_name!r} sent an authenticated message but has no auth key")
        key = localize_key(user["auth_key"], engine_id, algo)
        idx = data.find(auth_params)
        zeroed = data[:idx] + b"\x00" * len(auth_params) + data[idx + len(auth_params):]
        mac = hmac.new(key, zeroed, _AUTH[algo][0]).digest()[:_AUTH[algo][1]]
        if not hmac.compare_digest(mac, auth_params):
            raise SnmpError(f"authentication failed for user {user_name!r}")
    elif user["auth_protocol"] != "none":
        raise SnmpError(f"user {user_name!r} requires authentication")
    scoped_tag, scoped = items[3]
    if flags & 0x02:   # encrypted
        if user["priv_protocol"] not in _PRIV:
            raise SnmpError(f"user {user_name!r} has no privacy key")
        pkey = extend_key(localize_key(user["priv_key"], engine_id, user["auth_protocol"]),
                          _PRIV[user["priv_protocol"]], user["auth_protocol"])
        iv = boots.to_bytes(4, "big") + etime.to_bytes(4, "big") + priv_params
        plain = _aes_cfb(pkey, iv, scoped)
        scoped_tag, scoped, _ = ber_read(plain)
    sp_items = ber_items(scoped)
    rec = _pdu(sp_items[2][0], sp_items[2][1], 3)
    rec.update(version="v3", user=user_name, engine_id=engine_id.hex(), context=sp_items[1][1].decode(errors="replace"),
               authenticated=bool(flags & 1), encrypted=bool(flags & 2))
    return rec


def _pdu(tag: int, body: bytes, version: int) -> dict:
    items = ber_items(body)
    if tag == 0xA4:   # SNMPv1 Trap-PDU
        enterprise = ber_oid(items[0][1])
        agent = ber_value(items[1][0], items[1][1])
        generic, specific = ber_int(items[2][1]), ber_int(items[3][1])
        uptime = ber_value(items[4][0], items[4][1])
        trap_oid = _V1_GENERIC[generic] if generic < 6 else f"{enterprise}.0.{specific}"
        binds = items[5][1]
        rec = {"agent_address": agent, "enterprise": enterprise, "generic_trap": generic,
               "specific_trap": specific, "uptime": uptime}
    elif tag in (0xA7, 0xA6, 0xA8):   # SNMPv2-Trap, InformRequest, Report
        rec = {"request_id": ber_int(items[0][1])}
        binds = items[3][1]
        trap_oid, uptime = None, None
    else:
        raise SnmpError(f"not a trap PDU (tag 0x{tag:02x})")
    varbinds = {}
    for _t, vb in ber_items(binds):
        (_, oid_b), (vt, vv) = ber_items(vb)[:2]
        oid = ber_oid(oid_b)
        val = ber_value(vt, vv)
        if oid == SNMP_TRAP_OID:
            trap_oid = val
        elif oid == SYS_UPTIME:
            uptime = val
        else:
            varbinds[oid] = val
    name, category = TRAP_NAMES.get(trap_oid or "", (None, None))
    rec.update(trap_oid=trap_oid, trap_name=name, category=category, uptime=uptime, varbinds=varbinds,
               pdu="inform" if tag == 0xA6 else "trap")
    return rec


class SnmpTrapInput(Input):
    def run(self, stop: threading.Event) -> None:
        o = self.opts
        communities = set(o.get("communities") or [])
        users = {}
        for u in o.get("v3_users") or []:
            entry = {"auth_protocol": u.get("auth_protocol", "sha"), "priv_protocol": u.get("priv_protocol", "none")}
            if entry["auth_protocol"] != "none":
                entry["auth_key"] = password_to_key(os.environ[u["auth_key_env"]], entry["auth_protocol"])
            if entry["priv_protocol"] in _PRIV:
                entry["priv_key"] = password_to_key(os.environ[u["priv_key_env"]], entry["auth_protocol"])
            users[u["name"]] = entry
        sock = udp_socket(o["host"], o["port"])
        self.bound_port = sock.getsockname()[1]
        from ulpf.runtime import egress
        guard = egress.current()
        if guard is not None:
            guard.listener_ports.add(self.bound_port)   # inform acks are replies, not egress
        self.auth_failures = 0
        try:
            while not stop.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                except (socket.timeout, ConnectionResetError):
                    continue
                if not self.filter.allowed(addr[0]):
                    self.stats.dropped_denied += 1
                    continue
                try:
                    rec, resp = parse_message(data, communities, users)
                except (SnmpError, IndexError, ValueError, KeyError) as e:
                    self.stats.errors += 1
                    self.stats.last_error = f"{addr[0]}: {e}"
                    if "authentication" in str(e) or "community" in str(e) or "user" in str(e):
                        self.auth_failures += 1
                    continue
                rec["agent"] = addr[0]
                rec.setdefault("agent_address", addr[0])
                self.accept(addr[0], [orjson.dumps(rec, default=str)], block=False)
                if resp is not None:
                    sock.sendto(resp, addr)
        finally:
            sock.close()

    def describe(self) -> dict:
        return {**super().describe(), "bound_port": getattr(self, "bound_port", None),
                "auth_failures": getattr(self, "auth_failures", 0)}
