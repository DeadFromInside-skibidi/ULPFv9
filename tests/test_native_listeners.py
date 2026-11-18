"""
The compiled core's listeners (native/ulpf_core/src/listen) must journal what
the Python inputs journal: the same records, byte for byte, from the same
traffic. Each decoder is compared with its Python reference on generated
input (valid, odd and broken), then the listeners are run on real sockets
(UDP, TCP, TLS with SNI routing and client certificates, NetFlow, SNMP).
Skipped when the extension is not built.
"""
from __future__ import annotations

import hmac
import json
import os
import random
import socket
import ssl
import struct
import sys
import tempfile
import time
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401

import orjson  # noqa: E402

try:
    from ulpf import ulpf_core
    HAVE = hasattr(ulpf_core, "NativeListener")
except ImportError:
    HAVE = False

from tests.test_inputs import _pb  # noqa: E402

MAPPED_DOTTED = sys.version_info >= (3, 13)


def _fake_input(opts=None):
    stats = types.SimpleNamespace(dropped_oversize=0, dropped_denied=0, connections=0, dropped_overflow=0,
                                  received=0)
    return types.SimpleNamespace(stats=stats, filter=types.SimpleNamespace(allowed=lambda ip: True),
                                 opts=opts or {}, register_transport=lambda t: None,
                                 unregister_transport=lambda t: None)


class _Collect:
    def __init__(self):
        self.recs = []

    def add(self, source, rec):
        self.recs.append(rec)

    def flush(self, source=None):
        pass


def py_stream(framing: str, chunks: list[bytes]):
    from ulpf.runtime.inputs.syslog import _Tcp
    inp, b = _fake_input(), _Collect()
    t = _Tcp(inp, b, framing)
    t.connection_made(types.SimpleNamespace(get_extra_info=lambda k: ("10.0.0.1", 5000)))
    for c in chunks:
        t.data_received(c)
    t.connection_lost(None)
    return b.recs, inp.stats.dropped_oversize


def py_datagram(data: bytes, telemetry: bool):
    from ulpf.runtime.inputs.syslog import _Udp
    inp, b = _fake_input({"telemetry": "mavlink" if telemetry else "none"}), _Collect()
    _Udp(inp, b).datagram_received(data, ("10.0.0.1", 514))
    return b.recs


# ---------------------------------------------------------------------------
# generators
# ---------------------------------------------------------------------------

def syslog_streams(rnd: random.Random, n: int):
    msgs = [b"<134>Oct 11 22:14:15 r1 app: hello", b"<13>1 2026-10-21T10:00:00Z h a - - - multi\nline",
            b"", b"   ", b"x\r", b"\r\n", b"12345678 not octet", b"<14>" + b"A" * 300, b"plain text \t ok"]
    for _ in range(n):
        framing = rnd.choice(["auto", "auto", "newline", "octet"])
        parts = []
        for _ in range(rnd.randrange(0, 12)):
            m = rnd.choice(msgs)
            style = rnd.random()
            if style < 0.45:
                parts.append(str(len(m)).encode() + b" " + m)
            elif style < 0.9:
                parts.append(m + rnd.choice([b"\n", b"\r\n", b"\r\r\n"]))
            else:
                parts.append(m)                         # unterminated
        stream = b"".join(parts)
        if rnd.random() < 0.05:
            stream += b"\n" + b"z" * (1024 * 1024 + 10)   # past the frame limit
        cuts = sorted(rnd.sample(range(len(stream) + 1), min(len(stream), rnd.randrange(0, 6))))
        chunks = [stream[a:b] for a, b in zip([0] + cuts, cuts + [len(stream)]) if stream[a:b]]
        yield framing, chunks


def netflow_packets(rnd: random.Random, n: int):
    """Template and data packets of v5, v9 (with options templates) and IPFIX (variable
    length and enterprise elements), some truncated or corrupted."""
    now = 1_760_000_000
    out = []
    v9_fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4), (22, 4), (21, 4), (56, 6), (27, 16),
                 (61, 1), (10, 2), (58, 2)]
    for k in range(n):
        kind = rnd.choice(["v5", "v9", "ipfix", "junk"])
        if kind == "v5":
            cnt = rnd.randrange(0, 5)
            head = struct.pack("!HHIIIIBBH", 5, cnt, 100_000 + k, now + k, 0, 1, 0, 0, 0)
            recs = b"".join(struct.pack("!4s4s4sHHIIIIHHBBBBHHBBH", os.urandom(4), os.urandom(4), bytes(4), 1, 2,
                                        rnd.randrange(1 << 32), rnd.randrange(1 << 32), 90_000, 99_000,
                                        rnd.randrange(65536), 443, 0, 0x18, rnd.choice([6, 17, 1, 99]), 0, 0, 0,
                                        24, 24, 0) for _ in range(cnt))
            p = head + recs
        elif kind == "v9":
            fields = rnd.sample(v9_fields, rnd.randrange(1, len(v9_fields)))
            tid = rnd.choice([256, 300])
            tpl = struct.pack("!HH", tid, len(fields)) + b"".join(struct.pack("!HH", a, b) for a, b in fields)
            opt = struct.pack("!HHH", 400, 4, 4) + struct.pack("!HH", 1, 4) + struct.pack("!HH", 34, 4)
            body = b""
            if rnd.random() < 0.6:
                body += struct.pack("!HH", 0, 4 + len(tpl)) + tpl
            if rnd.random() < 0.3:
                body += struct.pack("!HH", 1, 4 + len(opt)) + opt
            recsz = sum(b for _, b in fields)
            data = os.urandom(recsz * rnd.randrange(0, 4) + rnd.choice([0, 0, 1, 3]))
            body += struct.pack("!HH", tid, 4 + len(data)) + data
            p = struct.pack("!HHIIII", 9, 2, 100_000 + k, now + k, k, rnd.choice([0, 7])) + body
        elif kind == "ipfix":
            fields = [(8, 4), (12, 4), (152, 8), (153, 8), (4, 1), (82 | 0x8000, 65535), (1, 8), (150, 4)]
            fields = rnd.sample(fields, rnd.randrange(1, len(fields)))
            tid = 256
            tb = b""
            for ie, ln in fields:
                tb += struct.pack("!HH", ie, ln) + (struct.pack("!I", 9) if ie & 0x8000 else b"")
            tpl = struct.pack("!HH", tid, len(fields)) + tb
            body = struct.pack("!HH", 2, 4 + len(tpl)) + tpl if rnd.random() < 0.7 else b""
            rec = b""
            for ie, ln in fields:
                if ln == 65535:
                    v = os.urandom(rnd.choice([0, 3, 300]))
                    rec += (bytes([len(v)]) if len(v) < 255 else b"\xff" + struct.pack("!H", len(v))) + v
                elif ie in (152, 153):
                    rec += struct.pack("!Q", (now + rnd.randrange(100)) * 1000 + rnd.randrange(1000))
                elif ie == 150:
                    rec += struct.pack("!I", now)
                else:
                    rec += os.urandom(ln)
            data = rec * rnd.randrange(0, 3)
            body += struct.pack("!HH", tid, 4 + len(data)) + data
            p = struct.pack("!HHIII", 10, 16 + len(body), now + k, k, rnd.choice([0, 1])) + body
        else:
            p = os.urandom(rnd.randrange(0, 40))
        if rnd.random() < 0.15 and len(p) > 4:
            p = p[:rnd.randrange(4, len(p))]
        out.append(p)
    return out


def snmp_messages(rnd: random.Random, users: list[dict], n: int):
    from ulpf.runtime.inputs.snmp import (_AUTH, _PRIV, _aes_cfb, ber_enc_int, ber_enc_oid, ber_tlv, extend_key,
                                          localize_key, password_to_key)
    out = []
    oids = ["1.3.6.1.6.3.1.1.5.3", "1.3.6.1.6.3.1.1.5.5", "1.3.6.1.4.1.9.9.41.2.0.1"]
    values = [ber_enc_int(rnd.randrange(-10**6, 10**6)), ber_tlv(0x04, b"eth0 down"), ber_tlv(0x04, "café".encode()),
              ber_tlv(0x04, b"\x00\x01binary"), ber_tlv(0x40, bytes([10, 1, 2, 3])), ber_tlv(0x41, (2**32 - 1).to_bytes(4, "big")),
              ber_tlv(0x46, (2**63 + 5).to_bytes(9, "big")), ber_tlv(0x05, b""), ber_enc_oid("1.3.6.1.2.1.1"),
              ber_tlv(0x43, (123456).to_bytes(4, "big")), ber_tlv(0x04, "​zero-width".encode())]

    def varbinds():
        vb = ber_tlv(0x30, ber_enc_oid("1.3.6.1.2.1.1.3.0") + ber_tlv(0x43, (12345).to_bytes(4, "big")))
        vb += ber_tlv(0x30, ber_enc_oid("1.3.6.1.6.3.1.1.4.1.0") + ber_enc_oid(rnd.choice(oids)))
        for _ in range(rnd.randrange(0, 4)):
            vb += ber_tlv(0x30, ber_enc_oid(f"1.3.6.1.4.1.{rnd.randrange(99)}.{rnd.randrange(9)}") + rnd.choice(values))
        return ber_tlv(0x30, vb)
    for _ in range(n):
        kind = rnd.choice(["v1", "v2c", "inform", "v3", "v3", "junk"])
        if kind == "v1":
            pdu = ber_tlv(0xA4, ber_enc_oid("1.3.6.1.4.1.9") + ber_tlv(0x40, bytes([10, 0, 0, 9]))
                          + ber_enc_int(rnd.choice([0, 2, 6, -1])) + ber_enc_int(17)
                          + ber_tlv(0x43, (999).to_bytes(4, "big")) + varbinds())
            m = ber_tlv(0x30, ber_enc_int(0) + ber_tlv(0x04, rnd.choice([b"public", b"wrong"])) + pdu)
        elif kind in ("v2c", "inform"):
            pdu = ber_tlv(0xA6 if kind == "inform" else 0xA7,
                          ber_enc_int(rnd.randrange(1, 10**6)) + ber_enc_int(0) + ber_enc_int(0) + varbinds())
            m = ber_tlv(0x30, ber_enc_int(1) + ber_tlv(0x04, rnd.choice([b"public", b"public", b"nope"])) + pdu)
        elif kind == "v3":
            u = rnd.choice(users)
            engine = bytes.fromhex("80001f8880c71100000a") if rnd.random() < 0.7 else os.urandom(9)
            boots, etime = rnd.randrange(1, 9), rnd.randrange(10**6)
            pdu = ber_tlv(0xA7, ber_enc_int(7) + ber_enc_int(0) + ber_enc_int(0) + varbinds())
            scoped = ber_tlv(0x30, ber_tlv(0x04, engine) + ber_tlv(0x04, b"ctx") + pdu)
            flags, salt, body = 0, b"", ber_tlv(0x30, b"")
            auth, priv = u["auth_protocol"], u["priv_protocol"]
            if auth != "none":
                flags |= 1
            if priv != "none":
                flags |= 2
                salt = os.urandom(8)
                pw = u["priv_password"] if rnd.random() < 0.9 else "badpriv123"
                pkey = extend_key(localize_key(password_to_key(pw, auth), engine, auth), _PRIV[priv], auth)
                enc = _aes_cfb(pkey, boots.to_bytes(4, "big") + etime.to_bytes(4, "big") + salt, scoped, encrypt=True)
                body = ber_tlv(0x04, enc)
            else:
                body = scoped
            maclen = _AUTH[auth][1] if auth != "none" else 0
            usm = ber_tlv(0x30, ber_tlv(0x04, engine) + ber_enc_int(boots) + ber_enc_int(etime)
                          + ber_tlv(0x04, u["name"].encode()) + ber_tlv(0x04, bytes(maclen)) + ber_tlv(0x04, salt))
            gd = ber_tlv(0x30, ber_enc_int(99) + ber_enc_int(65507) + ber_tlv(0x04, bytes([flags | 4])) + ber_enc_int(3))
            m = ber_tlv(0x30, ber_enc_int(3) + gd + ber_tlv(0x04, usm) + body)
            if auth != "none":
                pw = u["auth_password"] if rnd.random() < 0.9 else "badauth123"
                key = localize_key(password_to_key(pw, auth), engine, auth)
                mac = hmac.new(key, m, _AUTH[auth][0]).digest()[:maclen]
                i = m.find(bytes(maclen))
                m = m[:i] + mac + m[i + maclen:]
        else:
            m = os.urandom(rnd.randrange(0, 30))
        if rnd.random() < 0.1 and len(m) > 2:
            m = m[:rnd.randrange(2, len(m))]
        out.append(m)
    return out


def otlp_requests(rnd: random.Random, n: int):
    def anyv(depth=0):
        k = rnd.randrange(8 if depth < 2 else 5)
        if k == 0:
            return _pb(1, 2, rnd.choice(["hello world", "", "  ", "café", "x" * 50]).encode())
        if k == 1:
            return _pb(2, 0, rnd.choice([0, 1]))
        if k == 2:
            return _pb(3, 0, rnd.choice([0, 5, 2**63 + 7, 2**64 - 1]))
        if k == 3:
            return _pb(4, 1, struct.unpack("<Q", struct.pack("<d", rnd.choice([0.1, 1.5e-5, 1e16, -2.5, 1e300])))[0])
        if k == 4:
            return _pb(7, 2, os.urandom(4))
        if k == 5:
            return _pb(5, 2, b"".join(_pb(1, 2, anyv(depth + 1)) for _ in range(rnd.randrange(0, 3))))
        if k == 6:
            return _pb(6, 2, b"".join(_pb(1, 2, kv(f"k{i}", depth + 1)) for i in range(rnd.randrange(0, 3))))
        return b""

    def kv(key, depth=0):
        return _pb(1, 2, key.encode()) + _pb(2, 2, anyv(depth))
    out = []
    for _ in range(n):
        rls = b""
        for _ in range(rnd.randrange(1, 3)):
            res = b"".join(_pb(1, 2, kv(k)) for k in rnd.sample(["service.name", "host.name", "env"], rnd.randrange(0, 3)))
            logs = b""
            for _ in range(rnd.randrange(0, 4)):
                rec = _pb(1, 1, 1_760_000_000_000_000_000 + rnd.randrange(10**9)) + _pb(2, 0, rnd.randrange(25))
                if rnd.random() < 0.7:
                    rec += _pb(5, 2, anyv())
                if rnd.random() < 0.5:
                    rec += _pb(3, 2, b"WARN")
                for _ in range(rnd.randrange(0, 3)):
                    rec += _pb(6, 2, kv(rnd.choice(["log.file.path", "a", "b"])))
                if rnd.random() < 0.3:
                    rec += _pb(9, 2, os.urandom(16)) + _pb(10, 2, os.urandom(8)) + _pb(11, 1, 1)
                logs += _pb(2, 2, rec)
            rls += _pb(1, 2, _pb(1, 2, res) + _pb(2, 2, logs))
        if rnd.random() < 0.05:
            rls = rls[:max(1, len(rls) // 2)]
        out.append(rls)
    return out


# ---------------------------------------------------------------------------

def _self_signed(d: str, cn: str, ca=None, client=False):
    """A certificate for `cn` (self-signed, or signed by `ca` = (cert, key)); returns (cert path, key path, objs)."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    issuer_cert, issuer_key = (ca or (None, None))
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_cert.subject if issuer_cert else name)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=3)))
    if ca is None and not client and cn.startswith("ca"):
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    else:
        b = b.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)] + ([] if client else [x509.IPAddress(
            __import__("ipaddress").ip_address("127.0.0.1"))])), critical=False)
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client
                                                   else ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    cert = b.sign(issuer_key or key, hashes.SHA256())
    cp, kp = os.path.join(d, f"{cn}.crt"), os.path.join(d, f"{cn}.key")
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cp, kp, (cert, key)


def _drain(lst, want: int, timeout: float = 10.0):
    out = []
    end = time.time() + timeout
    while sum(len(b[2]) for b in out) < want and time.time() < end:
        b = lst.next_batch(200)
        if b is not None:
            out.append(b)
    return out


@unittest.skipUnless(HAVE, "ulpf_core listeners not built")
class TestListenerDecoders(unittest.TestCase):
    def test_syslog_framing_matches_python(self):
        rnd = random.Random(1)
        for framing, chunks in syslog_streams(rnd, 3000):
            got = ulpf_core._listener_probe("syslog_stream", framing, chunks, None)
            self.assertEqual(got, py_stream(framing, chunks), (framing, [c[:80] for c in chunks]))
        for data in [b"one\ntwo\r\nthree", b"single\r\n", b"\n\n", b"a\rb", b"  \n x \n", b"", b"tel\x00\x01"]:
            for tel in (False, True):
                self.assertEqual(ulpf_core._listener_probe("syslog_datagram", tel, data, None),
                                 py_datagram(data, tel), (data, tel))

    def test_netflow_matches_python(self):
        from ulpf.runtime.inputs.netflow import FlowDecoder
        rnd = random.Random(2)
        packets = netflow_packets(rnd, 4000)
        got = ulpf_core._listener_probe("netflow", "198.51.100.7", packets, MAPPED_DOTTED)
        dec = FlowDecoder(None)
        flows = 0
        for p, g in zip(packets, got):
            try:
                want = [orjson.dumps(f) for f in dec.decode(p, "198.51.100.7")]
            except (ValueError, struct.error, IndexError, TypeError):
                want = None
            if want is None:
                self.assertIsInstance(g, str, p.hex())
            else:
                self.assertEqual(g, want, p.hex())
                flows += len(want)
        self.assertGreater(flows, 1000)

    def test_snmp_matches_python(self):
        from ulpf.runtime.inputs.snmp import SnmpError, parse_message, password_to_key
        users = []
        for auth in ("md5", "sha", "sha224", "sha256", "sha384", "sha512", "none"):
            for priv in (("none", "aes", "aes192", "aes256") if auth != "none" else ("none",)):
                users.append({"name": f"u_{auth}_{priv}", "auth_protocol": auth, "priv_protocol": priv,
                              "auth_password": "authpass123", "priv_password": "privpass123"})
        cfg = json.dumps({"communities": ["public"], "v3_users": users})
        py_users = {}
        for u in users:
            e = {"auth_protocol": u["auth_protocol"], "priv_protocol": u["priv_protocol"]}
            if u["auth_protocol"] != "none":
                e["auth_key"] = password_to_key(u["auth_password"], u["auth_protocol"])
            if u["priv_protocol"] != "none":
                e["priv_key"] = password_to_key(u["priv_password"], u["auth_protocol"])
            py_users[u["name"]] = e
        rnd = random.Random(3)
        ok = 0
        for m in snmp_messages(rnd, users, 1500):
            try:
                rec, resp = parse_message(m, {"public"}, py_users)
                rec["agent"] = "10.0.0.9"
                rec.setdefault("agent_address", "10.0.0.9")
                want = (orjson.dumps(rec, default=str), resp)
            except (SnmpError, IndexError, ValueError, KeyError, OverflowError, TypeError, orjson.JSONEncodeError):
                want = None
            got = ulpf_core._listener_probe("snmp", cfg, m, None)
            if want is None:
                self.assertIsInstance(got, str, m.hex())
            else:
                self.assertEqual(got, want, m.hex())
                ok += 1
        self.assertGreater(ok, 400)

    def test_otlp_matches_python(self):
        from ulpf.runtime.inputs.http import otlp_protobuf_records, otlp_to_records
        rnd = random.Random(4)
        ok = 0
        for body in otlp_requests(rnd, 1500):
            try:
                want = [(s, r) for s, r in otlp_to_records(otlp_protobuf_records(body), "203.0.113.4").items()]
            except (ValueError, IndexError, struct.error, TypeError):
                want = None
            got = ulpf_core._listener_probe("otlp", "203.0.113.4", body, None)
            if want is None:
                self.assertIsInstance(got, str, body.hex())
            else:
                self.assertEqual(got, want, body.hex())
                ok += 1
        self.assertGreater(ok, 1000)


@unittest.skipUnless(HAVE, "ulpf_core listeners not built")
class TestListenersOnSockets(unittest.TestCase):
    def _listener(self, **cfg):
        cfg.setdefault("host", "127.0.0.1")
        cfg.setdefault("port", 0)
        lst = ulpf_core.NativeListener(json.dumps(cfg))
        self.addCleanup(lst.stop)
        return lst

    def test_udp_and_tcp_syslog(self):
        u = self._listener(kind="syslog", protocol="udp")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(50):
            s.sendto(b"<13>Oct 11 22:14:15 h app: udp %d\n" % i, ("127.0.0.1", u.bound_port))
        got = _drain(u, 50)
        recs = [r for b in got for r in b[2]]
        self.assertEqual(sorted(recs), sorted(b"<13>Oct 11 22:14:15 h app: udp %d" % i for i in range(50)))
        self.assertEqual({b[1] for b in got}, {"127.0.0.1"})
        t = self._listener(kind="syslog", protocol="tcp")
        msgs = [b"<134>1 2026-10-21T10:00:00Z fw app - - - m%d\nsecond line" % i for i in range(300)]
        with socket.create_connection(("127.0.0.1", t.bound_port)) as c:
            c.sendall(b"".join(str(len(m)).encode() + b" " + m for m in msgs))
        recs = [r for b in _drain(t, 300) for r in b[2]]
        self.assertEqual(recs, msgs)                    # one connection: order kept
        self.assertEqual(t.stats()["connections"], 1)

    def test_tls_sni_routing_and_client_certificates(self):
        d = tempfile.mkdtemp(prefix="ulpf_ntls_")
        ca_c, ca_k, ca = _self_signed(d, "ca-root")
        a_c, a_k, _ = _self_signed(d, "tenant-a.example", ca)
        b_c, b_k, _ = _self_signed(d, "tenant-b.example", ca)
        cl_c, cl_k, _ = _self_signed(d, "client-1", ca, client=True)
        lst = self._listener(kind="syslog", protocol="tls", tls={
            "cert": a_c, "key": a_k, "client_ca": ca_c,
            "sni_certs": [{"server_name": "tenant-b.example", "cert": b_c, "key": b_k}],
            "sni_routes": {"tenant-a.example": "tls_tenant_a", "tenant-b.example": "tls_tenant_b"}})

        def send(sni, msgs, client=True):
            ctx = ssl.create_default_context(cafile=ca_c)
            ctx.check_hostname = True
            if client:
                ctx.load_cert_chain(cl_c, cl_k)
            with socket.create_connection(("127.0.0.1", lst.bound_port)) as raw:
                with ctx.wrap_socket(raw, server_hostname=sni) as s:
                    s.sendall(b"".join(m + b"\n" for m in msgs))
                    # the server presented the certificate of the requested name
                    cn = dict(x[0] for x in s.getpeercert()["subject"])["commonName"]
                    self.assertEqual(cn, sni)
        send("tenant-a.example", [b"<13>Oct 11 22:14:15 h a: one"])
        send("tenant-b.example", [b"<13>Oct 11 22:14:15 h b: two", b"<13>Oct 11 22:14:15 h b: three"])
        got = _drain(lst, 3)
        by_input = {}
        for inp, src, recs, ts in got:
            by_input.setdefault(inp, []).extend(recs)
        self.assertEqual(by_input, {"tls_tenant_a": [b"<13>Oct 11 22:14:15 h a: one"],
                                    "tls_tenant_b": [b"<13>Oct 11 22:14:15 h b: two", b"<13>Oct 11 22:14:15 h b: three"]})
        # no client certificate: the server refuses the handshake (with TLS 1.3 the client learns
        # it on its first read), and nothing it sent is accepted
        ctx = ssl.create_default_context(cafile=ca_c)
        with socket.create_connection(("127.0.0.1", lst.bound_port)) as raw:
            try:
                with ctx.wrap_socket(raw, server_hostname="tenant-a.example") as s:
                    s.sendall(b"<13>Oct 11 22:14:15 h a: intruder\n")
                    s.settimeout(3)
                    s.recv(1)
            except (ssl.SSLError, ConnectionError, OSError, socket.timeout):
                pass
        time.sleep(0.3)
        self.assertGreaterEqual(lst.stats()["tls_failures"], 1)
        self.assertIsNone(lst.next_batch(300))

    def test_netflow_and_snmp(self):
        from tests.test_inputs import netflow_v5, netflow_v9, snmp_v2c_trap
        nf = self._listener(kind="netflow", state_path=os.path.join(tempfile.mkdtemp(), "t.json"),
                            ipv6_mapped_dotted=MAPPED_DOTTED)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tpl, data = netflow_v9(5)
        for p in (netflow_v5(4), tpl, data):
            s.sendto(p, ("127.0.0.1", nf.bound_port))
        recs = [orjson.loads(r) for b in _drain(nf, 9) for r in b[2]]
        self.assertEqual(len(recs), 9)
        self.assertEqual({r["netflow_version"] for r in recs}, {5, 9})
        sn = self._listener(kind="snmp", communities=["public"])
        s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s2.settimeout(3)
        s2.sendto(snmp_v2c_trap("public", "1.3.6.1.6.3.1.1.5.3", inform=True), ("127.0.0.1", sn.bound_port))
        resp, _ = s2.recvfrom(4096)                      # the inform is acknowledged
        self.assertEqual(resp[resp.find(b"\xa2"):][:1], b"\xa2")
        s2.sendto(snmp_v2c_trap("wrong", "1.3.6.1.6.3.1.1.5.3"), ("127.0.0.1", sn.bound_port))
        recs = [orjson.loads(r) for b in _drain(sn, 1) for r in b[2]]
        self.assertEqual(recs[0]["trap_name"], "linkDown")
        time.sleep(0.3)
        self.assertEqual(sn.stats()["auth_failures"], 1)

    def test_udp_overflow_is_counted_not_blocking(self):
        u = self._listener(kind="syslog", protocol="udp", queue_batches=1, batch=1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(2000):
            s.sendto(b"<13>Oct 11 22:14:15 h app: flood %d" % i, ("127.0.0.1", u.bound_port))
        time.sleep(1.0)
        st = u.stats()
        self.assertGreater(st["dropped_overflow"], 0)
        got = sum(len(b[2]) for b in _drain(u, 10**9, timeout=1.0))
        self.assertLess(got, 2000)


def _hpack(headers: list[tuple[str, str]]) -> bytes:
    """Literal header fields without indexing, no Huffman (RFC 7541 6.2.2)."""
    def n(v: int) -> bytes:
        if v < 127:
            return bytes([v])
        out, v = bytearray([127]), v - 127
        while v >= 128:
            out.append(v % 128 + 128)
            v //= 128
        return bytes(out + bytes([v]))
    return b"".join(b"\0" + n(len(k)) + k.encode() + n(len(v)) + v.encode() for k, v in headers)


def grpc_call(port: int, path: str, message: bytes, metadata=(), timeout: float = 10.0) -> dict:
    """One unary gRPC call over cleartext HTTP/2 (prior knowledge); returns the frames seen on stream 1."""
    def frame(kind, flags, stream, payload=b""):
        return struct.pack(">I", len(payload))[1:] + bytes([kind, flags]) + struct.pack(">I", stream) + payload
    hdrs = [(":method", "POST"), (":scheme", "http"), (":path", path), (":authority", f"127.0.0.1:{port}"),
            ("content-type", "application/grpc"), ("te", "trailers"), *metadata]
    body = b"\0" + struct.pack(">I", len(message)) + message
    seen = {"data": b"", "headers": 0, "ended": False}
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as c:
        c.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0) + frame(1, 4, 1, _hpack(hdrs))
                  + frame(0, 1, 1, body))
        buf = b""
        while not seen["ended"]:
            while len(buf) < 9 or len(buf) < 9 + int.from_bytes(buf[:3], "big"):
                chunk = c.recv(65536)
                if not chunk:
                    return seen
                buf += chunk
            size = int.from_bytes(buf[:3], "big")
            kind, flags, stream = buf[3], buf[4], int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
            payload, buf = buf[9:9 + size], buf[9 + size:]
            if kind == 4 and not flags & 1:
                c.sendall(frame(4, 1, 0))                      # SETTINGS ack
            elif kind == 6 and not flags & 1:
                c.sendall(frame(6, 1, 0, payload))             # PING ack
            elif kind == 7:
                return seen                                    # GOAWAY
            elif stream == 1 and kind == 0:
                seen["data"] += payload
            elif stream == 1 and kind == 1:
                seen["headers"] += 1
            if stream == 1 and kind in (0, 1) and flags & 1:
                seen["ended"] = True
    return seen


@unittest.skipUnless(HAVE, "ulpf_core listeners not built")
class TestNativeInputsInRuntime(unittest.TestCase):
    """The native inputs run by the supervisor: records journaled, routed by SNI and stored."""

    def test_syslog_tls_sni_and_otlp_grpc(self):
        from tests.test_inputs import delivered, free_port, start_runtime, stored, wait_for
        d = tempfile.mkdtemp(prefix="ulpf_nrt_")
        ca_c, _, ca = _self_signed(d, "ca-root")
        a_c, a_k, _ = _self_signed(d, "tenant-a.example", ca)
        b_c, b_k, _ = _self_signed(d, "tenant-b.example", ca)
        os.environ["ULPF_T_OTLP_KEY"] = "otlp-secret-1"
        rt = start_runtime(d, [
            {"type": "syslog", "name": "tls_in", "engine": "native", "protocol": "tls", "host": "127.0.0.1",
             "port": free_port(), "tls": {"cert": a_c, "key": a_k,
                                "sni_certs": [{"server_name": "tenant-b.example", "cert": b_c, "key": b_k}],
                                "sni_routes": {"tenant-b.example": "tenant_b"}}},
            {"type": "syslog", "name": "tenant_b", "engine": "native", "protocol": "udp", "host": "127.0.0.1",
             "port": free_port(socket.SOCK_DGRAM)},
            {"type": "otlp_grpc", "name": "otlp", "host": "127.0.0.1", "port": free_port(),
             "api_key_env": "ULPF_T_OTLP_KEY"}])
        try:
            self.assertTrue(wait_for(lambda: all(rt.inputs[n].describe()["bound_port"]
                                                 for n in ("tls_in", "tenant_b", "otlp")), 10))
            self.assertEqual(type(rt.inputs["tls_in"]).__name__, "NativeSyslogInput")
            port = rt.inputs["tls_in"].describe()["bound_port"]
            for sni, msg in (("tenant-a.example", b"<13>Oct 11 22:14:15 h a: one"),
                             ("tenant-b.example", b"<13>Oct 11 22:14:15 h b: two")):
                ctx = ssl.create_default_context(cafile=ca_c)
                with socket.create_connection(("127.0.0.1", port)) as raw, \
                        ctx.wrap_socket(raw, server_hostname=sni) as s:
                    s.sendall(msg + b"\n")
            body = _pb(1, 2, _pb(1, 2, _pb(1, 2, _pb(1, 2, b"service.name") + _pb(2, 2, _pb(1, 2, b"api"))))
                       + _pb(2, 2, _pb(2, 2, _pb(1, 1, 1_760_000_000_000_000_000) + _pb(5, 2, _pb(1, 2, b"grpc hello")))))
            gport = rt.inputs["otlp"].describe()["bound_port"]
            path = "/opentelemetry.proto.collector.logs.v1.LogsService/Export"
            ok = grpc_call(gport, path, body, [("authorization", "Bearer otlp-secret-1")])
            self.assertTrue(ok["ended"])
            grpc_call(gport, path, body, [("authorization", "Bearer wrong")])   # refused: not stored
            self.assertTrue(wait_for(lambda: delivered(rt) >= 3, 30), delivered(rt))
            time.sleep(0.5)
            rows = stored(rt, "SELECT json_extract_string(normalised_json, '$.metadata.input'), raw_event "
                              "FROM events ORDER BY 1")
            self.assertEqual([r[0] for r in rows], ["otlp", "tenant_b", "tls_in"])
            self.assertIn("grpc hello", rows[0][1])
            self.assertIn("b: two", rows[1][1])
            self.assertGreaterEqual(rt.inputs["otlp"].describe()["listener"].get("auth_failures", 0), 1)
        finally:
            rt.stop()

    def test_config_rejects_unknown_sni_route(self):
        from ulpf.config import load_pipeline_config
        with self.assertRaises(Exception) as e:
            load_pipeline_config(data={"inputs": [{"type": "syslog", "name": "s", "protocol": "tls",
                                                   "tls": {"cert": "c", "key": "k",
                                                           "sni_routes": {"x.example": "nope"}}}],
                                       "outputs": [{"type": "file", "name": "o", "path": "o.ndjson"}]})
        self.assertIn("no input named 'nope'", str(e.exception))


if __name__ == "__main__":
    unittest.main()
