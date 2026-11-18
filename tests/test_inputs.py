"""Inputs end to end through the runtime: every source class with exact event counts."""
from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import os
import socket
import ssl
import struct
import sys
import tempfile
import time
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401
from tests.fakes import FakeHTTP, google_credentials, self_signed_cert  # noqa: E402

from ulpf.config import load_pipeline_config  # noqa: E402


def free_port(kind=socket.SOCK_STREAM) -> int:
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_for(pred, timeout=60.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.1)
    return False


def start_runtime(data_dir: str, inputs: list, mode: str = "industry", api: bool = False, **extra):
    from ulpf.runtime.supervisor import Runtime
    cfg = {"mode": mode, "workers": 1, "node": {"data_dir": data_dir}, "inputs": inputs,
           "api": {"enabled": api, "port": 0}, "evidence": {"enabled": False},
           "analytics": {"correlation": {"enabled": False}},
           "outputs": [{"type": "duckdb", "name": "store", "path": os.path.join(data_dir, "s.duckdb")}],
           "routes": [{"name": "logs", "when": {"kind_in": ["log"]}, "to": ["store"]}], "default_output": ""}
    cfg.update(extra)
    return Runtime(load_pipeline_config(data=cfg)).start()


def stored(rt, sql: str = "SELECT COUNT(*) FROM events"):
    with rt.database._conn_lock:
        return rt.database.conn.execute(sql).fetchall()


def delivered(rt) -> int:
    return rt.runners["store"].delivered_events


# ---------------------------------------------------------------------------

class TestFileInput(unittest.TestCase):
    def test_multiline_rotation_truncation_and_restart(self):
        d = tempfile.mkdtemp(prefix="ulpf_file_")
        logs = os.path.join(d, "logs")
        os.makedirs(logs)
        app = os.path.join(logs, "app.log")
        inp = [{"type": "file", "name": "app", "paths": [os.path.join(logs, "app.log")],
                "start_from": "beginning", "poll_interval_ms": 50,
                "multiline": {"start_pattern": r"^\d{4}-\d{2}-\d{2}", "timeout_ms": 300}}]

        def event(i):
            return (f"2026-10-21 10:00:{i % 60:02d} ERROR request {i} failed\n"
                    f"Traceback (most recent call last):\n  File \"svc.py\", line {i}, in handle\n"
                    f"ValueError: bad input {i}\n")

        with open(app, "w", newline="\n") as f:
            f.writelines(event(i) for i in range(100))
        rt = start_runtime(d, inp)
        try:
            self.assertTrue(wait_for(lambda: delivered(rt) >= 100, 30), delivered(rt))
            # rotation: rename + new file; the tail of the old file must still be read
            with open(app, "a", newline="\n") as f:
                f.writelines(event(i) for i in range(100, 150))
            os.replace(app, app + ".1")
            with open(app, "w", newline="\n") as f:
                f.writelines(event(i) for i in range(150, 200))
            self.assertTrue(wait_for(lambda: delivered(rt) >= 200, 30), delivered(rt))
            # copy-truncate: the file shrinks and is read from the start
            with open(app, "w", newline="\n") as f:
                f.writelines(event(i) for i in range(200, 210))
            self.assertTrue(wait_for(lambda: delivered(rt) >= 210, 30), delivered(rt))
            raw = stored(rt, "SELECT raw_event FROM events LIMIT 1")[0][0]
            self.assertIn("Traceback", raw)
            self.assertIn("ValueError", raw)         # the whole stack trace is one event
        finally:
            rt.stop()
        # restart: only new lines are read, nothing twice
        with open(app, "a", newline="\n") as f:
            f.writelines(event(i) for i in range(210, 260))
        rt = start_runtime(d, inp)
        try:
            self.assertTrue(wait_for(lambda: stored(rt)[0][0] >= 260, 30))
            time.sleep(1.0)
            total, distinct = stored(rt, "SELECT COUNT(*), COUNT(DISTINCT raw_hash) FROM events")[0]
            self.assertEqual(total, 260)
            self.assertEqual(distinct, 260)
        finally:
            rt.stop()

    def test_container_decoders(self):
        from ulpf.runtime.decoders import ContainerDecoder, JournaldDecoder
        docker = ContainerDecoder("docker", tempfile.mkdtemp())
        raw = (b'{"log":"part one, ","stream":"stdout","time":"2026-10-21T10:00:00Z"}\n'
               b'{"log":"part two\\n","stream":"stdout","time":"2026-10-21T10:00:00Z"}')
        text, meta = docker.decode(raw, "/var/lib/docker/containers/abc/abc-json.log")
        self.assertEqual(text, "part one, part two")
        self.assertEqual((meta["stream"], meta["id"]), ("stdout", "abc"))
        cri = ContainerDecoder("kubernetes", tempfile.mkdtemp())
        name = "web-7d9f_prod_nginx-" + "a" * 64 + ".log"
        text, meta = cri.decode(b"2026-10-21T10:00:00.1Z stderr P GET /x \n2026-10-21T10:00:00.2Z stderr F 404",
                                "/var/log/containers/" + name)
        self.assertEqual(text, "GET /x 404")
        self.assertEqual((meta["pod"], meta["namespace"], meta["name"]), ("web-7d9f", "prod", "nginx"))
        text, meta = JournaldDecoder().decode(
            json.dumps({"MESSAGE": "Accepted password for root", "_SYSTEMD_UNIT": "sshd.service",
                        "_HOSTNAME": "bastion", "PRIORITY": "6"}).encode(), "journald")
        self.assertEqual(text, "Accepted password for root")
        self.assertEqual(meta["journald"]["_SYSTEMD_UNIT"], "sshd.service")


# ---------------------------------------------------------------------------
# HTTP / OTLP (served by the API)
# ---------------------------------------------------------------------------

def _pb_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _pb(field: int, wire: int, payload) -> bytes:
    key = _pb_varint((field << 3) | wire)
    if wire == 2:
        return key + _pb_varint(len(payload)) + payload
    if wire == 1:
        return key + struct.pack("<Q", payload)
    return key + _pb_varint(payload)


def otlp_protobuf(records: list[tuple[str, dict]], service: str) -> bytes:
    def anystr(s):
        return _pb(1, 2, s.encode())

    def kv(k, v):
        return _pb(1, 2, k.encode()) + _pb(2, 2, anystr(v))

    resource = _pb(1, 2, kv("service.name", service))
    logs = b"".join(_pb(2, 2, _pb(1, 1, 1_760_000_000_000_000_000) + _pb(2, 0, 9) + _pb(5, 2, anystr(body))
                          + b"".join(_pb(6, 2, kv(k, v)) for k, v in attrs.items()))
                    for body, attrs in records)
    scope_logs = _pb(2, 2, logs)
    return _pb(1, 2, _pb(1, 2, resource) + scope_logs)


class TestHttpAndOtlp(unittest.TestCase):
    def test_http_and_otlp_ingest_with_auth(self):
        d = tempfile.mkdtemp(prefix="ulpf_http_")
        os.environ["ULPF_T_INGEST"] = "s3cret"
        rt = start_runtime(d, [{"type": "http", "name": "http", "api_key_env": "ULPF_T_INGEST"},
                               {"type": "otlp", "name": "otlp", "api_key_env": "ULPF_T_INGEST"}], api=True)
        base = rt.api_server.url

        def post(path, body, ctype, key="s3cret", gz=False):
            headers = {"Content-Type": ctype}
            if key:
                headers["X-API-Key"] = key
            if gz:
                body = gzip.compress(body)
                headers["Content-Encoding"] = "gzip"
            req = urllib.request.Request(base + path, data=body, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    return r.status, r.read()
            except urllib.error.HTTPError as e:
                return e.code, e.read()

        try:
            ndjson = b"\n".join(json.dumps({"src_ip": f"10.0.0.{i}", "action": "deny", "msg": "x"}).encode()
                                for i in range(50))
            self.assertEqual(post("/api/v1/ingest/stream/fw01", ndjson, "application/x-ndjson", key=None)[0], 401)
            st, body = post("/api/v1/ingest/stream/fw01", ndjson, "application/x-ndjson", gz=True)
            self.assertEqual((st, json.loads(body)["accepted"]), (200, 50))
            arr = json.dumps(["<134>Oct 11 22:14:15 host app: line %d" % i for i in range(20)]).encode()
            self.assertEqual(json.loads(post("/api/v1/ingest/stream/fw02", arr, "application/json")[1])["accepted"], 20)
            pb = otlp_protobuf([(f"<34>Oct 11 22:14:15 db01 sshd[1]: Failed password for root from 10.9.9.{i}",
                                 {"log.file.path": "/var/log/auth.log"}) for i in range(10)], "auth-svc")
            self.assertEqual(post("/v1/logs", pb, "application/x-protobuf")[0], 200)
            js = {"resourceLogs": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "api"}}]},
                                    "scopeLogs": [{"logRecords": [{"timeUnixNano": "1760000000000000000",
                                                                   "body": {"kvlistValue": {"values": [
                                                                       {"key": "user", "value": {"stringValue": "bob"}}]}},
                                                                   "attributes": []} for _ in range(5)]}]}]}
            self.assertEqual(post("/v1/logs", json.dumps(js).encode(), "application/json")[0], 200)
            self.assertTrue(wait_for(lambda: delivered(rt) >= 85, 30), delivered(rt))
            sources = dict(stored(rt, "SELECT json_extract_string(normalised_json, '$.metadata.ingestion_source'), "
                                      "COUNT(*) FROM events GROUP BY 1"))
            self.assertEqual(sources.get("fw01"), 50)
            self.assertEqual(sources.get("fw02"), 20)
            self.assertEqual(sources.get("auth-svc"), 10)   # OTLP source: resource service.name
            self.assertEqual(sources.get("api"), 5)
            # raw retrieval through the API returns the exact journaled bytes
            eid = stored(rt, "SELECT event_id FROM events WHERE raw_event LIKE '%Failed password%' LIMIT 1")[0][0]
            with urllib.request.urlopen(urllib.request.Request(base + f"/api/v1/events/{eid}/raw?format=json",
                                                               headers={"X-API-Key": "s3cret"}), timeout=20) as r:
                doc = json.loads(r.read())
            self.assertTrue(doc["matches_event"])
            self.assertTrue(doc["raw"].startswith("<34>Oct 11"))
        finally:
            rt.stop()


# ---------------------------------------------------------------------------
# Syslog TLS
# ---------------------------------------------------------------------------

class TestSyslogTls(unittest.TestCase):
    def test_tls_octet_counted_and_newline(self):
        d = tempfile.mkdtemp(prefix="ulpf_tls_")
        cert, key = self_signed_cert(d)
        port = free_port()
        rt = start_runtime(d, [{"type": "syslog", "name": "tls", "protocol": "tls", "host": "127.0.0.1",
                                "port": port, "tls": {"cert": cert, "key": key}}])
        try:
            ctx = ssl.create_default_context(cafile=cert)
            msgs = [f"<134>1 2026-10-21T10:00:00Z fw01 app - - - multi\nline message {i}".encode() for i in range(30)]
            with socket.create_connection(("127.0.0.1", port)) as raw:
                with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as s:
                    s.sendall(b"".join(str(len(m)).encode() + b" " + m for m in msgs))
            with socket.create_connection(("127.0.0.1", port)) as raw:
                with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as s:
                    s.sendall(b"".join(b"<134>Oct 11 22:14:15 r1 app: nl %d\n" % i for i in range(20)))
            self.assertTrue(wait_for(lambda: delivered(rt) >= 50, 30), delivered(rt))
            n = stored(rt, "SELECT COUNT(*) FROM events WHERE raw_event LIKE '%multi%line message%'")[0][0]
            self.assertEqual(n, 30)                  # newlines inside octet frames survive
        finally:
            rt.stop()


# ---------------------------------------------------------------------------
# NetFlow / SNMP
# ---------------------------------------------------------------------------

def netflow_v5(n: int) -> bytes:
    now = int(time.time())
    head = struct.pack("!HHIIIIBBH", 5, n, 100_000, now, 0, 1, 0, 0, 0)
    recs = b"".join(struct.pack("!4s4s4sHHIIIIHHBBBBHHBBH", bytes([10, 0, 0, i + 1]), bytes([8, 8, 8, 8]),
                                bytes(4), 1, 2, 10, 1500, 90_000, 99_000, 40000 + i, 443, 0, 0x18, 6, 0, 0, 0,
                                24, 24, 0) for i in range(n))
    return head + recs


def netflow_v9(n: int) -> tuple[bytes, bytes]:
    now = int(time.time())
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4)]
    tpl = struct.pack("!HH", 256, len(fields)) + b"".join(struct.pack("!HH", a, b) for a, b in fields)
    tset = struct.pack("!HH", 0, 4 + len(tpl)) + tpl
    head = struct.pack("!HHIIII", 9, 1, 100_000, now, 1, 7)
    data = b"".join(bytes([192, 168, 1, i + 1]) + bytes([1, 1, 1, 1]) + struct.pack("!HHBII", 5000 + i, 53, 17, 120, 2)
                    for i in range(n))
    pad = (4 - (4 + len(data)) % 4) % 4
    dset = struct.pack("!HH", 256, 4 + len(data) + pad) + data + bytes(pad)
    return head + tset, struct.pack("!HHIIII", 9, n, 100_000, now, 2, 7) + dset


def snmp_v2c_trap(community: str, oid: str, inform: bool = False) -> bytes:
    from ulpf.runtime.inputs.snmp import ber_enc_int, ber_enc_oid, ber_tlv
    vb = (ber_tlv(0x30, ber_enc_oid("1.3.6.1.2.1.1.3.0") + ber_tlv(0x43, (12345).to_bytes(4, "big")))
          + ber_tlv(0x30, ber_enc_oid("1.3.6.1.6.3.1.1.4.1.0") + ber_enc_oid(oid))
          + ber_tlv(0x30, ber_enc_oid("1.3.6.1.2.1.2.2.1.1.3") + ber_enc_int(3)))
    pdu = ber_tlv(0xA6 if inform else 0xA7, ber_enc_int(42) + ber_enc_int(0) + ber_enc_int(0) + ber_tlv(0x30, vb))
    return ber_tlv(0x30, ber_enc_int(1) + ber_tlv(0x04, community.encode()) + pdu)


def snmp_v3_trap(user: str, auth_pw: str, priv_pw: str, oid: str) -> bytes:
    from ulpf.runtime.inputs.snmp import (_aes_cfb, ber_enc_int, ber_enc_oid, ber_tlv, localize_key,
                                          password_to_key)
    engine = bytes.fromhex("80001f8880c71100000a")
    boots, etime = 3, 1000
    vb = ber_tlv(0x30, ber_enc_oid("1.3.6.1.6.3.1.1.4.1.0") + ber_enc_oid(oid))
    pdu = ber_tlv(0xA7, ber_enc_int(7) + ber_enc_int(0) + ber_enc_int(0) + ber_tlv(0x30, vb))
    scoped = ber_tlv(0x30, ber_tlv(0x04, engine) + ber_tlv(0x04, b"") + pdu)
    salt = os.urandom(8)
    pkey = localize_key(password_to_key(priv_pw, "sha"), engine, "sha")
    enc = _aes_cfb(pkey, boots.to_bytes(4, "big") + etime.to_bytes(4, "big") + salt, scoped, encrypt=True)
    usm = ber_tlv(0x30, ber_tlv(0x04, engine) + ber_enc_int(boots) + ber_enc_int(etime) + ber_tlv(0x04, user.encode())
                  + ber_tlv(0x04, bytes(12)) + ber_tlv(0x04, salt))
    gd = ber_tlv(0x30, ber_enc_int(99) + ber_enc_int(65507) + ber_tlv(0x04, b"\x03") + ber_enc_int(3))
    msg = ber_tlv(0x30, ber_enc_int(3) + gd + ber_tlv(0x04, usm) + ber_tlv(0x04, enc))
    akey = localize_key(password_to_key(auth_pw, "sha"), engine, "sha")
    mac = hmac.new(akey, msg, hashlib.sha1).digest()[:12]
    i = msg.find(bytes(12))
    return msg[:i] + mac + msg[i + 12:]


class TestNetworkCollectors(unittest.TestCase):
    def test_netflow_v5_v9_and_snmp_v2c_v3(self):
        d = tempfile.mkdtemp(prefix="ulpf_nf_")
        nf_port, snmp_port = free_port(socket.SOCK_DGRAM), free_port(socket.SOCK_DGRAM)
        os.environ.update(ULPF_T_AUTH="authpass123", ULPF_T_PRIV="privpass123")
        rt = start_runtime(d, [
            {"type": "netflow", "name": "nf", "host": "127.0.0.1", "port": nf_port},
            {"type": "snmp_trap", "name": "snmp", "host": "127.0.0.1", "port": snmp_port, "communities": ["ulpf"],
             "v3_users": [{"name": "ops", "auth_protocol": "sha", "auth_key_env": "ULPF_T_AUTH",
                           "priv_protocol": "aes", "priv_key_env": "ULPF_T_PRIV"}]}])
        try:
            self.assertTrue(wait_for(lambda: all(rt.inputs[n].describe()["bound_port"] for n in ("nf", "snmp")), 10))
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.addCleanup(s.close)
            s.settimeout(3)
            s.sendto(netflow_v5(5), ("127.0.0.1", nf_port))
            tpl, data = netflow_v9(4)
            s.sendto(tpl, ("127.0.0.1", nf_port))
            s.sendto(data, ("127.0.0.1", nf_port))
            s.sendto(snmp_v2c_trap("ulpf", "1.3.6.1.6.3.1.1.5.3"), ("127.0.0.1", snmp_port))
            s.sendto(snmp_v2c_trap("ulpf", "1.3.6.1.6.3.1.1.5.4", inform=True), ("127.0.0.1", snmp_port))
            ack, _ = s.recvfrom(65535)                 # inform is acknowledged
            self.assertEqual(ack[ack.find(b"\xa2")], 0xA2)
            s.sendto(snmp_v2c_trap("wrong", "1.3.6.1.6.3.1.1.5.3"), ("127.0.0.1", snmp_port))
            s.sendto(snmp_v3_trap("ops", "authpass123", "privpass123", "1.3.6.1.6.3.1.1.5.5"), ("127.0.0.1", snmp_port))
            s.sendto(snmp_v3_trap("ops", "WRONGPASS!!", "privpass123", "1.3.6.1.6.3.1.1.5.5"), ("127.0.0.1", snmp_port))
            self.assertTrue(wait_for(lambda: delivered(rt) >= 12, 30), delivered(rt))
            time.sleep(0.5)
            rows = stored(rt, "SELECT json_extract_string(normalised_json, '$.metadata.input'), "
                              "source_ip, destination_ip, raw_event FROM events")
            flows = [r for r in rows if r[0] == "nf"]
            traps = [r for r in rows if r[0] == "snmp"]
            self.assertEqual(len(flows), 9)
            self.assertIn("10.0.0.1", {r[1] for r in flows})
            self.assertIn("192.168.1.1", {r[1] for r in flows})
            self.assertEqual(len(traps), 3)            # wrong community / wrong v3 key dropped
            v3 = [json.loads(r[3]) for r in traps if json.loads(r[3])["version"] == "v3"]
            self.assertEqual(v3[0]["trap_name"], "authenticationFailure")
            self.assertTrue(v3[0]["encrypted"])
            self.assertGreaterEqual(rt.inputs["snmp"].describe()["auth_failures"], 2)
        finally:
            rt.stop()


@unittest.skipUnless(sys.platform == "win32", "Windows event channels")
class TestWindowsEventLog(unittest.TestCase):
    def test_reads_and_parses_live_system_events(self):
        from ulpf.engine.pipeline import Pipeline
        from ulpf.runtime.inputs.evtx import EvtxInput

        class Ctx:
            pass

        inp = EvtxInput("evtx", {"type": "evtx", "channels": ["System"], "query": "*"}, Ctx())
        inp.exe = "wevtutil"
        newest = inp._query_newest("System")
        events = inp._query("System", max(0, newest - 5))
        self.assertGreaterEqual(len(events), 1)
        p = Pipeline(enable_auto_parser=False)
        r = p.process_line(events[-1].decode("utf-8", "replace").replace("\r", "").replace("\n", ""))
        self.assertTrue(r["success"])
        self.assertEqual(r["event"]["raw_format"], "xml")


# ---------------------------------------------------------------------------
# Cloud pull inputs
# ---------------------------------------------------------------------------

class TestCloudInputs(unittest.TestCase):
    def test_cloudtrail_pubsub_okta_entra(self):
        trail = {"Records": [{"eventName": "ConsoleLogin", "sourceIPAddress": f"203.0.113.{i}",
                              "userIdentity": {"userName": "alice"}, "eventTime": "2026-10-21T10:00:00Z"}
                             for i in range(7)]}
        state = {"sqs": [{"ReceiptHandle": "rh1", "Body": json.dumps(
            {"Records": [{"s3": {"bucket": {"name": "trail"}, "object": {"key": "AWSLogs/1/x.json.gz"}}}]})}],
            "deleted": [], "pubsub": [{"ackId": f"a{i}", "message": {"data": base64.b64encode(
                json.dumps({"severity": "ERROR", "textPayload": f"disk {i}"}).encode()).decode()}} for i in range(4)],
            "acked": [], "okta_pages": 0}

        def respond(req):
            p = req["path"]
            if req["headers"].get("x-amz-target") == "AmazonSQS.ReceiveMessage":
                msgs, state["sqs"] = state["sqs"], []
                return 200, {}, {"Messages": msgs}
            if req["headers"].get("x-amz-target") == "AmazonSQS.DeleteMessage":
                state["deleted"].append(json.loads(req["body"])["ReceiptHandle"])
                return 200, {}, {}
            if p.startswith("/trail/"):
                return 200, {}, gzip.compress(json.dumps(trail).encode())
            if p.startswith("/token") or "oauth2" in p:
                return 200, {}, {"access_token": "tok", "expires_in": 3600}
            if p.endswith(":pull"):
                msgs, state["pubsub"] = state["pubsub"], []
                return 200, {}, {"receivedMessages": msgs}
            if p.endswith(":acknowledge"):
                state["acked"] += json.loads(req["body"])["ackIds"]
                return 200, {}, {}
            if p.startswith("/api/v1/logs"):
                state["okta_pages"] += 1
                if "after=2" in p:
                    return 200, {"Link": f'<{fake.url}/api/v1/logs?after=2>; rel="next"'}, []
                return 200, {"Link": f'<{fake.url}/api/v1/logs?after=2>; rel="next"'}, [
                    {"eventType": "user.session.start", "outcome": {"result": "FAILURE"},
                     "client": {"ipAddress": f"198.51.100.{i}"}, "actor": {"alternateId": "bob@x"}} for i in range(3)]
            if p.startswith("/v1.0/auditLogs/signIns"):
                if "skiptoken" in p:
                    return 200, {}, {"value": [{"id": "s3", "createdDateTime": "2026-10-21T10:00:03Z",
                                                "userPrincipalName": "carol@x", "ipAddress": "192.0.2.3"}]}
                return 200, {}, {"value": [{"id": f"s{i}", "createdDateTime": f"2026-10-21T10:00:0{i}Z",
                                            "userPrincipalName": "carol@x", "ipAddress": f"192.0.2.{i}"}
                                           for i in range(2)],
                                 "@odata.nextLink": f"{fake.url}/v1.0/auditLogs/signIns?$skiptoken=abc"}
            if p.startswith("/v1.0/auditLogs/directoryAudits"):
                return 200, {}, {"value": []}
            return 404, {}, {}

        fake = FakeHTTP(respond)
        d = tempfile.mkdtemp(prefix="ulpf_cloud_")
        os.environ.update(ULPF_T_AK="AKID", ULPF_T_SK="secret", ULPF_T_OKTA="ssws", ULPF_T_ENTRA="cs")
        creds = google_credentials(fake.url + "/token", d)
        url = fake.url
        rt = start_runtime(d, [
            {"type": "cloudtrail", "name": "ct", "region": "us-east-1", "queue_url": url + "/q", "endpoint": url,
             "access_key_env": "ULPF_T_AK", "secret_key_env": "ULPF_T_SK", "poll_interval_ms": 200},
            {"type": "pubsub", "name": "ps", "project": "p", "subscription": "s", "credentials_file": creds,
             "endpoint": url, "poll_interval_ms": 200},
            {"type": "okta", "name": "okta", "domain": "x.okta.com", "token_env": "ULPF_T_OKTA", "endpoint": url,
             "poll_interval_s": 5},
            {"type": "entra", "name": "entra", "tenant_id": "t", "client_id": "c", "client_secret_env": "ULPF_T_ENTRA",
             "login_endpoint": url, "graph_endpoint": url, "poll_interval_s": 5}])
        try:
            self.assertTrue(wait_for(lambda: delivered(rt) >= 7 + 4 + 3 + 3, 40), delivered(rt))
            by_input = dict(stored(rt, "SELECT json_extract_string(normalised_json, '$.metadata.input'), COUNT(*) "
                                       "FROM events GROUP BY 1"))
            self.assertEqual(by_input, {"ct": 7, "ps": 4, "okta": 3, "entra": 3})
            self.assertEqual(state["deleted"], ["rh1"])           # SQS message removed after journaling
            self.assertEqual(sorted(state["acked"]), [f"a{i}" for i in range(4)])
            ck = rt.checkpoints.get("okta:okta")
            self.assertTrue(ck and "after=2" in ck["value"])     # cursor advanced to the next page
        finally:
            rt.stop()
            fake.close()

    def test_cloud_inputs_rejected_in_defence_mode(self):
        from ulpf.config import ConfigError
        with self.assertRaises(ConfigError) as cm:
            load_pipeline_config(data={"mode": "defence", "outputs": [{"type": "duckdb", "name": "s"}],
                                       "inputs": [{"type": "pubsub", "name": "ps", "project": "p",
                                                   "subscription": "s", "credentials_file": "x"}]})
        self.assertIn("defence.no_cloud", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
