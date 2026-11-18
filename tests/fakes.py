"""In-process fake servers and fixtures for connector tests (no network beyond 127.0.0.1)."""
from __future__ import annotations

import datetime
import json
import os
import socket
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeHTTP:
    """Records every request; ``responder(req) -> (status, headers, body)`` decides the answer."""

    def __init__(self, responder=None, tls_context=None):
        self.requests: list[dict] = []
        self.responder = responder or (lambda req: (200, {}, b"{}"))
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _handle(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                req = {"method": self.command, "path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                       "body": body}
                with outer._lock:
                    outer.requests.append(req)
                status, headers, out = outer.responder(req)
                if isinstance(out, (dict, list)):
                    out = json.dumps(out).encode()
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _handle

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if tls_context is not None:
            self.server.socket = tls_context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.url = f"{'https' if tls_context else 'http'}://127.0.0.1:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def bodies(self, path_prefix: str = "") -> list[bytes]:
        with self._lock:
            return [r["body"] for r in self.requests if r["path"].startswith(path_prefix)]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class FakeTcpSink:
    """Accepts TCP connections and collects every byte received."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        self.data = bytearray()
        self._lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._read, args=(c,), daemon=True).start()

    def _read(self, c):
        while True:
            try:
                b = c.recv(65536)
            except OSError:
                return
            if not b:
                return
            with self._lock:
                self.data += b

    def frames(self) -> list[bytes]:
        """Octet-counted frames received so far."""
        with self._lock:
            buf = bytes(self.data)
        out, i = [], 0
        while i < len(buf):
            sp = buf.find(b" ", i)
            if sp < 0:
                break
            n = int(buf[i:sp])
            if sp + 1 + n > len(buf):
                break
            out.append(buf[sp + 1:sp + 1 + n])
            i = sp + 1 + n
        return out

    def close(self):
        self.sock.close()


class FakeMqttBroker:
    """Minimal MQTT 3.1.1 broker: CONNECT, SUBSCRIBE, PUBLISH (QoS 0/1) to subscribers, PUBACK, PING.

    ``publish()`` sends to every subscribed client; ``acked`` collects the packet IDs the
    clients acknowledged (an input must ack only after it has journaled the message).
    """

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        self.clients: list[socket.socket] = []
        self.subscribed = threading.Event()
        self.acked: list[int] = []
        self._lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    @staticmethod
    def _varint(n: int) -> bytes:
        out = bytearray()
        while True:
            b, n = n % 128, n // 128
            out.append(b | (0x80 if n else 0))
            if not n:
                return bytes(out)

    @staticmethod
    def _recv_exact(c, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = c.recv(n - len(buf))
            if not chunk:
                raise ConnectionError
            buf += chunk
        return buf

    def _read_packet(self, c):
        head = self._recv_exact(c, 1)[0]
        mult, length = 1, 0
        while True:
            b = self._recv_exact(c, 1)[0]
            length += (b & 0x7F) * mult
            mult *= 128
            if not b & 0x80:
                break
        return head, self._recv_exact(c, length) if length else b""

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            while True:
                head, body = self._read_packet(c)
                kind = head >> 4
                if kind == 1:                                   # CONNECT
                    c.sendall(b"\x20\x02\x00\x00")
                elif kind == 8:                                 # SUBSCRIBE
                    pid = body[:2]
                    i, granted = 2, b""
                    while i < len(body):
                        n = int.from_bytes(body[i:i + 2], "big")
                        granted += bytes([min(body[i + 2 + n], 1)])
                        i += 3 + n
                    c.sendall(b"\x90" + self._varint(2 + len(granted)) + pid + granted)
                    with self._lock:
                        self.clients.append(c)
                    self.subscribed.set()
                elif kind == 4:                                 # PUBACK
                    with self._lock:
                        self.acked.append(int.from_bytes(body[:2], "big"))
                elif kind == 12:                                # PINGREQ
                    c.sendall(b"\xd0\x00")
                elif kind == 14:                                # DISCONNECT
                    return
        except (ConnectionError, OSError):
            return

    def publish(self, topic: str, payload: bytes, qos: int = 1, pid: int = 1) -> None:
        t = topic.encode()
        var = len(t).to_bytes(2, "big") + t + (pid.to_bytes(2, "big") if qos else b"")
        pkt = bytes([0x30 | (qos << 1)]) + self._varint(len(var) + len(payload)) + var + payload
        with self._lock:
            for c in self.clients:
                c.sendall(pkt)

    def close(self):
        self.sock.close()
        with self._lock:
            for c in self.clients:
                try:
                    c.close()
                except OSError:
                    pass


def self_signed_cert(directory: str | None = None) -> tuple[str, str]:
    """(cert.pem, key.pem) for CN=127.0.0.1 (also a SAN), valid for a day."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import ipaddress
    directory = directory or tempfile.mkdtemp()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                                                        x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    cp, kp = os.path.join(directory, "cert.pem"), os.path.join(directory, "key.pem")
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cp, kp


def google_credentials(token_url: str, directory: str | None = None) -> str:
    """A service-account key file whose token_uri points at a fake server."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    directory = directory or tempfile.mkdtemp()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    path = os.path.join(directory, "sa.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"type": "service_account", "client_email": "ulpf@test.iam.gserviceaccount.com",
                   "private_key": pem, "token_uri": token_url}, f)
    return path
