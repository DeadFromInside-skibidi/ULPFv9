"""
Forwarder fleet control plane: enrollment, mTLS certificates, signed configuration, backpressure.

Thousands of edge forwarders (``ulpf fleet agent``) talk to the SIEM cluster over
HTTPS with mutual TLS:

1. **Enrollment** with a single-use, expiring token (stored as SHA-256 only).
   The agent sends a CSR (or the server generates the key pair for bootstrap
   kits); the fleet CA (ECDSA P-256) signs a 30-day client certificate whose
   CN is the agent id. The agent also receives an agent token (stored hashed)
   and the fleet's Ed25519 configuration-signing public key, which it pins.
2. **Heartbeats** (every 30 s with jitter; 10,000 agents is ~330 req/s) carry
   throughput and buffer fill. They are kept in memory and flushed to SQLite
   every 30 s, so heartbeats cost no disk write each.
   The answer says which configuration version the agent must run, whether
   its certificate must be rotated (< 7 days left) and a ``throttle_eps``
   when the ingest cluster is saturated (buffer fill > 80 %): cluster-wide
   backpressure pushed to the edge instead of dropped events at the core.
3. **Configuration bundles** are versioned per group and signed with Ed25519;
   agents refuse bundles whose signature does not verify against the pinned
   key, then hot-reload their pipeline.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import NameOID

CERT_DAYS = 30
ROTATE_DAYS = 7
ONLINE_SECONDS = 120
_DDL = """
CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, grp TEXT NOT NULL, token_sha TEXT NOT NULL,
  cert_serial TEXT, cert_expires REAL, enrolled_at REAL NOT NULL, info TEXT, last_seen REAL, stats TEXT,
  revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS tokens (sha TEXT PRIMARY KEY, grp TEXT NOT NULL, expires REAL NOT NULL, used INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS configs (grp TEXT NOT NULL, version INTEGER NOT NULL, config TEXT NOT NULL,
  issued_at REAL NOT NULL, actor TEXT, signature TEXT NOT NULL, PRIMARY KEY (grp, version));
"""


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _canonical(d) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def verify_bundle(bundle: dict, public_raw: bytes) -> bool:
    """Agent side: the bundle's Ed25519 signature over its canonical body (without ``signature``)."""
    body = {k: v for k, v in bundle.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(bytes.fromhex(bundle["signature"]), _canonical(body))
        return True
    except Exception:
        return False


class FleetControl:
    def __init__(self, data_dir: str, passphrase_env: str = "ULPF_FLEET_PASSPHRASE"):
        self.dir = os.path.join(data_dir, "fleet")
        os.makedirs(self.dir, exist_ok=True)
        pw = os.environ.get(passphrase_env)
        self._enc = serialization.BestAvailableEncryption(pw.encode()) if pw else serialization.NoEncryption()
        self._pw = pw.encode() if pw else None
        self._lock = threading.RLock()
        self._db = sqlite3.connect(os.path.join(self.dir, "fleet.db"), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_DDL)
        self._ca_key, self._ca_cert = self._load_ca()
        self._sign_key = self._load_signing()
        self._hb: dict[str, tuple[float, dict]] = {}
        self._last_flush = time.time()
        self.cluster = {"buffer_fill": 0.0, "eps": 0}

    # -- keys ------------------------------------------------------------------
    def _load_ca(self):
        kp, cp = os.path.join(self.dir, "ca.key"), os.path.join(self.dir, "ca.pem")
        if os.path.exists(kp) and os.path.exists(cp):
            with open(kp, "rb") as f:
                key = serialization.load_pem_private_key(f.read(), self._pw)
            with open(cp, "rb") as f:
                return key, x509.load_pem_x509_certificate(f.read())
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ULPF Fleet CA"),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ULPF")])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(now + dt.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                             content_commitment=False, key_encipherment=False,
                                             data_encipherment=False, key_agreement=False, encipher_only=False,
                                             decipher_only=False), critical=True)
                .sign(key, hashes.SHA256()))
        self._write(kp, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          self._enc), 0o600)
        self._write(cp, cert.public_bytes(serialization.Encoding.PEM), 0o644)
        return key, cert

    def _load_signing(self) -> Ed25519PrivateKey:
        p = os.path.join(self.dir, "config-signing.pem")
        if os.path.exists(p):
            with open(p, "rb") as f:
                return serialization.load_pem_private_key(f.read(), self._pw)
        k = Ed25519PrivateKey.generate()
        self._write(p, k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, self._enc),
                    0o600)
        return k

    @staticmethod
    def _write(path: str, data: bytes, mode: int) -> None:
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def public_key(self) -> bytes:
        return self._sign_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def ca_pem(self) -> str:
        return self._ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    # -- enrollment -----------------------------------------------------------
    def create_enrollment_token(self, group: str, ttl: float = 86400) -> str:
        tok = "fet_" + secrets.token_urlsafe(24)
        with self._lock:
            self._db.execute("INSERT INTO tokens VALUES (?,?,?,0)", (_sha(tok), group, time.time() + ttl))
        return tok

    def _issue(self, agent_id: str, public_key) -> x509.Certificate:
        now = dt.datetime.now(dt.timezone.utc)
        return (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
                                         x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "ulpf-forwarder")]))
                .issuer_name(self._ca_cert.subject).public_key(public_key)
                .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(now + dt.timedelta(days=CERT_DAYS))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(agent_id)]), critical=False)
                .sign(self._ca_key, hashes.SHA256()))

    def _cert_for(self, agent_id: str, csr_pem: str | None):
        key_pem = None
        if csr_pem:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
            if not csr.is_signature_valid:
                raise ValueError("CSR signature invalid")
            pub = csr.public_key()
        else:
            k = ec.generate_private_key(ec.SECP256R1())
            pub = k.public_key()
            key_pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()).decode()
        cert = self._issue(agent_id, pub)
        return cert, key_pem

    def enroll(self, token: str, agent_id: str, info: dict, csr_pem: str | None = None) -> dict:
        if not agent_id or len(agent_id) > 128 or not all(c.isalnum() or c in "-_." for c in agent_id):
            raise ValueError("agent id: 1-128 letters, digits, - _ .")
        with self._lock:
            row = self._db.execute("SELECT grp, expires, used FROM tokens WHERE sha=?", (_sha(token),)).fetchone()
            if row is None or row[2] or row[1] < time.time():
                raise PermissionError("enrollment token invalid, used or expired")
            self._db.execute("UPDATE tokens SET used=1 WHERE sha=?", (_sha(token),))
            cert, key_pem = self._cert_for(agent_id, csr_pem)
            agent_token = "fat_" + secrets.token_urlsafe(32)
            self._db.execute("INSERT OR REPLACE INTO agents (id, grp, token_sha, cert_serial, cert_expires, "
                             "enrolled_at, info) VALUES (?,?,?,?,?,?,?)",
                             (agent_id, row[0], _sha(agent_token), format(cert.serial_number, "x"),
                              cert.not_valid_after_utc.timestamp(), time.time(), json.dumps(info)[:10_000]))
        out = {"agent_id": agent_id, "group": row[0], "agent_token": agent_token,
               "certificate": cert.public_bytes(serialization.Encoding.PEM).decode(), "ca": self.ca_pem(),
               "config_signing_key": self.public_key().hex()}
        if key_pem:
            out["private_key"] = key_pem
        return out

    def _auth(self, agent_id: str, token: str):
        row = self._db.execute("SELECT grp, token_sha, cert_expires, revoked FROM agents WHERE id=?",
                               (agent_id,)).fetchone()
        if row is None or row[3] or not hmac.compare_digest(row[1], _sha(token or "")):
            raise PermissionError("unknown, revoked or unauthenticated agent")
        return row

    def rotate_certificate(self, agent_id: str, token: str, csr_pem: str | None = None) -> dict:
        with self._lock:
            self._auth(agent_id, token)
            cert, key_pem = self._cert_for(agent_id, csr_pem)
            self._db.execute("UPDATE agents SET cert_serial=?, cert_expires=? WHERE id=?",
                             (format(cert.serial_number, "x"), cert.not_valid_after_utc.timestamp(), agent_id))
        out = {"certificate": cert.public_bytes(serialization.Encoding.PEM).decode()}
        if key_pem:
            out["private_key"] = key_pem
        return out

    def revoke(self, agent_id: str) -> None:
        with self._lock:
            self._db.execute("UPDATE agents SET revoked=1 WHERE id=?", (agent_id,))

    # -- configuration --------------------------------------------------------
    def publish_config(self, group: str, config: dict, actor: str) -> dict:
        with self._lock:
            cur = self._db.execute("SELECT MAX(version) FROM configs WHERE grp=?", (group,)).fetchone()[0] or 0
            body = {"group": group, "version": cur + 1, "config": config, "issued_at": time.time()}
            sig = self._sign_key.sign(_canonical(body)).hex()
            self._db.execute("INSERT INTO configs VALUES (?,?,?,?,?,?)",
                             (group, cur + 1, json.dumps(config), body["issued_at"], actor, sig))
        return {"group": group, "version": cur + 1}

    def _latest(self, group: str):
        return self._db.execute("SELECT version, config, issued_at, signature FROM configs WHERE grp=? "
                                "ORDER BY version DESC LIMIT 1", (group,)).fetchone()

    def config_bundle(self, agent_id: str, token: str) -> dict:
        with self._lock:
            grp = self._auth(agent_id, token)[0]
            row = self._latest(grp)
        if row is None:
            return {"group": grp, "version": 0, "config": None}
        return {"group": grp, "version": row[0], "config": json.loads(row[1]), "issued_at": row[2],
                "signature": row[3]}

    # -- heartbeats / backpressure ---------------------------------------------
    def set_cluster_health(self, buffer_fill: float, eps: int | None = None) -> None:
        self.cluster["buffer_fill"] = max(0.0, min(1.0, float(buffer_fill)))
        if eps is not None:
            self.cluster["eps"] = int(eps)

    def _throttle(self, agent_eps: float) -> int | None:
        fill = self.cluster["buffer_fill"]
        if fill <= 0.8:
            return None
        factor = max(0.1, 1.0 - (fill - 0.8) / 0.2 * 0.9)          # 80 % -> 100 %, 100 % -> 10 %
        return max(50, int(max(agent_eps, 100) * factor))

    def heartbeat(self, agent_id: str, token: str, stats: dict) -> dict:
        with self._lock:
            grp, _sha_, cert_exp, _rev = self._auth(agent_id, token)
            latest = self._latest(grp)
            self._hb[agent_id] = (time.time(), {k: stats.get(k) for k in
                                                ("eps", "buffer_fill", "dropped", "config_version", "version",
                                                 "bytes_per_s") if k in stats})
            if time.time() - self._last_flush > 30:
                self.flush()
        return {"config_version": latest[0] if latest else 0,
                "throttle_eps": self._throttle(float(stats.get("eps") or 0)),
                "rotate_certificate": cert_exp - time.time() < ROTATE_DAYS * 86400,
                "heartbeat_seconds": 30, "server_time": time.time()}

    def flush(self) -> None:
        with self._lock:
            rows = [(t, json.dumps(s), a) for a, (t, s) in self._hb.items()]
            self._db.executemany("UPDATE agents SET last_seen=?, stats=? WHERE id=?", rows)
            self._last_flush = time.time()

    def agents(self, group: str | None = None) -> list[dict]:
        self.flush()
        q = "SELECT id, grp, enrolled_at, last_seen, stats, cert_expires, revoked, info FROM agents"
        rows = self._db.execute(q + (" WHERE grp=?" if group else ""), (group,) if group else ()).fetchall()
        now = time.time()
        return [{"id": r[0], "group": r[1], "enrolled_at": r[2], "last_seen": r[3],
                 "online": bool(r[3] and now - r[3] < ONLINE_SECONDS) and not r[6],
                 "stats": json.loads(r[4]) if r[4] else {}, "cert_expires": r[5], "revoked": bool(r[6]),
                 "info": json.loads(r[7]) if r[7] else {}} for r in rows]

    def summary(self) -> dict:
        ags = self.agents()
        groups: dict[str, int] = {}
        for a in ags:
            groups[a["group"]] = groups.get(a["group"], 0) + 1
        return {"agents": len(ags), "online": sum(1 for a in ags if a["online"]), "groups": groups,
                "eps": sum(float((a["stats"] or {}).get("eps") or 0) for a in ags if a["online"]),
                "cluster": dict(self.cluster)}
