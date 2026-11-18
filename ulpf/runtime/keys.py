"""
Signing keys, forward-secure key ratchets and key escrow.

Ed25519 signing keys (evidence seals, approved parser specs)
    ``load_or_create_signing_key`` returns a private key from a *provider*:

    * ``file``    PKCS#8 PEM, encrypted with the passphrase in
                  ``ULPF_EVIDENCE_PASSPHRASE`` (or ``evidence.key_passphrase_env``)
                  when it is set; unencrypted otherwise (not allowed in defence
                  mode unless the ``defence.key_protection`` rule is waived).
    * ``keyring`` the OS keyring (Windows Credential Manager, macOS Keychain,
                  Secret Service) through the optional ``keyring`` package.
    * ``pkcs11``  a non-extractable key generated on a PKCS#11 token / HSM
                  (YubiKey, Nitrokey, CloudHSM, Luna, SoftHSM2); signing runs
                  on the token (``ulpf.runtime.hwkeys``).
    * ``tpm``     the key sealed by the TPM 2.0 chip (``<path>.tpm``): only
                  this machine's TPM can unwrap it.

    The public key is always written next to the private one (``<name>.pub``,
    SubjectPublicKeyInfo PEM). Only the ``.pub`` file is given to verifiers:
    it can check signatures but cannot produce them.

Row-MAC key ratchet (forward security)
    Stored rows are MAC'd with keyed BLAKE2b. The key for journal records in
    epoch ``e`` (``e = (seq - 1) // epoch_records``) is::

        K_0 = random 32 bytes          K_{e+1} = BLAKE2b-256(K_e, person="ulpf-ratchet")

    The host keeps only the key of the oldest epoch it can still write
    (the commit watermark's), so a compromise at time T yields keys that
    cannot MAC — or re-MAC — any row committed before T. ``K_0`` is escrowed
    at creation for verifiers: sealed to an auditor's X25519 public key when
    ``evidence.row_key_escrow`` is configured (the host never keeps it in
    clear), else written once to ``row_key.k0`` for the operator to move
    off-box (forward security only holds after it is moved).

Erasure is best effort: superseded keys are overwritten in place (bytearray)
and their state files replaced; copies an SSD or a journaling filesystem
keeps are outside the process's reach (use full-disk encryption / a TPM).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)

PASSPHRASE_ENV = "ULPF_EVIDENCE_PASSPHRASE"
PROVIDERS = ("file", "keyring", "pkcs11", "tpm")
_RAW = serialization.Encoding.Raw
_RAW_FMT = serialization.PublicFormat.Raw


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

def atomic_write(path: str, data: bytes, mode: int = 0o600) -> None:
    """Write ``data`` to ``path`` durably (tmp file, fsync, rename)."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    for attempt in range(20):           # Windows: a reader may hold the target open
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == 19:
                os.remove(tmp)
                raise
            time.sleep(0.05)


def _create_exclusive(path: str, data: bytes) -> bool:
    """Create ``path`` with owner-only permissions; False if another process won the race."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    return True


def pub_path(private_path: str) -> str:
    return os.path.splitext(private_path)[0] + ".pub"


# ---------------------------------------------------------------------------
# Ed25519
# ---------------------------------------------------------------------------

def raw_public(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    if not isinstance(key, Ed25519PublicKey):     # private key, or a hardware key (hwkeys)
        key = key.public_key()
    return key.public_bytes(_RAW, _RAW_FMT)


def raw_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(_RAW, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def fingerprint(pub: bytes) -> str:
    """Short public identifier of a raw public key."""
    return hashlib.sha256(pub).hexdigest()[:32]


def public_pem(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    if not isinstance(key, Ed25519PublicKey):
        key = key.public_key()
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_public_key(path_or_data: str | bytes) -> bytes:
    """Raw 32-byte Ed25519 public key from a PEM file/bytes, 64 hex chars or raw bytes."""
    data = path_or_data
    if isinstance(path_or_data, str) and os.path.exists(path_or_data):
        with open(path_or_data, "rb") as f:
            data = f.read()
    if isinstance(data, str):
        data = data.encode()
    text = data.strip()
    if text.startswith(b"-----BEGIN"):
        key = serialization.load_pem_public_key(text)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("not an Ed25519 public key")
        return raw_public(key)
    if len(text) == 64:
        return bytes.fromhex(text.decode())
    if len(data) == 32:
        return bytes(data)
    raise ValueError("unrecognised public key (expected PEM, 64 hex chars or 32 raw bytes)")


def verify_signature(pub: bytes, signature_hex: str, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def passphrase_from_env(env_name: str | None = None) -> bytes | None:
    v = os.environ.get(env_name or PASSPHRASE_ENV)
    return v.encode("utf-8") if v else None


_key_cache: dict[tuple, Ed25519PrivateKey] = {}
_key_lock = threading.Lock()


_provider_options: dict[str, dict] = {}


def configure_provider(provider: str, options: dict | None) -> None:
    """Options of a hardware provider (``evidence.pkcs11`` / ``evidence.tpm``)."""
    _provider_options[provider] = dict(options or {})


def load_or_create_signing_key(path: str, passphrase: bytes | None = None, provider: str = "file",
                               label: str | None = None) -> Ed25519PrivateKey:
    """The Ed25519 private key stored at ``path`` (``file``) or under ``label`` (``keyring``).

    Created on first use; the public key is (re)written to ``pub_path(path)``.
    Concurrent first use by several processes yields one key (exclusive create).
    """
    if provider not in PROVIDERS:
        raise ValueError(f"unknown key provider {provider!r} (supported: {', '.join(PROVIDERS)})")
    cache_key = (provider, os.path.abspath(path), label, passphrase)
    with _key_lock:
        key = _key_cache.get(cache_key)
        if key is None:
            if provider == "keyring":
                key = _keyring_key(label or os.path.basename(path))
            elif provider == "pkcs11":
                from ulpf.runtime.hwkeys import pkcs11_key
                key = pkcs11_key(_provider_options.get("pkcs11", {}),
                                 "ulpf-" + (label or os.path.basename(path)).replace(":", "-"))
            elif provider == "tpm":
                from ulpf.runtime.hwkeys import tpm_sealed_key
                key = tpm_sealed_key(path, _provider_options.get("tpm", {}))
            else:
                key = _file_key(path, passphrase)
            _key_cache[cache_key] = key
    pub = pub_path(path)
    try:
        with open(pub, "rb") as f:
            current = f.read()
    except OSError:
        current = b""
    if current != public_pem(key):
        try:
            atomic_write(pub, public_pem(key), 0o644)
        except OSError as e:
            logger.warning(f"could not write public key {pub}: {e}")
    return key


def _file_key(path: str, passphrase: bytes | None) -> Ed25519PrivateKey:
    for _ in range(3):
        if os.path.exists(path):
            with open(path, "rb") as f:
                data = f.read()
            if not data:                     # another process is mid-create
                time.sleep(0.05)
                continue
            try:
                key = serialization.load_pem_private_key(data, password=passphrase)
            except TypeError as e:
                raise ValueError(f"{path} is passphrase-protected: set {PASSPHRASE_ENV} "
                                 "(or evidence.key_passphrase_env)") from e
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError(f"{path} is not an Ed25519 private key")
            return key
        key = Ed25519PrivateKey.generate()
        enc = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
        if _create_exclusive(path, pem):
            if not passphrase:
                logger.info(f"created unencrypted signing key {path} (set {PASSPHRASE_ENV} to encrypt new keys)")
            return key
    raise OSError(f"could not read or create signing key {path}")


def _keyring_key(label: str) -> Ed25519PrivateKey:
    try:
        import keyring
    except ImportError as e:
        raise RuntimeError("evidence.key_provider 'keyring' needs the keyring package "
                           "(pip install 'ulpf[keyring]')") from e
    stored = keyring.get_password("ulpf", label)
    if stored:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(stored))
    key = Ed25519PrivateKey.generate()
    keyring.set_password("ulpf", label, raw_private(key).hex())
    return key


# ---------------------------------------------------------------------------
# Row-MAC key ratchet
# ---------------------------------------------------------------------------

def ratchet(key: bytes | bytearray) -> bytes:
    return hashlib.blake2b(bytes(key), digest_size=32, person=b"ulpf-ratchet").digest()


def k0_id(k0: bytes) -> str:
    """Public identifier of a ratchet's K_0 (recorded in seals; reveals nothing about the key)."""
    return hashlib.blake2b(k0, digest_size=16, person=b"ulpf-k0-id").hexdigest()


def _wipe(b: bytearray) -> None:
    for i in range(len(b)):
        b[i] = 0


class RowKeyChain:
    """Keys ``K_e`` for epochs ``e >= base_epoch``, derived forward from the base key.

    Verifiers build one from the escrowed K_0 (``RowKeyChain(0, k0, n)``);
    workers get the host's current base and advance it as sequence numbers
    grow. Keys of epochs before the base cannot be derived.
    """

    def __init__(self, base_epoch: int, base_key: bytes, epoch_records: int, legacy: bytes | None = None,
                 k0: str | None = None):
        if epoch_records < 1:
            raise ValueError("epoch_records must be >= 1")
        self.base_epoch = int(base_epoch)
        self._base = bytearray(base_key)
        self.epoch_records = int(epoch_records)
        self.legacy = legacy              # pre-ratchet static key (v1 seals), if any
        self.k0 = k0 if k0 is not None else (k0_id(bytes(base_key)) if base_epoch == 0 else None)
        self._cursor: tuple[int, bytes] = (self.base_epoch, bytes(self._base))
        self._lock = threading.Lock()

    def epoch_of(self, seq: int) -> int:
        return max(0, int(seq) - 1) // self.epoch_records

    def key_for_epoch(self, epoch: int) -> bytes | None:
        with self._lock:
            if epoch < self.base_epoch:
                return None
            e, k = self._cursor
            if epoch < e:
                e, k = self.base_epoch, bytes(self._base)
            while e < epoch:
                k = ratchet(k)
                e += 1
            self._cursor = (e, k)
            return k

    def key_for_seq(self, seq: int) -> bytes | None:
        return self.key_for_epoch(self.epoch_of(seq))

    @property
    def current(self) -> bytes:
        """Key of the newest epoch derived so far (rows that carry no journal sequence)."""
        return self._cursor[1]

    def advance_to_epoch(self, epoch: int) -> bool:
        """Move the base forward to ``epoch`` and erase every earlier key. True if it moved."""
        with self._lock:
            if epoch <= self.base_epoch:
                return False
            k = bytes(self._base)
            for _ in range(epoch - self.base_epoch):
                k = ratchet(k)
            _wipe(self._base)
            self._base = bytearray(k)
            self.base_epoch = epoch
            if self._cursor[0] < epoch:
                self._cursor = (epoch, k)
            return True

    def advance_to_seq(self, next_seq: int) -> bool:
        """Keep only keys that can still be needed by records ``>= next_seq``."""
        return self.advance_to_epoch(self.epoch_of(next_seq))

    def snapshot(self) -> dict:
        """Picklable description of the current base (handed to worker processes)."""
        with self._lock:
            return {"epoch": self.base_epoch, "key": bytes(self._base).hex(),
                    "epoch_records": self.epoch_records, "k0": self.k0}

    @classmethod
    def from_snapshot(cls, snap: dict) -> "RowKeyChain":
        return cls(snap["epoch"], bytes.fromhex(snap["key"]), snap["epoch_records"], k0=snap.get("k0"))


class RowKeyRatchet(RowKeyChain):
    """The host's persistent ratchet (``<evidence dir>/row_key.state``)."""

    def __init__(self, directory: str, epoch_records: int, escrow_pub: str | None = None,
                 legacy: bytes | None = None):
        self.dir = directory
        self.state_path = os.path.join(directory, "row_key.state")
        os.makedirs(directory, exist_ok=True)
        st = self._load()
        if st is None:
            k0 = os.urandom(32)
            self._escrow(k0, escrow_pub)
            st = {"epoch": 0, "key": k0.hex(), "epoch_records": int(epoch_records), "k0": k0_id(k0)}
            atomic_write(self.state_path, json.dumps(st).encode())
        elif int(st["epoch_records"]) != int(epoch_records):
            logger.warning(f"evidence: row-key epochs stay at {st['epoch_records']} records "
                           f"(configured {epoch_records}); an existing ratchet cannot change epoch size")
        super().__init__(st["epoch"], bytes.fromhex(st["key"]), st["epoch_records"], legacy=legacy, k0=st["k0"])

    def _load(self) -> dict | None:
        try:
            with open(self.state_path, "rb") as f:
                return json.loads(f.read())
        except FileNotFoundError:
            return None

    def _escrow(self, k0: bytes, escrow_pub: str | None) -> None:
        if escrow_pub:
            with open(escrow_pub, "rb") as f:
                recipient = load_x25519_public(f.read())
            doc = seal_to(recipient, k0, info=b"ulpf-row-key-k0")
            doc["k0"] = k0_id(k0)
            atomic_write(os.path.join(self.dir, "row_key.k0.sealed"), json.dumps(doc, indent=1).encode(), 0o644)
            logger.info("evidence: row-key K_0 escrowed to the configured X25519 public key")
        else:
            atomic_write(os.path.join(self.dir, "row_key.k0"), k0)
            logger.warning(f"evidence: row-key K_0 written to {os.path.join(self.dir, 'row_key.k0')}; move it "
                           "off this host (verifiers need it; forward security holds only once it is gone), "
                           "or configure evidence.row_key_escrow")

    def advance_to_epoch(self, epoch: int) -> bool:
        if not super().advance_to_epoch(epoch):
            return False
        atomic_write(self.state_path, json.dumps(self.snapshot()).encode())
        return True


def load_row_key(path: str, escrow_private: str | None = None) -> bytes:
    """K_0 from ``row_key.k0`` (raw/hex) or ``row_key.k0.sealed`` (needs the escrow private key)."""
    with open(path, "rb") as f:
        data = f.read()
    if data.lstrip().startswith(b"{"):
        if not escrow_private:
            raise ValueError(f"{path} is sealed to an escrow key: pass the X25519 private key")
        with open(escrow_private, "rb") as f:
            pem = f.read()
        try:
            priv = serialization.load_pem_private_key(pem, password=passphrase_from_env())
        except TypeError:       # the escrow key is not encrypted (or is, and no passphrase is set)
            priv = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(priv, X25519PrivateKey):
            raise ValueError(f"{escrow_private} is not an X25519 private key")
        return open_sealed(priv, json.loads(data), info=b"ulpf-row-key-k0")
    if len(data) == 32:
        return data
    text = data.strip()
    if len(text) == 64:
        return bytes.fromhex(text.decode())
    raise ValueError(f"{path}: expected 32 raw bytes, 64 hex chars or a sealed JSON document")


# ---------------------------------------------------------------------------
# X25519 sealed boxes (key escrow)
# ---------------------------------------------------------------------------

def load_x25519_public(data: bytes) -> X25519PublicKey:
    key = serialization.load_pem_public_key(data.strip())
    if not isinstance(key, X25519PublicKey):
        raise ValueError("not an X25519 public key")
    return key


def _box_key(shared: bytes, eph_pub: bytes, recipient_pub: bytes, info: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt=eph_pub + recipient_pub, info=info).derive(shared)


def seal_to(recipient: X25519PublicKey, plaintext: bytes, info: bytes = b"ulpf-escrow") -> dict:
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(_RAW, _RAW_FMT)
    rec_pub = recipient.public_bytes(_RAW, _RAW_FMT)
    key = _box_key(eph.exchange(recipient), eph_pub, rec_pub, info)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, eph_pub + rec_pub)
    return {"alg": "x25519-hkdf-sha256-aes256gcm", "ephemeral_pub": eph_pub.hex(),
            "recipient_pub": rec_pub.hex(), "nonce": nonce.hex(), "ciphertext": ct.hex()}


def open_sealed(private: X25519PrivateKey, doc: dict, info: bytes = b"ulpf-escrow") -> bytes:
    if doc.get("alg") != "x25519-hkdf-sha256-aes256gcm":
        raise ValueError(f"unsupported escrow algorithm {doc.get('alg')!r}")
    eph_pub = bytes.fromhex(doc["ephemeral_pub"])
    rec_pub = private.public_key().public_bytes(_RAW, _RAW_FMT)
    if rec_pub.hex() != doc["recipient_pub"]:
        raise ValueError("sealed to a different escrow key")
    key = _box_key(private.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub, rec_pub, info)
    return AESGCM(key).decrypt(bytes.fromhex(doc["nonce"]), bytes.fromhex(doc["ciphertext"]), eph_pub + rec_pub)


def generate_escrow_keypair(directory: str, name: str = "ulpf_escrow",
                            passphrase: bytes | None = None) -> tuple[str, str]:
    """Create an auditor X25519 key pair. Returns (private PEM path, public PEM path)."""
    priv = X25519PrivateKey.generate()
    enc = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    priv_path = os.path.join(directory, f"{name}.pem")
    pub_file = os.path.join(directory, f"{name}.pub")
    if not _create_exclusive(priv_path, priv.private_bytes(serialization.Encoding.PEM,
                                                           serialization.PrivateFormat.PKCS8, enc)):
        raise FileExistsError(priv_path)
    atomic_write(pub_file, priv.public_key().public_bytes(serialization.Encoding.PEM,
                                                          serialization.PublicFormat.SubjectPublicKeyInfo), 0o644)
    return priv_path, pub_file
