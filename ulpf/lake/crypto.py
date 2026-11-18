"""
Client-side encryption for the cold tier (AES-256-GCM).

Each data file has its own random 256-bit data key (DEK), used as the Parquet modular-encryption
footer and column key (uniform encryption, AES_GCM_V1). The DEK is wrapped with the table's
master key (AES-256-GCM, the file's table path as associated data, so a wrapped key cannot be
moved to another file) and stored in the Delta log entry of the file. Bloom sidecars are sealed
with the same DEK. The master key comes from an environment variable and is never written.

Commits carry a MAC chain (HMAC-SHA256 under a key derived from the master key): each commit's
MAC covers its actions and the previous commit's MAC, so an edited or removed commit is
detected by ``DeltaTable.verify``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class LakeKey:
    def __init__(self, master: bytes):
        if len(master) != 32:
            raise ValueError("the lakehouse master key must be 32 bytes (base64 in the environment)")
        self._aead = AESGCM(master)
        self.mac_key = hmac.new(master, b"ulpf-lake-commit-mac-v1", hashlib.sha256).digest()
        self.key_id = hashlib.sha256(b"ulpf-lake-key-id|" + master).hexdigest()[:16]

    @classmethod
    def from_env(cls, name: str) -> "LakeKey":
        value = os.environ.get(name)
        if not value:
            raise RuntimeError(f"environment variable {name} (lakehouse master key) is not set")
        return cls(base64.b64decode(value))

    @staticmethod
    def new_dek() -> bytes:
        return os.urandom(32)

    def wrap(self, dek: bytes, path: str) -> str:
        nonce = os.urandom(12)
        return base64.b64encode(nonce + self._aead.encrypt(nonce, dek, b"dek|" + path.encode())).decode()

    def unwrap(self, wrapped: str, path: str) -> bytes:
        raw = base64.b64decode(wrapped)
        return self._aead.decrypt(raw[:12], raw[12:], b"dek|" + path.encode())


def seal(dek: bytes, data: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(dek).encrypt(nonce, data, aad)


def open_sealed(dek: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(dek).decrypt(blob[:12], blob[12:], aad)


def commit_mac(mac_key: bytes, prev: str, body: bytes) -> str:
    return hmac.new(mac_key, prev.encode() + b"|" + body, hashlib.sha256).hexdigest()


def mac_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
