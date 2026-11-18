"""
Cryptographic Provenance
==========================
Attaches provenance metadata to parsed events and signs ParserSpecs so a
tampered learned-parser file is detected on load.

Specs are signed with Ed25519 (signature scheme 3). The signature binds the
spec's content hash, its lifecycle state and the operator decision
(``decided_by`` / ``decided_at``), so promoting a spec by editing its file, or
re-attributing an approval, invalidates it. Verification needs only public
keys: this installation's (``parser_signing.pub``) plus any listed in
``ULPF_PARSER_TRUSTED_KEYS`` (``os.pathsep``-separated PEM files, e.g. the
other nodes of a cluster sharing learned parsers).

The private key is ``parser_signing.pem`` in the ULPF data directory (or
``ULPF_PARSER_SIGNING_KEY``), PKCS#8, encrypted with
``ULPF_EVIDENCE_PASSPHRASE`` when that is set.

Specs signed by earlier versions with HMAC-SHA256 (schemes 1 and 2) still
verify while the legacy ``parser_signing.key`` (or ``ULPF_SIGNING_KEY_FILE``)
exists; they are re-signed with Ed25519 on their next state change.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
from typing import Any

from ulpf.intelligence.auto_parser.parser_spec import ParserSpec
from ulpf.intelligence.auto_parser.compiler import CompiledParser

logger = logging.getLogger(__name__)

SIG_SCHEME = 3
_SIG_FIELDS = ("hmac_sha256", "hmac_scheme", "pki_signature", "ed25519", "signer", "signer_pub", "sig_scheme")


def _data_path(name: str) -> str:
    from ulpf.platform.paths import get_data_dir
    return str(get_data_dir() / name)


def _load_legacy_key() -> bytes | None:
    """The pre-Ed25519 HMAC key, if this installation has one (never created any more)."""
    path = os.environ.get("ULPF_SIGNING_KEY_FILE") or _data_path("parser_signing.key")
    try:
        with open(path, "rb") as f:
            key = f.read()
        return key if len(key) >= 32 else None
    except OSError:
        return None


def _load_signing_key():
    from ulpf.runtime.keys import load_or_create_signing_key, passphrase_from_env
    path = os.environ.get("ULPF_PARSER_SIGNING_KEY") or _data_path("parser_signing.pem")
    return load_or_create_signing_key(path, passphrase_from_env())


def _trusted_from_env() -> list[bytes]:
    from ulpf.runtime.keys import load_public_key
    out = []
    for p in filter(None, (os.environ.get("ULPF_PARSER_TRUSTED_KEYS") or "").split(os.pathsep)):
        try:
            out.append(load_public_key(p))
        except (OSError, ValueError) as e:
            logger.warning(f"ignoring trusted parser key {p}: {e}")
    return out


def is_signed(spec: ParserSpec) -> bool:
    return bool(spec.metadata.get("ed25519") or spec.metadata.get("hmac_sha256"))


class ProvenanceManager:
    """Manages cryptographic provenance for parsers and events.

    ``signing_key`` an Ed25519 private key (default: this installation's);
    ``trusted`` extra raw public keys whose signatures are accepted;
    ``hmac_key`` the legacy key that verifies HMAC-signed (scheme 1/2) specs.
    """

    def __init__(self, hmac_key: bytes | None = None, signing_key=None, trusted: list[bytes] | None = None):
        from ulpf.runtime.keys import fingerprint, raw_public
        self._legacy_key = hmac_key if hmac_key is not None else _load_legacy_key()
        self._signing_key = signing_key or _load_signing_key()
        self.public_key = raw_public(self._signing_key)
        self.fingerprint = fingerprint(self.public_key)
        self._trusted = {fingerprint(p): p for p in [self.public_key, *(trusted or []), *_trusted_from_env()]}

    def attach_event_provenance(self, parsed_event: dict[str, Any],
                                parser: CompiledParser,
                                raw_line: str,
                                fingerprint: str) -> None:
        """Attach provenance metadata to a successfully parsed event."""
        meta = parsed_event.setdefault("_meta", {})
        meta["parser_id"] = parser.parser_id
        meta["parser_version"] = parser.version
        meta["source_fingerprint"] = fingerprint
        meta["parser_confidence"] = parser.spec.confidence

    @staticmethod
    def _material(spec: ParserSpec, scheme: int) -> str:
        # Scheme 1 (8.2) signed the content hash only; scheme 2 also binds the
        # lifecycle state; scheme 3 (Ed25519) also binds the operator decision.
        if scheme == 1:
            return spec.content_hash
        if scheme == 2:
            return f"{spec.content_hash}|state={spec.state}"
        md = spec.metadata
        return (f"ulpf-parser-spec|{spec.content_hash}|state={spec.state}"
                f"|decided_by={md.get('decided_by', '')}|decided_at={md.get('decided_at', '')}")

    def sign_parser_spec(self, spec: ParserSpec) -> None:
        """Bind the spec's content, lifecycle state and decision to this installation's signing key."""
        for f in _SIG_FIELDS:
            spec.metadata.pop(f, None)
        spec.metadata["sig_scheme"] = SIG_SCHEME
        spec.metadata["signer"] = self.fingerprint
        spec.metadata["signer_pub"] = self.public_key.hex()
        spec.metadata["ed25519"] = self._signing_key.sign(self._material(spec, SIG_SCHEME).encode()).hex()

    def verify_parser_spec(self, spec: ParserSpec) -> bool | None:
        """True = signature valid, False = tampered or untrusted, None = unsigned."""
        md = spec.metadata
        if md.get("ed25519"):
            from ulpf.runtime.keys import verify_signature
            pub = self._trusted.get(md.get("signer", ""))
            if pub is None:
                logger.error(f"Parser {spec.parser_id} is signed by an untrusted key {md.get('signer')!r}")
                return False
            ok = verify_signature(pub, md["ed25519"], self._material(spec, int(md.get("sig_scheme", SIG_SCHEME))).encode())
            if not ok:
                logger.error(f"Signature mismatch for parser {spec.parser_id}: spec was modified after signing")
            return ok
        stored = md.get("hmac_sha256")
        if not stored:
            return None
        if self._legacy_key is None:
            logger.error(f"Parser {spec.parser_id} carries a legacy HMAC signature but this installation "
                         "has no parser_signing.key to check it")
            return False
        scheme = int(md.get("hmac_scheme", 1))
        expected = hmac.new(self._legacy_key, self._material(spec, scheme).encode("utf-8"), hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(stored, expected)
        if not ok:
            logger.error(f"HMAC mismatch for parser {spec.parser_id}: spec was modified after signing")
        return ok
