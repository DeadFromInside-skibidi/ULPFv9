"""
Signed, self-verifying evidence packs (ZIP).

    manifest.json   kind, metadata, {file: {sha256, bytes}}   (canonical JSON)
    manifest.sig    Ed25519 signature of manifest.json (hex)
    signer.pub      signer's public key (PEM); give verifiers your key out of band too
    verify_pack.py  standalone verifier (standard library only)
    ...             the pack's files

Packs are signed with the installation's evidence identity key
(``<data dir>/evidence/evidence.pem``), the same key that anchors the seal
chain, so a verifier needs one public key for both.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import time
import zipfile

from ulpf.compliance import verify_pack as _verifier


def identity_key(data_dir: str, passphrase_env: str | None = None):
    from ulpf.runtime.keys import load_or_create_signing_key, passphrase_from_env
    path = os.path.join(data_dir, "evidence", "evidence.pem")
    return load_or_create_signing_key(path, passphrase_from_env(passphrase_env))


def canonical(d) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def write_pack(path: str, kind: str, files: dict[str, bytes], key, meta: dict | None = None) -> dict:
    """Write a signed pack; returns its manifest."""
    from ulpf.runtime.keys import fingerprint, public_pem, raw_public
    for reserved in ("manifest.json", "manifest.sig", "signer.pub", "verify_pack.py"):
        if reserved in files:
            raise ValueError(f"{reserved} is reserved")
    with open(_verifier.__file__, "rb") as f:
        files = {**files, "verify_pack.py": f.read(), "signer.pub": public_pem(key)}
    manifest = {"format": "ulpf.pack", "version": 1, "kind": kind,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "signer_fingerprint": fingerprint(raw_public(key)), **(meta or {}),
                "files": {n: {"sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)} for n, b in sorted(files.items())}}
    mbytes = canonical(manifest)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", mbytes)
        z.writestr("manifest.sig", key.sign(mbytes).hex())
        for name, data in sorted(files.items()):
            z.writestr(name, data)
    os.replace(tmp, path)
    return manifest


def verify(path: str, pubkey: bytes | None = None) -> dict:
    return _verifier.verify(path, pubkey)


def evidence_for(data_dir: str, journal, seqs: list[int]) -> tuple[dict[str, bytes], list[dict]]:
    """Seals and Merkle inclusion proofs for journal records (for packs).

    Returns ({"seals/<file>": bytes}, proofs). Records not sealed yet (or whose
    journal record expired) are listed with ``"sealed": False``.
    """
    from ulpf.runtime.evidence import inclusion_proof, leaf, load_seals
    seal_dir = os.path.join(data_dir, "evidence", "seals")
    seals = load_seals(seal_dir) if os.path.isdir(seal_dir) else []
    files: dict[str, bytes] = {}
    proofs: list[dict] = []
    leaves_cache: dict[str, list[bytes]] = {}
    for seq in sorted(set(seqs)):
        s = next((x for x in seals if x["first_seq"] <= seq <= x["last_seq"]), None)
        rec = journal.read(seq) if journal is not None else None
        if s is None or rec is None:
            proofs.append({"seq": seq, "sealed": False})
            continue
        key = s["seal_hash"]
        if key not in leaves_cache:
            leaves_cache[key] = [leaf(q, journal.read(q).sha256) for q in range(s["first_seq"], s["last_seq"] + 1)]
            files[f"seals/seal-{s['first_seq']:020d}-{s['last_seq']:020d}.json"] = canonical(s)
        leaves = leaves_cache[key]
        i = seq - s["first_seq"]
        proofs.append({"seq": seq, "sealed": True, "seal_hash": key, "raw_sha256": rec.sha256_hex,
                       "leaf": leaves[i].hex(), "proof": inclusion_proof(leaves, i)})
    return files, [p for p in proofs if p.get("sealed")] + [p for p in proofs if not p.get("sealed")]


def zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for n, b in sorted(files.items()):
            z.writestr(n, b)
    return buf.getvalue()
