#!/usr/bin/env python3
"""
Standalone verifier for ULPF evidence packs (DPDP breach packs, erasure
certificates, CBAM data packs). Needs only the Python standard library.

    python verify_pack.py PACK.zip [--pubkey signer.pub]

Checks:
  1. every file listed in manifest.json has the SHA-256 and size recorded there,
     and no unlisted file was added;
  2. manifest.sig is a valid Ed25519 signature of manifest.json by the signer's
     public key (signer.pub inside the pack, or --pubkey: pass the key you
     obtained from the publisher out of band to rule out a re-signed pack);
  3. when the pack carries evidence (seals/*.json and proofs.json): each seal's
     hash and Ed25519 signature, and each record's Merkle inclusion proof
     against its seal's root.

Exit status 0 = valid. This file is copied verbatim into every pack.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import zipfile

# ---------------------------------------------------------------------------
# Ed25519 verification (RFC 8032, section 5.1.7), pure Python
# ---------------------------------------------------------------------------

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _xrecover(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_BY = 4 * pow(5, _P - 2, _P) % _P
_BX = _xrecover(_BY, 0)
_B = (_BX, _BY, 1, _BX * _BY % _P)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s: int, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _equal(p, q) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _decode(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _xrecover(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decode(public)
    r = _decode(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    return _equal(_mul(s, _B), _add(r, _mul(h, a)))


def public_key_raw(pem_or_hex: bytes) -> bytes:
    """Raw 32-byte Ed25519 key from SubjectPublicKeyInfo PEM, 64 hex chars or raw bytes."""
    text = pem_or_hex.strip()
    if text.startswith(b"-----BEGIN"):
        body = b"".join(l for l in text.splitlines() if l and not l.startswith(b"-----"))
        der = base64.b64decode(body)
        if len(der) != 44 or not der.startswith(bytes.fromhex("302a300506032b6570032100")):
            raise ValueError("not an Ed25519 SubjectPublicKeyInfo")
        return der[12:]
    if len(text) == 64:
        return bytes.fromhex(text.decode())
    if len(pem_or_hex) == 32:
        return bytes(pem_or_hex)
    raise ValueError("unrecognised public key")


# ---------------------------------------------------------------------------
# Evidence (seals, Merkle proofs) — same rules as ulpf.runtime.evidence
# ---------------------------------------------------------------------------

def _canonical(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


def seal_hash(seal: dict) -> str:
    return hashlib.sha256(_canonical({k: v for k, v in seal.items()
                                      if k not in ("seal_hash", "hmac_sha256", "signature")})).hexdigest()


def leaf(seq: int, digest: bytes) -> bytes:
    return hashlib.sha256(b"ulpf-leaf" + seq.to_bytes(8, "big") + digest).digest()


def verify_proof(leaf_hash: bytes, proof: list, root_hex: str) -> bool:
    h = leaf_hash
    for step in proof:
        sib = bytes.fromhex(step["hash"])
        h = hashlib.sha256(sib + h if step["side"] == "left" else h + sib).digest()
    return h.hex() == root_hex


def verify(path: str, pubkey: bytes | None = None) -> dict:
    problems: list[str] = []
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
        manifest_bytes = z.read("manifest.json")
        manifest = json.loads(manifest_bytes)
        sig = bytes.fromhex(z.read("manifest.sig").decode().strip())
        signer = pubkey or public_key_raw(z.read("signer.pub"))
        if not ed25519_verify(signer, manifest_bytes, sig):
            problems.append("manifest signature invalid (pack modified or signed by another key)")
        if pubkey is not None and "signer.pub" in names and public_key_raw(z.read("signer.pub")) != pubkey:
            problems.append("signer.pub in the pack is not the expected publisher key")
        listed = set(manifest.get("files", {}))
        for name, meta in manifest.get("files", {}).items():
            if name not in names:
                problems.append(f"{name}: listed in the manifest but missing")
                continue
            data = z.read(name)
            if hashlib.sha256(data).hexdigest() != meta["sha256"] or len(data) != meta["bytes"]:
                problems.append(f"{name}: content does not match the manifest")
        extra = names - listed - {"manifest.json", "manifest.sig"}
        for name in sorted(extra):
            problems.append(f"{name}: not listed in the manifest")
        proofs_checked = seals_checked = 0
        seals = {}
        for name in sorted(n for n in names if n.startswith("seals/") and n.endswith(".json")):
            s = json.loads(z.read(name))
            seals[s["seal_hash"]] = s
            if seal_hash(s) != s.get("seal_hash"):
                problems.append(f"{name}: seal content does not match its hash")
            elif s.get("signature") and s.get("signer_pub"):
                if not ed25519_verify(bytes.fromhex(s["signer_pub"]), s["seal_hash"].encode(),
                                      bytes.fromhex(s["signature"])):
                    problems.append(f"{name}: seal signature invalid")
            seals_checked += 1
        if "proofs.json" in names:
            for p in json.loads(z.read("proofs.json")):
                s = seals.get(p["seal_hash"])
                if s is None:
                    problems.append(f"record {p['seq']}: its seal is not in the pack")
                    continue
                lf = leaf(int(p["seq"]), bytes.fromhex(p["raw_sha256"]))
                if lf.hex() != p["leaf"] or not verify_proof(lf, p["proof"], s["merkle_root"]):
                    problems.append(f"record {p['seq']}: Merkle proof does not reach the seal root")
                proofs_checked += 1
    return {"valid": not problems, "problems": problems, "files": len(listed), "seals_checked": seals_checked,
            "proofs_checked": proofs_checked, "kind": manifest.get("kind"), "signer": signer.hex()}


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 2
    pub = None
    if "--pubkey" in argv:
        i = argv.index("--pubkey")
        with open(argv[i + 1], "rb") as f:
            pub = public_key_raw(f.read())
        argv = argv[:i] + argv[i + 2:]
    res = verify(argv[0], pub)
    print(json.dumps(res, indent=2))
    return 0 if res["valid"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
