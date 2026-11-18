#!/usr/bin/env python3
"""
ulpf-forensic-verify: court-admissible, air-gapped verification of ULPF evidence.

Runs on an isolated forensic workstation with only the Python standard library
(``cryptography`` is used when present, for speed and encrypted journals). It
never contacts the SIEM server; copy this file and ``verify_pack.py`` (or the
compiled ``ulpf-forensic-verify`` binary from ``native/ulpf_forensic``) next to
the evidence.

    ulpf-forensic-verify journal  --journal DIR [--seals DIR] [--pubkey evidence.pub]
                                  [--journal-key journal.key] [--rows events.parquet --k0 HEX
                                  --epoch-records N --node NODE] [--json]
    ulpf-forensic-verify proof    --proof proof.json --seal seal.json [--pubkey evidence.pub]
    ulpf-forensic-verify pack     PACK.zip [--pubkey signer.pub]

What ``journal`` proves, streaming (memory is bounded by one seal window):

1. Every journal block: magic, CRC-32, AES-256-GCM tag (encrypted journals),
   record framing, gap-free sequence numbers. Every record: SHA-256 of its raw
   bytes (DPDP erasure tombstones are recognised and reported).
2. On a CRC failure caused by a single flipped bit, the exact **byte offset
   and bit** in the segment file is located (CRC-32 syndrome decoding) and
   confirmed by re-checking the CRC and the record's SHA-256 with the bit
   restored. Every finding names the segment file, byte offset and sequence.
3. Seals: canonical hash, hash chain, forward-secure Ed25519 signing chain,
   identity anchors pinned to ``--pubkey``, and each window's Merkle root
   recomputed from the journal digests.
4. Optional: stored rows (Parquet export) against the journal (``raw_hash``)
   and their BLAKE2b ratchet row MACs derived from the escrowed ``K_0``.

Exit status: 0 verified, 1 problems found, 2 usage error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import zlib

try:
    from ulpf.compliance.verify_pack import ed25519_verify as _py_ed25519_verify
    from ulpf.compliance.verify_pack import public_key_raw, verify as verify_pack
except ImportError:      # copied next to verify_pack.py on a workstation without ULPF
    from verify_pack import ed25519_verify as _py_ed25519_verify  # type: ignore
    from verify_pack import public_key_raw, verify as verify_pack  # type: ignore

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as _EdPub
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
except ImportError:      # pragma: no cover - stdlib-only workstation
    _EdPub = _AESGCM = None

VERSION = "10.0.0"
_MAGIC = b"ULJB"
_HDR = struct.Struct("<4sBBHQIIII")
_REC = struct.Struct("<QdHHI32s")
_FLAG_ENC = 1
ERASED_MAGIC = b"\x00ULPF-ERASED\x00"
_CRC_POLY = 0xEDB88320
MAX_BLOCK = 1 << 30            # a header claiming a larger payload is corrupt, never allocated
MAX_LOCATE_BITS = 1 << 27      # syndrome search bound (16 MiB blocks)


def ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if _EdPub is not None:
        try:
            _EdPub.from_public_bytes(pub).verify(sig, msg)
            return True
        except Exception:
            return False
    return _py_ed25519_verify(pub, msg, sig)


# ---------------------------------------------------------------------------
# Evidence rules (identical to ulpf.runtime.evidence)
# ---------------------------------------------------------------------------

def canonical(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


def seal_hash(seal: dict) -> str:
    return hashlib.sha256(canonical({k: v for k, v in seal.items()
                                     if k not in ("seal_hash", "hmac_sha256", "signature")})).hexdigest()


def anchor_message(anchor: dict) -> bytes:
    return canonical({k: v for k, v in anchor.items() if k != "signature"})


def leaf(seq: int, digest: bytes) -> bytes:
    return hashlib.sha256(b"ulpf-leaf" + seq.to_bytes(8, "big") + digest).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    cur = leaves
    while len(cur) > 1:
        nxt = [hashlib.sha256(cur[i] + cur[i + 1]).digest() for i in range(0, len(cur) - 1, 2)]
        if len(cur) % 2:
            nxt.append(cur[-1])
        cur = nxt
    return cur[0]


def verify_proof(leaf_hash: bytes, proof: list, root_hex: str) -> bool:
    h = leaf_hash
    for step in proof:
        sib = bytes.fromhex(step["hash"])
        h = hashlib.sha256(sib + h if step["side"] == "left" else h + sib).digest()
    return h.hex() == root_hex


def ratchet(key: bytes) -> bytes:
    return hashlib.blake2b(key, digest_size=32, person=b"ulpf-ratchet").digest()


def event_id(node: str, seq: int, ordinal: int = 0) -> str:
    hx = hashlib.sha256(f"{node}:{seq}:{ordinal}".encode()).hexdigest()
    return f"{hx[:8]}-{hx[8:12]}-8{hx[13:16]}-{'89ab'[int(hx[16], 16) & 3]}{hx[17:20]}-{hx[20:32]}"


def row_mac(key: bytes, row) -> str:
    data = "\x1f".join("\x00" if v is None else (v if isinstance(v, str) else str(v)) for v in row[:-1])
    return hashlib.blake2b(data.encode("utf-8", "surrogatepass"), key=key[:64], digest_size=32).hexdigest()


# ---------------------------------------------------------------------------
# CRC-32 single-bit error location
# ---------------------------------------------------------------------------

def locate_bit_flip(payload: bytes, stored_crc: int) -> tuple[int, int] | None:
    """(byte index, bit) of the single flipped bit that explains a CRC-32 mismatch, or None.

    zlib's CRC-32 is reflected: a flip of bit j of byte k XORs ``L^m(1)`` into the
    final register, where L is one zero-input shift and m = 8*(n-k) - j. Walking L
    from 1 finds m; the candidate is confirmed by recomputing the CRC.
    """
    n = len(payload)
    syndrome = (zlib.crc32(payload) ^ stored_crc) & 0xFFFFFFFF
    if syndrome == 0 or n == 0 or 8 * n > MAX_LOCATE_BITS:
        return None
    d = 1
    for m in range(0, 8 * n + 1):
        if d == syndrome and m > 0:
            nk = -(-m // 8)
            k, j = n - nk, (-m) % 8
            if 0 <= k < n:
                fixed = bytearray(payload)
                fixed[k] ^= 1 << j
                if zlib.crc32(bytes(fixed)) & 0xFFFFFFFF == stored_crc:
                    return k, j
            return None
        d = (d >> 1) ^ (_CRC_POLY if d & 1 else 0)
    return None


# ---------------------------------------------------------------------------
# Journal scan
# ---------------------------------------------------------------------------

class Report:
    def __init__(self):
        self.problems: list[dict] = []
        self.notes: list[str] = []
        self.stats = {"segments": 0, "blocks": 0, "records": 0, "erased_records": 0, "bytes": 0,
                      "seals": 0, "signatures_checked": 0, "merkle_roots_checked": 0,
                      "rows_checked": 0, "row_macs_checked": 0}

    def problem(self, kind: str, message: str, **where) -> None:
        self.problems.append({"kind": kind, "message": message, **where})

    def to_dict(self) -> dict:
        return {"tool": "ulpf-forensic-verify", "version": VERSION, "valid": not self.problems,
                **self.stats, "problems": self.problems, "notes": self.notes}


def _segments(journal_dir: str) -> list[tuple[int, str]]:
    out = []
    for n in os.listdir(journal_dir):
        if n.startswith("seg-") and n.endswith(".ulj"):
            try:
                out.append((int(n[4:-4]), os.path.join(journal_dir, n)))
            except ValueError:
                continue
    return sorted(out)


def _parse_records(payload: bytes, bfirst: int, count: int, seg: str, base: int | None, rep: Report):
    """Yield (seq, digest, erased, raw-offset-in-file-or-None). ``base`` = file offset of the plaintext."""
    pos = 0
    for i in range(count):
        if pos + _REC.size > len(payload):
            rep.problem("framing", f"block truncated inside record {bfirst + i}", segment=seg, seq=bfirst + i)
            return
        seq, _ts, sl, il, rl, digest = _REC.unpack_from(payload, pos)
        raw_at = pos + _REC.size + sl + il
        if raw_at + rl > len(payload):
            rep.problem("framing", f"record {seq} overruns its block", segment=seg, seq=seq)
            return
        if seq != bfirst + i:
            rep.problem("sequence", f"record {i} of block {bfirst} carries sequence {seq}", segment=seg,
                        seq=bfirst + i, offset=None if base is None else base + pos)
        raw = payload[raw_at:raw_at + rl]
        erased = False
        if hashlib.sha256(raw).digest() != digest:
            if raw.startswith(ERASED_MAGIC):
                erased = True
            else:
                where = {"offset": base + raw_at, "length": rl} if base is not None else {"record_index": i}
                rep.problem("record_hash", f"record {seq}: raw bytes do not match their SHA-256",
                            segment=seg, seq=seq, **where)
        yield seq, digest, erased, (None if base is None else base + raw_at)
        pos = raw_at + rl


def scan_journal(journal_dir: str, rep: Report, aead_key: bytes | None = None):
    """Yield (seq, sha256 digest, erased) for every readable record, in order; record problems in ``rep``."""
    aead = _AESGCM(aead_key) if aead_key and _AESGCM is not None else None
    expected: int | None = None
    segs = _segments(journal_dir)
    for si, (first, path) in enumerate(segs):
        seg = os.path.basename(path)
        rep.stats["segments"] += 1
        size = os.path.getsize(path)
        rep.stats["bytes"] += size
        if expected is not None and first != expected:
            rep.problem("gap", f"segment starts at record {first}, expected {expected}", segment=seg, seq=expected)
        expected = first
        with open(path, "rb") as f:
            offset = 0
            while offset < size:
                hdr = f.read(_HDR.size)
                if len(hdr) < _HDR.size:
                    if si == len(segs) - 1:
                        rep.notes.append(f"{seg}: torn header at the tail (offset {offset}); crash mid-write")
                    else:
                        rep.problem("truncated", "segment ends inside a block header", segment=seg, offset=offset)
                    break
                magic, ver, flags, _r, bfirst, count, plen, crc, _r2 = _HDR.unpack(hdr)
                if magic != _MAGIC or plen > MAX_BLOCK:
                    rep.problem("block_header", f"invalid block header (magic {magic!r}); rest of segment unreadable",
                                segment=seg, offset=offset, seq=expected)
                    break
                payload = f.read(plen)
                if len(payload) < plen:
                    if si == len(segs) - 1:
                        rep.notes.append(f"{seg}: torn block at the tail (offset {offset}); crash mid-write")
                    else:
                        rep.problem("truncated", "segment ends inside a block", segment=seg, offset=offset,
                                    seq=bfirst)
                    break
                rep.stats["blocks"] += 1
                if bfirst != expected:
                    rep.problem("gap", f"block starts at record {bfirst}, expected {expected}", segment=seg,
                                offset=offset, seq=expected)
                pay_off = offset + _HDR.size
                if zlib.crc32(payload) & 0xFFFFFFFF != crc:
                    loc = locate_bit_flip(payload, crc)
                    msg = f"block {bfirst}..{bfirst + count - 1} fails its CRC-32"
                    where = {"segment": seg, "offset": pay_off, "seq": bfirst, "seq_last": bfirst + count - 1}
                    if loc is not None:
                        where.update(offset=pay_off + loc[0], bit=loc[1])
                        msg += f": single bit flipped at byte offset {pay_off + loc[0]} (bit {loc[1]})"
                    rep.problem("block_crc", msg, **where)
                    if not flags & _FLAG_ENC:
                        # the record holding the altered bytes (its SHA-256 fails)
                        hits = _record_hits(payload, bfirst, count, seg, pay_off)
                        if hits:
                            rep.problems[-1].update(seq=hits[0], seq_altered=hits[0])
                if flags & _FLAG_ENC:
                    if aead is None:
                        rep.problem("encrypted", "encrypted block: pass --journal-key (and install cryptography)",
                                    segment=seg, offset=offset, seq=bfirst)
                        expected = bfirst + count
                        offset = pay_off + plen
                        continue
                    try:
                        payload = aead.decrypt(payload[:12], payload[12:], struct.pack("<QI", bfirst, count))
                    except Exception:
                        rep.problem("aead", f"block {bfirst}..{bfirst + count - 1}: AES-GCM authentication failed",
                                    segment=seg, offset=offset, seq=bfirst)
                        expected = bfirst + count
                        offset = pay_off + plen
                        continue
                    base = None
                else:
                    base = pay_off
                for seq, digest, erased, _o in _parse_records(payload, bfirst, count, seg, base, rep):
                    rep.stats["records"] += 1
                    if erased:
                        rep.stats["erased_records"] += 1
                    yield seq, digest, erased
                expected = bfirst + count
                offset = pay_off + plen


def _record_hits(payload: bytes, bfirst: int, count: int, seg: str, base: int) -> list[int]:
    r = Report()
    for _ in _parse_records(payload, bfirst, count, seg, base, r):
        pass
    return [p["seq"] for p in r.problems if p["kind"] == "record_hash"]


# ---------------------------------------------------------------------------
# Seals
# ---------------------------------------------------------------------------

def load_seals(seal_dir: str) -> list[dict]:
    out = []
    for n in sorted(os.listdir(seal_dir)):
        if n.startswith("seal-") and n.endswith(".json"):
            with open(os.path.join(seal_dir, n), "r", encoding="utf-8") as f:
                s = json.load(f)
            s["_file"] = n
            out.append(s)
    return out


def check_seal_chain(seals: list[dict], pinned: bytes | None, rep: Report) -> None:
    prev = None
    expected_signer = None
    for s in seals:
        sid = {"seal": s.get("_file"), "seq": s.get("first_seq"), "seq_last": s.get("last_seq")}
        body = {k: v for k, v in s.items() if k != "_file"}
        rep.stats["seals"] += 1
        if seal_hash(body) != s.get("seal_hash"):
            rep.problem("seal_hash", "seal content does not match its hash (edited seal file)", **sid)
        if prev is not None and s.get("prev_seal_hash") != prev:
            rep.problem("seal_chain", "prev_seal_hash does not match the previous seal (removed/reordered)", **sid)
        prev = s.get("seal_hash")
        if int(s.get("version", 1)) < 2:
            rep.notes.append(f"{s.get('_file')}: version-1 HMAC seal; its MAC needs evidence.key (not checked)")
            expected_signer = None
            continue
        anchor = s.get("anchor")
        if anchor is not None:
            ident = bytes.fromhex(anchor.get("identity_pub", ""))
            if pinned is not None and ident != pinned:
                rep.problem("anchor_identity", f"chain anchored by an unknown identity key "
                            f"({anchor.get('identity_fpr')})", **sid)
            elif not ed25519_verify(ident, anchor_message(anchor), bytes.fromhex(anchor.get("signature", ""))):
                rep.problem("anchor_signature", "anchor signature invalid", **sid)
            if anchor.get("genesis_pub") != s.get("signer_pub"):
                rep.problem("anchor_signer", "seal not signed by the key its anchor certifies", **sid)
            if expected_signer is not None:
                rep.notes.append(f"{s.get('_file')}: signing chain re-anchored ({anchor.get('reason', '?')})")
        elif expected_signer is None:
            rep.problem("uncertified", "signing key not certified (no anchor and no previous seal)", **sid)
        elif s.get("signer_pub") != expected_signer:
            rep.problem("fs_chain", "signed by a key the previous seal did not name (forward-secure chain broken)",
                        **sid)
        try:
            ok = ed25519_verify(bytes.fromhex(s.get("signer_pub", "")), s["seal_hash"].encode(),
                                bytes.fromhex(s.get("signature", "")))
        except (ValueError, KeyError):
            ok = False
        if not ok:
            rep.problem("seal_signature", "Ed25519 signature invalid", **sid)
        rep.stats["signatures_checked"] += 1
        expected_signer = s.get("next_pub")
    if pinned is None:
        rep.notes.append("no --pubkey given: anchors were checked against the key they carry, not pinned")


def verify_journal(journal_dir: str, seal_dir: str | None = None, pubkey: bytes | None = None,
                   journal_key: bytes | None = None, rows_path: str | None = None, k0: bytes | None = None,
                   epoch_records: int | None = None, node: str | None = None) -> dict:
    rep = Report()
    seals = load_seals(seal_dir) if seal_dir and os.path.isdir(seal_dir) else []
    if seals:
        check_seal_chain(seals, pubkey, rep)
    want_rows = bool(rows_path)
    digests_for_rows: dict[str, tuple[int, str, bool]] = {}
    si = 0
    window: list[bytes] = []
    window_missing = 0
    last_seq = 0
    seals_sorted = sorted(seals, key=lambda s: s["first_seq"])

    def close_window(s: dict) -> None:
        nonlocal window, window_missing
        sid = {"seal": s.get("_file"), "seq": s["first_seq"], "seq_last": s["last_seq"]}
        if window_missing:
            rep.problem("seal_records_missing", f"{window_missing} sealed record(s) missing from the journal", **sid)
        elif merkle_root(window).hex() != s["merkle_root"]:
            rep.problem("merkle_root", "Merkle root recomputed from the journal does not match the seal "
                        "(records altered, including their stored digests)", **sid)
        else:
            rep.stats["merkle_roots_checked"] += 1
        window, window_missing = [], 0

    for seq, digest, erased in scan_journal(journal_dir, rep, journal_key):
        last_seq = seq
        if want_rows and node:
            digests_for_rows[event_id(node, seq)] = (seq, digest.hex(), erased)
        while si < len(seals_sorted) and seq > seals_sorted[si]["last_seq"]:
            s = seals_sorted[si]
            window_missing += s["last_seq"] - s["first_seq"] + 1 - len(window) - window_missing
            close_window(s)
            si += 1
        if si < len(seals_sorted) and seals_sorted[si]["first_seq"] <= seq:
            window.append(leaf(seq, digest))
            if seq == seals_sorted[si]["last_seq"]:
                close_window(seals_sorted[si])
                si += 1
    while si < len(seals_sorted):
        s = seals_sorted[si]
        if s["first_seq"] > last_seq:
            rep.problem("seal_records_missing", "sealed records are not in the journal (retention or deletion)",
                        seal=s.get("_file"), seq=s["first_seq"], seq_last=s["last_seq"])
        else:
            window_missing += s["last_seq"] - s["first_seq"] + 1 - len(window) - window_missing
            close_window(s)
        si += 1
    if want_rows:
        _check_rows(rows_path, digests_for_rows, k0, epoch_records, rep)
    return rep.to_dict()


def _check_rows(rows_path: str, digests: dict, k0: bytes | None, epoch_records: int | None, rep: Report) -> None:
    try:
        import pyarrow.parquet as pq
    except ImportError:
        rep.problem("rows", "checking stored rows needs pyarrow (pip install pyarrow)")
        return
    table = pq.read_table(rows_path)
    cols = table.column_names
    if "event_id" not in cols or "raw_hash" not in cols:
        rep.problem("rows", "rows file lacks event_id/raw_hash columns")
        return
    i_id, i_hash = cols.index("event_id"), cols.index("raw_hash")
    i_mac = cols.index("row_mac") if "row_mac" in cols else None
    keys: dict[int, bytes] = {}

    def key_for(seq: int) -> bytes | None:
        if k0 is None or not epoch_records:
            return None
        e = max(0, seq - 1) // epoch_records
        if e not in keys:
            base_e = max([x for x in keys if x <= e], default=0)
            k = keys.get(base_e, k0)
            for _ in range(base_e, e):
                k = ratchet(k)
            keys[e] = k
        return keys[e]

    for batch in table.to_batches(65536):
        for row in zip(*[c.to_pylist() for c in batch.columns]):
            hit = digests.get(row[i_id])
            if hit is None:
                continue
            seq, digest_hex, erased = hit
            rep.stats["rows_checked"] += 1
            if row[i_hash] != digest_hex:
                rep.problem("row_raw_hash", f"stored event of record {seq} has a raw_hash that differs from the "
                            "journal", seq=seq, event_id=row[i_id])
                continue
            if i_mac is None or erased:
                continue
            k = key_for(seq)
            if k is not None and row[i_mac] is not None:
                if row_mac(k, row) != row[i_mac]:
                    rep.problem("row_mac", f"stored event of record {seq} was modified after it was written",
                                seq=seq, event_id=row[i_id])
                else:
                    rep.stats["row_macs_checked"] += 1


def verify_proof_file(proof_path: str, seal_path: str, pubkey: bytes | None) -> dict:
    with open(proof_path, "r", encoding="utf-8") as f:
        proofs = json.load(f)
    with open(seal_path, "r", encoding="utf-8") as f:
        seal = json.load(f)
    rep = Report()
    check_seal_chain([seal], pubkey, rep)
    for p in proofs if isinstance(proofs, list) else [proofs]:
        lf = leaf(int(p["seq"]), bytes.fromhex(p["raw_sha256"]))
        if not seal["first_seq"] <= int(p["seq"]) <= seal["last_seq"]:
            rep.problem("proof", f"record {p['seq']} is outside this seal", seq=p["seq"])
        elif lf.hex() != p.get("leaf", lf.hex()) or not verify_proof(lf, p["proof"], seal["merkle_root"]):
            rep.problem("proof", f"record {p['seq']}: Merkle proof does not reach the seal root", seq=p["seq"])
    return rep.to_dict()


def _read_key(path: str | None) -> bytes | None:
    if not path:
        return None
    with open(path, "rb") as f:
        return public_key_raw(f.read())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ulpf-forensic-verify", description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)
    j = sub.add_parser("journal", help="verify raw journal segments, seals and (optionally) stored rows")
    j.add_argument("--journal", required=True)
    j.add_argument("--seals")
    j.add_argument("--pubkey", help="identity public key (evidence.pub) obtained out of band")
    j.add_argument("--journal-key", help="32-byte journal AES key file (encrypted journals)")
    j.add_argument("--rows", help="stored events exported as Parquet (EVENT_COLUMNS incl. row_mac)")
    j.add_argument("--k0", help="escrowed row-key K_0 (hex)")
    j.add_argument("--epoch-records", type=int)
    j.add_argument("--node")
    j.add_argument("--json", action="store_true")
    p = sub.add_parser("proof", help="verify Merkle inclusion proof(s) against a seal")
    p.add_argument("--proof", required=True)
    p.add_argument("--seal", required=True)
    p.add_argument("--pubkey")
    p.add_argument("--json", action="store_true")
    k = sub.add_parser("pack", help="verify a signed ULPF evidence / compliance pack (ZIP)")
    k.add_argument("pack")
    k.add_argument("--pubkey")
    k.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "journal":
        jkey = None
        if a.journal_key:
            with open(a.journal_key, "rb") as f:
                jkey = f.read()
            if len(jkey) != 32:
                print("journal key must be 32 bytes", file=sys.stderr)
                return 2
        res = verify_journal(a.journal, a.seals, _read_key(a.pubkey), jkey, a.rows,
                             bytes.fromhex(a.k0) if a.k0 else None, a.epoch_records, a.node)
    elif a.cmd == "proof":
        res = verify_proof_file(a.proof, a.seal, _read_key(a.pubkey))
    else:
        res = verify_pack(a.pack, _read_key(a.pubkey))
    if getattr(a, "json", False):
        print(json.dumps(res, indent=2))
    else:
        print(f"ulpf-forensic-verify {VERSION}: {'VERIFIED' if res['valid'] else 'FAILED'}")
        for kname in ("segments", "blocks", "records", "erased_records", "seals", "signatures_checked",
                      "merkle_roots_checked", "rows_checked", "row_macs_checked", "files", "proofs_checked"):
            if res.get(kname):
                print(f"  {kname:22s} {res[kname]}")
        for pr in res["problems"]:
            if isinstance(pr, dict):
                where = ", ".join(f"{x}={pr[x]}" for x in ("segment", "seal", "offset", "bit", "seq", "seq_last",
                                                          "seq_altered") if pr.get(x) is not None)
                print(f"  PROBLEM [{pr['kind']}] {pr['message']} ({where})")
            else:
                print(f"  PROBLEM {pr}")
        for n in res.get("notes", []):
            print(f"  note: {n}")
    return 0 if res["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
