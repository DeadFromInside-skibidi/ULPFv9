"""
Continuous evidence sealing (U2).

Every journal record's SHA-256 is computed at entry. The sealer groups
records into windows (``seal_every_events`` or ``seal_every_seconds``) and
writes a *seal* per window::

    leaf_i  = SHA-256("ulpf-leaf" | seq_i (8 bytes) | sha256(raw_i))
    root    = Merkle root of the leaves (odd node promoted)
    seal    = {node, first_seq, last_seq, count, merkle_root, prev_seal_hash,
               created_at, schema_version, signer_pub, next_pub, [anchor], [row_mac]}
    seal_hash = SHA-256(canonical JSON of seal)
    signature = Ed25519(sk_i, seal_hash)

Forward-secure signatures (seal version 2): every seal is signed by a fresh
one-time Ed25519 key ``sk_i`` and names the public key of the next one
(``next_pub``); ``sk_i`` is erased once the seal is written. The first key
of a chain is certified by the installation's long-term identity key
(``evidence.pem`` / ``evidence.pub``) in an ``anchor`` carried by the seal.
A verifier needs only ``evidence.pub``. Someone who takes over the host at
time T obtains the next one-time key, not the erased earlier ones, so seals
written before T cannot be re-signed; rewriting history would need a new
anchor, which is visible (``notes``) and contradicts any off-box copy of the
seals (they are emitted as ``event_kind='seal'`` events to the outputs).

Stored rows (``evidence.row_mac``) are MAC'd with the BLAKE2b ratchet in
``ulpf.runtime.keys``: records of epoch ``e`` use ``K_e``, and the host
erases keys of committed epochs. Verifiers derive every key from the
escrowed ``K_0``.

Seals of version 1 (HMAC-SHA256 with ``evidence.key``, static row key) are
still verified when that key is given.

``verify_seals`` recomputes every root from the journal's raw bytes and,
optionally, checks that the stored events still carry the original raw hash
and a valid row MAC.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time

from ulpf.engine.schema import SCHEMA_VERSION

logger = logging.getLogger(__name__)

_LEAF_PREFIX = b"ulpf-leaf"
SEAL_VERSION = 2
SIG_ALG = "ed25519-fs"
ROW_MAC_STATIC = "blake2b-256"
ROW_MAC_RATCHET = "blake2b-256-ratchet"
_UNSIGNED_FIELDS = ("seal_hash", "hmac_sha256", "signature")


def leaf(seq: int, digest: bytes) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + seq.to_bytes(8, "big") + digest).digest()


def merkle_levels(leaves: list[bytes]) -> list[list[bytes]]:
    levels = [leaves]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = [hashlib.sha256(cur[i] + cur[i + 1]).digest() for i in range(0, len(cur) - 1, 2)]
        if len(cur) % 2:
            nxt.append(cur[-1])
        levels.append(nxt)
    return levels


try:      # compiled Merkle root (ulpf_core crypto.rs, same tree); the Python tree is the reference
    from ulpf.ulpf_core import merkle_root as _native_merkle_root
except (ImportError, AttributeError):
    _native_merkle_root = None


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if _native_merkle_root is not None and len(leaves) > 32:
        return _native_merkle_root(leaves)
    return merkle_levels(leaves)[-1][0]


def inclusion_proof(leaves: list[bytes], index: int) -> list[dict]:
    proof = []
    for level in merkle_levels(leaves)[:-1]:
        sib = index ^ 1
        if sib < len(level):
            proof.append({"side": "left" if sib < index else "right", "hash": level[sib].hex()})
        index //= 2
    return proof


def verify_proof(leaf_hash: bytes, proof: list[dict], root_hex: str) -> bool:
    h = leaf_hash
    for step in proof:
        sib = bytes.fromhex(step["hash"])
        h = hashlib.sha256(sib + h if step["side"] == "left" else h + sib).digest()
    return h.hex() == root_hex


def _canonical(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


def seal_hash(seal: dict) -> str:
    body = {k: v for k, v in seal.items() if k not in _UNSIGNED_FIELDS}
    return hashlib.sha256(_canonical(body)).hexdigest()


def anchor_message(anchor: dict) -> bytes:
    return _canonical({k: v for k, v in anchor.items() if k != "signature"})


def identity_key_path(evidence_dir: str) -> str:
    return os.path.join(evidence_dir, "evidence.pem")


def identity_pub_path(evidence_dir: str) -> str:
    return os.path.join(evidence_dir, "evidence.pub")


def _read_legacy_key(path: str) -> bytes | None:
    try:
        with open(path, "rb") as f:
            key = f.read()
        return key if len(key) == 32 else None
    except OSError:
        return None


class Sealer:
    """Seals journal windows. ``key`` is the legacy v1 HMAC key (only kept for verification)."""

    def __init__(self, directory: str, node: str, every_events: int, every_seconds: float, emit=None,
                 key: bytes | None = None, row_mac: bool = False, row_keys=None, identity=None,
                 passphrase: bytes | None = None, key_provider: str = "file"):
        self.dir = directory
        self.evidence_dir = os.path.dirname(directory)
        self.row_mac = row_mac          # recorded in each seal: verify then requires row MACs
        self.row_keys = row_keys        # keys.RowKeyRatchet (ratcheted row MACs) or None
        os.makedirs(directory, exist_ok=True)
        self.node = node
        self.every_events = every_events
        self.every_seconds = every_seconds
        self.emit = emit
        self.legacy_key = key if key is not None else \
            _read_legacy_key(os.path.join(self.evidence_dir, "evidence.key"))
        self._identity = identity
        self._passphrase = passphrase
        self._provider = key_provider
        self._lock = threading.Lock()
        self._seal_lock = threading.Lock()
        self._leaves: list[bytes] = []
        self._first: int | None = None
        self._last = 0
        self._opened = time.monotonic()
        self._state_path = os.path.join(directory, "sealer.state")
        st = self._load_state()
        self.prev_hash = st.get("prev_seal_hash", "0" * 64)
        self.last_sealed = st.get("last_sealed_seq", 0)
        self._fs_key = None
        self._anchor = st.get("anchor")
        self._kek: bytes | None = None
        had_key = bool(st.get("fs_sk") or st.get("fs_sk_enc"))
        self._fs_key = self._load_fs_key(st)
        self._adopt_orphans()
        if self._fs_key is None:
            self._start_chain("genesis" if self.last_sealed == 0 else "upgrade" if not had_key else "recovery")
        elif st.get("fs_sk"):
            self._save_state()          # migrate a v9 plaintext one-time key to the encrypted form
        self.seals_written = 0
        self._wake = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="ulpf-sealer", daemon=True)
        self._stop = threading.Event()
        self._thread.start()

    # ------------------------------------------------------------------
    # Keys
    # ------------------------------------------------------------------

    @property
    def key(self):
        """What a verifier on this host can check rows with: the row-key ratchet, else the v1 key."""
        return self.row_keys if self.row_keys is not None else self.legacy_key

    def identity(self):
        if self._identity is None:
            from ulpf.runtime.keys import load_or_create_signing_key
            self._identity = load_or_create_signing_key(identity_key_path(self.evidence_dir), self._passphrase,
                                                        self._provider, label=f"evidence:{self.node}")
        return self._identity

    @property
    def identity_pub(self) -> bytes:
        from ulpf.runtime.keys import raw_public
        return raw_public(self.identity())

    def _start_chain(self, reason: str) -> None:
        """New one-time key chain, certified by the identity key (written into the next seal)."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from ulpf.runtime.keys import fingerprint, raw_public
        ident = self.identity()
        sk = Ed25519PrivateKey.generate()
        anchor = {"type": "ulpf.anchor", "version": 1, "node": self.node, "created_at": time.time(),
                  "reason": reason, "genesis_pub": raw_public(sk).hex(),
                  "identity_pub": raw_public(ident).hex(), "identity_fpr": fingerprint(raw_public(ident)),
                  "after_seq": self.last_sealed, "after_seal_hash": self.prev_hash}
        anchor["signature"] = ident.sign(anchor_message(anchor)).hex()
        self._fs_key, self._anchor = sk, anchor
        self._save_state()
        if reason != "genesis":
            logger.info(f"evidence: new signing chain anchored after record {self.last_sealed} ({reason})")

    def _adopt_orphans(self) -> None:
        """A crash after a seal file was written but before the state was: continue after that seal.

        Its successor key was never persisted, so the chain is re-anchored.
        """
        try:
            names = sorted(n for n in os.listdir(self.dir) if n.startswith("seal-") and n.endswith(".json"))
        except OSError:
            return
        orphan = None
        for n in reversed(names):
            try:
                last = int(n[len("seal-"):-len(".json")].split("-")[1])
            except (IndexError, ValueError):
                continue
            if last > self.last_sealed:
                with open(os.path.join(self.dir, n), "r", encoding="utf-8") as f:
                    orphan = json.load(f)
            break
        if orphan is None or orphan.get("prev_seal_hash") != self.prev_hash:
            return
        self.prev_hash, self.last_sealed = orphan["seal_hash"], orphan["last_seq"]
        self._fs_key, self._anchor = None, None
        logger.warning(f"evidence: adopted seal {orphan['first_seq']}..{orphan['last_seq']} written before a crash")

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def _load_state(self) -> dict:
        try:
            with open(self._state_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _state_kek(self) -> bytes:
        """Key that encrypts the one-time signing key at rest.

        Ed25519 signatures are deterministic (RFC 8032), so the identity key's
        signature over a fixed context is a stable secret only the identity key
        (passphrase file, keyring, TPM-sealed or PKCS#11 token) can produce.
        """
        if self._kek is None:
            sig = self.identity().sign(b"ulpf-fs-state-kek\x00" + self.node.encode("utf-8"))
            self._kek = hashlib.sha256(b"ulpf-fs-kek-v1" + sig).digest()
        return self._kek

    def _load_fs_key(self, st: dict):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        if st.get("fs_sk_enc"):
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            enc = st["fs_sk_enc"]
            try:
                raw = AESGCM(self._state_kek()).decrypt(bytes.fromhex(enc["nonce"]), bytes.fromhex(enc["ct"]),
                                                       b"ulpf-fs-sk|" + self.node.encode("utf-8"))
                return Ed25519PrivateKey.from_private_bytes(raw)
            except Exception as e:      # identity key replaced: the chain is re-anchored
                logger.warning(f"evidence: one-time signing key could not be decrypted ({e}); re-anchoring")
                return None
        if st.get("fs_sk"):
            return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(st["fs_sk"]))
        return None

    def _save_state(self) -> None:
        from ulpf.runtime.keys import atomic_write, raw_private
        enc = None
        if self._fs_key is not None:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = os.urandom(12)
            enc = {"nonce": nonce.hex(), "ct": AESGCM(self._state_kek()).encrypt(
                nonce, raw_private(self._fs_key), b"ulpf-fs-sk|" + self.node.encode("utf-8")).hex()}
        st = {"prev_seal_hash": self.prev_hash, "last_sealed_seq": self.last_sealed, "fs_sk_enc": enc}
        if self._anchor is not None:
            st["anchor"] = self._anchor
        atomic_write(self._state_path, json.dumps(st).encode())

    def recover(self, journal) -> int:
        """Re-add records journaled after the last seal (crash between append and seal)."""
        n = 0
        for block in journal.iter_from(self.last_sealed + 1):
            for r in block:
                self._add(r.seq, r.sha256)
                n += 1
        return n

    # Journal listener (called under the journal lock, in sequence order)
    def on_append(self, first: int, raws, digests, *_):
        with self._lock:
            for i, d in enumerate(digests):
                self._add(first + i, d)
        if len(self._leaves) >= self.every_events:
            self._wake.set()

    def _add(self, seq: int, digest: bytes) -> None:
        if seq <= self.last_sealed or seq <= self._last:
            return
        if self._first is None:
            self._first = seq
            self._opened = time.monotonic()
        self._leaves.append(leaf(seq, digest))
        self._last = seq

    def tick(self) -> None:
        if self._leaves and time.monotonic() - self._opened >= self.every_seconds:
            self._wake.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(1.0)
            self._wake.clear()
            if self._leaves and (len(self._leaves) >= self.every_events
                                 or time.monotonic() - self._opened >= self.every_seconds):
                self.seal_now("window")

    def seal_now(self, reason: str = "manual") -> dict | None:
        # One seal at a time: each seal must chain onto the one written before it
        with self._seal_lock:
            return self._seal(reason)

    def _seal(self, reason: str) -> dict | None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from ulpf.runtime.keys import raw_public
        with self._lock:
            if not self._leaves:
                return None
            # Seal at most every_events per seal, in order
            take = self._leaves[:self.every_events]
            first = self._first
            last = first + len(take) - 1
            rest = self._leaves[len(take):]
            self._leaves = rest
            self._first = last + 1 if rest else None
            self._opened = time.monotonic()
        sk, nxt = self._fs_key, Ed25519PrivateKey.generate()
        seal = {"type": "ulpf.seal", "version": SEAL_VERSION, "node": self.node, "first_seq": first,
                "last_seq": last, "count": len(take), "merkle_root": merkle_root(take).hex(),
                "prev_seal_hash": self.prev_hash, "created_at": time.time(),
                "schema_version": SCHEMA_VERSION, "reason": reason, "sig_alg": SIG_ALG,
                "signer_pub": raw_public(sk).hex(), "next_pub": raw_public(nxt).hex()}
        if self._anchor is not None:
            seal["anchor"] = self._anchor
        if self.row_mac:
            if self.row_keys is not None:
                seal.update(row_mac=ROW_MAC_RATCHET, row_key_epoch_records=self.row_keys.epoch_records,
                            row_key_k0=self.row_keys.k0)
            else:
                seal["row_mac"] = ROW_MAC_STATIC
        seal["seal_hash"] = seal_hash(seal)
        seal["signature"] = sk.sign(seal["seal_hash"].encode()).hex()
        path = os.path.join(self.dir, f"seal-{first:020d}-{last:020d}.json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(seal, f, indent=1, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        self.prev_hash = seal["seal_hash"]
        self.last_sealed = last
        self.seals_written += 1
        # The one-time key that signed this seal is gone once the state names its successor
        self._fs_key, self._anchor = nxt, None
        del sk
        self._save_state()
        if self.emit is not None:
            from ulpf.runtime.analytics import derived_event
            ev = derived_event("seal", self.node, f"{first}-{last}", 0,
                               message=f"Evidence seal {first}..{last} ({len(take)} records), "
                                       f"Merkle root {seal['merkle_root'][:16]}",
                               severity=1, category="audit", extensions=seal)
            try:
                self.emit([ev])
            except Exception:
                logger.exception("could not route seal event")
        if self._leaves and len(self._leaves) >= self.every_events:
            self._wake.set()
        return seal

    def stats(self) -> dict:
        return {"seals_written": self.seals_written, "last_sealed_seq": self.last_sealed,
                "pending_records": len(self._leaves), "head": self.prev_hash,
                "row_key_epoch": self.row_keys.base_epoch if self.row_keys is not None else None}

    def close(self) -> None:
        self._stop.set()
        self._wake.set()


def load_seals(directory: str) -> list[dict]:
    seals = []
    for n in sorted(os.listdir(directory)):
        if n.startswith("seal-") and n.endswith(".json"):
            with open(os.path.join(directory, n), "r", encoding="utf-8") as f:
                seals.append(json.load(f))
    return seals


def _default_pubkey(directory: str) -> bytes | None:
    from ulpf.runtime.keys import load_public_key
    path = identity_pub_path(os.path.dirname(directory))
    try:
        return load_public_key(path) if os.path.exists(path) else None
    except ValueError:
        return None


def _row_chain_for(seal: dict, key, row_key):
    """The key source rows of ``seal`` are checked with: bytes, a RowKeyChain, or None."""
    from ulpf.runtime.keys import RowKeyChain
    kind = seal.get("row_mac")
    if kind == ROW_MAC_RATCHET:
        src = row_key if row_key is not None else key
        if isinstance(src, RowKeyChain):
            return src
        if isinstance(src, (bytes, bytearray)) and len(src) == 32:
            return RowKeyChain(0, bytes(src), int(seal["row_key_epoch_records"]))
        return None
    if isinstance(key, RowKeyChain):
        return key.legacy
    return key


def verify_seals(directory: str, journal, key=None, database=None, from_seq: int | None = None,
                 to_seq: int | None = None, *, pubkey: bytes | str | None = None, row_key=None,
                 erasures: dict | None = None) -> dict:
    """Recompute seals from the journal; optionally check the stored events.

    ``pubkey``  the identity public key that must have anchored every signing
                chain (raw bytes, hex or a PEM path); default
                ``<evidence dir>/evidence.pub``. Without one, anchors are
                checked against the key they carry and ``anchor_pinned`` is False.
    ``key``     v1 seals: the HMAC key (``evidence.key``). Also accepted as
                the row key below when ``row_key`` is not given.
    ``row_key`` ratcheted row MACs: K_0 (32 bytes) or a ``RowKeyChain``.
                Rows whose epoch key is not derivable are counted in
                ``row_macs_unchecked``, not reported as problems.
    ``erasures`` {event_id: record} of rows erased under a signed DPDP Certificate
                of Erasure (default: the certificates in ``<data dir>/compliance/erasures``
                signed by the pinned identity key). Their personal data was removed on
                purpose, so their row MAC is not expected to verify; their raw_hash is
                still checked. Counted in ``rows_erased``.
    """
    from ulpf.runtime.keys import RowKeyChain, load_public_key, verify_signature
    seals = load_seals(directory)
    pinned = None
    if pubkey is not None:
        pinned = load_public_key(pubkey) if not isinstance(pubkey, bytes) or len(pubkey) != 32 else pubkey
    else:
        pinned = _default_pubkey(directory)
    problems: list[str] = []
    if erasures is None and database is not None:
        from ulpf.compliance.dpdp import erasure_ledger
        erasures, ledger_problems = erasure_ledger(os.path.dirname(os.path.dirname(directory)), pinned)
        problems += ledger_problems
    erasures = erasures or {}
    rows_erased = 0
    notes: list[str] = []
    prev = None
    expected_signer: str | None = None
    checked_records = checked_events = not_in_store = 0
    signatures = macs_unchecked = 0
    for s in seals:
        sid = f"seal {s['first_seq']}..{s['last_seq']}"
        in_range = not ((from_seq is not None and s["last_seq"] < from_seq)
                        or (to_seq is not None and s["first_seq"] > to_seq))
        if seal_hash(s) != s.get("seal_hash"):
            problems.append(f"{sid}: seal content does not match its hash (edited seal file)")
        if prev is not None and s["prev_seal_hash"] != prev:
            problems.append(f"{sid}: chain broken (prev_seal_hash does not match the previous seal)")
        prev = s["seal_hash"]
        if int(s.get("version", 1)) >= 2:
            anchor = s.get("anchor")
            if anchor is not None:
                ident = bytes.fromhex(anchor.get("identity_pub", ""))
                if pinned is not None and ident != pinned:
                    problems.append(f"{sid}: signing chain anchored by an unknown identity key "
                                    f"({anchor.get('identity_fpr')})")
                elif not verify_signature(ident, anchor.get("signature", ""), anchor_message(anchor)):
                    problems.append(f"{sid}: anchor signature invalid")
                if anchor.get("genesis_pub") != s.get("signer_pub"):
                    problems.append(f"{sid}: seal not signed by the key its anchor certifies")
                if expected_signer is not None:
                    notes.append(f"{sid}: signing chain re-anchored ({anchor.get('reason', '?')})")
            elif expected_signer is None:
                problems.append(f"{sid}: signing key not certified (no anchor and no previous seal)")
            elif s.get("signer_pub") != expected_signer:
                problems.append(f"{sid}: signed by a key the previous seal did not name "
                                "(forward-secure chain broken)")
            if not verify_signature(bytes.fromhex(s.get("signer_pub", "")), s.get("signature", ""),
                                    s["seal_hash"].encode()):
                problems.append(f"{sid}: Ed25519 signature invalid")
            signatures += 1
            expected_signer = s.get("next_pub")
        else:
            legacy = key.legacy if isinstance(key, RowKeyChain) else key
            if legacy is None:
                notes.append(f"{sid}: version-1 seal HMAC not checked (no evidence.key given)")
            else:
                expected_mac = hmac.new(legacy, s["seal_hash"].encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected_mac, s.get("hmac_sha256", "")):
                    problems.append(f"{sid}: HMAC invalid (not produced by this installation's key)")
            expected_signer = None
        if not in_range:
            continue
        leaves = []
        missing = 0
        digests: dict[int, str] = {}
        for seq in range(s["first_seq"], s["last_seq"] + 1):
            try:
                r = journal.read(seq)
            except Exception as e:
                problems.append(f"{sid}: record {seq} unreadable or altered in the journal ({e})")
                r = None
            if r is None:
                missing += 1
                continue
            leaves.append(leaf(seq, r.sha256))
            digests[seq] = r.sha256_hex
            checked_records += 1
        if missing:
            problems.append(f"{sid}: {missing} record(s) no longer in the journal (retention or deletion)")
        elif merkle_root(leaves).hex() != s["merkle_root"]:
            problems.append(f"{sid}: Merkle root mismatch: journal records were altered")
        if database is not None and digests:
            chain = _row_chain_for(s, key, row_key)
            if isinstance(chain, RowKeyChain) and s.get("row_key_k0") and chain.k0 \
                    and chain.k0 != s["row_key_k0"]:
                notes.append(f"{sid}: row key given is not this chain's K_0; row MACs not checked")
                chain = None
            altered, absent, edited, unchecked, erased = _check_store(database, s["node"], digests, chain,
                                                                      require_mac=bool(s.get("row_mac")),
                                                                      erasures=erasures)
            rows_erased += erased
            checked_events += len(digests) - len(absent)
            not_in_store += len(absent)
            macs_unchecked += unchecked
            for seq in altered[:20]:
                problems.append(f"{sid}: stored event for record {seq} has a raw_hash that differs "
                                "from the journal (stored event altered)")
            for seq, why in edited[:20]:
                problems.append(f"{sid}: stored event for record {seq} was modified after it was "
                                f"written ({why})")
    return {"valid": not problems, "seals": len(seals), "records_checked": checked_records,
            "events_checked": checked_events, "records_not_in_store": not_in_store,
            "signatures_checked": signatures, "anchor_pinned": pinned is not None,
            "row_macs_unchecked": macs_unchecked, "rows_erased": rows_erased, "problems": problems,
            "notes": notes}


def _check_store(database, node: str, digests: dict[int, str], key=None, require_mac: bool = False,
                 erasures: dict | None = None) -> tuple[list[int], list[int], list[tuple[int, str]], int, int]:
    """Compare stored events with the journal.

    ``key`` is a static row key (bytes), a ``RowKeyChain`` or None (row MACs
    not checked). Returns (records whose stored raw_hash differs, records
    with no stored event, (record, reason) for rows whose row MAC does not
    verify, rows whose MAC could not be checked). A row MAC present is
    always checked; a missing one is an edit when the seal says rows were
    MAC'd (``require_mac``).
    """
    from ulpf.runtime.ids import event_id
    from ulpf.runtime.keys import RowKeyChain
    from ulpf.storage.database import EVENT_COLUMNS, row_mac
    ids = {event_id(node, seq): seq for seq in digests}
    altered, edited = [], []
    unchecked = erased = 0
    erasures = erasures or {}
    found = set()
    keys = list(ids)
    cols = ", ".join(EVENT_COLUMNS)
    i_hash, i_mac = EVENT_COLUMNS.index("raw_hash"), EVENT_COLUMNS.index("row_mac")
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        placeholders = ", ".join("?" for _ in chunk)
        with database._conn_lock:
            rows = database.conn.execute(
                f"SELECT {cols} FROM events WHERE event_id IN ({placeholders})", chunk).fetchall()
        for row in rows:
            seq = ids[row[0]]
            found.add(row[0])
            if row[i_hash] != digests[seq]:
                altered.append(seq)
                continue
            if row[0] in erasures:
                erased += 1
                continue
            k = key.key_for_seq(seq) if isinstance(key, RowKeyChain) else key
            if k is None:
                if require_mac:
                    unchecked += 1
            elif row[i_mac] is None:
                if require_mac:
                    edited.append((seq, "row MAC missing"))
            elif not hmac.compare_digest(row_mac(k, row), row[i_mac]):
                edited.append((seq, "row MAC mismatch"))
    absent = [seq for eid, seq in ids.items() if eid not in found]
    return sorted(altered), sorted(absent), sorted(edited), unchecked, erased
