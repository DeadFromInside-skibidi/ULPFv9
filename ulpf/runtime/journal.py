"""
Input journal: durable, append-only log of every accepted raw record.

One journal serves four purposes:

* **Durability** — inputs acknowledge a record only after it is journaled;
  after a crash everything above the commit watermark is replayed.
* **Raw preservation** (requirement a) — the exact bytes received, kept for
  ``retention_days``.
* **Raw retrieval / traceability** (requirement d) — events carry their
  journal sequence number; ``read(seq)`` returns the original bytes.
* **Evidence** (U2) — each record's SHA-256 is computed here, at entry, and
  feeds the evidence sealer.

Layout: ``<dir>/seg-<first_seq>.ulj`` segments made of blocks::

    header (32 bytes): magic 'ULJB' | version u8 | flags u8 | reserved u16 |
                       first_seq u64 | count u32 | payload_len u32 | crc32 u32 | reserved u32
    payload: records, or nonce(12) + AES-256-GCM(records) when flags & 1

    record: seq u64 | recv_ts f64 | src_len u16 | input_len u16 | raw_len u32 |
            sha256 (32) | source | input | raw

A torn block at the end of the newest segment (crash mid-write) is detected
by length/CRC and truncated on open.

Erasure (``erase``, DPDP right to erasure): the raw bytes of committed records
in closed segments are replaced by a tombstone (``ERASED_MAGIC`` + a
commitment) and the segment is rewritten. The record keeps its original
SHA-256, so Merkle seals over it still verify; ``read`` returns it with
``erased=True`` instead of reporting a digest mismatch.
"""
from __future__ import annotations

import bisect
import hashlib
import logging
import os
import struct
import threading
import time
import zlib
from dataclasses import dataclass
from typing import Iterator

logger = logging.getLogger(__name__)

_MAGIC = b"ULJB"
_HDR = struct.Struct("<4sBBHQIIII")       # 32 bytes
_REC = struct.Struct("<QdHHI32s")         # 56 bytes
_IDX = struct.Struct("<QQI")              # first_seq, offset, count
_FLAG_ENC = 1
_sha256 = hashlib.sha256
ERASED_MAGIC = b"\x00ULPF-ERASED\x00"


@dataclass(frozen=True)
class JournalRecord:
    seq: int
    recv_ts: float
    source: str
    input: str
    raw: bytes
    sha256: bytes
    erased: bool = False       # raw bytes destroyed (right to erasure); sha256 is the original

    @property
    def sha256_hex(self) -> str:
        return self.sha256.hex()


class JournalCorruption(RuntimeError):
    pass


def load_or_create_key(path: str) -> bytes:
    """32-byte AES key, created with owner-only permissions on first use."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            key = f.read()
        if len(key) != 32:
            raise ValueError(f"{path} must contain exactly 32 bytes")
        return key
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    key = os.urandom(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


class Journal:
    def __init__(self, directory: str, segment_bytes: int = 64 * 2**20, sync: str = "interval",
                 sync_interval_ms: int = 200, key: bytes | None = None,
                 retention_days: float = 30.0, read_only: bool = False):
        self.dir = directory
        self.read_only = read_only
        if not read_only:
            os.makedirs(directory, exist_ok=True)
        elif not os.path.isdir(directory):
            raise FileNotFoundError(f"no journal at {directory}")
        self.segment_bytes = segment_bytes
        self.sync = sync
        self.retention_days = retention_days
        self._aead = None
        if key is not None:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self._aead = AESGCM(key)
        self._lock = threading.Lock()
        self._state_path = os.path.join(directory, "journal.state")
        self._segments: list[int] = []        # first seq of each segment, ascending
        self._index_cache: dict[int, list[tuple[int, int, int]]] = {}
        self._active_index: list[tuple[int, int, int]] = []
        self._fh = None
        self._active_first = 0
        self._dirty = False
        self._listeners: list = []
        self.committed_seq = 0
        self.next_seq = 1
        self.records_written = 0
        self.bytes_written = 0
        self._recover()
        self._stop = threading.Event()
        self._syncer = None
        if sync == "interval" and not read_only:
            self._syncer = threading.Thread(target=self._sync_loop, args=(sync_interval_ms / 1000,),
                                            name="ulpf-journal-sync", daemon=True)
            self._syncer.start()

    # ------------------------------------------------------------------
    # Recovery
    # ------------------------------------------------------------------

    def _seg_path(self, first: int) -> str:
        return os.path.join(self.dir, f"seg-{first:020d}.ulj")

    def _recover(self) -> None:
        firsts = sorted(int(n[4:24]) for n in os.listdir(self.dir)
                        if n.startswith("seg-") and n.endswith(".ulj"))
        self._segments = firsts
        state = self._read_state()
        self.committed_seq = state.get("committed_seq", 0)
        if self.read_only:
            # Never write or truncate: a live runtime may be appending right now
            self._active_first = -1
            if firsts:
                index, _end, next_seq = self._scan_segment(firsts[-1], repair=True, quiet=True)
                self._index_cache[firsts[-1]] = index
                self.next_seq = next_seq
            else:
                self.next_seq = 1
            return
        if not firsts:
            self.next_seq = max(state.get("next_seq", 1), self.committed_seq + 1)
            self._open_new_segment(self.next_seq)
            return
        last = firsts[-1]
        index, end_offset, next_seq = self._scan_segment(last, repair=True)
        if next_seq - 1 < self.committed_seq:
            raise JournalCorruption(
                f"journal ends at record {next_seq - 1} but records up to {self.committed_seq} were "
                "committed: durable records are missing")
        self._active_first = last
        self._active_index = index
        self.next_seq = max(next_seq, state.get("next_seq", 1), self.committed_seq + 1)
        self._fh = open(self._seg_path(last), "r+b")
        self._fh.seek(end_offset)
        self._fh.truncate()

    def _scan_segment(self, first: int, repair: bool = False, quiet: bool = False) -> tuple[list, int, int]:
        """Return (block index, end offset of last valid block, next seq).

        Only the *final* block of a segment may be invalid (a write torn by a
        crash); with ``repair`` it is ignored. An invalid block followed by
        more data is corruption and always raises.
        """
        path = self._seg_path(first)
        index: list[tuple[int, int, int]] = []
        next_seq = first
        offset = 0
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            while True:
                hdr = f.read(_HDR.size)
                if len(hdr) < _HDR.size:
                    break
                magic, _ver, _flags, _r, bfirst, count, plen, crc, _r2 = _HDR.unpack(hdr)
                payload = f.read(plen) if magic == _MAGIC else b""
                if magic != _MAGIC or len(payload) < plen or zlib.crc32(payload) != crc:
                    block_end = offset + _HDR.size + plen
                    if magic == _MAGIC and len(payload) == plen and block_end < size:
                        raise JournalCorruption(
                            f"{path}: block at offset {offset} (records {bfirst}..{bfirst + count - 1}) "
                            "fails its checksum and is followed by more data: the journal was altered")
                    break
                index.append((bfirst, offset, count))
                offset += _HDR.size + plen
                next_seq = bfirst + count
        if offset < size:
            if repair:
                if not quiet:
                    logger.warning(f"Journal: truncating {size - offset} torn bytes at the end of {path}")
            else:
                raise JournalCorruption(f"{path}: invalid block at offset {offset}")
        return index, offset, next_seq

    def _read_state(self) -> dict:
        try:
            import json
            with open(self._state_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _write_state(self) -> None:
        import json
        tmp = self._state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"committed_seq": self.committed_seq, "next_seq": self.next_seq}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._state_path)

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    def _open_new_segment(self, first: int) -> None:
        if self._fh is not None:
            self._seal_active()
        self._active_first = first
        self._active_index = []
        self._fh = open(self._seg_path(first), "w+b")
        if first not in self._segments:
            self._segments.append(first)

    def _seal_active(self) -> None:
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._fh.close()
        idx_path = self._seg_path(self._active_first)[:-4] + ".idx"
        with open(idx_path + ".tmp", "wb") as f:
            for entry in self._active_index:
                f.write(_IDX.pack(*entry))
        os.replace(idx_path + ".tmp", idx_path)
        self._index_cache[self._active_first] = list(self._active_index)
        self._fh = None

    def add_listener(self, fn) -> None:
        """fn(first_seq, raws, digests, source, input_name, recv_ts) runs after every append,
        under the journal lock, so listeners see records in sequence order."""
        self._listeners.append(fn)

    def append(self, source: str, input_name: str, raws: list[bytes],
               recv_ts: float | None = None) -> tuple[int, list[bytes]]:
        """Journal raw records; returns (first_seq, sha256 digests)."""
        if not raws:
            return self.next_seq, []
        ts = time.time() if recv_ts is None else recv_ts
        src_b = source.encode("utf-8")[:65535]
        inp_b = input_name.encode("utf-8")[:65535]
        tail = src_b + inp_b
        pack = _REC.pack
        digests = [_sha256(r).digest() for r in raws]
        with self._lock:
            first = self.next_seq
            parts = []
            for i, raw in enumerate(raws):
                parts.append(pack(first + i, ts, len(src_b), len(inp_b), len(raw), digests[i]))
                parts.append(tail)
                parts.append(raw)
            payload = b"".join(parts)
            flags = 0
            if self._aead is not None:
                nonce = os.urandom(12)
                aad = struct.pack("<QI", first, len(raws))
                payload = nonce + self._aead.encrypt(nonce, payload, aad)
                flags |= _FLAG_ENC
            if self._fh.tell() + len(payload) > self.segment_bytes and self._active_index:
                self._open_new_segment(first)
            offset = self._fh.tell()
            self._fh.write(_HDR.pack(_MAGIC, 1, flags, 0, first, len(raws), len(payload),
                                     zlib.crc32(payload), 0))
            self._fh.write(payload)
            self._active_index.append((first, offset, len(raws)))
            self.next_seq = first + len(raws)
            self.records_written += len(raws)
            self.bytes_written += _HDR.size + len(payload)
            if self.sync == "always":
                self._fh.flush()
                os.fsync(self._fh.fileno())
            else:
                self._dirty = True
            for fn in self._listeners:
                fn(first, raws, digests, source, input_name, ts)
        return first, digests

    def flush(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.flush()
                os.fsync(self._fh.fileno())
            self._dirty = False

    def _sync_loop(self, interval: float) -> None:
        while not self._stop.wait(interval):
            if self._dirty:
                try:
                    self.flush()
                except (OSError, ValueError):
                    pass

    def set_committed(self, seq: int) -> None:
        """Advance the replay watermark: every record <= seq reached every sink buffer."""
        if seq > self.committed_seq:
            self.committed_seq = seq
            self._write_state()

    def close(self) -> None:
        self._stop.set()
        if self.read_only:
            return
        with self._lock:
            if self._fh is not None:
                self._seal_active()
        self._write_state()

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    def _segment_index(self, first: int) -> list[tuple[int, int, int]]:
        if first == self._active_first and self._fh is not None:
            return self._active_index
        idx = self._index_cache.get(first)
        if idx is None:
            idx_path = self._seg_path(first)[:-4] + ".idx"
            if os.path.exists(idx_path):
                with open(idx_path, "rb") as f:
                    data = f.read()
                idx = [_IDX.unpack_from(data, o) for o in range(0, len(data), _IDX.size)]
            else:
                idx, _, _ = self._scan_segment(first)
            self._index_cache[first] = idx
        return idx

    def _read_block(self, first_seg: int, offset: int) -> list[JournalRecord]:
        if first_seg == self._active_first:
            with self._lock:
                fh = self._fh          # re-read under the lock: close() may have run meanwhile
                if fh is not None:
                    fh.flush()
        with open(self._seg_path(first_seg), "rb") as f:
            f.seek(offset)
            magic, _v, flags, _r, bfirst, count, plen, crc, _r2 = _HDR.unpack(f.read(_HDR.size))
            payload = f.read(plen)
        if magic != _MAGIC or zlib.crc32(payload) != crc:
            raise JournalCorruption(f"block at {first_seg}:{offset} failed its checksum")
        if flags & _FLAG_ENC:
            if self._aead is None:
                raise JournalCorruption("journal block is encrypted but no key is configured")
            payload = self._aead.decrypt(payload[:12], payload[12:], struct.pack("<QI", bfirst, count))
        out = []
        pos = 0
        for _ in range(count):
            seq, ts, sl, il, rl, digest = _REC.unpack_from(payload, pos)
            pos += _REC.size
            src = payload[pos:pos + sl].decode("utf-8", "replace")
            pos += sl
            inp = payload[pos:pos + il].decode("utf-8", "replace")
            pos += il
            out.append(JournalRecord(seq, ts, src, inp, payload[pos:pos + rl], digest))
            pos += rl
        return out

    def read(self, seq: int) -> JournalRecord | None:
        """Return the record with this sequence number, or None if it was never written or expired."""
        i = bisect.bisect_right(self._segments, seq) - 1
        if i < 0 or seq >= self.next_seq:
            return None
        first = self._segments[i]
        if not os.path.exists(self._seg_path(first)):
            return None
        index = self._segment_index(first)
        j = bisect.bisect_right([b[0] for b in index], seq) - 1
        if j < 0:
            return None
        bfirst, offset, count = index[j]
        if seq >= bfirst + count:
            return None
        rec = self._read_block(first, offset)[seq - bfirst]
        if _sha256(rec.raw).digest() != rec.sha256:
            if rec.raw.startswith(ERASED_MAGIC):
                return JournalRecord(rec.seq, rec.recv_ts, rec.source, rec.input, rec.raw, rec.sha256, True)
            raise JournalCorruption(f"record {seq}: stored bytes do not match their SHA-256")
        return rec

    def iter_from(self, seq: int) -> Iterator[list[JournalRecord]]:
        """Yield blocks of records with sequence >= seq (used for replay)."""
        for first in list(self._segments):
            if not os.path.exists(self._seg_path(first)):
                continue
            for bfirst, offset, count in list(self._segment_index(first)):
                if bfirst + count <= seq:
                    continue
                yield [r for r in self._read_block(first, offset) if r.seq >= seq]

    # ------------------------------------------------------------------
    # Erasure
    # ------------------------------------------------------------------

    def erase(self, tombstones: dict[int, bytes]) -> int:
        """Destroy the raw bytes of committed records: {seq: tombstone}. Returns records erased.

        Segments holding them are rewritten (new nonce when encrypted) and atomically
        replaced; the active segment is closed first if it holds one.
        """
        if self.read_only:
            raise PermissionError("journal is open read-only")
        if not tombstones:
            return 0
        bad = [s for s in tombstones if s > self.committed_seq or s < 1]
        if bad:
            raise ValueError(f"records not committed yet (or never written): {sorted(bad)[:5]}")
        erased = 0
        with self._lock:
            if self._fh is not None and self._active_index and max(tombstones) >= self._active_first:
                self._open_new_segment(self.next_seq)          # close the active segment
            by_seg: dict[int, dict[int, bytes]] = {}
            for seq, tomb in tombstones.items():
                i = bisect.bisect_right(self._segments, seq) - 1
                if i < 0:
                    continue
                by_seg.setdefault(self._segments[i], {})[seq] = ERASED_MAGIC + tomb
            for first, targets in sorted(by_seg.items()):
                if os.path.exists(self._seg_path(first)):
                    erased += self._rewrite_segment(first, targets)
        return erased

    def _rewrite_segment(self, first: int, targets: dict[int, bytes]) -> int:
        """Lock held. Rewrite a closed segment with some records' raw bytes replaced."""
        path = self._seg_path(first)
        tmp = path + ".erase.tmp"
        index: list[tuple[int, int, int]] = []
        erased = 0
        with open(tmp, "wb") as out:
            for bfirst, offset, count in self._segment_index(first):
                recs = self._read_block(first, offset)
                if not any(r.seq in targets for r in recs):
                    with open(path, "rb") as f:          # untouched block: copy verbatim
                        f.seek(offset)
                        hdr = f.read(_HDR.size)
                        plen = _HDR.unpack(hdr)[6]
                        index.append((bfirst, out.tell(), count))
                        out.write(hdr + f.read(plen))
                    continue
                parts = []
                for r in recs:
                    raw = r.raw
                    if r.seq in targets:
                        if not raw.startswith(ERASED_MAGIC):
                            erased += 1
                        raw = targets[r.seq]
                    src_b, inp_b = r.source.encode("utf-8"), r.input.encode("utf-8")
                    parts += [_REC.pack(r.seq, r.recv_ts, len(src_b), len(inp_b), len(raw), r.sha256),
                              src_b, inp_b, raw]
                payload = b"".join(parts)
                flags = 0
                if self._aead is not None:
                    nonce = os.urandom(12)
                    payload = nonce + self._aead.encrypt(nonce, payload, struct.pack("<QI", bfirst, count))
                    flags |= _FLAG_ENC
                index.append((bfirst, out.tell(), count))
                out.write(_HDR.pack(_MAGIC, 1, flags, 0, bfirst, count, len(payload), zlib.crc32(payload), 0))
                out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        for attempt in range(50):                       # Windows: a reader may hold the file open
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == 49:
                    os.remove(tmp)
                    raise
                time.sleep(0.05)
        idx_path = path[:-4] + ".idx"
        with open(idx_path + ".tmp", "wb") as f:
            for entry in index:
                f.write(_IDX.pack(*entry))
        os.replace(idx_path + ".tmp", idx_path)
        self._index_cache[first] = index
        return erased

    # ------------------------------------------------------------------
    # Retention
    # ------------------------------------------------------------------

    def sweep(self, now: float | None = None) -> int:
        """Delete closed segments that are fully committed and older than retention. Returns count."""
        if self.retention_days <= 0:
            return 0
        now = now or time.time()
        cutoff = now - self.retention_days * 86400
        removed = 0
        with self._lock:
            snapshot = list(self._segments)
            for first, nxt in zip(snapshot, snapshot[1:]):
                path = self._seg_path(first)
                if nxt - 1 > self.committed_seq:
                    break
                try:
                    if os.path.getmtime(path) >= cutoff:
                        continue
                    os.remove(path)
                    idx = path[:-4] + ".idx"
                    if os.path.exists(idx):
                        os.remove(idx)
                except OSError:
                    continue
                self._index_cache.pop(first, None)
                self._segments.remove(first)
                removed += 1
        return removed

    def stats(self) -> dict:
        return {"next_seq": self.next_seq, "committed_seq": self.committed_seq,
                "segments": len(self._segments), "records_written": self.records_written,
                "bytes_written": self.bytes_written, "encrypted": self._aead is not None,
                "sync": self.sync}
