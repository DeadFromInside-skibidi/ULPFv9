"""
Per-sink disk buffer.

Workers (any process) write sink-encoded *segments*; the sink's sender thread
in the host reads them in order, delivers, then deletes them.

Segment names encode what they hold::

    L-<from_seq>-<to_seq>-<count>.<ext>     log events from journal records from..to
    D-<time_ns>-<count>.<ext>               derived events (seals, drift, anomalies, correlations)

Exactly-once into the buffer: a log segment's name is fixed by its journal
range, and a sender delivers it only once ``to_seq`` is at or below the
journal's *persisted* commit watermark. A replay after a crash covers only
records above that watermark, so it can only rewrite segments that were never
delivered — never resend one that was.

Capacity: ``max_bytes`` caps the directory. ``when_full='block'`` makes
writers wait (backpressure reaches the inputs); ``'drop_oldest'`` deletes
the oldest segments and counts the dropped events.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass

_SIZE_TTL = 0.25


@dataclass(frozen=True)
class Segment:
    name: str
    path: str
    kind: str          # "L" or "D"
    from_seq: int
    to_seq: int
    count: int
    size: int


def parse_name(name: str) -> tuple[str, int, int, int] | None:
    stem = name.split(".", 1)[0]
    parts = stem.split("-")
    try:
        if parts[0] == "L" and len(parts) == 4:
            return "L", int(parts[1]), int(parts[2]), int(parts[3])
        if parts[0] == "D" and len(parts) == 3:
            return "D", int(parts[1]), int(parts[1]), int(parts[2])
    except ValueError:
        return None
    return None


class BufferFull(RuntimeError):
    pass


class DiskBuffer:
    def __init__(self, directory: str, max_bytes: int, when_full: str = "block", ext: str = "seg"):
        self.dir = directory
        os.makedirs(directory, exist_ok=True)
        self.max_bytes = int(max_bytes)
        self.when_full = when_full
        self.ext = ext
        self._size_cache = (0.0, 0)
        self._lock = threading.Lock()
        self.dropped_events = 0
        self.dropped_segments = 0

    # ------------------------------------------------------------------
    # Writers
    # ------------------------------------------------------------------

    def _dir_size(self, fresh: bool = False) -> int:
        ts, size = self._size_cache
        now = time.monotonic()
        if fresh or now - ts > _SIZE_TTL:
            size = 0
            try:
                with os.scandir(self.dir) as it:
                    for e in it:
                        if e.is_file():
                            size += e.stat().st_size
            except OSError:
                pass
            self._size_cache = (now, size)
        return size

    def log_name(self, from_seq: int, to_seq: int, count: int) -> str:
        return f"L-{from_seq:020d}-{to_seq:020d}-{count}.{self.ext}"

    def exists(self, name: str) -> bool:
        return os.path.exists(os.path.join(self.dir, name))

    def write(self, name: str, payload: bytes, stop: threading.Event | None = None,
              timeout: float | None = None) -> int:
        """Atomically add a segment. Returns events dropped to make room (drop_oldest).

        Blocks while the buffer is full in 'block' mode; raises BufferFull if
        ``timeout`` expires or ``stop`` is set while waiting.
        """
        path = os.path.join(self.dir, name)
        if os.path.exists(path):
            return 0  # replay of a segment that is already buffered
        need = len(payload)
        dropped = 0
        deadline = None if timeout is None else time.monotonic() + timeout
        parsed = parse_name(name)
        mine = parsed[1] if parsed and parsed[0] == "L" else None
        while self._dir_size() + need > self.max_bytes:
            if self.when_full == "drop_oldest":
                dropped += self._drop_oldest()
                self._dir_size(fresh=True)
                if not self.segments():
                    break
                continue
            segs = self.segments()
            if need > self.max_bytes and not segs:
                break    # a segment larger than the whole buffer is accepted alone, once it is empty
            # Senders deliver in journal order, so segments after this batch cannot drain until it
            # is written: waiting for them would deadlock. Overshoot is at most one batch per worker.
            if mine is not None and segs and all(s.kind == "L" and s.from_seq > mine for s in segs):
                break
            if (stop is not None and stop.is_set()) or (deadline and time.monotonic() > deadline):
                raise BufferFull(f"{self.dir} is full ({self.max_bytes} bytes)")
            time.sleep(0.05)
            self._dir_size(fresh=True)
        tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
        with open(tmp, "wb") as f:
            f.write(payload)
        os.replace(tmp, path)
        ts, size = self._size_cache
        self._size_cache = (ts, size + need)
        return dropped

    def write_derived(self, payload: bytes, count: int) -> str:
        name = f"D-{time.time_ns():020d}-{count}.{self.ext}"
        self.write(name, payload)
        return name

    def _drop_oldest(self) -> int:
        segs = self.segments()
        if not segs:
            return 0
        oldest = segs[0]
        try:
            os.remove(oldest.path)
        except OSError:
            return 0
        with self._lock:
            self.dropped_events += oldest.count
            self.dropped_segments += 1
        return oldest.count

    # ------------------------------------------------------------------
    # Sender side
    # ------------------------------------------------------------------

    def segments(self) -> list[Segment]:
        out = []
        try:
            entries = list(os.scandir(self.dir))
        except OSError:
            return out
        for e in entries:
            if e.name.endswith(".tmp"):
                continue
            meta = parse_name(e.name)
            if meta is None:
                continue
            try:
                size = e.stat().st_size
            except OSError:
                continue
            out.append(Segment(e.name, e.path, meta[0], meta[1], meta[2], meta[3], size))
        # Log segments in journal order; derived segments by creation time, after
        # log segments of the same moment
        out.sort(key=lambda s: (0 if s.kind == "L" else 1, s.from_seq))
        return out

    def ready(self, committed_seq: int) -> list[Segment]:
        return [s for s in self.segments() if s.kind == "D" or s.to_seq <= committed_seq]

    @staticmethod
    def read(seg: Segment) -> bytes:
        with open(seg.path, "rb") as f:
            return f.read()

    def ack(self, seg: Segment) -> None:
        try:
            os.remove(seg.path)
        except FileNotFoundError:
            pass
        ts, size = self._size_cache
        self._size_cache = (ts, max(0, size - seg.size))

    def clean_tmp(self) -> None:
        for name in os.listdir(self.dir):
            if name.endswith(".tmp"):
                try:
                    os.remove(os.path.join(self.dir, name))
                except OSError:
                    pass

    @staticmethod
    def _mtime(path: str) -> float | None:
        try:
            return os.path.getmtime(path)
        except OSError:          # delivered and removed by the sender meanwhile
            return None

    def stats(self) -> dict:
        segs = self.segments()
        times = [t for t in (self._mtime(s.path) for s in segs) if t is not None]
        oldest = min(times) if times else None
        return {"segments": len(segs), "bytes": sum(s.size for s in segs),
                "events": sum(s.count for s in segs), "max_bytes": self.max_bytes,
                "fill_ratio": round(sum(s.size for s in segs) / max(self.max_bytes, 1), 4),
                "oldest_age_seconds": round(time.time() - oldest, 1) if oldest else 0.0,
                "dropped_events": self.dropped_events, "dropped_segments": self.dropped_segments,
                "when_full": self.when_full}
