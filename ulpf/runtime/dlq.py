"""
Dead-letter queue: events a sink rejected permanently, kept with the reason.

NDJSON files under ``<data dir>/dlq/<sink>/``, one line per event::

    {"time": ..., "sink": ..., "reason": ..., "event_id": ..., "raw_hash": ...,
     "attempts": n, "record": <the encoded record as text>}

Bounded by ``max_bytes`` (oldest files removed first; the total stays below
``max_bytes`` plus one rotated file) and ``retention_days``. Events removed to
respect the bound are counted in ``evicted``.
"""
from __future__ import annotations

import os
import threading
import time

import orjson


class DeadLetterQueue:
    def __init__(self, directory: str, max_bytes: int = 512 * 2**20, retention_days: float = 7.0,
                 rotate_bytes: int = 16 * 2**20):
        self.dir = directory
        os.makedirs(directory, exist_ok=True)
        self.max_bytes = max_bytes
        self.retention_days = retention_days
        # The file being appended to is never deleted, so it must be small next to
        # the cap: total size stays below max_bytes + rotate_bytes
        self.rotate_bytes = min(rotate_bytes, max(64 * 1024, max_bytes // 4))
        self._lock = threading.Lock()
        self.count = 0
        self.evicted_files = 0

    def _current(self, sink: str) -> str:
        d = os.path.join(self.dir, sink)
        os.makedirs(d, exist_ok=True)
        files = sorted(n for n in os.listdir(d) if n.endswith(".ndjson"))
        if files:
            path = os.path.join(d, files[-1])
            if os.path.getsize(path) < self.rotate_bytes:
                return path
        return os.path.join(d, f"dlq-{time.time_ns():020d}.ndjson")

    def write(self, sink: str, reason: str, records: list[dict], attempts: int = 1) -> None:
        if not records:
            return
        now = time.time()
        lines = []
        for r in records:
            lines.append(orjson.dumps({
                "time": now, "sink": sink, "reason": reason[:2000], "attempts": attempts,
                "event_id": r.get("event_id"), "raw_hash": r.get("raw_hash"),
                "reason_detail": r.get("reason_detail"), "record": r.get("record"),
            }, default=str))
        with self._lock:
            # Split across files so no file outgrows rotate_bytes (keeps the cap meaningful)
            i = 0
            while i < len(lines):
                path = self._current(sink)
                room = max(1, self.rotate_bytes - (os.path.getsize(path) if os.path.exists(path) else 0))
                j, size = i, 0
                while j < len(lines) and (j == i or size + len(lines[j]) + 1 <= room):
                    size += len(lines[j]) + 1
                    j += 1
                with open(path, "ab") as f:
                    f.write(b"\n".join(lines[i:j]) + b"\n")
                i = j
                self.enforce_limits()
            self.count += len(records)

    def enforce_limits(self) -> None:
        files = []
        for root, _dirs, names in os.walk(self.dir):
            for n in names:
                if n.endswith(".ndjson"):
                    p = os.path.join(root, n)
                    try:
                        files.append((os.path.getmtime(p), os.path.getsize(p), p))
                    except OSError:
                        pass
        files.sort()
        total = sum(f[1] for f in files)
        cutoff = time.time() - self.retention_days * 86400 if self.retention_days > 0 else None
        for mtime, size, path in files[:-1]:  # never delete the file being appended to
            if total <= self.max_bytes and (cutoff is None or mtime >= cutoff):
                break
            try:
                os.remove(path)
                total -= size
                self.evicted_files += 1
            except OSError:
                pass

    def read(self, sink: str | None = None, limit: int = 100) -> list[dict]:
        out = []
        base = os.path.join(self.dir, sink) if sink else self.dir
        for root, _dirs, names in os.walk(base):
            for n in sorted(names, reverse=True):
                if not n.endswith(".ndjson"):
                    continue
                with open(os.path.join(root, n), "rb") as f:
                    for line in reversed(f.read().splitlines()):
                        if line.strip():
                            out.append(orjson.loads(line))
                            if len(out) >= limit:
                                return out
        return out

    def stats(self) -> dict:
        size = files = 0
        for root, _dirs, names in os.walk(self.dir):
            for n in names:
                if n.endswith(".ndjson"):
                    files += 1
                    size += os.path.getsize(os.path.join(root, n))
        return {"events_written": self.count, "files": files, "bytes": size,
                "max_bytes": self.max_bytes, "evicted_files": self.evicted_files}
