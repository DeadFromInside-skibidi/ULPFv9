"""
Hash-chained audit log of operator and system actions.

Each line is JSON ``{seq, time, actor, action, details, prev, hash}`` where
``hash = SHA-256(prev + canonical JSON of the entry)``. Editing, deleting or
reordering any line breaks every hash after it; ``verify_audit_log`` reports
the first broken line.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time

_GENESIS = "0" * 64


def _entry_hash(prev: str, entry: dict) -> str:
    body = json.dumps({k: entry[k] for k in ("seq", "time", "actor", "action", "details")},
                      sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev + body).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._lock = threading.Lock()
        self._seq, self._prev = self._tail()

    def _tail(self) -> tuple[int, str]:
        if not os.path.exists(self.path):
            return 0, _GENESIS
        last = None
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
        if last is None:
            return 0, _GENESIS
        e = json.loads(last)
        return e["seq"], e["hash"]

    def record(self, action: str, details: dict | None = None, actor: str = "system") -> dict:
        with self._lock:
            entry = {"seq": self._seq + 1, "time": time.time(), "actor": actor, "action": action,
                     "details": details or {}}
            entry["prev"] = self._prev
            entry["hash"] = _entry_hash(self._prev, entry)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._seq, self._prev = entry["seq"], entry["hash"]
            return entry


def verify_audit_log(path: str) -> dict:
    prev = _GENESIS
    n = 0
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            e = json.loads(line)
            if e.get("prev") != prev or _entry_hash(prev, e) != e.get("hash") or e.get("seq") != n + 1:
                return {"valid": False, "entries": n, "broken_at_line": lineno}
            prev = e["hash"]
            n += 1
    return {"valid": True, "entries": n, "head": prev}
