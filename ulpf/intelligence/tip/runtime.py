"""
The indicator matcher of this process (workers, the Python enricher, the native lane).

Off until ``configure(path)`` names a snapshot (the runtime does, with ``intel.enabled``); while off,
enrichment keeps the legacy IP lookup of ``ulpf.intelligence.intel_db``. ``reload()`` swaps in a new
snapshot (the host broadcasts ``reload_intel`` after each rebuild); the core matcher swaps atomically,
so batches in flight finish on the snapshot they started with.
"""
from __future__ import annotations

import logging
import os
import threading

from ulpf.intelligence.tip.matcher import new_matcher

logger = logging.getLogger(__name__)
_lock = threading.Lock()
_path: str | None = None
_matcher = None


def configure(path: str | None) -> None:
    global _path, _matcher
    with _lock:
        _path = path
        _matcher = None
    if path:
        reload()


def reload() -> int:
    """Load the configured snapshot; returns the indicator count (-1: no snapshot)."""
    global _matcher
    with _lock:
        path = _path
        if not path or not os.path.isfile(path):
            return -1
        m = _matcher if _matcher is not None else new_matcher()
        try:
            n = m.load(path)
        except (OSError, ValueError) as e:
            logger.warning(f"threat-intel snapshot {path} not loaded: {e}")
            return -1
        _matcher = m
        return n


def active():
    """The loaded matcher, or None (legacy IP lookups)."""
    return _matcher


def is_native(m) -> bool:
    from ulpf.intelligence.tip.matcher import PyMatcher
    return m is not None and not isinstance(m, PyMatcher)
