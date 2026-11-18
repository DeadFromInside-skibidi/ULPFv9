"""
Quarantine & Anti-Poisoning
=============================
Protects the learning plane from resource exhaustion and parser poisoning.

* Volume: each source may contribute at most
  ``per_source_unknown_events_per_sec`` samples per second; excess lines are
  simply not sampled (they are still stored via the raw fallback). A busy
  legitimate device is never locked out of learning.
* Cardinality poisoning: a source that creates more than
  ``per_source_new_clusters_per_sec`` NEW structural fingerprints in a second
  is fabricating structures; it is quarantined from learning for 60 s.
"""
from __future__ import annotations

import collections
import time

from ulpf.intelligence.auto_parser.config import PoisoningLimits

_QUARANTINE_SECONDS = 60.0
_MAX_TRACKED_SOURCES = 10_000


class QuarantineManager:
    """Rate limiting and quarantine for sources of unknown events."""

    def __init__(self, limits: PoisoningLimits):
        self.limits = limits
        self._unknown_events: dict[str, collections.deque] = {}
        self._new_clusters: dict[str, collections.deque] = {}
        self._quarantined_sources: dict[str, float] = {}

    def is_quarantined(self, source_ip: str) -> bool:
        expiry = self._quarantined_sources.get(source_ip)
        if expiry is None:
            return False
        if time.time() > expiry:
            del self._quarantined_sources[source_ip]
            return False
        return True

    @staticmethod
    def _window(store: dict, key: str, now: float) -> collections.deque:
        history = store.get(key)
        if history is None:
            if len(store) >= _MAX_TRACKED_SOURCES:
                store.clear()
            history = store[key] = collections.deque()
        while history and now - history[0] > 1.0:
            history.popleft()
        return history

    def check_and_record_event(self, source_ip: str) -> bool:
        """True if an unknown event from this source may be sampled for learning."""
        source_ip = source_ip or "unknown_source"
        if self.is_quarantined(source_ip):
            return False
        now = time.time()
        history = self._window(self._unknown_events, source_ip, now)
        if len(history) >= self.limits.per_source_unknown_events_per_sec:
            return False
        history.append(now)
        return True

    def record_new_cluster(self, source_ip: str) -> bool:
        """Record that a source produced a new structure. False (and quarantine) if abusive."""
        source_ip = source_ip or "unknown_source"
        now = time.time()
        history = self._window(self._new_clusters, source_ip, now)
        history.append(now)
        if len(history) > self.limits.per_source_new_clusters_per_sec:
            self._quarantined_sources[source_ip] = now + _QUARANTINE_SECONDS
            return False
        return True

    def validate_message_length(self, raw_line: str) -> bool:
        """Reject lines with more tokens than the profile allows."""
        return raw_line.count(" ") < self.limits.max_token_count_per_event
