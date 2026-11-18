"""
Lifecycle Manager
===================
Manages parser state transitions:
CANDIDATE → VALIDATING → CANARY → ACTIVE → DRIFTING → RETIRED

PENDING_APPROVAL (defence mode): validated and signed, but never used until
an operator approves it (``ulpf parsers approve <id>``).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from ulpf.intelligence.auto_parser.parser_spec import ParserSpec


class ParserLifecycleManager:
    """Manages the state transitions of parsers."""

    VALID_STATES = ["candidate", "validating", "pending_approval", "canary", "active", "drifting", "retired"]

    def __init__(self):
        # Tracking data for canaries (parser_id -> dict of stats)
        self._canary_stats: dict[str, dict[str, Any]] = {}

    def transition(self, spec: ParserSpec, new_state: str) -> None:
        """Transition parser to a new state."""
        if new_state not in self.VALID_STATES:
            raise ValueError(f"Invalid parser state: {new_state}")

        old_state = spec.state
        spec.state = new_state
        
        # Initialise canary tracking
        if new_state == "canary" and old_state != "canary":
            self._canary_stats[spec.parser_id] = {
                "start_time": time.time(),
                "events_processed": 0,
                "errors": 0,
            }

    def record_canary_event(self, parser_id: str, success: bool) -> None:
        """Record a parsing event for a canary."""
        if parser_id in self._canary_stats:
            stats = self._canary_stats[parser_id]
            stats["events_processed"] += 1
            if not success:
                stats["errors"] += 1

    def get_canary_stats(self, parser_id: str) -> dict[str, Any] | None:
        """Get tracking stats for a canary."""
        if parser_id not in self._canary_stats:
            return None
            
        stats = self._canary_stats[parser_id].copy()
        stats["duration"] = time.time() - stats["start_time"]
        return stats
        
    def cleanup_canary(self, parser_id: str) -> None:
        """Remove canary tracking data."""
        self._canary_stats.pop(parser_id, None)
