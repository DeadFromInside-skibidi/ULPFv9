"""
Storage Backend Abstract Interface
=====================================
All storage implementations (SQLite, DuckDB, PostgreSQL, etc.)
implement this interface. The engine never knows which backend is active.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class StorageBackend(ABC):
    """Abstract base class for ULPF storage backends."""

    @abstractmethod
    def insert_batch(self, events: list[dict]) -> int:
        """
        Insert a batch of normalized events.
        Returns the number of events successfully stored.
        """
        ...

    @abstractmethod
    def query(self, filters: dict | None = None, limit: int = 100,
              offset: int = 0) -> list[dict]:
        """
        Query stored events with optional filters.
        Returns list of event dicts.
        """
        ...

    @abstractmethod
    def search(self, query: str, limit: int = 50) -> list[dict]:
        """
        Full-text search across stored events.
        Returns matching event dicts.
        """
        ...

    @abstractmethod
    def get_event(self, event_id: str) -> dict | None:
        """Retrieve a single event by ID."""
        ...

    @abstractmethod
    def stats(self) -> dict:
        """Get storage statistics (counts, sizes, distributions)."""
        ...

    @abstractmethod
    def close(self) -> None:
        """Close the storage connection."""
        ...

    # Optional methods with defaults

    def store_anomaly(self, anomaly: dict) -> None:
        """Store an anomaly record. Optional override."""
        pass

    def count(self) -> int:
        """Return total event count. Default uses stats()."""
        s = self.stats()
        return s.get("total_events", 0)
