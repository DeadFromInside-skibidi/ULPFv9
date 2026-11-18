"""
ULPF Storage Layer
===================
Abstracts storage implementations so the engine does not depend on a specific database.
"""
from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ulpf.storage.interface import StorageBackend

logger = logging.getLogger("ulpf.storage")


def create_storage(backend: str = "duckdb", path: str | None = None, read_only: bool = False,
                   **options) -> StorageBackend:
    """
    Factory to instantiate a storage backend.

    Args:
        backend: Only "duckdb" is supported.
        path: Path to database file (default: canonical store, see get_db_path)
        read_only: Open without taking the write lock (for concurrent readers)
        options: Database options (partition, partition_max_mb, retention_days,
                 archive_dir, archive_format)
    """
    if backend and backend.lower() != "duckdb":
        raise ValueError(f"Unsupported storage backend {backend!r}; ULPF ships the DuckDB backend")
    from ulpf.storage.database import Database
    db = Database(db_path=path or None, read_only=read_only, **options)
    logger.info(f"Using DuckDB backend at {db.db_path}{' (read-only)' if db.read_only else ''}")
    return db
