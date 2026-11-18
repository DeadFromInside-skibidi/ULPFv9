"""
ULPF Plugin Configuration
===========================
Dataclass-based configuration for the ULPF plugin.
All fields have sensible defaults for air-gapped deployment.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class ULPFConfig:
    """Configuration for the ULPF plugin."""

    # Storage
    storage_backend: str = "duckdb"
    storage_path: str = ""  # Empty = canonical store (ULPF_DB_PATH or <data dir>/ulpf.duckdb)

    # Directories
    config_dir: str = ""     # Empty = auto-resolve to config/
    learned_parsers_dir: str = ""  # Empty = ULPF_LEARNED_PARSERS_DIR or <data dir>/learned_parsers
    evidence_dir: str = ""   # Empty = <data dir>/evidence

    # Workers
    num_workers: int = 0     # 0 = auto (cpu_count - 1, min 1)
    batch_size: int = 2000
    queue_max_size: int = 100_000

    # Processing
    enable_anomaly_detection: bool = True
    enable_correlation: bool = True
    enable_forensics: bool = True
    enable_log_dna: bool = True
    enable_auto_parser: bool = True

    # Air-gap
    offline: bool = True

    # Logging
    log_level: str = "INFO"

    def resolve_paths(self, project_root: str | None = None) -> None:
        """Resolve empty paths.

        Mutable state (event store, evidence) lives in the platform data
        directory so every entry point — CLI, desktop GUI, REST API, network
        listener — shares one store. Read-only assets (config/) resolve
        relative to the install root.
        """
        import sys
        from ulpf.platform.paths import get_data_dir, get_db_path
        from ulpf.intelligence.auto_parser.registry import default_learned_dir
        root = project_root or getattr(
            sys, "_MEIPASS",
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        )

        if not self.storage_path:
            self.storage_path = str(get_db_path())

        if not self.config_dir:
            self.config_dir = os.path.join(root, "config")

        if not self.learned_parsers_dir:
            self.learned_parsers_dir = default_learned_dir()

        if not self.evidence_dir:
            self.evidence_dir = str(get_data_dir() / "evidence")

    @classmethod
    def from_dict(cls, d: dict) -> ULPFConfig:
        """Create config from a dictionary, ignoring unknown keys."""
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in d.items() if k in known}
        return cls(**filtered)

    def to_dict(self) -> dict:
        """Serialize to dict."""
        return {
            "storage_backend": self.storage_backend,
            "storage_path": self.storage_path,
            "config_dir": self.config_dir,
            "learned_parsers_dir": self.learned_parsers_dir,
            "evidence_dir": self.evidence_dir,
            "num_workers": self.num_workers,
            "batch_size": self.batch_size,
            "queue_max_size": self.queue_max_size,
            "enable_anomaly_detection": self.enable_anomaly_detection,
            "enable_correlation": self.enable_correlation,
            "enable_forensics": self.enable_forensics,
            "enable_log_dna": self.enable_log_dna,
            "enable_auto_parser": self.enable_auto_parser,
            "offline": self.offline,
            "log_level": self.log_level,
        }
