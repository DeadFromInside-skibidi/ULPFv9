"""
Platform Paths & Dispatcher
===========================
Provides a unified API for querying platform directories, system telemetry,
and log source discovery without scattering OS checks in the application code.
"""
from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import Any

from ulpf.platform.base import PlatformAdapter
from ulpf.platform.linux import LinuxAdapter
from ulpf.platform.macos import MacOSAdapter
from ulpf.platform.windows import WindowsAdapter

_CURRENT_ADAPTER: PlatformAdapter | None = None


def get_adapter() -> PlatformAdapter:
    """Return the active platform adapter for the current host OS."""
    global _CURRENT_ADAPTER
    if _CURRENT_ADAPTER is None:
        sys_name = platform.system()
        if sys_name == "Windows":
            _CURRENT_ADAPTER = WindowsAdapter()
        elif sys_name == "Darwin":
            _CURRENT_ADAPTER = MacOSAdapter()
        else:
            _CURRENT_ADAPTER = LinuxAdapter()
    return _CURRENT_ADAPTER


def get_data_dir() -> Path:
    """Return standard application database and persistence directory.

    ``ULPF_DATA_DIR`` overrides the platform default so containers and
    air-gapped installs can pin state to a mounted volume.
    """
    override = os.environ.get("ULPF_DATA_DIR")
    if override:
        return Path(override)
    return get_adapter().get_data_dir()


def get_db_path() -> Path:
    """Return the canonical DuckDB event store path.

    Every entry point (CLI, desktop GUI, REST API, network listener) resolves
    the database through this function so they all read and write the same
    store. ``ULPF_DB_PATH`` overrides the location.
    """
    override = os.environ.get("ULPF_DB_PATH")
    if override:
        return Path(override)
    return get_data_dir() / "ulpf.duckdb"


def get_config_dir() -> Path:
    """Return persistent configuration directory."""
    return get_adapter().get_config_dir()


def get_cache_dir() -> Path:
    """Return ephemeral cache directory."""
    return get_adapter().get_cache_dir()


def get_log_dir() -> Path:
    """Return operational log storage directory."""
    return get_adapter().get_log_dir()


def get_temp_dir() -> Path:
    """Return temporary directory."""
    return get_adapter().get_temp_dir()


def get_system_info() -> dict[str, Any]:
    """Return platform metadata and air-gap status."""
    return get_adapter().get_system_info()


def get_default_log_sources() -> list[dict[str, Any]]:
    """Return standard log sources for this operating system."""
    return get_adapter().get_default_log_sources()


def open_folder(path: Path | str) -> bool:
    """Open folder in system file browser."""
    return get_adapter().open_folder_in_file_manager(path)
