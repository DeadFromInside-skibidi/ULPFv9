"""
macOS Platform Adapter
======================
Handles Apple macOS path resolution (Library/Application Support),
system metrics, and log source discovery (system.log, install.log, Unified Log).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ulpf.platform.base import PlatformAdapter


class MacOSAdapter(PlatformAdapter):
    """Adapter for Apple macOS environments."""

    @property
    def name(self) -> str:
        return "macos"

    def get_data_dir(self) -> Path:
        """Returns ~/Library/Application Support/ULPF."""
        return Path.home() / "Library" / "Application Support" / "ULPF"

    def get_config_dir(self) -> Path:
        """Returns ~/Library/Preferences/ULPF."""
        return Path.home() / "Library" / "Preferences" / "ULPF"

    def get_cache_dir(self) -> Path:
        """Returns ~/Library/Caches/ULPF."""
        return Path.home() / "Library" / "Caches" / "ULPF"

    def get_log_dir(self) -> Path:
        """Returns ~/Library/Logs/ULPF."""
        return Path.home() / "Library" / "Logs" / "ULPF"

    def get_default_log_sources(self) -> list[dict[str, Any]]:
        """Return common macOS log file paths."""
        sources: list[dict[str, Any]] = []

        standard_logs = [
            ("/var/log/system.log", "macOS System Log", "syslog", "Legacy syslog daemon output"),
            ("/var/log/install.log", "macOS Installer Log", "syslog", "Package and OS update logs"),
            ("/var/log/wifi.log", "Airport / Wi-Fi Log", "syslog", "macOS wireless networking logs"),
        ]

        for path_str, name, fmt, desc in standard_logs:
            p = Path(path_str)
            if p.exists():
                sources.append({
                    "name": name,
                    "path": str(p),
                    "type": "file",
                    "format": fmt,
                    "description": desc,
                })

        return sources
