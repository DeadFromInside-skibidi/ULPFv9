"""
Linux Platform Adapter
======================
Handles Linux-specific path resolution (XDG Base Directory Specification),
system metrics, and log source discovery (/var/log/syslog, auth.log, journald, etc.).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ulpf.platform.base import PlatformAdapter


class LinuxAdapter(PlatformAdapter):
    """Adapter for Linux / sovereign defense server environments."""

    @property
    def name(self) -> str:
        return "linux"

    def get_data_dir(self) -> Path:
        """Returns $XDG_DATA_HOME/ulpf (fallback ~/.local/share/ulpf)."""
        xdg_data = os.environ.get("XDG_DATA_HOME")
        if xdg_data:
            base = Path(xdg_data)
        else:
            base = Path.home() / ".local" / "share"
        return base / "ulpf"

    def get_config_dir(self) -> Path:
        """Returns $XDG_CONFIG_HOME/ulpf (fallback ~/.config/ulpf)."""
        xdg_config = os.environ.get("XDG_CONFIG_HOME")
        if xdg_config:
            base = Path(xdg_config)
        else:
            base = Path.home() / ".config"
        return base / "ulpf"

    def get_cache_dir(self) -> Path:
        """Returns $XDG_CACHE_HOME/ulpf (fallback ~/.cache/ulpf)."""
        xdg_cache = os.environ.get("XDG_CACHE_HOME")
        if xdg_cache:
            base = Path(xdg_cache)
        else:
            base = Path.home() / ".cache"
        return base / "ulpf"

    def get_log_dir(self) -> Path:
        """Returns log storage directory."""
        return self.get_data_dir() / "logs"

    def get_default_log_sources(self) -> list[dict[str, Any]]:
        """Return common Linux log file paths and services."""
        sources: list[dict[str, Any]] = []

        standard_logs = [
            ("/var/log/syslog", "System Syslog", "syslog", "Standard Debian/Ubuntu syslog"),
            ("/var/log/messages", "System Messages", "syslog", "RHEL/CentOS system messages"),
            ("/var/log/auth.log", "Authentication Log", "syslog", "PAM / SSH authentication events"),
            ("/var/log/secure", "Secure Log", "syslog", "RHEL authentication log"),
            ("/var/log/audit/audit.log", "Linux Audit Daemon", "kv", "Kernel audit / SELinux events"),
            ("/var/log/nginx/access.log", "Nginx Access Log", "w3c", "Nginx HTTP server access"),
            ("/var/log/apache2/access.log", "Apache Access Log", "w3c", "Apache HTTP server access"),
            ("/var/log/dpkg.log", "DPKG Package Log", "syslog", "Debian package installer logs"),
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
