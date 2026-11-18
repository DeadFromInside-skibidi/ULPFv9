"""
Windows Platform Adapter
========================
Handles Windows-specific path resolution, system information, and log sources
(such as Windows Event Logs, IIS W3C logs, and Firewall logs).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ulpf.platform.base import PlatformAdapter


class WindowsAdapter(PlatformAdapter):
    """Adapter for Microsoft Windows environments."""

    @property
    def name(self) -> str:
        return "windows"

    def get_data_dir(self) -> Path:
        """Returns %LOCALAPPDATA%\\ULPF (or user home fallback)."""
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            base = Path(local_app_data)
        else:
            base = Path.home() / "AppData" / "Local"
        return base / "ULPF"

    def get_config_dir(self) -> Path:
        """Returns %APPDATA%\\ULPF\\config."""
        app_data = os.environ.get("APPDATA")
        if app_data:
            base = Path(app_data)
        else:
            base = Path.home() / "AppData" / "Roaming"
        return base / "ULPF" / "config"

    def get_cache_dir(self) -> Path:
        """Returns %LOCALAPPDATA%\\ULPF\\cache."""
        return self.get_data_dir() / "cache"

    def get_log_dir(self) -> Path:
        """Returns %LOCALAPPDATA%\\ULPF\\logs."""
        return self.get_data_dir() / "logs"

    def get_default_log_sources(self) -> list[dict[str, Any]]:
        """Return discovered standard Windows log directories and files."""
        sources: list[dict[str, Any]] = []
        sys_root = os.environ.get("SystemRoot", r"C:\Windows")
        sys_drive = os.environ.get("SystemDrive", r"C:")

        # 1. Windows Event Logs Directory
        winevt_dir = Path(sys_root) / "System32" / "Winevt" / "Logs"
        if winevt_dir.exists():
            sources.append({
                "name": "Windows Event Logs (System32)",
                "path": str(winevt_dir),
                "type": "directory",
                "format": "evtx",
                "description": "Standard Windows Event Log files (.evtx)",
            })

        # 2. IIS Log Directory
        iis_dir = Path(sys_drive) / "inetpub" / "logs" / "LogFiles"
        if iis_dir.exists():
            sources.append({
                "name": "IIS W3C Web Logs",
                "path": str(iis_dir),
                "type": "directory",
                "format": "w3c",
                "description": "Microsoft IIS web server access logs",
            })

        # 3. Windows Firewall Log
        fw_log = Path(sys_root) / "System32" / "LogFiles" / "Firewall" / "pfirewall.log"
        if fw_log.exists():
            sources.append({
                "name": "Windows Firewall Log",
                "path": str(fw_log),
                "type": "file",
                "format": "w3c",
                "description": "Windows Defender Firewall packet drop/allow log",
            })

        # 4. Windows Update Log / Setup
        setup_log = Path(sys_root) / "WindowsUpdate.log"
        if setup_log.exists():
            sources.append({
                "name": "Windows Update Log",
                "path": str(setup_log),
                "type": "file",
                "format": "syslog",
                "description": "Windows system update transaction logs",
            })

        return sources
