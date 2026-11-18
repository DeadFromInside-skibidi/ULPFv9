"""
Platform Abstraction Layer — Base Interface
===========================================
Defines the abstract interface for OS-specific operations, paths, system info,
and log source discovery. Keeps GUI and engine code free from platform-checking branches.
"""
from __future__ import annotations

import abc
import os
import platform
import tempfile
from pathlib import Path
from typing import Any


class PlatformAdapter(abc.ABC):
    """Abstract base class for operating system adapters."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Return platform identifier ('windows', 'linux', 'macos')."""
        pass

    @abc.abstractmethod
    def get_data_dir(self) -> Path:
        """Return path for application database and persistent state."""
        pass

    @abc.abstractmethod
    def get_config_dir(self) -> Path:
        """Return path for persistent configuration files."""
        pass

    @abc.abstractmethod
    def get_cache_dir(self) -> Path:
        """Return path for ephemeral caches."""
        pass

    @abc.abstractmethod
    def get_log_dir(self) -> Path:
        """Return path for application operational logs."""
        pass

    def get_temp_dir(self) -> Path:
        """Return platform temporary directory."""
        return Path(tempfile.gettempdir()) / "ulpf"

    def get_system_info(self) -> dict[str, Any]:
        """Return hardware and OS metadata without external network calls."""
        return {
            "os_name": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor() or platform.machine(),
            "python_version": platform.python_version(),
            "is_air_gapped": self.is_air_gapped(),
        }

    @abc.abstractmethod
    def get_default_log_sources(self) -> list[dict[str, Any]]:
        """Return common log file locations native to this operating system."""
        pass

    def is_air_gapped(self) -> bool:
        """
        Report whether this host has no outbound IPv4 route.

        ``connect()`` on a UDP socket only consults the kernel routing table;
        no packet is transmitted. If the kernel can pick a route to the
        RFC 5737 TEST-NET-1 address, a default gateway exists and the host is
        NOT air-gapped. ULPF itself never makes outbound connections either
        way; this check reports the host's network posture honestly.
        """
        import socket
        from ulpf.runtime.egress import route_probe
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with route_probe():          # not egress: the egress guard ignores it
                s.connect(("192.0.2.1", 9))
            local_ip = s.getsockname()[0]
            return local_ip in ("0.0.0.0", "")
        except OSError:
            return True
        finally:
            s.close()

    def open_folder_in_file_manager(self, path: Path | str) -> bool:
        """Open target folder in the native file manager (Explorer, Finder, or file manager)."""
        p = Path(path)
        if not p.exists():
            return False
        try:
            import subprocess
            if self.name == "windows":
                os.startfile(str(p))
            elif self.name == "macos":
                subprocess.Popen(["open", str(p)])
            else:
                subprocess.Popen(["xdg-open", str(p)])
            return True
        except Exception:
            return False
