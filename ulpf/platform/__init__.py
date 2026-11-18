"""
ULPF Platform Abstraction Layer
===============================
Provides isolated OS adapters for Windows, Linux, and macOS.
"""
from ulpf.platform.base import PlatformAdapter
from ulpf.platform.paths import (
    get_adapter,
    get_cache_dir,
    get_config_dir,
    get_data_dir,
    get_db_path,
    get_default_log_sources,
    get_log_dir,
    get_system_info,
    get_temp_dir,
    open_folder,
)

__all__ = [
    "PlatformAdapter",
    "get_adapter",
    "get_data_dir",
    "get_db_path",
    "get_config_dir",
    "get_cache_dir",
    "get_log_dir",
    "get_temp_dir",
    "get_system_info",
    "get_default_log_sources",
    "open_folder",
]
