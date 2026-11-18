"""
ULPF Plugin Lifecycle Management
===================================
Handles startup, shutdown, and offline enforcement.
"""
from __future__ import annotations

import logging
import os
import sys

logger = logging.getLogger("ulpf.plugin")


def enforce_offline(config) -> None:
    """
    Verify that the plugin is configured for air-gapped operation.

    This is an advisory check — the engine already has no network
    dependencies, but this logs a confirmation.
    """
    if config.offline or os.environ.get("ULPF_OFFLINE", "0") == "1":
        logger.info(
            "ULPF running in OFFLINE mode. "
            "No external network access required or attempted."
        )
    else:
        logger.warning(
            "ULPF offline mode is disabled. For air-gapped deployment, "
            "set config.offline=True or ULPF_OFFLINE=1."
        )


def validate_environment(config) -> list[str]:
    """
    Validate the runtime environment. Returns list of warnings.
    """
    warnings = []

    # Check Python version
    if sys.version_info < (3, 9):
        warnings.append(f"Python 3.9+ required, found {sys.version}")

    # Check config directory exists
    if config.config_dir and not os.path.isdir(config.config_dir):
        warnings.append(f"Config directory not found: {config.config_dir}")

    # Check storage directory is writable
    storage_dir = os.path.dirname(config.storage_path)
    if storage_dir:
        os.makedirs(storage_dir, exist_ok=True)

    # Check evidence directory
    if config.evidence_dir:
        os.makedirs(config.evidence_dir, exist_ok=True)

    return warnings
