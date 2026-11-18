"""
ULPF Plugin Health Check
=========================
Produces structured health/status information for monitoring.
"""
from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ulpf.plugin.interface import ULPFPlugin


def health_check(plugin: ULPFPlugin) -> dict[str, Any]:
    """
    Generate a health check report.

    Returns a structured dict with status, uptime, throughput,
    and component health.
    """
    uptime = time.time() - plugin._start_time if plugin._start_time else 0.0
    metrics = plugin._pipeline.get_metrics() if plugin._pipeline else {}

    total = metrics.get("total_events", 0)
    eps = total / max(uptime, 0.001) if uptime > 0 else 0.0

    return {
        "status": "healthy" if plugin._running else "stopped",
        "uptime_seconds": round(uptime, 1),
        "events_processed": total,
        "events_successful": metrics.get("successful", 0),
        "events_failed": metrics.get("failed", 0),
        "events_per_second": round(eps, 1),
        "success_rate_pct": metrics.get("success_rate", 0.0),
        "storage_backend": plugin._config.storage_backend,
        "parsers_loaded": len(plugin._pipeline.registry.get_all_parsers()) if plugin._pipeline else 0,
        "format_distribution": metrics.get("format_distribution", {}),
        "offline_mode": plugin._config.offline,
        "anomaly_detection": plugin._config.enable_anomaly_detection,
        "correlation": plugin._config.enable_correlation,
        "forensics": plugin._config.enable_forensics,
        "anomalies_detected": len(plugin._anomaly_detector.anomalies) if plugin._anomaly_detector else 0,
        "version": plugin.version,
    }
