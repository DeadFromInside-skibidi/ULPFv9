"""
🏆 Statistical Anomaly Detection (No ML Libraries)
====================================================
Pure-Python anomaly detection suitable for air-gapped networks:
  - Rolling baselines for event volume, severity, source IPs
  - Z-score and moving average outlier detection
  - Entropy-based anomaly detection
  - No numpy, no sklearn — runs on vanilla Python 3.9+
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from typing import Any


class RollingStats:
    """Efficient rolling statistics calculator without numpy."""

    def __init__(self, window_size: int = 100):
        self.window = window_size
        self._values: deque[float] = deque(maxlen=window_size)
        self._sum: float = 0.0
        self._sum_sq: float = 0.0

    def add(self, value: float):
        if len(self._values) == self.window:
            old = self._values[0]
            self._sum -= old
            self._sum_sq -= old * old
        self._values.append(value)
        self._sum += value
        self._sum_sq += value * value

    @property
    def mean(self) -> float:
        n = len(self._values)
        return self._sum / n if n > 0 else 0.0

    @property
    def variance(self) -> float:
        n = len(self._values)
        if n < 2:
            return 0.0
        return max((self._sum_sq / n) - (self.mean ** 2), 0.0)

    @property
    def std_dev(self) -> float:
        return math.sqrt(self.variance)

    @property
    def count(self) -> int:
        return len(self._values)

    def z_score(self, value: float) -> float:
        """Return z-score of a value relative to rolling baseline."""
        sd = self.std_dev
        if sd == 0:
            return 0.0 if value == self.mean else (3.0 if value > self.mean else -3.0)
        return (value - self.mean) / sd


class AnomalyDetector:
    """
    Detects anomalies in log event streams using pure statistics.

    Monitors:
      1. Event volume per time bucket (volume spikes/drops)
      2. Severity distribution shifts
      3. New/unusual source IPs (first-seen tracking)
      4. Protocol distribution changes
      5. Cross-entropy of event patterns
    """

    def __init__(self, baseline_window: int = 200, z_threshold: float = 2.5,
                 max_known_ips: int = 500_000, max_anomalies: int = 10_000,
                 new_ip_warmup: int = 50, new_ip_external_only: bool = False,
                 new_ip_max_novelty: float | None = None):
        """``new_ip_max_novelty``: only flag a first-seen IP while the share of new
        IPs among the last 1,000 IP observations is below this (the population
        has stabilised); while a network is still being learned every IP is new
        and alerts would be noise. ``new_ip_external_only`` skips private ranges."""
        self.z_threshold = z_threshold
        self.new_ip_warmup = new_ip_warmup
        self.new_ip_external_only = new_ip_external_only
        self.new_ip_max_novelty = new_ip_max_novelty
        self._ip_obs: deque[int] = deque(maxlen=1000)   # 1 = new, 0 = known
        self._ip_obs_new = 0

        # Rolling stats for different metrics
        self._volume_stats = RollingStats(baseline_window)
        self._severity_stats = RollingStats(baseline_window)
        self._bytes_stats = RollingStats(baseline_window)

        # First-seen IP tracker (insertion-ordered so the oldest can be forgotten)
        self._known_ips: dict[str, None] = {}
        self._max_known_ips = max_known_ips
        self._new_ips: deque[dict] = deque(maxlen=1000)

        self._protocol_counts: Counter = Counter()
        self._category_counts: Counter = Counter()

        # Anomaly log (bounded) + lifetime counters
        self.anomalies: deque[dict] = deque(maxlen=max_anomalies)
        self._type_counts: Counter = Counter()
        self._total_anomalies: int = 0
        self._total_events: int = 0

    def analyse_event(self, event: dict) -> list[dict]:
        """
        Analyse a single event for anomalies.
        Returns list of anomaly dicts (may be empty).
        """
        self._total_events += 1
        detected: list[dict] = []

        # 1. Severity anomaly
        severity = event.get("severity", 0)
        self._severity_stats.add(severity)
        if self._severity_stats.count > 10:
            z = self._severity_stats.z_score(severity)
            if abs(z) > self.z_threshold:
                a = _anomaly("severity_spike", severity, self._severity_stats, z, event)
                detected.append(a)

        # 2. New IP detection
        for endpoint in ("source", "destination"):
            ip = (event.get(endpoint) or {}).get("ip")
            if not ip:
                continue
            is_new = ip not in self._known_ips
            obs = self._ip_obs
            if len(obs) == obs.maxlen:
                self._ip_obs_new -= obs[0]
            obs.append(1 if is_new else 0)
            self._ip_obs_new += 1 if is_new else 0
            if is_new:
                self._known_ips[ip] = None
                if len(self._known_ips) > self._max_known_ips:
                    del self._known_ips[next(iter(self._known_ips))]
                self._new_ips.append({
                    "ip": ip,
                    "endpoint": endpoint,
                    "event_id": event.get("event_id"),
                    "timestamp": event.get("timestamp"),
                    "category": event.get("category"),
                })
                # Flag only once the baseline period has passed (and, when
                # configured, the IP population has stopped growing)
                if self._total_events > self.new_ip_warmup and self._new_ip_alertable(ip):
                    detected.append({
                        "type": "new_ip",
                        "description": f"First-seen {endpoint} IP: {ip}",
                        "ip": ip,
                        "endpoint": endpoint,
                        "event_id": event.get("event_id"),
                        "risk": "medium",
                    })

        # 3. Track protocol distribution
        proto = (event.get("network") or {}).get("protocol")
        if proto:
            self._protocol_counts[proto] += 1

        # 4. Track category distribution
        cat = event.get("category", "other")
        self._category_counts[cat] += 1

        # 5. Bytes anomaly
        total_bytes = 0
        for bfield in ("bytes_in", "bytes_out"):
            b = (event.get("network") or {}).get(bfield)
            if b and isinstance(b, (int, float)):
                total_bytes += b
        if total_bytes > 0:
            self._bytes_stats.add(total_bytes)
            if self._bytes_stats.count > 10:
                z = self._bytes_stats.z_score(total_bytes)
                if abs(z) > self.z_threshold:
                    detected.append(_anomaly("bytes_spike", total_bytes,
                                             self._bytes_stats, z, event))

        self._record(detected)
        return detected

    def _new_ip_alertable(self, ip: str) -> bool:
        if not self._ip_external_ok(ip):
            return False
        if self.new_ip_max_novelty is not None:
            obs = self._ip_obs
            if len(obs) < obs.maxlen or self._ip_obs_new / len(obs) >= self.new_ip_max_novelty:
                return False
        return True

    def _ip_external_ok(self, ip) -> bool:
        if not self.new_ip_external_only:
            return True
        import ipaddress
        try:
            return ipaddress.ip_address(ip).is_global
        except ValueError:
            return False

    def _record(self, detected: list[dict]) -> None:
        if detected:
            self.anomalies.extend(detected)
            self._total_anomalies += len(detected)
            self._type_counts.update(a["type"] for a in detected)

    def analyse_batch(self, events: list[dict]) -> list[dict]:
        """Analyse a batch and return all anomalies."""
        all_anomalies = []
        for event in events:
            all_anomalies.extend(self.analyse_event(event))

        all_anomalies.extend(self.analyse_batch_aggregate(events))
        return all_anomalies

    def analyse_batch_aggregate(self, events: list[dict]) -> list[dict]:
        """Batch-level checks only (volume, entropy) for events already analysed individually."""
        batch_anomalies = self._batch_analysis(events)
        self._record(batch_anomalies)
        return batch_anomalies

    def analyse_batch_aggregate_severities(self, severities: list) -> list[dict]:
        """``analyse_batch_aggregate`` from the batch's severities alone."""
        batch_anomalies = self._batch_analysis_severities(severities)
        self._record(batch_anomalies)
        return batch_anomalies

    def get_baseline_report(self) -> dict:
        """Get current baseline statistics."""
        return {
            "total_events_analysed": self._total_events,
            "severity": {
                "mean": round(self._severity_stats.mean, 2),
                "std_dev": round(self._severity_stats.std_dev, 2),
                "samples": self._severity_stats.count,
            },
            "bytes": {
                "mean": round(self._bytes_stats.mean, 2),
                "std_dev": round(self._bytes_stats.std_dev, 2),
                "samples": self._bytes_stats.count,
            },
            "known_ips": len(self._known_ips),
            "new_ips_recent": len(self._new_ips),
            "protocol_distribution": dict(self._protocol_counts.most_common(10)),
            "category_distribution": dict(self._category_counts.most_common(10)),
            "total_anomalies_detected": self._total_anomalies,
            "anomaly_type_distribution": dict(self._type_counts),
        }

    def get_anomalies(self, limit: int = 50) -> list[dict]:
        """Get the most recent anomalies (oldest first)."""
        n = len(self.anomalies)
        return [self.anomalies[i] for i in range(max(0, n - limit), n)]

    def _batch_analysis(self, events: list[dict]) -> list[dict]:
        """Batch-level anomaly detection."""
        if len(events) < 5:
            return []
        return self._batch_analysis_severities([e.get("severity", 0) or 0 for e in events])

    def _batch_analysis_severities(self, severities: list) -> list[dict]:
        """Batch-level checks from the batch's severities (``e.get("severity", 0) or 0``)."""
        anomalies = []
        n = len(severities)
        if n < 5:
            return anomalies

        # Volume anomaly
        self._volume_stats.add(n)
        if self._volume_stats.count > 3:
            z = self._volume_stats.z_score(n)
            if abs(z) > self.z_threshold:
                anomalies.append({
                    "type": "volume_anomaly",
                    "description": f"Batch size {n} is {'above' if z > 0 else 'below'} "
                                   f"baseline (mean={self._volume_stats.mean:.1f}, z={z:.2f})",
                    "batch_size": n,
                    "baseline_mean": round(self._volume_stats.mean, 1),
                    "z_score": round(z, 2),
                    "risk": "high" if abs(z) > 3.5 else "medium",
                })

        # A burst of near-identical HIGH-severity events (low entropy + high mean)
        # is characteristic of automated attack tooling; uniform low-severity
        # traffic (e.g. routine info syslog) is not.
        entropy = _entropy(severities)
        mean_sev = sum(severities) / n
        if entropy < 0.5 and n >= 20 and mean_sev >= 7:
            anomalies.append({
                "type": "low_entropy",
                "description": f"{n} events with near-identical high severity "
                               f"(mean {mean_sev:.1f}, entropy {entropy:.3f}) — possible automated attack.",
                "entropy": round(entropy, 4),
                "mean_severity": round(mean_sev, 2),
                "severity_distribution": dict(Counter(severities)),
                "risk": "high",
            })

        return anomalies


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _anomaly(atype: str, value: float, stats: RollingStats,
             z: float, event: dict) -> dict:
    return _spike(atype, value, stats.mean, stats.std_dev, z, event.get("event_id"))


def _spike(atype: str, value: float, mean: float, std: float, z: float, event_id) -> dict:
    return {
        "type": atype,
        "description": f"{atype}: value={value:.1f}, baseline_mean={mean:.1f}, "
                       f"std_dev={std:.1f}, z_score={z:.2f}",
        "value": value,
        "baseline_mean": round(mean, 2),
        "baseline_std": round(std, 2),
        "z_score": round(z, 2),
        "event_id": event_id,
        "risk": "critical" if abs(z) > 4 else "high" if abs(z) > 3 else "medium",
    }


class NativeAnomalyDetector:
    """``AnomalyDetector.analyse_batch`` with the per-event state in the compiled core
    (``ulpf_core.AnomalyState``): it reads native events where they are, without event
    dicts. The core reports raw findings; their dicts, the ``is_global`` check of a
    first-seen address and the batch-level checks stay here, so the anomalies are the
    ones ``AnomalyDetector`` produces for the same events in the same order.

    Every batch of a worker must go through one instance (the state is order-dependent):
    ``analyse_batch`` for event dicts, ``analyse_native`` for a native-lane batch.
    The per-protocol/category counters of ``get_baseline_report`` are not kept.
    """

    def __init__(self, state_cls, baseline_window: int = 200, z_threshold: float = 2.5,
                 max_known_ips: int = 500_000, **kw):
        self.py = AnomalyDetector(baseline_window=baseline_window, z_threshold=z_threshold,
                                  max_known_ips=max_known_ips, **kw)
        self.state = state_cls(baseline_window, z_threshold, max_known_ips, self.py.new_ip_warmup,
                               self.py.new_ip_max_novelty)

    def analyse_batch(self, events: list[dict]) -> list[dict]:
        return self.analyse_native(None, list(enumerate(events)))

    def analyse_native(self, batch, py_events: list[tuple[int, dict]]) -> list[dict]:
        """Anomalies of a batch: native events of ``batch`` plus (record index, event dict)."""
        items = []
        for i, e in py_events:
            net = e.get("network") or {}
            items.append((i, e.get("severity", 0), (e.get("source") or {}).get("ip"),
                          (e.get("destination") or {}).get("ip"), net.get("bytes_in"), net.get("bytes_out"),
                          e.get("event_id")))
        findings, severities = self.state.analyse(batch, items)
        out = []
        py = self.py
        for f in findings:
            if f[0] == "new_ip":
                _, ip, endpoint, eid = f
                if not py._ip_external_ok(ip):
                    continue
                out.append({"type": "new_ip", "description": f"First-seen {endpoint} IP: {ip}", "ip": ip,
                            "endpoint": endpoint, "event_id": eid, "risk": "medium"})
            else:
                out.append(_spike(*f))
        py._total_events = self.state.total_events
        py._record(out)
        out.extend(py.analyse_batch_aggregate_severities(severities))
        return out


def _entropy(values: list) -> float:
    """Shannon entropy of a list of values."""
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)
