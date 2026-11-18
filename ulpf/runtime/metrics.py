"""Prometheus exposition of runtime counters (``/api/v1/metrics``)."""
from __future__ import annotations


def _esc(v) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"')


def prometheus_lines(s: dict) -> list[str]:
    out: list[str] = []

    def metric(name: str, kind: str, help_: str, samples: list[tuple[dict, float]]) -> None:
        out.append(f"# HELP {name} {help_}")
        out.append(f"# TYPE {name} {kind}")
        for labels, value in samples:
            lab = ",".join(f'{k}="{_esc(v)}"' for k, v in labels.items())
            out.append(f"{name}{{{lab}}} {value}" if lab else f"{name} {value}")

    j = s.get("journal") or {}
    metric("ulpf_journal_records_total", "counter", "Records written to the input journal.",
           [({}, j.get("records_written", 0))])
    metric("ulpf_journal_committed_seq", "gauge", "Highest journal sequence delivered to every sink buffer.",
           [({}, s.get("committed_seq", 0))])
    metric("ulpf_journal_lag_records", "gauge", "Journaled records not yet committed.",
           [({}, max(0, j.get("next_seq", 1) - 1 - s.get("committed_seq", 0)))])
    inputs = s.get("inputs") or {}
    for key, help_ in (("received", "Records received by an input."),
                       ("ingested", "Records an input journaled."),
                       ("dropped_overflow", "Records dropped because the pipeline was saturated (UDP)."),
                       ("dropped_rate_limit", "Records dropped by the per-source rate limit."),
                       ("dropped_denied", "Records from sources outside allow_sources."),
                       ("errors", "Input errors."), ("restarts", "Input restarts.")):
        metric(f"ulpf_input_{key}_total", "counter", help_,
               [({"input": n}, v.get(key, 0)) for n, v in inputs.items()])
    p = s.get("pipeline") or {}
    counts = p.get("counts") or {}
    metric("ulpf_pipeline_events_total", "counter", "Events produced by the workers by outcome.",
           [({"outcome": k}, counts.get(k, 0)) for k in ("events", "raw_fallback", "auto_parsed",
                                                       "skipped", "failed", "derived")])
    metric("ulpf_pipeline_in_flight_batches", "gauge", "Batches dispatched but not finished.",
           [({}, p.get("in_flight_batches", 0))])
    metric("ulpf_pipeline_worker_restarts_total", "counter", "Worker processes restarted.",
           [({}, p.get("worker_restarts", 0))])
    outs = s.get("outputs") or {}
    metric("ulpf_output_delivered_events_total", "counter", "Events delivered by an output.",
           [({"output": n}, v.get("delivered_events", 0)) for n, v in outs.items()])
    metric("ulpf_output_dead_lettered_total", "counter", "Events an output sent to the dead-letter queue.",
           [({"output": n}, v.get("dead_lettered", 0)) for n, v in outs.items()])
    metric("ulpf_output_retries_total", "counter", "Delivery retries.",
           [({"output": n}, v.get("retries", 0)) for n, v in outs.items()])
    metric("ulpf_output_healthy", "gauge", "1 if the last delivery attempt succeeded.",
           [({"output": n}, 1 if v.get("healthy") else 0) for n, v in outs.items()])
    metric("ulpf_buffer_events", "gauge", "Events waiting in an output's disk buffer.",
           [({"output": n}, (v.get("buffer") or {}).get("events", 0)) for n, v in outs.items()])
    metric("ulpf_buffer_fill_ratio", "gauge", "Buffer bytes / buffer.max_mb.",
           [({"output": n}, (v.get("buffer") or {}).get("fill_ratio", 0)) for n, v in outs.items()])
    metric("ulpf_buffer_dropped_events_total", "counter", "Events dropped by when_full: drop_oldest.",
           [({"output": n}, (v.get("buffer") or {}).get("dropped_events", 0)) for n, v in outs.items()])
    ev = s.get("evidence") or {}
    if ev:
        metric("ulpf_evidence_seals_total", "counter", "Evidence seals written.",
               [({}, ev.get("seals_written", 0))])
        metric("ulpf_evidence_last_sealed_seq", "gauge", "Highest journal sequence covered by a seal.",
               [({}, ev.get("last_sealed_seq", 0))])
    return out
