"""
ULPF v9 runtime: a durable, general-purpose ingest pipeline.

    inputs ─▶ journal (durable, raw, hashed) ─▶ workers (parse, normalise, enrich,
    analyse, route, encode) ─▶ per-sink disk buffers ─▶ senders ─▶ outputs

See ``ulpf.runtime.supervisor.Runtime`` and ``config/pipeline.example.yaml``.
"""
