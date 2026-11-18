"""
Native lane: the compiled core (``ulpf_core.Engine``) for whole dispatcher batches.

For every record it can reproduce exactly — syslog, CEF, LEEF, key=value and
JSON lines in printable ASCII whose timestamps, severities and values have
unambiguous Python semantics — the core detects, parses, normalises, adds
the worker's fields, applies enrichment and produces the event-store row
(row MAC included) straight into Arrow buffers, with the GIL released.
Every other record is returned in ``delegated`` and goes through the Python
pipeline, in order, exactly as before (APG, plugins, CSV/W3C/XML, raw
fallback). ``tests/test_native_lane.py`` checks both paths agree row by row.

Rows reach pyarrow through the Arrow C Data Interface (PyCapsule interface),
without a copy; records are read from the Python bytes objects in place.

Enrichment needs GeoIP databases and the IOC store, so it is split: the core
lists the batch's distinct addresses, the lookups run here (cached per
address), and the core finishes the rows with the answers.

On by default when the extension is built; ``ULPF_NATIVE_LANE=0`` turns it off.
Known difference: events with no or empty timestamp get the batch's start
time (millisecond resolution) instead of a per-event clock reading, and
``metadata.processing_time_ms`` (sampled for 1 in 4096 events) stays null.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

import pyarrow as pa

logger = logging.getLogger(__name__)


def _tables() -> dict:
    from ulpf.engine import normalizer as n
    from ulpf.engine import schema
    return {
        "aliases": {k: list(v) for k, v in n._FIELD_ALIASES_TUPLES.items()},
        "schema_paths": {k: list(v) for k, v in n._SCHEMA_PATHS.items()},
        "action_map": n.ACTION_MAP, "direction_map": n.DIRECTION_MAP,
        "protocol_map": n.PROTOCOL_MAP, "protocol_names": n.PROTOCOL_NAME_MAP,
        "syslog_sev": n.SYSLOG_SEV, "cef_sev": n.CEF_SEV, "text_sev": n.TEXT_SEV,
        "categories": list(schema.CATEGORIES), "category_aliases": schema.CATEGORY_ALIASES,
        "nullish": sorted(n._NULLISH), "int_fields": sorted(n._INT_FIELDS),
        "schema_version": schema.SCHEMA_VERSION,
    }


def load_engine():
    """The compiled engine, or None (not built, too old, or disabled)."""
    if os.environ.get("ULPF_NATIVE_LANE", "1") == "0":
        return None
    try:
        from ulpf import ulpf_core
    except ImportError:
        return None
    if not hasattr(ulpf_core, "Engine"):
        logger.info("ulpf_core is a 9.0 build without the batch engine; rebuild native/ulpf_core")
        return None
    try:
        return ulpf_core.Engine(_tables())
    except Exception:
        logger.warning("ulpf_core.Engine failed to initialise; using the Python pipeline", exc_info=True)
        return None


def key_runs(row_key, first: int, last: int):
    """[(first_seq, last_seq, key)] covering first..last, for the core's row MACs."""
    if row_key is None:
        return None
    if isinstance(row_key, (bytes, bytearray)):
        return [(first, last, bytes(row_key))]
    runs = []
    for epoch in range(row_key.epoch_of(first), row_key.epoch_of(last) + 1):
        key = row_key.key_for_epoch(epoch)
        if key is None:
            continue
        lo = max(first, epoch * row_key.epoch_records + 1)
        hi = min(last, (epoch + 1) * row_key.epoch_records)
        runs.append((lo, hi, key))
    return runs


def _arrow_table(batch) -> pa.Table:
    """The core's store rows as a table: imported through the Arrow C Data Interface
    (PyCapsule), so the column buffers the core wrote are used in place."""
    from ulpf.storage.database import ARROW_SCHEMA
    rb = pa.record_batch(batch)
    if rb.schema != ARROW_SCHEMA:
        raise RuntimeError(f"ulpf_core store schema differs from ARROW_SCHEMA: {rb.schema}")
    return pa.Table.from_batches([rb])


@dataclass
class LaneResult:
    native: list[int]           # record indices processed natively (ascending)
    delegated: list[int]        # record indices for the Python pipeline (ascending)
    table: pa.Table             # store rows of the native records, in `native` order
    events: list | None         # their event dicts (when asked for)
    projections: list | None    # correlation projections (when asked for)
    batch: object = None        # the core's Batch: finished events (drift_items, events_json, anomaly state)
    sigma_undecided: list = field(default_factory=list)   # positions whose Sigma hits Python must evaluate
    sigma_matches: int = 0
    targets: list | None = None  # per native event: sink indices (with an Analytics router) ...
    targets_uniform: list | None = None   # ... or, when every native event has the same ones, those
    unrouted: int = 0


class NativeLane:
    def __init__(self, engine):
        from ulpf import ulpf_core
        self.engine = engine
        self.engine_module = ulpf_core      # Analytics, AnomalyState
        self.records = 0
        self.native_records = 0

    @classmethod
    def create(cls) -> "NativeLane | None":
        eng = load_engine()
        return cls(eng) if eng is not None else None

    def run(self, raws: list[bytes], digests: list[bytes], first_seq: int, node: str, input_name: str,
            source: str, source_ip: str, tags: list[str], row_key=None, want_events: bool = False,
            want_projections: bool = False, analytics=None) -> LaneResult:
        import orjson
        from ulpf.engine.enricher import _lookup_geo
        from ulpf.engine.schema import utc_now_iso
        from ulpf.intelligence.intel_db import get_intel_db
        from ulpf.intelligence.tip import runtime as tip_runtime

        batch = self.engine.parse(raws, digests, first_seq, node, input_name, source, source_ip, utc_now_iso())
        geo, ioc = {}, {}
        db = get_intel_db()
        tip = tip_runtime.active()
        tip = tip if tip_runtime.is_native(tip) else None
        for ip in batch.ips():
            g = _lookup_geo(ip)
            geo[ip] = (g.get("country"), g.get("cc"), g.get("city"), g.get("lat"), g.get("lon"))
            if tip is None:
                hit = db.lookup_ioc(ip)
                if hit:
                    ioc[ip] = (hit["cat"], float(hit["conf"]), "threat:" + hit["cat"].lower().replace(" ", "_"))
        out = batch.finish(geo, ioc, list(tags), key_runs(row_key, first_seq, first_seq + len(raws) - 1),
                           want_events, want_projections, analytics, tip)
        native = out["rows"]
        self.records += len(raws)
        self.native_records += len(native)
        events = orjson.loads(out["events"]) if out["events"] is not None else None
        proj = orjson.loads(out["projections"]) if out["projections"] is not None else None
        return LaneResult(native=native, delegated=batch.delegated, table=_arrow_table(out["arrow"]),
                          events=events, projections=proj, batch=batch, sigma_undecided=out["sigma_undecided"],
                          sigma_matches=out["sigma_matches"], targets=out["targets"],
                          targets_uniform=out["targets_uniform"], unrouted=out["unrouted"])

    def stats(self) -> dict:
        return {"records": self.records, "native": self.native_records,
                "native_ratio": round(self.native_records / self.records, 4) if self.records else None}
