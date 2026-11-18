"""Helpers shared by the OCSF, UDM and ASIM views."""
from __future__ import annotations

import copy
from datetime import datetime, timezone

SUCCESS = frozenset(("allowed", "success", "accepted", "login", "logon", "permitted", "created", "connected"))
FAILURE = frozenset(("blocked", "denied", "dropped", "failure", "failed", "rejected", "reset", "quarantined"))
BLOCKED = frozenset(("blocked", "denied", "dropped", "rejected", "reset", "quarantined"))


def outcome(event: dict) -> str:
    """success / failure / unknown, from the normalised action (and an API error code)."""
    a = (event.get("action") or "").lower()
    if a in SUCCESS:
        return "success"
    if a in FAILURE:
        return "failure"
    return "unknown"


def epoch_ms(ts) -> int | None:
    if not ts:
        return None
    try:
        return int(datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return None


def iso_from_ms(ms) -> str | None:
    if ms is None:
        return None
    try:
        return datetime.fromtimestamp(int(ms) / 1000, timezone.utc).isoformat(timespec="milliseconds")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def iso_utc(ts) -> str | None:
    """An ISO-8601 timestamp in UTC with a Z suffix (UDM / ASIM datetime), unchanged instant."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def clean(d):
    """Drop None / empty containers recursively (keeps 0, False and "")."""
    if isinstance(d, dict):
        out = {}
        for k, v in d.items():
            v = clean(v)
            if v is None or v == {} or v == []:
                continue
            out[k] = v
        return out
    if isinstance(d, list):
        return [x for x in (clean(v) for v in d) if x not in (None, {}, [])]
    return d


def as_int(v) -> int | None:
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    s = str(v).strip()
    try:
        return int(s, 16) if s[:2].lower() == "0x" else int(s)   # Windows logs process IDs in hex
    except ValueError:
        return None


def basename(path) -> str | None:
    if not path:
        return None
    s = str(path).rstrip("/\\")
    for sep in ("\\", "/"):
        if sep in s:
            s = s.rsplit(sep, 1)[1]
    return s or None


def parent_dir(path) -> str | None:
    if not path:
        return None
    s = str(path).rstrip("/\\")
    for sep in ("\\", "/"):
        if sep in s:
            return s.rsplit(sep, 1)[0] or sep
    return None


# The unified fields with no exact home in a standard: carried as they are under x_ulpf,
# so a ULPF event survives the round trip unified -> standard -> unified.
RESIDUAL_TOP = ("category", "event_type", "action", "severity", "severity_label", "event_kind", "timestamp",
                "timestamp_original", "related_events", "extensions", "correlation_id", "raw_format", "tags")


def residual(event: dict, raw: bool = False) -> dict:
    """The x_ulpf block: top-level classification plus the groups, as the event has them
    (and the raw record, for a standard without a field for it)."""
    keys = RESIDUAL_TOP + (("raw_event",) if raw else ())
    out = {k: copy.deepcopy(event.get(k)) for k in keys if k in event}
    for g in ("source", "destination", "network", "device", "rule", "threat", "user", "geo", "metadata", "evidence"):
        if g in event:
            out[g] = copy.deepcopy(event[g])
    return {"v": 1, "event": out}


def restore(x: dict | None) -> dict | None:
    """The unified event an x_ulpf block carries (None when absent or of another version)."""
    if not isinstance(x, dict) or x.get("v") != 1 or not isinstance(x.get("event"), dict):
        return None
    return copy.deepcopy(x["event"])
