"""
Event routing: which outputs receive an event.

Routes are evaluated in order. An event goes to the outputs of every route
whose conditions all hold, until a matching route marked ``final``. An event
matching no route goes to ``default_output`` and is counted as unrouted.
"""
from __future__ import annotations

from dataclasses import dataclass, field


def get_path(event: dict, dotted: str):
    cur = event
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


@dataclass
class Route:
    name: str
    to: tuple[str, ...]
    final: bool = False
    kind_in: frozenset | None = None
    input_in: frozenset | None = None
    source_in: frozenset | None = None
    raw_format_in: frozenset | None = None
    category_in: frozenset | None = None
    severity_gte: int | None = None
    severity_lte: int | None = None
    field_exists: tuple = ()
    field_equals: dict = field(default_factory=dict)

    @classmethod
    def from_config(cls, r: dict) -> "Route":
        w = r.get("when") or {}

        def fs(key):
            v = w.get(key)
            return frozenset(v) if v else None

        return cls(name=r["name"], to=tuple(r["to"]), final=bool(r.get("final")),
                   kind_in=fs("kind_in"), input_in=fs("input_in"), source_in=fs("source_in"),
                   raw_format_in=fs("raw_format_in"), category_in=fs("category_in"),
                   severity_gte=w.get("severity_gte"), severity_lte=w.get("severity_lte"),
                   field_exists=tuple(w.get("field_exists") or ()),
                   field_equals=dict(w.get("field_equals") or {}))

    def matches(self, event: dict) -> bool:
        if self.kind_in is not None and event.get("event_kind", "log") not in self.kind_in:
            return False
        meta = event.get("metadata") or {}
        if self.input_in is not None and meta.get("input") not in self.input_in:
            return False
        if self.source_in is not None and meta.get("ingestion_source") not in self.source_in:
            return False
        if self.raw_format_in is not None and event.get("raw_format") not in self.raw_format_in:
            return False
        if self.category_in is not None and event.get("category") not in self.category_in:
            return False
        sev = event.get("severity") or 0
        if self.severity_gte is not None and sev < self.severity_gte:
            return False
        if self.severity_lte is not None and sev > self.severity_lte:
            return False
        for p in self.field_exists:
            if get_path(event, p) in (None, "", [], {}):
                return False
        for p, v in self.field_equals.items():
            if get_path(event, p) != v:
                return False
        return True


class Router:
    def __init__(self, routes: list[dict], default_output: str | None):
        self.routes = [Route.from_config(r) for r in routes]
        self.default = default_output
        self.unrouted = 0

    def targets(self, event: dict, count_unrouted: bool = True) -> list[str]:
        out: list[str] = []
        for r in self.routes:
            if r.matches(event):
                for t in r.to:
                    if t not in out:
                        out.append(t)
                if r.final:
                    break
        if not out:
            if count_unrouted:
                self.unrouted += 1
            if self.default:
                out.append(self.default)
        return out

    def ir(self) -> tuple[dict, list[str]]:
        """The routes for the compiled core (``ulpf_core.Analytics``): (description, sink names);
        sinks are referred to by their index in the names list."""
        names: list[str] = []

        def idx(n: str) -> int:
            if n not in names:
                names.append(n)
            return names.index(n)

        def fs(s):
            return sorted(s) if s is not None else None

        routes = [{"to": [idx(t) for t in r.to], "final": r.final, "kind_in": fs(r.kind_in),
                   "input_in": fs(r.input_in), "source_in": fs(r.source_in), "raw_format_in": fs(r.raw_format_in),
                   "category_in": fs(r.category_in), "severity_gte": r.severity_gte, "severity_lte": r.severity_lte,
                   "field_exists": list(r.field_exists), "field_equals": [[p, v] for p, v in r.field_equals.items()]}
                  for r in self.routes]
        return {"routes": routes, "default": idx(self.default) if self.default else None}, names

    def split(self, events: list[dict]) -> dict[str, list[dict]]:
        by_sink: dict[str, list[dict]] = {}
        for e in events:
            for t in self.targets(e):
                by_sink.setdefault(t, []).append(e)
        return by_sink
