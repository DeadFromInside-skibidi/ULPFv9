"""
Security query languages over ULPF telemetry: Microsoft Sentinel KQL, Splunk SPL2 and
CrowdStrike Falcon LogScale (HQL).

``parse(dialect, text)`` -> logical plan (``ir.Plan``); syntax errors are ``QuerySyntaxError``
with line and column. ``sqlgen`` compiles a plan to DuckDB SQL over Arrow data; ``engine`` runs
it against the event store or the lakehouse under the workload governor; ``live`` runs the
row-level subset continuously on the ingest path (live tail).
"""
from __future__ import annotations

from ulpf.query.ir import Plan
from ulpf.query.lexer import QuerySyntaxError

DIALECTS = ("kql", "spl", "hql")
_ALIASES = {"spl2": "spl", "splunk": "spl", "kusto": "kql", "sentinel": "kql", "logscale": "hql",
            "humio": "hql", "lql": "hql", "cql": "hql"}


def dialect_of(name: str) -> str:
    d = _ALIASES.get(name.lower(), name.lower())
    if d not in DIALECTS:
        raise ValueError(f"unknown query dialect {name!r} (kql, spl, hql)")
    return d


def parse(dialect: str, text: str) -> Plan:
    d = dialect_of(dialect)
    if d == "kql":
        from ulpf.query.kql import parse as p
    elif d == "spl":
        from ulpf.query.spl import parse as p
    else:
        from ulpf.query.hql import parse as p
    try:
        return p(text)
    except RecursionError:
        raise QuerySyntaxError("query nested too deeply", text, 0) from None


__all__ = ["parse", "dialect_of", "DIALECTS", "Plan", "QuerySyntaxError"]
