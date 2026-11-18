"""
The logical plan the three dialects compile to: a source and a list of stages, each stage a
table-to-table operator over expressions. ``sqlgen`` turns a plan into DuckDB SQL over Arrow
data; ``live`` runs the row-level subset as a streaming filter.

Every node keeps ``pos`` (offset in the query text) for error messages.
"""
from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------- expressions

@dataclass
class Expr:
    pos: int = field(default=0, kw_only=True)


@dataclass
class Field(Expr):
    name: str


@dataclass
class Lit(Expr):
    value: object          # str, int, float, bool, None
    kind: str = ""         # "" | "timespan" (seconds) | "datetime" (ISO text) | "regex"


@dataclass
class Unary(Expr):
    op: str                # not, -
    arg: Expr


@dataclass
class Binary(Expr):
    op: str
    left: Expr
    right: Expr


@dataclass
class InList(Expr):
    arg: Expr
    items: list
    negate: bool = False
    ci: bool = False


@dataclass
class Between(Expr):
    arg: Expr
    lo: Expr
    hi: Expr
    negate: bool = False


@dataclass
class Call(Expr):
    name: str
    args: list
    kwargs: dict = field(default_factory=dict)


# Binary operators the generator knows (dialects map onto these)
#   arithmetic + - * / %   comparison == != < <= > >=   logic and or
#   ieq ine (case-insensitive equality)   contains ncontains contains_cs ncontains_cs
#   has nhas startswith nstartswith endswith nendswith   regex nregex   like nlike (SQL %/_)
#   glob (HQL/SPL * wildcards, case per flag in the right literal)

AGGREGATES = frozenset((
    "count", "countif", "dcount", "dc", "distinct_count", "sum", "avg", "mean", "min", "max", "make_set",
    "make_list", "values", "list", "percentile", "stdev", "variance", "any", "take_any", "earliest",
    "latest", "first", "last", "median", "sumif", "avgif", "range"))


def is_aggregate(e) -> bool:
    return isinstance(e, Call) and e.name in AGGREGATES


# ---------------------------------------------------------------- stages

@dataclass
class Stage:
    pos: int = field(default=0, kw_only=True)


@dataclass
class Where(Stage):
    cond: Expr


@dataclass
class Extend(Stage):
    items: list            # [(name, Expr)]


@dataclass
class Project(Stage):
    items: list            # [(name, Expr)]


@dataclass
class ProjectAway(Stage):
    names: list


@dataclass
class Rename(Stage):
    pairs: list            # [(old, new)]


@dataclass
class Aggregate(Stage):
    aggs: list             # [(name, Call)]
    by: list               # [(name, Expr)]


@dataclass
class Sort(Stage):
    keys: list             # [(Expr, descending)]


@dataclass
class Limit(Stage):
    n: int
    tail: bool = False


@dataclass
class Top(Stage):
    n: int
    key: Expr
    desc: bool = True


@dataclass
class Distinct(Stage):
    names: list


@dataclass
class Dedup(Stage):
    names: list
    keep: int = 1


@dataclass
class Rex(Stage):
    source: Expr           # the text the pattern runs on
    pattern: str           # RE2 syntax, named groups (?P<name>...)
    names: list            # group names, in order
    filter: bool = False   # HQL: lines that do not match are dropped


@dataclass
class MvExpand(Stage):
    name: str
    expr: Expr | None = None


@dataclass
class Join(Stage):
    kind: str              # inner leftouter rightouter fullouter leftanti leftsemi innerunique
    right: "Plan"
    keys: list             # [(left name, right name)]


@dataclass
class MakeSeries(Stage):
    aggs: list             # [(name, Call)]
    on: Expr
    start: Expr | None
    end: Expr | None
    step: float            # seconds
    by: list               # [(name, Expr)]
    default: object = 0


@dataclass
class Lookup(Stage):
    table: str
    keys: list             # [(event field, lookup column)]
    outputs: list          # [(lookup column, output name)]; empty = every other column


@dataclass
class Plan:
    source: str            # "events" (or a lookup / dataset name)
    stages: list
    dialect: str = ""
    text: str = ""

    def row_level(self) -> bool:
        """Only per-row operators (a live tail can run it on each batch independently)."""
        return all(isinstance(s, (Where, Extend, Project, ProjectAway, Rename, Rex, MvExpand, Limit))
                   and not (isinstance(s, Limit) and s.tail) for s in self.stages)
