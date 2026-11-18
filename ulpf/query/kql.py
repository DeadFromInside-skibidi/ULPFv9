"""
Kusto Query Language (Microsoft Sentinel / Azure Data Explorer) subset.

    Table | where ... | extend a = ... | project a, b = ... | project-away x | project-rename n = o
          | summarize agg(...)[, ...] [by key, bin(timestamp, 1h)] | count | take n | top n by e [asc]
          | sort by e [asc|desc] | distinct a, b | mv-expand x | join kind=... (subquery) on key
          | make-series agg default=0 on timestamp [from e to e] step 1h [by key]

String operators: == != =~ !~ contains has startswith endswith (with ! and _cs variants),
matches regex, in / !in / in~, between (a .. b). Column names default the way Kusto names
them (count_, sum_bytes, ...).
"""
from __future__ import annotations

from ulpf.query import ir
from ulpf.query.exprs import ExprParser
from ulpf.query.lexer import Cursor

_STRING_OPS = {
    "contains": "contains", "contains_cs": "contains_cs", "has": "has", "has_cs": "has_cs",
    "startswith": "startswith", "startswith_cs": "startswith_cs", "endswith": "endswith",
    "endswith_cs": "endswith_cs", "like": "like",
}


def default_name(e: ir.Expr) -> str:
    if isinstance(e, ir.Field):
        return e.name
    if isinstance(e, ir.Call):
        if e.name in ("bin", "floor", "tostring", "toint", "tolong", "todouble", "toreal", "tolower", "toupper")                 and e.args and isinstance(e.args[0], ir.Field):
            return e.args[0].name
        if e.name == "count" and not e.args:
            return "count_"
        if e.args and isinstance(e.args[0], ir.Field):
            return f"{e.name}_{e.args[0].name}".replace(".", "_")
        return f"{e.name}_"
    return "Column1"


class KqlExpr(ExprParser):
    def compare(self, left):
        c = self.c
        t = c.tok
        neg = False
        if t.is_op("!") and c.peek().kind == "ident" and c.peek().pos == t.end:
            neg = True
            word = str(c.peek().value).lower()
        elif t.kind == "ident" and not t.quoted:
            word = str(t.value).lower()
        else:
            if t.is_op("=~", "!~"):
                c.next()
                return ir.Binary("ieq" if t.value == "=~" else "ine", left, self._additive(), pos=t.pos)
            return super().compare(left)
        if word in _STRING_OPS:
            if neg:
                c.next()
            c.next()
            op = _STRING_OPS[word]
            return ir.Binary(("n" if neg else "") + op, left, self._additive(), pos=t.pos)
        if word == "matches" and not neg:
            c.next()
            c.expect_word("regex")
            return ir.Binary("regex", left, self._additive(), pos=t.pos)
        if word in ("in", "between"):
            if neg:
                c.next()
            c.next()
            if word == "in":
                ci = bool(c.accept_op("~"))
                c.expect_op("(")
                items = self.expr_list()
                c.expect_op(")")
                return ir.InList(left, items, neg, ci, pos=t.pos)
            c.expect_op("(")
            lo = self._additive()
            c.expect_op("..")
            hi = self._additive()
            c.expect_op(")")
            return ir.Between(left, lo, hi, neg, pos=t.pos)
        return None


class KqlParser:
    def __init__(self, text: str):
        self.c = Cursor(text, "kql")
        self.e = KqlExpr(self.c)
        self.text = text

    def parse(self) -> ir.Plan:
        plan = self.pipeline(top=True)
        if self.c.tok.kind != "eof":
            self.c.error("expected '|' or end of query")
        return plan

    def pipeline(self, top: bool = False) -> ir.Plan:
        c = self.c
        if c.tok.kind == "ident" and not c.tok.is_word(*_OPERATORS):
            source, _ = c.name("a table name")
        elif top:
            source = "events"
        else:
            c.error("expected a table name")
        stages = []
        while c.accept_op("|"):
            stages.append(self.operator())
        return ir.Plan(source, stages, "kql", self.text)

    # ---------------------------------------------------------------- operators
    def operator(self):
        c = self.c
        t = c.tok
        if t.kind != "ident":
            c.error("expected a query operator")
        op = str(t.value).lower()
        fn = getattr(self, "op_" + op.replace("-", "_"), None)
        if fn is None or op not in _OPERATORS:
            c.error(f"unknown query operator {op!r}")
        c.next()
        return fn(t.pos)

    def op_where(self, pos):
        return ir.Where(self.e.expr(), pos=pos)

    op_filter = op_where

    def _items(self, need_name: bool):
        """``[name =] expr`` items; a bare expression is named the way Kusto names it."""
        items = []
        while True:
            t = self.c.tok
            if t.kind == "ident" and self.c.name_then("="):
                name, _ = self.c.name()
                self.c.expect_op("=")
                items.append((name, self.e.expr()))
            else:
                e = self.e.expr()
                if need_name and not isinstance(e, ir.Field):
                    self.c.error("extend needs name = expression", t)
                items.append((default_name(e), e))
            if not self.c.accept_op(","):
                return items

    def op_project(self, pos):
        return ir.Project(self._items(False), pos=pos)

    def op_extend(self, pos):
        return ir.Extend(self._items(True), pos=pos)

    def op_project_away(self, pos):
        names = [self.c.name()[0]]
        while self.c.accept_op(","):
            names.append(self.c.name()[0])
        return ir.ProjectAway(names, pos=pos)

    def op_project_rename(self, pos):
        pairs = []
        while True:
            new, _ = self.c.name()
            self.c.expect_op("=")
            old, _ = self.c.name()
            pairs.append((old, new))
            if not self.c.accept_op(","):
                return ir.Rename(pairs, pos=pos)

    def _aggs(self):
        aggs = []
        while True:
            t = self.c.tok
            if t.kind == "ident" and self.c.name_then("="):
                name, _ = self.c.name()
                self.c.expect_op("=")
            else:
                name = None
            e = self.e.expr()
            if not ir.is_aggregate(e):
                self.c.error("expected an aggregation function such as count() or sum(x)", t)
            aggs.append((name or default_name(e), e))
            if not self.c.accept_op(","):
                return aggs

    def _by(self):
        by = []
        while True:
            t = self.c.tok
            if t.kind == "ident" and self.c.name_then("="):
                name, _ = self.c.name()
                self.c.expect_op("=")
                by.append((name, self.e.expr()))
            else:
                e = self.e.expr()
                by.append((default_name(e), e))
            if not self.c.accept_op(","):
                return by

    def op_summarize(self, pos):
        aggs = [] if self.c.tok.is_word("by") else self._aggs()
        by = self._by() if self.c.accept_word("by") else []
        if not aggs and not by:
            self.c.error("summarize needs an aggregation or a by clause")
        return ir.Aggregate(aggs, by, pos=pos)

    def op_count(self, pos):
        return ir.Aggregate([("Count", ir.Call("count", [], pos=pos))], [], pos=pos)

    def _int(self, what):
        t = self.c.tok
        if t.kind != "number" or not isinstance(t.value, int):
            self.c.error(f"expected {what}")
        self.c.next()
        return t.value

    def op_take(self, pos):
        return ir.Limit(self._int("a row count"), pos=pos)

    op_limit = op_take

    def op_top(self, pos):
        n = self._int("a row count")
        self.c.expect_word("by")
        key = self.e.expr()
        desc = not self.c.accept_word("asc")
        self.c.accept_word("desc")
        return ir.Top(n, key, desc, pos=pos)

    def op_sort(self, pos):
        self.c.expect_word("by")
        keys = []
        while True:
            e = self.e.expr()
            desc = True
            if self.c.accept_word("asc"):
                desc = False
            else:
                self.c.accept_word("desc")
            if self.c.accept_word("nulls"):
                self.c.expect_word("first", "last")
            keys.append((e, desc))
            if not self.c.accept_op(","):
                return ir.Sort(keys, pos=pos)

    op_order = op_sort

    def op_distinct(self, pos):
        names = [self.c.name()[0]]
        while self.c.accept_op(","):
            names.append(self.c.name()[0])
        return ir.Distinct(names, pos=pos)

    def op_mv_expand(self, pos):
        t = self.c.tok
        if t.kind == "ident" and self.c.name_then("="):
            name, _ = self.c.name()
            self.c.expect_op("=")
            e = self.e.expr()
        else:
            e = self.e.expr()
            name = default_name(e)
        if self.c.accept_word("to"):
            self.c.expect_word("typeof")
            self.c.expect_op("(")
            self.c.next()
            self.c.expect_op(")")
        return ir.MvExpand(name, e, pos=pos)

    def op_join(self, pos):
        kind = "innerunique"
        if self.c.accept_word("kind"):
            self.c.expect_op("=")
            t = self.c.next()
            kind = str(t.value).lower()
            if kind not in ("inner", "innerunique", "leftouter", "rightouter", "fullouter", "leftanti",
                            "leftsemi", "rightanti", "rightsemi", "anti", "semi"):
                self.c.error("unknown join kind", t)
        self.c.expect_op("(")
        right = self.pipeline()
        self.c.expect_op(")")
        self.c.expect_word("on")
        keys = []
        while True:
            if self.c.tok.is_op("$"):
                self.c.next()
                self.c.expect_word("left")
                self.c.expect_op(".")
                lname, _ = self.c.name()
                self.c.expect_op("==")
                self.c.expect_op("$")
                self.c.expect_word("right")
                self.c.expect_op(".")
                rname, _ = self.c.name()
                keys.append((lname, rname))
            else:
                n, _ = self.c.name()
                keys.append((n, n))
            if not self.c.accept_op(","):
                break
        return ir.Join({"anti": "leftanti", "semi": "leftsemi"}.get(kind, kind), right, keys, pos=pos)

    def op_make_series(self, pos):
        aggs = []
        default = 0
        while True:
            t = self.c.tok
            if t.kind == "ident" and self.c.name_then("="):
                name, _ = self.c.name()
                self.c.expect_op("=")
            else:
                name = None
            e = self.e.expr()
            if not ir.is_aggregate(e):
                self.c.error("expected an aggregation function", t)
            if self.c.accept_word("default"):
                self.c.expect_op("=")
                d = self.e.expr()
                if not isinstance(d, ir.Lit):
                    self.c.error("default must be a literal")
                default = d.value
            aggs.append((name or default_name(e), e))
            if not self.c.accept_op(","):
                break
        self.c.expect_word("on")
        on = self.e.expr()
        start = end = None
        if self.c.accept_word("from"):
            start = self.e.expr()
        if self.c.accept_word("to"):
            end = self.e.expr()
        self.c.expect_word("step")
        t = self.c.tok
        if t.kind != "timespan":
            self.c.error("expected a timespan step such as 1h")
        self.c.next()
        by = self._by() if self.c.accept_word("by") else []
        return ir.MakeSeries(aggs, on, start, end, t.value, by, default, pos=pos)


_OPERATORS = ("where", "filter", "project", "extend", "project-away", "project-rename", "summarize", "count",
              "take", "limit", "top", "sort", "order", "distinct", "mv-expand", "join", "make-series")


def parse(text: str) -> ir.Plan:
    return KqlParser(text).parse()
