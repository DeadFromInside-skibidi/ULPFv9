"""
Splunk SPL2 subset.

    from <dataset> [where <expr>] | where ... | search a=b* "term" | eval x = ... | stats count() AS n BY f
    | rex field=_raw "(?<user>\\w+)" | dedup [N] f, g | lookup <table> <field> [AS <event field>] [OUTPUT a [AS b]]
    | table f, g | fields [-] f | sort [N] -f | head N | tail N | rename a AS b | bin _time span=1h
    | timechart span=1h count() [BY f] | top [N] f

Expressions: ``=`` and ``==`` compare, ``AND OR NOT``, ``IN (..)``, ``LIKE``, ``.`` concatenates.
Field names may be single-quoted ('src ip'). ``search`` terms are case-insensitive with ``*``.
Aggregates are named as Splunk names them: ``count``, ``count(x)``, ``dc(user)``, ``sum(bytes)``.
"""
from __future__ import annotations

import re

from ulpf.query import ir
from ulpf.query.exprs import ExprParser
from ulpf.query.lexer import Cursor

_AGG_ALIASES = {"distinct_count": "dc", "mean": "avg", "c": "count"}
_PERC = re.compile(r"^(?:perc|p)(\d{1,2}(?:\.\d+)?)$")


def check_regex(pattern: str, text: str, pos: int) -> None:
    """Reject a malformed pattern at parse time, at its position in the query."""
    from ulpf.query.lexer import QuerySyntaxError
    try:
        re.compile(pattern)
    except re.error as e:
        raise QuerySyntaxError(f"invalid regular expression: {e}", text, pos) from None


def convert_named_groups(pattern: str) -> tuple[str, list]:
    """PCRE ``(?<name>...)`` to RE2 ``(?P<name>...)``; returns (pattern, names in order)."""
    out = re.sub(r"\(\?<([A-Za-z_][A-Za-z0-9_.]*)>", r"(?P<\1>", pattern)
    return out, re.findall(r"\(\?P<([A-Za-z_][A-Za-z0-9_.]*)>", out)


class SplExpr(ExprParser):
    and_words = ("and",)
    or_words = ("or",)
    not_words = ("not",)
    concat_dot = True

    def compare(self, left):
        c = self.c
        t = c.tok
        if t.is_op("="):
            c.next()
            return ir.Binary("==", left, self._additive(), pos=t.pos)
        if t.is_word("like"):
            c.next()
            return ir.Binary("like", left, self._additive(), pos=t.pos)
        if t.is_word("in"):
            c.next()
            c.expect_op("(")
            items = self.expr_list()
            c.expect_op(")")
            return ir.InList(left, items, pos=t.pos)
        if t.is_word("not") and c.peek().is_word("in", "like"):
            c.next()
            w = c.next()
            if w.is_word("like"):
                return ir.Binary("nlike", left, self._additive(), pos=t.pos)
            c.expect_op("(")
            items = self.expr_list()
            c.expect_op(")")
            return ir.InList(left, items, True, pos=t.pos)
        return super().compare(left)

    def call(self):
        e = super().call()
        e.name = _AGG_ALIASES.get(e.name, e.name)
        m = _PERC.match(e.name)
        if m and e.args:
            e.args = [e.args[0], ir.Lit(float(m.group(1)), pos=e.pos)]
            e.name = "percentile"
        return e


def _agg_name(text: str, e: ir.Call) -> str:
    if e.name == "count" and not e.args:
        return "count"
    return text


class SplParser:
    def __init__(self, text: str):
        self.text = text
        self.c = Cursor(text, "spl")
        self.e = SplExpr(self.c)

    def parse(self) -> ir.Plan:
        c = self.c
        source = "events"
        stages: list = []
        if c.accept_word("from"):
            source, _ = c.name("a dataset name")
            if c.tok.is_word("where"):
                t = c.next()
                stages.append(ir.Where(self.e.expr(), pos=t.pos))
        elif c.tok.kind == "ident" and not c.tok.quoted and hasattr(self, "cmd_" + str(c.tok.value).lower()) \
                and not c.name_then("=", "!="):
            stages.extend(self.command())                   # a first command without a pipe
        elif c.tok.kind != "eof" and not c.tok.is_op("|"):
            stages.append(self.cmd_search(c.tok.pos))     # a bare search before the first pipe
        while c.accept_op("|"):
            stages.extend(self.command())
        if c.tok.kind != "eof":
            c.error("expected '|' or end of query")
        return ir.Plan(source, stages, "spl", self.text)

    def command(self) -> list:
        c = self.c
        t = c.tok
        if t.kind != "ident":
            c.error("expected a command")
        name = str(t.value).lower()
        fn = getattr(self, "cmd_" + name, None)
        if fn is None:
            c.error(f"unknown command {name!r}")
        c.next()
        r = fn(t.pos)
        return r if isinstance(r, list) else [r]

    # ---------------------------------------------------------------- helpers
    def _names(self) -> list:
        """Field list: comma- or space-separated (stops at '|', 'AS', 'BY', 'OUTPUT')."""
        names = []
        while self.c.tok.kind == "ident" and not self.c.tok.is_word("by", "as", "output", "outputnew"):
            names.append(self.c.name()[0])
            self.c.accept_op(",")
        if not names:
            self.c.error("expected a field name")
        return names

    def _span(self) -> float:
        self.c.expect_word("span")
        self.c.expect_op("=")
        t = self.c.tok
        if t.kind != "timespan":
            self.c.error("expected a span such as 1h")
        self.c.next()
        return t.value

    def _int(self, what="a number"):
        t = self.c.tok
        if t.kind != "number" or not isinstance(t.value, int):
            self.c.error(f"expected {what}")
        self.c.next()
        return t.value

    # ---------------------------------------------------------------- commands
    def cmd_where(self, pos):
        return ir.Where(self.e.expr(), pos=pos)

    def cmd_search(self, pos):
        return ir.Where(SearchTerms(self.c).parse(), pos=pos)

    def cmd_eval(self, pos):
        items = []
        while True:
            name, _ = self.c.name()
            self.c.expect_op("=")
            items.append((name, self.e.expr()))
            if not self.c.accept_op(","):
                return ir.Extend(items, pos=pos)

    def _aggs(self):
        aggs = []
        while True:
            t = self.c.tok
            start = t.pos
            if t.kind != "ident":
                self.c.error("expected an aggregation such as count() or sum(bytes)")
            if self.c.peek().is_op("("):
                e = self.e.expr()
            else:                                   # bare "count" / "dc"
                self.c.next()
                e = ir.Call(_AGG_ALIASES.get(str(t.value).lower(), str(t.value).lower()), [], pos=t.pos)
            if not ir.is_aggregate(e):
                self.c.error("expected an aggregation function", t)
            text = self.text[start:self.c.toks[self.c.i - 1].end]
            name = _agg_name(text, e)
            if self.c.accept_word("as"):
                name, _ = self.c.name()
            aggs.append((name, e))
            if not self.c.accept_op(","):
                if self.c.tok.kind == "ident" and not self.c.tok.is_word("by") and self.c.peek().is_op("("):
                    continue                          # space-separated aggregations
                return aggs

    def cmd_stats(self, pos):
        aggs = self._aggs()
        by = []
        if self.c.accept_word("by"):
            by = [(n, ir.Field(n, pos=pos)) for n in self._names()]
        return ir.Aggregate(aggs, by, pos=pos)

    def cmd_timechart(self, pos):
        span = self._span()
        aggs = self._aggs()
        by = [("_time", ir.Call("bin", [ir.Field("_time", pos=pos), ir.Lit(span, "timespan", pos=pos)], pos=pos))]
        if self.c.accept_word("by"):
            by += [(n, ir.Field(n, pos=pos)) for n in self._names()]
        return [ir.Aggregate(aggs, by, pos=pos), ir.Sort([(ir.Field("_time", pos=pos), False)], pos=pos)]

    def cmd_bin(self, pos):
        name, fpos = self.c.name()
        span = self._span()
        out = name
        if self.c.accept_word("as"):
            out, _ = self.c.name()
        return ir.Extend([(out, ir.Call("bin", [ir.Field(name, pos=fpos), ir.Lit(span, "timespan", pos=pos)],
                                        pos=pos))], pos=pos)

    cmd_bucket = cmd_bin

    def cmd_rex(self, pos):
        field = "_raw"
        if self.c.tok.is_word("field"):
            self.c.next()
            self.c.expect_op("=")
            field, _ = self.c.name()
        t = self.c.tok
        if t.kind != "string":
            self.c.error("expected a quoted regular expression")
        self.c.next()
        pattern, names = convert_named_groups(t.value)
        check_regex(pattern, self.text, t.pos)
        if not names:
            self.c.error("rex needs at least one named group (?<name>...)", t)
        return ir.Rex(ir.Field(field, pos=pos), pattern, names, pos=pos)

    def cmd_dedup(self, pos):
        keep = 1
        if self.c.tok.kind == "number":
            keep = self._int()
        return ir.Dedup(self._names(), keep, pos=pos)

    def cmd_lookup(self, pos):
        table, _ = self.c.name("a lookup table name")
        keys = []
        while self.c.tok.kind == "ident" and not self.c.tok.is_word("output", "outputnew"):
            col, _ = self.c.name()
            local = col
            if self.c.accept_word("as"):
                local, _ = self.c.name()
            keys.append((local, col))
            self.c.accept_op(",")
        if not keys:
            self.c.error("lookup needs a match field")
        outputs = []
        if self.c.accept_word("output", "outputnew"):
            while self.c.tok.kind == "ident":
                col, _ = self.c.name()
                out = col
                if self.c.accept_word("as"):
                    out, _ = self.c.name()
                outputs.append((col, out))
                self.c.accept_op(",")
        return ir.Lookup(table, keys, outputs, pos=pos)

    def cmd_table(self, pos):
        return ir.Project([(n, ir.Field(n, pos=pos)) for n in self._names()], pos=pos)

    def cmd_fields(self, pos):
        if self.c.accept_op("-"):
            return ir.ProjectAway(self._names(), pos=pos)
        self.c.accept_op("+")
        return self.cmd_table(pos)

    def cmd_sort(self, pos):
        limit = None
        if self.c.tok.kind == "number":
            limit = self._int()
        keys = []
        while self.c.tok.kind == "ident" or self.c.tok.is_op("-", "+"):
            desc = bool(self.c.accept_op("-"))
            if not desc:
                self.c.accept_op("+")
            e = self.e.expr()
            if self.c.accept_word("desc"):
                desc = True
            else:
                self.c.accept_word("asc")
            keys.append((e, desc))
            if not self.c.accept_op(","):
                break
        if not keys:
            self.c.error("sort needs a field")
        out = [ir.Sort(keys, pos=pos)]
        if limit:
            out.append(ir.Limit(limit, pos=pos))
        return out

    def cmd_head(self, pos):
        return ir.Limit(self._int() if self.c.tok.kind == "number" else 10, pos=pos)

    cmd_limit = cmd_head

    def cmd_tail(self, pos):
        return ir.Limit(self._int() if self.c.tok.kind == "number" else 10, tail=True, pos=pos)

    def cmd_rename(self, pos):
        pairs = []
        while True:
            old, _ = self.c.name()
            self.c.expect_word("as")
            new, _ = self.c.name()
            pairs.append((old, new))
            if not self.c.accept_op(","):
                return ir.Rename(pairs, pos=pos)

    def cmd_top(self, pos):
        n = 10
        if self.c.tok.kind == "number":
            n = self._int()
        if self.c.tok.is_word("limit"):
            self.c.next()
            self.c.expect_op("=")
            n = self._int()
        names = self._names()
        return [ir.Aggregate([("count", ir.Call("count", [], pos=pos))], [(f, ir.Field(f, pos=pos)) for f in names],
                             pos=pos),
                ir.Top(n, ir.Field("count", pos=pos), True, pos=pos)]


class SearchTerms:
    """SPL search syntax: ``a=b*`` ``a!=b`` ``"phrase"`` ``word`` with implicit AND, OR, NOT, ( )."""

    def __init__(self, cur: Cursor):
        self.c = cur

    def parse(self) -> ir.Expr:
        e = self._or()
        return e

    def _stop(self):
        return self.c.tok.kind == "eof" or self.c.tok.is_op("|", ")")

    def _or(self):
        left = self._and()
        while self.c.tok.is_word("or"):
            t = self.c.next()
            left = ir.Binary("or", left, self._and(), pos=t.pos)
        return left

    def _and(self):
        left = self._not()
        while not self._stop() and not self.c.tok.is_word("or"):
            t = self.c.tok
            self.c.accept_word("and")
            left = ir.Binary("and", left, self._not(), pos=t.pos)
        return left

    def _not(self):
        if self.c.tok.is_word("not"):
            t = self.c.next()
            return ir.Unary("not", self._not(), pos=t.pos)
        return self._term()

    def _value(self) -> ir.Lit:
        t = self.c.tok
        if t.kind == "string":
            self.c.next()
            return ir.Lit(str(t.value), pos=t.pos)
        start, end = t.pos, None
        while True:                       # adjacent tokens form one bare value: 10.0.0.*  admin*
            tok = self.c.tok
            if tok.kind == "eof" or tok.is_op("|", "(", ")", "=", "!=") or (end is not None and tok.pos != end):
                break
            self.c.next()
            end = tok.end
        if end is None:
            self.c.error("expected a value")
        return ir.Lit(self.c.text[start:end], pos=start)

    def _term(self):
        c = self.c
        t = c.tok
        if c.accept_op("("):
            e = self._or()
            c.expect_op(")")
            return e
        if t.kind == "ident" and c.name_then("=", "!=", "<", ">", "<=", ">="):
            name, _ = c.name()
            op = c.next()
            v = self._value()
            if op.value in ("=", "!="):
                e = ir.Binary("glob", ir.Field(name, pos=t.pos), ir.Lit(("i", v.value), "glob", pos=v.pos), pos=op.pos)
                return ir.Unary("not", e, pos=op.pos) if op.value == "!=" else e
            return ir.Binary(op.value, ir.Field(name, pos=t.pos), _num(v), pos=op.pos)
        v = self._value()
        return ir.Binary("glob", ir.Field("_raw", pos=t.pos), ir.Lit(("i", f"*{v.value}*"), "glob", pos=v.pos), pos=t.pos)


def _num(v: ir.Lit) -> ir.Lit:
    try:
        return ir.Lit(int(v.value), pos=v.pos)
    except ValueError:
        try:
            return ir.Lit(float(v.value), pos=v.pos)
        except ValueError:
            return v


def parse(text: str) -> ir.Plan:
    return SplParser(text).parse()
