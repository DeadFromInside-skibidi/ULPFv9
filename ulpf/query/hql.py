"""
CrowdStrike Falcon LogScale (Humio) query language subset.

A pipeline of stages separated by ``|``. A stage is

* a filter: terms joined by implicit AND / ``and`` / ``or`` / ``not`` / ``!``:
  ``field=value`` (``*`` wildcards, case-sensitive), ``field!=value``, ``field=/re/i``,
  ``field>5``, ``"free text"`` and bare words (case-insensitive, on @rawstring),
  ``/re/flags`` on @rawstring, whose named groups become fields;
* an assignment ``x := expr``;
* a function: groupBy([f, g], function=[count(), sum(x)], limit=n), count(), sum(x), avg(x),
  min(x), max(x), head(n), tail(n), sort(f, order=asc, limit=n), table([f]), select([f]),
  drop([f]), rename(field=a, as=b), regex("re", field=f), lowercase(f), length(f, as=n),
  top(f, limit=n), bucket(span=1h, function=count()), timeChart(span=1h, function=count(),
  series=f), filter(expr), eval(x = expr), in(f, values=[...]).

Aggregates are named the LogScale way: _count, _sum, _avg, _min, _max (or ``as=``).
"""
from __future__ import annotations

from ulpf.query import ir
from ulpf.query.exprs import ExprParser
from ulpf.query.lexer import Cursor
from ulpf.query.spl import check_regex, convert_named_groups

_AGGS = {"count": "_count", "sum": "_sum", "avg": "_avg", "min": "_min", "max": "_max",
         "collect": "_collect", "percentile": "_percentile", "stddev": "_stddev"}
_FUNCS = ("groupby", "count", "sum", "avg", "min", "max", "head", "tail", "sort", "table", "select", "drop",
          "rename", "regex", "lowercase", "length", "top", "bucket", "timechart", "filter", "eval", "in", "test")


class HqlExpr(ExprParser):
    and_words = ("and",)
    or_words = ("or",)
    not_words = ("not",)

    def other_primary(self):
        c = self.c
        t = c.tok
        if c.accept_op("["):
            items = self.expr_list("]")
            c.expect_op("]")
            return ir.Call("__list", items, pos=t.pos)
        c.error("expected an expression")

    def compare(self, left):
        t = self.c.tok
        if t.is_op("="):                         # inside filter()/eval(): = compares
            self.c.next()
            return ir.Binary("==", left, self._additive(), pos=t.pos)
        return super().compare(left)


def _glob_or_eq(field: ir.Expr, v: ir.Lit, op_pos: int) -> ir.Expr:
    if isinstance(v.value, str) and "*" in v.value:
        if v.value == "*":
            return ir.Unary("not", ir.Call("isnull", [field], pos=op_pos), pos=op_pos)
        return ir.Binary("glob", field, ir.Lit(("", v.value), "glob", pos=v.pos), pos=op_pos)
    return ir.Binary("==", field, v, pos=op_pos)


class HqlParser:
    def __init__(self, text: str):
        self.text = text
        self.c = Cursor(text, "hql")
        self.e = HqlExpr(self.c)

    def parse(self) -> ir.Plan:
        stages: list = []
        c = self.c
        if c.tok.kind == "eof":
            return ir.Plan("events", [], "hql", self.text)
        while True:
            stages.extend(self.stage())
            if c.tok.kind == "eof":
                break
            c.expect_op("|")
        return ir.Plan("events", stages, "hql", self.text)

    # ---------------------------------------------------------------- stages
    def stage(self) -> list:
        c = self.c
        t = c.tok
        if t.kind == "ident" and c.name_then(":="):
            name, _ = c.name()
            c.expect_op(":=")
            return [ir.Extend([(name, self.e.expr())], pos=t.pos)]
        if t.kind == "ident" and c.peek().is_op("(") and c.peek().pos == t.end \
                and str(t.value).lower() in _FUNCS and str(t.value).lower() not in ("in", "test"):
            return self.function()
        if t.kind == "regex" and self._alone():
            return [self._rawregex(c.next())]
        return [ir.Where(self.filter_or(), pos=t.pos)]

    def _alone(self) -> bool:
        nxt = self.c.peek()
        return nxt.kind == "eof" or nxt.is_op("|")

    def _rawregex(self, t) -> ir.Stage:
        pat, flags = t.value
        pattern, names = convert_named_groups(pat)
        check_regex(pattern, self.text, t.pos)
        if "i" in flags:
            pattern = "(?i)" + pattern
        if names:
            return ir.Rex(ir.Field("@rawstring", pos=t.pos), pattern, names, filter=True, pos=t.pos)
        return ir.Where(ir.Binary("regex", ir.Field("@rawstring", pos=t.pos), ir.Lit(pattern, pos=t.pos), pos=t.pos),
                        pos=t.pos)

    # ---------------------------------------------------------------- filters
    def _stop(self):
        t = self.c.tok
        return t.kind == "eof" or t.is_op("|", ")")

    def filter_or(self):
        left = self.filter_and()
        while self.c.tok.is_word("or"):
            t = self.c.next()
            left = ir.Binary("or", left, self.filter_and(), pos=t.pos)
        return left

    def filter_and(self):
        left = self.filter_not()
        while not self._stop() and not self.c.tok.is_word("or"):
            t = self.c.tok
            self.c.accept_word("and")
            left = ir.Binary("and", left, self.filter_not(), pos=t.pos)
        return left

    def filter_not(self):
        t = self.c.tok
        if t.is_word("not") or (t.is_op("!") and not self.c.peek().is_op("=")):
            self.c.next()
            return ir.Unary("not", self.filter_not(), pos=t.pos)
        return self.term()

    def _value(self) -> ir.Lit:
        c = self.c
        t = c.tok
        if t.kind == "string":
            c.next()
            return ir.Lit(t.value, pos=t.pos)
        if t.kind == "regex":
            c.next()
            return ir.Lit(t.value, "regex", pos=t.pos)
        start, end = t.pos, None
        while True:
            tok = c.tok
            if tok.kind in ("eof", "string", "regex") or tok.is_op("|", "(", ")", "=", "!=", "<", ">", "<=", ">=") \
                    or (end is not None and tok.pos != end):
                break
            c.next()
            end = tok.end
        if end is None:
            c.error("expected a value")
        raw = self.text[start:end]
        if t.kind == "number" and end == t.end:
            return ir.Lit(t.value, pos=start)
        return ir.Lit(raw, pos=start)

    def term(self):
        c = self.c
        t = c.tok
        if c.accept_op("("):
            e = self.filter_or()
            c.expect_op(")")
            return e
        if t.kind == "ident" and c.peek().is_op("(") and c.peek().pos == t.end:
            name = str(t.value).lower()
            if name in ("in", "test", "filter"):
                call = self.e.call()
                if name == "in":
                    if not call.args or "values" not in call.kwargs:
                        c.error("in() needs a field and values=[...]", t)
                    vals = call.kwargs["values"]
                    items = vals.args if isinstance(vals, ir.Call) and vals.name == "__list" else [vals]
                    items = [ir.Lit(x.name, pos=x.pos) if isinstance(x, ir.Field) else x for x in items]   # bare words
                    return ir.InList(call.args[0], items, pos=t.pos)
                if len(call.args) != 1:
                    c.error(f"{name}() takes one expression", t)
                return call.args[0]
            c.error(f"{name}() cannot be used inside a filter", t)
        if t.kind == "regex":
            c.next()
            pat, flags = t.value
            pattern, _ = convert_named_groups(pat)
            return ir.Binary("regex", ir.Field("@rawstring", pos=t.pos),
                             ir.Lit(("(?i)" if "i" in flags else "") + pattern, pos=t.pos), pos=t.pos)
        if (t.kind == "ident" or t.is_op("@")) and not t.quoted and c.name_then("=", "!=", "<", ">", "<=", ">="):
            name, fpos = c.name()
            op = c.next()
            v = self._value()
            f = ir.Field(name, pos=fpos)
            if v.kind == "regex":
                pat, flags = v.value
                pattern, _ = convert_named_groups(pat)
                e = ir.Binary("regex", f, ir.Lit(("(?i)" if "i" in flags else "") + pattern, pos=v.pos), pos=op.pos)
            elif op.value in ("=", "!="):
                e = _glob_or_eq(f, v, op.pos)
            else:
                return ir.Binary(op.value, f, v if isinstance(v.value, (int, float)) else _num(v), pos=op.pos)
            return ir.Unary("not", e, pos=op.pos) if op.value == "!=" else e
        v = self._value()                          # free text: case-insensitive on @rawstring
        return ir.Binary("glob", ir.Field("@rawstring", pos=t.pos), ir.Lit(("i", f"*{v.value}*"), "glob", pos=v.pos),
                         pos=t.pos)

    # ---------------------------------------------------------------- functions
    def _fields(self, e: ir.Expr) -> list:
        items = e.args if isinstance(e, ir.Call) and e.name == "__list" else [e]
        out = []
        for x in items:
            if isinstance(x, ir.Field):
                out.append(x.name)
            elif isinstance(x, ir.Lit) and isinstance(x.value, str):
                out.append(x.value)
            else:
                self.c.error("expected field names")
        return out

    def _aggs(self, e: ir.Expr | None) -> list:
        if e is None:
            return [("_count", ir.Call("count", [], pos=0))]
        items = e.args if isinstance(e, ir.Call) and e.name == "__list" else [e]
        out = []
        for x in items:
            if not (isinstance(x, ir.Call) and x.name in _AGGS):
                self.c.error("function= takes aggregations such as count() or sum(x)")
            out.append(self._agg(x))
        return out

    def _agg(self, call: ir.Call):
        name = _AGGS[call.name]
        as_ = call.kwargs.get("as")
        if isinstance(as_, (ir.Field, ir.Lit)):
            name = as_.name if isinstance(as_, ir.Field) else str(as_.value)
        if call.name == "count" and isinstance(call.kwargs.get("distinct"), ir.Lit) and call.kwargs["distinct"].value:
            call = ir.Call("dcount", call.args, pos=call.pos)
        elif call.name == "collect":
            call = ir.Call("make_set", call.args, pos=call.pos)
        elif call.name == "percentile":
            p = call.kwargs.get("percentiles") or call.kwargs.get("percentile") or ir.Lit(50, pos=call.pos)
            p = p.args[0] if isinstance(p, ir.Call) and p.name == "__list" else p
            call = ir.Call("percentile", [call.args[0], p], pos=call.pos)
        elif call.name == "stddev":
            call = ir.Call("stdev", call.args, pos=call.pos)
        else:
            call = ir.Call(call.name, call.args, pos=call.pos)
        return name, call

    def _int_kw(self, call, key, default=None):
        v = call.kwargs.get(key)
        if v is None:
            return default
        if not (isinstance(v, ir.Lit) and isinstance(v.value, int)):
            self.c.error(f"{key}= must be a number")
        return v.value

    def _span(self, call) -> float:
        v = call.kwargs.get("span")
        if not (isinstance(v, ir.Lit) and v.kind == "timespan"):
            self.c.error("span= must be a duration such as 1h")
        return v.value

    def function(self) -> list:
        t = self.c.tok
        call = self.e.call()
        name, pos = call.name, t.pos
        if name in _AGGS:
            return [ir.Aggregate([self._agg(call)], [], pos=pos)]
        if name == "groupby":
            if not call.args:
                self.c.error("groupBy() needs fields", t)
            by = [(f, ir.Field(f, pos=pos)) for f in self._fields(call.args[0])]
            out = [ir.Aggregate(self._aggs(call.kwargs.get("function")), by, pos=pos)]
            lim = self._int_kw(call, "limit")
            if lim:
                out.append(ir.Limit(lim, pos=pos))
            return out
        if name in ("head", "tail"):
            n = call.args[0].value if call.args and isinstance(call.args[0], ir.Lit) else self._int_kw(call, "limit", 200)
            return [ir.Limit(int(n), tail=name == "tail", pos=pos)]
        if name == "sort":
            fields = self._fields(call.args[0]) if call.args else ["_count"]
            order = call.kwargs.get("order")
            desc = not (isinstance(order, (ir.Field, ir.Lit)) and str(getattr(order, "name", getattr(order, "value", "")))
                        .lower() in ("asc", "ascending"))
            out = [ir.Sort([(ir.Field(f, pos=pos), desc) for f in fields], pos=pos)]
            lim = self._int_kw(call, "limit")
            if lim:
                out.append(ir.Limit(lim, pos=pos))
            return out
        if name in ("table", "select"):
            fields = self._fields(call.args[0]) if call.args else self.c.error("table() needs fields", t)
            out = [ir.Project([(f, ir.Field(f, pos=pos)) for f in fields], pos=pos)]
            lim = self._int_kw(call, "limit")
            if lim:
                out.append(ir.Limit(lim, pos=pos))
            return out
        if name == "drop":
            return [ir.ProjectAway(self._fields(call.args[0]), pos=pos)]
        if name == "rename":
            src = call.kwargs.get("field") or (call.args[0] if call.args else None)
            dst = call.kwargs.get("as")
            if src is None or dst is None:
                self.c.error("rename() needs field= and as=", t)
            return [ir.Rename([(self._fields(src)[0], self._fields(dst)[0])], pos=pos)]
        if name == "regex":
            if not call.args or not isinstance(call.args[0], ir.Lit):
                self.c.error('regex() needs a pattern: regex("(?<user>\\\\w+)")', t)
            raw = call.args[0].value
            pat, flags = raw if call.args[0].kind == "regex" else (raw, "")
            pattern, names = convert_named_groups(pat)
            check_regex(pattern, self.text, call.args[0].pos)
            if "i" in flags or (isinstance(call.kwargs.get("flags"), ir.Lit) and "i" in str(call.kwargs["flags"].value)):
                pattern = "(?i)" + pattern
            field = self._fields(call.kwargs["field"])[0] if "field" in call.kwargs else "@rawstring"
            strict = call.kwargs.get("strict")
            keep = isinstance(strict, ir.Lit) and strict.value is False
            if not names:
                return [ir.Where(ir.Binary("regex", ir.Field(field, pos=pos), ir.Lit(pattern, pos=pos), pos=pos), pos=pos)]
            return [ir.Rex(ir.Field(field, pos=pos), pattern, names, filter=not keep, pos=pos)]
        if name == "lowercase":
            f = self._fields(call.args[0])[0] if call.args else self.c.error("lowercase() needs a field", t)
            return [ir.Extend([(f, ir.Call("tolower", [ir.Field(f, pos=pos)], pos=pos))], pos=pos)]
        if name == "length":
            f = self._fields(call.args[0])[0] if call.args else self.c.error("length() needs a field", t)
            as_ = call.kwargs.get("as")
            out = self._fields(as_)[0] if as_ is not None else "_length"
            return [ir.Extend([(out, ir.Call("strlen", [ir.Field(f, pos=pos)], pos=pos))], pos=pos)]
        if name == "top":
            fields = self._fields(call.args[0]) if call.args else self.c.error("top() needs a field", t)
            n = self._int_kw(call, "limit", 10)
            return [ir.Aggregate([("_count", ir.Call("count", [], pos=pos))], [(f, ir.Field(f, pos=pos)) for f in fields],
                                 pos=pos), ir.Top(n, ir.Field("_count", pos=pos), True, pos=pos)]
        if name in ("bucket", "timechart"):
            span = self._span(call)
            by = [("_bucket", ir.Call("bin", [ir.Field("@timestamp", pos=pos), ir.Lit(span, "timespan", pos=pos)],
                                      pos=pos))]
            series = call.kwargs.get("series") or call.kwargs.get("field")
            if series is not None:
                by += [(f, ir.Field(f, pos=pos)) for f in self._fields(series)]
            return [ir.Aggregate(self._aggs(call.kwargs.get("function")), by, pos=pos),
                    ir.Sort([(ir.Field("_bucket", pos=pos), False)], pos=pos)]
        if name == "filter":
            if len(call.args) != 1:
                self.c.error("filter() takes one expression", t)
            return [ir.Where(call.args[0], pos=pos)]
        if name == "eval":
            if call.args or not call.kwargs:
                self.c.error("eval() takes name = expression", t)
            return [ir.Extend(list(call.kwargs.items()), pos=pos)]
        self.c.error(f"unsupported function {name}()", t)


def _num(v: ir.Lit) -> ir.Lit:
    try:
        return ir.Lit(int(v.value), pos=v.pos)
    except (TypeError, ValueError):
        try:
            return ir.Lit(float(v.value), pos=v.pos)
        except (TypeError, ValueError):
            return v


def parse(text: str) -> ir.Plan:
    return HqlParser(text).parse()
