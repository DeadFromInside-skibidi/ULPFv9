"""
Logical plan -> one DuckDB SQL statement over a table named ``events``.

Each stage is a CTE. While rows still have the source's shape ("star"), field names resolve
through the source's ``Resolver`` (columns, then event JSON); after ``project`` / ``summarize``
only the named columns exist. Sort order survives later stages as a hidden ``__ord`` column.
Types steer casts: JSON text used as a number is ``TRY_CAST`` to DOUBLE, text compared with a
time is cast to TIMESTAMPTZ. Every literal is escaped; regular expressions run in RE2 (linear
time). Semantic errors carry the query position (line / column).
"""
from __future__ import annotations

import re

from ulpf.query import ir
from ulpf.query.lexer import QuerySyntaxError
from ulpf.query.resolve import Resolver, canonical, qident, qstr

NUMERIC = ("int", "float")
_RE2_META = set("\\.+*?()|[]{}^$")


def re2_escape(s: str) -> str:
    return "".join("\\" + c if c in _RE2_META else c for c in s)


def glob_regex(pattern: str, ci: bool) -> str:
    body = "".join(".*" if c == "*" else re2_escape(c) for c in pattern)
    return ("(?is)" if ci else "(?s)") + body


class Ctx:
    """What a CTE's rows contain."""

    def __init__(self, star: bool, cols: dict, hidden: frozenset = frozenset(), ordered: bool = False):
        self.star = star
        self.cols = dict(cols)            # name -> type (explicit columns, in order)
        self.hidden = hidden              # source fields removed with project-away
        self.ordered = ordered            # has __ord


class Gen:
    def __init__(self, resolver: Resolver, lookups: dict | None = None, strict: bool = False):
        self.r = resolver
        self.lookups = lookups or {}      # name -> [column names]
        self.strict = strict              # unknown fields are errors (KQL) instead of null
        self.ctes: list[tuple[str, str]] = []
        self.n = 0
        self.text = ""

    # ---------------------------------------------------------------- helpers
    def err(self, msg: str, node) -> None:
        raise QuerySyntaxError(msg, self.text, getattr(node, "pos", 0))

    def cte(self, sql: str) -> str:
        self.n += 1
        name = f"s{self.n}"
        self.ctes.append((name, sql))
        return name

    def field(self, name: str, ctx: Ctx, node=None) -> tuple[str, str]:
        if name in ctx.cols:
            return qident(name), ctx.cols[name]
        c = canonical(name)
        for k, t in ctx.cols.items():                # a renamed / projected alias of the same field
            if canonical(k) == c:
                return qident(k), t
        if ctx.star and name not in ctx.hidden:
            return self.r.resolve(name)
        if self.strict:
            self.err(f"unknown column {name!r}", node)
        return "NULL", "any"

    # ---------------------------------------------------------------- entry
    def compile(self, plan: ir.Plan, max_rows: int | None = None) -> str:
        self.text = plan.text
        src, ctx = self.pipeline(plan)
        cols, order = self.output_cols(ctx, src)
        sql = f"SELECT {cols} FROM {src}{order}"
        if max_rows is not None:
            sql += f" LIMIT {int(max_rows)}"
        with_ = ",\n".join(f"{n} AS ({q})" for n, q in self.ctes)
        return (f"WITH {with_}\n" if with_ else "") + sql

    def output_cols(self, ctx: Ctx, src: str) -> tuple[str, str]:
        parts = []
        if ctx.star:
            seen = set()
            for out, canon in self.r.display:
                if out in ctx.hidden or canon in ctx.hidden or any(canonical(k) == canon for k in ctx.cols):
                    continue
                parts.append(f"{self.r.resolve(canon)[0]} AS {qident(out)}")
                seen.add(out)
        parts += [qident(k) for k in ctx.cols]
        order = " ORDER BY __ord" if ctx.ordered else \
            (f" ORDER BY {self.r.time()[0]} DESC NULLS LAST" if ctx.star else "")
        return ", ".join(parts) or "*", order

    def pipeline(self, plan: ir.Plan) -> tuple[str, Ctx]:
        if plan.source.lower() not in ("events", "*", "main") and plan.source not in self.lookups \
                and not _is_events_alias(plan.source):
            raise QuerySyntaxError(f"unknown table {plan.source!r} (events, or a lookup: "
                                   f"{', '.join(sorted(self.lookups)) or 'none'})", plan.text, 0)
        if plan.source in self.lookups:
            src = self.cte(f"SELECT * FROM {qident('lookup_' + plan.source)}")
            ctx = Ctx(False, {c: "str" for c in self.lookups[plan.source]})
        else:
            src = "events"
            ctx = Ctx(True, {})
        for st in plan.stages:
            src, ctx = getattr(self, "st_" + type(st).__name__.lower())(st, src, ctx)
        return src, ctx

    # ---------------------------------------------------------------- stages
    def _keep_ord(self, ctx: Ctx) -> str:
        return ", __ord" if ctx.ordered else ""

    def st_where(self, st: ir.Where, src, ctx):
        cond, _ = self.expr(st.cond, ctx)
        return self.cte(f"SELECT * FROM {src} WHERE {cond}"), ctx

    def _assign(self, name: str, sql: str, typ: str, src: str, ctx: Ctx):
        cols = dict(ctx.cols)
        if ctx.star:
            if name in cols or name in self.r.physical:
                q = f"SELECT * REPLACE ({sql} AS {qident(name)}) FROM {src}"
            else:
                q = f"SELECT *, {sql} AS {qident(name)} FROM {src}"
        else:
            sel = [f"{sql} AS {qident(name)}" if k == name else qident(k) for k in cols]
            if name not in cols:
                sel.append(f"{sql} AS {qident(name)}")
            q = f"SELECT {', '.join(sel)}{self._keep_ord(ctx)} FROM {src}"
        cols[name] = typ
        return self.cte(q), Ctx(ctx.star, cols, ctx.hidden - {name}, ctx.ordered)

    def st_extend(self, st: ir.Extend, src, ctx):
        for name, e in st.items:
            sql, typ = self.expr(e, ctx)
            src, ctx = self._assign(name, sql, typ, src, ctx)
        return src, ctx

    def st_project(self, st: ir.Project, src, ctx):
        sel, cols = [], {}
        for name, e in st.items:
            sql, typ = self.expr(e, ctx)
            if name in cols:
                self.err(f"duplicate column {name!r}", e)
            sel.append(f"{sql} AS {qident(name)}")
            cols[name] = typ
        return self.cte(f"SELECT {', '.join(sel)}{self._keep_ord(ctx)} FROM {src}"), Ctx(False, cols, ordered=ctx.ordered)

    def st_projectaway(self, st: ir.ProjectAway, src, ctx):
        cols = {k: t for k, t in ctx.cols.items() if k not in st.names}
        if ctx.star:
            hidden = set(ctx.hidden) | {canonical(n) for n in st.names} | set(st.names)
            gone = [n for n in st.names if n in ctx.cols]
            q = f"SELECT * EXCLUDE ({', '.join(qident(n) for n in gone)}) FROM {src}" if gone else None
            return (self.cte(q) if q else src), Ctx(True, cols, frozenset(hidden), ctx.ordered)
        if len(cols) == len(ctx.cols):
            return src, ctx
        return self.cte(f"SELECT {', '.join(qident(k) for k in cols)}{self._keep_ord(ctx)} FROM {src}"), \
            Ctx(False, cols, ordered=ctx.ordered)

    def st_rename(self, st: ir.Rename, src, ctx):
        for old, new in st.pairs:
            sql, typ = self.field(old, ctx, st)
            if ctx.star:
                src, ctx = self._assign(new, sql, typ, src, ctx)
                if old in ctx.cols:
                    cols = {k: t for k, t in ctx.cols.items() if k != old}
                    src = self.cte(f"SELECT * EXCLUDE ({qident(old)}) FROM {src}")
                    ctx = Ctx(True, cols, ctx.hidden | {canonical(old), old}, ctx.ordered)
                else:
                    ctx = Ctx(True, ctx.cols, ctx.hidden | {canonical(old), old}, ctx.ordered)
            else:
                cols = {}
                sel = []
                for k, t in ctx.cols.items():
                    if k == old:
                        sel.append(f"{qident(k)} AS {qident(new)}")
                        cols[new] = t
                    else:
                        sel.append(qident(k))
                        cols[k] = t
                if old not in ctx.cols:
                    sel.append(f"NULL AS {qident(new)}")
                    cols[new] = "any"
                src = self.cte(f"SELECT {', '.join(sel)}{self._keep_ord(ctx)} FROM {src}")
                ctx = Ctx(False, cols, ordered=ctx.ordered)
        return src, ctx

    def st_aggregate(self, st: ir.Aggregate, src, ctx):
        sel, cols, groups = [], {}, []
        for name, e in st.by:
            sql, typ = self.expr(e, ctx)
            sel.append(f"{sql} AS {qident(name)}")
            groups.append(sql)
            cols[name] = typ
        for name, call in st.aggs:
            sql, typ = self.agg(call, ctx)
            if name in cols:
                self.err(f"duplicate column {name!r}", call)
            sel.append(f"{sql} AS {qident(name)}")
            cols[name] = typ
        q = f"SELECT {', '.join(sel)} FROM {src}"
        if groups:
            q += " GROUP BY " + ", ".join(groups)
        return self.cte(q), Ctx(False, cols)

    def _order_by(self, keys, ctx) -> str:
        parts = []
        for e, desc in keys:
            sql, _ = self.expr(e, ctx)
            parts.append(f"{sql} {'DESC' if desc else 'ASC'} NULLS LAST")
        return ", ".join(parts)

    def st_sort(self, st: ir.Sort, src, ctx):
        ob = self._order_by(st.keys, ctx)
        star = "* EXCLUDE (__ord)" if ctx.ordered else "*"
        return self.cte(f"SELECT {star}, row_number() OVER (ORDER BY {ob}) AS __ord FROM {src}"), \
            Ctx(ctx.star, ctx.cols, ctx.hidden, True)

    def st_top(self, st: ir.Top, src, ctx):
        src, ctx = self.st_sort(ir.Sort([(st.key, st.desc)], pos=st.pos), src, ctx)
        return self.cte(f"SELECT * FROM {src} WHERE __ord <= {int(st.n)}"), ctx

    def st_limit(self, st: ir.Limit, src, ctx):
        if st.tail:
            if not ctx.ordered and ctx.star:            # tail of the time-ordered events
                src, ctx = self.st_sort(ir.Sort([(ir.Field("timestamp"), False)], pos=st.pos), src, ctx)
            if ctx.ordered:
                return self.cte(f"SELECT * FROM {src} QUALIFY row_number() OVER (ORDER BY __ord DESC) <= "
                                f"{int(st.n)}"), ctx
        order = " ORDER BY __ord" if ctx.ordered else ""
        return self.cte(f"SELECT * FROM {src}{order} LIMIT {int(st.n)}"), ctx

    def st_distinct(self, st: ir.Distinct, src, ctx):
        sel, cols = [], {}
        for n in st.names:
            sql, typ = self.field(n, ctx, st)
            sel.append(f"{sql} AS {qident(n)}")
            cols[n] = typ
        return self.cte(f"SELECT DISTINCT {', '.join(sel)} FROM {src}"), Ctx(False, cols)

    def st_dedup(self, st: ir.Dedup, src, ctx):
        keys = ", ".join(self.field(n, ctx, st)[0] for n in st.names)
        order = "__ord" if ctx.ordered else (f"{self.r.time()[0]} DESC" if ctx.star else "1")
        return self.cte(f"SELECT * FROM {src} QUALIFY row_number() OVER (PARTITION BY {keys} ORDER BY {order}) "
                        f"<= {int(st.keep)}"), ctx

    def st_rex(self, st: ir.Rex, src, ctx):
        text, _ = self.expr(st.source, ctx)
        text = f"CAST({text} AS VARCHAR)"
        try:
            index = re.compile(st.pattern).groupindex
        except re.error as e:
            self.err(f"invalid regular expression: {e}", st)
        pat = qstr(st.pattern)
        if st.filter:
            src = self.cte(f"SELECT * FROM {src} WHERE regexp_matches({text}, {pat})")
        for name in st.names:
            sql = f"CASE WHEN regexp_matches({text}, {pat}) THEN regexp_extract({text}, {pat}, {index[name]}) END"
            src, ctx = self._assign(name, sql, "str", src, ctx)
        return src, ctx

    def st_mvexpand(self, st: ir.MvExpand, src, ctx):
        sql, typ = self.expr(st.expr or ir.Field(st.name), ctx)
        lst = sql if typ == "list" else f"TRY_CAST(json({sql}) AS VARCHAR[])"
        if ctx.star:
            if st.name in ctx.cols or st.name in self.r.physical:
                q = f"SELECT * REPLACE (unnest({lst}) AS {qident(st.name)}) FROM {src}"
            else:
                q = f"SELECT *, unnest({lst}) AS {qident(st.name)} FROM {src}"
        else:
            sel = [f"unnest({lst}) AS {qident(k)}" if k == st.name else qident(k) for k in ctx.cols]
            if st.name not in ctx.cols:
                sel.append(f"unnest({lst}) AS {qident(st.name)}")
            q = f"SELECT {', '.join(sel)} FROM {src}"
        cols = dict(ctx.cols)
        cols[st.name] = "any"
        return self.cte(q), Ctx(ctx.star, cols, ctx.hidden)

    def _materialise_keys(self, src, ctx, names, prefix, node):
        exprs = [f"{self.field(n, ctx, node)[0]} AS __{prefix}{i}" for i, n in enumerate(names)]
        return self.cte(f"SELECT *, {', '.join(exprs)} FROM {src}")

    def _explicit(self, src, ctx):
        """Rows with named columns only (the right side of a join)."""
        if not ctx.star:
            return src, ctx
        cols, sel = {}, []
        for out, canon in self.r.display:
            sql, typ = self.r.resolve(canon)
            sel.append(f"{sql} AS {qident(out)}")
            cols[out] = typ
        for k, t in ctx.cols.items():
            if k not in cols:
                sel.append(qident(k))
                cols[k] = t
        return self.cte(f"SELECT {', '.join(sel)} FROM {src}"), Ctx(False, cols)

    def st_join(self, st: ir.Join, src, ctx):
        right_gen = Gen(self.r, self.lookups, self.strict)
        right_gen.text, right_gen.n = self.text, self.n + 1000
        rsrc, rctx = right_gen.pipeline(st.right)
        rsrc, rctx = right_gen._explicit(rsrc, rctx)
        rk = right_gen._materialise_keys(rsrc, rctx, [r for _, r in st.keys], "rk", st)
        self.ctes += right_gen.ctes
        self.n = right_gen.n
        kind = st.kind
        if kind in ("rightanti", "rightsemi"):
            self.err(f"join kind={kind} is not supported (swap the sides and use left{kind[5:]})", st)
        if kind == "innerunique":          # Kusto: one left row per key, then an inner join
            keys = ", ".join(self.field(l, ctx, st)[0] for l, _ in st.keys)
            src = self.cte(f"SELECT * FROM {src} QUALIFY row_number() OVER (PARTITION BY {keys}) = 1")
            kind = "inner"
        lk = self._materialise_keys(src, ctx, [l for l, _ in st.keys], "lk", st)
        on = " AND ".join(f"l.__lk{i} = r.__rk{i}" for i in range(len(st.keys)))
        lex = ", ".join(f"__lk{i}" for i in range(len(st.keys)))
        if kind in ("leftanti", "leftsemi"):
            q = f"SELECT l.* EXCLUDE ({lex}) FROM {lk} l {'ANTI' if kind == 'leftanti' else 'SEMI'} JOIN {rk} r ON {on}"
            return self.cte(q), Ctx(ctx.star, ctx.cols, ctx.hidden)
        join = {"inner": "JOIN", "leftouter": "LEFT JOIN", "rightouter": "RIGHT JOIN", "fullouter": "FULL JOIN"}[kind]
        left_names = set(ctx.cols) | ({out for out, _ in self.r.display} if ctx.star else set())
        cols = dict(ctx.cols)
        sel = [f"l.* EXCLUDE ({lex})"]
        right_keys = {r for _, r in st.keys}
        for k, t in rctx.cols.items():
            if k in right_keys and k in left_names:
                continue                    # the join key: one copy (Kusto adds key1 only when names differ)
            out = k
            while out in left_names or out in cols:
                out = out + "1"
            sel.append(f"r.{qident(k)} AS {qident(out)}")
            cols[out] = t
        q = f"SELECT {', '.join(sel)} FROM {lk} l {join} {rk} r ON {on}"
        return self.cte(q), Ctx(ctx.star, cols, ctx.hidden)

    def st_makeseries(self, st: ir.MakeSeries, src, ctx):
        on, on_t = self.expr(st.on, ctx)
        if on_t not in ("ts", "json", "str", "any"):
            self.err("make-series needs a time column after 'on'", st.on)
        on = on if on_t == "ts" else f"TRY_CAST({on} AS TIMESTAMPTZ)"
        step = f"INTERVAL '{int(st.step * 1_000_000)} microseconds'"
        start = self.expr(st.start, ctx)[0] if st.start is not None else f"(SELECT min({on}) FROM {src})"
        end = self.expr(st.end, ctx)[0] if st.end is not None else f"(SELECT max({on}) FROM {src})"
        by = [(n, self.expr(e, ctx)) for n, e in st.by]
        bsel = [f"{sql} AS {qident(n)}" for n, (sql, _) in by]
        bnames = [qident(n) for n, _ in by]
        sel = bsel + [f"time_bucket({step}, {on}, CAST(({start}) AS TIMESTAMPTZ)) AS __t"]
        sel += [f"{self.agg(c, ctx)[0]} AS {qident(n)}" for n, c in st.aggs]
        base = self.cte(f"SELECT {', '.join(sel)} FROM {src} WHERE {on} >= ({start}) AND {on} < ({end}) GROUP BY ALL")
        grid = self.cte(f"SELECT unnest(generate_series(time_bucket({step}, CAST(({start}) AS TIMESTAMPTZ), "
                        f"CAST(({start}) AS TIMESTAMPTZ)), CAST(({end}) AS TIMESTAMPTZ) - INTERVAL '1 microsecond', "
                        f"{step})) AS __t")
        keys = self.cte(f"SELECT DISTINCT {', '.join(bnames)} FROM {base}") if by else None
        cross = f"{keys} k CROSS JOIN {grid} g" if keys else f"{grid} g"
        using = " AND ".join([f"a.{b} IS NOT DISTINCT FROM k.{b}" for b in bnames] + ["a.__t = g.__t"])
        d = _lit_sql(st.default)
        aggs = ", ".join(f"list(COALESCE(a.{qident(n)}, {d}) ORDER BY g.__t) AS {qident(n)}" for n, _ in st.aggs)
        time_name = st.on.name if isinstance(st.on, ir.Field) else "timestamp"
        ksel = ", ".join(f"k.{b}" for b in bnames)
        q = (f"SELECT {ksel + ', ' if ksel else ''}{aggs}, list(g.__t ORDER BY g.__t) AS {qident(time_name)} "
             f"FROM {cross} LEFT JOIN {base} a ON {using}" + (f" GROUP BY {ksel}" if ksel else ""))
        cols = {n: t for n, (_, t) in by}
        cols.update({n: "list" for n, _ in st.aggs})
        cols[time_name] = "list"
        return self.cte(q), Ctx(False, cols)

    def st_lookup(self, st: ir.Lookup, src, ctx):
        if st.table not in self.lookups:
            self.err(f"unknown lookup table {st.table!r} (available: {', '.join(sorted(self.lookups)) or 'none'})", st)
        lcols = self.lookups[st.table]
        for _, col in st.keys:
            if col not in lcols:
                self.err(f"lookup {st.table!r} has no column {col!r}", st)
        outs = st.outputs or [(c, c) for c in lcols if c not in {k for _, k in st.keys}]
        for col, _ in outs:
            if col not in lcols:
                self.err(f"lookup {st.table!r} has no column {col!r}", st)
        lk = self._materialise_keys(src, ctx, [local for local, _ in st.keys], "lk", st)
        tab = qident("lookup_" + st.table)
        keycols = ", ".join(qident(c) for _, c in st.keys)
        dedup = self.cte(f"SELECT * FROM {tab} QUALIFY row_number() OVER (PARTITION BY {keycols}) = 1")
        on = " AND ".join(f"CAST(l.__lk{i} AS VARCHAR) = CAST(r.{qident(c)} AS VARCHAR)"
                          for i, (_, c) in enumerate(st.keys))
        lex = ", ".join(f"__lk{i}" for i in range(len(st.keys)))
        cols = dict(ctx.cols)
        sel = [f"l.* EXCLUDE ({lex})"]
        for col, out in outs:
            if out in cols or (ctx.star and out in self.r.physical):
                self.err(f"lookup output {out!r} already exists: rename it with AS", st)
            sel.append(f"r.{qident(col)} AS {qident(out)}")
            cols[out] = "str"
        return self.cte(f"SELECT {', '.join(sel)} FROM {lk} l LEFT JOIN {dedup} r ON {on}"), \
            Ctx(ctx.star, cols, ctx.hidden, ctx.ordered)

    # ---------------------------------------------------------------- expressions
    def expr(self, e, ctx) -> tuple[str, str]:
        m = getattr(self, "ex_" + type(e).__name__.lower(), None)
        if m is None:
            self.err("unsupported expression", e)
        return m(e, ctx)

    def ex_field(self, e: ir.Field, ctx):
        return self.field(e.name, ctx, e)

    def ex_lit(self, e: ir.Lit, ctx):
        if e.kind == "timespan":
            return f"INTERVAL '{int(round(e.value * 1_000_000))} microseconds'", "span"
        if e.kind == "datetime":
            return _ts_lit(e.value), "ts"
        if e.kind in ("regex", "glob"):
            self.err("a regular expression is not a value here", e)
        return _lit_sql(e.value), _lit_type(e.value)

    def ex_unary(self, e: ir.Unary, ctx):
        sql, typ = self.expr(e.arg, ctx)
        if e.op == "not":
            return f"(NOT COALESCE(({sql}), FALSE))", "bool"
        return f"(-{self.num(sql, typ)})", typ if typ in NUMERIC else "float"

    def num(self, sql, typ):
        return sql if typ in NUMERIC or typ in ("span", "ts") else f"TRY_CAST({sql} AS DOUBLE)"

    def text_(self, sql, typ):
        return sql if typ == "str" else f"CAST({sql} AS VARCHAR)"

    def _coerce(self, a, b):
        (sa, ta), (sb, tb) = a, b
        if ta in NUMERIC and tb in ("json", "str", "any"):
            sb = f"TRY_CAST({sb} AS DOUBLE)"
        elif tb in NUMERIC and ta in ("json", "str", "any"):
            sa = f"TRY_CAST({sa} AS DOUBLE)"
        elif ta == "ts" and tb in ("json", "str"):
            sb = f"TRY_CAST({sb} AS TIMESTAMPTZ)" if not sb.startswith("'") else _ts_lit_sql(sb)
        elif tb == "ts" and ta in ("json", "str"):
            sa = f"TRY_CAST({sa} AS TIMESTAMPTZ)" if not sa.startswith("'") else _ts_lit_sql(sa)
        elif ta == "bool" and tb in ("json", "str"):
            sb = f"TRY_CAST({sb} AS BOOLEAN)"
        return sa, sb

    def ex_binary(self, e: ir.Binary, ctx):
        op = e.op
        if op in ("and", "or"):
            a, _ = self.expr(e.left, ctx)
            b, _ = self.expr(e.right, ctx)
            return f"(COALESCE(({a}), FALSE) {op.upper()} COALESCE(({b}), FALSE))", "bool"
        if op == "glob":
            sa, ta = self.expr(e.left, ctx)
            flags, pat = e.right.value
            return f"COALESCE(regexp_full_match({self.text_(sa, ta)}, {qstr(glob_regex(pat, 'i' in flags))}), FALSE)", "bool"
        if op in ("regex", "nregex"):
            sa, ta = self.expr(e.left, ctx)
            if not isinstance(e.right, ir.Lit) or not isinstance(e.right.value, str):
                self.err("matches regex needs a string pattern", e.right)
            pat = e.right.value
            try:
                re.compile(pat.replace("(?P<", "(?P<").replace("(?i)", ""))
            except re.error as x:
                self.err(f"invalid regular expression: {x}", e.right)
            m = f"COALESCE(regexp_matches({self.text_(sa, ta)}, {qstr(pat)}), FALSE)"
            return (m if op == "regex" else f"(NOT {m})"), "bool"
        a = self.expr(e.left, ctx)
        b = self.expr(e.right, ctx)
        if op in ("+", "-", "*", "/", "%"):
            (sa, ta), (sb, tb) = a, b
            if ta == "ts" or tb == "ts" or ta == "span" or tb == "span":
                rt = "span" if ta == tb == "ts" and op == "-" else ("ts" if "ts" in (ta, tb) else "span")
                return f"({sa} {op} {sb})", rt
            if op == "+" and (ta == "str" or tb == "str") and e.left.__class__ is ir.Lit and isinstance(
                    getattr(e.left, "value", None), str):
                return f"(CAST({sa} AS VARCHAR) || CAST({sb} AS VARCHAR))", "str"
            sa, sb = self.num(sa, ta), self.num(sb, tb)
            if op == "/":
                return f"(CAST({sa} AS DOUBLE) / NULLIF({sb}, 0))", "float"
            rt = "int" if ta == tb == "int" else "float"
            return f"({sa} {op} {sb})", rt
        if op == "concat":
            return f"(COALESCE(CAST({a[0]} AS VARCHAR), '') || COALESCE(CAST({b[0]} AS VARCHAR), ''))", "str"
        if op in ("==", "!=", "<", "<=", ">", ">="):
            sa, sb = self._coerce(a, b)
            sqlop = {"==": "=", "!=": "<>"}.get(op, op)
            return f"({sa} {sqlop} {sb})", "bool"
        sa, sb = self.text_(*a), self.text_(*b)
        neg = op.startswith("n") and op[1:] in _STR_OPS
        base = op[1:] if neg else op
        if op in ("ieq", "ine"):
            r = f"(lower({sa}) = lower({sb}))"
            return (r if op == "ieq" else f"(NOT COALESCE({r}, FALSE))"), "bool"
        if base not in _STR_OPS:
            self.err(f"unsupported operator {op!r}", e)
        r = _STR_OPS[base](sa, sb, e.right)
        r = f"COALESCE({r}, FALSE)"
        return (f"(NOT {r})" if neg else r), "bool"

    def ex_inlist(self, e: ir.InList, ctx):
        sa, ta = self.expr(e.arg, ctx)
        items = [self.expr(x, ctx) for x in e.items]
        if any(t in NUMERIC for _, t in items) and ta in ("json", "str", "any"):
            sa = f"TRY_CAST({sa} AS DOUBLE)"
        if e.ci:
            sa = f"lower(CAST({sa} AS VARCHAR))"
            vals = ", ".join(f"lower(CAST({s} AS VARCHAR))" for s, _ in items)
        else:
            vals = ", ".join(s for s, _ in items)
        r = f"COALESCE(({sa} IN ({vals})), FALSE)" if items else "FALSE"
        return (f"(NOT {r})" if e.negate else r), "bool"

    def ex_between(self, e: ir.Between, ctx):
        a = self.expr(e.arg, ctx)
        lo, hi = self.expr(e.lo, ctx), self.expr(e.hi, ctx)
        sa, slo = self._coerce(a, lo)
        _, shi = self._coerce(a, hi)
        r = f"COALESCE(({sa} BETWEEN {slo} AND {shi}), FALSE)"
        return (f"(NOT {r})" if e.negate else r), "bool"

    def ex_call(self, e: ir.Call, ctx):
        if ir.is_aggregate(e):
            self.err(f"{e.name}() is an aggregation: use it in summarize / stats / groupBy", e)
        fn = _SCALARS.get(e.name)
        if fn is None:
            self.err(f"unknown function {e.name}()", e)
        args = [self.expr(a, ctx) for a in e.args]
        return fn(self, e, args, ctx)

    # ---------------------------------------------------------------- aggregates
    def agg(self, e: ir.Call, ctx) -> tuple[str, str]:
        name = e.name
        args = [self.expr(a, ctx) for a in e.args if not (isinstance(a, ir.Lit) and a.value == "*")]
        need = {"count": (0, 1), "countif": (1, 1), "dcount": (1, 2), "dc": (1, 1), "distinct_count": (1, 1),
                "percentile": (2, 2), "sumif": (2, 2), "avgif": (2, 2)}.get(name, (1, 1))
        if not need[0] <= len(args) <= need[1]:
            self.err(f"{name}() takes {need[0]}" + (f" to {need[1]}" if need[1] != need[0] else "") + " argument(s)", e)
        a = args[0] if args else None
        num = (lambda x: self.num(*x))
        if name == "count":
            return ("count(*)" if a is None else f"count({a[0]})"), "int"
        if name == "countif":
            return f"count_if(COALESCE({a[0]}, FALSE))", "int"
        if name in ("dcount", "dc", "distinct_count"):
            return f"count(DISTINCT {a[0]})", "int"
        if name == "sum":
            return f"sum({num(a)})", "float" if a[1] not in ("int",) else "int"
        if name in ("avg", "mean"):
            return f"avg({num(a)})", "float"
        if name in ("min", "max"):
            v = a[0] if a[1] in ("ts", "int", "float", "str") else num(a)
            return f"{name}({v})", a[1] if a[1] in ("ts", "int", "float", "str") else "float"
        if name in ("make_set", "values"):
            return (f"list_sort(list(DISTINCT {a[0]}))" if name == "values" else f"list(DISTINCT {a[0]})"), "list"
        if name in ("make_list", "list"):
            return f"list({a[0]})", "list"
        if name == "percentile":
            p = e.args[1]
            if not (isinstance(p, ir.Lit) and isinstance(p.value, (int, float))):
                self.err("percentile() needs a number for the percentile", p)
            return f"quantile_cont({num(a)}, {float(p.value) / 100})", "float"
        if name == "median":
            return f"median({num(a)})", "float"
        if name == "stdev":
            return f"stddev_samp({num(a)})", "float"
        if name == "variance":
            return f"var_samp({num(a)})", "float"
        if name in ("any", "take_any"):
            return f"any_value({a[0]})", a[1]
        if name in ("earliest", "first"):
            return f"arg_min({a[0]}, {self.r.time()[0]})", a[1]
        if name in ("latest", "last"):
            return f"arg_max({a[0]}, {self.r.time()[0]})", a[1]
        if name == "sumif":
            return f"sum({num(a)}) FILTER (WHERE COALESCE({args[1][0]}, FALSE))", "float"
        if name == "avgif":
            return f"avg({num(a)}) FILTER (WHERE COALESCE({args[1][0]}, FALSE))", "float"
        if name == "range":
            return f"(max({num(a)}) - min({num(a)}))", "float"
        self.err(f"unsupported aggregation {name}()", e)


def _is_events_alias(name: str) -> bool:
    return name.lower() in ("securityevent", "commonsecuritylog", "syslog", "events", "logs", "signinlogs",
                            "devicenetworkevents", "deviceprocessevents", "deviceevents", "auditlogs",
                            "ulpf", "main", "index")


def _lit_type(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    return "str"


def _lit_sql(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v) if v == v and v not in (float("inf"), float("-inf")) else "NULL"
    return qstr(v)


def parse_datetime(text: str):
    """A datetime literal (ISO-8601 forms; no zone means UTC), or None."""
    import datetime as _dt
    t = text.strip().replace("Z", "+00:00").replace("z", "+00:00")
    try:
        v = _dt.datetime.fromisoformat(t)
    except ValueError:
        return None
    return v if v.tzinfo else v.replace(tzinfo=_dt.timezone.utc)


def _ts_lit(text: str) -> str:
    v = parse_datetime(text)
    if v is None:
        return f"TRY_CAST({qstr(text)} AS TIMESTAMPTZ)"
    return f"TIMESTAMPTZ {qstr(v.isoformat(sep=' '))}"


def _ts_lit_sql(sql_literal: str) -> str:
    return _ts_lit(sql_literal[1:-1].replace("''", "'"))


def _like_has(a, b, node):
    if isinstance(node, ir.Lit) and isinstance(node.value, str):
        term = re2_escape(node.value)
        return f"regexp_matches({a}, {qstr('(?i)(^|[^[:alnum:]_])' + term + '($|[^[:alnum:]_])')})"
    return f"regexp_matches({a}, '(?i)(^|[^[:alnum:]_])' || {b} || '($|[^[:alnum:]_])')"


def _like_has_cs(a, b, node):
    if isinstance(node, ir.Lit) and isinstance(node.value, str):
        term = re2_escape(node.value)
        return f"regexp_matches({a}, {qstr('(^|[^[:alnum:]_])' + term + '($|[^[:alnum:]_])')})"
    return f"regexp_matches({a}, '(^|[^[:alnum:]_])' || {b} || '($|[^[:alnum:]_])')"


_STR_OPS = {
    "contains": lambda a, b, n: f"contains(lower({a}), lower({b}))",
    "contains_cs": lambda a, b, n: f"contains({a}, {b})",
    "has": _like_has, "has_cs": _like_has_cs,
    "startswith": lambda a, b, n: f"starts_with(lower({a}), lower({b}))",
    "startswith_cs": lambda a, b, n: f"starts_with({a}, {b})",
    "endswith": lambda a, b, n: f"ends_with(lower({a}), lower({b}))",
    "endswith_cs": lambda a, b, n: f"ends_with({a}, {b})",
    "like": lambda a, b, n: f"({a} LIKE {b})",
}


# ---------------------------------------------------------------- scalar functions
def _n(k):
    def check(g, e, args):
        if len(args) not in k:
            g.err(f"{e.name}() takes {' or '.join(str(x) for x in sorted(k))} argument(s)", e)
    return check


def _fn(arity, build, typ):
    def f(g, e, args, ctx):
        _n(arity)(g, e, args)
        out = build(g, e, args, ctx)
        return out if isinstance(out, tuple) else (out, typ(args) if callable(typ) else typ)
    return f


def _bin(g, e, args, ctx):
    (sa, ta), (sb, tb) = args
    if tb == "span":
        x = sa if ta == "ts" else f"TRY_CAST({sa} AS TIMESTAMPTZ)"
        return f"time_bucket({sb}, {x})", "ts"
    x, y = g.num(sa, ta), g.num(sb, tb)
    return f"(floor({x} / NULLIF({y}, 0)) * {y})", "float" if "float" in (ta, tb) else "int"


def _case(g, e, args, ctx):
    if len(args) < 2:
        g.err("case() needs condition, value pairs", e)
    pairs = args[:len(args) - len(args) % 2]
    parts = " ".join(f"WHEN COALESCE({c}, FALSE) THEN {v}" for (c, _), (v, _) in zip(pairs[::2], pairs[1::2]))
    els = f" ELSE {args[-1][0]}" if len(args) % 2 else ""
    return f"(CASE {parts}{els} END)", args[1][1]


def _substring(zero_based):
    def f(g, e, args, ctx):
        _n({2, 3})(g, e, args)
        s = g.text_(*args[0])
        start = g.num(*args[1])
        start = f"({start}) + 1" if zero_based else start
        if len(args) == 3:
            return f"substr({s}, CAST({start} AS BIGINT), CAST({g.num(*args[2])} AS BIGINT))", "str"
        return f"substr({s}, CAST({start} AS BIGINT))", "str"
    return f


def _extract(g, e, args, ctx):
    _n({2, 3})(g, e, args)
    if len(args) == 2:                              # SPL-ish: extract(text, regex) -> group 1
        text, pat, grp = args[0], args[1], ("1", "int")
    else:                                           # KQL: extract(regex, group, text)
        pat, grp, text = args
    return f"NULLIF(regexp_extract({g.text_(*text)}, {pat[0]}, CAST({grp[0]} AS INTEGER)), '')", "str"


_SCALARS = {
    "ago": _fn({1}, lambda g, e, a, c: f"(now() - {a[0][0]})", "ts"),
    "now": _fn({0}, lambda g, e, a, c: "now()", "ts"),
    "datetime": _fn({1}, lambda g, e, a, c: _ts_lit(e.args[0].value) if isinstance(e.args[0], ir.Lit)
                    else f"TRY_CAST({a[0][0]} AS TIMESTAMPTZ)", "ts"),
    "todatetime": _fn({1}, lambda g, e, a, c: f"TRY_CAST({a[0][0]} AS TIMESTAMPTZ)", "ts"),
    "bin": _fn({2}, _bin, None), "floor": _fn({2}, _bin, None), "bucket": _fn({2}, _bin, None),
    "startofday": _fn({1}, lambda g, e, a, c: f"date_trunc('day', {a[0][0]})", "ts"),
    "startofhour": _fn({1}, lambda g, e, a, c: f"date_trunc('hour', {a[0][0]})", "ts"),
    "tolower": _fn({1}, lambda g, e, a, c: f"lower({g.text_(*a[0])})", "str"),
    "toupper": _fn({1}, lambda g, e, a, c: f"upper({g.text_(*a[0])})", "str"),
    "strlen": _fn({1}, lambda g, e, a, c: f"length({g.text_(*a[0])})", "int"),
    "substring": _substring(True), "substr": _substring(False),
    "strcat": lambda g, e, a, c: (f"concat({', '.join(g.text_(*x) for x in a)})", "str"),
    "iff": _fn({3}, lambda g, e, a, c: f"(CASE WHEN COALESCE({a[0][0]}, FALSE) THEN {a[1][0]} ELSE {a[2][0]} END)",
               lambda a: a[1][1]),
    "case": _case,
    "coalesce": lambda g, e, a, c: (f"COALESCE({', '.join(x for x, _ in a)})", a[0][1] if a else "any"),
    "isnull": _fn({1}, lambda g, e, a, c: f"({a[0][0]} IS NULL)", "bool"),
    "isnotnull": _fn({1}, lambda g, e, a, c: f"({a[0][0]} IS NOT NULL)", "bool"),
    "isempty": _fn({1}, lambda g, e, a, c: f"(COALESCE(CAST({a[0][0]} AS VARCHAR), '') = '')", "bool"),
    "isnotempty": _fn({1}, lambda g, e, a, c: f"(COALESCE(CAST({a[0][0]} AS VARCHAR), '') <> '')", "bool"),
    "tostring": _fn({1}, lambda g, e, a, c: f"CAST({a[0][0]} AS VARCHAR)", "str"),
    "toint": _fn({1}, lambda g, e, a, c: f"TRY_CAST({a[0][0]} AS BIGINT)", "int"),
    "todouble": _fn({1}, lambda g, e, a, c: f"TRY_CAST({a[0][0]} AS DOUBLE)", "float"),
    "tonumber": _fn({1, 2}, lambda g, e, a, c: f"TRY_CAST({a[0][0]} AS DOUBLE)", "float"),
    "extract": _extract,
    "split": _fn({2}, lambda g, e, a, c: f"string_split({g.text_(*a[0])}, {a[1][0]})", "list"),
    "array_length": _fn({1}, lambda g, e, a, c: f"len({a[0][0]})", "int"),
    "round": _fn({1, 2}, lambda g, e, a, c: f"round({g.num(*a[0])}, {a[1][0] if len(a) > 1 else 0})", "float"),
    "abs": _fn({1}, lambda g, e, a, c: f"abs({g.num(*a[0])})", "float"),
    "ceiling": _fn({1}, lambda g, e, a, c: f"ceil({g.num(*a[0])})", "float"),
    "sqrt": _fn({1}, lambda g, e, a, c: f"sqrt({g.num(*a[0])})", "float"),
    "log": _fn({1}, lambda g, e, a, c: f"ln({g.num(*a[0])})", "float"),
    "exp": _fn({1}, lambda g, e, a, c: f"exp({g.num(*a[0])})", "float"),
    "pow": _fn({2}, lambda g, e, a, c: f"pow({g.num(*a[0])}, {g.num(*a[1])})", "float"),
    "replace_string": _fn({3}, lambda g, e, a, c: f"replace({g.text_(*a[0])}, {a[1][0]}, {a[2][0]})", "str"),
    "replace_regex": _fn({3}, lambda g, e, a, c: f"regexp_replace({g.text_(*a[0])}, {a[1][0]}, {a[2][0]}, 'g')", "str"),
    "trim": _fn({1}, lambda g, e, a, c: f"trim({g.text_(*a[0])})", "str"),
    "match": _fn({2}, lambda g, e, a, c: f"COALESCE(regexp_matches({g.text_(*a[0])}, {a[1][0]}), FALSE)", "bool"),
    "like": _fn({2}, lambda g, e, a, c: f"COALESCE({g.text_(*a[0])} LIKE {a[1][0]}, FALSE)", "bool"),
    "strftime": _fn({2}, lambda g, e, a, c: f"strftime({a[0][0]}, {a[1][0]})", "str"),
    "__list": lambda g, e, a, c: (f"[{', '.join(x for x, _ in a)}]", "list"),
}
_SCALARS.update({
    "iif": _SCALARS["iff"], "if": _SCALARS["iff"], "lower": _SCALARS["tolower"], "upper": _SCALARS["toupper"],
    "len": _SCALARS["strlen"], "length": _SCALARS["strlen"], "tolong": _SCALARS["toint"],
    "toreal": _SCALARS["todouble"], "ceil": _SCALARS["ceiling"], "ln": _SCALARS["log"],
    "mvcount": _SCALARS["array_length"], "replace": _SCALARS["replace_regex"],
})


def compile_plan(plan: ir.Plan, resolver: Resolver, lookups: dict | None = None, max_rows: int | None = None) -> str:
    return Gen(resolver, lookups, strict=False).compile(plan, max_rows)
