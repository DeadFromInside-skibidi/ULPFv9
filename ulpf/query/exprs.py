"""
Expression parsing shared by the dialects: precedence climbing over

    or  <  and  <  not  <  comparison / string operators  <  + - (SPL: .)  <  * / %  <  unary -  <  primary

A dialect supplies its comparison operators (``compare``), its boolean words, and how a
primary that is not a literal, field or call is read. Depth is bounded (deeply nested input
is an error, not a stack overflow).
"""
from __future__ import annotations

from ulpf.query import ir
from ulpf.query.lexer import Cursor

MAX_DEPTH = 64             # parenthesis depth (about 9 Python frames per level)


class ExprParser:
    and_words = ("and",)
    or_words = ("or",)
    not_words = ("not",)
    concat_dot = False          # SPL: "a . b" concatenates
    eq_ops = ("==",)            # tokens meaning equality

    def __init__(self, cur: Cursor):
        self.c = cur
        self.depth = 0

    # ---- entry points
    def expr(self) -> ir.Expr:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            self.c.error("expression nested too deeply")
        try:
            return self._or()
        finally:
            self.depth -= 1

    def expr_list(self, close: str = ")") -> list:
        items = []
        if self.c.tok.is_op(close):
            return items
        while True:
            items.append(self.expr())
            if not self.c.accept_op(","):
                return items

    # ---- precedence levels
    def _or(self):
        left = self._and()
        while True:
            t = self.c.tok
            if t.is_word(*self.or_words) or (self.or_words == ("or",) and t.is_op("||")):
                self.c.next()
                left = ir.Binary("or", left, self._and(), pos=t.pos)
            else:
                return left

    def _and(self):
        left = self._not()
        while True:
            t = self.c.tok
            if t.is_word(*self.and_words):
                self.c.next()
                left = ir.Binary("and", left, self._not(), pos=t.pos)
            else:
                return left

    def _not(self):
        t = self.c.tok
        if t.is_word(*self.not_words) and not self.c.peek().is_op("("):
            self.c.next()
            return ir.Unary("not", self._not(), pos=t.pos)
        return self._compare()

    def _compare(self):
        left = self._additive()
        while True:
            t = self.c.tok
            r = self.compare(left)
            if r is None:
                return left
            left = r
            if t is self.c.tok:            # defensive: an operator must consume tokens
                self.c.error("internal parser error")

    def compare(self, left):
        """Dialect hook: parse one comparison with ``left`` already read, or None."""
        c = self.c
        t = c.tok
        for op, name in (("==", "=="), ("!=", "!="), ("<>", "!="), ("<=", "<="), (">=", ">="), ("<", "<"), (">", ">")):
            if t.is_op(op) or (op == "==" and t.value in self.eq_ops and t.kind == "op"):
                c.next()
                return ir.Binary(name, left, self._additive(), pos=t.pos)
        return None

    def _additive(self):
        left = self._mult()
        while True:
            t = self.c.tok
            if t.is_op("+", "-") or (self.concat_dot and t.is_op(".")):
                self.c.next()
                op = "concat" if t.value == "." else t.value
                left = ir.Binary(op, left, self._mult(), pos=t.pos)
            else:
                return left

    def _mult(self):
        left = self._unary()
        while True:
            t = self.c.tok
            if t.is_op("*", "/", "%"):
                self.c.next()
                left = ir.Binary(t.value, left, self._unary(), pos=t.pos)
            else:
                return left

    def _unary(self):
        t = self.c.tok
        if t.is_op("-"):
            self.c.next()
            arg = self._unary()
            if isinstance(arg, ir.Lit) and isinstance(arg.value, (int, float)) and not isinstance(arg.value, bool):
                return ir.Lit(-arg.value, arg.kind, pos=t.pos)
            return ir.Unary("-", arg, pos=t.pos)
        if t.is_op("!") and not self.c.peek().kind == "ident":
            self.c.next()
            return ir.Unary("not", self._unary(), pos=t.pos)
        return self.primary()

    # ---- primaries
    def primary(self):
        c = self.c
        t = c.tok
        if t.kind == "number":
            c.next()
            return ir.Lit(t.value, pos=t.pos)
        if t.kind in ("string", "word"):
            c.next()
            return ir.Lit(t.value, pos=t.pos)
        if t.kind == "timespan":
            c.next()
            return ir.Lit(t.value, "timespan", pos=t.pos)
        if t.kind == "regex":
            c.next()
            return ir.Lit(t.value, "regex", pos=t.pos)
        if t.is_op("("):
            c.next()
            e = self.expr()
            c.expect_op(")")
            return e
        if t.is_word("true", "false") and not c.peek().is_op("("):
            c.next()
            return ir.Lit(str(t.value).lower() == "true", pos=t.pos)
        if t.is_word("null") and not c.peek().is_op("("):
            c.next()
            return ir.Lit(None, pos=t.pos)
        if t.kind == "ident" or t.is_op("@"):
            if t.kind == "ident" and c.peek().is_op("(") and c.peek().pos == t.end and not t.quoted:
                return self.call()
            name, pos = c.name()
            return ir.Field(name, pos=pos)
        return self.other_primary()

    def other_primary(self):
        self.c.error("expected an expression")

    def call(self):
        c = self.c
        t = c.next()
        name = str(t.value).lower()
        c.expect_op("(")
        args, kwargs = [], {}
        if not c.tok.is_op(")"):
            while True:
                if c.tok.kind == "ident" and c.peek().is_op("=") and not c.peek(2).is_op("="):
                    k = str(c.next().value)
                    c.next()
                    kwargs[k] = self.kwarg_value()
                elif c.tok.is_op("*") and c.peek().is_op(")", ","):
                    c.next()
                    args.append(ir.Lit("*", pos=t.pos))
                else:
                    args.append(self.expr())
                if not c.accept_op(","):
                    break
        c.expect_op(")")
        return ir.Call(name, args, kwargs, pos=t.pos)

    def kwarg_value(self):
        return self.expr()
