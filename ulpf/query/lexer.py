"""
Tokens for the query dialects (KQL, SPL2, HQL), with exact 1-based line and column numbers.

One lexer serves all three; the dialect only changes a few rules: KQL verbatim strings
(``@"..."``) and ``$left`` / ``$right``, SPL2 single-quoted field names, HQL ``/regex/flags``
and ``:=``. Timespans (``1h``, ``250ms``) are their own token. Every token keeps its offset
so errors can point at the exact character.
"""
from __future__ import annotations

from dataclasses import dataclass

MAX_QUERY = 64 * 1024
TIMESPAN_UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800,
                  "sec": 1, "min": 60, "hr": 3600, "day": 86400}
_OPS = ("==", "!=", "=~", "!~", "<=", ">=", ":=", "..", "<>", "|", "(", ")", "[", "]", "{", "}", ",",
        "=", "<", ">", "+", "-", "*", "/", "%", "!", ".", ":", "$", "@", "~")


class QuerySyntaxError(ValueError):
    def __init__(self, message: str, text: str, offset: int):
        self.message, self.offset = message, offset
        self.line = text.count("\n", 0, offset) + 1
        self.column = offset - (text.rfind("\n", 0, offset) + 1) + 1
        src = text.splitlines()[self.line - 1] if text.splitlines() else ""
        self.snippet = f"{src}\n{' ' * (self.column - 1)}^"
        super().__init__(f"line {self.line}, column {self.column}: {message}")

    def to_dict(self) -> dict:
        return {"error": self.message, "line": self.line, "column": self.column, "snippet": self.snippet}


@dataclass(frozen=True)
class Tok:
    kind: str       # ident, string, number, timespan, regex, word (bare value: 10.0.0.1), op, eof
    value: object
    pos: int
    end: int
    quoted: bool = False

    def is_op(self, *ops: str) -> bool:
        return self.kind == "op" and self.value in ops

    def is_word(self, *words: str) -> bool:
        return self.kind == "ident" and not self.quoted and str(self.value).lower() in words


def _ident_char(c: str, first: bool) -> bool:
    return c.isalpha() or c == "_" or (not first and (c.isdigit() or c == "-"))


def tokenize(text: str, dialect: str) -> list[Tok]:
    if len(text) > MAX_QUERY:
        raise QuerySyntaxError(f"query longer than {MAX_QUERY} characters", text, MAX_QUERY)
    out: list[Tok] = []
    i, n = 0, len(text)
    prev_value = lambda: out[-1] if out else None      # noqa: E731
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
            continue
        if text.startswith("//", i) and dialect == "kql":
            while i < n and text[i] != "\n":
                i += 1
            continue
        start = i
        # strings
        if c in "\"'" or (c == "@" and dialect == "kql" and i + 1 < n and text[i + 1] in "\"'"):
            verbatim = c == "@"
            if verbatim:
                i += 1
            q = text[i]
            i += 1
            buf = []
            while True:
                if i >= n:
                    raise QuerySyntaxError("unterminated string", text, start)
                ch = text[i]
                if ch == q:
                    if verbatim and i + 1 < n and text[i + 1] == q:
                        buf.append(q)
                        i += 2
                        continue
                    i += 1
                    break
                if ch == "\\" and not verbatim and i + 1 < n:
                    nxt = text[i + 1]
                    buf.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'"}.get(nxt, "\\" + nxt))
                    i += 2
                    continue
                if ch == "\n" and q != '"':
                    raise QuerySyntaxError("unterminated string", text, start)
                buf.append(ch)
                i += 1
            if dialect == "spl" and q == "'":      # SPL2: single quotes name a field
                out.append(Tok("ident", "".join(buf), start, i, quoted=True))
            else:
                out.append(Tok("string", "".join(buf), start, i))
            continue
        # HQL regex literal /.../flags (where an operand is expected)
        if c == "/" and dialect == "hql":
            p = prev_value()
            operand_expected = p is None or (p.kind == "op" and p.value in ("|", "(", ",", "=", "!=", "!", "[", ":=")) \
                or p.is_word("and", "or", "not")
            if operand_expected:
                i += 1
                buf = []
                while True:
                    if i >= n or text[i] == "\n":
                        raise QuerySyntaxError("unterminated regex", text, start)
                    if text[i] == "\\" and i + 1 < n:
                        buf.append(text[i:i + 2])
                        i += 2
                        continue
                    if text[i] == "/":
                        i += 1
                        break
                    buf.append(text[i])
                    i += 1
                flags = ""
                while i < n and text[i] in "igmd":
                    flags += text[i]
                    i += 1
                out.append(Tok("regex", ("".join(buf), flags), start, i))
                continue
        # numbers and timespans
        if c.isdigit() or (c == "." and i + 1 < n and text[i + 1].isdigit()):
            while i < n and (text[i].isdigit() or text[i] == "."):
                if text[i] == "." and i + 1 < n and text[i + 1] == ".":
                    break                              # 1..10 (between)
                i += 1
            if i < n and text[i] in "eE" and i + 1 < n and (text[i + 1].isdigit() or text[i + 1] in "+-"):
                i += 2
                while i < n and text[i].isdigit():
                    i += 1
            num = text[start:i]
            if num.count(".") > 1 or num.endswith("."):
                if dialect == "kql":
                    raise QuerySyntaxError(f"invalid number {num!r} (quote addresses: '10.0.0.1')", text, start)
                out.append(Tok("word", num, start, i))     # a bare value such as 10.0.0.1 or 10.0.0.*
                continue
            j = i
            while j < n and text[j].isalpha():
                j += 1
            unit = text[i:j].lower()
            if unit in TIMESPAN_UNITS and (j >= n or not (text[j].isalnum() or text[j] == "_")):
                out.append(Tok("timespan", float(num) * TIMESPAN_UNITS[unit], start, j))
                i = j
                continue
            if unit and dialect != "hql":
                raise QuerySyntaxError(f"invalid number or timespan {text[start:j]!r}", text, start)
            if unit:                                   # HQL bare value like 10abc: an identifier
                i = j
                while i < n and _ident_char(text[i], False):
                    i += 1
                out.append(Tok("ident", text[start:i], start, i))
                continue
            try:
                v = int(num) if num.isdigit() else float(num)
            except ValueError:
                raise QuerySyntaxError(f"invalid number {num!r}", text, start) from None
            out.append(Tok("number", v, start, i))
            continue
        # identifiers (dotted names are joined by the parsers)
        if _ident_char(c, True) or (c in "@#" and dialect == "hql" and i + 1 < n and _ident_char(text[i + 1], True)):
            i += 1
            while i < n and _ident_char(text[i], False):
                if text[i] == "-" and not (dialect == "kql" and text[start:i].lower() in
                                           ("mv", "project", "make", "project-away", "mv-expand")):
                    break                              # a-b is subtraction except KQL op names
                i += 1
            out.append(Tok("ident", text[start:i], start, i))
            if dialect == "kql" and text[start:i].lower() == "datetime":
                j = i
                while j < n and text[j] in " 	":
                    j += 1
                if j < n and text[j] == "(":         # datetime(2026-10-25 08:00): raw literal text
                    k = text.find(")", j)
                    if k < 0:
                        raise QuerySyntaxError("unterminated datetime(...)", text, j)
                    out.append(Tok("op", "(", j, j + 1))
                    raw = text[j + 1:k].strip()
                    if raw[:1] in "\"'" and raw[-1:] == raw[:1] and len(raw) >= 2:
                        raw = raw[1:-1]
                    out.append(Tok("string", raw, j + 1, k))
                    out.append(Tok("op", ")", k, k + 1))
                    i = k + 1
            continue
        for op in _OPS:
            if text.startswith(op, i):
                out.append(Tok("op", op, start, i + len(op)))
                i += len(op)
                break
        else:
            raise QuerySyntaxError(f"unexpected character {c!r}", text, start)
    out.append(Tok("eof", None, n, n))
    return out


class Cursor:
    """Token stream with the error helpers every parser uses."""

    def __init__(self, text: str, dialect: str):
        self.text = text
        self.toks = tokenize(text, dialect)
        self.i = 0

    @property
    def tok(self) -> Tok:
        return self.toks[self.i]

    def peek(self, k: int = 1) -> Tok:
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def next(self) -> Tok:
        t = self.toks[self.i]
        if t.kind != "eof":
            self.i += 1
        return t

    def error(self, message: str, tok: Tok | None = None):
        t = tok or self.tok
        found = "end of query" if t.kind == "eof" else repr(self.text[t.pos:t.end])
        raise QuerySyntaxError(f"{message} (found {found})", self.text, t.pos)

    def expect_op(self, *ops: str) -> Tok:
        if not self.tok.is_op(*ops):
            self.error(f"expected {' or '.join(repr(o) for o in ops)}")
        return self.next()

    def accept_op(self, *ops: str) -> Tok | None:
        return self.next() if self.tok.is_op(*ops) else None

    def accept_word(self, *words: str) -> Tok | None:
        return self.next() if self.tok.is_word(*words) else None

    def expect_word(self, *words: str) -> Tok:
        if not self.tok.is_word(*words):
            self.error(f"expected {' or '.join(words)}")
        return self.next()

    def adjacent(self, a: Tok, b: Tok) -> bool:
        return a.end == b.pos

    def after_name(self) -> Tok:
        """The token after the (possibly dotted) name at the cursor, without consuming it."""
        k = self.i
        t = self.toks[k]
        if t.is_op("@") and self.toks[k + 1].kind == "ident":
            k += 1
        if self.toks[k].kind != "ident":
            return self.toks[k]
        end = self.toks[k].end
        k += 1
        while self.toks[k].is_op(".") and self.toks[k].pos == end and self.toks[k + 1].kind == "ident"                 and self.toks[k + 1].pos == self.toks[k].end:
            end = self.toks[k + 1].end
            k += 2
        return self.toks[k]

    def name_then(self, *ops: str) -> bool:
        """A name followed by one of ``ops`` (``=`` not followed by another ``=``)."""
        t = self.after_name()
        if not t.is_op(*ops):
            return False
        nxt = self.toks[self.toks.index(t) + 1] if t.kind != "eof" else t
        return not (t.value == "=" and nxt.is_op("="))

    def name(self, what: str = "a field name") -> tuple[str, int]:
        """A (possibly dotted) field name: user.name, source.ip, @timestamp, 'quoted name'."""
        t = self.tok
        if t.kind == "ident":
            self.next()
            parts, end = [str(t.value)], t.end
            while self.tok.is_op(".") and self.tok.pos == end and self.peek().kind == "ident" \
                    and self.peek().pos == self.tok.end:
                self.next()
                p = self.next()
                parts.append(str(p.value))
                end = p.end
            return ".".join(parts), t.pos
        if t.is_op("@") and self.peek().kind == "ident" and self.peek().pos == t.end:
            self.next()
            name, _ = self.name(what)
            return "@" + name, t.pos
        self.error(f"expected {what}")
