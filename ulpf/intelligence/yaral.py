"""
Google SecOps (Chronicle) YARA-L 2.0 rules over ULPF events (their UDM view).

    rule failed_then_success {
      meta:
        severity = "HIGH"
      events:
        $fail.metadata.event_type = "USER_LOGIN"
        $fail.security_result.action = "FAIL"
        $fail.target.user.userid = $user
        $ok.metadata.event_type = "USER_LOGIN"
        $ok.security_result.action = "ALLOW"
        $ok.target.user.userid = $user
        $fail.metadata.event_timestamp.seconds < $ok.metadata.event_timestamp.seconds
      match:
        $user over 15m
      outcome:
        $risk_score = max(70)
        $failures = count_distinct($fail.metadata.product_log_id)
      condition:
        #fail >= 5 and $ok
    }

Sections: meta, events, match, outcome, condition (options is accepted and ignored).
Events: field paths ``$e.a.b``, comparisons ``= != < <= > >=`` (``nocase``), regex literals
``/re/ nocase``, ``re.regex(path, `re`)``, ``re.capture``, ``net.ip_in_range_cidr``,
``strings.to_lower / to_upper / concat / coalesce``, placeholders ``$x`` (bindings and joins),
``and / or / not``, cross-event comparisons (``$a.ts < $b.ts`` for order).
Match: ``$x[, $y] over 15m`` (hop window from the first event of a key), or
``over 15m before|after $e`` (sliding window pivoting on ``$e``).
Outcome: count, count_distinct, sum, min, max, avg, array, array_distinct, if(...).
Condition: ``$e``, ``!$e``, ``#e op N``, outcome variables, ``and / or / not``.

Evaluation is split like Chronicle's: workers test each event variable's own predicates on
each event and send compact candidates (bindings, the fields joins and outcomes need, time);
the host joins candidates per match key and window. Conditions with ``!$e`` or an upper bound
(``#e < N``) are decided when the window closes; others as soon as they hold (once per window).
Regular expressions run in Python ``re`` (backreferences work); patterns with nested
quantifiers are rejected and matched text is capped at 4 KiB, so matching stays bounded.
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import itertools
import logging
import os
import re
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

MAX_RULE_TEXT = 256 * 1024
MAX_REGEX_INPUT = 4096
MAX_CANDIDATES_PER_VAR = 500
MAX_ASSIGNMENTS = 20_000
_DUR = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class YaraLError(ValueError):
    def __init__(self, message: str, text: str = "", offset: int = 0):
        self.line = text.count("\n", 0, offset) + 1
        self.column = offset - (text.rfind("\n", 0, offset) + 1) + 1
        super().__init__(f"line {self.line}, column {self.column}: {message}" if text else message)


# ---------------------------------------------------------------------------- lexer

@dataclass(frozen=True)
class T:
    k: str          # ident var count str raw regex num dur op nl eof
    v: Any
    p: int


_OPS = ("!=", "<=", ">=", "=", "<", ">", "(", ")", ",", ".", ":", "{", "}", "[", "]", "!", "-", "+", "*")


def lex(text: str) -> list[T]:
    if len(text) > MAX_RULE_TEXT:
        raise YaraLError("rule text too long")
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == "\n":
            out.append(T("nl", None, i))
            i += 1
            continue
        if c in " \t\r":
            i += 1
            continue
        if text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise YaraLError("unterminated comment", text, i)
            out += [T("nl", None, i)] * text.count("\n", i, j)
            i = j + 2
            continue
        s = i
        if c == '"':
            i += 1
            buf = []
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n:
                    buf.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(text[i + 1], "\\" + text[i + 1]))
                    i += 2
                    continue
                if text[i] == "\n":
                    raise YaraLError("unterminated string", text, s)
                buf.append(text[i])
                i += 1
            if i >= n:
                raise YaraLError("unterminated string", text, s)
            i += 1
            out.append(T("str", "".join(buf), s))
            continue
        if c == "`":
            j = text.find("`", i + 1)
            if j < 0:
                raise YaraLError("unterminated raw string", text, s)
            out.append(T("raw", text[i + 1:j], s))
            i = j + 1
            continue
        if c == "/" and out and out[-1].k == "op" and out[-1].v in ("=", "!="):
            i += 1
            buf = []
            while i < n and text[i] != "/":
                if text[i] == "\\" and i + 1 < n:
                    buf.append(text[i:i + 2])
                    i += 2
                    continue
                if text[i] == "\n":
                    raise YaraLError("unterminated regex", text, s)
                buf.append(text[i])
                i += 1
            if i >= n:
                raise YaraLError("unterminated regex", text, s)
            i += 1
            out.append(T("regex", "".join(buf), s))
            continue
        if c in "$#" and i + 1 < n and (text[i + 1].isalnum() or text[i + 1] == "_"):
            i += 1
            while i < n and (text[i].isalnum() or text[i] == "_"):
                i += 1
            out.append(T("var" if c == "$" else "count", text[s + 1:i], s))
            continue
        if c == "%" and i + 1 < n and text[i + 1].isalpha():
            raise YaraLError("reference lists (%list) are not supported", text, s)
        if c.isdigit():
            while i < n and (text[i].isdigit() or text[i] == "."):
                i += 1
            if i < n and text[i] in _DUR and not (i + 1 < n and text[i + 1].isalnum()):
                out.append(T("dur", float(text[s:i]) * _DUR[text[i]], s))
                i += 1
                continue
            num = text[s:i]
            out.append(T("num", float(num) if "." in num else int(num), s))
            continue
        if c.isalpha() or c == "_":
            while i < n and (text[i].isalnum() or text[i] == "_"):
                i += 1
            out.append(T("ident", text[s:i], s))
            continue
        for op in _OPS:
            if text.startswith(op, i):
                out.append(T("op", op, s))
                i += len(op)
                break
        else:
            raise YaraLError(f"unexpected character {c!r}", text, s)
    out.append(T("eof", None, n))
    return out


# ---------------------------------------------------------------------------- AST

@dataclass
class Path:
    var: str
    parts: list


@dataclass
class Ph:            # placeholder $x
    name: str


@dataclass
class Lit:
    v: Any


@dataclass
class Rx:
    pat: re.Pattern


@dataclass
class Cmp:
    op: str
    a: Any
    b: Any
    nocase: bool = False


@dataclass
class Fn:
    name: str
    args: list


@dataclass
class BoolOp:
    op: str          # and / or
    xs: list


@dataclass
class Not:
    x: Any


@dataclass
class EvRef:         # condition: $e / #e
    var: str
    count: bool


def _vars(x, acc=None) -> set:
    acc = set() if acc is None else acc
    if isinstance(x, Path):
        acc.add(x.var)
    elif isinstance(x, Cmp):
        _vars(x.a, acc)
        _vars(x.b, acc)
    elif isinstance(x, Fn):
        for a in x.args:
            _vars(a, acc)
    elif isinstance(x, BoolOp):
        for a in x.xs:
            _vars(a, acc)
    elif isinstance(x, Not):
        _vars(x.x, acc)
    return acc


def _phs(x, acc=None) -> set:
    acc = set() if acc is None else acc
    if isinstance(x, Ph):
        acc.add(x.name)
    elif isinstance(x, Cmp):
        _phs(x.a, acc)
        _phs(x.b, acc)
    elif isinstance(x, Fn):
        for a in x.args:
            _phs(a, acc)
    elif isinstance(x, BoolOp):
        for a in x.xs:
            _phs(a, acc)
    elif isinstance(x, Not):
        _phs(x.x, acc)
    return acc


def _paths(x, acc=None) -> list:
    acc = [] if acc is None else acc
    if isinstance(x, Path):
        acc.append(x)
    elif isinstance(x, Cmp):
        _paths(x.a, acc)
        _paths(x.b, acc)
    elif isinstance(x, Fn):
        for a in x.args:
            _paths(a, acc)
    elif isinstance(x, BoolOp):
        for a in x.xs:
            _paths(a, acc)
    elif isinstance(x, Not):
        _paths(x.x, acc)
    return acc


_NESTED_QUANT = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d*,?\d*\})")


def _regex(pat: str, nocase: bool, text: str, pos: int) -> re.Pattern:
    if _NESTED_QUANT.search(pat):
        raise YaraLError("regular expressions with nested quantifiers are rejected (catastrophic backtracking)",
                         text, pos)
    try:
        return re.compile(pat, re.IGNORECASE if nocase else 0)
    except re.error as e:
        raise YaraLError(f"invalid regular expression: {e}", text, pos) from None


# ---------------------------------------------------------------------------- parser

_SECTIONS = ("meta", "events", "match", "outcome", "condition", "options")
_FUNCS = {"re.regex", "re.capture", "re.replace", "net.ip_in_range_cidr", "strings.to_lower", "strings.to_upper",
          "strings.concat", "strings.coalesce", "strings.contains", "strings.length", "timestamp.current_seconds"}
_AGG = {"count", "count_distinct", "sum", "min", "max", "avg", "array", "array_distinct"}


class Parser:
    def __init__(self, text: str):
        self.text = text
        self.t = lex(text)
        self.i = 0

    @property
    def tok(self) -> T:
        return self.t[self.i]

    def nxt(self) -> T:
        t = self.t[self.i]
        if t.k != "eof":
            self.i += 1
        return t

    def err(self, msg: str, tok: T | None = None):
        tok = tok or self.tok
        found = "end of rule" if tok.k == "eof" else repr(self.text[tok.p:tok.p + 20].split("\n")[0])
        raise YaraLError(f"{msg} (found {found})", self.text, tok.p)

    def skip_nl(self):
        while self.tok.k == "nl":
            self.i += 1

    def expect(self, k: str, v=None) -> T:
        self.skip_nl()
        t = self.tok
        if t.k != k or (v is not None and t.v != v):
            self.err(f"expected {v or k}")
        return self.nxt()

    def at_section(self) -> bool:
        self.skip_nl()
        t = self.tok
        return (t.k == "ident" and t.v in _SECTIONS and self.t[self.i + 1].k == "op" and self.t[self.i + 1].v == ":") \
            or (t.k == "op" and t.v == "}")

    def rules(self) -> list["Rule"]:
        out = []
        self.skip_nl()
        while self.tok.k != "eof":
            out.append(self.rule())
            self.skip_nl()
        if not out:
            self.err("expected a rule")
        return out

    def rule(self) -> "Rule":
        start = self.expect("ident", "rule")
        name = self.expect("ident").v
        self.expect("op", "{")
        r = Rule(name=name, text=self.text, pos=start.p)
        while True:
            self.skip_nl()
            if self.tok.k == "op" and self.tok.v == "}":
                self.nxt()
                break
            sec = self.expect("ident")
            if sec.v not in _SECTIONS:
                self.err(f"unknown section {sec.v!r}", sec)
            self.expect("op", ":")
            getattr(self, "sec_" + sec.v)(r)
        if not r.events:
            raise YaraLError(f"rule {name}: an events section is required", self.text, start.p)
        if r.condition is None:
            raise YaraLError(f"rule {name}: a condition section is required", self.text, start.p)
        r.finish()
        return r

    def sec_meta(self, r):
        while not self.at_section():
            k = self.expect("ident").v
            self.expect("op", "=")
            self.skip_nl()
            t = self.nxt()
            if t.k not in ("str", "num", "ident"):
                self.err("expected a meta value", t)
            r.meta[k] = t.v

    def sec_options(self, r):
        while not self.at_section():
            self.nxt()

    def sec_events(self, r):
        while not self.at_section():
            r.events.append(self.expr())
            while self.tok.k == "nl":
                self.nxt()

    def sec_match(self, r):
        while True:
            t = self.expect("var")
            r.match.append(t.v)
            self.skip_nl()
            if self.tok.k == "op" and self.tok.v == ",":
                self.nxt()
                continue
            break
        self.expect("ident", "over")
        d = self.expect("dur")
        r.window = d.v
        self.skip_nl()
        if self.tok.k == "ident" and self.tok.v in ("before", "after"):
            r.slide = self.nxt().v
            r.pivot = self.expect("var").v

    def sec_outcome(self, r):
        while not self.at_section():
            v = self.expect("var").v
            self.expect("op", "=")
            r.outcome[v] = self.expr()

    def sec_condition(self, r):
        self.skip_nl()
        r.condition = self.cexpr()
        self.skip_nl()

    # ---- event / outcome expressions
    def expr(self):
        return self._or()

    def _or(self):
        x = self._and()
        xs = [x]
        while self.tok.k == "ident" and self.tok.v == "or":
            self.nxt()
            self.skip_nl()
            xs.append(self._and())
        return xs[0] if len(xs) == 1 else BoolOp("or", xs)

    def _and(self):
        x = self._not()
        xs = [x]
        while self.tok.k == "ident" and self.tok.v == "and":
            self.nxt()
            self.skip_nl()
            xs.append(self._not())
        return xs[0] if len(xs) == 1 else BoolOp("and", xs)

    def _not(self):
        if self.tok.k == "ident" and self.tok.v == "not":
            self.nxt()
            return Not(self._not())
        return self._cmp()

    def _cmp(self):
        a = self.value()
        t = self.tok
        if t.k == "op" and t.v in ("=", "!=", "<", "<=", ">", ">="):
            self.nxt()
            if self.tok.k == "regex":
                rt = self.nxt()
                nocase = self._nocase()
                if t.v not in ("=", "!="):
                    self.err("a regex compares with = or !=", rt)
                m = Cmp("=", a, Rx(_regex(rt.v, nocase, self.text, rt.p)))
                return m if t.v == "=" else Not(m)
            b = self.value()
            return Cmp(t.v, a, b, self._nocase())
        return a

    def _nocase(self) -> bool:
        if self.tok.k == "ident" and self.tok.v == "nocase":
            self.nxt()
            return True
        return False

    def value(self):
        t = self.tok
        if t.k == "var":
            self.nxt()
            if self.tok.k == "op" and self.tok.v == "." and self.t[self.i + 1].k == "ident":
                parts = []
                while self.tok.k == "op" and self.tok.v == "." and self.t[self.i + 1].k == "ident":
                    self.nxt()
                    parts.append(self.nxt().v)
                return Path(t.v, parts)
            return Ph(t.v)
        if t.k in ("str", "raw"):
            self.nxt()
            return Lit(t.v)
        if t.k == "num":
            self.nxt()
            return Lit(t.v)
        if t.k == "op" and t.v == "-" and self.t[self.i + 1].k == "num":
            self.nxt()
            return Lit(-self.nxt().v)
        if t.k == "op" and t.v == "(":
            self.nxt()
            self.skip_nl()
            x = self.expr()
            self.expect("op", ")")
            return x
        if t.k == "ident":
            if t.v in ("true", "false"):
                self.nxt()
                return Lit(t.v == "true")
            name = self.nxt().v
            if self.tok.k == "op" and self.tok.v == "." and self.t[self.i + 1].k == "ident":
                self.nxt()
                name += "." + self.nxt().v
            if not (self.tok.k == "op" and self.tok.v == "("):
                self.err(f"unknown name {name!r}", t)
            if name not in _FUNCS and name not in _AGG and name != "if":
                self.err(f"unsupported function {name}()", t)
            self.nxt()
            args = []
            self.skip_nl()
            if not (self.tok.k == "op" and self.tok.v == ")"):
                while True:
                    self.skip_nl()
                    args.append(self.expr())
                    self.skip_nl()
                    if self.tok.k == "op" and self.tok.v == ",":
                        self.nxt()
                        continue
                    break
            self.expect("op", ")")
            nocase = self._nocase()
            if name in ("re.regex", "re.capture", "re.replace"):
                if len(args) < 2 or not isinstance(args[1], Lit):
                    self.err(f"{name}() needs a field and a pattern", t)
                args[1] = Rx(_regex(str(args[1].v), nocase, self.text, t.p))
            return Fn(name, args)
        self.err("expected a value")

    # ---- condition
    def cexpr(self):
        x = self._cand()
        xs = [x]
        while self.tok.k == "ident" and self.tok.v == "or":
            self.nxt()
            self.skip_nl()
            xs.append(self._cand())
        return xs[0] if len(xs) == 1 else BoolOp("or", xs)

    def _cand(self):
        x = self._cnot()
        xs = [x]
        while self.tok.k == "ident" and self.tok.v == "and":
            self.nxt()
            self.skip_nl()
            xs.append(self._cnot())
        return xs[0] if len(xs) == 1 else BoolOp("and", xs)

    def _cnot(self):
        t = self.tok
        if (t.k == "ident" and t.v == "not") or (t.k == "op" and t.v == "!"):
            self.nxt()
            return Not(self._cnot())
        return self._ccmp()

    def _ccmp(self):
        t = self.tok
        if t.k == "op" and t.v == "(":
            self.nxt()
            x = self.cexpr()
            self.expect("op", ")")
            return x
        if t.k == "count":
            self.nxt()
            a = EvRef(t.v, True)
        elif t.k == "var":
            self.nxt()
            a = EvRef(t.v, False)
        else:
            self.err("expected $event, #event or an outcome variable")
        op = self.tok
        if op.k == "op" and op.v in ("=", "!=", "<", "<=", ">", ">="):
            self.nxt()
            b = self.tok
            if b.k != "num":
                self.err("expected a number", b)
            self.nxt()
            return Cmp(op.v, a, Lit(b.v))
        if a.count:
            self.err("#event needs a comparison such as #e > 5", op)
        return a


# ---------------------------------------------------------------------------- rule

@dataclass
class Rule:
    name: str
    text: str = ""
    pos: int = 0
    meta: dict = field(default_factory=dict)
    events: list = field(default_factory=list)
    match: list = field(default_factory=list)
    window: float = 0.0
    slide: str = ""                  # "", "before", "after"
    pivot: str = ""
    outcome: dict = field(default_factory=dict)
    condition: Any = None
    # derived
    evvars: list = field(default_factory=list)
    local: dict = field(default_factory=dict)      # var -> [predicate]
    binds: dict = field(default_factory=dict)      # var -> [(placeholder, value expr)]
    cross: list = field(default_factory=list)      # predicates over several variables / placeholders
    need: dict = field(default_factory=dict)       # var -> {path key: Path} the host needs
    negated: set = field(default_factory=set)
    deferred: bool = False                         # decided at window close
    disjunctive: bool = False                      # the condition has an "or": variables may be absent

    @property
    def severity(self) -> str:
        return str(self.meta.get("severity") or "MEDIUM").upper()

    def finish(self) -> None:
        for e in self.events:
            for p in _paths(e):
                if p.var not in self.evvars:
                    self.evvars.append(p.var)
        conj = []
        for e in self.events:
            conj += e.xs if isinstance(e, BoolOp) and e.op == "and" else [e]
        for v in self.evvars:
            self.local[v], self.binds[v], self.need[v] = [], [], {}
        for c in conj:
            vs, ps = _vars(c), _phs(c)
            if isinstance(c, Cmp) and c.op == "=" and len(vs) == 1 and (
                    (isinstance(c.a, Ph) and not _phs(c.b)) or (isinstance(c.b, Ph) and not _phs(c.a))):
                ph, val = (c.a, c.b) if isinstance(c.a, Ph) else (c.b, c.a)
                self.binds[next(iter(vs))].append((ph.name, val))
            elif len(vs) == 1 and not ps:
                self.local[next(iter(vs))].append(c)
            else:
                self.cross.append(c)
                for p in _paths(c):
                    self.need[p.var][".".join(p.parts)] = p
        for oexpr in self.outcome.values():
            for p in _paths(oexpr):
                self.need.setdefault(p.var, {})[".".join(p.parts)] = p
        for v in self.match:
            if not any(ph == v for b in self.binds.values() for ph, _ in b):
                raise YaraLError(f"rule {self.name}: match variable ${v} is not assigned in events", self.text, self.pos)
        if self.slide and self.pivot not in self.evvars:
            raise YaraLError(f"rule {self.name}: sliding window pivot ${self.pivot} is not an event", self.text, self.pos)
        self._scan_condition(self.condition, False)
        self.disjunctive = _has_or(self.condition)
        for v in self.evvars:
            if not self.binds[v] and not self.local[v] and not self.need[v]:
                raise YaraLError(f"rule {self.name}: ${v} has no conditions", self.text, self.pos)

    def _scan_condition(self, x, neg: bool) -> None:
        if isinstance(x, EvRef):
            if x.var in self.outcome:
                return
            if x.var not in self.evvars:
                raise YaraLError(f"rule {self.name}: condition uses unknown ${x.var}", self.text, self.pos)
            if neg and not x.count:
                self.negated.add(x.var)
                self.deferred = True
        elif isinstance(x, Not):
            self._scan_condition(x.x, not neg)
        elif isinstance(x, BoolOp):
            for a in x.xs:
                self._scan_condition(a, neg)
        elif isinstance(x, Cmp):
            if isinstance(x.a, EvRef) and x.a.count and x.op in ("<", "<=", "=") and x.a.var not in self.outcome:
                self.deferred = True       # an upper bound: only the closed window can tell
            self._scan_condition(x.a, neg)


def _has_or(x) -> bool:
    if isinstance(x, BoolOp):
        return x.op == "or" or any(_has_or(a) for a in x.xs)
    if isinstance(x, Not):
        return _has_or(x.x)
    return False


def parse_rules(text: str) -> list[Rule]:
    return Parser(text).rules()


# ---------------------------------------------------------------------------- evaluation (one event)

def _epoch(v) -> float | None:
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    if isinstance(v, str):
        try:
            return _dt.datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def get_path(doc: dict, parts: list):
    """A UDM path's value: lists (repeated fields) are flattened; ``event_timestamp.seconds``
    is the epoch time of a timestamp."""
    cur = [doc]
    for i, p in enumerate(parts):
        nxt = []
        for c in cur:
            if isinstance(c, dict):
                if p in c:
                    v = c[p]
                    nxt.extend(v if isinstance(v, list) else [v])
                elif p in ("seconds", "nanos") and i == len(parts) - 1:
                    pass
            elif p == "seconds" and i == len(parts) - 1:
                t = _epoch(c)
                if t is not None:
                    nxt.append(int(t))
        cur = nxt
        if not cur:
            return None
    vals = [x for x in cur if x is not None and not isinstance(x, dict)]
    if not vals:
        return None
    return vals if len(vals) > 1 else vals[0]


def _as_list(v) -> list:
    return [] if v is None else v if isinstance(v, list) else [v]


def _cmp_one(op: str, a, b, nocase: bool) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        if nocase:
            a, b = a.lower(), b.lower()
    else:
        try:
            a, b = float(a), float(b)
        except (TypeError, ValueError):
            a, b = str(a), str(b)
    if op == "=":
        return a == b
    if op == "!=":
        return a != b
    try:
        return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
    except TypeError:
        return False


class Env:
    """Values for one evaluation: event variables -> UDM doc or extracted fields; placeholders."""

    def __init__(self, docs: dict, phs: dict | None = None, fields: dict | None = None):
        self.docs, self.phs, self.fields = docs, phs or {}, fields or {}

    def val(self, x):
        if isinstance(x, Lit):
            return x.v
        if isinstance(x, Ph):
            return self.phs.get(x.name)
        if isinstance(x, Path):
            key = ".".join(x.parts)
            f = self.fields.get(x.var)
            if f is not None and key in f:
                return f[key]
            d = self.docs.get(x.var)
            return get_path(d, x.parts) if d is not None else None
        if isinstance(x, Fn):
            return _fn(self, x)
        if isinstance(x, (Cmp, BoolOp, Not)):
            return truth(self, x)
        raise YaraLError(f"cannot evaluate {type(x).__name__}")


def _str(v) -> str | None:
    if v is None:
        return None
    return str(v)[:MAX_REGEX_INPUT]


def _fn(env: Env, f: Fn):
    n = f.name
    if n in ("re.regex", "re.capture", "re.replace"):
        vals = _as_list(env.val(f.args[0]))
        rx = f.args[1].pat
        if n == "re.regex":
            return any(rx.search(_str(v) or "") is not None for v in vals)
        if n == "re.capture":
            for v in vals:
                m = rx.search(_str(v) or "")
                if m:
                    return m.group(1) if m.groups() else m.group(0)
            return None
        rep = env.val(f.args[2]) if len(f.args) > 2 else ""
        return rx.sub(str(rep), _str(vals[0]) or "") if vals else None
    if n == "net.ip_in_range_cidr":
        try:
            net = ipaddress.ip_network(str(env.val(f.args[1])), strict=False)
        except ValueError:
            return False
        for v in _as_list(env.val(f.args[0])):
            try:
                if ipaddress.ip_address(str(v)) in net:
                    return True
            except ValueError:
                pass
        return False
    if n in ("strings.to_lower", "strings.to_upper"):
        v = env.val(f.args[0])
        conv = str.lower if n.endswith("lower") else str.upper
        return [conv(str(x)) for x in v] if isinstance(v, list) else (None if v is None else conv(str(v)))
    if n == "strings.concat":
        return "".join("" if env.val(a) is None else str(env.val(a)) for a in f.args)
    if n == "strings.coalesce":
        return next((v for v in (env.val(a) for a in f.args) if v not in (None, "")), None)
    if n == "strings.contains":
        h, nd = env.val(f.args[0]), env.val(f.args[1])
        return any(str(nd) in str(x) for x in _as_list(h)) if nd is not None else False
    if n == "strings.length":
        v = env.val(f.args[0])
        return None if v is None else len(str(v))
    if n == "timestamp.current_seconds":
        return int(_dt.datetime.now(_dt.timezone.utc).timestamp())
    if n == "if":
        if len(f.args) != 3:
            raise YaraLError("if() takes a condition and two values")
        return env.val(f.args[1]) if truth(env, f.args[0]) else env.val(f.args[2])
    raise YaraLError(f"{n}() is an aggregation: use it in outcome")


def truth(env: Env, x) -> bool:
    if isinstance(x, BoolOp):
        return all(truth(env, a) for a in x.xs) if x.op == "and" else any(truth(env, a) for a in x.xs)
    if isinstance(x, Not):
        return not truth(env, x.x)
    if isinstance(x, Cmp):
        if isinstance(x.b, Rx):
            return any(x.b.pat.search(_str(v) or "") is not None for v in _as_list(env.val(x.a)))
        a, b = env.val(x.a), env.val(x.b)
        if a is None or b is None:
            return x.op == "!=" and not (a is None and b is None)
        av, bv = _as_list(a), _as_list(b)
        if x.op == "!=":                   # repeated fields: no element equals
            return not any(_cmp_one("=", p, q, x.nocase) for p in av for q in bv)
        return any(_cmp_one(x.op, p, q, x.nocase) for p in av for q in bv)
    if isinstance(x, Fn):
        return bool(_fn(env, x))
    v = env.val(x)
    return bool(v)


# ---------------------------------------------------------------------------- worker side

class YaraLEngine:
    """Workers: candidates of each rule's event variables, from each event's UDM view."""

    def __init__(self, rules: list[Rule]):
        self.rules = rules
        self.candidates = 0

    @classmethod
    def load(cls, paths) -> "YaraLEngine":
        rules, errors = load_rules(paths)
        for e in errors:
            logger.warning(f"yara-l: {e}")
        eng = cls(rules)
        eng.errors = errors
        return eng

    errors: list = []

    def extract(self, events: list[dict]) -> list:
        """[(rule index, variable, epoch time, bindings, fields, event id)] for these events."""
        if not self.rules:
            return []
        from ulpf.engine.standards.udm import to_udm
        out = []
        for e in events:
            if e.get("event_kind", "log") != "log":
                continue
            try:
                doc = to_udm(e, lossless=False)
            except Exception:
                continue
            ts = _epoch((doc.get("metadata") or {}).get("event_timestamp")) or _epoch(e.get("timestamp"))
            if ts is None:
                continue
            for ri, r in enumerate(self.rules):
                for v in r.evvars:
                    env = Env({v: doc})
                    try:
                        if not all(truth(env, p) for p in r.local[v]):
                            continue
                        binds = {}
                        for ph, val in r.binds[v]:
                            bv = env.val(val)
                            if bv is None:
                                break
                            binds[ph] = bv if not isinstance(bv, list) else bv[0] if len(bv) == 1 else bv
                        else:
                            fields = {k: _jsonable(get_path(doc, p.parts)) for k, p in r.need[v].items()}
                            out.append((ri, v, ts, {k: _jsonable(x) for k, x in binds.items()}, fields,
                                        e.get("event_id")))
                    except YaraLError:
                        continue
        self.candidates += len(out)
        return out


def _jsonable(v):
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, list):
        return [_jsonable(x) for x in v]
    return str(v)


# ---------------------------------------------------------------------------- host side

@dataclass
class Cand:
    var: str
    ts: float
    binds: dict
    fields: dict
    event_id: Any
    n: int


@dataclass
class YDetection:
    rule: Rule
    key: tuple
    counts: dict
    outcome: dict
    events: list
    start: float
    end: float

    def to_dict(self) -> dict:
        return {"rule": self.rule.name, "severity": self.rule.severity, "meta": self.rule.meta,
                "match": dict(zip(self.rule.match, self.key)), "counts": self.counts, "outcome": self.outcome,
                "events": self.events,
                "window": [_dt.datetime.fromtimestamp(self.start, _dt.timezone.utc).isoformat(),
                           _dt.datetime.fromtimestamp(self.end, _dt.timezone.utc).isoformat()]}


class _Win:
    def __init__(self, start: float):
        self.start = start
        self.cands: dict[str, list[Cand]] = {}
        self.fired = False


class YaraLCorrelator:
    """Host: joins candidates per rule, match key and window; returns detections."""

    def __init__(self, rules: list[Rule], max_keys: int = 50_000):
        self.rules = rules
        self.max_keys = max_keys
        self._wins: list[OrderedDict] = [OrderedDict() for _ in rules]
        self._seq = itertools.count()
        self._watermark = 0.0
        self.detections = 0

    def submit(self, cands: list) -> list[YDetection]:
        out = []
        for ri, var, ts, binds, fields, eid in sorted(cands, key=lambda c: c[2]):
            if not 0 <= ri < len(self.rules):
                continue
            r = self.rules[ri]
            self._watermark = max(self._watermark, ts)
            c = Cand(var, ts, binds, fields, eid, next(self._seq))
            key = tuple(_key(binds.get(m)) for m in r.match)
            out += self._add(ri, r, key, c)
        out += self.tick(self._watermark)
        self.detections += len(out)
        return out

    def _add(self, ri, r: Rule, key, c: Cand) -> list:
        wins = self._wins[ri]
        if not r.match:                                  # single-event rule
            w = _Win(c.ts)
            w.cands[c.var] = [c]
            d = self._evaluate(r, key, w, c.ts, c.ts)
            return [d] if d else []
        w = wins.get(key)
        out = []
        if w is not None and not r.slide and c.ts - w.start > r.window:
            out += self._close(ri, r, key, w)            # hop window ended: decide, start a new one
            w = None
        if w is None:
            w = wins[key] = _Win(c.ts)
            if len(wins) > self.max_keys:
                old_key, old = wins.popitem(last=False)
                out += self._close(ri, r, old_key, old)
        else:
            wins.move_to_end(key)
        lst = w.cands.setdefault(c.var, [])
        lst.append(c)
        if len(lst) > MAX_CANDIDATES_PER_VAR:
            lst.pop(0)
        if r.slide:
            out += self._slide(r, key, w, c)
        elif not r.deferred and not w.fired:
            d = self._evaluate(r, key, w, w.start, w.start + r.window)
            if d:
                w.fired = True
                out.append(d)
        return out

    def _slide(self, r: Rule, key, w: _Win, c: Cand) -> list:
        """Sliding window: one window per pivot event, before or after it."""
        out = []
        horizon = c.ts - 2 * r.window
        for v in list(w.cands):
            w.cands[v] = [x for x in w.cands[v] if x.ts >= horizon]
        pivots = w.cands.get(r.pivot, [])
        fired = getattr(w, "fired_pivots", set())
        w.fired_pivots = fired
        for p in pivots:
            if p.n in fired:
                continue
            lo, hi = (p.ts - r.window, p.ts) if r.slide == "before" else (p.ts, p.ts + r.window)
            if r.deferred and self._watermark <= hi:
                continue                                 # negation: wait for the window to pass
            sub = _Win(lo)
            for v, cs in w.cands.items():
                sub.cands[v] = [x for x in cs if lo <= x.ts <= hi and (v != r.pivot or x is p)]
            d = self._evaluate(r, key, sub, lo, hi)
            if d:
                fired.add(p.n)
                out.append(d)
            elif r.deferred:
                fired.add(p.n)                           # decided (no detection)
        return out

    def _close(self, ri, r: Rule, key, w: _Win) -> list:
        if r.deferred and not w.fired:
            d = self._evaluate(r, key, w, w.start, w.start + r.window)
            return [d] if d else []
        return []

    def tick(self, now: float) -> list:
        """Decide windows that have ended (event time ``now``)."""
        out = []
        for ri, r in enumerate(self.rules):
            if not r.match:
                continue
            wins = self._wins[ri]
            for key in [k for k, w in wins.items() if now - w.start > (2 * r.window if r.slide else r.window)]:
                w = wins.pop(key)
                if r.slide:
                    out += self._slide(r, key, w, Cand("", now, {}, {}, None, -1))
                else:
                    out += self._close(ri, r, key, w)
        return out

    # ---- join
    def _evaluate(self, r: Rule, key, w: _Win, start, end) -> YDetection | None:
        present = [v for v in r.evvars if w.cands.get(v) and v not in r.negated]
        assigns = self._join(r, present, w)
        counts = {v: 0 for v in r.evvars}
        used: dict[str, dict] = {v: {} for v in r.evvars}
        if assigns:
            for a in assigns:
                for v, c in a.items():
                    used[v][c.n] = c
        elif len(present) > 1 and r.disjunctive:        # "$a or $b": each may match without the other
            for v in present:
                for a in self._join(r, [v], w):
                    used[v][a[v].n] = a[v]
        for v in present:
            counts[v] = len(used[v])
        for v in r.negated:                             # events that would join an assignment
            n = 0
            for c in w.cands.get(v, []):
                if (not assigns and not present) or any(self._consistent(r, {**a, v: c}) for a in (assigns or [{}])):
                    n += 1
            counts[v] = n
        outcome = {}
        for name, x in r.outcome.items():
            outcome[name] = _aggregate(x, used, assigns, r)
        if not _cond(r.condition, counts, outcome):
            return None
        evs = [c.event_id for v in r.evvars for c in used[v].values() if c.event_id][:50]
        return YDetection(r, key, counts, outcome, evs, start, end)

    def _join(self, r: Rule, vars_: list, w: _Win) -> list:
        if not vars_:
            return []
        out: list = []
        lists = [w.cands.get(v, []) for v in vars_]

        def rec(i, a):
            if len(out) >= MAX_ASSIGNMENTS:
                return
            if i == len(vars_):
                out.append(dict(a))
                return
            for c in lists[i]:
                a[vars_[i]] = c
                if self._consistent(r, a):
                    rec(i + 1, a)
                del a[vars_[i]]
        rec(0, {})
        return out

    def _consistent(self, r: Rule, a: dict) -> bool:
        phs: dict = {}
        for v, c in a.items():
            for k, val in c.binds.items():
                if k in phs and not _same(phs[k], val):
                    return False
                phs[k] = val
        env = Env({}, phs, {v: c.fields for v, c in a.items()})
        for p in r.cross:
            if not _vars(p) <= set(a) or not _phs(p) <= set(phs):
                continue                                  # decided once its variables are assigned
            if not truth(env, p):
                return False
        return True


def _key(v):
    if isinstance(v, list):
        return tuple(sorted(map(str, v)))
    return v


def _same(a, b) -> bool:
    if isinstance(a, list) or isinstance(b, list):
        return bool(set(map(str, _as_list(a))) & set(map(str, _as_list(b))))
    return a == b or str(a) == str(b)


def _cond(x, counts: dict, outcome: dict) -> bool:
    if isinstance(x, BoolOp):
        return all(_cond(a, counts, outcome) for a in x.xs) if x.op == "and" else \
            any(_cond(a, counts, outcome) for a in x.xs)
    if isinstance(x, Not):
        return not _cond(x.x, counts, outcome)
    if isinstance(x, EvRef):
        if x.var in outcome:
            return bool(outcome[x.var])
        return counts.get(x.var, 0) > 0
    if isinstance(x, Cmp):
        a = outcome.get(x.a.var) if x.a.var in outcome else counts.get(x.a.var, 0)
        if a is None:
            return False
        return _cmp_one(x.op, a, x.b.v, False)
    return False


def _aggregate(x, used: dict, assigns: list, r: Rule):
    """An outcome expression over the participating events (aggregations over events,
    plain expressions over the match placeholders)."""
    if isinstance(x, Fn) and x.name in _AGG:
        inner = x.args[0] if x.args else None
        vals = []
        evvars = _vars(inner) if inner is not None else set()
        rows = [c for v in (evvars or r.evvars) for c in used.get(v, {}).values()] if evvars or inner is None else []
        if inner is None:
            vals = [1 for _ in rows]
        elif evvars:
            for c in rows:
                env = Env({}, c.binds, {c.var: c.fields})
                vals += _as_list(env.val(inner))
        else:
            phs = assigns[0] if assigns else {}
            env = Env({}, {k: v for c in phs.values() for k, v in c.binds.items()} if phs else {})
            vals = _as_list(env.val(inner))
        vals = [v for v in vals if v is not None]
        n = x.name
        if n == "count":
            return len(vals)
        if n == "count_distinct":
            return len({str(v) for v in vals})
        if n == "array":
            return vals[:1000]
        if n == "array_distinct":
            return sorted({str(v) for v in vals})[:1000]
        nums = []
        for v in vals:
            try:
                nums.append(float(v))
            except (TypeError, ValueError):
                pass
        if not nums:
            return None
        return {"sum": sum(nums), "min": min(nums), "max": max(nums), "avg": sum(nums) / len(nums)}[n]
    phs = {}
    for a in assigns[:1]:
        for c in a.values():
            phs.update(c.binds)
    return Env({}, phs).val(x)


# ---------------------------------------------------------------------------- loading

def load_rules(paths) -> tuple[list[Rule], list[str]]:
    rules, errors, seen = [], [], set()
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, fs in os.walk(p):
                files += [os.path.join(root, f) for f in sorted(fs) if f.endswith((".yaral", ".yl2", ".yaral2"))]
        else:
            files.append(p)
    for f in files:
        try:
            with open(f, encoding="utf-8") as fh:
                text = fh.read()
            for r in parse_rules(text):
                if r.name in seen:
                    errors.append(f"{f}: duplicate rule {r.name}")
                    continue
                seen.add(r.name)
                rules.append(r)
        except (OSError, YaraLError) as e:
            errors.append(f"{f}: {e}")
    return rules, errors
