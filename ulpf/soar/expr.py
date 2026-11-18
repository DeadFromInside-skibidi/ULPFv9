"""
Safe expressions and ``{{ }}`` templates for playbooks.

Expressions are parsed with :mod:`ast` and evaluated by a whitelist walker:
literals, names/dotted paths into the run context, subscripts, comparisons
(``== != < <= > >= in not in``), ``and``/``or``/``not``, arithmetic ``+ - * / %``,
lists/tuples/dicts and a few pure functions (``len lower upper startswith
endswith contains any all int float str min max cidr_contains``). No calls on
objects, no attribute access on non-dicts, no comprehensions, no lambdas.
Inputs are bounded (length, depth, result size), so a hostile playbook or
event field cannot run code or exhaust memory.
"""
from __future__ import annotations

import ast
import ipaddress
import re

MAX_EXPR = 2000
MAX_DEPTH = 40
MAX_SEQ = 100_000
_TEMPLATE = re.compile(r"\{\{\s*(.{1,2000}?)\s*\}\}")


class ExprError(ValueError):
    pass


def _cidr_contains(cidr: str, ip: str) -> bool:
    try:
        return ipaddress.ip_address(str(ip)) in ipaddress.ip_network(str(cidr), strict=False)
    except ValueError:
        return False


_FUNCS = {
    "len": len, "lower": lambda s: str(s).lower(), "upper": lambda s: str(s).upper(),
    "startswith": lambda s, p: str(s).startswith(str(p)), "endswith": lambda s, p: str(s).endswith(str(p)),
    "contains": lambda c, x: x in c if c is not None else False, "any": any, "all": all,
    "int": int, "float": float, "str": str, "bool": bool, "min": min, "max": max, "abs": abs,
    "cidr_contains": _cidr_contains, "default": lambda v, d: d if v is None else v,
}

_CMP = {ast.Eq: lambda a, b: a == b, ast.NotEq: lambda a, b: a != b, ast.Lt: lambda a, b: a < b,
        ast.LtE: lambda a, b: a <= b, ast.Gt: lambda a, b: a > b, ast.GtE: lambda a, b: a >= b,
        ast.In: lambda a, b: a in b, ast.NotIn: lambda a, b: a not in b,
        ast.Is: lambda a, b: a is b, ast.IsNot: lambda a, b: a is not b}
_BIN = {ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b, ast.Mult: lambda a, b: a * b,
        ast.Div: lambda a, b: a / b, ast.Mod: lambda a, b: a % b, ast.FloorDiv: lambda a, b: a // b}


class _Missing:
    """Absent path: compares unequal to everything, falsy, never raises on further lookups."""

    def __bool__(self):
        return False

    def __eq__(self, other):
        return other is None or isinstance(other, _Missing)

    def __hash__(self):
        return 0

    def __repr__(self):
        return "None"


MISSING = _Missing()


def _lookup(obj, key):
    if isinstance(obj, dict):
        return obj.get(key, MISSING)
    if isinstance(obj, (list, tuple)) and isinstance(key, int) and -len(obj) <= key < len(obj):
        return obj[key]
    return MISSING


def _ev(node, ctx: dict, depth: int):
    if depth > MAX_DEPTH:
        raise ExprError("expression too deeply nested")
    d = depth + 1
    if isinstance(node, ast.Expression):
        return _ev(node.body, ctx, d)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in ("true", "True"):
            return True
        if node.id in ("false", "False"):
            return False
        if node.id in ("null", "None"):
            return None
        return ctx.get(node.id, MISSING)
    if isinstance(node, ast.Attribute):
        return _lookup(_ev(node.value, ctx, d), node.attr)
    if isinstance(node, ast.Subscript):
        return _lookup(_ev(node.value, ctx, d), _ev(node.slice, ctx, d))
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            v = True
            for x in node.values:
                v = _ev(x, ctx, d)
                if not v:
                    return v
            return v
        v = False
        for x in node.values:
            v = _ev(x, ctx, d)
            if v:
                return v
        return v
    if isinstance(node, ast.UnaryOp):
        v = _ev(node.operand, ctx, d)
        if isinstance(node.op, ast.Not):
            return not v
        if isinstance(node.op, ast.USub):
            return -v
        raise ExprError("unsupported unary operator")
    if isinstance(node, ast.Compare):
        left = _ev(node.left, ctx, d)
        for op, comp in zip(node.ops, node.comparators):
            right = _ev(comp, ctx, d)
            fn = _CMP.get(type(op))
            if fn is None:
                raise ExprError("unsupported comparison")
            try:
                if isinstance(left, _Missing) or isinstance(right, _Missing):
                    ok = fn(None if isinstance(left, _Missing) else left, None if isinstance(right, _Missing) else right) \
                        if type(op) in (ast.Eq, ast.NotEq, ast.Is, ast.IsNot) else False
                else:
                    ok = fn(left, right)
            except TypeError:
                ok = False
            if not ok:
                return False
            left = right
        return True
    if isinstance(node, ast.BinOp):
        fn = _BIN.get(type(node.op))
        if fn is None:
            raise ExprError("unsupported operator")
        a, b = _ev(node.left, ctx, d), _ev(node.right, ctx, d)
        if isinstance(node.op, ast.Mult) and (isinstance(a, (str, list)) or isinstance(b, (str, list))):
            raise ExprError("sequence repetition is not allowed")
        try:
            r = fn(a, b)
        except (TypeError, ZeroDivisionError) as e:
            raise ExprError(str(e)) from None
        if isinstance(r, (str, list)) and len(r) > MAX_SEQ:
            raise ExprError("result too large")
        return r
    if isinstance(node, (ast.List, ast.Tuple)):
        return [_ev(x, ctx, d) for x in node.elts]
    if isinstance(node, ast.Dict):
        return {_ev(k, ctx, d): _ev(v, ctx, d) for k, v in zip(node.keys, node.values)}
    if isinstance(node, ast.IfExp):
        return _ev(node.body, ctx, d) if _ev(node.test, ctx, d) else _ev(node.orelse, ctx, d)
    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name) or node.func.id not in _FUNCS or node.keywords:
            raise ExprError("only built-in functions may be called: " + ", ".join(sorted(_FUNCS)))
        args = [None if isinstance(a, _Missing) else a for a in (_ev(x, ctx, d) for x in node.args)]
        try:
            return _FUNCS[node.func.id](*args)
        except (TypeError, ValueError) as e:
            raise ExprError(f"{node.func.id}(): {e}") from None
    raise ExprError(f"unsupported syntax: {type(node).__name__}")


_cache: dict[str, ast.Expression] = {}


def compile_expr(text: str) -> ast.Expression:
    if len(text) > MAX_EXPR:
        raise ExprError("expression too long")
    tree = _cache.get(text)
    if tree is None:
        src = text.replace("&&", " and ").replace("||", " or ")
        try:
            tree = ast.parse(src.strip(), mode="eval")
        except SyntaxError as e:
            raise ExprError(f"syntax error in {text!r}: {e.msg}") from None
        if len(_cache) < 4096:
            _cache[text] = tree
    return tree


def evaluate(text: str, ctx: dict):
    v = _ev(compile_expr(text), ctx, 0)
    return None if isinstance(v, _Missing) else v


def render(value, ctx: dict):
    """Render ``{{ expr }}`` templates in strings, lists and dicts. A string that is exactly one
    template yields the raw value (a list stays a list)."""
    if isinstance(value, str):
        m = _TEMPLATE.fullmatch(value.strip())
        if m:
            return evaluate(m.group(1), ctx)
        return _TEMPLATE.sub(lambda mm: _s(evaluate(mm.group(1), ctx)), value)
    if isinstance(value, list):
        return [render(v, ctx) for v in value]
    if isinstance(value, dict):
        return {k: render(v, ctx) for k, v in value.items()}
    return value


def _s(v) -> str:
    return "" if v is None else str(v)
