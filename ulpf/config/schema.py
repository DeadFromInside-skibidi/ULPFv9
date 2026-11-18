"""
Typed option specs and a validator that reports YAML line numbers.

A spec is a dict ``{name: Opt}``. Nested sections use ``Opt(dict, spec=...)``,
lists of sections use ``Opt(list, item=...)``. Validation fills defaults,
rejects unknown keys and wrong types, and collects every problem with its
YAML path and line instead of stopping at the first.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml


@dataclass
class Opt:
    type: type | tuple
    default: Any = None
    required: bool = False
    choices: tuple | None = None
    spec: dict | None = None          # for nested dict sections
    item: Any = None                  # for lists: a type, or a spec dict
    help: str = ""
    min: float | None = None


@dataclass
class ConfigIssue:
    path: str
    line: int | None
    message: str

    def __str__(self) -> str:
        where = f"line {self.line}: " if self.line else ""
        return f"{where}{self.path}: {self.message}"


class ConfigError(ValueError):
    def __init__(self, issues: list[ConfigIssue]):
        self.issues = issues
        super().__init__("\n".join(str(i) for i in issues))


# ---------------------------------------------------------------------------
# YAML loading with line numbers
# ---------------------------------------------------------------------------

def load_yaml_with_lines(text: str) -> tuple[Any, dict[str, int]]:
    """Parse YAML and return (data, {dotted.path: line})."""
    node = yaml.compose(text, Loader=yaml.SafeLoader)
    lines: dict[str, int] = {}

    def walk(n, path: str):
        if n is None:
            return
        lines[path or "<root>"] = n.start_mark.line + 1
        if isinstance(n, yaml.MappingNode):
            for k, v in n.value:
                key = k.value
                p = f"{path}.{key}" if path else key
                lines[p] = k.start_mark.line + 1
                walk(v, p)
        elif isinstance(n, yaml.SequenceNode):
            for i, v in enumerate(n.value):
                walk(v, f"{path}[{i}]")

    walk(node, "")
    data = yaml.safe_load(text) if node is not None else {}
    return data, lines


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_TYPE_NAMES = {str: "string", int: "integer", float: "number", bool: "boolean",
               dict: "mapping", list: "list"}


def _type_name(t) -> str:
    if isinstance(t, tuple):
        return " or ".join(_type_name(x) for x in t)
    return _TYPE_NAMES.get(t, getattr(t, "__name__", str(t)))


def _type_ok(value: Any, t) -> bool:
    types = t if isinstance(t, tuple) else (t,)
    if isinstance(value, bool) and bool not in types:
        return False  # yaml `true` must not pass as an integer
    if float in types and isinstance(value, int) and not isinstance(value, bool):
        return True
    return isinstance(value, types)


@dataclass
class Validator:
    lines: dict[str, int] = field(default_factory=dict)
    issues: list[ConfigIssue] = field(default_factory=list)

    def error(self, path: str, message: str) -> None:
        line = self.lines.get(path)
        probe = path
        while line is None and ("." in probe or "[" in probe):
            probe = probe.rsplit(".", 1)[0] if "." in probe else probe.rsplit("[", 1)[0]
            line = self.lines.get(probe)
        self.issues.append(ConfigIssue(path, line, message))

    def section(self, data: Any, spec: dict, path: str) -> dict:
        if data is None:
            data = {}
        if not isinstance(data, dict):
            self.error(path, f"expected a mapping, got {type(data).__name__}")
            return {}
        out: dict = {}
        for key in data:
            if key not in spec:
                hint = _closest(key, spec)
                self.error(f"{path}.{key}" if path else key,
                           f"unknown option{f' (did you mean {hint!r}?)' if hint else ''}")
        for name, opt in spec.items():
            p = f"{path}.{name}" if path else name
            if name not in data or data[name] is None:
                if opt.required:
                    self.error(p, "is required")
                    continue
                if opt.spec is not None and opt.type is dict:
                    # An omitted section with required options is simply off (None);
                    # one whose options all have defaults is filled with them
                    if any(o.required for o in opt.spec.values()):
                        out[name] = None
                    else:
                        out[name] = self.section({}, opt.spec, p)
                else:
                    out[name] = _copy_default(opt.default)
                continue
            out[name] = self.value(data[name], opt, p)
        return out

    def value(self, v: Any, opt: Opt, path: str) -> Any:
        if opt.spec is not None and opt.type is dict:
            return self.section(v, opt.spec, path)
        if not _type_ok(v, opt.type):
            self.error(path, f"expected {_type_name(opt.type)}, got {type(v).__name__} ({v!r})")
            return _copy_default(opt.default)
        if opt.choices is not None and v not in opt.choices:
            self.error(path, f"must be one of {', '.join(map(str, opt.choices))} (got {v!r})")
        if opt.min is not None and isinstance(v, (int, float)) and v < opt.min:
            self.error(path, f"must be >= {opt.min} (got {v})")
        if opt.type is list and opt.item is not None:
            out = []
            for i, item in enumerate(v):
                p = f"{path}[{i}]"
                if isinstance(opt.item, dict):
                    out.append(self.section(item, opt.item, p))
                elif not _type_ok(item, opt.item):
                    self.error(p, f"expected {_type_name(opt.item)}, got {type(item).__name__}")
                else:
                    out.append(item)
            return out
        return v


def _copy_default(d):
    if isinstance(d, (dict, list)):
        import copy
        return copy.deepcopy(d)
    return d


def _closest(key: str, spec: dict) -> str | None:
    import difflib
    m = difflib.get_close_matches(str(key), list(spec), n=1, cutoff=0.7)
    return m[0] if m else None
