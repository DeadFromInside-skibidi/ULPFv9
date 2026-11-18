"""
Parser Compiler
=================
Compiles a deterministic ParserSpec into an executable matcher.
No exec(), no dynamic code execution: the result is one anchored, compiled
regex with *named* groups plus a small extraction closure.

A spec's structure comes from its *layout* — an ordered list of elements:

    {"k": "lit",   "v": "auth-engine", "o": "", "c": ""}       invariant token
    {"k": "field", "v": "source.ip",   "o": "[", "c": "]"}     variable token
    {"k": "kv",    "v": "user.name",   "key": "user"}          key=value token

joined by the spec's delimiter. Specs learned before layouts existed are
converted from their template string and field positions.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Sequence

from ulpf.intelligence.auto_parser.parser_spec import ParserSpec

# Line-level KV extraction for kv_format specs. An unquoted value runs up to a
# tab, the next "<sep>key=", or the end of the line, so "msg=Login failed"
# keeps its spaces while "src=10.0.0.1 dst=10.0.0.2" still splits.
_KV_ANY = re.compile(r'([\w.\-]+)=("(?:[^"\\]|\\.)*"|.*?)(?=\t|[\s,;|]+[\w.\-]+=|[\s,;|]*$)')

_PLACEHOLDER = re.compile(r"^([*(\[<+~]*)\{([\w.\-]+)\}([*)>\]+~]*)$")
_WILDCARD = re.compile(r"^([*(\[<+~]*)<\*>([*)>\]+~]*)$")

KNOWN_MASKS = {
    "ipv4", "ipv6", "mac", "timestamp", "pid", "port",
    "numeric_id", "hex", "uuid", "email", "url", "domain",
    "username", "path"
}

_MASK_PATTERNS = {
    "ipv4": r"(?:\d{1,3}\.){3}\d{1,3}",
    "ipv6": r"(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}",
    "mac": r"(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}",
    "pid": r"\d{1,7}",
    "port": r"\d{1,5}",
    "numeric_id": r"\d+",
    "hex": r"0x[0-9a-fA-F]+",
    "uuid": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "email": r"[\w.+-]+@[\w-]+\.[\w.]+",
    "url": r"(?:https?|ftp)://\S+",
    "domain": r"[a-zA-Z][\w-]*(?:\.[\w-]+)+\.[a-zA-Z]{2,}",
    "username": r"[a-zA-Z][\w.-]+",
    "path": r"(?:/[\w.\-]+){2,}|[A-Z]:\\\S+",
}


class CompiledParser:
    """An executable parser compiled from a ParserSpec."""

    def __init__(self, spec: ParserSpec, pattern: re.Pattern,
                 extract_fn: Callable[[Sequence, str], dict[str, Any]], generic: bool = False):
        self.spec = spec
        self.parser_id = spec.parser_id
        self.version = spec.version
        self.pattern = pattern
        self._extract_fn = extract_fn
        # A generic parser has no invariant anchor; it may only be used via exact
        # fingerprint match, never for adaptive matching of arbitrary lines.
        self.generic = generic

    def parse(self, raw_line: str) -> dict[str, Any] | None:
        """Parse a line. Returns extracted fields dict, or None if no match."""
        match = self.pattern.match(raw_line)
        if not match:
            return None
        return self._extract_fn(match.groups(), raw_line)

    # The extraction as data for the native matcher (``_extract_spec``), or None
    extract_spec: dict | None = None

    def parse_groups(self, groups: Sequence, raw_line: str) -> dict[str, Any]:
        """Extract fields from the pattern's group values (captured by the native matcher)."""
        return self._extract_fn(groups, raw_line)

    def __repr__(self) -> str:
        return f"CompiledParser({self.parser_id}, v{self.version})"


class ParserCompiler:
    """Compiles ParserSpecs to CompiledParsers."""

    @staticmethod
    def compile(spec: ParserSpec) -> CompiledParser:
        if not spec.template and not spec.fields and not spec.match.format_hints.get("layout"):
            raise ValueError(f"Cannot compile empty spec: {spec.parser_id}")

        layout, delimiter, legacy = layout_for(spec)
        if not layout:
            raise ValueError(f"Spec {spec.parser_id} has no structural layout")
        pattern_str, group_fields = _build_regex(layout, delimiter, legacy)
        try:
            compiled = re.compile(pattern_str)
        except re.error as e:
            raise ValueError(f"Failed to compile parser regex: {e} (pattern: {pattern_str})")

        literals = sum(1 for el in layout if el["k"] == "lit") + sum(
            1 for el in layout if el["k"] == "group" for it in el["items"] if it["k"] == "lit")
        generic = literals == 0 and not spec.match.kv_format and len(delimiter) <= 1
        parser = CompiledParser(spec, compiled, _build_extractor(spec, group_fields), generic)
        parser.extract_spec = _extract_spec(spec, group_fields)
        return parser


# ---------------------------------------------------------------------------
# Layout resolution
# ---------------------------------------------------------------------------

def layout_for(spec: ParserSpec) -> tuple[list[dict], str, bool]:
    """Return (layout, delimiter, is_legacy) for a spec."""
    delimiter = spec.match.delimiter or " "
    layout = spec.match.format_hints.get("layout")
    if layout:
        return layout, delimiter, False
    return _legacy_layout(spec, delimiter), delimiter, True


def _legacy_layout(spec: ParserSpec, delimiter: str) -> list[dict]:
    """Rebuild a layout from a pre-layout template string and field positions."""
    by_pos: dict[int, str] = {}
    for f in spec.fields:
        if f.position is not None and f.position not in by_pos and not f.name.startswith("metadata."):
            by_pos[f.position] = f.name
    by_key = {f.original_key: f.name for f in spec.fields if f.original_key}

    layout: list[dict] = []
    pos = 0
    for part in spec.template.split():
        if len(delimiter) > 1 and part == delimiter:
            continue
        m = _PLACEHOLDER.match(part) or _WILDCARD.match(part)
        if m:
            opener, closer = m.group(1), m.group(m.lastindex)
            name = by_pos.get(pos) or (m.group(2) if m.re is _PLACEHOLDER else f"extensions.field_{pos}")
            layout.append({"k": "field", "v": name, "o": opener, "c": closer})
        elif part.startswith("<") and part.endswith(">") and part[1:-1].lower() in KNOWN_MASKS:
            mask = part[1:-1].lower()
            layout.append({"k": "field", "v": by_pos.get(pos) or mask, "o": "", "c": "", "mask": mask})
        elif part.endswith("=<*>"):
            key = part[:-4]
            layout.append({"k": "kv", "v": by_key.get(key, key), "key": key})
        else:
            layout.append({"k": "lit", "v": part, "o": "", "c": ""})
        pos += 1
    return layout


# ---------------------------------------------------------------------------
# Regex construction
# ---------------------------------------------------------------------------

def _build_regex(layout: list[dict], delimiter: str, legacy: bool) -> tuple[str, list[str]]:
    # Only a plain space is free whitespace: a tab separates fields whose
    # values may themselves contain spaces ("msg=Login failed for alice")
    space = delimiter == " " or (legacy and len(delimiter) == 1)
    if space:
        sep = r"\s+"
    else:
        sep = r"\s*" + re.escape(delimiter) + r"\s*"
    single_char = not space and len(delimiter) == 1
    # A value between single-char delimiters; quoted values may contain the delimiter
    cell = f'"[^"]*"|[^{re.escape(delimiter)}]*' if single_char else ".*?"

    parts: list[str] = []
    group_fields: list[str] = []
    last = len(layout) - 1
    for i, el in enumerate(layout):
        kind = el["k"]
        opener, closer = el.get("o", ""), el.get("c", "")
        if kind == "lit":
            parts.append(re.escape(f"{opener}{el['v']}{closer}"))
            continue
        if kind == "group":
            # Nested space-separated template inside one delimited segment
            sub: list[str] = []
            items = el["items"]
            for j, it in enumerate(items):
                if it["k"] == "lit":
                    sub.append(re.escape(it["v"]))
                    continue
                g = f"g{len(group_fields)}"
                group_fields.append(it["v"])
                span = int(it.get("span", 1))
                if i == last and j == len(items) - 1:
                    inner = ".+"
                else:
                    inner = r"\S+" + (rf"(?:\s+\S+){{{span - 1}}}" if span > 1 else "")
                sub.append(f"(?P<{g}>{inner})")
            parts.append(r"\s+".join(sub))
            continue

        g = f"g{len(group_fields)}"
        group_fields.append(el["v"])
        if kind == "kv":
            if i == last:
                # The final value runs to the end of the line ("msg=disk full on /var")
                val = r'"[^"]*"|.+' if space else r'"[^"]*"|.*'
            else:
                val = r'"[^"]*"|\S+' if space else cell
            parts.append(re.escape(el["key"]) + "=" + f"(?P<{g}>{val})")
            continue

        span = int(el.get("span", 1))
        if el.get("mask") in _MASK_PATTERNS:
            inner = _MASK_PATTERNS[el["mask"]]
        elif span > 1:
            # One field covering several delimiter-separated tokens (e.g. a date + time)
            tok = r"\S+" if space else (f"[^{re.escape(delimiter)}]*" if single_char else ".*?")
            inner = tok + f"(?:{sep}{tok}){{{span - 1}}}"
        elif closer:
            inner = f"[^{re.escape(closer[0])}]*" if len(closer) == 1 else ".*?"
        elif i == last:
            inner = ".+" if space else ".*"
        elif space:
            inner = r'"[^"]*"|\S+'
        else:
            inner = cell
        parts.append(re.escape(opener) + f"(?P<{g}>{inner})" + re.escape(closer))

    tail = r"(?:\s.*)?$" if (space and layout and layout[-1]["k"] == "lit") else r"\s*$"
    return r"^\s*" + sep.join(parts) + tail, group_fields


def _safe_text(v: Any) -> bool:
    return isinstance(v, str) and all(" " <= c <= "~" or c == "	" for c in v)


def _extract_spec(spec: ParserSpec, group_fields: list[str]) -> dict | None:
    """``_build_extractor`` as data (``ulpf_core`` ``apg::Extract``); None when a default is not
    a printable-ASCII string (the native strip/split would differ from Python's)."""
    defaults = {f.name: f.default_value for f in spec.fields if f.default_value is not None}
    if not all(_safe_text(v) for v in defaults.values()):
        return None
    kv_names = {f.original_key: f.name for f in spec.fields if f.original_key}
    return {"names": list(group_fields), "kv_format": bool(spec.match.kv_format),
            "kv_names": [list(x) for x in kv_names.items()], "defaults": [list(x) for x in defaults.items()]}


def _build_extractor(spec: ParserSpec, group_fields: list[str]) -> Callable[[Sequence, str], dict[str, Any]]:
    """Build a fast, safe extraction closure over the pattern's group values (g0, g1, ... in order)."""
    defaults = {f.name: f.default_value for f in spec.fields if f.default_value is not None}
    kv_names = {f.original_key: f.name for f in spec.fields if f.original_key}
    kv_format = spec.match.kv_format
    names = tuple(group_fields)

    def extract(groups: Sequence, raw_line: str) -> dict[str, Any]:
        result = dict(defaults)
        for name, val in zip(names, groups):
            if val is not None:
                val = val.strip()
                if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
                    val = val[1:-1]
                result[name] = val

        if kv_format:
            for key, val in _KV_ANY.findall(raw_line):
                result.setdefault(kv_names.get(key, key), val.strip('"'))

        # Nested metadata blocks, e.g. "ps_id:26156;env:prod;status:active"
        for k, v in list(result.items()):
            if isinstance(v, str) and ";" in v and (":" in v or "=" in v):
                for part in v.split(";"):
                    part = part.strip()
                    sep = ":" if ":" in part else "=" if "=" in part else None
                    if sep:
                        sk, sv = part.split(sep, 1)
                        if sk.strip():
                            result[f"metadata.{sk.strip()}"] = sv.strip()
        return result

    return extract
