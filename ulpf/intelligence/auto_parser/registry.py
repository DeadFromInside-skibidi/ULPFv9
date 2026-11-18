"""
Two-Level Parser Registry
===========================
Hot-path registry.
Exact Registry: O(1) exact match on structural fingerprint.
Adaptive Registry: anchored (non-generic) parsers, found through an *anchor
index* instead of trying every regex in turn.

Anchor index: every literal token of a parser's layout is bounded by the
parser's separator in any line it matches (whitespace, or ``\s*<delim>\s*``),
so splitting the line on that separator yields the literal exactly. Each
parser is indexed under its rarest literal; a line is split once per distinct
separator in the registry (a handful) and each token is one dict lookup. The
candidates are a superset of the parsers that can match, and are tried in
priority order (state, then parsers learned from the line's own source), so
the result is the same as the old ordered scan while the cost no longer grows
with the number of learned parsers. Parsers without an indexable literal (kv
or grouped layouts) are always candidates.

Thread model: the learning thread registers parsers while worker threads
look them up. Writers rebuild immutable snapshots under a lock; readers only
touch the current snapshot, so lookups never block and never observe a
dict being resized.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path

from ulpf.intelligence.auto_parser.parser_spec import ParserSpec
from ulpf.intelligence.auto_parser.compiler import CompiledParser, ParserCompiler, layout_for

logger = logging.getLogger(__name__)

_LIVE_STATES = frozenset(("active", "canary", "candidate"))
_STATE_ORDER = {"active": 0, "canary": 1, "candidate": 2}
# Below this many adaptive parsers every one is a candidate (splitting the line costs more)
_INDEX_MIN_PARSERS = 5


def _literals(parser: CompiledParser) -> tuple[str | None, list[str]]:
    """(separator key, literal tokens a matching line must contain). None key = whitespace."""
    try:
        layout, delimiter, legacy = layout_for(parser.spec)
    except Exception:
        return None, []
    space = delimiter == " " or (legacy and len(delimiter) == 1)
    out = []
    for el in layout:
        if el.get("k") != "lit":
            continue
        tok = f"{el.get('o', '')}{el['v']}{el.get('c', '')}"
        if not tok or tok != tok.strip():
            continue
        if space:
            if any(ch.isspace() for ch in tok):
                continue
        elif delimiter in tok:
            continue
        out.append(tok)
    return (None if space else delimiter), out


class AnchorIndex:
    """Literal-token index over the adaptive parsers (see module docstring)."""

    def __init__(self, parsers: tuple[CompiledParser, ...]):
        self.parsers = parsers
        self.rank = [(_STATE_ORDER.get(p.spec.state, 9), i) for i, p in enumerate(parsers)]
        self.sources = [p.spec.metadata.get("learned_source") or "" for p in parsers]
        self.linear = len(parsers) < _INDEX_MIN_PARSERS
        self.tables: dict[str | None, dict[str, tuple[int, ...]]] = {}
        unindexed: list[int] = []
        if not self.linear:
            lits = [_literals(p) for p in parsers]
            freq: dict[tuple, int] = {}
            for key, toks in lits:
                for t in set(toks):
                    freq[(key, t)] = freq.get((key, t), 0) + 1
            buckets: dict[str | None, dict[str, list[int]]] = {}
            for i, (key, toks) in enumerate(lits):
                if not toks:
                    unindexed.append(i)
                    continue
                anchor = min(toks, key=lambda t: (freq[(key, t)], -len(t)))
                buckets.setdefault(key, {}).setdefault(anchor, []).append(i)
            self.tables = {k: {t: tuple(v) for t, v in b.items()} for k, b in buckets.items()}
        self.unindexed = tuple(unindexed)
        self.native = _native_set(parsers, [r[0] for r in self.rank], self.sources)

    def candidates(self, line: str) -> list[int]:
        if self.linear:
            return list(range(len(self.parsers)))
        hits = set(self.unindexed)
        for key, table in self.tables.items():
            if key is None:
                for tok in line.split():
                    found = table.get(tok)
                    if found:
                        hits.update(found)
            else:
                for tok in line.split(key):
                    found = table.get(tok.strip())
                    if found:
                        hits.update(found)
        return list(hits)

    def match(self, line: str, source: str = "") -> CompiledParser | None:
        cands = self.candidates(line)
        if not cands:
            return None
        if len(cands) > 1:
            rank, sources = self.rank, self.sources
            # Most trusted state first; within it, parsers learned from this source first
            cands.sort(key=lambda i: (rank[i][0], sources[i] != source, rank[i][1]))
        parsers = self.parsers
        for i in cands:
            p = parsers[i]
            if p.pattern.match(line):
                return p
        return None

    def match_parse(self, line: str, source: str = "") -> tuple[CompiledParser | None, dict | None]:
        """(parser, fields) for the parser ``match`` picks; one native pass when the core is built."""
        if self.native is not None:
            hit = self.native.first_match(line, source)
            if hit is None:
                return None, None
            i, fields = hit
            if i >= 0:
                p = self.parsers[i]
                return p, fields if isinstance(fields, dict) else p.parse_groups(fields, line)
        p = self.match(line, source)
        return (p, p.parse(line)) if p is not None else (None, None)


def _native_set(parsers, ranks: list[int], sources: list[str]):
    """The parsers as a ``ulpf_core.ApgSet`` (Rust RegexSet), or None without the core."""
    if not parsers or os.environ.get("ULPF_NATIVE_APG", "1") == "0":
        return None
    try:
        from ulpf.ulpf_core import ApgSet
    except ImportError:
        return None
    return ApgSet([p.pattern.pattern for p in parsers], ranks, sources,
                  [None if p.extract_spec is None else json.dumps(p.extract_spec) for p in parsers])


def default_learned_dir() -> str:
    """Resolve the learned-parsers directory.

    ``ULPF_LEARNED_PARSERS_DIR`` overrides; otherwise ``<data dir>/learned_parsers``,
    alongside the event store — learned parsers are runtime state and never
    written into the source tree.
    """
    env = os.environ.get("ULPF_LEARNED_PARSERS_DIR")
    if env:
        return env
    from ulpf.platform.paths import get_data_dir
    return str(get_data_dir() / "learned_parsers")


class AutoParserRegistry:
    """Two-level hot-path registry for auto-generated parsers with persistent disk storage."""

    def __init__(self, learned_dir: str | Path | None = None):
        self.learned_dir = str(learned_dir) if learned_dir else default_learned_dir()
        self._lock = threading.Lock()
        self._exact_registry: dict[str, CompiledParser] = {}
        self._parsers: dict[str, CompiledParser] = {}
        self._specs: dict[str, ParserSpec] = {}
        self._adaptive: tuple[CompiledParser, ...] = ()
        self._index = AnchorIndex(())
        self.has_generic = False
        self.version = 0
        self._disk_state: dict[str, float] = {}
        self.load_from_disk()

    def _scan_disk(self) -> dict[str, float]:
        try:
            return {e.name: e.stat().st_mtime for e in os.scandir(self.learned_dir)
                    if e.name.endswith(".json") and e.is_file()}
        except OSError:
            return {}

    def reload_if_changed(self) -> int:
        """Pick up specs added/updated on disk by other processes. Returns specs (re)loaded."""
        current = self._scan_disk()
        if current == self._disk_state:
            return 0
        changed = [n for n, m in current.items() if self._disk_state.get(n) != m]
        self._disk_state = current
        loaded = 0
        for name in changed:
            try:
                spec = self._read_spec(os.path.join(self.learned_dir, name))
                if spec is None:
                    continue
                existing = self._specs.get(spec.parser_id)
                if existing is not None and existing.content_hash == spec.content_hash \
                        and existing.state == spec.state:
                    continue
                self.register(spec, save_to_disk=False)
                loaded += 1
            except Exception as e:
                logger.debug(f"Skipping spec {name} during reload: {e}")
        return loaded

    def load_from_disk(self) -> int:
        """Load all saved parser specifications from the learned-parsers directory."""
        if not os.path.isdir(self.learned_dir):
            return 0
        self._disk_state = self._scan_disk()
        loaded = 0
        for fname in sorted(os.listdir(self.learned_dir)):
            if fname.endswith(".json"):
                fpath = os.path.join(self.learned_dir, fname)
                try:
                    spec = self._read_spec(fpath)
                    if spec is not None:
                        self.register(spec, save_to_disk=False)
                        loaded += 1
                except Exception as e:
                    logger.warning(f"Skipping invalid parser spec {fpath}: {e}")
        return loaded

    _provenance = None
    # Defence mode: a spec whose signature fields were stripped is refused, not loaded as "unsigned"
    require_signed = False

    def _read_spec(self, fpath: str) -> ParserSpec | None:
        """Load a spec file; signed specs whose signature does not verify are rejected."""
        from ulpf.intelligence.auto_parser.provenance import ProvenanceManager, is_signed
        with open(fpath, "r", encoding="utf-8") as f:
            spec = ParserSpec.from_json(f.read())
        if not is_signed(spec):
            if self.require_signed:
                logger.warning(f"Rejecting unsigned parser spec {fpath} (signatures are required)")
                return None
            return spec
        if AutoParserRegistry._provenance is None:
            AutoParserRegistry._provenance = ProvenanceManager()
        if AutoParserRegistry._provenance.verify_parser_spec(spec) is False:
            logger.warning(f"Rejecting tampered parser spec {fpath} (signature mismatch)")
            return None
        return spec

    def require_signatures(self) -> int:
        """Refuse unsigned specs from now on and drop those already loaded. Returns how many were dropped."""
        from ulpf.intelligence.auto_parser.provenance import is_signed
        self.require_signed = True
        with self._lock:
            unsigned = {pid for pid, s in self._specs.items() if not is_signed(s)}
            if not unsigned:
                return 0
            specs = {k: v for k, v in self._specs.items() if k not in unsigned}
            parsers = {k: v for k, v in self._parsers.items() if k not in unsigned}
            exact = {fp: p for fp, p in self._exact_registry.items() if p.parser_id not in unsigned}
            self._publish(specs, parsers, exact)
        for pid in sorted(unsigned):
            logger.warning(f"Dropped unsigned parser spec {pid} (signatures are required)")
        return len(unsigned)

    def save_parser(self, spec: ParserSpec) -> str:
        """Atomically persist a parser specification to the learned-parsers directory."""
        os.makedirs(self.learned_dir, exist_ok=True)
        fpath = os.path.join(self.learned_dir, f"{spec.parser_id}.json")
        payload = spec.to_json()
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                if f.read() == payload:
                    return fpath  # identical spec already saved (e.g. by another worker)
        except OSError:
            pass
        tmp = f"{fpath}.{os.getpid()}.{threading.get_ident()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(payload)
        # Windows refuses to replace a file another process has open for reading
        for attempt in range(10):
            try:
                os.replace(tmp, fpath)
                return fpath
            except PermissionError:
                if attempt == 9:
                    os.remove(tmp)
                    raise
                time.sleep(0.05)
        return fpath

    def register(self, spec: ParserSpec, compiled: CompiledParser | None = None,
                 save_to_disk: bool = False) -> CompiledParser:
        """Register (or replace) a parser atomically, optionally persisting it."""
        if compiled is None:
            compiled = ParserCompiler.compile(spec)
        with self._lock:
            specs = dict(self._specs)
            parsers = dict(self._parsers)
            exact = dict(self._exact_registry)
            old = parsers.get(spec.parser_id)
            if old is not None and old.spec.match.fingerprint:
                exact.pop(old.spec.match.fingerprint, None)
            specs[spec.parser_id] = spec
            parsers[spec.parser_id] = compiled
            if spec.match.fingerprint:
                exact[spec.match.fingerprint] = compiled
            self._publish(specs, parsers, exact)
        if save_to_disk:
            try:
                self.save_parser(spec)
            except OSError as e:
                logger.warning(f"Could not persist parser {spec.parser_id} to disk: {e}")
        logger.debug(f"Registered auto-parser {spec.parser_id} v{spec.version} ({spec.state})")
        return compiled

    def refresh(self) -> None:
        """Rebuild lookup snapshots after a spec's lifecycle state changed."""
        with self._lock:
            self._publish(dict(self._specs), dict(self._parsers), dict(self._exact_registry))

    def _publish(self, specs: dict, parsers: dict, exact: dict) -> None:
        self._specs = specs
        self._parsers = parsers
        self._exact_registry = exact
        # Most-trusted first: active, then canary, then candidates
        adaptive = tuple(sorted(
            (p for p in parsers.values() if p.spec.state in _LIVE_STATES and not p.generic),
            key=lambda p: _STATE_ORDER.get(p.spec.state, 9)))
        self._index = AnchorIndex(adaptive)       # readers take one snapshot: index and parsers agree
        self._adaptive = adaptive
        self.has_generic = any(p.generic and p.spec.state in _LIVE_STATES for p in exact.values())
        self.version += 1

    def has_parsers(self) -> bool:
        return bool(self._parsers)

    def get_exact_match(self, fingerprint: str) -> CompiledParser | None:
        """O(1) exact structural match (retired parsers excluded)."""
        p = self._exact_registry.get(fingerprint)
        if p is not None and p.spec.state in _LIVE_STATES:
            return p
        return None

    def get_adaptive_match(self, raw_line: str, family_hint: str = "", source: str = "") -> CompiledParser | None:
        """Most trusted anchored live parser whose regex matches the line (``source``: the
        line's source, whose own learned parsers win ties)."""
        return self._index.match(raw_line, source)

    def adaptive_parsers(self) -> tuple[CompiledParser, ...]:
        """The live anchored parsers, most trusted first (one consistent snapshot)."""
        return self._adaptive

    def get_adaptive_parse(self, raw_line: str, source: str = "") -> tuple[CompiledParser | None, dict | None]:
        """``get_adaptive_match`` and that parser's fields in one step (native when built)."""
        return self._index.match_parse(raw_line, source)

    def get_spec(self, parser_id: str) -> ParserSpec | None:
        return self._specs.get(parser_id)

    def list_parsers(self) -> list[ParserSpec]:
        return list(self._specs.values())

    def list_all(self) -> list[ParserSpec]:
        """Alias for API route compatibility."""
        return list(self._specs.values())
