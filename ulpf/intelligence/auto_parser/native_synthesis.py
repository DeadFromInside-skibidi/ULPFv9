"""
Native Parser Synthesis & Hot-Reload (APG 2.0)
=================================================
Synthesises compiled matchers as serialised DFA transition tables and
Aho-Corasick multi-pattern automata — without requiring an external Rust
or C compiler on the host.

Architecture:
  1. **DFA Transition Tables**: each ParserSpec's layout is compiled into a
     deterministic finite automaton table (list of (state, char-class, next-state)
     triples) that can be evaluated in a tight loop without regex backtracking.
  2. **Aho-Corasick Multi-Pattern Automaton**: all active parser literal anchors
     are compiled into a single Aho-Corasick automaton for O(n) multi-pattern
     matching across the entire input, replacing the per-parser regex probe.
  3. **Hot-Swap via Atomic Snapshots**: compiled matcher tables are immutable
     snapshots swapped atomically (Python: immutable tuple replacement under a
     lock; Rust: ArcSwap semantics) — zero-downtime parser table replacement.

The synthesised tables are pure data (lists/dicts of ints/strings) and are
serialisable to JSON or msgpack for transfer to Rust/Wasm workers.

Thread-safety: ``NativeMatcherSet`` snapshots are immutable and safe to
share across threads; only ``HotSwapRegistry`` mutates state under a lock.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ulpf.intelligence.auto_parser.parser_spec import ParserSpec
from ulpf.intelligence.auto_parser.compiler import (
    ParserCompiler, CompiledParser, layout_for, _MASK_PATTERNS,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DFA Transition Table
# ---------------------------------------------------------------------------
# Character classes for the DFA
CHAR_WHITESPACE = 0
CHAR_ALPHA = 1
CHAR_DIGIT = 2
CHAR_DOT = 3
CHAR_COLON = 4
CHAR_DASH = 5
CHAR_EQUALS = 6
CHAR_QUOTE = 7
CHAR_BRACKET_O = 8    # [, <, (
CHAR_BRACKET_C = 9    # ], >, )
CHAR_OTHER = 10
CHAR_EOF = 11
NUM_CHAR_CLASSES = 12

# State types
STATE_START = 0
STATE_LITERAL = 1
STATE_FIELD = 2
STATE_KV_KEY = 3
STATE_KV_VALUE = 4
STATE_ACCEPT = 5
STATE_REJECT = 6


def _char_class(ch: str) -> int:
    """Classify a character into a DFA character class."""
    if ch in (' ', '\t', '\r', '\n'):
        return CHAR_WHITESPACE
    if ch.isalpha() or ch == '_':
        return CHAR_ALPHA
    if ch.isdigit():
        return CHAR_DIGIT
    if ch == '.':
        return CHAR_DOT
    if ch == ':':
        return CHAR_COLON
    if ch == '-':
        return CHAR_DASH
    if ch == '=':
        return CHAR_EQUALS
    if ch in ('"', "'"):
        return CHAR_QUOTE
    if ch in ('[', '<', '(', '{'):
        return CHAR_BRACKET_O
    if ch in (']', '>', ')', '}'):
        return CHAR_BRACKET_C
    return CHAR_OTHER


@dataclass
class DFATransitionTable:
    """
    A deterministic finite automaton compiled from a ParserSpec layout.

    The table is a flat list of transitions:
        transitions[state * NUM_CHAR_CLASSES + char_class] = next_state

    Plus metadata mapping states to field extraction:
        field_states: state → field_name (which field this state captures)
        literal_states: state → expected_literal (for invariant matching)
    """
    spec_id: str
    num_states: int
    transitions: list[int]        # flat: [num_states × NUM_CHAR_CLASSES]
    field_states: dict[int, str]  # state → field name
    literal_states: dict[int, str]  # state → expected literal
    accept_states: set[int]
    delimiter: str = " "
    version: int = 0

    def serialise(self) -> dict[str, Any]:
        """Serialise to a JSON-compatible dict for cross-process transfer."""
        return {
            "spec_id": self.spec_id,
            "num_states": self.num_states,
            "transitions": self.transitions,
            "field_states": {str(k): v for k, v in self.field_states.items()},
            "literal_states": {str(k): v for k, v in self.literal_states.items()},
            "accept_states": list(self.accept_states),
            "delimiter": self.delimiter,
            "version": self.version,
        }

    @classmethod
    def deserialise(cls, d: dict[str, Any]) -> DFATransitionTable:
        return cls(
            spec_id=d["spec_id"],
            num_states=d["num_states"],
            transitions=d["transitions"],
            field_states={int(k): v for k, v in d["field_states"].items()},
            literal_states={int(k): v for k, v in d["literal_states"].items()},
            accept_states=set(d["accept_states"]),
            delimiter=d.get("delimiter", " "),
            version=d.get("version", 0),
        )


def compile_dfa(spec: ParserSpec) -> DFATransitionTable:
    """
    Compile a ParserSpec into a DFA transition table.

    The DFA models the parser's layout as a sequence of states:
    for each layout element, a state (or group of states) consumes
    the expected token — literal, field, or key=value.
    """
    layout, delimiter, legacy = layout_for(spec)
    if not layout:
        raise ValueError(f"Empty layout for spec {spec.parser_id}")

    states: list[list[int]] = []  # state → [next_state per char_class]
    field_map: dict[int, str] = {}
    literal_map: dict[int, str] = {}
    accept: set[int] = set()

    # State 0: start (skip leading whitespace)
    start = _new_state(states)

    current = start
    for i, el in enumerate(layout):
        kind = el.get("k", "")

        if kind == "lit":
            # Literal matching state
            lit_state = _new_state(states)
            literal_map[lit_state] = f"{el.get('o', '')}{el['v']}{el.get('c', '')}"
            # Transition from current to literal on any alpha/digit
            for cc in range(NUM_CHAR_CLASSES):
                if cc != CHAR_WHITESPACE:
                    states[current][cc] = lit_state
            # Separator state after literal
            sep_state = _new_state(states)
            for cc in range(NUM_CHAR_CLASSES):
                states[lit_state][cc] = sep_state
            current = sep_state

        elif kind == "field":
            # Field capture state
            field_state = _new_state(states)
            field_map[field_state] = el["v"]
            # Transition from current to field on any non-whitespace
            for cc in range(NUM_CHAR_CLASSES):
                if cc != CHAR_WHITESPACE:
                    states[current][cc] = field_state
            # Self-loop on field content (non-separator chars)
            for cc in range(NUM_CHAR_CLASSES):
                if cc != CHAR_WHITESPACE:
                    states[field_state][cc] = field_state
            # Separator state after field
            sep_state = _new_state(states)
            states[field_state][CHAR_WHITESPACE] = sep_state
            for cc in range(NUM_CHAR_CLASSES):
                if cc != CHAR_WHITESPACE:
                    states[sep_state][cc] = sep_state
            current = sep_state

        elif kind == "kv":
            # KV pair: key=value
            kv_key_state = _new_state(states)
            literal_map[kv_key_state] = el["key"]
            kv_eq_state = _new_state(states)
            kv_val_state = _new_state(states)
            field_map[kv_val_state] = el["v"]

            for cc in range(NUM_CHAR_CLASSES):
                if cc != CHAR_WHITESPACE:
                    states[current][cc] = kv_key_state
            for cc in range(NUM_CHAR_CLASSES):
                states[kv_key_state][cc] = kv_key_state
            states[kv_key_state][CHAR_EQUALS] = kv_eq_state
            for cc in range(NUM_CHAR_CLASSES):
                states[kv_eq_state][cc] = kv_val_state
            for cc in range(NUM_CHAR_CLASSES):
                if cc != CHAR_WHITESPACE:
                    states[kv_val_state][cc] = kv_val_state
            # Separator
            sep_state = _new_state(states)
            states[kv_val_state][CHAR_WHITESPACE] = sep_state
            current = sep_state

    # Mark final state as accept
    accept.add(current)
    # Also add EOF transitions to accept
    for s in range(len(states)):
        if states[s][CHAR_EOF] == STATE_REJECT:
            if s == current or s in accept:
                states[s][CHAR_EOF] = current

    # Flatten transitions
    flat = []
    for row in states:
        flat.extend(row)

    return DFATransitionTable(
        spec_id=spec.parser_id,
        num_states=len(states),
        transitions=flat,
        field_states=field_map,
        literal_states=literal_map,
        accept_states=accept,
        delimiter=delimiter,
        version=spec.version,
    )


def _new_state(states: list[list[int]]) -> int:
    """Add a new state to the DFA, returning its index."""
    idx = len(states)
    states.append([STATE_REJECT] * NUM_CHAR_CLASSES)
    return idx


# ---------------------------------------------------------------------------
# Aho-Corasick Multi-Pattern Automaton
# ---------------------------------------------------------------------------

@dataclass
class AhoCorasickNode:
    """A single node in the Aho-Corasick trie."""
    goto: dict[str, int] = field(default_factory=dict)
    fail: int = 0
    output: list[str] = field(default_factory=list)  # parser IDs that match here


class AhoCorasickAutomaton:
    """
    Multi-pattern string matching automaton (Aho-Corasick).

    Given all literal anchors from active parsers, builds a single automaton
    that scans the input once (O(n + m)) to find all parsers whose anchor
    literals appear in the line.

    This replaces the per-parser regex probe in the hot path.
    """

    def __init__(self) -> None:
        self._nodes: list[AhoCorasickNode] = [AhoCorasickNode()]  # root = 0
        self._built = False
        self._pattern_count = 0

    @property
    def pattern_count(self) -> int:
        return self._pattern_count

    def add_pattern(self, pattern: str, parser_id: str) -> None:
        """Add a literal pattern associated with a parser ID."""
        if self._built:
            raise RuntimeError("Cannot add patterns after build()")

        current = 0
        for ch in pattern:
            if ch not in self._nodes[current].goto:
                new_idx = len(self._nodes)
                self._nodes.append(AhoCorasickNode())
                self._nodes[current].goto[ch] = new_idx
            current = self._nodes[current].goto[ch]
        self._nodes[current].output.append(parser_id)
        self._pattern_count += 1

    def build(self) -> None:
        """Build failure links (BFS) to complete the automaton."""
        if self._built:
            return
        from collections import deque

        queue = deque()
        # Initialise depth-1 nodes
        for ch, s in self._nodes[0].goto.items():
            self._nodes[s].fail = 0
            queue.append(s)

        # BFS to build failure links
        while queue:
            r = queue.popleft()
            for ch, s in self._nodes[r].goto.items():
                queue.append(s)
                state = self._nodes[r].fail
                while state != 0 and ch not in self._nodes[state].goto:
                    state = self._nodes[state].fail
                self._nodes[s].fail = self._nodes[state].goto.get(ch, 0)
                if self._nodes[s].fail == s:
                    self._nodes[s].fail = 0
                # Merge outputs from failure chain
                self._nodes[s].output = (
                    self._nodes[s].output + self._nodes[self._nodes[s].fail].output
                )

        self._built = True

    def search(self, text: str) -> set[str]:
        """
        Search text for all matching patterns. Returns set of parser IDs.

        O(n + m) where n = len(text), m = total output count.
        """
        if not self._built:
            self.build()

        results: set[str] = set()
        state = 0

        for ch in text:
            while state != 0 and ch not in self._nodes[state].goto:
                state = self._nodes[state].fail
            state = self._nodes[state].goto.get(ch, 0)
            if self._nodes[state].output:
                results.update(self._nodes[state].output)

        return results

    def serialise(self) -> dict[str, Any]:
        """Serialise to a JSON-compatible dict."""
        return {
            "nodes": [
                {
                    "goto": node.goto,
                    "fail": node.fail,
                    "output": node.output,
                }
                for node in self._nodes
            ],
            "built": self._built,
            "pattern_count": self._pattern_count,
        }


# ---------------------------------------------------------------------------
# Native Matcher Set (Immutable Snapshot)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NativeMatcherSet:
    """
    Immutable snapshot of all compiled matchers for the hot path.

    Combines:
      - Per-parser DFA tables (for field extraction)
      - Aho-Corasick automaton (for O(n) multi-pattern dispatch)
      - Compiled regex parsers (fallback for complex patterns)

    This is the atomic unit that is swapped in ``HotSwapRegistry``.
    """
    version: int
    dfa_tables: dict[str, DFATransitionTable]   # parser_id → DFA
    aho_corasick: AhoCorasickAutomaton
    compiled_parsers: dict[str, CompiledParser]  # parser_id → regex fallback
    parser_priority: tuple[str, ...]             # ordered by trust (active > canary)
    created_at: float                            # monotonic timestamp
    anchored: frozenset[str] = frozenset()       # parsers with Aho-Corasick anchors
    native: Any = None                           # ulpf_core.ApgSet over native_ids, or None
    native_ids: tuple[str, ...] = ()

    def dispatch(self, raw_line: str) -> CompiledParser | None:
        """The most trusted parser (priority order) whose pattern matches the line."""
        return self.dispatch_parse(raw_line)[0]

    def dispatch_parse(self, raw_line: str) -> tuple[CompiledParser | None, dict | None]:
        """
        (parser, fields) for the most trusted matching parser:
          1. Native: one Rust RegexSet pass over every parser, captures from the winner
          2. Otherwise Aho-Corasick prefilter (parsers with anchors must have one in the
             line), then regex verification in priority order
        """
        if self.native is not None:
            hit = self.native.first_match(raw_line, "")
            if hit is None:
                return None, None
            i, fields = hit
            if i >= 0:
                parser = self.compiled_parsers[self.native_ids[i]]
                return parser, fields if isinstance(fields, dict) else parser.parse_groups(fields, raw_line)

        candidates = self.aho_corasick.search(raw_line)
        for pid in self.parser_priority:
            if pid in self.anchored and pid not in candidates:
                continue
            parser = self.compiled_parsers.get(pid)
            if parser and parser.pattern.match(raw_line):
                return parser, parser.parse(raw_line)
        return None, None


def _native_set(parsers: list[CompiledParser]):
    """Parsers in priority order as a ``ulpf_core.ApgSet`` (first match wins), or None."""
    from ulpf.intelligence.auto_parser.registry import _native_set as build
    return build(tuple(parsers), list(range(len(parsers))), [""] * len(parsers))


# ---------------------------------------------------------------------------
# Hot-Swap Registry (APG 2.0)
# ---------------------------------------------------------------------------

class HotSwapRegistry:
    """
    Atomic hot-swap of compiled matcher tables.

    Implements ArcSwap semantics in Python: readers take a snapshot reference
    (no lock), writers build a new snapshot under a lock and atomically
    replace the reference.  Zero-downtime parser table replacement.

    Lifecycle:
      1. ``register()`` or ``unregister()`` queue a rebuild
      2. ``_rebuild()`` constructs a new ``NativeMatcherSet``
      3. ``_swap()`` atomically replaces ``self._current``
      4. Readers see the new set on their next ``dispatch()`` call
    """

    _STATE_ORDER = {"active": 0, "canary": 1, "candidate": 2}
    _LIVE_STATES = frozenset(("active", "canary", "candidate"))

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._specs: dict[str, ParserSpec] = {}
        self._compiled: dict[str, CompiledParser] = {}
        self._version = 0
        # The immutable snapshot — readers grab this without locking
        self._current: NativeMatcherSet = self._build_empty()
        self._rebuild_pending = False

    @property
    def current(self) -> NativeMatcherSet:
        """The current immutable matcher set (lock-free read)."""
        return self._current

    @property
    def version(self) -> int:
        return self._version

    def register(self, spec: ParserSpec, compiled: CompiledParser | None = None) -> CompiledParser:
        """Register a parser and trigger a hot-swap rebuild."""
        if compiled is None:
            compiled = ParserCompiler.compile(spec)

        with self._lock:
            self._specs[spec.parser_id] = spec
            self._compiled[spec.parser_id] = compiled
            self._rebuild()

        return compiled

    def replace_all(self, parsers: list[CompiledParser]) -> None:
        """Swap in exactly these parsers (one rebuild)."""
        with self._lock:
            self._specs = {p.parser_id: p.spec for p in parsers}
            self._compiled = {p.parser_id: p for p in parsers}
            self._rebuild()

    def unregister(self, parser_id: str) -> None:
        """Remove a parser and trigger a hot-swap rebuild."""
        with self._lock:
            self._specs.pop(parser_id, None)
            self._compiled.pop(parser_id, None)
            self._rebuild()

    def dispatch(self, raw_line: str) -> CompiledParser | None:
        """Dispatch a line using the current snapshot (lock-free)."""
        return self._current.dispatch(raw_line)

    def _rebuild(self) -> None:
        """Build a new NativeMatcherSet and atomically swap it in."""
        self._version += 1

        # Build Aho-Corasick from all live parsers' literal anchors
        ac = AhoCorasickAutomaton()
        live_specs: list[tuple[str, ParserSpec]] = []
        anchored: set[str] = set()

        for pid, spec in self._specs.items():
            if spec.state not in self._LIVE_STATES:
                continue
            live_specs.append((pid, spec))
            # Extract literal anchors for AC
            try:
                layout, delimiter, legacy = layout_for(spec)
                for el in (layout or []):
                    if el.get("k") == "lit":
                        token = f"{el.get('o', '')}{el['v']}{el.get('c', '')}"
                        if token and len(token) >= 2:
                            ac.add_pattern(token, pid)
                            anchored.add(pid)
            except Exception:
                pass

        ac.build()

        # Build DFA tables
        dfa_tables: dict[str, DFATransitionTable] = {}
        for pid, spec in live_specs:
            try:
                dfa_tables[pid] = compile_dfa(spec)
            except Exception as e:
                logger.debug(f"DFA compilation failed for {pid}: {e}")

        # Priority ordering
        priority = tuple(sorted(
            [pid for pid, _ in live_specs],
            key=lambda pid: (
                self._STATE_ORDER.get(self._specs[pid].state, 9),
                pid,
            ),
        ))

        # Build compiled parser dict (only live)
        compiled = {pid: self._compiled[pid] for pid, _ in live_specs
                    if pid in self._compiled}
        native_ids = tuple(pid for pid in priority if pid in compiled)

        new_set = NativeMatcherSet(
            version=self._version,
            dfa_tables=dfa_tables,
            aho_corasick=ac,
            compiled_parsers=compiled,
            parser_priority=priority,
            created_at=time.monotonic(),
            anchored=frozenset(anchored),
            native=_native_set([compiled[pid] for pid in native_ids]),
            native_ids=native_ids,
        )

        # Atomic swap
        self._current = new_set
        logger.debug(f"Hot-swapped matcher set v{self._version}: "
                     f"{len(compiled)} parsers, {ac.pattern_count} AC patterns")

    def _build_empty(self) -> NativeMatcherSet:
        ac = AhoCorasickAutomaton()
        ac.build()
        return NativeMatcherSet(
            version=0,
            dfa_tables={},
            aho_corasick=ac,
            compiled_parsers={},
            parser_priority=(),
            created_at=time.monotonic(),
        )

    def get_stats(self) -> dict[str, Any]:
        current = self._current
        return {
            "version": current.version,
            "parser_count": len(current.compiled_parsers),
            "ac_patterns": current.aho_corasick.pattern_count,
            "dfa_tables": len(current.dfa_tables),
            "priority_order": list(current.parser_priority),
        }
