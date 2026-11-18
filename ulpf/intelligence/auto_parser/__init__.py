"""
ULPF Auto-Parser
==================
Self-learning, deterministic, air-gapped parser compiler platform.

APG 2.0 adds:
  - StreamingTokenizer: bitmask-vectorised token classification
  - VectorisedClusterer: LSH-indexed structural clustering
  - NativeSynthesis: DFA/Aho-Corasick pattern compilation + hot-swap
  - StreamingAPGEngine: continuous streaming learning engine
"""

from ulpf.intelligence.auto_parser.engine import AutoParserEngine
from ulpf.intelligence.auto_parser.config import AutoParserConfig, OperatingProfile
from ulpf.intelligence.auto_parser.parser_spec import ParserSpec, FieldSpec

# APG 2.0 exports
from ulpf.intelligence.auto_parser.streaming_engine import StreamingAPGEngine
from ulpf.intelligence.auto_parser.streaming_tokenizer import StreamingTokenizer, StreamFrame
from ulpf.intelligence.auto_parser.vectorised_clusterer import VectorisedClusterer, StreamCluster
from ulpf.intelligence.auto_parser.native_synthesis import (
    HotSwapRegistry, NativeMatcherSet, AhoCorasickAutomaton,
    compile_dfa, DFATransitionTable,
)

__all__ = [
    # v1 (backward-compatible)
    "AutoParserEngine",
    "AutoParserConfig",
    "OperatingProfile",
    "ParserSpec",
    "FieldSpec",
    # APG 2.0
    "StreamingAPGEngine",
    "StreamingTokenizer",
    "StreamFrame",
    "VectorisedClusterer",
    "StreamCluster",
    "HotSwapRegistry",
    "NativeMatcherSet",
    "AhoCorasickAutomaton",
    "compile_dfa",
    "DFATransitionTable",
]
