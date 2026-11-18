"""
Runtime tuning for high-throughput processes.

Every parsed event allocates a dozen small container objects. With CPython's
default GC thresholds (700 allocations) the cyclic collector runs constantly
and repeatedly rescans the long-lived heap; measured cost is ~15-20 % of
pipeline time. Entry points (CLI, desktop app, workers) call ``tune_gc()``
once startup imports are done: the startup heap is frozen out of collection
and gen-0 collections become ~70x rarer. Reference counting still frees
events immediately; only cycle detection is deferred.
"""
from __future__ import annotations

import gc

_tuned = False


def tune_gc(gen0_threshold: int = 50_000) -> None:
    global _tuned
    if _tuned:
        return
    gc.collect()
    gc.freeze()
    gc.set_threshold(gen0_threshold, 50, 100)
    _tuned = True
