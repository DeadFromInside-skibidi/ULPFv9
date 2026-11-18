"""
ULPF Engine — Core Processing Layer
======================================
The engine is the heart of ULPF: detection, parsing, normalization, enrichment.
It has ZERO dependency on FastAPI, GUI, CLI, or any specific storage backend.
"""
from ulpf.engine.pipeline import Pipeline
from ulpf.engine.schema import new_unified_event, SCHEMA_DEFINITION

__all__ = ["Pipeline", "new_unified_event", "SCHEMA_DEFINITION"]
