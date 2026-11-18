"""
Parser Specification
======================
Deterministic, serialisable specification for a learned parser.
No exec(), no arbitrary code generation. The compiler produces a safe
regex + field-extractor tuple from this spec.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Field specification
# ---------------------------------------------------------------------------

@dataclass
class FieldSpec:
    """Specification of a single field to extract."""
    name: str               # e.g. "source.ip", "user.name"
    field_type: str          # e.g. "ipv4", "timestamp", "hostname", "enum", "pid"
    position: int | None = None
    regex: str | None = None        # per-field extraction regex (optional)
    enum_values: list[str] | None = None
    required: bool = True
    default_value: str | None = None
    original_key: str | None = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


# ---------------------------------------------------------------------------
# Match specification
# ---------------------------------------------------------------------------

@dataclass
class MatchSpec:
    """Defines how a raw event is matched to this parser."""
    required_tokens: list[str] = field(default_factory=list)
    anchors: list[str] = field(default_factory=list)
    fingerprint: str | None = None
    delimiter: str = " "
    min_token_count: int = 2
    max_token_count: int = 512
    kv_format: bool = False
    format_hints: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Parser specification
# ---------------------------------------------------------------------------

SPEC_VERSION = "1.0.0"


@dataclass
class ParserSpec:
    """
    Complete, deterministic specification for a learned parser.

    This is the artefact that the learning plane produces and the
    compiler consumes. It is serialisable to JSON and verifiable
    via its content hash.
    """
    parser_id: str = ""
    version: int = 1
    source_family: str = "application.custom"
    match: MatchSpec = field(default_factory=MatchSpec)
    fields: list[FieldSpec] = field(default_factory=list)
    template: str = ""              # structural template: "<TIMESTAMP> <HOST> <EVENT> user=<USERNAME>"
    sample_count: int = 0
    sample_hashes: list[str] = field(default_factory=list)
    created_at: str = ""
    engine_version: str = SPEC_VERSION
    validation_hash: str | None = None
    previous_version: int | None = None
    state: str = "candidate"        # candidate | validating | canary | active | drifting | retired
    confidence: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    # ---- Serialisation ----

    def to_dict(self) -> dict:
        """Serialise to a plain dict suitable for JSON."""
        return {
            "parser_id": self.parser_id,
            "version": self.version,
            "source_family": self.source_family,
            "match": self.match.to_dict(),
            "fields": [f.to_dict() for f in self.fields],
            "template": self.template,
            "sample_count": self.sample_count,
            "sample_hashes": self.sample_hashes,
            "created_at": self.created_at,
            "engine_version": self.engine_version,
            "validation_hash": self.validation_hash,
            "previous_version": self.previous_version,
            "state": self.state,
            "confidence": self.confidence,
            "metadata": self.metadata,
            "content_hash": self.content_hash,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, d: dict) -> ParserSpec:
        """Reconstruct from a serialised dict."""
        match_data = d.get("match", {})
        match = MatchSpec(**{k: v for k, v in match_data.items()
                            if k in MatchSpec.__dataclass_fields__})

        fields = [FieldSpec(**{k: v for k, v in fd.items()
                               if k in FieldSpec.__dataclass_fields__})
                  for fd in d.get("fields", [])]

        simple = {k: v for k, v in d.items()
                  if k in cls.__dataclass_fields__
                  and k not in ("match", "fields")}

        return cls(match=match, fields=fields, **simple)

    @classmethod
    def from_json(cls, text: str) -> ParserSpec:
        return cls.from_dict(json.loads(text))

    # ---- Content hash ----

    @property
    def content_hash(self) -> str:
        """
        SHA-256 of the canonical serialisation of this spec.
        Used for provenance and integrity verification.
        """
        canonical = json.dumps({
            "parser_id": self.parser_id,
            "version": self.version,
            "source_family": self.source_family,
            "template": self.template,
            "fields": [f.to_dict() for f in self.fields],
            "match": self.match.to_dict(),
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # ---- Helpers ----

    def field_names(self) -> list[str]:
        return [f.name for f in self.fields]

    def has_field(self, name: str) -> bool:
        return any(f.name == name for f in self.fields)

    def get_field(self, name: str) -> FieldSpec | None:
        return next((f for f in self.fields if f.name == name or getattr(f, "original_key", None) == name), None)

    def bump_version(self) -> ParserSpec:
        """Create a new version of this spec, preserving lineage."""
        import copy
        new = copy.deepcopy(self)
        new.previous_version = self.version
        new.version = self.version + 1
        new.state = "candidate"
        new.created_at = datetime.now(timezone.utc).isoformat()
        new.validation_hash = None
        return new

    def __repr__(self) -> str:
        return (f"ParserSpec(id={self.parser_id!r}, v={self.version}, "
                f"family={self.source_family!r}, fields={len(self.fields)}, "
                f"state={self.state!r})")
