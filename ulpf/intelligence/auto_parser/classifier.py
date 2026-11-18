"""
Token Classifier
==================
Classifies each token position as **invariant** (part of the template)
or **variable** (a field to extract) by analysing multiple samples.

Given N samples of the same structural template:
- Position 0:  "FW01", "FW01", "FW01"    → invariant (same across all)
- Position 1:  "login", "login", "login"  → invariant
- Position 2:  "alice", "bob", "charlie"  → variable (differs)
- Position 3:  "src=10.1.1.1", ...        → partially variable (KV pair)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class TokenClassification:
    """Classification of a single token position."""
    position: int
    classification: str     # "invariant" | "variable" | "kv_pair"
    confidence: float       # 0.0–1.0
    invariant_value: str | None = None    # The constant value if invariant
    unique_ratio: float = 0.0             # fraction of unique values
    sample_count: int = 0
    kv_key: str | None = None             # If KV pair, the key

    @property
    def is_invariant(self) -> bool:
        return self.classification == "invariant"

    @property
    def is_variable(self) -> bool:
        return self.classification in ("variable", "kv_pair")

    def __repr__(self) -> str:
        val = f"={self.invariant_value!r}" if self.invariant_value else ""
        return f"Cls(pos={self.position}, {self.classification}{val}, conf={self.confidence:.0%})"


@dataclass
class ClassificationResult:
    """Result of classifying all positions in a set of samples."""
    classifications: list[TokenClassification] = field(default_factory=list)
    template_tokens: list[str] = field(default_factory=list)
    variable_positions: list[int] = field(default_factory=list)
    invariant_positions: list[int] = field(default_factory=list)

    @property
    def template_string(self) -> str:
        """Build the structural template from invariant/variable positions."""
        return " ".join(self.template_tokens)

    def __repr__(self) -> str:
        return (f"ClassificationResult(invariant={len(self.invariant_positions)}, "
                f"variable={len(self.variable_positions)})")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_positions(
    samples: list[list[str]],
    invariant_threshold: float = 0.90,
    kv_detect: bool = True,
) -> ClassificationResult:
    """
    Classify each token position across multiple samples.

    Args:
        samples: list of tokenised lines (each a list of token values)
        invariant_threshold: fraction of identical values required for invariant
        kv_detect: whether to detect key=value pairs

    Returns:
        ClassificationResult with per-position classifications
    """
    if not samples:
        return ClassificationResult()

    # Use the most common token count as the canonical length
    lengths = {}
    for row in samples:
        n = len(row)
        lengths[n] = lengths.get(n, 0) + 1
    canonical_length = max(lengths, key=lengths.get)

    # Filter to rows of canonical length
    consistent = [row for row in samples if len(row) == canonical_length]
    if not consistent:
        consistent = samples

    n_samples = len(consistent)
    result = ClassificationResult()

    for pos in range(canonical_length):
        values = [row[pos] for row in consistent if pos < len(row)]
        classification = _classify_single_position(
            pos, values, n_samples, invariant_threshold, kv_detect
        )
        result.classifications.append(classification)

        if classification.is_invariant:
            result.invariant_positions.append(pos)
            result.template_tokens.append(classification.invariant_value or "")
        else:
            result.variable_positions.append(pos)
            if classification.classification == "kv_pair" and classification.kv_key:
                result.template_tokens.append(f"{classification.kv_key}=<*>")
            else:
                result.template_tokens.append("<*>")

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _classify_single_position(
    position: int,
    values: list[str],
    total_samples: int,
    invariant_threshold: float,
    kv_detect: bool,
) -> TokenClassification:
    """Classify a single token position."""
    if not values:
        return TokenClassification(
            position=position, classification="variable",
            confidence=0.0, sample_count=0,
        )

    unique = set(values)
    unique_ratio = len(unique) / max(len(values), 1)
    n = len(values)

    # Check for KV pair pattern
    if kv_detect:
        kv_keys: dict[str, int] = {}
        for v in values:
            if "=" in v:
                key = v.split("=", 1)[0]
                kv_keys[key] = kv_keys.get(key, 0) + 1

        if kv_keys:
            best_key = max(kv_keys, key=kv_keys.get)
            key_ratio = kv_keys[best_key] / n
            if key_ratio >= invariant_threshold:
                return TokenClassification(
                    position=position,
                    classification="kv_pair",
                    confidence=key_ratio,
                    kv_key=best_key,
                    unique_ratio=unique_ratio,
                    sample_count=n,
                )

    # Check for invariant (all/most values identical)
    if len(unique) == 1:
        return TokenClassification(
            position=position,
            classification="invariant",
            confidence=1.0,
            invariant_value=values[0],
            unique_ratio=0.0,
            sample_count=n,
        )

    # Majority invariant check
    value_counts: dict[str, int] = {}
    for v in values:
        value_counts[v] = value_counts.get(v, 0) + 1
    most_common_value = max(value_counts, key=value_counts.get)
    most_common_ratio = value_counts[most_common_value] / n

    if most_common_ratio >= invariant_threshold:
        return TokenClassification(
            position=position,
            classification="invariant",
            confidence=most_common_ratio,
            invariant_value=most_common_value,
            unique_ratio=unique_ratio,
            sample_count=n,
        )

    # Variable
    return TokenClassification(
        position=position,
        classification="variable",
        confidence=1.0 - most_common_ratio,
        unique_ratio=unique_ratio,
        sample_count=n,
    )
