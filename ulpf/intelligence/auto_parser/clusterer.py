"""
Structural Clusterer
======================
Clusters masked log messages by structural fingerprint.
Uses fingerprint hash for O(1) exact match, then falls back to
similarity-based grouping for unknown families.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class TemplateCluster:
    """A cluster of structurally similar log messages."""
    cluster_id: str = ""
    template: str = ""                      # masked structural template
    fingerprint: str = ""
    samples: list[str] = field(default_factory=list)
    sample_masked: list[str] = field(default_factory=list)
    count: int = 0
    family: str = ""                        # parser family hint
    confidence: float = 0.0
    token_count: int = 0
    variable_positions: list[int] = field(default_factory=list)

    def add_sample(self, raw: str, masked: str) -> None:
        """Add a sample to this cluster."""
        self.count += 1
        if len(self.samples) < 100:  # cap stored samples
            self.samples.append(raw)
            self.sample_masked.append(masked)

    def __repr__(self) -> str:
        return f"Cluster({self.cluster_id[:8]}, n={self.count}, tpl={self.template[:60]})"


@dataclass
class ClusteringResult:
    """Result of clustering a batch of messages."""
    clusters: dict[str, TemplateCluster] = field(default_factory=dict)
    unclustered: list[str] = field(default_factory=list)
    total_messages: int = 0

    @property
    def cluster_count(self) -> int:
        return len(self.clusters)

    def largest_clusters(self, n: int = 10) -> list[TemplateCluster]:
        return sorted(self.clusters.values(), key=lambda c: c.count, reverse=True)[:n]

    def __repr__(self) -> str:
        return f"ClusteringResult(clusters={self.cluster_count}, total={self.total_messages})"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class StructuralClusterer:
    """
    Clusters log messages by structural template.

    Two-phase approach:
      1. Exact match: hash the masked template → O(1) lookup
      2. Similarity match: fuzzy comparison for templates that are
         similar but not identical (e.g. optional fields)
    """

    def __init__(self, similarity_threshold: float = 0.80,
                 max_clusters: int = 10000):
        self.similarity_threshold = similarity_threshold
        self.max_clusters = max_clusters
        self._clusters: dict[str, TemplateCluster] = {}

    def add_message(self, raw_line: str, masked_template: str,
                    fingerprint_id: str = "") -> TemplateCluster:
        """
        Add a single message to the appropriate cluster.

        Returns the cluster this message was assigned to.
        """
        # Phase 0: If structural fingerprint_id is provided, group directly by fingerprint
        if fingerprint_id:
            if fingerprint_id in self._clusters:
                cluster = self._clusters[fingerprint_id]
                cluster.add_sample(raw_line, masked_template)
                return cluster
            cluster = TemplateCluster(
                cluster_id=fingerprint_id,
                template=masked_template,
                fingerprint=fingerprint_id,
                token_count=len(masked_template.split()),
            )
            cluster.add_sample(raw_line, masked_template)
            self._clusters[fingerprint_id] = cluster
            return cluster

        # Phase 1: Exact match on masked template hash
        template_hash = _hash_template(masked_template)

        if template_hash in self._clusters:
            cluster = self._clusters[template_hash]
            cluster.add_sample(raw_line, masked_template)
            return cluster

        # Phase 2: Similarity match against existing clusters
        if self._clusters:
            best_match, best_score = self._find_similar(masked_template)
            if best_match and best_score >= self.similarity_threshold:
                best_match.add_sample(raw_line, masked_template)
                return best_match

        # Phase 3: Create new cluster (if within limits)
        if len(self._clusters) >= self.max_clusters:
            # Return a synthetic overflow cluster
            overflow_key = "__overflow__"
            if overflow_key not in self._clusters:
                self._clusters[overflow_key] = TemplateCluster(
                    cluster_id=overflow_key,
                    template="<OVERFLOW>",
                    fingerprint="overflow",
                )
            self._clusters[overflow_key].add_sample(raw_line, masked_template)
            return self._clusters[overflow_key]

        cluster = TemplateCluster(
            cluster_id=template_hash,
            template=masked_template,
            fingerprint=fingerprint_id or template_hash,
            token_count=len(masked_template.split()),
        )
        cluster.add_sample(raw_line, masked_template)
        self._clusters[template_hash] = cluster
        return cluster

    def cluster_batch(self, messages: list[tuple[str, str]],
                      fingerprint_id: str = "") -> ClusteringResult:
        """
        Cluster a batch of (raw_line, masked_template) pairs.
        """
        result = ClusteringResult(total_messages=len(messages))

        for raw, masked in messages:
            self.add_message(raw, masked, fingerprint_id)

        result.clusters = dict(self._clusters)
        return result

    def get_stable_clusters(self, min_count: int = 3) -> list[TemplateCluster]:
        """Return clusters with at least min_count samples."""
        return [c for c in self._clusters.values()
                if c.count >= min_count and c.cluster_id != "__overflow__"]

    def get_cluster(self, cluster_id: str) -> TemplateCluster | None:
        return self._clusters.get(cluster_id)

    @property
    def cluster_count(self) -> int:
        return len(self._clusters)

    def reset(self) -> None:
        self._clusters.clear()

    # ---- Internal ----

    def _find_similar(self, template: str) -> tuple[TemplateCluster | None, float]:
        """Find the most similar existing cluster (capped for performance)."""
        best_cluster = None
        best_score = 0.0

        tokens = set(template.split())
        # Only compare against a bounded subset for performance
        candidates = list(self._clusters.values())[:500]

        for cluster in candidates:
            if cluster.cluster_id == "__overflow__":
                continue

            score = _template_similarity(tokens, cluster.template)
            if score > best_score:
                best_score = score
                best_cluster = cluster

        return best_cluster, best_score


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_template(template: str) -> str:
    """Hash a masked template to a cluster ID."""
    return hashlib.sha256(template.encode("utf-8")).hexdigest()[:16]


def _template_similarity(tokens_a: set[str], template_b: str) -> float:
    """Jaccard similarity between two token sets."""
    tokens_b = set(template_b.split())
    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b
    return len(intersection) / max(len(union), 1)
