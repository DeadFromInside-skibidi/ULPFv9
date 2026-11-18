"""
Vectorised Structural Clusterer (APG 2.0)
============================================
Replaces the basic hash + O(n) Jaccard scan with a bitmask-vectorised,
streaming-first structural clusterer.

Key improvements over the v1 ``StructuralClusterer``:
  1. **Bitmask Jaccard**: O(k) similarity where k = token count, using
     packed uint64 bitmask vectors from the ``StreamingTokenizer``.
  2. **Two-tier index**: exact fingerprint hash (O(1)) falls through to
     locality-sensitive hashing (bitmask MinHash) for near-match discovery.
  3. **Streaming semantics**: ``add_frame()`` ingests one event at a time
     with bounded memory (reservoirs per cluster, eviction of cold clusters).
  4. **Drift detection**: per-cluster bitmask distribution histograms detect
     structural drift without holding every sample in memory.

Thread model: one instance per worker; the engine merges cluster inventories
from workers when flushing to the learning queue.
"""
from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass, field
from typing import Any

from ulpf.intelligence.auto_parser.streaming_tokenizer import (
    StreamFrame, bitmask_jaccard, VALUE_TYPE_MASK,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_DEFAULT_SIMILARITY_THRESHOLD = 0.80
_MAX_CLUSTERS = 10_000
_MAX_SAMPLES_PER_CLUSTER = 100
_DRIFT_WINDOW_EVENTS = 500
_COLD_CLUSTER_AGE_SEC = 600.0  # 10 min without events → eligible for eviction

# MinHash parameters for locality-sensitive hashing
_MINHASH_PERM_COUNT = 32
_MINHASH_BAND_SIZE = 4   # 32/4 = 8 bands
_MINHASH_SEED_BASE = 0x9E3779B97F4A7C15  # golden ratio derived


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class StreamCluster:
    """A cluster of structurally similar events, tracked incrementally."""
    cluster_id: str
    canonical_bitmask: bytes             # bitmask vector of the first/best sample
    canonical_fingerprint: str           # SHA-256[:16] of canonical bitmask
    delimiter: str = " "
    samples: list[str] = field(default_factory=list)
    sample_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    # Drift tracking: histogram of per-position value-type distribution
    _position_histograms: dict[int, dict[int, int]] = field(default_factory=dict)
    # MinHash signature for LSH near-match
    _minhash: tuple[int, ...] | None = None

    def add_sample(self, raw: str, bitmask_vector: bytes) -> None:
        """Add a sample to this cluster with reservoir sampling."""
        self.sample_count += 1
        now = time.monotonic()
        if self.first_seen == 0.0:
            self.first_seen = now
        self.last_seen = now

        # Reservoir sampling for bounded memory
        if len(self.samples) < _MAX_SAMPLES_PER_CLUSTER:
            self.samples.append(raw)
        else:
            import random
            j = random.randint(0, self.sample_count - 1)
            if j < _MAX_SAMPLES_PER_CLUSTER:
                self.samples[j] = raw

        # Update per-position histograms for drift detection
        n = len(bitmask_vector) // 8
        if n > 0:
            ints = struct.unpack(f'<{n}Q', bitmask_vector)
            for pos, mask in enumerate(ints):
                vtype = mask & VALUE_TYPE_MASK
                hist = self._position_histograms.setdefault(pos, {})
                hist[vtype] = hist.get(vtype, 0) + 1

    @property
    def is_cold(self) -> bool:
        """True if this cluster hasn't seen events in a while."""
        if self.last_seen == 0.0:
            return False
        return (time.monotonic() - self.last_seen) > _COLD_CLUSTER_AGE_SEC

    @property
    def drift_score(self) -> float:
        """
        Compute a drift score (0.0 = stable, 1.0 = completely drifted).

        Uses Shannon entropy over the per-position value-type distributions:
        low entropy = stable types, high = drifting.
        """
        if not self._position_histograms or self.sample_count < 10:
            return 0.0

        import math
        total_entropy = 0.0
        positions = 0

        for pos, hist in self._position_histograms.items():
            total = sum(hist.values())
            if total == 0:
                continue
            positions += 1
            entropy = 0.0
            for count in hist.values():
                p = count / total
                if p > 0:
                    entropy -= p * math.log2(p)
            # Normalise: max entropy for k classes = log2(k)
            k = len(hist)
            max_ent = math.log2(k) if k > 1 else 1.0
            total_entropy += entropy / max(max_ent, 1.0)

        if positions == 0:
            return 0.0
        return total_entropy / positions

    def __repr__(self) -> str:
        return f"StreamCluster({self.cluster_id[:8]}, n={self.sample_count}, drift={self.drift_score:.2f})"


@dataclass
class ClusterInventory:
    """Snapshot of all clusters for merging across workers."""
    clusters: dict[str, StreamCluster] = field(default_factory=dict)
    total_events: int = 0
    unclustered_count: int = 0

    @property
    def cluster_count(self) -> int:
        return len(self.clusters)

    def largest(self, n: int = 10) -> list[StreamCluster]:
        return sorted(self.clusters.values(), key=lambda c: c.sample_count, reverse=True)[:n]

    def drifting(self, threshold: float = 0.5) -> list[StreamCluster]:
        """Clusters whose structural drift exceeds the threshold."""
        return [c for c in self.clusters.values() if c.drift_score >= threshold]


# ---------------------------------------------------------------------------
# MinHash for LSH near-match
# ---------------------------------------------------------------------------

def _compute_minhash(bitmask_vector: bytes) -> tuple[int, ...]:
    """Compute a MinHash signature from a bitmask vector for LSH bucketing."""
    n = len(bitmask_vector) // 8
    if n == 0:
        return tuple([0] * _MINHASH_PERM_COUNT)

    ints = struct.unpack(f'<{n}Q', bitmask_vector)
    # Build a set of (position, bit) shingles
    shingles: set[int] = set()
    for pos, mask in enumerate(ints):
        vtype = mask & VALUE_TYPE_MASK
        for bit in range(16):
            if vtype & (1 << bit):
                shingles.add((pos << 5) | bit)

    if not shingles:
        return tuple([0] * _MINHASH_PERM_COUNT)

    # MinHash: for each permutation, find the minimum hash
    sig: list[int] = []
    for perm in range(_MINHASH_PERM_COUNT):
        seed = _MINHASH_SEED_BASE ^ (perm * 0x517CC1B727220A95)
        min_hash = 2**64 - 1
        for shingle in shingles:
            h = (shingle * seed) & ((1 << 64) - 1)
            h ^= h >> 33
            h = (h * 0xFF51AFD7ED558CCD) & ((1 << 64) - 1)
            h ^= h >> 33
            if h < min_hash:
                min_hash = h
        sig.append(min_hash)
    return tuple(sig)


def _lsh_bands(sig: tuple[int, ...]) -> list[int]:
    """Split a MinHash signature into bands for LSH bucketing."""
    bands: list[int] = []
    for band_start in range(0, _MINHASH_PERM_COUNT, _MINHASH_BAND_SIZE):
        band_end = min(band_start + _MINHASH_BAND_SIZE, len(sig))
        band_hash = hashlib.md5(
            struct.pack(f'<{band_end - band_start}Q', *sig[band_start:band_end])
        ).hexdigest()[:8]
        bands.append(int(band_hash, 16))
    return bands


# ---------------------------------------------------------------------------
# Vectorised Streaming Clusterer
# ---------------------------------------------------------------------------

class VectorisedClusterer:
    """
    APG 2.0 streaming structural clusterer with bitmask-vectorised similarity.

    Two-tier lookup:
      1. **Exact match**: SHA-256[:16] fingerprint of the bitmask vector → O(1)
      2. **LSH near-match**: MinHash bands → candidate set → full Jaccard

    Each call to ``add_frame()`` is O(1) amortised for exact matches and
    O(b × c) for near-matches where b = bands (8) and c = candidates per band.
    """

    def __init__(self, similarity_threshold: float = _DEFAULT_SIMILARITY_THRESHOLD,
                 max_clusters: int = _MAX_CLUSTERS):
        self.similarity_threshold = similarity_threshold
        self.max_clusters = max_clusters

        # Tier 1: exact fingerprint → cluster
        self._exact: dict[str, StreamCluster] = {}
        # Tier 2: LSH band hash → set of cluster IDs
        self._lsh_buckets: dict[int, set[str]] = {}
        # All clusters by ID
        self._clusters: dict[str, StreamCluster] = {}
        # Stats
        self._total_events = 0
        self._exact_hits = 0
        self._lsh_hits = 0
        self._new_clusters = 0

    def add_frame(self, frame: StreamFrame) -> StreamCluster:
        """
        Assign a StreamFrame to a cluster.

        Returns the cluster this event was assigned to.
        """
        self._total_events += 1

        # Tier 1: exact fingerprint match
        cluster = self._exact.get(frame.fingerprint_hash)
        if cluster is not None:
            cluster.add_sample(frame.raw, frame.bitmask_vector)
            self._exact_hits += 1
            return cluster

        # Tier 2: LSH near-match
        minhash = _compute_minhash(frame.bitmask_vector)
        bands = _lsh_bands(minhash)

        best_cluster: StreamCluster | None = None
        best_score = 0.0

        candidate_ids: set[str] = set()
        for band_hash in bands:
            bucket = self._lsh_buckets.get(band_hash)
            if bucket:
                candidate_ids.update(bucket)

        for cid in candidate_ids:
            candidate = self._clusters.get(cid)
            if candidate is None:
                continue
            score = bitmask_jaccard(frame.bitmask_vector, candidate.canonical_bitmask)
            if score > best_score:
                best_score = score
                best_cluster = candidate

        if best_cluster is not None and best_score >= self.similarity_threshold:
            best_cluster.add_sample(frame.raw, frame.bitmask_vector)
            # Also index this exact fingerprint for future O(1) hits
            self._exact[frame.fingerprint_hash] = best_cluster
            self._lsh_hits += 1
            return best_cluster

        # Tier 3: create new cluster
        if len(self._clusters) >= self.max_clusters:
            self._evict_cold_clusters()

        cluster = StreamCluster(
            cluster_id=frame.fingerprint_hash,
            canonical_bitmask=frame.bitmask_vector,
            canonical_fingerprint=frame.fingerprint_hash,
            delimiter=frame.delimiter,
        )
        cluster._minhash = minhash
        cluster.add_sample(frame.raw, frame.bitmask_vector)

        self._clusters[cluster.cluster_id] = cluster
        self._exact[frame.fingerprint_hash] = cluster

        # Index in LSH buckets
        for band_hash in bands:
            self._lsh_buckets.setdefault(band_hash, set()).add(cluster.cluster_id)

        self._new_clusters += 1
        return cluster

    def get_ready_clusters(self, min_samples: int = 50) -> list[StreamCluster]:
        """Return clusters with enough samples for learning."""
        return [c for c in self._clusters.values()
                if c.sample_count >= min_samples]

    def get_drifting_clusters(self, threshold: float = 0.5) -> list[StreamCluster]:
        """Return clusters exhibiting structural drift."""
        return [c for c in self._clusters.values()
                if c.drift_score >= threshold and c.sample_count >= 10]

    def get_cluster(self, cluster_id: str) -> StreamCluster | None:
        return self._clusters.get(cluster_id)

    def remove_cluster(self, cluster_id: str) -> None:
        """Remove a cluster (e.g. after successful learning)."""
        cluster = self._clusters.pop(cluster_id, None)
        if cluster is None:
            return
        # Remove from exact index
        to_remove = [fp for fp, c in self._exact.items() if c.cluster_id == cluster_id]
        for fp in to_remove:
            del self._exact[fp]
        # Remove from LSH
        if cluster._minhash:
            bands = _lsh_bands(cluster._minhash)
            for band_hash in bands:
                bucket = self._lsh_buckets.get(band_hash)
                if bucket:
                    bucket.discard(cluster_id)

    def snapshot(self) -> ClusterInventory:
        """Take a snapshot of the current cluster inventory."""
        return ClusterInventory(
            clusters=dict(self._clusters),
            total_events=self._total_events,
        )

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "total_events": self._total_events,
            "clusters": len(self._clusters),
            "exact_hits": self._exact_hits,
            "lsh_hits": self._lsh_hits,
            "new_clusters": self._new_clusters,
            "exact_index_size": len(self._exact),
        }

    def _evict_cold_clusters(self) -> int:
        """Remove clusters that haven't seen events recently."""
        cold = [cid for cid, c in self._clusters.items()
                if c.is_cold and c.sample_count < 5]
        if not cold:
            # Force evict smallest + coldest
            by_last = sorted(self._clusters.items(),
                             key=lambda kv: (kv[1].sample_count, kv[1].last_seen))
            cold = [kv[0] for kv in by_last[:max(1, len(self._clusters) // 10)]]

        for cid in cold:
            self.remove_cluster(cid)
        return len(cold)

    def reset(self) -> None:
        self._clusters.clear()
        self._exact.clear()
        self._lsh_buckets.clear()
        self._total_events = 0
        self._exact_hits = 0
        self._lsh_hits = 0
        self._new_clusters = 0
