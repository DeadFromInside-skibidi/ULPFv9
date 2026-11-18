"""
Reservoir Sampler
===================
Bounded-memory sampling for high-volume unknown streams.
Maintains a representative sample of logs for a given fingerprint.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FingerprintReservoir:
    """Reservoir for a specific structural fingerprint."""
    fingerprint: str
    max_size: int
    samples: list[str] = field(default_factory=list)
    seen_count: int = 0

    def add(self, item: str) -> bool:
        """
        Add an item using Reservoir Sampling (Algorithm R).
        Returns True if the item was added/kept, False if discarded.
        """
        self.seen_count += 1
        
        if len(self.samples) < self.max_size:
            self.samples.append(item)
            return True
            
        # Replace randomly with probability (max_size / seen_count)
        j = random.randint(0, self.seen_count - 1)
        if j < self.max_size:
            self.samples[j] = item
            return True
            
        return False

    def get_samples(self) -> list[str]:
        return self.samples.copy()


class Sampler:
    """Manages sampling across multiple fingerprints."""
    
    def __init__(self, max_samples_per_fingerprint: int = 1000,
                 max_fingerprints: int = 5000):
        self.max_samples = max_samples_per_fingerprint
        self.max_fingerprints = max_fingerprints
        # fingerprint_id -> FingerprintReservoir
        self._reservoirs: dict[str, FingerprintReservoir] = {}

    def add_sample(self, fingerprint: str, raw_line: str) -> None:
        """Add a sample to the appropriate reservoir."""
        if fingerprint not in self._reservoirs:
            # Bounded memory check
            if len(self._reservoirs) >= self.max_fingerprints:
                return
                
            self._reservoirs[fingerprint] = FingerprintReservoir(
                fingerprint=fingerprint,
                max_size=self.max_samples
            )
            
        self._reservoirs[fingerprint].add(raw_line)

    def get_samples(self, fingerprint: str) -> list[str]:
        """Get collected samples for a fingerprint."""
        res = self._reservoirs.get(fingerprint)
        if res:
            return res.get_samples()
        return []

    def get_ready_fingerprints(self, min_samples: int = 50) -> list[str]:
        """Return fingerprints that have gathered enough samples for learning."""
        return [fp for fp, res in self._reservoirs.items() 
                if len(res.samples) >= min_samples]
                
    def clear_fingerprint(self, fingerprint: str) -> None:
        """Remove a fingerprint's reservoir (e.g. after successful learning)."""
        self._reservoirs.pop(fingerprint, None)
