"""
ULPF Benchmark — Event Accounting System
==========================================
Deterministic ID-level tracking across all pipeline lifecycle stages:
  Generated -> Sent -> Received -> Accepted -> Parsed -> Normalized -> Persisted
Also tracks:
  Rejected, Dropped, Duplicated, Missing, Unexpected.

Generates:
  missing_ids.txt
  duplicate_ids.txt
  unexpected_ids.txt
  event_accounting.csv
  event_accounting.json
"""
from __future__ import annotations

import csv
import json
import os
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Set


@dataclass
class AccountingStage:
    name: str
    ids: Set[str] = field(default_factory=set)
    count: int = 0


class EventAccountant:
    """
    Deterministic benchmark ID accountant.
    Ensures zero loss is proven via explicit set difference and cardinality checks.
    """

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

        self.generated: List[str] = []
        self.sent: List[str] = []
        self.received: List[str] = []
        self.accepted: List[str] = []
        self.parsed: List[str] = []
        self.normalized: List[str] = []
        self.persisted: List[str] = []
        self.rejected: List[str] = []
        self.dropped: List[str] = []

    def record_generated(self, ids: Iterable[str]) -> None:
        self.generated.extend(ids)

    def record_sent(self, ids: Iterable[str]) -> None:
        self.sent.extend(ids)

    def record_received(self, ids: Iterable[str]) -> None:
        self.received.extend(ids)

    def record_accepted(self, ids: Iterable[str]) -> None:
        self.accepted.extend(ids)

    def record_parsed(self, ids: Iterable[str]) -> None:
        self.parsed.extend(ids)

    def record_normalized(self, ids: Iterable[str]) -> None:
        self.normalized.extend(ids)

    def record_persisted(self, ids: Iterable[str]) -> None:
        self.persisted.extend(ids)

    def record_rejected(self, ids: Iterable[str]) -> None:
        self.rejected.extend(ids)

    def record_dropped(self, ids: Iterable[str]) -> None:
        self.dropped.extend(ids)

    def compute_summary(self) -> Dict[str, Any]:
        """Compute complete accounting metrics and set differences."""
        gen_set = set(self.generated)
        sent_set = set(self.sent) if self.sent else gen_set
        persisted_counts = Counter(self.persisted)
        persisted_set = set(persisted_counts.keys())

        # Duplicate IDs in persisted
        duplicates = {bid: count for bid, count in persisted_counts.items() if count > 1}

        # Missing IDs: in expected (generated/sent) but not in persisted
        target_set = sent_set if self.sent else gen_set
        missing = sorted(list(target_set - persisted_set))

        # Unexpected IDs: in persisted but not in generated/sent
        unexpected = sorted(list(persisted_set - target_set))

        summary = {
            "counts": {
                "generated": len(self.generated),
                "sent": len(self.sent) if self.sent else len(self.generated),
                "received": len(self.received) if self.received else len(self.accepted),
                "accepted": len(self.accepted),
                "parsed": len(self.parsed),
                "normalized": len(self.normalized),
                "persisted": len(self.persisted),
                "rejected": len(self.rejected),
                "dropped": len(self.dropped),
                "unique_persisted": len(persisted_set),
                "missing": len(missing),
                "duplicate_count": sum(duplicates.values()) - len(duplicates),
                "unexpected": len(unexpected),
            },
            "zero_loss_verified": len(missing) == 0 and len(unexpected) == 0 and len(self.persisted) == len(target_set),
            "duplicate_free": len(duplicates) == 0,
        }
        return summary

    def save_artifacts(self) -> Dict[str, str]:
        """
        Write missing_ids.txt, duplicate_ids.txt, unexpected_ids.txt,
        event_accounting.csv, event_accounting.json.
        """
        summary = self.compute_summary()
        gen_set = set(self.generated)
        sent_set = set(self.sent) if self.sent else gen_set
        target_set = sent_set if self.sent else gen_set

        persisted_counts = Counter(self.persisted)
        persisted_set = set(persisted_counts.keys())
        duplicates = {bid: count for bid, count in persisted_counts.items() if count > 1}
        missing = sorted(list(target_set - persisted_set))
        unexpected = sorted(list(persisted_set - target_set))

        # 1. missing_ids.txt
        missing_path = os.path.join(self.output_dir, "missing_ids.txt")
        with open(missing_path, "w", encoding="utf-8") as f:
            for bid in missing:
                f.write(f"{bid}\n")

        # 2. duplicate_ids.txt
        duplicate_path = os.path.join(self.output_dir, "duplicate_ids.txt")
        with open(duplicate_path, "w", encoding="utf-8") as f:
            for bid, count in sorted(duplicates.items()):
                f.write(f"{bid}: {count}\n")

        # 3. unexpected_ids.txt
        unexpected_path = os.path.join(self.output_dir, "unexpected_ids.txt")
        with open(unexpected_path, "w", encoding="utf-8") as f:
            for bid in unexpected:
                f.write(f"{bid}\n")

        # 4. event_accounting.csv
        csv_path = os.path.join(self.output_dir, "event_accounting.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["stage", "event_count", "percentage_of_generated"])
            gen_count = max(len(self.generated), 1)
            for stage_name, val in summary["counts"].items():
                pct = round(val / gen_count * 100, 2)
                writer.writerow([stage_name, val, pct])

        # 5. event_accounting.json
        json_path = os.path.join(self.output_dir, "event_accounting.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        return {
            "missing_ids": missing_path,
            "duplicate_ids": duplicate_path,
            "unexpected_ids": unexpected_path,
            "csv": csv_path,
            "json": json_path,
        }
