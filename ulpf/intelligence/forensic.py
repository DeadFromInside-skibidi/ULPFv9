"""
Forensic Chain-of-Evidence Builder
====================================
For incident response and legal compliance:

  * every event contributes a leaf ``SHA-256(event_id | raw_hash | normalised_hash)``
  * leaves are linked into a sequential hash chain
    ``link_i = SHA-256(link_{i-1} | leaf_i)`` (genesis = 64 zeros), so
    reordering, insertion or deletion breaks every later link
  * a binary Merkle tree over the leaves yields a ``merkle_root``, allowing
    O(log n) inclusion proofs for a single event
  * exported packages carry a canonical ``package_hash_sha256`` and can be
    verified offline with :func:`verify_package` (CLI: ``ulpf forensic --verify``)
  * chains and the custody log are persisted, so they survive restarts
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any

from ulpf.engine.schema import new_uuid

logger = logging.getLogger(__name__)

GENESIS = "0" * 64
PACKAGE_VERSION = "2.0.0"


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()


def canonical_json(obj: Any) -> str:
    """Deterministic JSON used for every hash in a package."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _normalised_view(event: dict) -> dict:
    """The event content covered by the normalised hash (correlation output excluded)."""
    return {k: v for k, v in event.items() if k not in ("correlation_id", "related_events", "extensions")}


def merkle_root(leaves: list[str]) -> str:
    """Bitcoin-style binary Merkle root (odd node is paired with itself)."""
    if not leaves:
        return GENESIS
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(leaves: list[str], index: int) -> list[dict]:
    """Inclusion proof for ``leaves[index]``: list of {"sibling", "position"} steps."""
    proof: list[dict] = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sib = idx ^ 1
        proof.append({"sibling": level[sib], "position": "right" if sib > idx else "left"})
        level = [_sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        idx //= 2
    return proof


def verify_merkle_proof(leaf: str, proof: list[dict], root: str) -> bool:
    h = leaf
    for step in proof:
        h = _sha256(h + step["sibling"]) if step["position"] == "right" else _sha256(step["sibling"] + h)
    return h == root


class EvidenceItem:
    """A single piece of forensic evidence."""

    def __init__(self, event: dict):
        self.event = event
        self.event_id = event.get("event_id") or new_uuid()
        self.raw_event = event.get("raw_event") or ""
        self.raw_hash = _sha256(self.raw_event)
        self.normalised_hash = _sha256(canonical_json(_normalised_view(event)))
        self.leaf = _sha256(f"{self.event_id}|{self.raw_hash}|{self.normalised_hash}")
        self.timestamp = event.get("timestamp", "")
        self.category = event.get("category", "")
        self.severity = event.get("severity", 0)
        self.source_ip = (event.get("source") or {}).get("ip")
        self.dest_ip = (event.get("destination") or {}).get("ip")
        self.parser_id = (event.get("metadata") or {}).get("parser_id")
        recorded = (event.get("evidence") or {}).get("raw_hash")
        # The pipeline-entry hash must match the preserved raw text
        self.ingest_hash_match = recorded is None or recorded == self.raw_hash

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "raw_hash_sha256": self.raw_hash,
            "normalised_hash_sha256": self.normalised_hash,
            "leaf_hash": self.leaf,
            "ingest_hash_match": self.ingest_hash_match,
            "timestamp": self.timestamp,
            "category": self.category,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.dest_ip,
            "parser_id": self.parser_id,
        }


class EvidenceChain:
    """A chronological, hash-linked chain of evidence items."""

    def __init__(self, chain_id: str | None = None):
        self.chain_id = chain_id or new_uuid().replace("-", "")[:12]
        self.items: list[EvidenceItem] = []
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.description: str = ""
        self.tags: list[str] = []
        self._links: list[str] = []

    def add_event(self, event: dict) -> EvidenceItem:
        item = EvidenceItem(event)
        prev = self._links[-1] if self._links else GENESIS
        self._links.append(_sha256(f"{prev}|{item.leaf}"))
        self.items.append(item)
        return item

    def add_events(self, events: list[dict]) -> list[EvidenceItem]:
        return [self.add_event(e) for e in events]

    @property
    def chain_hash(self) -> str:
        """Head of the hash chain — changes if any item is altered, removed or reordered."""
        return self._links[-1] if self._links else ""

    @property
    def merkle_root(self) -> str:
        return merkle_root([i.leaf for i in self.items])

    def verify_integrity(self) -> dict:
        """Recompute every hash from the preserved evidence and compare."""
        if not self.items:
            return {"valid": True, "message": "Empty chain", "items": 0}
        prev = GENESIS
        for i, item in enumerate(self.items):
            raw_hash = _sha256(item.raw_event)
            if raw_hash != item.raw_hash:
                return {"valid": False, "position": i, "type": "raw_hash_mismatch",
                        "message": f"Raw event altered at position {i} (event {item.event_id})"}
            norm_hash = _sha256(canonical_json(_normalised_view(item.event)))
            if norm_hash != item.normalised_hash:
                return {"valid": False, "position": i, "type": "normalised_hash_mismatch",
                        "message": f"Normalised event altered at position {i} (event {item.event_id})"}
            leaf = _sha256(f"{item.event_id}|{raw_hash}|{norm_hash}")
            link = _sha256(f"{prev}|{leaf}")
            if i >= len(self._links) or link != self._links[i]:
                return {"valid": False, "position": i, "type": "chain_link_broken",
                        "message": f"Chain link broken at position {i}"}
            prev = link
        mismatched = [it.event_id for it in self.items if not it.ingest_hash_match]
        result = {"valid": True, "message": "Chain integrity verified", "items": len(self.items),
                  "chain_hash": self.chain_hash, "merkle_root": self.merkle_root}
        if mismatched:
            result["ingest_hash_mismatches"] = mismatched
            result["message"] += f" ({len(mismatched)} event(s) differ from their ingest-time hash)"
        return result

    def to_dict(self, include_events: bool = False) -> dict:
        d = {
            "chain_id": self.chain_id,
            "created_at": self.created_at,
            "description": self.description,
            "tags": self.tags,
            "item_count": len(self.items),
            "chain_hash": self.chain_hash,
            "merkle_root": self.merkle_root,
            "items": [item.to_dict() for item in self.items],
            "chain_links": list(self._links),
        }
        if include_events:
            d["events"] = [item.event for item in self.items]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceChain":
        chain = cls(d.get("chain_id"))
        chain.created_at = d.get("created_at", chain.created_at)
        chain.description = d.get("description", "")
        chain.tags = list(d.get("tags", []))
        for event in d.get("events", []):
            chain.add_event(event)
        stored_links = d.get("chain_links")
        if stored_links is not None:
            # Keep the links as recorded so verification detects later tampering
            chain._links = list(stored_links)
        return chain


class ForensicBuilder:
    """Builds, persists and exports forensic evidence chains."""

    def __init__(self, output_dir: str | None = None):
        if output_dir is None:
            from ulpf.platform.paths import get_data_dir
            output_dir = str(get_data_dir() / "evidence")
        self.output_dir = output_dir
        self._store_dir = os.path.join(output_dir, "chains")
        self._lock = threading.Lock()
        self.chains: dict[str, EvidenceChain] = {}
        self.custody_log: list[dict] = []
        self._load()

    # ---- persistence ----

    def _custody_path(self) -> str:
        return os.path.join(self._store_dir, "custody_log.jsonl")

    def _load(self) -> None:
        if not os.path.isdir(self._store_dir):
            return
        for fname in sorted(os.listdir(self._store_dir)):
            if fname.endswith(".chain.json"):
                try:
                    with open(os.path.join(self._store_dir, fname), "r", encoding="utf-8") as f:
                        chain = EvidenceChain.from_dict(json.load(f))
                    self.chains[chain.chain_id] = chain
                except Exception as e:
                    logger.warning(f"Could not load evidence chain {fname}: {e}")
        try:
            with open(self._custody_path(), "r", encoding="utf-8") as f:
                self.custody_log = [json.loads(line) for line in f if line.strip()]
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.warning(f"Could not load custody log: {e}")

    def _persist(self, chain: EvidenceChain) -> None:
        os.makedirs(self._store_dir, exist_ok=True)
        path = os.path.join(self._store_dir, f"{chain.chain_id}.chain.json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(chain.to_dict(include_events=True), f, default=str)
        os.replace(tmp, path)

    # ---- chain operations ----

    def create_chain(self, description: str = "", tags: list[str] | None = None) -> EvidenceChain:
        chain = EvidenceChain()
        chain.description = description
        chain.tags = list(tags or [])
        with self._lock:
            self.chains[chain.chain_id] = chain
            self._persist(chain)
            self._log_custody("chain_created", chain.chain_id, description)
        return chain

    def add_to_chain(self, chain_id: str, events: list[dict]) -> list[EvidenceItem]:
        chain = self.chains.get(chain_id)
        if not chain:
            raise ValueError(f"Chain {chain_id} not found")
        with self._lock:
            items = chain.add_events(events)
            self._persist(chain)
            self._log_custody("events_added", chain_id, f"Added {len(events)} events")
        return items

    def build_from_events(self, events: list[dict],
                          description: str = "Auto-generated evidence chain",
                          tags: list[str] | None = None) -> EvidenceChain:
        """Build a chain from events in chronological order (ties broken by event_id)."""
        chain = EvidenceChain()
        chain.description = description
        chain.tags = list(tags or [])
        chain.add_events(sorted(events, key=lambda e: (e.get("timestamp") or "", e.get("event_id") or "")))
        with self._lock:
            self.chains[chain.chain_id] = chain
            self._persist(chain)
            self._log_custody("chain_created", chain.chain_id, description)
            self._log_custody("events_added", chain.chain_id, f"Added {len(events)} events")
        return chain

    def export_package(self, chain_id: str) -> str:
        """Export a self-verifying forensic evidence package. Returns the file path."""
        chain = self.chains.get(chain_id)
        if not chain:
            raise ValueError(f"Chain {chain_id} not found")
        integrity = chain.verify_integrity()
        with self._lock:
            self._log_custody("package_exported", chain_id, "export requested")
            custody = [e for e in self.custody_log if e.get("chain_id") == chain_id]
        package = {
            "ulpf_forensic_package": {
                "version": PACKAGE_VERSION,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "generator": "ULPF Forensic Chain-of-Evidence Builder",
                "hash_algorithm": "SHA-256",
                "leaf_formula": "SHA256(event_id|raw_hash|normalised_hash)",
                "link_formula": "SHA256(previous_link|leaf), genesis = 64 zeros",
                "normalised_hash_formula": "SHA256(canonical_json(event minus correlation_id, related_events, extensions))",
            },
            "chain": chain.to_dict(),
            "integrity_check": integrity,
            "chain_of_custody": custody,
            "raw_events": [{"event_id": i.event_id, "raw_event": i.raw_event, "hash": i.raw_hash}
                           for i in chain.items],
            "normalised_events": [i.event for i in chain.items],
        }
        package["package_hash_sha256"] = _sha256(canonical_json(package))

        os.makedirs(self.output_dir, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.output_dir, f"evidence_{chain_id}_{ts}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(package, f, indent=2, ensure_ascii=False, default=str)
        return filepath

    def verify_chain(self, chain_id: str) -> dict:
        chain = self.chains.get(chain_id)
        if not chain:
            return {"valid": False, "message": f"Chain {chain_id} not found"}
        result = chain.verify_integrity()
        with self._lock:
            self._log_custody("chain_verified", chain_id, "valid" if result["valid"] else result["type"])
        return result

    def list_chains(self) -> list[dict]:
        return [
            {"chain_id": c.chain_id, "description": c.description, "item_count": len(c.items),
             "created_at": c.created_at, "chain_hash": c.chain_hash, "merkle_root": c.merkle_root,
             "tags": c.tags}
            for c in self.chains.values()
        ]

    def get_custody_log(self, chain_id: str | None = None) -> list[dict]:
        if chain_id:
            return [e for e in self.custody_log if e.get("chain_id") == chain_id]
        return list(self.custody_log)

    def _log_custody(self, action: str, chain_id: str, detail: str = "") -> None:
        """Append a custody entry; entries are hash-linked to the previous one."""
        prev = self.custody_log[-1]["entry_hash"] if self.custody_log and "entry_hash" in self.custody_log[-1] else GENESIS
        entry = {
            "action": action,
            "chain_id": chain_id,
            "detail": detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operator": os.environ.get("ULPF_OPERATOR") or _current_user(),
            "previous_entry_hash": prev,
        }
        entry["entry_hash"] = _sha256(canonical_json(entry))
        self.custody_log.append(entry)
        try:
            os.makedirs(self._store_dir, exist_ok=True)
            with open(self._custody_path(), "a", encoding="utf-8") as f:
                f.write(canonical_json(entry) + "\n")
        except OSError as e:
            logger.warning(f"Could not persist custody entry: {e}")


def _current_user() -> str:
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return "ULPF System"


def verify_package(path: str) -> dict:
    """Independently verify an exported evidence package file.

    Recomputes the package hash, every raw/normalised hash, every chain link
    and the Merkle root from the package contents alone.
    """
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            package = json.load(f)
    except (OSError, ValueError) as e:
        return {"valid": False, "items": 0, "chain_id": None, "chain_hash": None, "merkle_root": None,
                "problems": [f"Unreadable package: {e}"]}
    if not isinstance(package, dict):
        return {"valid": False, "items": 0, "chain_id": None, "chain_hash": None, "merkle_root": None,
                "problems": ["Not a ULPF evidence package"]}
    problems: list[str] = []

    claimed = package.pop("package_hash_sha256", None)
    if claimed is None:
        problems.append("package_hash_sha256 missing")
    elif _sha256(canonical_json(package)) != claimed:
        problems.append("package hash mismatch: file contents were modified after export")

    chain = package.get("chain", {})
    items = chain.get("items", [])
    raws = {r["event_id"]: r for r in package.get("raw_events", [])}
    events = {e.get("event_id"): e for e in package.get("normalised_events", [])}
    links = chain.get("chain_links", [])
    if len(links) != len(items):
        problems.append(f"chain has {len(links)} links for {len(items)} items")

    prev = GENESIS
    leaves: list[str] = []
    for i, item in enumerate(items):
        eid = item["event_id"]
        raw = raws.get(eid, {}).get("raw_event")
        event = events.get(eid)
        if raw is None or event is None:
            problems.append(f"item {i} ({eid}) missing raw or normalised event")
            break
        raw_hash = _sha256(raw)
        norm_hash = _sha256(canonical_json(_normalised_view(event)))
        if raw_hash != item["raw_hash_sha256"]:
            problems.append(f"item {i} ({eid}) raw event altered")
        if norm_hash != item["normalised_hash_sha256"]:
            problems.append(f"item {i} ({eid}) normalised event altered")
        leaf = _sha256(f"{eid}|{raw_hash}|{norm_hash}")
        leaves.append(leaf)
        link = _sha256(f"{prev}|{leaf}")
        if i < len(links) and link != links[i]:
            problems.append(f"chain link {i} broken")
        prev = link

    if leaves and merkle_root(leaves) != chain.get("merkle_root"):
        problems.append("merkle root mismatch")
    if leaves and prev != chain.get("chain_hash"):
        problems.append("chain head hash mismatch")

    return {"valid": not problems, "items": len(items), "chain_id": chain.get("chain_id"),
            "chain_hash": chain.get("chain_hash"), "merkle_root": chain.get("merkle_root"),
            "problems": problems}
