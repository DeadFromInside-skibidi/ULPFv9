"""
🏆 Log DNA Fingerprinting
===========================
Creates a structural "fingerprint" for each log source that enables:
  - Instant format recognition without iterating parsers
  - Format drift detection (alerts when a source changes its format)
  - A searchable log DNA database of known formats
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import threading
from collections import Counter

_DB_LOCK = threading.Lock()


def _default_dna_path() -> str:
    from ulpf.platform.paths import get_data_dir
    return str(get_data_dir() / "log_dna_db.json")


class LogFingerprint:
    """Structural fingerprint of a log format."""

    def __init__(self):
        self.fingerprint_id: str = ""
        self.field_count: int = 0
        self.delimiter: str = ""
        self.field_type_signature: str = ""  # e.g., "ts,ip,port,ip,port,proto,int,str"
        self.timestamp_position: int = -1
        self.ip_positions: list[int] = []
        self.char_freq: dict[str, float] = {}  # character frequency distribution
        self.avg_line_length: float = 0.0
        self.entropy: float = 0.0
        self.sample_hash: str = ""
        self.first_seen: str = ""
        self.source_label: str = ""
        # Distribution of per-line structural shapes (JSON key sets, or the class
        # sequence of the leading tokens): sensitive to added/removed keys and
        # reordered tokens, which the aggregate statistics above are not
        self.shape_dist: dict[str, float] = {}

    def to_dict(self) -> dict:
        return {
            "fingerprint_id": self.fingerprint_id,
            "field_count": self.field_count,
            "delimiter": repr(self.delimiter),
            "field_type_signature": self.field_type_signature,
            "timestamp_position": self.timestamp_position,
            "ip_positions": self.ip_positions,
            "char_freq_top10": dict(sorted(self.char_freq.items(), key=lambda x: -x[1])[:10]),
            "avg_line_length": round(self.avg_line_length, 1),
            "entropy": round(self.entropy, 4),
            "sample_hash": self.sample_hash,
            "source_label": self.source_label,
            "shape_dist": dict(sorted(self.shape_dist.items(), key=lambda x: -x[1])[:100]),
        }


class LogDNA:
    """Log DNA Fingerprinting engine."""

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or _default_dna_path()
        self.database: dict[str, dict] = {}
        self._load_db()

    def _load_db(self):
        if os.path.isfile(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    self.database = json.load(f)
            except (OSError, ValueError):
                self.database = {}

    def _save_db(self):
        """Merge with what is on disk and write atomically (safe across threads)."""
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        with _DB_LOCK:
            on_disk: dict = {}
            if os.path.isfile(self.db_path):
                try:
                    with open(self.db_path, "r", encoding="utf-8") as f:
                        on_disk = json.load(f)
                except (OSError, ValueError):
                    on_disk = {}
            on_disk.update(self.database)
            self.database = on_disk
            tmp = f"{self.db_path}.{os.getpid()}.{threading.get_ident()}.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.database, f, indent=2)
            os.replace(tmp, self.db_path)

    def fingerprint(self, lines: list[str], source_label: str = "") -> LogFingerprint:
        """Generate a structural fingerprint from a batch of log lines."""
        clean = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
        if not clean:
            raise ValueError("No valid lines to fingerprint")

        fp = LogFingerprint()
        fp.source_label = source_label

        # 1. Character frequency distribution
        all_chars = "".join(clean)
        total = max(len(all_chars), 1)
        freq = Counter(all_chars)
        fp.char_freq = {ch: round(cnt / total, 6) for ch, cnt in freq.most_common(30)}

        # 2. Shannon entropy
        fp.entropy = _shannon_entropy(all_chars)

        # 3. Average line length
        fp.avg_line_length = sum(len(l) for l in clean) / len(clean)

        # 4. Delimiter detection
        fp.delimiter = _detect_delim(clean)

        # 5. Field analysis (structural template mining, no engine/threads)
        try:
            from ulpf.intelligence.auto_parser.fingerprint import compute_batch_fingerprint
            from ulpf.intelligence.auto_parser.miners.native import NativeTemplateMiner
            batch_fp = compute_batch_fingerprint(clean)
            specs = NativeTemplateMiner().mine(clean[:500], batch_fp.fingerprint_id)
            if specs and specs[0].fields:
                spec = specs[0]
                fp.field_count = len(spec.fields)
                fp.field_type_signature = ",".join(f.field_type for f in spec.fields)
                fp.timestamp_position = next(
                    (f.position for f in spec.fields if f.field_type == "timestamp"), -1
                )
                fp.ip_positions = [f.position for f in spec.fields if f.field_type in ("ipv4", "ipv6")]
            else:
                # Fallback to batch fingerprint field count
                fp.field_count = batch_fp.field_count
                fp.field_type_signature = batch_fp.format_type
        except Exception:
            fp.field_count = 0
            fp.field_type_signature = "unknown"

        # 6. Structural shape distribution
        shapes = Counter(_line_shape(l) for l in clean[:2000])
        n = sum(shapes.values())
        fp.shape_dist = {s: round(c / n, 6) for s, c in shapes.most_common(100)}

        # 7. Generate fingerprint hash
        sig = f"{fp.delimiter}|{fp.field_count}|{fp.field_type_signature}|{fp.entropy:.2f}"
        fp.fingerprint_id = hashlib.sha256(sig.encode()).hexdigest()[:16]

        # 7. Sample hash (provenance of the profiled sample)
        fp.sample_hash = hashlib.sha256("\n".join(clean[:5]).encode()).hexdigest()

        return fp

    def register(self, fingerprint: LogFingerprint) -> str:
        """Register a fingerprint in the DNA database."""
        self.database[fingerprint.fingerprint_id] = fingerprint.to_dict()
        self._save_db()
        return fingerprint.fingerprint_id

    def match(self, lines: list[str]) -> tuple[str | None, float]:
        """
        Try to match lines against known fingerprints.
        Returns (fingerprint_id, similarity_score) or (None, 0.0).
        """
        try:
            fp = self.fingerprint(lines)
        except ValueError:
            return None, 0.0

        best_id = None
        best_score = 0.0

        for fid, stored in self.database.items():
            score = self._similarity(fp, stored)
            if score > best_score:
                best_score = score
                best_id = fid

        return (best_id, best_score) if best_score > 0.6 else (None, 0.0)

    def detect_drift(self, fingerprint_id: str, new_lines: list[str]) -> dict:
        """
        Compare new logs against a stored fingerprint to detect format changes.
        Returns a drift report.
        """
        if fingerprint_id not in self.database:
            return {"drift_detected": False, "error": "Fingerprint not found"}

        stored = self.database[fingerprint_id]
        try:
            new_fp = self.fingerprint(new_lines)
        except ValueError:
            return {"drift_detected": False, "error": "No valid lines"}

        similarity = self._similarity(new_fp, stored)
        drift = {
            "drift_detected": similarity < 0.85,
            "similarity_score": round(similarity, 4),
            "original_fingerprint": fingerprint_id,
            "changes": [],
        }

        # Detail specific changes
        if new_fp.field_count != stored.get("field_count", 0):
            drift["changes"].append({
                "field": "field_count",
                "old": stored.get("field_count"),
                "new": new_fp.field_count,
            })

        if new_fp.field_type_signature != stored.get("field_type_signature", ""):
            drift["changes"].append({
                "field": "field_type_signature",
                "old": stored.get("field_type_signature"),
                "new": new_fp.field_type_signature,
            })

        ent_diff = abs(new_fp.entropy - stored.get("entropy", 0))
        if ent_diff > 0.5:
            drift["changes"].append({
                "field": "entropy",
                "old": stored.get("entropy"),
                "new": round(new_fp.entropy, 4),
                "delta": round(ent_diff, 4),
            })

        # A changed delimiter or field count breaks every parser of a positional
        # source, so either is drift regardless of the aggregate similarity score.
        # JSON lines are not positional: their key sets (shape_dist) are the structure,
        # and a mined template's field count varies with optional keys.
        def json_share(dist):
            return sum(p for s, p in (dist or {}).items() if s.startswith("json:"))
        positional = not (json_share(stored.get("shape_dist")) > 0.9 and json_share(new_fp.shape_dist) > 0.9)
        if stored.get("delimiter") is not None and stored.get("delimiter") != repr(new_fp.delimiter):
            drift["changes"].append({"field": "delimiter", "old": stored.get("delimiter"),
                                     "new": repr(new_fp.delimiter)})
            if positional:
                drift["drift_detected"] = True
        if positional and any(c["field"] == "field_count" for c in drift["changes"]):
            drift["drift_detected"] = True
        if not positional:
            old_keys = {k for s in stored["shape_dist"] for k in s[5:].split(",") if s.startswith("json:")}
            new_keys = {k for s in new_fp.shape_dist for k in s[5:].split(",") if s.startswith("json:")}
            if old_keys != new_keys:
                drift["changes"].append({"field": "json_keys", "added": sorted(new_keys - old_keys)[:50],
                                         "removed": sorted(old_keys - new_keys)[:50]})

        return drift

    def list_known(self) -> list[dict]:
        return list(self.database.values())

    def _similarity(self, fp: LogFingerprint, stored: dict) -> float:
        """Calculate similarity between a fingerprint and stored one."""
        score = 0.0
        weights = 0.0

        # Field count similarity (weight: 3)
        fc_stored = stored.get("field_count", 0)
        if fc_stored > 0 or fp.field_count > 0:
            fc_sim = 1.0 - abs(fp.field_count - fc_stored) / max(fp.field_count, fc_stored, 1)
            score += fc_sim * 3
        else:
            score += 1.0 * 3
        weights += 3

        # Type signature match (weight: 5)
        sig_stored = stored.get("field_type_signature", "")
        if sig_stored or fp.field_type_signature:
            sig_sim = _string_similarity(fp.field_type_signature, sig_stored)
            score += sig_sim * 5
        else:
            score += 1.0 * 5
        weights += 5

        # Entropy similarity (weight: 2)
        ent_stored = stored.get("entropy", 0)
        if ent_stored > 0:
            ent_sim = 1.0 - min(abs(fp.entropy - ent_stored) / max(fp.entropy, ent_stored, 0.01), 1.0)
            score += ent_sim * 2
        else:
            score += 1.0 * 2
        weights += 2

        # Delimiter match (weight: 1) — stored as repr() in to_dict()
        score += 1.0 if stored.get("delimiter") == repr(fp.delimiter) else 0.0
        weights += 1

        # Character-distribution similarity (weight: 2): 1 - total variation distance
        stored_freq = stored.get("char_freq_top10") or {}
        if stored_freq:
            keys = set(stored_freq) | set(sorted(fp.char_freq, key=fp.char_freq.get, reverse=True)[:10])
            tvd = 0.5 * sum(abs(fp.char_freq.get(k, 0.0) - stored_freq.get(k, 0.0)) for k in keys)
            score += max(0.0, 1.0 - tvd) * 2
            weights += 2

        stats_sim = score / max(weights, 1)
        stored_shapes = stored.get("shape_dist")
        if not stored_shapes or not fp.shape_dist:
            return stats_sim                    # fingerprint stored by an older version
        # Shared probability mass of the two shape distributions (1.0 = same structure)
        shape_sim = sum(min(p, stored_shapes.get(s, 0.0)) for s, p in fp.shape_dist.items())
        return 0.5 * stats_sim + 0.5 * min(1.0, shape_sim)


_TOKEN = None


def _line_shape(line: str) -> str:
    """JSON object -> sorted key set; anything else -> class sequence of the first 8 tokens
    (a = letters, d = digits, punctuation kept), e.g. ``< d > a d d : d``."""
    global _TOKEN
    if line.startswith("{") and line.endswith("}"):
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                return "json:" + ",".join(sorted(obj))[:300]
        except ValueError:
            pass
    if _TOKEN is None:
        import re
        _TOKEN = re.compile(r"[A-Za-z]+|\d+|[^\sA-Za-z\d]")
    out = []
    for m in _TOKEN.finditer(line):
        t = m.group(0)
        out.append("a" if t[0].isalpha() else "d" if t[0].isdigit() else t)
        if len(out) == 8:
            break
    return " ".join(out)


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values() if c > 0)


def _detect_delim(lines: list[str]) -> str:
    candidates = {"\t": 0, ",": 0, "|": 0, " ": 0, ";": 0}
    for line in lines[:20]:
        for d in candidates:
            if len(line.split(d)) >= 3:
                candidates[d] += len(line.split(d))
    return max(candidates, key=candidates.get) if candidates else " "


def _string_similarity(a: str, b: str) -> float:
    """Simple character-level similarity (Jaccard-like)."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    set_a = set(a.split(","))
    set_b = set(b.split(","))
    intersection = set_a & set_b
    union = set_a | set_b
    return len(intersection) / max(len(union), 1)
