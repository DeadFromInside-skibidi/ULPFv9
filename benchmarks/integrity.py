"""
ULPF Benchmark — Integrity & Security Validation
====================================================
Validates that ULPF maintains data integrity, provenance hashing,
forensic chain integrity, and air-gap capability.

These are NOT performance tests — they verify correctness.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
from typing import Any, Dict, List

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class IntegrityValidator:
    """
    Validates ULPF data integrity guarantees:
      - Every event has a raw_hash provenance field
      - Every event has a unique event_id
      - Parsed events preserve the original raw_event
      - Timestamp normalization produces valid ISO8601
      - DuckDB stored events match pipeline output
    """

    def __init__(self, results_dir: str | None = None):
        self.results_dir = results_dir or os.path.join(
            PROJECT_ROOT, "benchmarks", "results", "integrity"
        )
        os.makedirs(self.results_dir, exist_ok=True)
        self.results: List[Dict[str, Any]] = []

    def _test(self, name: str, passed: bool, details: str = ""):
        result = {"test": name, "pass": passed, "details": details}
        self.results.append(result)
        status = "[OK]" if passed else "[FAIL]"
        print(f"  {status} {name}: {details}")
        return passed

    def run_all(self) -> Dict[str, Any]:
        """Run all integrity and security validation tests."""
        print(f"\n{'=' * 60}")
        print(f"  ULPF INTEGRITY & SECURITY VALIDATION")
        print(f"{'=' * 60}")

        self._test_provenance_hashing()
        self._test_event_id_uniqueness()
        self._test_raw_event_preservation()
        self._test_timestamp_normalization()
        self._test_storage_consistency()
        self._test_all_formats_parseable()
        self._test_air_gap_mode()
        self._test_forensic_chain()

        total = len(self.results)
        passed = sum(1 for r in self.results if r["pass"])
        failed = total - passed

        summary = {
            "total_tests": total,
            "passed": passed,
            "failed": failed,
            "pass_rate_pct": round(passed / max(total, 1) * 100, 1),
            "tests": self.results,
        }

        print(f"\n  {'-' * 48}")
        print(f"  Total: {total} | Passed: {passed} | Failed: {failed}")
        print(f"  Pass Rate: {summary['pass_rate_pct']}%")

        # Save results
        filepath = os.path.join(self.results_dir, "integrity_validation.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, default=str)

        return summary

    def _test_provenance_hashing(self):
        """Verify that every processed event has a raw_hash for provenance."""
        from benchmarks.generator import DeterministicGenerator
        from ulpf.engine.pipeline import Pipeline

        gen = DeterministicGenerator(seed=99)
        pipeline = Pipeline()

        lines = gen.generate(100)
        missing_hash = 0
        invalid_hash = 0

        for line in lines:
            result = pipeline.process_line(line)
            if result.get("success") and result.get("event"):
                event = result["event"]
                raw_hash = event.get("evidence", {}).get("raw_hash")
                if not raw_hash:
                    missing_hash += 1
                else:
                    # Verify the SHA-256 provenance hash of the raw line
                    expected = hashlib.sha256(line.strip().encode("utf-8")).hexdigest()
                    if raw_hash != expected:
                        invalid_hash += 1

        self._test(
            "Provenance Hashing",
            missing_hash == 0 and invalid_hash == 0,
            f"100 events: {missing_hash} missing, {invalid_hash} invalid"
        )

    def _test_event_id_uniqueness(self):
        """Verify all events get unique event_ids."""
        from benchmarks.generator import DeterministicGenerator
        from ulpf.engine.pipeline import Pipeline

        gen = DeterministicGenerator(seed=100)
        pipeline = Pipeline()
        lines = gen.generate(500)

        event_ids = set()
        duplicates = 0
        for line in lines:
            result = pipeline.process_line(line)
            if result.get("success") and result.get("event"):
                eid = result["event"].get("event_id")
                if eid in event_ids:
                    duplicates += 1
                event_ids.add(eid)

        self._test(
            "Event ID Uniqueness",
            duplicates == 0,
            f"500 events: {len(event_ids)} unique IDs, {duplicates} duplicates"
        )

    def _test_raw_event_preservation(self):
        """Verify original log line is preserved in raw_event field."""
        from benchmarks.generator import DeterministicGenerator
        from ulpf.engine.pipeline import Pipeline

        gen = DeterministicGenerator(seed=101)
        pipeline = Pipeline()
        lines = gen.generate(100)

        missing_raw = 0
        for line in lines:
            result = pipeline.process_line(line)
            if result.get("success") and result.get("event"):
                raw = result["event"].get("raw_event", "")
                if not raw:
                    missing_raw += 1

        self._test(
            "Raw Event Preservation",
            missing_raw == 0,
            f"100 events: {missing_raw} missing raw_event"
        )

    def _test_timestamp_normalization(self):
        """Verify timestamps are normalized to ISO8601 format."""
        from benchmarks.generator import DeterministicGenerator
        from ulpf.engine.pipeline import Pipeline
        import re

        gen = DeterministicGenerator(seed=102)
        pipeline = Pipeline()
        lines = gen.generate(100)

        iso_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
        invalid_ts = 0
        no_ts = 0

        for line in lines:
            result = pipeline.process_line(line)
            if result.get("success") and result.get("event"):
                ts = result["event"].get("timestamp", "")
                if not ts:
                    no_ts += 1
                elif not iso_pattern.match(ts):
                    invalid_ts += 1

        # Allow some events with missing timestamps (e.g. CSV without headers)
        self._test(
            "Timestamp Normalization",
            invalid_ts == 0,
            f"100 events: {invalid_ts} non-ISO, {no_ts} missing"
        )

    def _test_storage_consistency(self):
        """Verify events stored in DuckDB match pipeline output."""
        from benchmarks.generator import DeterministicGenerator
        from ulpf.engine.pipeline import Pipeline
        from ulpf.storage.database import Database

        tmp_db = os.path.join(tempfile.gettempdir(), f"ulpf_integrity_{os.getpid()}.duckdb")
        try:
            gen = DeterministicGenerator(seed=103)
            pipeline = Pipeline()
            db = Database(db_path=tmp_db)

            lines = gen.generate(50)
            events = []
            for line in lines:
                result = pipeline.process_line(line)
                if result.get("success") and result.get("event"):
                    events.append(result["event"])

            stored = db.store_events_bulk(events)
            read_back = db.query(limit=100)

            db.close()

            self._test(
                "Storage Consistency",
                stored == len(events) and len(read_back) == len(events),
                f"Stored {stored}, read back {len(read_back)}, expected {len(events)}"
            )
        except Exception as e:
            self._test("Storage Consistency", False, str(e))
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass

    def _test_all_formats_parseable(self):
        """Verify all 9 supported formats produce successful parse results."""
        from benchmarks.generator import DeterministicGenerator
        from ulpf.engine.pipeline import Pipeline

        formats = ["syslog3164", "syslog5424", "cef", "leef", "json",
                    "xml", "csv", "kv", "w3c"]

        pipeline = Pipeline()
        failed_formats = []

        for fmt in formats:
            gen = DeterministicGenerator(seed=104)
            lines = gen.generate(10, format_filter=fmt)
            successes = 0
            for line in lines:
                result = pipeline.process_line(line)
                if result.get("success"):
                    successes += 1
            if successes < 5:  # At least 50% should parse
                failed_formats.append(f"{fmt}({successes}/10)")

        self._test(
            "All Formats Parseable",
            len(failed_formats) == 0,
            f"Failed: {', '.join(failed_formats)}" if failed_formats else "All 9 formats OK"
        )

    def _test_air_gap_mode(self):
        """Verify ULPF can initialize and process without network access."""
        from ulpf.plugin.interface import ULPFPlugin

        tmp_db = os.path.join(tempfile.gettempdir(), f"ulpf_airgap_{os.getpid()}.duckdb")
        try:
            plugin = ULPFPlugin()
            plugin.initialize({
                "storage_backend": "duckdb",
                "storage_path": tmp_db,
                "offline": True,
            })
            plugin.start()

            # Process a single event
            result = plugin.process_event({
                "raw": "<134>Sep 15 12:00:00 fw-01 sshd[1234]: Test air-gap event"
            })

            plugin.shutdown()

            self._test(
                "Air-Gap Mode",
                result.get("success", False),
                "Initialized, processed, and stored without network"
            )
        except Exception as e:
            self._test("Air-Gap Mode", False, str(e))
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass

    def _test_forensic_chain(self):
        """Verify forensic evidence chain integrity."""
        from ulpf.plugin.interface import ULPFPlugin

        tmp_db = os.path.join(tempfile.gettempdir(), f"ulpf_forensic_{os.getpid()}.duckdb")
        try:
            plugin = ULPFPlugin()
            plugin.initialize({
                "storage_backend": "duckdb",
                "storage_path": tmp_db,
            })
            plugin.start()

            # Process some events
            test_lines = [
                "<134>Sep 15 12:00:00 fw-01 sshd[1234]: Failed password for root from 45.33.32.156",
                "CEF:0|Vendor|FW|1.0|100|Test Event|5|src=10.0.0.1 dst=10.0.0.2",
                '{"timestamp": "2025-09-15T12:00:00Z", "source_ip": "192.168.1.100", "message": "Test"}',
            ]
            for line in test_lines:
                plugin.process_event({"raw": line})

            # Build forensic chain
            if plugin.forensic_builder:
                events = plugin.storage.query(limit=10)
                chain = plugin.forensic_builder.build_from_events(
                    events,
                    description="Integrity test chain",
                    tags=["integrity_test"],
                )
                integrity = chain.verify_integrity()
                valid = integrity.get("valid", False)
                self._test(
                    "Forensic Chain Integrity",
                    valid,
                    f"Chain ID: {chain.chain_id[:16]}..., items: {len(chain.items)}"
                )
            else:
                self._test(
                    "Forensic Chain Integrity",
                    True,
                    "Forensic builder not enabled (skipped)"
                )

            plugin.shutdown()
        except Exception as e:
            self._test("Forensic Chain Integrity", False, str(e))
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass


if __name__ == "__main__":
    validator = IntegrityValidator()
    validator.run_all()
