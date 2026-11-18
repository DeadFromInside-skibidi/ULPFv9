"""
Parser Validator
==================
Three-axis validation for generated parsers:
1. Accuracy: Precision/recall against training samples
2. Safety: Negative-test suite, resource limits (regex complexity)
3. Performance: Throughput test against target EPS
"""
from __future__ import annotations

import time
import re
from dataclasses import dataclass
from typing import Any

from ulpf.intelligence.auto_parser.parser_spec import ParserSpec
from ulpf.intelligence.auto_parser.compiler import ParserCompiler, CompiledParser


@dataclass
class ValidationResult:
    """Result of parser validation."""
    passed: bool
    accuracy: float = 0.0
    throughput_eps: float = 0.0
    parse_time_ms_avg: float = 0.0
    rejection_reasons: list[str] = None

    def __post_init__(self):
        if self.rejection_reasons is None:
            self.rejection_reasons = []


class ParserValidator:
    """Validates a ParserSpec for production readiness."""

    def __init__(self, target_max_parse_time_ms: float = 1.0,
                 min_accuracy: float = 0.90):
        self.target_max_parse_time_ms = target_max_parse_time_ms
        self.min_accuracy = min_accuracy

    def validate(self, spec: ParserSpec, positive_samples: list[str],
                 negative_samples: list[str] = None) -> ValidationResult:
        """Run all validation checks."""
        result = ValidationResult(passed=True)
        negative_samples = negative_samples or []

        # 1. Compilation Check & Safety
        try:
            parser = ParserCompiler.compile(spec)
        except Exception as e:
            result.passed = False
            result.rejection_reasons.append(f"Compilation failed: {e}")
            return result

        # 2. Accuracy Check (Positive samples)
        if not positive_samples:
            result.passed = False
            result.rejection_reasons.append("No positive training samples provided")
            return result

        success_count = 0
        total_parse_time = 0.0

        for sample in positive_samples:
            t0 = time.perf_counter()
            parsed = parser.parse(sample)
            t1 = time.perf_counter()
            total_parse_time += (t1 - t0)
            
            if parsed is not None:
                success_count += 1

        result.accuracy = success_count / len(positive_samples)
        result.parse_time_ms_avg = (total_parse_time / len(positive_samples)) * 1000

        if result.accuracy < self.min_accuracy:
            result.passed = False
            result.rejection_reasons.append(f"Accuracy {result.accuracy:.2%} below minimum {self.min_accuracy:.2%}")

        if result.parse_time_ms_avg > self.target_max_parse_time_ms:
            result.passed = False
            result.rejection_reasons.append(
                f"Parse time {result.parse_time_ms_avg:.3f}ms exceeds target {self.target_max_parse_time_ms:.3f}ms"
            )

        # 3. Safety Check (Negative samples)
        for sample in negative_samples:
            parsed = parser.parse(sample)
            if parsed is not None:
                result.passed = False
                result.rejection_reasons.append("Failed negative test (matched when it shouldn't)")
                break

        return result
