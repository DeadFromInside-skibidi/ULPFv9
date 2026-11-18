"""
Admission & Evidence
======================
Controls parser promotion lifecycle using evidence thresholds based on
the active operating profile.
"""
from __future__ import annotations

import logging
from typing import Any

from ulpf.intelligence.auto_parser.config import OperatingProfile, PromotionThresholds
from ulpf.intelligence.auto_parser.parser_spec import ParserSpec
from ulpf.intelligence.auto_parser.validator import ParserValidator, ValidationResult

logger = logging.getLogger(__name__)


class AdmissionController:
    """Controls whether a parser is admitted to the next lifecycle stage."""

    def __init__(self, profile: OperatingProfile):
        self.profile = profile

    def can_promote_to_canary(self, spec: ParserSpec, validation: ValidationResult) -> tuple[bool, str]:
        """Check if candidate can be promoted to canary."""
        if not self.profile.auto_promotion:
            return False, "Auto-promotion disabled by profile"

        if spec.sample_count < self.profile.min_samples_for_promotion:
            return False, f"Insufficient samples ({spec.sample_count} < {self.profile.min_samples_for_promotion})"

        if not validation.passed:
            return False, f"Failed validation: {', '.join(validation.rejection_reasons)}"

        return True, "Ready for canary"

    def can_promote_to_active(self, spec: ParserSpec, canary_duration: float, 
                              canary_events: int, error_count: int) -> tuple[bool, str]:
        """Check if canary can be promoted to active production."""
        if not self.profile.auto_promotion:
            return False, "Auto-promotion disabled by profile"

        if canary_duration < self.profile.canary_duration_sec:
            return False, f"Canary duration not met ({canary_duration:.0f}s < {self.profile.canary_duration_sec}s)"

        if error_count > 0:
            return False, f"Canary encountered {error_count} errors"

        return True, "Ready for production"
