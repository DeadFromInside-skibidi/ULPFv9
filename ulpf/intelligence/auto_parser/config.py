"""
Auto-Parser Configuration
===========================
Loads operating profiles (SOC / Industrial / Defense) and tunable thresholds
from config/auto_parser.json. Provides typed dataclass access.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any


import sys

# ---------------------------------------------------------------------------
# Path to default config
# ---------------------------------------------------------------------------
_ROOT = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))
_CONFIG_PATH = os.path.join(
    _ROOT, "config", "auto_parser.json",
)


# ---------------------------------------------------------------------------
# Typed threshold containers
# ---------------------------------------------------------------------------

@dataclass
class PromotionThresholds:
    """Evidence thresholds required for parser promotion."""
    min_accuracy: float = 0.90
    min_field_stability: float = 0.85
    min_type_stability: float = 0.90
    negative_test_pass: bool = True
    replay_success_rate: float = 0.95
    max_parse_time_ms: float = 1.0

    @classmethod
    def from_dict(cls, d: dict) -> PromotionThresholds:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class DriftThresholds:
    """Thresholds that trigger parser drift investigation."""
    miss_rate_trigger: float = 0.10
    field_mismatch_trigger: float = 0.05
    type_conflict_trigger: float = 0.03
    evaluation_window_events: int = 1000

    @classmethod
    def from_dict(cls, d: dict) -> DriftThresholds:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class PoisoningLimits:
    """Anti-poisoning rate limiters and resource caps."""
    per_source_unknown_events_per_sec: int = 500
    per_source_new_clusters_per_sec: int = 50
    max_template_length_tokens: int = 256
    max_token_count_per_event: int = 512
    max_sample_size_per_candidate: int = 1000
    max_learning_cpu_pct: int = 25
    max_learning_ram_mb: int = 512
    queue_overflow_policy: str = "sample"  # "sample" | "drop" | "quarantine"

    @classmethod
    def from_dict(cls, d: dict) -> PoisoningLimits:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class OperatingProfile:
    """Complete operating profile for a deployment environment."""
    name: str = "soc"
    description: str = ""
    auto_discovery: bool = True
    auto_promotion: bool = True
    learning_budget_pct: int = 25
    min_samples_for_promotion: int = 50
    template_stability_window: int = 20
    canary_duration_sec: int = 60
    canary_traffic_pct: int = 5
    max_active_templates: int = 10000
    max_candidate_templates: int = 5000
    signed_artifacts: bool = False
    audit_trail: str = "standard"
    offline_only: bool = False
    native_confidence_threshold: float = 0.75

    promotion: PromotionThresholds = field(default_factory=PromotionThresholds)
    drift: DriftThresholds = field(default_factory=DriftThresholds)
    poisoning: PoisoningLimits = field(default_factory=PoisoningLimits)

    @classmethod
    def from_dict(cls, name: str, d: dict) -> OperatingProfile:
        promo = PromotionThresholds.from_dict(d.get("promotion_thresholds", {}))
        drift = DriftThresholds.from_dict(d.get("drift_thresholds", {}))
        poison = PoisoningLimits.from_dict(d.get("poisoning_limits", {}))

        simple_fields = {
            k: v for k, v in d.items()
            if k in cls.__dataclass_fields__
            and k not in ("promotion", "drift", "poisoning")
        }

        return cls(name=name, promotion=promo, drift=drift, poisoning=poison, **simple_fields)


@dataclass
class ParserFamilyConfig:
    """Definition of a parser family and its sub-families."""
    name: str
    sub_families: list[str] = field(default_factory=list)
    description: str = ""

    @classmethod
    def from_dict(cls, name: str, d: dict) -> ParserFamilyConfig:
        return cls(
            name=name,
            sub_families=d.get("sub_families", []),
            description=d.get("description", ""),
        )


# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------

class AutoParserConfig:
    """
    Loads and provides access to auto-parser configuration.

    Usage:
        config = AutoParserConfig()          # loads default config
        profile = config.active_profile      # OperatingProfile
        families = config.parser_families    # dict[str, ParserFamilyConfig]
    """

    def __init__(self, config_path: str | None = None):
        self._path = config_path or _CONFIG_PATH
        self._raw: dict[str, Any] = {}
        self._profiles: dict[str, OperatingProfile] = {}
        self._families: dict[str, ParserFamilyConfig] = {}
        self._active_name: str = "soc"
        self._load()

    def _load(self) -> None:
        """Load configuration from JSON file, with safe defaults."""
        if os.path.isfile(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    self._raw = json.load(f)
            except Exception:
                self._raw = {}

        self._active_name = self._raw.get("active_profile", "soc")

        # Load profiles
        for name, profile_dict in self._raw.get("profiles", {}).items():
            self._profiles[name] = OperatingProfile.from_dict(name, profile_dict)

        # Ensure at least a default SOC profile exists
        if "soc" not in self._profiles:
            self._profiles["soc"] = OperatingProfile(name="soc")

        # Load parser families
        for name, fam_dict in self._raw.get("parser_families", {}).items():
            self._families[name] = ParserFamilyConfig.from_dict(name, fam_dict)

    @property
    def active_profile(self) -> OperatingProfile:
        """Return the currently active operating profile."""
        return self._profiles.get(self._active_name, self._profiles["soc"])

    @property
    def active_profile_name(self) -> str:
        return self._active_name

    def get_profile(self, name: str) -> OperatingProfile:
        """Return a specific profile by name."""
        return self._profiles.get(name, self._profiles["soc"])

    def set_active_profile(self, name: str) -> None:
        """Switch the active operating profile."""
        if name in self._profiles:
            self._active_name = name

    @property
    def parser_families(self) -> dict[str, ParserFamilyConfig]:
        """Return all configured parser families."""
        return self._families

    def get_family(self, family_name: str) -> ParserFamilyConfig | None:
        """Lookup a parser family by name."""
        return self._families.get(family_name)

    @property
    def all_profile_names(self) -> list[str]:
        return list(self._profiles.keys())

    def to_dict(self) -> dict:
        """Serialize current configuration state."""
        return {
            "active_profile": self._active_name,
            "profiles": {n: _profile_to_dict(p) for n, p in self._profiles.items()},
            "families": {n: {"sub_families": f.sub_families, "description": f.description}
                         for n, f in self._families.items()},
        }


def _profile_to_dict(p: OperatingProfile) -> dict:
    """Serialize an OperatingProfile to a plain dict."""
    from dataclasses import asdict
    d = asdict(p)
    # Rename nested dataclass keys to match JSON config format
    d["promotion_thresholds"] = d.pop("promotion")
    d["drift_thresholds"] = d.pop("drift")
    d["poisoning_limits"] = d.pop("poisoning")
    return d
