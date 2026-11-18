"""
Template Miners
================
Interface and implementations for template miners.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ulpf.intelligence.auto_parser.parser_spec import ParserSpec


class TemplateMiner(ABC):
    """Abstract interface for template miners."""

    @abstractmethod
    def mine(self, lines: list[str], fingerprint_id: str = "") -> list[ParserSpec]:
        """
        Process a batch of lines and return inferred ParserSpecs.
        May return multiple specs if multiple clusters are found.
        """
        pass
