"""Abstract Base Parser — all ULPF parsers inherit from this."""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional


class _HeaderLine(dict):
    """Sentinel returned by ``parse()`` when a line was a stream header."""

    def __repr__(self) -> str:
        return "HEADER_LINE"


HEADER_LINE = _HeaderLine()


class BaseParser(ABC):
    """
    Plug-and-play parser interface.

    To add a new parser:
      1. Subclass BaseParser
      2. Set parser_id, parser_name, supported_formats
      3. Implement can_parse() and parse()
      4. Drop the file in ulpf/parsers/ — auto-discovered

    ``parse()`` receives pipeline context as keyword arguments
    (``raw_hash``, ``event_id``, ``timestamp_now``) and should forward them
    to ``build_normalized_event(**kwargs)``.
    """
    parser_id: str = "base"
    parser_name: str = "Base Parser"
    supported_formats: list[str] = []
    description: str = ""
    version: str = "1.0.0"

    @abstractmethod
    def can_parse(self, raw_line: str) -> bool:
        """Return True if this parser can handle the raw log line."""
        ...

    @abstractmethod
    def parse(self, raw_line: str, **kwargs) -> Optional[dict]:
        """Parse raw log line → normalized event dict.

        Return None on failure, or ``HEADER_LINE`` if the line was a stream
        header that only updated parser state.
        """
        ...

    def consume_header(self, raw_line: str) -> bool:
        """Absorb a stream header line (e.g. W3C ``#Fields:``, CSV header row).

        Returns True if the line was a header and must not become an event.
        Stateless formats keep the default.
        """
        return False

    def reset_state(self) -> None:
        """Forget per-stream state (headers) — called at the start of each file."""

    def get_info(self) -> dict:
        return {
            "parser_id": self.parser_id,
            "parser_name": self.parser_name,
            "supported_formats": self.supported_formats,
            "description": self.description,
            "version": self.version,
        }
