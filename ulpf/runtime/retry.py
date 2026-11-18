"""Delivery errors and retry policy shared by every sink."""
from __future__ import annotations

import random


class RetriableError(Exception):
    """Delivery failed but may succeed later (network, 5xx, 429, timeouts)."""


class PermanentError(Exception):
    """The destination rejected the data itself (4xx, mapping errors); retrying cannot help.

    ``rejected`` lists the indexes of records that were refused when a
    destination reports per-record status (e.g. Elasticsearch bulk items);
    None means the whole payload was refused.
    """

    def __init__(self, message: str, rejected: list[int] | None = None,
                 reasons: dict[int, str] | None = None):
        super().__init__(message)
        self.rejected = rejected
        self.reasons = reasons or {}


class Backoff:
    """Exponential backoff with full jitter."""

    def __init__(self, initial_ms: int = 500, max_ms: int = 60_000, max_attempts: int = 0):
        self.initial = initial_ms / 1000
        self.max = max_ms / 1000
        self.max_attempts = max_attempts
        self.attempt = 0

    def next_delay(self) -> float:
        self.attempt += 1
        cap = min(self.max, self.initial * (2 ** (self.attempt - 1)))
        return random.uniform(cap / 2, cap)

    @property
    def exhausted(self) -> bool:
        return self.max_attempts > 0 and self.attempt >= self.max_attempts

    def reset(self) -> None:
        self.attempt = 0


def classify_http(status: int, body: str = "") -> Exception | None:
    """Map an HTTP status to a delivery outcome (None = success)."""
    if 200 <= status < 300:
        return None
    if status in (408, 425, 429) or status >= 500:
        return RetriableError(f"HTTP {status}: {body[:300]}")
    return PermanentError(f"HTTP {status}: {body[:300]}")
