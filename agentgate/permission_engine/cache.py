"""
Simple TTL-based dict cache for IAM policy data.

Keys follow the pattern: "managed:{policy_arn}" or "inline:{identity}:{name}".
"""

from __future__ import annotations

import time
from typing import Any

DEFAULT_TTL = 300  # 5 minutes


class PolicyCache:
    """In-memory TTL cache for policy documents."""

    def __init__(self, ttl: float = DEFAULT_TTL) -> None:
        self._ttl = ttl
        self._store: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        """Return cached value if present and not expired, else None."""
        entry = self._store.get(key)
        if entry is None:
            return None
        timestamp, value = entry
        if time.monotonic() - timestamp > self._ttl:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        """Store a value with the current timestamp."""
        self._store[key] = (time.monotonic(), value)

    def invalidate(self, key: str) -> None:
        """Remove a specific key from the cache."""
        self._store.pop(key, None)

    def clear(self) -> None:
        """Remove all entries."""
        self._store.clear()

    @property
    def size(self) -> int:
        """Number of entries (including possibly expired ones)."""
        return len(self._store)
