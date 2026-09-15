from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Optional

from aire_detection.models import EnrichmentResult


class EnrichmentCache:
    """Simple bounded TTL cache to avoid hammering rate-limited free-tier APIs."""

    def __init__(self, ttl_seconds: int = 3600, max_entries: int = 5000):
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._store: dict[str, tuple[float, EnrichmentResult]] = {}

    def get(self, key: str) -> Optional[EnrichmentResult]:
        entry = self._store.get(key)
        if not entry:
            return None
        ts, result = entry
        if time.time() - ts > self.ttl_seconds:
            self._store.pop(key, None)
            return None
        return result

    def set(self, key: str, result: EnrichmentResult) -> None:
        if len(self._store) >= self.max_entries:
            oldest_key = min(self._store, key=lambda k: self._store[k][0])
            self._store.pop(oldest_key, None)
        self._store[key] = (time.time(), result)

    def __len__(self):
        return len(self._store)


class ThreatIntelProvider(ABC):
    """
    Abstract base for a threat-intelligence provider.

    Concrete providers must:
      - never hardcode credentials (read from environment variables)
      - time out promptly instead of hanging the pipeline
      - fail safe: on any error, return a non-malicious, low-confidence
        result with `error` populated rather than raising, so a TI
        outage never blocks detection output
      - clearly mark whether the result came from a live API call
        ("REAL/LIVE") or a mock/test double ("MOCK/TEST")
    """

    name: str = "base"
    timeout_seconds: float = 5.0

    def __init__(self, cache: Optional[EnrichmentCache] = None):
        # NOTE: must use an explicit None-check, not `cache or EnrichmentCache()`.
        # EnrichmentCache defines __len__, so a freshly-constructed empty cache
        # is falsy and `or` would silently discard a valid caller-supplied cache.
        self.cache = cache if cache is not None else EnrichmentCache()

    @abstractmethod
    def _query(self, indicator: str, indicator_type: str) -> EnrichmentResult:
        ...

    def lookup(self, indicator: str, indicator_type: str = "ip") -> EnrichmentResult:
        cache_key = f"{self.name}:{indicator_type}:{indicator}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        try:
            result = self._query(indicator, indicator_type)
        except Exception as exc:  # safe fallback: never raise into the pipeline
            result = EnrichmentResult(
                provider=self.name, indicator=indicator, indicator_type=indicator_type,
                is_malicious=False, reputation_score=0.0, confidence=0.0,
                mode="MOCK/TEST", error=str(exc),
            )
        self.cache.set(cache_key, result)
        return result
