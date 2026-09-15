from __future__ import annotations

import os
import time
from dataclasses import dataclass, field


@dataclass
class SensorCredential:
    sensor_id: str
    api_key: str


class SensorAuthStore:
    """
    Holds valid sensor API keys.

    Keys are read from the AIRE_SENSOR_KEYS environment variable, a
    comma-separated list of `sensor_id:api_key` pairs, e.g.:

        AIRE_SENSOR_KEYS="pc-a-collector:s3cr3t,vm-lab-collector:othersecret"

    Never hardcode real credentials in source or version control.
    A small set of deterministic test keys is provided for offline
    tests only and is clearly namespaced (`test-sensor-*`).
    """

    _TEST_CREDENTIALS = {
        "test-sensor-1": "test-key-do-not-use-in-prod",
        "test-sensor-2": "test-key-2-do-not-use-in-prod",
    }

    def __init__(self, credentials: dict | None = None, include_test_credentials: bool = False):
        self._credentials: dict[str, str] = {}
        if credentials:
            self._credentials.update(credentials)
        else:
            raw = os.environ.get("AIRE_SENSOR_KEYS", "")
            for pair in filter(None, (p.strip() for p in raw.split(","))):
                if ":" not in pair:
                    continue
                sensor_id, key = pair.split(":", 1)
                self._credentials[sensor_id] = key
        if include_test_credentials:
            self._credentials.update(self._TEST_CREDENTIALS)

    def is_valid(self, sensor_id: str, api_key: str) -> bool:
        expected = self._credentials.get(sensor_id)
        return expected is not None and _constant_time_eq(expected, api_key)

    def sensor_ids(self):
        return list(self._credentials.keys())


def _constant_time_eq(a: str, b: str) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0


@dataclass
class TokenBucket:
    capacity: int
    tokens: float
    refill_rate_per_sec: float
    last_refill: float = field(default_factory=time.time)

    def allow(self, cost: int = 1) -> bool:
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate_per_sec)
        self.last_refill = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


class RateLimiter:
    """Bounded per-sensor token-bucket rate limiter (in-memory, single-process)."""

    def __init__(self, capacity: int = 50, refill_rate_per_sec: float = 5.0, max_sensors: int = 5000):
        self.capacity = capacity
        self.refill_rate_per_sec = refill_rate_per_sec
        self.max_sensors = max_sensors
        self._buckets: dict[str, TokenBucket] = {}

    def allow(self, sensor_id: str, cost: int = 1) -> bool:
        bucket = self._buckets.get(sensor_id)
        if bucket is None:
            if len(self._buckets) >= self.max_sensors:
                # evict an arbitrary entry to bound memory under a sensor-ID flood
                self._buckets.pop(next(iter(self._buckets)))
            bucket = TokenBucket(self.capacity, self.capacity, self.refill_rate_per_sec)
            self._buckets[sensor_id] = bucket
        return bucket.allow(cost)
