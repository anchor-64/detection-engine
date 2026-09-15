from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
import urllib.parse

from aire_detection.enrichment.base import EnrichmentCache, ThreatIntelProvider
from aire_detection.models import EnrichmentResult


class AbuseIPDBProvider(ThreatIntelProvider):
    """
    Live AbuseIPDB provider. Credentials read exclusively from the
    ABUSEIPDB_API_KEY environment variable.
    """

    name = "abuseipdb"
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, cache: EnrichmentCache | None = None, api_key: str | None = None):
        super().__init__(cache=cache)
        self.api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY")

    def _query(self, indicator: str, indicator_type: str) -> EnrichmentResult:
        if indicator_type != "ip":
            return EnrichmentResult(
                provider=self.name, indicator=indicator, indicator_type=indicator_type,
                is_malicious=False, reputation_score=0.0, confidence=0.0,
                mode="MOCK/TEST", error="AbuseIPDB only supports IP indicators",
            )
        if not self.api_key:
            return EnrichmentResult(
                provider=self.name, indicator=indicator, indicator_type=indicator_type,
                is_malicious=False, reputation_score=0.0, confidence=0.0,
                mode="MOCK/TEST", error="ABUSEIPDB_API_KEY not configured; skipping live lookup",
            )

        qs = urllib.parse.urlencode({"ipAddress": indicator, "maxAgeInDays": 90})
        req = urllib.request.Request(
            f"{self.BASE_URL}?{qs}",
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            return EnrichmentResult(
                provider=self.name, indicator=indicator, indicator_type=indicator_type,
                is_malicious=False, reputation_score=0.0, confidence=0.0,
                mode="REAL/LIVE", error=f"AbuseIPDB request failed: {exc}",
            )

        payload = data.get("data", {})
        score = float(payload.get("abuseConfidenceScore", 0))
        return EnrichmentResult(
            provider=self.name, indicator=indicator, indicator_type=indicator_type,
            is_malicious=score >= 50, reputation_score=score,
            confidence=0.85, mode="REAL/LIVE",
            raw_response={"abuseConfidenceScore": score, "totalReports": payload.get("totalReports")},
        )


class MockAbuseIPDBProvider(ThreatIntelProvider):
    """Deterministic offline double for tests/demos — no network access required."""

    name = "abuseipdb"
    MALICIOUS_INDICATORS = {"198.51.100.66", "203.0.113.13"}

    def __init__(self, cache: EnrichmentCache | None = None, malicious_indicators: set | None = None):
        super().__init__(cache=cache)
        self.malicious_indicators = malicious_indicators or self.MALICIOUS_INDICATORS

    def _query(self, indicator: str, indicator_type: str) -> EnrichmentResult:
        is_bad = indicator in self.malicious_indicators
        return EnrichmentResult(
            provider=self.name, indicator=indicator, indicator_type=indicator_type,
            is_malicious=is_bad, reputation_score=98.0 if is_bad else 0.0,
            confidence=0.85, mode="MOCK/TEST",
            raw_response={"note": "deterministic offline mock, no network call made"},
        )
