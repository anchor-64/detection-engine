from __future__ import annotations

import json
import os
import urllib.request
import urllib.error

from aire_detection.enrichment.base import EnrichmentCache, ThreatIntelProvider
from aire_detection.models import EnrichmentResult


class VirusTotalProvider(ThreatIntelProvider):
    """
    Live VirusTotal v3 provider.

    Credentials are read exclusively from the VT_API_KEY environment
    variable — never hardcoded. If the key is absent, lookups fail
    safe (see ThreatIntelProvider.lookup) rather than raising.
    """

    name = "virustotal"
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, cache: EnrichmentCache | None = None, api_key: str | None = None):
        super().__init__(cache=cache)
        self.api_key = api_key or os.environ.get("VT_API_KEY")

    def _endpoint_for(self, indicator: str, indicator_type: str) -> str:
        if indicator_type == "ip":
            return f"{self.BASE_URL}/ip_addresses/{indicator}"
        if indicator_type == "domain":
            return f"{self.BASE_URL}/domains/{indicator}"
        if indicator_type == "hash":
            return f"{self.BASE_URL}/files/{indicator}"
        raise ValueError(f"Unsupported indicator_type for VirusTotal: {indicator_type}")

    def _query(self, indicator: str, indicator_type: str) -> EnrichmentResult:
        if not self.api_key:
            return EnrichmentResult(
                provider=self.name, indicator=indicator, indicator_type=indicator_type,
                is_malicious=False, reputation_score=0.0, confidence=0.0,
                mode="MOCK/TEST", error="VT_API_KEY not configured; skipping live lookup",
            )

        url = self._endpoint_for(indicator, indicator_type)
        req = urllib.request.Request(url, headers={"x-apikey": self.api_key})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            return EnrichmentResult(
                provider=self.name, indicator=indicator, indicator_type=indicator_type,
                is_malicious=False, reputation_score=0.0, confidence=0.0,
                mode="REAL/LIVE", error=f"VirusTotal request failed: {exc}",
            )

        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        total = malicious + suspicious + harmless + stats.get("undetected", 0)
        reputation_score = round((malicious + 0.5 * suspicious) / total * 100, 1) if total else 0.0

        return EnrichmentResult(
            provider=self.name, indicator=indicator, indicator_type=indicator_type,
            is_malicious=malicious > 0, reputation_score=reputation_score,
            confidence=0.9 if total else 0.3, mode="REAL/LIVE",
            raw_response={"last_analysis_stats": stats},
        )


class MockVirusTotalProvider(ThreatIntelProvider):
    """
    Deterministic offline double for tests and demos. Never touches
    the network. Indicators are classified malicious using a static
    denylist so test outcomes are reproducible without Internet access.
    """

    name = "virustotal"
    MALICIOUS_INDICATORS = {"198.51.100.66", "203.0.113.13", "evil-c2.example.test"}

    def __init__(self, cache: EnrichmentCache | None = None, malicious_indicators: set | None = None):
        super().__init__(cache=cache)
        self.malicious_indicators = malicious_indicators or self.MALICIOUS_INDICATORS

    def _query(self, indicator: str, indicator_type: str) -> EnrichmentResult:
        is_bad = indicator in self.malicious_indicators
        return EnrichmentResult(
            provider=self.name, indicator=indicator, indicator_type=indicator_type,
            is_malicious=is_bad, reputation_score=95.0 if is_bad else 2.0,
            confidence=0.9, mode="MOCK/TEST",
            raw_response={"note": "deterministic offline mock, no network call made"},
        )
