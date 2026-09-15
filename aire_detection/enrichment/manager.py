from __future__ import annotations

from typing import Optional

from aire_detection.enrichment.base import ThreatIntelProvider
from aire_detection.models import EnrichmentResult


class EnrichmentManager:
    """Fans an indicator out to all configured providers and collects results.

    A single slow/failed provider never blocks the others or the caller —
    each provider's own fail-safe lookup() guarantees a result object.
    """

    def __init__(self, providers: Optional[list[ThreatIntelProvider]] = None):
        self.providers = providers or []

    def enrich_indicator(self, indicator: str, indicator_type: str = "ip") -> list[EnrichmentResult]:
        results = []
        for provider in self.providers:
            results.append(provider.lookup(indicator, indicator_type))
        return results

    def enrich_event_indicators(self, event) -> list[EnrichmentResult]:
        results = []
        if event.source_ip:
            results.extend(self.enrich_indicator(event.source_ip, "ip"))
        if event.destination_ip:
            results.extend(self.enrich_indicator(event.destination_ip, "ip"))
        if event.domain:
            results.extend(self.enrich_indicator(event.domain, "domain"))
        return results
