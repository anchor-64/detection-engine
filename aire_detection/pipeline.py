"""
End-to-end Detection Engine pipeline.

Telemetry -> Normalization (caller's responsibility; events arrive
already as NormalizedEvent) -> Detection (single-event rules + Sigma)
-> Correlation -> Threat Intelligence Enrichment -> Severity
Classification -> MITRE ATT&CK mapping (carried on the match) ->
Incident.

The pipeline never performs response actions. It only produces
Incident objects; delivering them to a Response Engine is handled by
aire_detection.integration.client.
"""
from __future__ import annotations

from typing import Optional

from aire_detection.correlation.engine import CorrelationEngine
from aire_detection.enrichment.manager import EnrichmentManager
from aire_detection.models import DetectionMatch, EnrichmentResult, Incident, NormalizedEvent
from aire_detection.rules.base import RuleRegistry
from aire_detection.rules.registry import build_default_registry
from aire_detection.severity.classifier import classify_severity
from aire_detection.sigma.parser import SigmaRuleSet

# Rules whose evidence commonly carries a source_ip that should be enriched.
_ENRICH_RULE_PREFIXES = ("AUTH-004", "NETWORK", "EXFIL", "WEB", "SCRIPT-002", "SCRIPT-003")

RESPONSE_CATEGORY_BY_SEVERITY = {
    "CRITICAL": "immediate_containment_review",
    "HIGH": "priority_analyst_review",
    "MEDIUM": "standard_queue",
    "LOW": "log_only",
}


class DetectionPipeline:
    def __init__(
        self,
        rule_registry: Optional[RuleRegistry] = None,
        correlation_engine: Optional[CorrelationEngine] = None,
        sigma_ruleset: Optional[SigmaRuleSet] = None,
        enrichment_manager: Optional[EnrichmentManager] = None,
        asset_criticality_lookup: Optional[dict] = None,
    ):
        self.rule_registry = rule_registry or build_default_registry()
        self.correlation_engine = correlation_engine or CorrelationEngine()
        self.sigma_ruleset = sigma_ruleset or SigmaRuleSet()
        self.enrichment_manager = enrichment_manager or EnrichmentManager()
        self.asset_criticality_lookup = asset_criticality_lookup or {}

    def _asset_criticality(self, event: NormalizedEvent) -> str:
        host = event.host or event.destination_ip
        return self.asset_criticality_lookup.get(host, "standard")

    def _should_enrich(self, match: DetectionMatch) -> bool:
        return match.rule_id.startswith(_ENRICH_RULE_PREFIXES)

    def _enrich_for_match(self, match: DetectionMatch, event: NormalizedEvent) -> list[EnrichmentResult]:
        if not self._should_enrich(match):
            return []
        results: list[EnrichmentResult] = []
        for ip in filter(None, [match.evidence.get("source_ip"), event.source_ip,
                                 match.evidence.get("destination_ip"), event.destination_ip]):
            results.extend(self.enrichment_manager.enrich_indicator(ip, "ip"))
        # de-duplicate by (provider, indicator)
        seen = set()
        deduped = []
        for r in results:
            key = (r.provider, r.indicator)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(r)
        return deduped

    def _match_to_incident(self, match: DetectionMatch, event: NormalizedEvent, is_correlated: bool) -> Incident:
        enrichments = self._enrich_for_match(match, event)
        severity_result = classify_severity(
            match, enrichments=enrichments,
            asset_criticality=self._asset_criticality(event),
            is_correlated=is_correlated,
        )
        return Incident(
            rule_id=match.rule_id,
            rule_name=match.rule_name,
            severity=severity_result.severity,
            confidence=match.confidence,
            mitre_techniques=match.mitre_techniques,
            evidence=match.evidence,
            source_ip=match.evidence.get("source_ip") or event.source_ip,
            destination_ip=match.evidence.get("destination_ip") or event.destination_ip,
            affected_user=match.evidence.get("user") or event.user,
            affected_host=match.evidence.get("host") or match.evidence.get("target_host") or event.host,
            enrichment=[e.to_dict() for e in enrichments],
            severity_result=severity_result.to_dict(),
            correlated_event_ids=match.triggering_event_ids,
            recommended_response_category=RESPONSE_CATEGORY_BY_SEVERITY.get(severity_result.severity.value),
        )

    def process_event(self, event: NormalizedEvent) -> list[Incident]:
        incidents: list[Incident] = []

        for match in self.rule_registry.evaluate(event):
            incidents.append(self._match_to_incident(match, event, is_correlated=False))

        for match in self.sigma_ruleset.evaluate(event):
            incidents.append(self._match_to_incident(match, event, is_correlated=False))

        for match in self.correlation_engine.process(event):
            incidents.append(self._match_to_incident(match, event, is_correlated=True))

        return incidents

    def process_batch(self, events: list[NormalizedEvent]) -> list[Incident]:
        incidents: list[Incident] = []
        for event in events:
            incidents.extend(self.process_event(event))
        return incidents
