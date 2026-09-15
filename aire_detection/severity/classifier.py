"""
Deterministic severity classification.

No machine learning is used, per project requirement. Severity is a
composite score built from explicit, auditable factors:

  - base severity declared by the firing rule
  - detection confidence
  - threat-intel reputation of any enriched indicators
  - asset criticality of the affected host (if known)
  - whether the finding is a correlated (multi-event) detection

The final severity is deterministic given the same inputs, and every
result carries a human-readable list of reasons explaining exactly
why it landed where it did.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from aire_detection.models import DetectionMatch, EnrichmentResult, Severity, SeverityResult

BASE_SCORE = {
    Severity.LOW: 20,
    Severity.MEDIUM: 45,
    Severity.HIGH: 70,
    Severity.CRITICAL: 90,
}

ASSET_CRITICALITY_WEIGHT = {
    "low": 0,
    "standard": 5,
    "high": 15,
    "critical": 25,
}


def classify_severity(
    match: DetectionMatch,
    enrichments: Optional[list[EnrichmentResult]] = None,
    asset_criticality: str = "standard",
    is_correlated: bool = False,
) -> SeverityResult:
    enrichments = enrichments or []
    reasons: list[str] = []
    factors: dict = {}

    score = BASE_SCORE[match.severity]
    factors["base_severity"] = match.severity.value
    factors["base_score"] = score
    reasons.append(f"Base score {score} from rule severity {match.severity.value} ({match.rule_id}).")

    confidence_adj = round((match.confidence - 0.5) * 20, 1)
    score += confidence_adj
    factors["confidence"] = match.confidence
    factors["confidence_adjustment"] = confidence_adj
    reasons.append(f"Confidence {match.confidence:.2f} adjusted score by {confidence_adj:+.1f}.")

    malicious_enrichments = [e for e in enrichments if e.is_malicious]
    if malicious_enrichments:
        max_rep = max(e.reputation_score for e in malicious_enrichments)
        rep_adj = round(max_rep / 100 * 25, 1)
        score += rep_adj
        factors["max_reputation_score"] = max_rep
        factors["reputation_adjustment"] = rep_adj
        providers = sorted({e.provider for e in malicious_enrichments})
        reasons.append(
            f"Threat-intel enrichment flagged an indicator as malicious "
            f"(reputation {max_rep:.0f}/100 via {', '.join(providers)}); +{rep_adj:.1f}."
        )
    elif enrichments:
        reasons.append("Threat-intel enrichment ran but found no malicious indicators; no adjustment.")

    asset_key = (asset_criticality or "standard").lower()
    asset_adj = ASSET_CRITICALITY_WEIGHT.get(asset_key, ASSET_CRITICALITY_WEIGHT["standard"])
    score += asset_adj
    factors["asset_criticality"] = asset_key
    factors["asset_adjustment"] = asset_adj
    if asset_adj:
        reasons.append(f"Affected asset criticality '{asset_key}' added +{asset_adj}.")

    if is_correlated:
        score += 10
        factors["correlated"] = True
        reasons.append("Finding is a multi-event correlated detection (higher confidence than a single isolated event); +10.")
    else:
        factors["correlated"] = False

    score = max(0.0, min(100.0, score))
    factors["final_score"] = score

    if score >= 85:
        severity = Severity.CRITICAL
    elif score >= 65:
        severity = Severity.HIGH
    elif score >= 40:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW

    reasons.append(f"Final composite score {score:.1f} maps to {severity.value}.")

    return SeverityResult(severity=severity, score=score, reasons=reasons, factors=factors)
