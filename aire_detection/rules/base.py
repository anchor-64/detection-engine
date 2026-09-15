"""
Base infrastructure for detection rules.

Two kinds of rules exist in this engine:

1. Single-event rules: `Rule.match(event)` inspects one normalized
   event and returns a DetectionMatch or None. These are stateless.

2. Correlation rules: live in aire_detection/correlation/engine.py
   and maintain bounded, expiring state across many events (e.g.
   counting failed logins per source IP within a time window).

Every rule declares its static metadata (id, name, description,
severity, default confidence, MITRE techniques, false-positive
notes) up front so documentation and tests can introspect it
without instantiating telemetry.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from aire_detection.models import DetectionMatch, NormalizedEvent, Severity
from aire_detection.mitre.mapping import validate_techniques


@dataclass
class RuleMeta:
    rule_id: str
    name: str
    description: str
    severity: Severity
    confidence: float
    mitre_techniques: list = field(default_factory=list)
    false_positive_notes: str = ""

    def __post_init__(self):
        validate_techniques(self.mitre_techniques)
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"{self.rule_id}: confidence must be within [0,1]")


class Rule:
    """Base class for a stateless, single-event detection rule."""

    meta: RuleMeta

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        raise NotImplementedError

    def _build_match(self, event: NormalizedEvent, evidence: dict,
                      confidence: Optional[float] = None,
                      severity: Optional[Severity] = None) -> DetectionMatch:
        return DetectionMatch(
            rule_id=self.meta.rule_id,
            rule_name=self.meta.name,
            description=self.meta.description,
            severity=severity or self.meta.severity,
            confidence=confidence if confidence is not None else self.meta.confidence,
            mitre_techniques=list(self.meta.mitre_techniques),
            evidence=evidence,
            triggering_event_ids=[event.event_id],
            false_positive_notes=self.meta.false_positive_notes,
        )


class RuleRegistry:
    """Central registry of all single-event rules, keyed by rule_id."""

    def __init__(self):
        self._rules: dict[str, Rule] = {}

    def register(self, rule: Rule) -> None:
        if rule.meta.rule_id in self._rules:
            raise ValueError(f"Duplicate rule id registered: {rule.meta.rule_id}")
        self._rules[rule.meta.rule_id] = rule

    def get(self, rule_id: str) -> Optional[Rule]:
        return self._rules.get(rule_id)

    def all(self) -> list[Rule]:
        return list(self._rules.values())

    def evaluate(self, event: NormalizedEvent) -> list[DetectionMatch]:
        matches = []
        for rule in self._rules.values():
            try:
                m = rule.match(event)
            except Exception:
                # A single misbehaving rule must never take down the pipeline.
                continue
            if m is not None:
                matches.append(m)
        return matches

    def __len__(self):
        return len(self._rules)

    def __contains__(self, rule_id):
        return rule_id in self._rules
