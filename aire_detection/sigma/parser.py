"""
Practical Sigma-style rule support.

IMPORTANT — SCOPE DISCLAIMER:
This module implements a *practical subset* of the Sigma rule
specification, not the full SigmaHQ specification. Supported:

  - top-level fields: id, title, description, status, level, logsource,
    detection, tags
  - a `detection` block containing named selections (dicts of
    field: value or field: [values]) and a `condition` string that is
    one of: "selection", "not selection", "sel1 and sel2",
    "sel1 or sel2", "1 of sel*", "all of sel*"
  - field value matching: exact match, list-of-values (OR), and
    simple wildcard matching with `*` via fnmatch, plus a `|contains`,
    `|startswith`, `|endswith` field-name modifier suffix

NOT supported (explicitly out of scope): aggregation conditions
(count() by ...), near/timeframe correlation, backslash field
modifiers beyond contains/startswith/endswith, regex modifiers, and
the full Sigma correlation-rules extension. Anything requiring those
should be expressed as a native Rule/CorrelationRule instead.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

import yaml

from aire_detection.models import DetectionMatch, NormalizedEvent, Severity
from aire_detection.mitre.mapping import ATTACK_TECHNIQUES, validate_techniques

SIGMA_LEVEL_TO_SEVERITY = {
    "informational": Severity.LOW,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


@dataclass
class SigmaRule:
    rule_id: str
    title: str
    description: str
    level: str
    logsource: dict
    detection: dict
    tags: list = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        return SIGMA_LEVEL_TO_SEVERITY.get((self.level or "medium").lower(), Severity.MEDIUM)

    @property
    def mitre_techniques(self) -> list:
        techniques = []
        for tag in self.tags:
            t = tag.replace("attack.", "") if tag.startswith("attack.") else tag
            if t.upper().startswith("T") and t[1:2].isdigit():
                techniques.append(t.upper())
        return techniques

    @classmethod
    def from_yaml(cls, text: str) -> "SigmaRule":
        data = yaml.safe_load(text)
        return cls(
            rule_id=str(data.get("id", data.get("title", "sigma-unknown"))),
            title=data.get("title", "Untitled Sigma Rule"),
            description=data.get("description", ""),
            level=data.get("level", "medium"),
            logsource=data.get("logsource", {}) or {},
            detection=data.get("detection", {}) or {},
            tags=data.get("tags", []) or [],
        )

    def _selection_matches(self, selection: dict, event_dict: dict) -> bool:
        for field_name, expected in selection.items():
            modifier = None
            if "|" in field_name:
                field_name, modifier = field_name.split("|", 1)
            actual = event_dict.get(field_name)
            if actual is None:
                return False
            actual_str = str(actual)
            expected_values = expected if isinstance(expected, list) else [expected]
            matched_any = False
            for exp in expected_values:
                exp_str = str(exp)
                if modifier == "contains":
                    matched_any = exp_str.lower() in actual_str.lower()
                elif modifier == "startswith":
                    matched_any = actual_str.lower().startswith(exp_str.lower())
                elif modifier == "endswith":
                    matched_any = actual_str.lower().endswith(exp_str.lower())
                elif "*" in exp_str:
                    matched_any = fnmatch.fnmatch(actual_str.lower(), exp_str.lower())
                else:
                    matched_any = actual_str.lower() == exp_str.lower()
                if matched_any:
                    break
            if not matched_any:
                return False
        return True

    def evaluate(self, event: NormalizedEvent) -> bool:
        condition = self.detection.get("condition", "")
        selections = {k: v for k, v in self.detection.items() if k != "condition"}
        event_dict = event.to_dict()
        # flatten raw sub-dict fields to top level for matching convenience
        for k, v in (event.raw or {}).items():
            event_dict.setdefault(k, v)

        results = {name: self._selection_matches(sel, event_dict) for name, sel in selections.items()}

        cond = condition.strip()
        if cond in results:
            return results[cond]
        if cond.startswith("not "):
            name = cond[4:].strip()
            return not results.get(name, False)
        if " and " in cond:
            parts = [p.strip() for p in cond.split(" and ")]
            return all(results.get(p, False) for p in parts)
        if " or " in cond:
            parts = [p.strip() for p in cond.split(" or ")]
            return any(results.get(p, False) for p in parts)
        if cond.startswith("1 of "):
            prefix = cond[5:].strip().rstrip("*")
            matching = [v for k, v in results.items() if k.startswith(prefix)]
            return any(matching)
        if cond.startswith("all of "):
            prefix = cond[7:].strip().rstrip("*")
            matching = [v for k, v in results.items() if k.startswith(prefix)]
            return bool(matching) and all(matching)
        # empty/unsupported condition: no match, fail closed (no false alerting)
        return False

    def to_detection_match(self, event: NormalizedEvent) -> DetectionMatch:
        # Only keep technique IDs that are in our curated, validated registry;
        # community Sigma rules sometimes reference IDs we haven't vetted.
        techniques = [t for t in self.mitre_techniques if t in ATTACK_TECHNIQUES]
        return DetectionMatch(
            rule_id=f"SIGMA-{self.rule_id}",
            rule_name=self.title,
            description=self.description,
            severity=self.severity,
            confidence=0.6,
            mitre_techniques=techniques,
            evidence={"logsource": self.logsource, "matched_event": event.event_id},
            triggering_event_ids=[event.event_id],
            false_positive_notes="Sigma-rule-based match; false-positive rate depends on the specific community rule quality.",
        )


class SigmaRuleSet:
    """A collection of loaded SigmaRule objects that can be evaluated against events."""

    def __init__(self, rules: list[SigmaRule] | None = None):
        self.rules = rules or []

    @classmethod
    def load_directory(cls, directory: str) -> "SigmaRuleSet":
        import os
        rules = []
        if os.path.isdir(directory):
            for fname in sorted(os.listdir(directory)):
                if fname.endswith((".yml", ".yaml")):
                    with open(os.path.join(directory, fname), "r", encoding="utf-8") as fh:
                        rules.append(SigmaRule.from_yaml(fh.read()))
        return cls(rules=rules)

    def evaluate(self, event: NormalizedEvent) -> list[DetectionMatch]:
        matches = []
        for rule in self.rules:
            try:
                if rule.evaluate(event):
                    matches.append(rule.to_detection_match(event))
            except Exception:
                continue
        return matches
