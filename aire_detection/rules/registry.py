from __future__ import annotations

from aire_detection.rules import auth, endpoint, script, network, web, priv, evasion, exfil
from aire_detection.rules.base import RuleRegistry


def build_default_registry(exfil_threshold_bytes: int = 500 * 1024 * 1024) -> RuleRegistry:
    """Builds a RuleRegistry containing every single-event rule (36 rules)."""
    registry = RuleRegistry()
    for rule in (
        auth.get_rules()
        + endpoint.get_rules()
        + script.get_rules()
        + network.get_rules()
        + web.get_rules()
        + priv.get_rules()
        + exfil.get_rules(threshold_bytes=exfil_threshold_bytes)
        + evasion.get_rules()
    ):
        registry.register(rule)
    return registry


def all_rule_ids() -> list[str]:
    return [r.meta.rule_id for r in build_default_registry().all()]
