import pytest

from aire_detection.mitre.mapping import is_valid_technique, technique_name, validate_techniques
from aire_detection.rules.registry import build_default_registry
from aire_detection.correlation.engine import CorrelationEngine


def test_known_techniques_valid():
    assert is_valid_technique("T1110")
    assert is_valid_technique("T1046")
    assert technique_name("T1110") == "Brute Force"


def test_unknown_technique_invalid():
    assert not is_valid_technique("T9999.999")


def test_validate_techniques_raises_on_bad_id():
    with pytest.raises(ValueError):
        validate_techniques(["T1110", "T-FAKE"])


def test_every_single_event_rule_has_valid_mitre_ids():
    registry = build_default_registry()
    for rule in registry.all():
        for tid in rule.meta.mitre_techniques:
            assert is_valid_technique(tid), f"{rule.meta.rule_id} references invalid technique {tid}"


def test_every_correlation_rule_has_valid_mitre_ids():
    engine = CorrelationEngine()
    for rule in engine.rules:
        for tid in rule.meta.mitre_techniques:
            assert is_valid_technique(tid), f"{rule.meta.rule_id} references invalid technique {tid}"
