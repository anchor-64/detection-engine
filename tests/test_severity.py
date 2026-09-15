from aire_detection.models import DetectionMatch, EnrichmentResult, Severity
from aire_detection.severity.classifier import classify_severity


def _match(severity=Severity.MEDIUM, confidence=0.5):
    return DetectionMatch(
        rule_id="TEST-001", rule_name="Test Rule", description="desc",
        severity=severity, confidence=confidence, mitre_techniques=["T1110"],
        evidence={}, triggering_event_ids=["e1"],
    )


def test_base_severity_no_modifiers():
    result = classify_severity(_match(Severity.LOW, confidence=0.5))
    assert result.severity in (Severity.LOW, Severity.MEDIUM)  # base 20 + small confidence adj
    assert "Base score" in result.reasons[0]


def test_malicious_enrichment_increases_severity():
    clean = classify_severity(_match(Severity.MEDIUM, confidence=0.5), enrichments=[])
    dirty = classify_severity(_match(Severity.MEDIUM, confidence=0.5), enrichments=[
        EnrichmentResult(provider="virustotal", indicator="1.2.3.4", indicator_type="ip",
                          is_malicious=True, reputation_score=95.0, confidence=0.9, mode="MOCK/TEST"),
    ])
    assert dirty.score > clean.score
    assert dirty.severity.rank >= clean.severity.rank


def test_non_malicious_enrichment_does_not_increase_score():
    clean = classify_severity(_match(Severity.MEDIUM, confidence=0.5), enrichments=[])
    checked_clean = classify_severity(_match(Severity.MEDIUM, confidence=0.5), enrichments=[
        EnrichmentResult(provider="virustotal", indicator="1.2.3.4", indicator_type="ip",
                          is_malicious=False, reputation_score=1.0, confidence=0.9, mode="MOCK/TEST"),
    ])
    assert checked_clean.score == clean.score


def test_asset_criticality_increases_score():
    standard = classify_severity(_match(), asset_criticality="standard")
    critical_asset = classify_severity(_match(), asset_criticality="critical")
    assert critical_asset.score > standard.score


def test_correlation_flag_increases_score():
    single = classify_severity(_match(), is_correlated=False)
    correlated = classify_severity(_match(), is_correlated=True)
    assert correlated.score > single.score


def test_confidence_scales_score():
    low_conf = classify_severity(_match(Severity.MEDIUM, confidence=0.1))
    high_conf = classify_severity(_match(Severity.MEDIUM, confidence=0.95))
    assert high_conf.score > low_conf.score


def test_score_bounded_0_to_100():
    result = classify_severity(_match(Severity.CRITICAL, confidence=1.0), enrichments=[
        EnrichmentResult(provider="virustotal", indicator="1.2.3.4", indicator_type="ip",
                          is_malicious=True, reputation_score=100.0, confidence=1.0, mode="MOCK/TEST"),
    ], asset_criticality="critical", is_correlated=True)
    assert 0.0 <= result.score <= 100.0


def test_deterministic_same_inputs_same_output():
    m = _match(Severity.HIGH, confidence=0.7)
    r1 = classify_severity(m, asset_criticality="high", is_correlated=True)
    r2 = classify_severity(m, asset_criticality="high", is_correlated=True)
    assert r1.score == r2.score
    assert r1.severity == r2.severity


def test_reasons_are_human_readable_and_nonempty():
    result = classify_severity(_match())
    assert len(result.reasons) >= 2
    assert all(isinstance(r, str) and len(r) > 0 for r in result.reasons)


def test_unknown_asset_criticality_falls_back_to_standard():
    known = classify_severity(_match(), asset_criticality="standard")
    unknown = classify_severity(_match(), asset_criticality="not-a-real-tier")
    assert known.score == unknown.score
