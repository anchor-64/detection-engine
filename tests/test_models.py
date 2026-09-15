from aire_detection.models import (
    DetectionMatch, EnrichmentResult, EventType, Incident, NormalizedEvent,
    Severity, SeverityResult, utc_now,
)


def test_normalized_event_roundtrip():
    e = NormalizedEvent(
        event_type=EventType.NETWORK_CONNECTION, timestamp=utc_now(),
        source="zeek", sensor="pc-a", source_ip="10.0.0.5", destination_ip="10.0.0.6",
        destination_port=443, bytes_out=1024, raw={"conn_state": "SF"},
    )
    d = e.to_dict()
    assert d["event_type"] == "NETWORK_CONNECTION"
    assert isinstance(d["timestamp"], str)
    restored = NormalizedEvent.from_dict(d)
    assert restored.source_ip == "10.0.0.5"
    assert restored.raw["conn_state"] == "SF"


def test_normalized_event_malformed_missing_required_field():
    try:
        NormalizedEvent.from_dict({"event_type": "NETWORK_CONNECTION", "source": "x", "sensor": "y"})
        assert False, "should have raised due to missing timestamp"
    except (KeyError, TypeError):
        pass


def test_normalized_event_unknown_event_type_rejected():
    try:
        NormalizedEvent.from_dict({
            "event_type": "NOT_A_REAL_TYPE", "timestamp": utc_now().isoformat(),
            "source": "x", "sensor": "y",
        })
        assert False, "should have raised on invalid event_type"
    except ValueError:
        pass


def test_detection_match_roundtrip():
    m = DetectionMatch(
        rule_id="AUTH-001", rule_name="Failed Authentication", description="desc",
        severity=Severity.LOW, confidence=0.9, mitre_techniques=["T1110"],
        evidence={"user": "bob"}, triggering_event_ids=["abc"],
    )
    d = m.to_dict()
    restored = DetectionMatch.from_dict(d)
    assert restored.severity == Severity.LOW
    assert restored.evidence["user"] == "bob"


def test_enrichment_result_roundtrip():
    r = EnrichmentResult(
        provider="virustotal", indicator="1.2.3.4", indicator_type="ip",
        is_malicious=True, reputation_score=90.0, confidence=0.9, mode="MOCK/TEST",
    )
    d = r.to_dict()
    restored = EnrichmentResult.from_dict(d)
    assert restored.is_malicious is True
    assert restored.mode == "MOCK/TEST"


def test_severity_result_roundtrip():
    s = SeverityResult(severity=Severity.HIGH, score=72.5, reasons=["a", "b"], factors={"x": 1})
    d = s.to_dict()
    restored = SeverityResult.from_dict(d)
    assert restored.severity == Severity.HIGH
    assert restored.score == 72.5


def test_incident_roundtrip_json_safe():
    import json
    i = Incident(
        rule_id="NETWORK-001", rule_name="Port Scanning", severity=Severity.MEDIUM,
        confidence=0.7, mitre_techniques=["T1046"], evidence={"ports": [22, 80]},
    )
    d = i.to_dict()
    json.dumps(d)  # must not raise
    restored = Incident.from_dict(d)
    assert restored.rule_id == "NETWORK-001"
    assert restored.severity == Severity.MEDIUM


def test_severity_rank_ordering():
    assert Severity.LOW.rank < Severity.MEDIUM.rank < Severity.HIGH.rank < Severity.CRITICAL.rank
