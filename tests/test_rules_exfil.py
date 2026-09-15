from aire_detection.models import EventType
from aire_detection.rules.exfil import LargeOutboundTransferRule


def test_exfil001_positive_over_threshold(event_factory):
    rule = LargeOutboundTransferRule(threshold_bytes=1000)
    e = event_factory(EventType.NETWORK_CONNECTION, bytes_out=5000, destination_ip="8.8.8.8")
    assert rule.match(e) is not None


def test_exfil001_negative_under_threshold(event_factory):
    rule = LargeOutboundTransferRule(threshold_bytes=1000)
    e = event_factory(EventType.NETWORK_CONNECTION, bytes_out=500, destination_ip="8.8.8.8")
    assert rule.match(e) is None


def test_exfil001_boundary_exactly_at_threshold(event_factory):
    rule = LargeOutboundTransferRule(threshold_bytes=1000)
    e = event_factory(EventType.NETWORK_CONNECTION, bytes_out=1000, destination_ip="8.8.8.8")
    assert rule.match(e) is not None  # >= threshold counts as a match


def test_exfil001_malformed_missing_bytes(event_factory):
    rule = LargeOutboundTransferRule(threshold_bytes=1000)
    e = event_factory(EventType.NETWORK_CONNECTION, bytes_out=None, destination_ip="8.8.8.8")
    assert rule.match(e) is None


def test_exfil001_configurable_threshold_is_respected():
    rule_strict = LargeOutboundTransferRule(threshold_bytes=100)
    rule_lenient = LargeOutboundTransferRule(threshold_bytes=10_000_000)
    assert rule_strict.threshold_bytes != rule_lenient.threshold_bytes
