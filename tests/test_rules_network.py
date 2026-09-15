from aire_detection.models import EventType
from aire_detection.rules import network as net


def test_network004_positive_external_rdp(event_factory):
    rule = net.SuspiciousRemoteServiceConnectionRule()
    e = event_factory(EventType.NETWORK_CONNECTION, source_ip="203.0.113.5",
                       destination_ip="10.0.0.10", destination_port=3389)
    assert rule.match(e) is not None


def test_network004_negative_internal_source(event_factory):
    rule = net.SuspiciousRemoteServiceConnectionRule()
    e = event_factory(EventType.NETWORK_CONNECTION, source_ip="10.0.0.5",
                       destination_ip="10.0.0.10", destination_port=3389,
                       raw={"source_is_internal": True})
    assert rule.match(e) is None


def test_network004_negative_normal_port(event_factory):
    rule = net.SuspiciousRemoteServiceConnectionRule()
    e = event_factory(EventType.NETWORK_CONNECTION, source_ip="203.0.113.5",
                       destination_ip="10.0.0.10", destination_port=443)
    assert rule.match(e) is None


def test_network005_positive_smb_anomaly(event_factory):
    rule = net.SMBConnectionAnomalyRule()
    e = event_factory(EventType.NETWORK_CONNECTION, destination_port=445,
                       raw={"smb_anomaly": "anonymous_logon"})
    assert rule.match(e) is not None


def test_network005_negative_no_anomaly_flag(event_factory):
    rule = net.SMBConnectionAnomalyRule()
    e = event_factory(EventType.NETWORK_CONNECTION, destination_port=445, raw={})
    assert rule.match(e) is None


def test_network007_positive_high_entropy_domain(event_factory):
    rule = net.SuspiciousDNSActivityRule()
    e = event_factory(EventType.DNS_EVENT, domain="xk29fjq8zmvpqlaw.example.com", source_ip="10.0.0.5")
    assert rule.match(e) is not None


def test_network007_negative_normal_domain(event_factory):
    rule = net.SuspiciousDNSActivityRule()
    e = event_factory(EventType.DNS_EVENT, domain="www.google.com", source_ip="10.0.0.5")
    assert rule.match(e) is None


def test_network007_boundary_short_label_skipped(event_factory):
    rule = net.SuspiciousDNSActivityRule()
    e = event_factory(EventType.DNS_EVENT, domain="ab.example.com", source_ip="10.0.0.5")
    assert rule.match(e) is None


def test_network007_malformed_empty_domain(event_factory):
    rule = net.SuspiciousDNSActivityRule()
    e = event_factory(EventType.DNS_EVENT, domain=None, source_ip="10.0.0.5")
    assert rule.match(e) is None
