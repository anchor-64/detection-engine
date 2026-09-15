"""
Mandatory Scenario 2 — Port Scanning (end-to-end).

Simulates a source probing many distinct ports on a target host and
verifies the full pipeline produces a correctly-mapped NETWORK-001
Incident (T1046 — Network Service Discovery).
"""
from aire_detection.correlation.engine import CorrelationEngine
from aire_detection.enrichment.manager import EnrichmentManager
from aire_detection.enrichment.virustotal import MockVirusTotalProvider
from aire_detection.enrichment.abuseipdb import MockAbuseIPDBProvider
from aire_detection.models import EventType
from aire_detection.pipeline import DetectionPipeline
from aire_detection.rules.registry import build_default_registry


def _build_pipeline():
    return DetectionPipeline(
        rule_registry=build_default_registry(),
        correlation_engine=CorrelationEngine(),
        enrichment_manager=EnrichmentManager(providers=[MockVirusTotalProvider(), MockAbuseIPDBProvider()]),
    )


def test_e2e_port_scan_fires_and_maps_to_t1046(event_factory):
    pipeline = _build_pipeline()
    scanner_ip = "198.51.100.66"
    target_ip = "10.0.0.50"

    incidents = []
    for port in range(20, 40):  # 20 distinct ports, well above default threshold of 15
        e = event_factory(
            EventType.NETWORK_CONNECTION, offset_seconds=(port - 20) * 0.5,
            source="zeek", source_ip=scanner_ip, destination_ip=target_ip, destination_port=port,
        )
        incidents.extend(pipeline.process_event(e))

    port_scan_incidents = [i for i in incidents if i.rule_id == "NETWORK-001"]
    assert len(port_scan_incidents) >= 1

    incident = port_scan_incidents[-1]
    assert "T1046" in incident.mitre_techniques
    assert incident.source_ip == scanner_ip
    assert incident.destination_ip == target_ip
    assert incident.evidence["distinct_ports_contacted"] >= 15
    assert any(e["is_malicious"] for e in incident.enrichment)  # scanner IP is on the mock denylist
    assert incident.severity.value in ("HIGH", "CRITICAL")


def test_e2e_port_scan_below_threshold_does_not_fire(event_factory):
    pipeline = _build_pipeline()
    incidents = []
    for port in range(20, 25):  # only 5 distinct ports, below threshold of 15
        e = event_factory(
            EventType.NETWORK_CONNECTION, offset_seconds=(port - 20) * 0.5,
            source="zeek", source_ip="203.0.113.201", destination_ip="10.0.0.50", destination_port=port,
        )
        incidents.extend(pipeline.process_event(e))
    assert not any(i.rule_id == "NETWORK-001" for i in incidents)


def test_e2e_port_scan_same_port_repeated_is_not_a_scan(event_factory):
    """Repeated connections to the *same* port (e.g. a busy legitimate
    service) must not be mistaken for a scan, which specifically looks
    at distinct-port diversity."""
    pipeline = _build_pipeline()
    incidents = []
    for i in range(30):
        e = event_factory(
            EventType.NETWORK_CONNECTION, offset_seconds=i * 0.2,
            source="zeek", source_ip="203.0.113.202", destination_ip="10.0.0.50", destination_port=443,
        )
        incidents.extend(pipeline.process_event(e))
    assert not any(i.rule_id == "NETWORK-001" for i in incidents)
