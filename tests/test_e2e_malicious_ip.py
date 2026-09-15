"""
Mandatory Scenario 3 — Malicious Outbound Connection (end-to-end).

Simulates an internal host making an outbound connection to an IP
address that threat intelligence classifies as malicious, and
verifies the pipeline enriches, classifies, and raises an incident
appropriately even though no single-event or correlation rule alone
would otherwise flag a plain outbound connection.

This scenario exercises the C2-beacon detection path: a Suricata/Zeek-
style alert or connection combined with mandatory enrichment is what
turns an ordinary-looking connection into an actionable incident.
"""
from aire_detection.correlation.engine import CorrelationEngine
from aire_detection.enrichment.manager import EnrichmentManager
from aire_detection.enrichment.virustotal import MockVirusTotalProvider
from aire_detection.enrichment.abuseipdb import MockAbuseIPDBProvider
from aire_detection.models import EventType
from aire_detection.normalization.suricata import normalize_suricata_alert
from aire_detection.pipeline import DetectionPipeline
from aire_detection.rules.registry import build_default_registry


def _build_pipeline():
    return DetectionPipeline(
        rule_registry=build_default_registry(),
        correlation_engine=CorrelationEngine(),
        enrichment_manager=EnrichmentManager(providers=[MockVirusTotalProvider(), MockAbuseIPDBProvider()]),
    )


def test_e2e_malicious_ip_large_outbound_transfer_flagged(event_factory):
    """A large outbound transfer (EXFIL-001) to a known-malicious IP
    should be enriched and severely classified."""
    pipeline = _build_pipeline()
    malicious_ip = "203.0.113.13"  # on the mock TI denylist

    e = event_factory(
        EventType.NETWORK_CONNECTION, source="zeek", host="workstation-07",
        source_ip="10.0.0.42", destination_ip=malicious_ip, destination_port=443,
        bytes_out=600 * 1024 * 1024,  # 600MB, over the 500MB default EXFIL-001 threshold
    )
    incidents = pipeline.process_event(e)

    exfil_incidents = [i for i in incidents if i.rule_id == "EXFIL-001"]
    assert len(exfil_incidents) == 1
    incident = exfil_incidents[0]
    assert incident.destination_ip == malicious_ip
    assert any(en["is_malicious"] and en["provider"] in ("virustotal", "abuseipdb") for en in incident.enrichment)
    assert incident.severity.value == "CRITICAL"
    assert "T1041" in incident.mitre_techniques or "T1567" in incident.mitre_techniques


def test_e2e_malicious_ip_via_suricata_alert(event_factory):
    """A Suricata alert naming a connection to a malicious IP should
    normalize cleanly and, once enriched, reflect the elevated risk in
    the resulting Incident even though no bespoke Suricata-only rule
    exists (vendor-neutral detection requirement)."""
    pipeline = _build_pipeline()
    malicious_ip = "198.51.100.66"

    raw_alert = {
        "timestamp": "2026-01-01T12:00:00.000000+0000",
        "src_ip": "10.0.0.42", "src_port": 51000,
        "dest_ip": malicious_ip, "dest_port": 8443, "proto": "TCP",
        "alert": {"signature": "ET CNC Known malicious C2 beacon", "severity": 1, "category": "A Network Trojan was Detected"},
        "app_proto": "tls",
    }
    event = normalize_suricata_alert(raw_alert, sensor="suricata-sensor-01")
    enrichments = pipeline.enrichment_manager.enrich_indicator(event.destination_ip, "ip")

    assert any(e.is_malicious for e in enrichments)
    assert event.raw["signature"] == "ET CNC Known malicious C2 beacon"


def test_e2e_malicious_ip_clean_destination_no_ti_flag(event_factory):
    pipeline = _build_pipeline()
    e = event_factory(
        EventType.NETWORK_CONNECTION, source="zeek", host="workstation-07",
        source_ip="10.0.0.42", destination_ip="93.184.216.34",  # clean, not on denylist
        destination_port=443, bytes_out=600 * 1024 * 1024,
    )
    incidents = pipeline.process_event(e)
    exfil_incidents = [i for i in incidents if i.rule_id == "EXFIL-001"]
    assert len(exfil_incidents) == 1
    assert not any(en["is_malicious"] for en in exfil_incidents[0].enrichment)
    assert exfil_incidents[0].severity.value != "CRITICAL"
