"""
Mandatory Scenario 1 — SSH Brute Force (end-to-end).

Simulates a source repeatedly failing SSH authentication against a
target host, feeds the raw events through the full detection
pipeline (single-event rules + correlation + enrichment + severity),
and asserts on the final Incident: rule fired, MITRE mapping, and
severity uplift from threat-intel enrichment.
"""
from datetime import timedelta

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


def test_e2e_ssh_bruteforce_known_malicious_ip(event_factory):
    pipeline = _build_pipeline()
    attacker_ip = "198.51.100.66"  # matches the deterministic mock TI denylist

    incidents = []
    for i in range(6):
        e = event_factory(
            EventType.AUTHENTICATION_FAILURE, offset_seconds=i * 2,
            source="sshd", protocol="ssh", source_ip=attacker_ip,
            host="victim-host", user=f"admin{i % 2}", destination_port=22,
        )
        incidents.extend(pipeline.process_event(e))

    brute_force_incidents = [i for i in incidents if i.rule_id == "AUTH-004"]
    # The correlation window keeps evaluating on every subsequent event while
    # the attack continues, so it may fire more than once once the threshold
    # is crossed (this mirrors real streaming correlation engines; incident
    # de-duplication/aggregation is a Response Engine / SOAR concern, not a
    # detection concern). What matters here is that it fired at least once
    # and that every firing carries correct evidence.
    assert len(brute_force_incidents) >= 1, "SSH Brute Force should fire once the threshold is crossed"

    incident = brute_force_incidents[-1]
    assert "T1110" in incident.mitre_techniques
    assert incident.source_ip == attacker_ip
    assert incident.affected_host == "victim-host"
    assert incident.severity.value == "CRITICAL"  # HIGH base + malicious enrichment + correlation bump
    assert incident.recommended_response_category == "immediate_containment_review"
    assert any(e["is_malicious"] for e in incident.enrichment)
    assert incident.correlated_event_ids  # carries the full evidence chain, not just the last event


def test_e2e_ssh_bruteforce_malicious_ip_scores_higher_than_clean_ip(event_factory):
    """Enrichment must move the needle: identical attack pattern from a
    known-malicious IP should score at least as high as, and in this
    case strictly higher than, the same pattern from a clean IP —
    isolating the threat-intel contribution to the composite score."""
    def run(source_ip):
        pipeline = _build_pipeline()
        incidents = []
        for i in range(6):
            e = event_factory(
                EventType.AUTHENTICATION_FAILURE, offset_seconds=i * 2,
                source="sshd", protocol="ssh", source_ip=source_ip,
                host="victim-host", user="root", destination_port=22,
            )
            incidents.extend(pipeline.process_event(e))
        return [i for i in incidents if i.rule_id == "AUTH-004"][-1]

    malicious_incident = run("198.51.100.66")
    clean_incident = run("192.0.2.50")

    assert any(e["is_malicious"] for e in malicious_incident.enrichment)
    assert not any(e["is_malicious"] for e in clean_incident.enrichment)
    assert malicious_incident.severity_result["score"] > clean_incident.severity_result["score"]


def test_e2e_ssh_bruteforce_below_threshold_does_not_fire(event_factory):
    pipeline = _build_pipeline()
    incidents = []
    for i in range(3):  # below default threshold of 5
        e = event_factory(
            EventType.AUTHENTICATION_FAILURE, offset_seconds=i,
            source="sshd", protocol="ssh", source_ip="203.0.113.201",
            host="victim-host", user="root", destination_port=22,
        )
        incidents.extend(pipeline.process_event(e))
    assert not any(i.rule_id == "AUTH-004" for i in incidents)
