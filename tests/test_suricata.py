import pytest

from aire_detection.models import EventType
from aire_detection.normalization.suricata import normalize_suricata_alert


def test_suricata_normalize_basic():
    raw = {
        "timestamp": "2026-01-01T12:00:00.000000+0000",
        "src_ip": "203.0.113.5", "src_port": 51234,
        "dest_ip": "10.0.0.10", "dest_port": 22, "proto": "TCP",
        "alert": {"signature": "ET SCAN Potential SSH Scan", "severity": 2, "category": "Attempted Information Leak"},
        "app_proto": "ssh",
    }
    event = normalize_suricata_alert(raw, sensor="suricata-sensor-01")
    assert event.event_type == EventType.SURICATA_ALERT
    assert event.source_ip == "203.0.113.5"
    assert event.destination_port == 22
    assert event.raw["signature"] == "ET SCAN Potential SSH Scan"
    assert "Attempted Information Leak" in event.tags


def test_suricata_normalize_missing_timestamp_raises():
    with pytest.raises(ValueError):
        normalize_suricata_alert({"src_ip": "1.2.3.4"}, sensor="s1")


def test_suricata_normalize_missing_alert_block_defaults_safely():
    raw = {"timestamp": "2026-01-01T12:00:00.000000+0000", "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8", "proto": "TCP"}
    event = normalize_suricata_alert(raw, sensor="s1")
    assert event.raw["signature"] is None
    assert event.tags == []
