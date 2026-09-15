import pytest

from aire_detection.models import EventType
from aire_detection.normalization.zeek import normalize_zeek_conn


def test_zeek_normalize_basic():
    raw = {
        "ts": 1767268800.123456, "id.orig_h": "10.0.0.5", "id.orig_p": 51234,
        "id.resp_h": "10.0.0.10", "id.resp_p": 445, "proto": "tcp",
        "conn_state": "S0", "orig_bytes": 120, "resp_bytes": 0,
    }
    event = normalize_zeek_conn(raw, sensor="zeek-sensor-01")
    assert event.event_type == EventType.NETWORK_CONNECTION
    assert event.source_ip == "10.0.0.5"
    assert event.destination_port == 445
    assert event.connection_state == "S0"
    assert event.bytes_out == 120


def test_zeek_normalize_missing_ts_raises():
    with pytest.raises(ValueError):
        normalize_zeek_conn({"id.orig_h": "10.0.0.5"}, sensor="s1")


def test_zeek_normalize_extra_fields_preserved_in_raw():
    raw = {"ts": 1767268800.0, "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.10",
           "service": "smb", "local_orig": True}
    event = normalize_zeek_conn(raw, sensor="s1")
    assert event.raw["service"] == "smb"
    assert event.raw["local_orig"] is True


def test_zeek_normalize_feeds_smb_anomaly_rule():
    from aire_detection.rules.network import SMBConnectionAnomalyRule
    raw = {"ts": 1767268800.0, "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.10",
           "id.resp_p": 445, "smb_anomaly": "anonymous_logon"}
    event = normalize_zeek_conn(raw, sensor="s1")
    rule = SMBConnectionAnomalyRule()
    assert rule.match(event) is not None


def test_zeek_normalize_feeds_port_scan_correlation():
    """Vendor-neutrality guard: Zeek-sourced connections must be able to
    trigger the same generic NETWORK-001 correlation rule as any other
    NETWORK_CONNECTION-typed telemetry, without rule-side special-casing."""
    from datetime import timedelta
    from aire_detection.correlation.engine import PortScanRule

    rule = PortScanRule(distinct_port_threshold=5, window_seconds=60)
    base_ts = 1767268800.0
    match = None
    for i in range(5):
        raw = {"ts": base_ts + i, "id.orig_h": "198.51.100.20", "id.resp_h": "10.0.0.5",
               "id.resp_p": 1000 + i, "proto": "tcp"}
        event = normalize_zeek_conn(raw, sensor="zeek-sensor-01")
        result = rule.process(event)
        if result is not None:
            match = result
    assert match is not None
    assert match.rule_id == "NETWORK-001"
