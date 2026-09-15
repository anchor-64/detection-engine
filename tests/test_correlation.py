from datetime import timedelta

from aire_detection.models import EventType
from aire_detection.correlation.engine import (
    AccountLockoutSpikeRule, ArchiveBeforeTransferRule, BoundedWindowStore,
    ExcessiveConnectionAttemptsRule, HostDiscoverySweepRule, PasswordSprayingRule,
    PortScanRule, RDPBruteForceRule, RepeatedFailedAuthenticationRule, SSHBruteForceRule,
)


def _fire(rule, events):
    result = None
    for e in events:
        r = rule.process(e)
        if r is not None:
            result = r
    return result


def test_ssh_bruteforce_positive(event_factory):
    rule = SSHBruteForceRule(threshold=5, window_seconds=60)
    events = [
        event_factory(EventType.AUTHENTICATION_FAILURE, offset_seconds=i, source_ip="198.51.100.10",
                      host="victim", destination_port=22, protocol="ssh")
        for i in range(5)
    ]
    match = _fire(rule, events)
    assert match is not None
    assert match.rule_id == "AUTH-004"
    assert match.evidence["attempt_count"] == 5


def test_ssh_bruteforce_negative_below_threshold(event_factory):
    rule = SSHBruteForceRule(threshold=5, window_seconds=60)
    events = [
        event_factory(EventType.AUTHENTICATION_FAILURE, offset_seconds=i, source_ip="198.51.100.10",
                      host="victim", destination_port=22, protocol="ssh")
        for i in range(4)
    ]
    assert _fire(rule, events) is None


def test_ssh_bruteforce_window_expiration(event_factory):
    """Attempts spread out beyond the window should not accumulate."""
    rule = SSHBruteForceRule(threshold=5, window_seconds=10)
    events = [
        event_factory(EventType.AUTHENTICATION_FAILURE, offset_seconds=i * 20, source_ip="198.51.100.10",
                      host="victim", destination_port=22, protocol="ssh")
        for i in range(5)
    ]
    assert _fire(rule, events) is None  # each attempt is 20s apart, window is 10s


def test_ssh_bruteforce_ignores_non_ssh(event_factory):
    rule = SSHBruteForceRule(threshold=3, window_seconds=60)
    events = [
        event_factory(EventType.AUTHENTICATION_FAILURE, offset_seconds=i, source_ip="10.0.0.1",
                      host="victim", destination_port=443, protocol="https")
        for i in range(5)
    ]
    assert _fire(rule, events) is None


def test_password_spraying_positive(event_factory):
    rule = PasswordSprayingRule(distinct_user_threshold=5, window_seconds=600)
    events = [
        event_factory(EventType.AUTHENTICATION_FAILURE, offset_seconds=i, source_ip="203.0.113.9", user=f"user{i}")
        for i in range(5)
    ]
    match = _fire(rule, events)
    assert match is not None
    assert match.rule_id == "AUTH-003"


def test_password_spraying_negative_single_user_repeated(event_factory):
    rule = PasswordSprayingRule(distinct_user_threshold=5, window_seconds=600)
    events = [
        event_factory(EventType.AUTHENTICATION_FAILURE, offset_seconds=i, source_ip="203.0.113.9", user="same_user")
        for i in range(10)
    ]
    assert _fire(rule, events) is None  # only 1 distinct user, not spraying


def test_repeated_failed_auth_positive(event_factory):
    rule = RepeatedFailedAuthenticationRule(threshold=5, window_seconds=300)
    events = [event_factory(EventType.AUTHENTICATION_FAILURE, offset_seconds=i, user="bob", host="h1") for i in range(5)]
    assert _fire(rule, events) is not None


def test_account_lockout_spike_positive(event_factory):
    rule = AccountLockoutSpikeRule(threshold=3, window_seconds=600)
    events = [
        event_factory(EventType.ACCOUNT_LOCKOUT, offset_seconds=i, user=f"user{i}", domain="corp.local")
        for i in range(3)
    ]
    match = _fire(rule, events)
    assert match is not None
    assert match.rule_id == "AUTH-005"


def test_account_lockout_spike_negative(event_factory):
    rule = AccountLockoutSpikeRule(threshold=5, window_seconds=600)
    events = [
        event_factory(EventType.ACCOUNT_LOCKOUT, offset_seconds=i, user=f"user{i}", domain="corp.local")
        for i in range(2)
    ]
    assert _fire(rule, events) is None


def test_port_scan_positive(event_factory):
    rule = PortScanRule(distinct_port_threshold=10, window_seconds=60)
    events = [
        event_factory(EventType.NETWORK_CONNECTION, offset_seconds=i, source_ip="198.51.100.20",
                      destination_ip="10.0.0.5", destination_port=1000 + i)
        for i in range(10)
    ]
    match = _fire(rule, events)
    assert match is not None
    assert match.rule_id == "NETWORK-001"
    assert match.evidence["distinct_ports_contacted"] == 10


def test_port_scan_negative_same_port_repeated(event_factory):
    rule = PortScanRule(distinct_port_threshold=10, window_seconds=60)
    events = [
        event_factory(EventType.NETWORK_CONNECTION, offset_seconds=i, source_ip="198.51.100.20",
                      destination_ip="10.0.0.5", destination_port=443)
        for i in range(20)
    ]
    assert _fire(rule, events) is None  # only 1 distinct port


def test_host_discovery_sweep_positive(event_factory):
    rule = HostDiscoverySweepRule(distinct_host_threshold=10, window_seconds=60)
    events = [
        event_factory(EventType.NETWORK_CONNECTION, offset_seconds=i, source_ip="198.51.100.30",
                      destination_ip=f"10.0.0.{i}")
        for i in range(10)
    ]
    match = _fire(rule, events)
    assert match is not None
    assert match.rule_id == "NETWORK-002"


def test_excessive_connection_attempts_positive(event_factory):
    rule = ExcessiveConnectionAttemptsRule(threshold=50, window_seconds=60)
    events = [
        event_factory(EventType.NETWORK_CONNECTION, offset_seconds=i * 0.1, source_ip="198.51.100.40",
                      destination_ip="10.0.0.5")
        for i in range(50)
    ]
    match = _fire(rule, events)
    assert match is not None
    assert match.rule_id == "NETWORK-003"


def test_rdp_bruteforce_positive(event_factory):
    rule = RDPBruteForceRule(threshold=5, window_seconds=60)
    events = [
        event_factory(EventType.AUTHENTICATION_FAILURE, offset_seconds=i, source_ip="203.0.113.15",
                      host="victim", destination_port=3389, protocol="rdp")
        for i in range(5)
    ]
    match = _fire(rule, events)
    assert match is not None
    assert match.rule_id == "NETWORK-006"


def test_archive_before_transfer_positive(event_factory):
    rule = ArchiveBeforeTransferRule(correlation_window_seconds=900, transfer_threshold_bytes=1000)
    archive_event = event_factory(EventType.FILE_EVENT, offset_seconds=0, host="h1",
                                   raw={"action": "created", "file_path": r"C:\Temp\data.zip"})
    transfer_event = event_factory(EventType.NETWORK_CONNECTION, offset_seconds=30, host="h1",
                                    bytes_out=5000, destination_ip="203.0.113.99")
    assert rule.process(archive_event) is None
    match = rule.process(transfer_event)
    assert match is not None
    assert match.rule_id == "EXFIL-002"


def test_archive_before_transfer_negative_no_prior_archive(event_factory):
    rule = ArchiveBeforeTransferRule(correlation_window_seconds=900, transfer_threshold_bytes=1000)
    transfer_event = event_factory(EventType.NETWORK_CONNECTION, offset_seconds=30, host="h1",
                                    bytes_out=5000, destination_ip="203.0.113.99")
    assert rule.process(transfer_event) is None


def test_bounded_window_store_evicts_by_key_limit(event_factory, base_time):
    store = BoundedWindowStore(window_seconds=600, max_keys=3, max_items_per_key=100)
    for i in range(10):
        store.add(f"key-{i}", base_time, "payload")
    assert store.key_count() <= 3


def test_bounded_window_store_caps_items_per_key(base_time):
    store = BoundedWindowStore(window_seconds=600, max_keys=10, max_items_per_key=5)
    for i in range(20):
        store.add("same-key", base_time + timedelta(seconds=i), "payload")
    entries = store.get("same-key", base_time + timedelta(seconds=20))
    assert len(entries) <= 5


def test_bounded_window_store_prunes_expired_entries(base_time):
    store = BoundedWindowStore(window_seconds=10)
    store.add("k1", base_time, "old")
    entries = store.get("k1", base_time + timedelta(seconds=60))
    assert len(entries) == 0
