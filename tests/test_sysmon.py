import pytest

from aire_detection.models import EventType
from aire_detection.normalization.sysmon import normalize_sysmon_process_create


def test_sysmon_normalize_basic():
    raw = {
        "UtcTime": "2026-01-01 12:00:00.000",
        "ProcessGuid": "{guid1}", "ProcessId": 4321,
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -enc AAAA", "User": "CORP\\bob",
        "IntegrityLevel": "Medium", "Computer": "WORKSTATION01",
        "ParentProcessGuid": "{guid0}", "ParentProcessId": 100,
        "ParentImage": r"C:\Windows\explorer.exe", "ParentCommandLine": "explorer.exe",
    }
    event = normalize_sysmon_process_create(raw, sensor="wazuh-agent-01")
    assert event.event_type == EventType.PROCESS_CREATE
    assert event.process_name == "powershell.exe"
    assert event.parent_process_name == "explorer.exe"
    assert event.host == "WORKSTATION01"
    assert event.user == "CORP\\bob"
    assert event.sensor == "wazuh-agent-01"
    assert event.raw["image_path"].endswith("powershell.exe")


def test_sysmon_normalize_missing_timestamp_raises():
    raw = {"Image": "notepad.exe"}
    with pytest.raises(ValueError):
        normalize_sysmon_process_create(raw, sensor="s1")


def test_sysmon_normalize_handles_missing_optional_fields():
    raw = {"UtcTime": "2026-01-01 12:00:00.000", "Image": r"C:\a\b.exe"}
    event = normalize_sysmon_process_create(raw, sensor="s1")
    assert event.parent_process_name is None
    assert event.process_id is None


def test_sysmon_normalize_feeds_endpoint_rule(event_factory):
    from aire_detection.rules.endpoint import SuspiciousPowerShellParentChildRule
    raw = {
        "UtcTime": "2026-01-01 12:00:00.000",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "ParentImage": r"C:\Program Files\Microsoft Office\WINWORD.EXE",
        "Computer": "WORKSTATION01",
    }
    event = normalize_sysmon_process_create(raw, sensor="s1")
    rule = SuspiciousPowerShellParentChildRule()
    match = rule.match(event)
    assert match is not None
