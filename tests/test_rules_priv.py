from aire_detection.models import EventType
from aire_detection.rules import priv


def test_priv001_positive_unexplained_elevation(event_factory):
    rule = priv.SuspiciousPrivilegeEscalationRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="evil.exe", parent_process_name="explorer.exe",
                       integrity_level="System", raw={"parent_integrity_level": "Medium"})
    assert rule.match(e) is not None


def test_priv001_negative_legit_uac(event_factory):
    rule = priv.SuspiciousPrivilegeEscalationRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="setup.exe", parent_process_name="consent.exe",
                       integrity_level="High", raw={"parent_integrity_level": "Medium"})
    assert rule.match(e) is None


def test_priv001_negative_same_level(event_factory):
    rule = priv.SuspiciousPrivilegeEscalationRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="app.exe", parent_process_name="explorer.exe",
                       integrity_level="Medium", raw={"parent_integrity_level": "Medium"})
    assert rule.match(e) is None


def test_priv002_positive_temp_service_binary(event_factory):
    rule = priv.SuspiciousServiceCreationRule()
    e = event_factory(EventType.SERVICE_EVENT, raw={
        "action": "created", "service_name": "UpdaterSvc",
        "service_binary_path": r"C:\Users\Public\svc.exe",
    })
    assert rule.match(e) is not None


def test_priv002_negative_standard_dir(event_factory):
    rule = priv.SuspiciousServiceCreationRule()
    e = event_factory(EventType.SERVICE_EVENT, raw={
        "action": "created", "service_name": "LegitSvc",
        "service_binary_path": r"C:\Program Files\Vendor\svc.exe",
    })
    assert rule.match(e) is None


def test_priv003_positive_powershell_task(event_factory):
    rule = priv.SuspiciousScheduledTaskCreationRule()
    e = event_factory(EventType.SCHEDULED_TASK_EVENT, raw={
        "action": "created", "task_name": "Updater",
        "task_action": "powershell.exe -File payload.ps1",
    })
    assert rule.match(e) is not None


def test_priv003_negative_normal_task(event_factory):
    rule = priv.SuspiciousScheduledTaskCreationRule()
    e = event_factory(EventType.SCHEDULED_TASK_EVENT, raw={
        "action": "created", "task_name": "DiskCleanup",
        "task_action": r"C:\Windows\System32\cleanmgr.exe",
    })
    assert rule.match(e) is None


def test_priv004_positive_run_key_temp_binary(event_factory):
    rule = priv.SuspiciousRegistryRunKeyRule()
    e = event_factory(EventType.REGISTRY_EVENT, raw={
        "key_path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "value_name": "Updater", "value_data": r"C:\Users\bob\AppData\Local\Temp\svc.exe",
    })
    assert rule.match(e) is not None


def test_priv004_negative_standard_dir(event_factory):
    rule = priv.SuspiciousRegistryRunKeyRule()
    e = event_factory(EventType.REGISTRY_EVENT, raw={
        "key_path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "value_name": "Vendor", "value_data": r"C:\Program Files\Vendor\app.exe",
    })
    assert rule.match(e) is None


def test_priv004_negative_wrong_key(event_factory):
    rule = priv.SuspiciousRegistryRunKeyRule()
    e = event_factory(EventType.REGISTRY_EVENT, raw={
        "key_path": r"HKCU\Software\SomeApp\Settings",
        "value_name": "x", "value_data": r"C:\Temp\x.exe",
    })
    assert rule.match(e) is None
