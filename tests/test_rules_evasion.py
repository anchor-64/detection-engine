from aire_detection.models import EventType
from aire_detection.rules import evasion


def test_evasion001_positive_kill_security_agent(event_factory):
    rule = evasion.SecurityToolTamperingRule()
    e = event_factory(EventType.PROCESS_CREATE, command_line="taskkill /F /IM MsMpEng.exe")
    assert rule.match(e) is not None


def test_evasion001_negative_kill_unrelated_process(event_factory):
    rule = evasion.SecurityToolTamperingRule()
    e = event_factory(EventType.PROCESS_CREATE, command_line="taskkill /F /IM notepad.exe")
    assert rule.match(e) is None


def test_evasion001_negative_no_stop_verb(event_factory):
    rule = evasion.SecurityToolTamperingRule()
    e = event_factory(EventType.PROCESS_CREATE, command_line="tasklist | findstr MsMpEng.exe")
    assert rule.match(e) is None


def test_evasion002_positive_log_clear(event_factory):
    rule = evasion.WindowsEventLogClearingRule()
    e = event_factory(EventType.LOG_CLEAR_EVENT, user="bob", host="h1", raw={"log_name": "Security"})
    assert rule.match(e) is not None


def test_evasion002_negative_wrong_event_type(event_factory):
    rule = evasion.WindowsEventLogClearingRule()
    e = event_factory(EventType.PROCESS_CREATE)
    assert rule.match(e) is None


def test_evasion003_positive_self_delete(event_factory):
    rule = evasion.SuspiciousFileDeletionRule()
    e = event_factory(EventType.FILE_EVENT, process_name="payload.exe",
                       raw={"action": "deleted", "file_path": r"C:\Temp\payload.exe", "self_delete": True})
    assert rule.match(e) is not None


def test_evasion003_negative_normal_temp_cleanup(event_factory):
    rule = evasion.SuspiciousFileDeletionRule()
    e = event_factory(EventType.FILE_EVENT, process_name="installer.exe",
                       raw={"action": "deleted", "file_path": r"C:\Temp\setup.tmp", "self_delete": False})
    assert rule.match(e) is None
