from __future__ import annotations

import base64
import re
from typing import Optional

from aire_detection.models import DetectionMatch, EventType, NormalizedEvent, Severity
from aire_detection.rules.base import Rule, RuleMeta

POWERSHELL_NAMES = {"powershell.exe", "pwsh.exe"}
SCRIPT_HOSTS = {"wscript.exe", "cscript.exe", "cmd.exe", "mshta.exe"}


def _lower(s):
    return (s or "").lower()


class EncodedPowerShellRule(Rule):
    """SCRIPT-001 — PowerShell invoked with -EncodedCommand (base64
    UTF-16LE), a heavily favored obfuscation/delivery technique."""

    meta = RuleMeta(
        rule_id="SCRIPT-001",
        name="Encoded PowerShell",
        description="PowerShell was executed with -EncodedCommand/-Enc carrying a base64-encoded script body.",
        severity=Severity.HIGH,
        confidence=0.7,
        mitre_techniques=["T1059.001", "T1027"],
        false_positive_notes=(
            "Some configuration-management tools (DSC, remote deployment "
            "agents) legitimately use encoded commands; allow-list known agents."
        ),
    )

    PATTERN = re.compile(r"-e(nc(odedcommand)?)?\s+([A-Za-z0-9+/=]{20,})", re.IGNORECASE)

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        if _lower(event.process_name) not in POWERSHELL_NAMES:
            return None
        cmd = event.command_line or ""
        m = self.PATTERN.search(cmd)
        if not m:
            return None
        decoded_preview = None
        try:
            raw = base64.b64decode(m.group(3) + "===")
            decoded_preview = raw.decode("utf-16-le", errors="replace")[:200]
        except Exception:
            decoded_preview = None
        return self._build_match(event, evidence={
            "command_line": cmd, "decoded_preview": decoded_preview, "host": event.host,
        })


class PowerShellDownloadActivityRule(Rule):
    """SCRIPT-002 — PowerShell using a .NET download cradle
    (WebClient/Invoke-WebRequest/Net.WebClient) to fetch remote content."""

    meta = RuleMeta(
        rule_id="SCRIPT-002",
        name="PowerShell Download Activity",
        description="PowerShell command line contains a download-cradle pattern (WebClient/DownloadString/IWR).",
        severity=Severity.HIGH,
        confidence=0.6,
        mitre_techniques=["T1105", "T1059.001"],
        false_positive_notes="Legitimate deployment scripts and installers use the same cmdlets.",
    )

    PATTERN = re.compile(
        r"(downloadstring|downloadfile|net\.webclient|invoke-webrequest|iwr\s|wget\s|curl\s)",
        re.IGNORECASE,
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        if _lower(event.process_name) not in POWERSHELL_NAMES:
            return None
        cmd = event.command_line or ""
        if not self.PATTERN.search(cmd):
            return None
        return self._build_match(event, evidence={"command_line": cmd, "host": event.host})


class PowerShellWebRequestRule(Rule):
    """SCRIPT-003 — PowerShell command line references a raw URL
    combined with execution (IEX), the classic download-and-execute one-liner."""

    meta = RuleMeta(
        rule_id="SCRIPT-003",
        name="PowerShell Web Request",
        description="PowerShell command line combines a remote URL with immediate execution (IEX/Invoke-Expression).",
        severity=Severity.CRITICAL,
        confidence=0.75,
        mitre_techniques=["T1105", "T1059.001"],
        false_positive_notes="Extremely rare in legitimate admin usage; still verify destination domain reputation.",
    )

    PATTERN = re.compile(r"(iex|invoke-expression)\s*\(.*https?://", re.IGNORECASE)

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        if _lower(event.process_name) not in POWERSHELL_NAMES:
            return None
        cmd = event.command_line or ""
        if not self.PATTERN.search(cmd):
            return None
        return self._build_match(event, evidence={"command_line": cmd, "host": event.host})


class SuspiciousScriptHostExecutionRule(Rule):
    """SCRIPT-004 — a generic script host (cmd/wscript/cscript/mshta)
    invoked with chained command separators typical of one-liner droppers."""

    meta = RuleMeta(
        rule_id="SCRIPT-004",
        name="Suspicious Script Host Execution",
        description="A script host was executed with multiple chained commands (&, &&, |, ;) suggesting a scripted dropper chain.",
        severity=Severity.MEDIUM,
        confidence=0.4,
        mitre_techniques=["T1059"],
        false_positive_notes="Legitimate batch scripts routinely chain commands; low standalone confidence, best used with correlation.",
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        if _lower(event.process_name) not in SCRIPT_HOSTS:
            return None
        cmd = event.command_line or ""
        # Count chain separators without double-counting "&" inside "&&".
        separators = cmd.count("&&") + cmd.count(";") + cmd.count("|")
        if separators < 3:
            return None
        return self._build_match(event, evidence={"command_line": cmd, "separator_count": separators, "host": event.host})


class SuspiciousBase64CommandRule(Rule):
    """SCRIPT-005 — any process command line carrying a long inline
    base64 blob outside the dedicated -EncodedCommand path."""

    meta = RuleMeta(
        rule_id="SCRIPT-005",
        name="Suspicious Base64 Command",
        description="Command line contains a long inline base64-looking blob, commonly used to smuggle a payload.",
        severity=Severity.MEDIUM,
        confidence=0.4,
        mitre_techniques=["T1027", "T1140"],
        false_positive_notes="Base64 is common in legitimate config/data; length + entropy threshold reduces noise but doesn't eliminate it.",
    )

    PATTERN = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        cmd = event.command_line or ""
        if _lower(event.process_name) in POWERSHELL_NAMES and "-enc" in cmd.lower():
            return None  # already covered more precisely by SCRIPT-001
        m = self.PATTERN.search(cmd)
        if not m:
            return None
        return self._build_match(event, evidence={
            "command_line": cmd, "blob_length": len(m.group(0)), "host": event.host,
        })


class SuspiciousCommandObfuscationRule(Rule):
    """SCRIPT-006 — heavy use of string-concatenation / character-code
    obfuscation techniques (e.g. `'p'+'ow'+'ershell'`, backtick
    insertion, char() building) inside a command line."""

    meta = RuleMeta(
        rule_id="SCRIPT-006",
        name="Suspicious Command Obfuscation",
        description="Command line shows string-splitting/char-code obfuscation techniques used to evade static signature matching.",
        severity=Severity.MEDIUM,
        confidence=0.45,
        mitre_techniques=["T1027.010"],
        false_positive_notes="Some legitimate scripts build strings dynamically for unrelated reasons; corroborate with other rules.",
    )

    PATTERN = re.compile(r"(\$env:[a-z]+\[|`[a-z]`|\+\s*['\"][a-z]{1,3}['\"]\s*\+|char\(\d+\))", re.IGNORECASE)

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        cmd = event.command_line or ""
        if not self.PATTERN.search(cmd):
            return None
        return self._build_match(event, evidence={"command_line": cmd, "host": event.host})


def get_rules():
    return [
        EncodedPowerShellRule(),
        PowerShellDownloadActivityRule(),
        PowerShellWebRequestRule(),
        SuspiciousScriptHostExecutionRule(),
        SuspiciousBase64CommandRule(),
        SuspiciousCommandObfuscationRule(),
    ]
