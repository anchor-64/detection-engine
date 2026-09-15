from __future__ import annotations

import re
from typing import Optional

from aire_detection.models import DetectionMatch, EventType, NormalizedEvent, Severity
from aire_detection.rules.base import Rule, RuleMeta

SUSPICIOUS_PROCESS_NAMES = {
    "psexec.exe", "procdump.exe", "mimikatz.exe", "nc.exe", "ncat.exe",
    "wce.exe", "pwdump.exe", "gsecdump.exe",
}

POWERSHELL_NAMES = {"powershell.exe", "pwsh.exe"}
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe"}
SUSPICIOUS_OFFICE_CHILDREN = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
}
WINDOWS_INTERPRETERS = {"wscript.exe", "cscript.exe", "mshta.exe"}
TEMP_DIR_PATTERN = re.compile(
    r"(\\Temp\\|\\AppData\\Local\\Temp\\|/tmp/|\\Users\\Public\\|\\ProgramData\\)",
    re.IGNORECASE,
)


def _lower(s):
    return (s or "").lower()


class SuspiciousProcessCreationRule(Rule):
    """ENDPOINT-001 — process creation matching a small deny-list of
    well-known offensive-security / credential-dumping tool binaries."""

    meta = RuleMeta(
        rule_id="ENDPOINT-001",
        name="Suspicious Process Creation",
        description="A process matching a known offensive-tooling binary name was created.",
        severity=Severity.HIGH,
        confidence=0.6,
        mitre_techniques=["T1105"],
        false_positive_notes=(
            "Binary name matching alone can be defeated by renaming; this "
            "rule is a coarse, high-signal-but-evadable tripwire, not a "
            "complete credential-theft detector."
        ),
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        name = _lower(event.process_name)
        if name not in SUSPICIOUS_PROCESS_NAMES:
            return None
        return self._build_match(event, evidence={
            "process_name": event.process_name,
            "command_line": event.command_line,
            "parent_process_name": event.parent_process_name,
            "host": event.host,
            "user": event.user,
        })


class SuspiciousPowerShellExecutionRule(Rule):
    """ENDPOINT-002 — PowerShell launched with flags commonly used to
    bypass execution policy or hide the window."""

    meta = RuleMeta(
        rule_id="ENDPOINT-002",
        name="Suspicious PowerShell Execution",
        description=(
            "PowerShell was executed with flags typically used to bypass "
            "security controls (-ExecutionPolicy Bypass, -WindowStyle "
            "Hidden, -NoProfile combined with -NonInteractive, etc.)."
        ),
        severity=Severity.MEDIUM,
        confidence=0.55,
        mitre_techniques=["T1059", "T1059.001"],
        false_positive_notes=(
            "Many legitimate admin scripts and scheduled tasks use these "
            "same flags; tune against your environment's baseline."
        ),
    )

    SUSPICIOUS_FLAGS = re.compile(
        r"(-nop\b|-noprofile|-w(indowstyle)?\s+hidden|-exec(utionpolicy)?\s+bypass|-enc\b)",
        re.IGNORECASE,
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        if _lower(event.process_name) not in POWERSHELL_NAMES:
            return None
        cmd = event.command_line or ""
        if not self.SUSPICIOUS_FLAGS.search(cmd):
            return None
        return self._build_match(event, evidence={
            "command_line": cmd, "host": event.host, "user": event.user,
        })


class SuspiciousPowerShellParentChildRule(Rule):
    """ENDPOINT-003 — PowerShell spawned from a parent process that
    should not normally launch a scripting interpreter (e.g. Office
    apps, browsers, mshta)."""

    meta = RuleMeta(
        rule_id="ENDPOINT-003",
        name="Suspicious PowerShell Parent/Child Chain",
        description=(
            "PowerShell was launched as a child of a process (Office app, "
            "browser, or script host) that does not normally spawn a shell, "
            "a pattern strongly associated with malicious document macros "
            "or exploit payloads."
        ),
        severity=Severity.HIGH,
        confidence=0.65,
        mitre_techniques=["T1059.001", "T1204.002"],
        false_positive_notes=(
            "Some legitimate add-ins or automation tooling launch "
            "PowerShell from Office; check for signed, known-good "
            "publishers before escalating."
        ),
    )

    SUSPICIOUS_PARENTS = OFFICE_PARENTS | {"mshta.exe", "wscript.exe", "cscript.exe", "wmiprvse.exe"}

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        if _lower(event.process_name) not in POWERSHELL_NAMES:
            return None
        parent = _lower(event.parent_process_name)
        if parent not in self.SUSPICIOUS_PARENTS:
            return None
        return self._build_match(event, evidence={
            "parent_process_name": event.parent_process_name,
            "command_line": event.command_line, "host": event.host,
        })


class SuspiciousWindowsInterpreterExecutionRule(Rule):
    """ENDPOINT-004 — wscript/cscript/mshta launched with a remote or
    encoded script reference."""

    meta = RuleMeta(
        rule_id="ENDPOINT-004",
        name="Suspicious Windows Interpreter Execution",
        description=(
            "A Windows script host (wscript/cscript/mshta) was executed "
            "referencing a remote URL or an obfuscated/encoded script."
        ),
        severity=Severity.MEDIUM,
        confidence=0.55,
        mitre_techniques=["T1218.005", "T1059"],
        false_positive_notes="Some legacy internal tooling still relies on HTA/VBS launchers.",
    )

    REMOTE_REF = re.compile(r"https?://", re.IGNORECASE)

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        if _lower(event.process_name) not in WINDOWS_INTERPRETERS:
            return None
        cmd = event.command_line or ""
        if not self.REMOTE_REF.search(cmd):
            return None
        return self._build_match(event, evidence={"command_line": cmd, "host": event.host})


class SuspiciousProcessFromTempRule(Rule):
    """ENDPOINT-005 — an executable launched directly from a
    world-writable temp/download-style directory."""

    meta = RuleMeta(
        rule_id="ENDPOINT-005",
        name="Suspicious Process from Temporary Directory",
        description="A process image was executed from a temporary or world-writable directory.",
        severity=Severity.MEDIUM,
        confidence=0.45,
        mitre_techniques=["T1204.002"],
        false_positive_notes="Installers legitimately self-extract and run from temp directories.",
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        path = event.raw.get("image_path") or event.command_line or ""
        if not TEMP_DIR_PATTERN.search(path):
            return None
        return self._build_match(event, evidence={
            "image_path": path, "process_name": event.process_name, "host": event.host,
        })


class SuspiciousOfficeChildProcessRule(Rule):
    """ENDPOINT-006 — an Office application spawned a shell/scripting
    child process, the classic malicious-macro pattern."""

    meta = RuleMeta(
        rule_id="ENDPOINT-006",
        name="Suspicious Office Child Process",
        description="A Microsoft Office application spawned a shell or scripting interpreter child process.",
        severity=Severity.HIGH,
        confidence=0.65,
        mitre_techniques=["T1204.002", "T1566.001"],
        false_positive_notes="Some enterprise macros legitimately shell out; verify against known business workflows.",
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        parent = _lower(event.parent_process_name)
        child = _lower(event.process_name)
        if parent not in OFFICE_PARENTS or child not in SUSPICIOUS_OFFICE_CHILDREN:
            return None
        return self._build_match(event, evidence={
            "parent_process_name": event.parent_process_name,
            "process_name": event.process_name,
            "command_line": event.command_line, "host": event.host,
        })


class SuspiciousRundll32Rule(Rule):
    """ENDPOINT-007 — rundll32 invoked with a non-standard export or a
    remote/UNC path, commonly used to proxy-execute malicious DLLs."""

    meta = RuleMeta(
        rule_id="ENDPOINT-007",
        name="Suspicious Rundll32 Execution",
        description="rundll32.exe was executed referencing a remote path, UNC share, or unusual export.",
        severity=Severity.MEDIUM,
        confidence=0.5,
        mitre_techniques=["T1218.011"],
        false_positive_notes="rundll32 is used constantly for legitimate control-panel applets; scope by path.",
    )

    SUSPICIOUS_REF = re.compile(r"(https?://|\\\\[^\\]+\\|javascript:)", re.IGNORECASE)

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        if _lower(event.process_name) != "rundll32.exe":
            return None
        cmd = event.command_line or ""
        if not self.SUSPICIOUS_REF.search(cmd):
            return None
        return self._build_match(event, evidence={"command_line": cmd, "host": event.host})


class SuspiciousRegsvr32Rule(Rule):
    """ENDPOINT-008 — regsvr32 used with /i and a remote scriptlet
    (the "Squiblydoo" AppLocker-bypass pattern)."""

    meta = RuleMeta(
        rule_id="ENDPOINT-008",
        name="Suspicious Regsvr32 Execution",
        description="regsvr32.exe was executed with a remote scriptlet reference (Squiblydoo-style bypass).",
        severity=Severity.HIGH,
        confidence=0.7,
        mitre_techniques=["T1218.010", "T1553.005"],
        false_positive_notes="Legitimate use of remote scriptlets via regsvr32 is extremely rare.",
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        if _lower(event.process_name) != "regsvr32.exe":
            return None
        cmd = (event.command_line or "").lower()
        if "scrobj.dll" not in cmd or ("http://" not in cmd and "https://" not in cmd):
            return None
        return self._build_match(event, evidence={"command_line": event.command_line, "host": event.host})


class SuspiciousMshtaRule(Rule):
    """ENDPOINT-009 — mshta.exe launched referencing a remote HTA
    payload or inline script."""

    meta = RuleMeta(
        rule_id="ENDPOINT-009",
        name="Suspicious Mshta Execution",
        description="mshta.exe was executed referencing a remote HTA file or inline vbscript/javascript.",
        severity=Severity.HIGH,
        confidence=0.65,
        mitre_techniques=["T1218.005"],
        false_positive_notes="Legacy line-of-business HTA tools exist; verify publisher and network destination.",
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        if _lower(event.process_name) != "mshta.exe":
            return None
        cmd = (event.command_line or "").lower()
        if not ("http://" in cmd or "https://" in cmd or "vbscript:" in cmd or "javascript:" in cmd):
            return None
        return self._build_match(event, evidence={"command_line": event.command_line, "host": event.host})


class SuspiciousCertutilRule(Rule):
    """ENDPOINT-010 — certutil abused for its undocumented download/
    decode capability rather than certificate management."""

    meta = RuleMeta(
        rule_id="ENDPOINT-010",
        name="Suspicious Certutil Execution",
        description="certutil.exe was executed with -urlcache/-decode flags, a common LOLBin download/decode abuse pattern.",
        severity=Severity.MEDIUM,
        confidence=0.6,
        mitre_techniques=["T1105", "T1140"],
        false_positive_notes="Some legitimate cert-management scripts use -decode; rare in normal endpoint use.",
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        if _lower(event.process_name) != "certutil.exe":
            return None
        cmd = (event.command_line or "").lower()
        if not ("-urlcache" in cmd or "-decode" in cmd or "/urlcache" in cmd or "/decode" in cmd):
            return None
        return self._build_match(event, evidence={"command_line": event.command_line, "host": event.host})


def get_rules():
    return [
        SuspiciousProcessCreationRule(),
        SuspiciousPowerShellExecutionRule(),
        SuspiciousPowerShellParentChildRule(),
        SuspiciousWindowsInterpreterExecutionRule(),
        SuspiciousProcessFromTempRule(),
        SuspiciousOfficeChildProcessRule(),
        SuspiciousRundll32Rule(),
        SuspiciousRegsvr32Rule(),
        SuspiciousMshtaRule(),
        SuspiciousCertutilRule(),
    ]
