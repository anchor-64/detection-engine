from __future__ import annotations

import re
from typing import Optional

from aire_detection.models import DetectionMatch, EventType, NormalizedEvent, Severity
from aire_detection.rules.base import Rule, RuleMeta

SECURITY_PROCESS_NAMES = {
    "msmpeng.exe", "mssense.exe", "cbcomms.exe", "savservice.exe",
    "wazuh-agent.exe", "sysmon.exe", "sysmon64.exe", "auditd", "falcon-sensor",
}


class SecurityToolTamperingRule(Rule):
    """EVASION-001 — an attempt to stop, kill, or reconfigure a
    security agent/monitoring process."""

    meta = RuleMeta(
        rule_id="EVASION-001",
        name="Security Tool/Process Tampering",
        description="A command attempted to stop, kill, or disable a known security-agent or monitoring process.",
        severity=Severity.CRITICAL,
        confidence=0.7,
        mitre_techniques=["T1562.001"],
        false_positive_notes="Legitimate agent upgrades/reinstalls briefly stop the service; correlate with a following install/update event.",
    )

    STOP_CMD = re.compile(r"(taskkill|net stop|sc stop|stop-service|kill\s)", re.IGNORECASE)

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        cmd = event.command_line or ""
        if not self.STOP_CMD.search(cmd):
            return None
        target_hit = None
        for name in SECURITY_PROCESS_NAMES:
            if name in cmd.lower():
                target_hit = name
                break
        if not target_hit:
            return None
        return self._build_match(event, evidence={"command_line": cmd, "target": target_hit, "host": event.host})


class WindowsEventLogClearingRule(Rule):
    """EVASION-002 — the Windows event log was cleared (wevtutil cl /
    Clear-EventLog / EventID 1102), a strong anti-forensics indicator."""

    meta = RuleMeta(
        rule_id="EVASION-002",
        name="Windows Event Log Clearing",
        description="A Windows event log was cleared, which is rarely done for legitimate operational reasons and is a strong anti-forensics indicator.",
        severity=Severity.CRITICAL,
        confidence=0.85,
        mitre_techniques=["T1070.001"],
        false_positive_notes="Some disk-space-management scripts clear logs on a schedule; if so, allow-list that specific scheduled task/service account.",
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.LOG_CLEAR_EVENT:
            return None
        return self._build_match(event, evidence={
            "log_name": event.raw.get("log_name"), "user": event.user, "host": event.host,
        })


class SuspiciousFileDeletionRule(Rule):
    """EVASION-003 — deletion of a batch of recently-dropped files or
    the tool's own binary immediately after execution (self-cleanup)."""

    meta = RuleMeta(
        rule_id="EVASION-003",
        name="Suspicious File Deletion",
        description="A process deleted its own recently-written binary or a batch of files shortly after execution, a common anti-forensics cleanup pattern.",
        severity=Severity.MEDIUM,
        confidence=0.4,
        mitre_techniques=["T1070.004"],
        false_positive_notes="Installers and self-extracting archives routinely delete temp files after use; corroborate with prior suspicious execution.",
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.FILE_EVENT:
            return None
        if (event.raw.get("action") or "").lower() != "deleted":
            return None
        if not event.raw.get("self_delete"):
            return None
        return self._build_match(event, evidence={
            "file_path": event.raw.get("file_path"), "process_name": event.process_name, "host": event.host,
        })


def get_rules():
    return [
        SecurityToolTamperingRule(),
        WindowsEventLogClearingRule(),
        SuspiciousFileDeletionRule(),
    ]
