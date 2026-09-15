from __future__ import annotations

import re
from typing import Optional

from aire_detection.models import DetectionMatch, EventType, NormalizedEvent, Severity
from aire_detection.rules.base import Rule, RuleMeta


def _lower(s):
    return (s or "").lower()


class SuspiciousPrivilegeEscalationRule(Rule):
    """PRIV-001 — a process running at System/High integrity was
    spawned by a process that started at Medium/Low integrity, without
    a recognized legitimate elevation path (UAC prompt, installer)."""

    meta = RuleMeta(
        rule_id="PRIV-001",
        name="Suspicious Privilege Escalation",
        description="A child process runs at a higher integrity level than its parent without a recognized legitimate elevation mechanism.",
        severity=Severity.HIGH,
        confidence=0.5,
        mitre_techniques=["T1068", "T1548"],
        false_positive_notes="Legitimate UAC elevation and signed installers also change integrity level; ideally corroborate with consent.exe lineage before escalating.",
    )

    RANK = {"low": 0, "medium": 1, "high": 2, "system": 3}
    LEGITIMATE_ELEVATORS = {"consent.exe", "msiexec.exe", "trustedinstaller.exe"}

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.PROCESS_CREATE:
            return None
        child_level = _lower(event.integrity_level)
        parent_level = _lower(event.raw.get("parent_integrity_level"))
        if child_level not in self.RANK or parent_level not in self.RANK:
            return None
        if self.RANK[child_level] <= self.RANK[parent_level]:
            return None
        if _lower(event.parent_process_name) in self.LEGITIMATE_ELEVATORS:
            return None
        return self._build_match(event, evidence={
            "process_name": event.process_name, "parent_process_name": event.parent_process_name,
            "child_integrity": event.integrity_level, "parent_integrity": event.raw.get("parent_integrity_level"),
            "host": event.host,
        })


class SuspiciousServiceCreationRule(Rule):
    """PRIV-002 — a new Windows service was created pointing at a
    binary in a non-standard (writable/temp) location."""

    meta = RuleMeta(
        rule_id="PRIV-002",
        name="Suspicious Service Creation",
        description="A new service was created with an executable path outside standard system/program directories.",
        severity=Severity.HIGH,
        confidence=0.55,
        mitre_techniques=["T1543.003"],
        false_positive_notes="Some third-party software installs services into non-standard vendor directories; verify signing.",
    )

    STANDARD_DIRS = re.compile(r"^(c:\\windows\\|c:\\program files)", re.IGNORECASE)

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.SERVICE_EVENT:
            return None
        if (event.raw.get("action") or "").lower() != "created":
            return None
        path = event.raw.get("service_binary_path") or ""
        if self.STANDARD_DIRS.match(path):
            return None
        return self._build_match(event, evidence={
            "service_name": event.raw.get("service_name"), "binary_path": path, "host": event.host,
        })


class SuspiciousScheduledTaskCreationRule(Rule):
    """PRIV-003 — a scheduled task was created that runs a script
    interpreter or references a temp-directory payload, a common
    persistence mechanism."""

    meta = RuleMeta(
        rule_id="PRIV-003",
        name="Suspicious Scheduled Task Creation",
        description="A scheduled task was created that launches a script interpreter or a binary from a temporary directory.",
        severity=Severity.MEDIUM,
        confidence=0.5,
        mitre_techniques=["T1053.005"],
        false_positive_notes="Legitimate software update mechanisms and backup tools also create scheduled tasks; scope by action path.",
    )

    SUSPICIOUS_ACTION = re.compile(
        r"(powershell|wscript|cscript|mshta|\\temp\\|\\appdata\\local\\temp\\)", re.IGNORECASE
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.SCHEDULED_TASK_EVENT:
            return None
        if (event.raw.get("action") or "").lower() != "created":
            return None
        task_action = event.raw.get("task_action") or ""
        if not self.SUSPICIOUS_ACTION.search(task_action):
            return None
        return self._build_match(event, evidence={
            "task_name": event.raw.get("task_name"), "task_action": task_action, "host": event.host,
        })


class SuspiciousRegistryRunKeyRule(Rule):
    """PRIV-004 — a value was written to a Run/RunOnce autostart
    registry key, a classic persistence technique."""

    meta = RuleMeta(
        rule_id="PRIV-004",
        name="Suspicious Registry Run Key",
        description="A value was written to a Run/RunOnce autostart registry key referencing an executable outside standard directories.",
        severity=Severity.MEDIUM,
        confidence=0.5,
        mitre_techniques=["T1547.001"],
        false_positive_notes="Many legitimate applications register autostart entries; scope by binary path and publisher when possible.",
    )

    RUN_KEY = re.compile(r"\\(Run|RunOnce)$", re.IGNORECASE)
    STANDARD_DIRS = re.compile(r"^(c:\\windows\\|c:\\program files)", re.IGNORECASE)

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.REGISTRY_EVENT:
            return None
        key_path = event.raw.get("key_path") or ""
        if not self.RUN_KEY.search(key_path):
            return None
        value_data = event.raw.get("value_data") or ""
        if self.STANDARD_DIRS.match(value_data):
            return None
        return self._build_match(event, evidence={
            "key_path": key_path, "value_name": event.raw.get("value_name"),
            "value_data": value_data, "host": event.host,
        })


def get_rules():
    return [
        SuspiciousPrivilegeEscalationRule(),
        SuspiciousServiceCreationRule(),
        SuspiciousScheduledTaskCreationRule(),
        SuspiciousRegistryRunKeyRule(),
    ]
