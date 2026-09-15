from __future__ import annotations

import re
from typing import Optional

from aire_detection.models import DetectionMatch, EventType, NormalizedEvent, Severity
from aire_detection.rules.base import Rule, RuleMeta

SUSPICIOUS_ACCOUNT_PATTERN = re.compile(
    r"(admin|adm1n|root|backup|svc[_-]?temp|test|support|helpdesk)\d*$", re.IGNORECASE
)


class FailedAuthenticationRule(Rule):
    """AUTH-001 — a single failed authentication attempt. Low severity;
    exists mainly as raw signal feeding correlation rules (AUTH-002..005)."""

    meta = RuleMeta(
        rule_id="AUTH-001",
        name="Failed Authentication",
        description="A single authentication attempt failed.",
        severity=Severity.LOW,
        confidence=0.9,
        mitre_techniques=["T1110"],
        false_positive_notes=(
            "Users routinely mistype passwords; a single failure is weak "
            "signal on its own and should not page anyone by itself."
        ),
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.AUTHENTICATION_FAILURE:
            return None
        return self._build_match(event, evidence={
            "user": event.user,
            "source_ip": event.source_ip,
            "host": event.host,
            "service": event.protocol or event.source,
        })


class SuspiciousNewAccountRule(Rule):
    """AUTH-006 — a newly created account whose name matches a pattern
    commonly used for staging backdoor/persistence accounts."""

    meta = RuleMeta(
        rule_id="AUTH-006",
        name="Suspicious New Account",
        description=(
            "A new account was created with a name pattern commonly used "
            "for backdoor or persistence accounts (e.g. admin-like, "
            "temporary service, or support account names)."
        ),
        severity=Severity.MEDIUM,
        confidence=0.5,
        mitre_techniques=["T1136", "T1136.001"],
        false_positive_notes=(
            "Legitimate IT operations do create accounts matching these "
            "naming patterns; correlate with the requesting admin/ticket "
            "before treating as confirmed malicious."
        ),
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.ACCOUNT_CREATED:
            return None
        username = event.user or ""
        if not SUSPICIOUS_ACCOUNT_PATTERN.search(username):
            return None
        return self._build_match(event, evidence={
            "new_account": username,
            "host": event.host,
            "created_by": event.raw.get("created_by"),
        })


def get_rules():
    return [FailedAuthenticationRule(), SuspiciousNewAccountRule()]
