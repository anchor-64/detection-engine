from __future__ import annotations

from typing import Optional

from aire_detection.models import DetectionMatch, EventType, NormalizedEvent, Severity
from aire_detection.rules.base import Rule, RuleMeta


class LargeOutboundTransferRule(Rule):
    """EXFIL-001 — a single connection transferred an unusually large
    volume of data outbound. Threshold is configurable per deployment."""

    meta = RuleMeta(
        rule_id="EXFIL-001",
        name="Large Outbound Transfer",
        description="A single outbound network connection transferred a volume of data exceeding the configured exfiltration threshold.",
        severity=Severity.HIGH,
        confidence=0.5,
        mitre_techniques=["T1041", "T1567"],
        false_positive_notes="Legitimate backups, large file uploads, and software updates can exceed the threshold; scope by destination reputation and asset context.",
    )

    def __init__(self, threshold_bytes: int = 500 * 1024 * 1024):
        self.threshold_bytes = threshold_bytes

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.NETWORK_CONNECTION:
            return None
        bytes_out = event.bytes_out or 0
        if bytes_out < self.threshold_bytes:
            return None
        return self._build_match(event, evidence={
            "bytes_out": bytes_out, "threshold_bytes": self.threshold_bytes,
            "destination_ip": event.destination_ip, "source_ip": event.source_ip,
        })


def get_rules(threshold_bytes: int = 500 * 1024 * 1024):
    return [LargeOutboundTransferRule(threshold_bytes=threshold_bytes)]
