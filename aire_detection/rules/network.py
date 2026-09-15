from __future__ import annotations

import math
import re
from collections import Counter
from typing import Optional

from aire_detection.models import DetectionMatch, EventType, NormalizedEvent, Severity
from aire_detection.rules.base import Rule, RuleMeta

RISKY_PORTS = {23: "telnet", 445: "smb", 3389: "rdp", 135: "rpc", 5900: "vnc"}


class SuspiciousRemoteServiceConnectionRule(Rule):
    """NETWORK-004 — an inbound connection to a legacy/high-risk
    remote-access or management port from outside the local network."""

    meta = RuleMeta(
        rule_id="NETWORK-004",
        name="Suspicious Remote Service Connection",
        description="A connection was observed to a legacy or high-risk remote-management port (telnet, SMB, RDP, RPC, VNC) from an external source.",
        severity=Severity.MEDIUM,
        confidence=0.4,
        mitre_techniques=["T1021"],
        false_positive_notes="Internal management traffic on these ports is normal; scope by source-network context (external vs internal) before alerting broadly.",
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.NETWORK_CONNECTION:
            return None
        if event.destination_port not in RISKY_PORTS:
            return None
        if event.raw.get("source_is_internal"):
            return None
        return self._build_match(event, evidence={
            "source_ip": event.source_ip, "destination_ip": event.destination_ip,
            "destination_port": event.destination_port, "service": RISKY_PORTS[event.destination_port],
        })


class SMBConnectionAnomalyRule(Rule):
    """NETWORK-005 — SMB (445) connection carrying an anomaly flag from
    the sensor (e.g. named-pipe access pattern, anonymous auth)."""

    meta = RuleMeta(
        rule_id="NETWORK-005",
        name="SMB Connection Anomaly",
        description="An SMB connection was flagged by the sensor for an anomalous access pattern (e.g. anonymous logon, unusual named-pipe access, admin-share write from a workstation).",
        severity=Severity.MEDIUM,
        confidence=0.5,
        mitre_techniques=["T1021.002"],
        false_positive_notes="Backup and management software legitimately use admin shares; verify against known-good service accounts.",
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.NETWORK_CONNECTION:
            return None
        if event.destination_port != 445:
            return None
        if not event.raw.get("smb_anomaly"):
            return None
        return self._build_match(event, evidence={
            "source_ip": event.source_ip, "destination_ip": event.destination_ip,
            "anomaly": event.raw.get("smb_anomaly"),
        })


class SuspiciousDNSActivityRule(Rule):
    """NETWORK-007 — a DNS query for a domain with characteristics
    typical of DGA (domain generation algorithm) output: high entropy,
    long random-looking label, or an uncommon TLD combined with length."""

    meta = RuleMeta(
        rule_id="NETWORK-007",
        name="Suspicious DNS Activity",
        description="A DNS query was made for a domain exhibiting high-entropy/DGA-like characteristics in its label.",
        severity=Severity.MEDIUM,
        confidence=0.4,
        mitre_techniques=["T1071.004"],
        false_positive_notes="CDNs, ad-tech, and some SaaS platforms legitimately use randomized-looking subdomains; entropy heuristics alone produce noise and should feed correlation/enrichment rather than alert solo.",
    )

    LABEL_RE = re.compile(r"^([a-z0-9-]+)\.")

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.DNS_EVENT:
            return None
        domain = (event.domain or "").lower().strip(".")
        if not domain:
            return None
        m = self.LABEL_RE.match(domain + ".")
        label = m.group(1) if m else domain
        if len(label) < 12:
            return None
        entropy = self._shannon_entropy(label)
        if entropy < 3.6:
            return None
        return self._build_match(event, evidence={
            "domain": domain, "label": label, "entropy": round(entropy, 2), "source_ip": event.source_ip,
        })


def get_rules():
    return [
        SuspiciousRemoteServiceConnectionRule(),
        SMBConnectionAnomalyRule(),
        SuspiciousDNSActivityRule(),
    ]
