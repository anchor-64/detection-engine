from __future__ import annotations

import re
from typing import Optional

from aire_detection.models import DetectionMatch, EventType, NormalizedEvent, Severity
from aire_detection.rules.base import Rule, RuleMeta


def _target(event: NormalizedEvent) -> str:
    return " ".join(filter(None, [event.uri, event.query]))


class WAFRequestBlockedRule(Rule):
    """WEB-001 — the upstream WAF already made a block decision; we
    surface it as a first-class detection so it feeds correlation/severity."""

    meta = RuleMeta(
        rule_id="WEB-001",
        name="WAF Request Blocked",
        description="The web application firewall blocked an inbound HTTP request.",
        severity=Severity.LOW,
        confidence=0.9,
        mitre_techniques=["T1190"],
        false_positive_notes="WAF rules themselves can misfire on legitimate traffic; treat as confirmation signal, not sole basis for action.",
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.WAF_EVENT:
            return None
        if (event.waf_action or "").lower() != "blocked":
            return None
        return self._build_match(event, evidence={
            "uri": event.uri, "source_ip": event.source_ip, "waf_action": event.waf_action,
        })


class SQLInjectionAttemptRule(Rule):
    """WEB-002 — request URI/query contains classic SQL-injection syntax."""

    meta = RuleMeta(
        rule_id="WEB-002",
        name="SQL Injection Attempt",
        description="An HTTP request contained classic SQL-injection syntax in the URI or query string.",
        severity=Severity.HIGH,
        confidence=0.6,
        mitre_techniques=["T1190"],
        false_positive_notes="Some legitimate applications pass raw SQL-like text (e.g. search terms); tune with allow-listed endpoints.",
    )

    PATTERN = re.compile(
        r"(\bunion\b.{0,20}\bselect\b|\bor\b\s+1\s*=\s*1|--\s|;--|\bsleep\(\d+\)|xp_cmdshell|information_schema)",
        re.IGNORECASE,
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type not in (EventType.HTTP_EVENT, EventType.WAF_EVENT):
            return None
        target = _target(event)
        if not self.PATTERN.search(target):
            return None
        return self._build_match(event, evidence={"uri": event.uri, "query": event.query, "source_ip": event.source_ip})


class XSSAttemptRule(Rule):
    """WEB-003 — request carries a script-injection payload pattern."""

    meta = RuleMeta(
        rule_id="WEB-003",
        name="Cross-Site Scripting Attempt",
        description="An HTTP request contained a script-injection (XSS) payload pattern.",
        severity=Severity.MEDIUM,
        confidence=0.55,
        mitre_techniques=["T1190"],
        false_positive_notes="Security scanners and legitimate rich-text content can trigger this; correlate with WAF verdict.",
    )

    PATTERN = re.compile(r"(<script|onerror\s*=|onload\s*=|javascript:|document\.cookie)", re.IGNORECASE)

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type not in (EventType.HTTP_EVENT, EventType.WAF_EVENT):
            return None
        target = _target(event)
        if not self.PATTERN.search(target):
            return None
        return self._build_match(event, evidence={"uri": event.uri, "query": event.query, "source_ip": event.source_ip})


class PathTraversalAttemptRule(Rule):
    """WEB-004 — directory-traversal sequences targeting sensitive paths."""

    meta = RuleMeta(
        rule_id="WEB-004",
        name="Path Traversal Attempt",
        description="An HTTP request contained directory-traversal sequences (../, encoded variants) potentially targeting files outside the webroot.",
        severity=Severity.HIGH,
        confidence=0.6,
        mitre_techniques=["T1190"],
        false_positive_notes="Rare in legitimate traffic; near-zero false-positive baseline once URL-decoding is applied correctly.",
    )

    PATTERN = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|/etc/passwd|boot\.ini)", re.IGNORECASE)

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type not in (EventType.HTTP_EVENT, EventType.WAF_EVENT):
            return None
        target = _target(event)
        if not self.PATTERN.search(target):
            return None
        return self._build_match(event, evidence={"uri": event.uri, "query": event.query, "source_ip": event.source_ip})


class CommandInjectionAttemptRule(Rule):
    """WEB-005 — request carries shell-metacharacter chaining typical
    of OS command injection attempts."""

    meta = RuleMeta(
        rule_id="WEB-005",
        name="Command Injection Attempt",
        description="An HTTP request parameter contained shell metacharacters chained with common commands, suggestive of OS command injection.",
        severity=Severity.CRITICAL,
        confidence=0.6,
        mitre_techniques=["T1190", "T1059"],
        false_positive_notes="Free-text fields occasionally contain these characters incidentally; still high-value signal when combined with a command name.",
    )

    PATTERN = re.compile(r"(;|\||&&)\s*(cat|whoami|wget|curl|nc|bash|sh|id|uname)\b", re.IGNORECASE)

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type not in (EventType.HTTP_EVENT, EventType.WAF_EVENT):
            return None
        target = _target(event)
        if not self.PATTERN.search(target):
            return None
        return self._build_match(event, evidence={"uri": event.uri, "query": event.query, "source_ip": event.source_ip})


class LocalFileInclusionAttemptRule(Rule):
    """WEB-006 — request references a PHP wrapper or common LFI target
    file, distinct from generic path traversal."""

    meta = RuleMeta(
        rule_id="WEB-006",
        name="Local File Inclusion Attempt",
        description="An HTTP request referenced a PHP stream wrapper (php://, file://) or a commonly-included sensitive file.",
        severity=Severity.HIGH,
        confidence=0.55,
        mitre_techniques=["T1190"],
        false_positive_notes="Legitimate file-upload/include features in some CMS platforms can superficially resemble this; verify parameter context.",
    )

    PATTERN = re.compile(r"(php://filter|php://input|file://|expect://|include\s*\(|/proc/self/environ)", re.IGNORECASE)

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type not in (EventType.HTTP_EVENT, EventType.WAF_EVENT):
            return None
        target = _target(event)
        if not self.PATTERN.search(target):
            return None
        return self._build_match(event, evidence={"uri": event.uri, "query": event.query, "source_ip": event.source_ip})


class SuspiciousWebScannerActivityRule(Rule):
    """WEB-007 — the User-Agent string matches a known automated
    scanner/tooling signature."""

    meta = RuleMeta(
        rule_id="WEB-007",
        name="Suspicious Web Scanner Activity",
        description="An HTTP request's User-Agent matched a known automated vulnerability-scanner or exploitation-framework signature.",
        severity=Severity.MEDIUM,
        confidence=0.65,
        mitre_techniques=["T1595.002"],
        false_positive_notes="Authorized internal vulnerability scanning will also match; allow-list scheduled scanner source IPs.",
    )

    SCANNERS = re.compile(
        r"(sqlmap|nikto|nmap scripting engine|acunetix|nessus|dirbuster|gobuster|wpscan|masscan|zgrab|burpsuite)",
        re.IGNORECASE,
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type not in (EventType.HTTP_EVENT, EventType.WAF_EVENT):
            return None
        ua = event.user_agent or ""
        if not self.SCANNERS.search(ua):
            return None
        return self._build_match(event, evidence={"user_agent": ua, "source_ip": event.source_ip, "uri": event.uri})


def get_rules():
    return [
        WAFRequestBlockedRule(),
        SQLInjectionAttemptRule(),
        XSSAttemptRule(),
        PathTraversalAttemptRule(),
        CommandInjectionAttemptRule(),
        LocalFileInclusionAttemptRule(),
        SuspiciousWebScannerActivityRule(),
    ]
