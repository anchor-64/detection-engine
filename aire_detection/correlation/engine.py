"""
Correlation engine: multi-event detection rules that require bounded,
expiring state (as opposed to the stateless single-event rules in
aire_detection/rules/).

Design goals (per project requirements):
  - bounded memory: every tracked key structure has a hard cap on the
    number of keys and the number of items per key
  - expiration: entries older than the configured time window are
    pruned lazily on every access, so memory does not grow unbounded
    even under sustained traffic
  - deterministic, explainable output: every fired DetectionMatch
    carries the raw evidence (counts, window, distinct values) that
    triggered it
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta
from typing import Deque, Optional

from aire_detection.models import DetectionMatch, EventType, NormalizedEvent, Severity
from aire_detection.rules.base import RuleMeta


class BoundedWindowStore:
    """
    Generic per-key sliding-time-window store.

    Maps key -> deque[(timestamp, payload)]. Old entries are pruned
    whenever a key is touched. If the number of distinct keys exceeds
    max_keys, the least-recently-touched key is evicted (simple LRU),
    which bounds total memory regardless of how many distinct sources
    (e.g. attacker IPs) appear over the lifetime of the process.
    """

    def __init__(self, window_seconds: int, max_keys: int = 10_000, max_items_per_key: int = 1_000):
        self.window = timedelta(seconds=window_seconds)
        self.max_keys = max_keys
        self.max_items_per_key = max_items_per_key
        self._store: dict[str, Deque[tuple]] = {}
        self._lru: deque = deque()  # tracks key touch order for eviction

    def _evict_if_needed(self):
        while len(self._store) > self.max_keys:
            try:
                oldest_key = self._lru.popleft()
            except IndexError:
                break
            self._store.pop(oldest_key, None)

    def _prune(self, key: str, now: datetime):
        dq = self._store.get(key)
        if not dq:
            return
        cutoff = now - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        if not dq:
            self._store.pop(key, None)

    def add(self, key: str, now: datetime, payload) -> Deque[tuple]:
        dq = self._store.setdefault(key, deque())
        dq.append((now, payload))
        while len(dq) > self.max_items_per_key:
            dq.popleft()
        self._lru.append(key)
        self._prune(key, now)
        self._evict_if_needed()
        return self._store.get(key, deque())

    def get(self, key: str, now: datetime) -> Deque[tuple]:
        self._prune(key, now)
        return self._store.get(key, deque())

    def key_count(self) -> int:
        return len(self._store)


class CorrelationRule:
    """Base class for a stateful, multi-event correlation rule."""
    meta: RuleMeta

    def process(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        raise NotImplementedError

    def _build_match(self, evidence: dict, triggering_event_ids: list,
                      confidence: Optional[float] = None,
                      severity: Optional[Severity] = None) -> DetectionMatch:
        return DetectionMatch(
            rule_id=self.meta.rule_id,
            rule_name=self.meta.name,
            description=self.meta.description,
            severity=severity or self.meta.severity,
            confidence=confidence if confidence is not None else self.meta.confidence,
            mitre_techniques=list(self.meta.mitre_techniques),
            evidence=evidence,
            triggering_event_ids=triggering_event_ids,
            false_positive_notes=self.meta.false_positive_notes,
        )


class RepeatedFailedAuthenticationRule(CorrelationRule):
    """AUTH-002 — repeated failed logins against a single user/host pair."""

    meta = RuleMeta(
        rule_id="AUTH-002", name="Repeated Failed Authentication",
        description="Multiple failed authentication attempts were observed against the same user/host within a short window.",
        severity=Severity.MEDIUM, confidence=0.65, mitre_techniques=["T1110"],
        false_positive_notes="Users with cached/expired credentials on multiple devices can trigger repeated failures; check for a single client vs. many.",
    )

    def __init__(self, threshold: int = 5, window_seconds: int = 300):
        self.threshold = threshold
        self.store = BoundedWindowStore(window_seconds)

    def process(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.AUTHENTICATION_FAILURE:
            return None
        key = f"{event.user}|{event.host}"
        entries = self.store.add(key, event.timestamp, event.event_id)
        if len(entries) < self.threshold:
            return None
        return self._build_match(
            evidence={"user": event.user, "host": event.host, "attempt_count": len(entries),
                      "threshold": self.threshold, "window_seconds": self.store.window.total_seconds()},
            triggering_event_ids=[e[1] for e in entries],
        )


class PasswordSprayingRule(CorrelationRule):
    """AUTH-003 — one source IP attempts few passwords across many
    distinct usernames (low attempts-per-user, high distinct-user count)."""

    meta = RuleMeta(
        rule_id="AUTH-003", name="Password Spraying",
        description="A single source attempted authentication against many distinct usernames within a short window, consistent with password spraying.",
        severity=Severity.HIGH, confidence=0.6, mitre_techniques=["T1110.003"],
        false_positive_notes="Shared NAT/proxy egress IPs (campus, corporate VPN) can produce many distinct users from one IP; corroborate with failure ratio.",
    )

    def __init__(self, distinct_user_threshold: int = 8, window_seconds: int = 600):
        self.distinct_user_threshold = distinct_user_threshold
        self.store = BoundedWindowStore(window_seconds)

    def process(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.AUTHENTICATION_FAILURE:
            return None
        if not event.source_ip:
            return None
        entries = self.store.add(event.source_ip, event.timestamp, (event.user, event.event_id))
        payloads = [payload for _, payload in entries]
        distinct_users = {u for u, _ in payloads if u}
        if len(distinct_users) < self.distinct_user_threshold:
            return None
        return self._build_match(
            evidence={"source_ip": event.source_ip, "distinct_usernames": len(distinct_users),
                      "usernames_sample": sorted(list(distinct_users))[:20],
                      "threshold": self.distinct_user_threshold,
                      "window_seconds": self.store.window.total_seconds()},
            triggering_event_ids=[eid for _, eid in payloads],
        )


class SSHBruteForceRule(CorrelationRule):
    """AUTH-004 — mandatory scenario: repeated failed SSH authentication
    from a single source IP against a single target host."""

    meta = RuleMeta(
        rule_id="AUTH-004", name="SSH Brute Force",
        description="Repeated failed SSH authentication attempts were observed from a single source IP against a target host, exceeding the configured threshold within the time window.",
        severity=Severity.HIGH, confidence=0.75, mitre_techniques=["T1110"],
        false_positive_notes="Misconfigured automation (cron jobs, monitoring agents) with stale keys can trigger repeated SSH failures; verify the source is not an authorized internal system.",
    )

    def __init__(self, threshold: int = 5, window_seconds: int = 60):
        self.threshold = threshold
        self.store = BoundedWindowStore(window_seconds)

    def _is_ssh(self, event: NormalizedEvent) -> bool:
        svc = (event.protocol or event.source or "").lower()
        return "ssh" in svc or event.destination_port == 22

    def process(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.AUTHENTICATION_FAILURE:
            return None
        if not self._is_ssh(event):
            return None
        if not event.source_ip:
            return None
        key = f"{event.source_ip}|{event.host or event.destination_ip}"
        entries = self.store.add(key, event.timestamp, event.event_id)
        if len(entries) < self.threshold:
            return None
        return self._build_match(
            evidence={
                "source_ip": event.source_ip, "target_host": event.host or event.destination_ip,
                "attempt_count": len(entries), "threshold": self.threshold,
                "window_seconds": self.store.window.total_seconds(), "service": "ssh",
                "usernames_attempted": event.raw.get("username_history"),
            },
            triggering_event_ids=[e[1] for e in entries],
        )


class AccountLockoutSpikeRule(CorrelationRule):
    """AUTH-005 — a spike of account lockout events within a short
    window, suggestive of either an active brute-force wave or a
    broken automated process hammering a shared credential."""

    meta = RuleMeta(
        rule_id="AUTH-005", name="Account Lockout Spike",
        description="Multiple distinct account lockouts were observed within a short window, suggesting an active credential-attack wave or a malfunctioning automated process.",
        severity=Severity.MEDIUM, confidence=0.5, mitre_techniques=["T1110"],
        false_positive_notes="A misconfigured service using a stale cached password can lock out many accounts; check for a single offending client/service first.",
    )

    def __init__(self, threshold: int = 5, window_seconds: int = 600):
        self.threshold = threshold
        self.store = BoundedWindowStore(window_seconds)

    def process(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.ACCOUNT_LOCKOUT:
            return None
        key = event.domain or event.host or "global"
        entries = self.store.add(key, event.timestamp, (event.user, event.event_id))
        payloads = [payload for _, payload in entries]
        distinct_users = {u for u, _ in payloads if u}
        if len(distinct_users) < self.threshold:
            return None
        return self._build_match(
            evidence={"scope": key, "distinct_locked_accounts": len(distinct_users),
                      "accounts_sample": sorted(list(distinct_users))[:20],
                      "threshold": self.threshold, "window_seconds": self.store.window.total_seconds()},
            triggering_event_ids=[eid for _, eid in payloads],
        )


class PortScanRule(CorrelationRule):
    """NETWORK-001 — mandatory scenario: a source probing many distinct
    ports on a destination within a short window."""

    meta = RuleMeta(
        rule_id="NETWORK-001", name="Port Scanning",
        description="A single source contacted many distinct ports on a destination host within a short window, consistent with port-scanning activity.",
        severity=Severity.MEDIUM, confidence=0.7, mitre_techniques=["T1046"],
        false_positive_notes="Vulnerability-management scanners and load balancers/health checks can resemble scanning; allow-list known scanner source IPs.",
    )

    def __init__(self, distinct_port_threshold: int = 15, window_seconds: int = 60):
        self.distinct_port_threshold = distinct_port_threshold
        self.store = BoundedWindowStore(window_seconds)

    def process(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type not in (EventType.NETWORK_CONNECTION, EventType.PORT_SCAN):
            return None
        if not event.source_ip or not event.destination_ip:
            return None
        key = f"{event.source_ip}|{event.destination_ip}"
        entries = self.store.add(key, event.timestamp, (event.destination_port, event.event_id))
        payloads = [payload for _, payload in entries]
        distinct_ports = {p for p, _ in payloads if p is not None}
        if len(distinct_ports) < self.distinct_port_threshold:
            return None
        return self._build_match(
            evidence={
                "source_ip": event.source_ip, "destination_ip": event.destination_ip,
                "distinct_ports_contacted": len(distinct_ports),
                "ports_sample": sorted(list(distinct_ports))[:30],
                "threshold": self.distinct_port_threshold,
                "window_seconds": self.store.window.total_seconds(),
            },
            triggering_event_ids=[eid for _, eid in payloads],
        )


class HostDiscoverySweepRule(CorrelationRule):
    """NETWORK-002 — a source contacting many distinct destination
    hosts within a short window (network sweep / ping sweep)."""

    meta = RuleMeta(
        rule_id="NETWORK-002", name="Host Discovery Sweep",
        description="A single source contacted many distinct destination hosts within a short window, consistent with a network discovery sweep.",
        severity=Severity.MEDIUM, confidence=0.6, mitre_techniques=["T1018", "T1046"],
        false_positive_notes="Network monitoring tools, DHCP servers, and asset-discovery scanners legitimately contact many hosts; allow-list known management systems.",
    )

    def __init__(self, distinct_host_threshold: int = 20, window_seconds: int = 60):
        self.distinct_host_threshold = distinct_host_threshold
        self.store = BoundedWindowStore(window_seconds)

    def process(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type not in (EventType.NETWORK_CONNECTION, EventType.PORT_SCAN):
            return None
        if not event.source_ip:
            return None
        entries = self.store.add(event.source_ip, event.timestamp, (event.destination_ip, event.event_id))
        payloads = [payload for _, payload in entries]
        distinct_hosts = {h for h, _ in payloads if h}
        if len(distinct_hosts) < self.distinct_host_threshold:
            return None
        return self._build_match(
            evidence={
                "source_ip": event.source_ip, "distinct_hosts_contacted": len(distinct_hosts),
                "hosts_sample": sorted(list(distinct_hosts))[:30],
                "threshold": self.distinct_host_threshold,
                "window_seconds": self.store.window.total_seconds(),
            },
            triggering_event_ids=[eid for _, eid in payloads],
        )


class ExcessiveConnectionAttemptsRule(CorrelationRule):
    """NETWORK-003 — a source generating an abnormally high total
    volume of connection attempts, regardless of port/host diversity."""

    meta = RuleMeta(
        rule_id="NETWORK-003", name="Excessive Connection Attempts",
        description="A single source generated an abnormally high number of connection attempts within a short window.",
        severity=Severity.LOW, confidence=0.4, mitre_techniques=["T1595"],
        false_positive_notes="Legitimate high-throughput clients (load balancers, CDNs, monitoring probes) can exceed volumetric thresholds; tune per environment.",
    )

    def __init__(self, threshold: int = 100, window_seconds: int = 60):
        self.threshold = threshold
        self.store = BoundedWindowStore(window_seconds)

    def process(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.NETWORK_CONNECTION:
            return None
        if not event.source_ip:
            return None
        entries = self.store.add(event.source_ip, event.timestamp, event.event_id)
        if len(entries) < self.threshold:
            return None
        return self._build_match(
            evidence={"source_ip": event.source_ip, "connection_count": len(entries),
                      "threshold": self.threshold, "window_seconds": self.store.window.total_seconds()},
            triggering_event_ids=[e[1] for e in entries],
        )


class RDPBruteForceRule(CorrelationRule):
    """NETWORK-006 — repeated failed RDP authentication from a single
    source against a single target."""

    meta = RuleMeta(
        rule_id="NETWORK-006", name="RDP Brute Force",
        description="Repeated failed RDP authentication attempts were observed from a single source IP against a target host within the time window.",
        severity=Severity.HIGH, confidence=0.7, mitre_techniques=["T1110", "T1021.001"],
        false_positive_notes="Jump-box/RDP-gateway architectures can produce many attempts from one IP; verify the source is not an authorized broker.",
    )

    def __init__(self, threshold: int = 5, window_seconds: int = 60):
        self.threshold = threshold
        self.store = BoundedWindowStore(window_seconds)

    def _is_rdp(self, event: NormalizedEvent) -> bool:
        svc = (event.protocol or event.source or "").lower()
        return "rdp" in svc or event.destination_port == 3389

    def process(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type != EventType.AUTHENTICATION_FAILURE:
            return None
        if not self._is_rdp(event):
            return None
        if not event.source_ip:
            return None
        key = f"{event.source_ip}|{event.host or event.destination_ip}"
        entries = self.store.add(key, event.timestamp, event.event_id)
        if len(entries) < self.threshold:
            return None
        return self._build_match(
            evidence={"source_ip": event.source_ip, "target_host": event.host or event.destination_ip,
                      "attempt_count": len(entries), "threshold": self.threshold,
                      "window_seconds": self.store.window.total_seconds(), "service": "rdp"},
            triggering_event_ids=[e[1] for e in entries],
        )


class ArchiveBeforeTransferRule(CorrelationRule):
    """EXFIL-002 — an archive was created on a host shortly before a
    large outbound transfer originated from that same host."""

    meta = RuleMeta(
        rule_id="EXFIL-002", name="Suspicious Archive Before Transfer",
        description="An archive file was created on a host shortly before a large outbound network transfer originated from that host, consistent with stage-then-exfiltrate behavior.",
        severity=Severity.HIGH, confidence=0.55, mitre_techniques=["T1560.001", "T1041"],
        false_positive_notes="Legitimate backup jobs archive-then-upload on a schedule; allow-list known backup service accounts/hosts.",
    )

    ARCHIVE_EXT = (".zip", ".rar", ".7z", ".tar.gz", ".tgz")

    def __init__(self, correlation_window_seconds: int = 900, transfer_threshold_bytes: int = 50 * 1024 * 1024):
        self.transfer_threshold_bytes = transfer_threshold_bytes
        self.archive_store = BoundedWindowStore(correlation_window_seconds)

    def process(self, event: NormalizedEvent) -> Optional[DetectionMatch]:
        if event.event_type == EventType.FILE_EVENT:
            path = (event.raw.get("file_path") or "").lower()
            if (event.raw.get("action") or "").lower() == "created" and path.endswith(self.ARCHIVE_EXT):
                if event.host:
                    self.archive_store.add(event.host, event.timestamp, (event.raw.get("file_path"), event.event_id))
            return None

        if event.event_type != EventType.NETWORK_CONNECTION:
            return None
        if not event.host:
            return None
        bytes_out = event.bytes_out or 0
        if bytes_out < self.transfer_threshold_bytes:
            return None
        archive_entries = self.archive_store.get(event.host, event.timestamp)
        if not archive_entries:
            return None
        archive_path, archive_event_id = archive_entries[-1]
        return self._build_match(
            evidence={
                "host": event.host, "archive_path": archive_path, "bytes_out": bytes_out,
                "destination_ip": event.destination_ip,
                "transfer_threshold_bytes": self.transfer_threshold_bytes,
            },
            triggering_event_ids=[archive_event_id, event.event_id],
        )


class CorrelationEngine:
    """Orchestrates all stateful correlation rules against the event stream."""

    def __init__(self, rules: Optional[list] = None):
        self.rules = rules if rules is not None else self.default_rules()

    @staticmethod
    def default_rules():
        return [
            RepeatedFailedAuthenticationRule(),
            PasswordSprayingRule(),
            SSHBruteForceRule(),
            AccountLockoutSpikeRule(),
            PortScanRule(),
            HostDiscoverySweepRule(),
            ExcessiveConnectionAttemptsRule(),
            RDPBruteForceRule(),
            ArchiveBeforeTransferRule(),
        ]

    def process(self, event: NormalizedEvent) -> list[DetectionMatch]:
        matches = []
        for rule in self.rules:
            try:
                m = rule.process(event)
            except Exception:
                continue
            if m is not None:
                matches.append(m)
        return matches
