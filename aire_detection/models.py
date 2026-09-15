"""
Core data models for the AIRE Detection Engine.

All models are plain dataclasses with explicit to_dict()/from_dict()
JSON-serialization helpers (rather than relying on a third-party
schema library) so the contract is easy to audit and has zero
runtime dependencies.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(ts: datetime) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    v = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(v)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class EventType(str, Enum):
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    AUTHENTICATION_SUCCESS = "AUTHENTICATION_SUCCESS"
    ACCOUNT_LOCKOUT = "ACCOUNT_LOCKOUT"
    ACCOUNT_CREATED = "ACCOUNT_CREATED"
    PROCESS_CREATE = "PROCESS_CREATE"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    PORT_SCAN = "PORT_SCAN"
    DNS_EVENT = "DNS_EVENT"
    HTTP_EVENT = "HTTP_EVENT"
    SURICATA_ALERT = "SURICATA_ALERT"
    ZEEK_CONNECTION = "ZEEK_CONNECTION"
    WAF_EVENT = "WAF_EVENT"
    THREAT_INTELLIGENCE_EVENT = "THREAT_INTELLIGENCE_EVENT"
    FILE_EVENT = "FILE_EVENT"
    REGISTRY_EVENT = "REGISTRY_EVENT"
    SCHEDULED_TASK_EVENT = "SCHEDULED_TASK_EVENT"
    SERVICE_EVENT = "SERVICE_EVENT"
    LOG_CLEAR_EVENT = "LOG_CLEAR_EVENT"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[self.value]


def _dc_to_dict(obj) -> dict:
    """Convert a dataclass to a JSON-safe dict, handling datetime/Enum."""
    def conv(v):
        if isinstance(v, datetime):
            return iso(v)
        if isinstance(v, Enum):
            return v.value
        if isinstance(v, dict):
            return {k: conv(x) for k, x in v.items()}
        if isinstance(v, (list, tuple)):
            return [conv(x) for x in v]
        if hasattr(v, "to_dict"):
            return v.to_dict()
        return v

    return {k: conv(v) for k, v in asdict(obj).items()}


@dataclass
class NormalizedEvent:
    """
    The stable normalized event contract. Every telemetry source
    (Sysmon, Suricata, Zeek, WAF, auth logs, threat-intel feeds, ...)
    is translated into this shape before detection logic ever sees it.
    """
    event_type: EventType
    timestamp: datetime
    source: str                      # originating system, e.g. "sshd", "sysmon", "suricata"
    sensor: str                      # collector/sensor identity that forwarded this event
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None

    user: Optional[str] = None
    host: Optional[str] = None
    domain: Optional[str] = None

    # process / sysmon fields
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    process_guid: Optional[str] = None
    command_line: Optional[str] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    parent_process_guid: Optional[str] = None
    parent_command_line: Optional[str] = None
    integrity_level: Optional[str] = None

    # network / connection fields
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    connection_state: Optional[str] = None
    action: Optional[str] = None  # e.g. allowed/blocked/dropped

    # web / WAF fields
    http_method: Optional[str] = None
    uri: Optional[str] = None
    query: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    waf_action: Optional[str] = None

    # generic evidence bag for source-specific extras
    raw: dict = field(default_factory=dict)
    tags: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return _dc_to_dict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "NormalizedEvent":
        d = dict(d)
        d["event_type"] = EventType(d["event_type"])
        d["timestamp"] = parse_iso(d["timestamp"]) if isinstance(d["timestamp"], str) else d["timestamp"]
        known = {f for f in cls.__dataclass_fields__.keys()}
        filtered = {k: v for k, v in d.items() if k in known}
        return cls(**filtered)


@dataclass
class DetectionMatch:
    """A single rule firing against one or more normalized events."""
    rule_id: str
    rule_name: str
    description: str
    severity: Severity
    confidence: float                 # 0.0 - 1.0
    mitre_techniques: list            # list[str] of ATT&CK IDs
    evidence: dict
    triggering_event_ids: list
    match_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=utc_now)
    false_positive_notes: str = ""

    def to_dict(self) -> dict:
        return _dc_to_dict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "DetectionMatch":
        d = dict(d)
        d["severity"] = Severity(d["severity"])
        if isinstance(d.get("timestamp"), str):
            d["timestamp"] = parse_iso(d["timestamp"])
        known = set(cls.__dataclass_fields__.keys())
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class EnrichmentResult:
    """Result of enriching an indicator (IP/domain/hash) via a TI provider."""
    provider: str                    # "virustotal" | "abuseipdb"
    indicator: str
    indicator_type: str              # "ip" | "domain" | "hash"
    is_malicious: bool
    reputation_score: float          # normalized 0-100
    confidence: float
    mode: str                        # "REAL/LIVE" | "MOCK/TEST"
    raw_response: dict = field(default_factory=dict)
    queried_at: datetime = field(default_factory=utc_now)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return _dc_to_dict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "EnrichmentResult":
        d = dict(d)
        if isinstance(d.get("queried_at"), str):
            d["queried_at"] = parse_iso(d["queried_at"])
        known = set(cls.__dataclass_fields__.keys())
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class SeverityResult:
    severity: Severity
    score: float                      # 0-100 composite score
    reasons: list                     # list[str] human-readable explanation
    factors: dict                     # raw factor breakdown for auditability

    def to_dict(self) -> dict:
        return _dc_to_dict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "SeverityResult":
        d = dict(d)
        d["severity"] = Severity(d["severity"])
        return cls(**d)


@dataclass
class Incident:
    """
    The final structured output of the pipeline: a detection (possibly
    correlated from multiple matches/events), enriched and classified,
    ready to be handed to the Response Engine or dashboard.
    """
    rule_id: str
    rule_name: str
    severity: Severity
    confidence: float
    mitre_techniques: list
    evidence: dict
    incident_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=utc_now)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    affected_user: Optional[str] = None
    affected_host: Optional[str] = None
    enrichment: list = field(default_factory=list)     # list[EnrichmentResult.to_dict()]
    severity_result: Optional[dict] = None              # SeverityResult.to_dict()
    correlated_event_ids: list = field(default_factory=list)
    recommended_response_category: Optional[str] = None
    status: str = "OPEN"

    def to_dict(self) -> dict:
        return _dc_to_dict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Incident":
        d = dict(d)
        d["severity"] = Severity(d["severity"])
        if isinstance(d.get("created_at"), str):
            d["created_at"] = parse_iso(d["created_at"])
        known = set(cls.__dataclass_fields__.keys())
        return cls(**{k: v for k, v in d.items() if k in known})
