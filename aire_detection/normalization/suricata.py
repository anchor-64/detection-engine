"""
Normalizes Suricata EVE JSON `alert` records into NormalizedEvent.

Suricata's eve.json alert events look like:

{
  "timestamp": "2026-01-01T12:00:00.000000+0000",
  "src_ip": "203.0.113.5", "src_port": 51234,
  "dest_ip": "10.0.0.10", "dest_port": 22, "proto": "TCP",
  "alert": {"signature": "ET SCAN Potential SSH Scan", "severity": 2, "category": "..."},
  "app_proto": "ssh"
}
"""
from __future__ import annotations

from aire_detection.models import EventType, NormalizedEvent, parse_iso


def normalize_suricata_alert(raw: dict, sensor: str) -> NormalizedEvent:
    timestamp_raw = raw.get("timestamp")
    if not timestamp_raw:
        raise ValueError("Suricata event missing required timestamp field")
    # Suricata emits e.g. "...+0000" (no colon); normalize to a form parse_iso accepts.
    ts_str = timestamp_raw
    if len(ts_str) >= 5 and ts_str[-5] in "+-" and ts_str[-3] != ":":
        ts_str = ts_str[:-2] + ":" + ts_str[-2:]
    timestamp = parse_iso(ts_str)

    alert = raw.get("alert", {}) or {}

    return NormalizedEvent(
        event_type=EventType.SURICATA_ALERT,
        timestamp=timestamp,
        source="suricata",
        sensor=sensor,
        source_ip=raw.get("src_ip"),
        destination_ip=raw.get("dest_ip"),
        source_port=raw.get("src_port"),
        destination_port=raw.get("dest_port"),
        protocol=raw.get("proto"),
        action=alert.get("action"),
        raw={
            "signature": alert.get("signature"),
            "signature_severity": alert.get("severity"),
            "category": alert.get("category"),
            "app_proto": raw.get("app_proto"),
        },
        tags=[alert.get("category")] if alert.get("category") else [],
    )
