"""
Normalizes Zeek conn.log JSON records into NormalizedEvent.

Zeek conn.log (JSON output) records look like:

{
  "ts": 1767268800.123456, "id.orig_h": "10.0.0.5", "id.orig_p": 51234,
  "id.resp_h": "10.0.0.10", "id.resp_p": 445, "proto": "tcp",
  "conn_state": "S0", "orig_bytes": 120, "resp_bytes": 0
}
"""
from __future__ import annotations

from datetime import datetime, timezone

from aire_detection.models import EventType, NormalizedEvent


def normalize_zeek_conn(raw: dict, sensor: str) -> NormalizedEvent:
    """
    Emits EventType.NETWORK_CONNECTION (the generic, vendor-neutral
    connection type), not a Zeek-specific event type. This is
    deliberate: detection rules (port scanning, host discovery, SMB
    anomaly, exfiltration, etc.) are written once against
    NETWORK_CONNECTION and must fire identically regardless of
    whether the telemetry originated from Zeek, Suricata's flow
    records, or a generic sensor. `source="zeek"` preserves the
    telemetry's origin for evidence/audit purposes without requiring
    rules to special-case it.
    """
    ts_epoch = raw.get("ts")
    if ts_epoch is None:
        raise ValueError("Zeek conn record missing required ts field")
    timestamp = datetime.fromtimestamp(float(ts_epoch), tz=timezone.utc)

    return NormalizedEvent(
        event_type=EventType.NETWORK_CONNECTION,
        timestamp=timestamp,
        source="zeek",
        sensor=sensor,
        source_ip=raw.get("id.orig_h"),
        destination_ip=raw.get("id.resp_h"),
        source_port=_to_int(raw.get("id.orig_p")),
        destination_port=_to_int(raw.get("id.resp_p")),
        protocol=raw.get("proto"),
        connection_state=raw.get("conn_state"),
        bytes_out=_to_int(raw.get("orig_bytes")),
        bytes_in=_to_int(raw.get("resp_bytes")),
        raw={k: v for k, v in raw.items() if k not in {
            "ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
            "proto", "conn_state", "orig_bytes", "resp_bytes",
        }},
    )


def _to_int(value):
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
