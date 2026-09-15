"""
Normalizes raw Sysmon Event ID 1 (ProcessCreate) telemetry (as commonly
shipped in JSON form by Winlogbeat/Wazuh) into the stable NormalizedEvent
contract used throughout the detection pipeline.

Only Event ID 1 (process creation) is handled here; this module is the
single translation point so detection rules never need to know Sysmon's
raw field names.
"""
from __future__ import annotations

from aire_detection.models import EventType, NormalizedEvent, parse_iso


def normalize_sysmon_process_create(raw: dict, sensor: str) -> NormalizedEvent:
    """
    Expected raw Sysmon-like shape (subset of real Sysmon EventData):

    {
      "UtcTime": "2026-01-01 12:00:00.000",
      "ProcessGuid": "{...}", "ProcessId": 1234, "Image": "C:\\...\\powershell.exe",
      "CommandLine": "powershell.exe -enc ...", "User": "CORP\\bob",
      "IntegrityLevel": "Medium", "Computer": "WORKSTATION01",
      "ParentProcessGuid": "{...}", "ParentProcessId": 5678,
      "ParentImage": "C:\\...\\winword.exe", "ParentCommandLine": "..."
    }
    """
    timestamp_raw = raw.get("UtcTime")
    timestamp = parse_iso(timestamp_raw.replace(" ", "T") + "Z") if timestamp_raw and "T" not in timestamp_raw else (
        parse_iso(timestamp_raw) if timestamp_raw else None
    )
    if timestamp is None:
        raise ValueError("Sysmon event missing required UtcTime field")

    def basename(path):
        if not path:
            return None
        return path.replace("/", "\\").split("\\")[-1]

    return NormalizedEvent(
        event_type=EventType.PROCESS_CREATE,
        timestamp=timestamp,
        source="sysmon",
        sensor=sensor,
        host=raw.get("Computer"),
        user=raw.get("User"),
        process_name=basename(raw.get("Image")),
        process_id=_to_int(raw.get("ProcessId")),
        process_guid=raw.get("ProcessGuid"),
        command_line=raw.get("CommandLine"),
        parent_process_name=basename(raw.get("ParentImage")),
        parent_process_id=_to_int(raw.get("ParentProcessId")),
        parent_process_guid=raw.get("ParentProcessGuid"),
        parent_command_line=raw.get("ParentCommandLine"),
        integrity_level=raw.get("IntegrityLevel"),
        raw={
            "image_path": raw.get("Image"),
            "parent_integrity_level": raw.get("ParentIntegrityLevel"),
            **{k: v for k, v in raw.items() if k not in {
                "UtcTime", "Computer", "User", "Image", "ProcessId", "ProcessGuid",
                "CommandLine", "ParentImage", "ParentProcessId", "ParentProcessGuid",
                "ParentCommandLine", "IntegrityLevel",
            }},
        },
    )


def _to_int(value):
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
