# Detection Engine ↔ Response Engine Integration

This document is the versioned contract between the **AIRE Detection Engine**
(this repository) and the separately-developed **AIRE Response Engine**.

**Separation of concerns is absolute:**

- The **Detection Engine** determines *what happened* — it detects, correlates,
  enriches, and classifies. It never blocks an IP, disables an account, kills a
  process, or isolates a host.
- The **Response Engine** determines *what action to take* — it receives a
  fully-described `Incident` and makes its own response decision.

No detection rule in this codebase executes a response action. This is
enforced structurally: `aire_detection/rules/` and `aire_detection/correlation/`
only ever construct `DetectionMatch`/`Incident` objects; there is no code path
from a rule to a firewall/process/account API anywhere in this package.

---

## 1. Endpoint

```
POST {RESPONSE_ENGINE_BASE_URL}/api/v1/incidents
```

Versioned under `/api/v1/` — a breaking change to the payload shape ships as
`/api/v2/incidents` rather than mutating v1 in place.

## 2. Authentication

`Authorization: Bearer {AIRE_RESPONSE_ENGINE_TOKEN}` — read exclusively from
the `AIRE_RESPONSE_ENGINE_TOKEN` environment variable on the Detection Engine
side (see `aire_detection/integration/client.py::ResponseEngineClientConfig`).
Never hardcode this token. The Response Engine is expected to reject requests
missing or presenting an invalid bearer token with `401 Unauthorized`.

## 3. Idempotency

Every `Incident` carries a stable `incident_id` (UUID4) minted once at
detection time. The Detection Engine sends this same ID on every retry via the
`Idempotency-Key` HTTP header **and** in the JSON body's `incident_id` field.
**The Response Engine MUST treat a repeated `incident_id` as the same incident**
and must not take a duplicate response action if it receives the same
`incident_id` twice (e.g. due to a client-side retry after a dropped response).

## 4. Retry & timeout behavior (Detection Engine side)

Implemented in `ResponseEngineClient.send_incident()`:

- Request timeout: 5 seconds (configurable via `ResponseEngineClientConfig.timeout_seconds`)
- Retries: up to 3 attempts (configurable), exponential backoff starting at 0.5s
- A `4xx` response is treated as non-retryable (the request itself is wrong;
  retrying won't help) and the client gives up immediately
- A `5xx` response, connection error, or timeout is retried
- If all retries are exhausted, `send_incident()` returns a structured
  `{"status": "failed", "error": ..., "incident_id": ...}` dict — **it never
  raises**, so a Response Engine outage cannot crash or stall the detection
  pipeline. The caller (e.g. a scheduled forwarder job) is responsible for
  deciding what to do with failed sends (dead-letter queue, alert, etc.)

## 5. Request schema

`Content-Type: application/json`, body is the full `Incident.to_dict()` output:

```json
{
  "rule_id": "AUTH-004",
  "rule_name": "SSH Brute Force",
  "severity": "CRITICAL",
  "confidence": 0.75,
  "mitre_techniques": ["T1110"],
  "evidence": {
    "source_ip": "198.51.100.66",
    "target_host": "victim-host",
    "attempt_count": 6,
    "threshold": 5,
    "window_seconds": 60.0,
    "service": "ssh"
  },
  "incident_id": "8f14e45f-ceea-4b3e-a6cd-4a3f6c1b9c2a",
  "created_at": "2026-01-01T12:00:10Z",
  "source_ip": "198.51.100.66",
  "destination_ip": null,
  "affected_user": null,
  "affected_host": "victim-host",
  "enrichment": [
    {
      "provider": "abuseipdb",
      "indicator": "198.51.100.66",
      "indicator_type": "ip",
      "is_malicious": true,
      "reputation_score": 98.0,
      "confidence": 0.85,
      "mode": "MOCK/TEST",
      "raw_response": {"note": "deterministic offline mock, no network call made"},
      "queried_at": "2026-01-01T12:00:10Z",
      "error": null
    }
  ],
  "severity_result": {
    "severity": "CRITICAL",
    "score": 92.5,
    "reasons": [
      "Base score 70 from rule severity HIGH (AUTH-004).",
      "Confidence 0.75 adjusted score by +5.0.",
      "Threat-intel enrichment flagged an indicator as malicious (reputation 98/100 via abuseipdb); +24.5.",
      "Finding is a multi-event correlated detection (higher confidence than a single isolated event); +10.",
      "Final composite score 92.5 maps to CRITICAL."
    ],
    "factors": {"base_severity": "HIGH", "base_score": 70, "confidence": 0.75, "confidence_adjustment": 5.0}
  },
  "correlated_event_ids": ["evt-1", "evt-2", "evt-3", "evt-4", "evt-5", "evt-6"],
  "recommended_response_category": "immediate_containment_review",
  "status": "OPEN"
}
```

### Field notes for the Response Engine

- **`incident_id`** — use for idempotent processing (Section 3)
- **`rule_id` / `rule_name`** — which detection fired
- **`severity`** — one of `LOW | MEDIUM | HIGH | CRITICAL`
- **`confidence`** — 0.0–1.0, the *detection* confidence (independent of severity)
- **`mitre_techniques`** — validated real ATT&CK IDs only (never invented)
- **`evidence`** — rule-specific structured evidence; always JSON-safe
- **`source_ip` / `destination_ip` / `affected_user` / `affected_host`** — the
  primary entities involved, promoted to top-level fields for convenience even
  though they're also present in `evidence`
- **`enrichment`** — list of threat-intel results consulted; check `mode` to
  distinguish `"REAL/LIVE"` from `"MOCK/TEST"` results before trusting them in
  a production response decision
- **`severity_result`** — the full explainable scoring breakdown
- **`correlated_event_ids`** — every triggering event ID, not just the last one
- **`recommended_response_category`** — a *suggestion only* (`log_only` |
  `standard_queue` | `priority_analyst_review` | `immediate_containment_review`),
  derived purely from severity. The Response Engine is not obligated to follow
  it and makes its own authoritative decision.
- **`status`** — always `"OPEN"` when sent by the Detection Engine; the
  Response Engine owns subsequent status transitions

## 6. Response schema (expected from the Response Engine)

The Detection Engine does not require a specific response body shape to
function (see error handling above), but the reference Response Engine is
expected to reply:

```json
{ "status": "accepted", "incident_id": "8f14e45f-...", "action_taken": "queued_for_review" }
```

or, on validation failure:

```json
{ "status": "rejected", "incident_id": "8f14e45f-...", "error": "missing required field: severity" }
```

## 7. Error handling summary

| Condition | Detection Engine behavior |
|---|---|
| Response Engine returns 2xx | Success; response body parsed and returned to caller |
| Response Engine returns 4xx | No retry (request is malformed/unauthorized); logged and returned as failure |
| Response Engine returns 5xx | Retried up to `max_retries` with exponential backoff |
| Connection refused / timeout | Retried up to `max_retries` with exponential backoff |
| All retries exhausted | Returns `{"status": "failed", ...}`; never raises |

## 8. API versioning

The version is embedded in the path (`/api/v1/incidents`). `ResponseEngineClient`
exposes `API_VERSION = "v1"` as a module constant in
`aire_detection/integration/client.py`; bumping to v2 means updating that
constant plus the corresponding request/response schema in this document.

---

## 9. Local development setup (two separate services)

Terminal 1 — start a minimal stub Response Engine for local testing:

```bash
python3 - << 'PY'
from fastapi import FastAPI, Request
import uvicorn

app = FastAPI()

@app.post("/api/v1/incidents")
async def receive_incident(request: Request):
    body = await request.json()
    print("Received incident:", body["incident_id"], body["rule_id"], body["severity"])
    return {"status": "accepted", "incident_id": body["incident_id"], "action_taken": "logged"}

uvicorn.run(app, host="0.0.0.0", port=8100)
PY
```

Terminal 2 — start the Detection Engine's ingestion API:

```bash
export AIRE_SENSOR_KEYS="pc-a-collector:devkey123"
export AIRE_RESPONSE_ENGINE_URL="http://localhost:8100"
uvicorn aire_detection.ingestion.api:create_app --factory --host 0.0.0.0 --port 8000
```

Terminal 3 — send telemetry and forward the resulting incident:

```bash
curl -X POST http://localhost:8000/api/v1/ingest/events \
  -H "Content-Type: application/json" -H "X-API-Key: devkey123" \
  -d '{"sensor_id":"pc-a-collector","events":[{
        "event_type":"AUTHENTICATION_FAILURE","timestamp":"2026-01-01T12:00:00Z",
        "source":"sshd","sensor":"pc-a-collector","source_ip":"198.51.100.66",
        "host":"victim-host","user":"root","destination_port":22,"protocol":"ssh"}]}'
```

```python
# forward_incidents.py — example forwarder run alongside the ingestion API
from aire_detection.integration.client import ResponseEngineClient, ResponseEngineClientConfig
from aire_detection.models import Incident

client = ResponseEngineClient(ResponseEngineClientConfig(base_url="http://localhost:8100"))
# incident = <pulled from the ingestion API's in-memory store, a queue, or a DB>
# result = client.send_incident(incident)
```

In a full deployment, the ingestion API's accepted incidents would be pushed to
a queue (or the `/api/v1/incidents/recent` endpoint polled) by a small
forwarder process that calls `ResponseEngineClient.send_incident()` — kept as a
separate process so a Response Engine outage never blocks telemetry ingestion.
