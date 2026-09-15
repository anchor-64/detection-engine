"""
Remote telemetry ingestion service.

Exposes a single authenticated endpoint that accepts batches of
structured, normalized-event JSON from a sensor/collector and runs
them through the Detection Engine pipeline.

Security properties:
  - authentication required (sensor ID + API key header) — never
    exposes an unauthenticated ingestion endpoint
  - TLS-ready: this app speaks plain HTTP; TLS termination is expected
    to be provided by a reverse proxy (nginx/Caddy) or an ASGI server
    configured with a certificate in any real deployment (documented
    in docs/INTEGRATION.md)
  - request size is bounded (max events per batch, enforced by pydantic
    validation) to avoid unbounded memory use per request
  - per-sensor rate limiting
  - structured logging of accepted/rejected requests without ever
    logging the API key itself
  - malformed events are reported per-item rather than failing the
    whole batch or raising an unhandled exception
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aire_detection.ingestion.auth import RateLimiter, SensorAuthStore
from aire_detection.models import NormalizedEvent
from aire_detection.pipeline import DetectionPipeline

logger = logging.getLogger("aire.ingestion")

MAX_EVENTS_PER_BATCH = 500


class EventPayload(BaseModel):
    """Mirrors NormalizedEvent's public JSON contract. Unknown extra
    fields are rejected to keep the contract explicit and auditable."""

    event_type: str
    timestamp: str
    source: str
    sensor: str
    event_id: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    domain: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    process_guid: Optional[str] = None
    command_line: Optional[str] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    parent_process_guid: Optional[str] = None
    parent_command_line: Optional[str] = None
    integrity_level: Optional[str] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    connection_state: Optional[str] = None
    action: Optional[str] = None
    http_method: Optional[str] = None
    uri: Optional[str] = None
    query: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    waf_action: Optional[str] = None
    raw: dict = Field(default_factory=dict)
    tags: list = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class IngestBatch(BaseModel):
    sensor_id: str
    events: list[EventPayload]

    model_config = ConfigDict(extra="forbid")


class EventIngestResult(BaseModel):
    event_index: int
    accepted: bool
    event_id: Optional[str] = None
    incidents_raised: int = 0
    error: Optional[str] = None


class IngestResponse(BaseModel):
    batch_accepted_count: int
    batch_rejected_count: int
    results: list[EventIngestResult]


def create_app(
    pipeline: Optional[DetectionPipeline] = None,
    auth_store: Optional[SensorAuthStore] = None,
    rate_limiter: Optional[RateLimiter] = None,
) -> FastAPI:
    app = FastAPI(title="AIRE Detection Engine Ingestion API", version="1.0.0")

    state = {
        "pipeline": pipeline or DetectionPipeline(),
        "auth": auth_store or SensorAuthStore(),
        "rate_limiter": rate_limiter or RateLimiter(),
        "incidents": [],  # bounded ring buffer of the most recent incidents for local inspection/tests
    }
    MAX_STORED_INCIDENTS = 2000

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/api/v1/ingest/events", response_model=IngestResponse)
    def ingest_events(
        batch: IngestBatch,
        request: Request,
        x_api_key: str = Header(..., alias="X-API-Key"),
    ):
        if len(batch.events) == 0:
            raise HTTPException(status_code=400, detail="Batch must contain at least one event.")
        if len(batch.events) > MAX_EVENTS_PER_BATCH:
            raise HTTPException(
                status_code=413,
                detail=f"Batch exceeds maximum of {MAX_EVENTS_PER_BATCH} events per request.",
            )

        if not state["auth"].is_valid(batch.sensor_id, x_api_key):
            logger.warning("Ingestion auth failure for sensor_id=%s", batch.sensor_id)
            raise HTTPException(status_code=401, detail="Invalid sensor_id or API key.")

        if not state["rate_limiter"].allow(batch.sensor_id, cost=len(batch.events)):
            logger.warning("Rate limit exceeded for sensor_id=%s", batch.sensor_id)
            raise HTTPException(status_code=429, detail="Rate limit exceeded for this sensor.")

        results: list[EventIngestResult] = []
        accepted = 0
        rejected = 0

        for idx, event_payload in enumerate(batch.events):
            try:
                event_dict = event_payload.model_dump()
                normalized = NormalizedEvent.from_dict(event_dict)
            except (ValidationError, ValueError, KeyError) as exc:
                rejected += 1
                results.append(EventIngestResult(event_index=idx, accepted=False, error=str(exc)))
                continue

            try:
                incidents = state["pipeline"].process_event(normalized)
            except Exception as exc:
                # A processing failure on one event must never crash the request
                # or block the rest of the batch.
                logger.exception("Pipeline processing error for event_id=%s", normalized.event_id)
                rejected += 1
                results.append(EventIngestResult(
                    event_index=idx, accepted=False, event_id=normalized.event_id,
                    error=f"processing_error: {exc}",
                ))
                continue

            state["incidents"].extend(incidents)
            if len(state["incidents"]) > MAX_STORED_INCIDENTS:
                state["incidents"] = state["incidents"][-MAX_STORED_INCIDENTS:]

            accepted += 1
            results.append(EventIngestResult(
                event_index=idx, accepted=True, event_id=normalized.event_id,
                incidents_raised=len(incidents),
            ))

        logger.info(
            "Ingest batch from sensor_id=%s: accepted=%d rejected=%d",
            batch.sensor_id, accepted, rejected,
        )
        return IngestResponse(batch_accepted_count=accepted, batch_rejected_count=rejected, results=results)

    @app.get("/api/v1/incidents/recent")
    def recent_incidents(limit: int = 50, x_api_key: str = Header(..., alias="X-API-Key")):
        # Any valid sensor credential may read recent incidents for local
        # debugging; production deployments should scope this to an
        # operator role rather than sensor credentials (see INTEGRATION.md).
        if x_api_key not in {v for v in _all_keys(state["auth"])}:
            raise HTTPException(status_code=401, detail="Invalid API key.")
        limit = max(1, min(limit, MAX_STORED_INCIDENTS))
        return [i.to_dict() for i in state["incidents"][-limit:]]

    app.state.aire = state
    return app


def _all_keys(auth_store: SensorAuthStore):
    return [auth_store._credentials[s] for s in auth_store.sensor_ids()]  # noqa: SLF001 (internal helper, test/debug endpoint only)
