import pytest
from fastapi.testclient import TestClient

from aire_detection.ingestion.api import MAX_EVENTS_PER_BATCH, create_app
from aire_detection.ingestion.auth import RateLimiter, SensorAuthStore
from aire_detection.pipeline import DetectionPipeline

SENSOR_ID = "test-sensor-1"
API_KEY = "test-key-do-not-use-in-prod"


def make_client(rate_limiter=None):
    auth = SensorAuthStore(include_test_credentials=True)
    app = create_app(pipeline=DetectionPipeline(), auth_store=auth, rate_limiter=rate_limiter or RateLimiter(capacity=1000, refill_rate_per_sec=1000))
    return TestClient(app)


def _event(event_type="AUTHENTICATION_FAILURE", **overrides):
    base = {
        "event_type": event_type, "timestamp": "2026-01-01T12:00:00Z",
        "source": "sshd", "sensor": SENSOR_ID, "user": "bob", "source_ip": "10.0.0.1",
    }
    base.update(overrides)
    return base


def test_health_endpoint():
    client = make_client()
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_ingest_requires_api_key_header():
    client = make_client()
    resp = client.post("/api/v1/ingest/events", json={"sensor_id": SENSOR_ID, "events": [_event()]})
    assert resp.status_code == 422  # missing required header


def test_ingest_rejects_invalid_api_key():
    client = make_client()
    resp = client.post(
        "/api/v1/ingest/events",
        json={"sensor_id": SENSOR_ID, "events": [_event()]},
        headers={"X-API-Key": "wrong-key"},
    )
    assert resp.status_code == 401


def test_ingest_accepts_valid_authenticated_batch():
    client = make_client()
    resp = client.post(
        "/api/v1/ingest/events",
        json={"sensor_id": SENSOR_ID, "events": [_event()]},
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["batch_accepted_count"] == 1
    assert body["batch_rejected_count"] == 0


def test_ingest_rejects_empty_batch():
    client = make_client()
    resp = client.post(
        "/api/v1/ingest/events",
        json={"sensor_id": SENSOR_ID, "events": []},
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 400


def test_ingest_rejects_oversized_batch():
    client = make_client()
    events = [_event() for _ in range(MAX_EVENTS_PER_BATCH + 1)]
    resp = client.post(
        "/api/v1/ingest/events",
        json={"sensor_id": SENSOR_ID, "events": events},
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 413


def test_ingest_reports_per_event_malformed_errors_without_failing_batch():
    client = make_client()
    good = _event()
    bad = _event(event_type="NOT_A_REAL_EVENT_TYPE")
    resp = client.post(
        "/api/v1/ingest/events",
        json={"sensor_id": SENSOR_ID, "events": [good, bad]},
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["batch_accepted_count"] == 1
    assert body["batch_rejected_count"] == 1
    assert body["results"][1]["accepted"] is False
    assert body["results"][1]["error"] is not None


def test_ingest_rejects_unknown_extra_fields():
    client = make_client()
    payload = _event()
    payload["totally_made_up_field"] = "x"
    resp = client.post(
        "/api/v1/ingest/events",
        json={"sensor_id": SENSOR_ID, "events": [payload]},
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 422


def test_ingest_triggers_detection_and_reports_incident_count():
    """Five rapid SSH auth failures from one IP should trip AUTH-004 and
    the response should reflect that at least one event raised incidents."""
    client = make_client()
    events = [
        _event(source_ip="198.51.100.66", host="victim", destination_port=22, protocol="ssh",
               timestamp=f"2026-01-01T12:00:0{i}Z")
        for i in range(6)
    ]
    resp = client.post(
        "/api/v1/ingest/events",
        json={"sensor_id": SENSOR_ID, "events": events},
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 200
    body = resp.json()
    total_incidents = sum(r["incidents_raised"] for r in body["results"])
    assert total_incidents >= 6  # at least one AUTH-001 per event, plus AUTH-004 once threshold hit


def test_rate_limiting_blocks_after_capacity_exhausted():
    limiter = RateLimiter(capacity=2, refill_rate_per_sec=0.0001)
    client = make_client(rate_limiter=limiter)
    for _ in range(2):
        resp = client.post(
            "/api/v1/ingest/events",
            json={"sensor_id": SENSOR_ID, "events": [_event()]},
            headers={"X-API-Key": API_KEY},
        )
        assert resp.status_code == 200
    resp = client.post(
        "/api/v1/ingest/events",
        json={"sensor_id": SENSOR_ID, "events": [_event()]},
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 429


def test_recent_incidents_requires_valid_key():
    client = make_client()
    resp = client.get("/api/v1/incidents/recent", headers={"X-API-Key": "wrong"})
    assert resp.status_code == 401
    resp2 = client.get("/api/v1/incidents/recent", headers={"X-API-Key": API_KEY})
    assert resp2.status_code == 200
