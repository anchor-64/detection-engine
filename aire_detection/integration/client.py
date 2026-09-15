"""
Detection Engine -> Response Engine integration client.

This client implements the DETECTION side of the versioned contract
documented in docs/INTEGRATION.md. It POSTs structured Incident
objects to a Response Engine's `POST /api/v1/incidents` endpoint.

Design principles enforced here:
  - The Detection Engine never executes response actions itself. This
    client's only job is to hand off a fully-described Incident and
    let the Response Engine decide what to do with it.
  - Idempotency: every Incident already carries a stable incident_id
    (a UUID minted at detection time). The same incident_id is sent on
    every retry, so a Response Engine that de-duplicates by
    incident_id will not double-act on a retried request.
  - Bounded retries with exponential backoff and a hard timeout, so a
    slow/unreachable Response Engine cannot stall the detection
    pipeline indefinitely.
  - Authentication via a bearer token read from the environment,
    never hardcoded.
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from aire_detection.models import Incident

logger = logging.getLogger("aire.integration")

API_VERSION = "v1"


@dataclass
class ResponseEngineClientConfig:
    base_url: str
    api_token: str | None = None
    timeout_seconds: float = 5.0
    max_retries: int = 3
    backoff_base_seconds: float = 0.5

    @classmethod
    def from_env(cls) -> "ResponseEngineClientConfig":
        return cls(
            base_url=os.environ.get("AIRE_RESPONSE_ENGINE_URL", "http://localhost:8100"),
            api_token=os.environ.get("AIRE_RESPONSE_ENGINE_TOKEN"),
        )


class ResponseEngineClient:
    def __init__(self, config: ResponseEngineClientConfig | None = None):
        self.config = config or ResponseEngineClientConfig.from_env()

    @property
    def endpoint(self) -> str:
        return f"{self.config.base_url.rstrip('/')}/api/{API_VERSION}/incidents"

    def _build_request(self, incident: Incident) -> urllib.request.Request:
        body = json.dumps(incident.to_dict()).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": incident.incident_id,
        }
        if self.config.api_token:
            headers["Authorization"] = f"Bearer {self.config.api_token}"
        return urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")

    def send_incident(self, incident: Incident) -> dict:
        """
        Send a single incident. Retries transient failures (network
        errors, 5xx) with exponential backoff. Returns the parsed JSON
        response on success, or a structured error dict on final failure
        (never raises to the caller, so a Response Engine outage does
        not crash the detection pipeline).
        """
        last_error = None
        for attempt in range(1, self.config.max_retries + 1):
            req = self._build_request(incident)
            try:
                with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
                    raw = resp.read().decode("utf-8")
                    return json.loads(raw) if raw else {"status": "accepted"}
            except urllib.error.HTTPError as exc:
                last_error = f"HTTP {exc.code}: {exc.reason}"
                if exc.code < 500:
                    # Client error (4xx) — retrying the same request will not help.
                    break
            except urllib.error.URLError as exc:
                last_error = f"connection error: {exc.reason}"
            except TimeoutError:
                last_error = "timeout"

            if attempt < self.config.max_retries:
                sleep_for = self.config.backoff_base_seconds * (2 ** (attempt - 1))
                logger.warning(
                    "Response Engine send failed (attempt %d/%d) for incident_id=%s: %s; retrying in %.1fs",
                    attempt, self.config.max_retries, incident.incident_id, last_error, sleep_for,
                )
                time.sleep(sleep_for)

        logger.error(
            "Giving up sending incident_id=%s to Response Engine after %d attempts: %s",
            incident.incident_id, self.config.max_retries, last_error,
        )
        return {"status": "failed", "error": last_error, "incident_id": incident.incident_id}

    def send_batch(self, incidents: list[Incident]) -> list[dict]:
        return [self.send_incident(i) for i in incidents]
