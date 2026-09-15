# AIRE Detection Engine

The **Detection Engine** component of AIRE (Automated Incident Response Engine) — a
production-quality, testable security event detection, correlation, enrichment, and
severity-classification pipeline, built as a standalone Python service that hands
finished **Incidents** off to a separately-developed **Response Engine**.

> \*\*Scope boundary:\*\* the Detection Engine determines \*what happened\*. It never
> executes response actions (no firewall blocks, no account disabling, no process
> termination). That is exclusively the Response Engine's job — see
> \[`docs/INTEGRATION.md`](docs/INTEGRATION.md).

\---

## 1\. Architecture

```
Telemetry (Sysmon / Suricata / Zeek / WAF / Auth logs / Sensors)
        │
        ▼
Normalization  →  NormalizedEvent (stable, vendor-neutral contract)
        │
        ├──────────────┬──────────────────┐
        ▼              ▼                  ▼
  Single-event    Sigma-rule        Correlation Engine
  Rules (36)      Evaluation        (9 stateful, bounded/expiring rules)
        │              │                  │
        └──────────────┴──────────────────┘
                       ▼
              Threat Intel Enrichment
              (VirusTotal, AbuseIPDB — live + mock)
                       ▼
              Severity Classification
              (deterministic, explainable, no ML)
                       ▼
                    Incident
                       ▼
        Response Engine (POST /api/v1/incidents)
```

Every stage is independently testable and independently replaceable. Detection
rules never see raw Sysmon/Suricata/Zeek field names — normalization is the single
translation point (`aire\_detection/normalization/`), so the same rule fires
identically regardless of telemetry source.

### Package layout

```
aire\_detection/
  models.py             NormalizedEvent, DetectionMatch, EnrichmentResult,
                         SeverityResult, Incident — all JSON-serializable
  mitre/mapping.py       Curated registry of real MITRE ATT\&CK technique IDs
  rules/                 36 single-event detection rules (base.py + registry.py)
  correlation/engine.py  9 stateful, bounded/expiring correlation rules
  severity/classifier.py Deterministic severity scoring with full reasoning trail
  enrichment/            VirusTotal / AbuseIPDB providers (live + offline mocks) + cache
  sigma/parser.py        Practical Sigma rule subset (documented scope)
  normalization/         Sysmon / Suricata / Zeek → NormalizedEvent translators
  ingestion/api.py        Authenticated remote telemetry ingestion API (FastAPI)
  integration/client.py  Client that POSTs Incidents to the Response Engine
  pipeline.py            Orchestrates the full flow end-to-end
sigma\_rules/              Example Sigma rule YAML files
tests/                    182 tests covering every rule, engine, and scenario
docs/
  INTEGRATION.md          Detection → Response Engine contract
  LAB\_DEPLOYMENT.md        Same-network / VM / two-network test procedures
```

\---

## 2\. Installation

Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
```

\---

## 3\. Configuration

All configuration is environment-variable based; nothing sensitive is hardcoded.

|Variable|Purpose|Required|
|-|-|-|
|`VT\_API\_KEY`|VirusTotal v3 API key|No — falls back to a safe, non-malicious mock result if absent|
|`ABUSEIPDB\_API\_KEY`|AbuseIPDB API key|No — same safe fallback|
|`AIRE\_SENSOR\_KEYS`|Comma-separated `sensor\_id:api\_key` pairs for ingestion auth|Yes, for the ingestion API|
|`AIRE\_RESPONSE\_ENGINE\_URL`|Base URL of the Response Engine|No — defaults to `http://localhost:8100`|
|`AIRE\_RESPONSE\_ENGINE\_TOKEN`|Bearer token for the Response Engine|No, but recommended for any non-local deployment|

Example:

```bash
export AIRE\_SENSOR\_KEYS="pc-a-collector:$(openssl rand -hex 24)"
export VT\_API\_KEY="your-virustotal-key"          # optional
export ABUSEIPDB\_API\_KEY="your-abuseipdb-key"    # optional
export AIRE\_RESPONSE\_ENGINE\_URL="http://localhost:8100"
```

\---

## 4\. Running

### As a library (embedded pipeline)

```python
from aire\_detection.pipeline import DetectionPipeline
from aire\_detection.models import NormalizedEvent, EventType, utc\_now

pipeline = DetectionPipeline()
event = NormalizedEvent(
    event\_type=EventType.AUTHENTICATION\_FAILURE, timestamp=utc\_now(),
    source="sshd", sensor="pc-a", source\_ip="198.51.100.66",
    host="victim-host", user="root", destination\_port=22, protocol="ssh",
)
incidents = pipeline.process\_event(event)
for incident in incidents:
    print(incident.rule\_id, incident.severity.value, incident.mitre\_techniques)
```

### As a remote ingestion service

```bash
uvicorn aire\_detection.ingestion.api:create\_app --factory --host 0.0.0.0 --port 8000
```

Send telemetry:

```bash
curl -X POST http://localhost:8000/api/v1/ingest/events \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: <sensor-api-key>" \\
  -d '{
    "sensor\_id": "pc-a-collector",
    "events": \[{
      "event\_type": "AUTHENTICATION\_FAILURE",
      "timestamp": "2026-01-01T12:00:00Z",
      "source": "sshd", "sensor": "pc-a-collector",
      "source\_ip": "198.51.100.66", "host": "victim-host",
      "user": "root", "destination\_port": 22, "protocol": "ssh"
    }]
  }'
```

\---

## 5\. Event schema (normalized contract)

Every telemetry source is translated into a `NormalizedEvent` before any rule
evaluates it. Supported `event\_type` values:

`AUTHENTICATION\_FAILURE`, `AUTHENTICATION\_SUCCESS`, `ACCOUNT\_LOCKOUT`,
`ACCOUNT\_CREATED`, `PROCESS\_CREATE`, `NETWORK\_CONNECTION`, `PORT\_SCAN`,
`DNS\_EVENT`, `HTTP\_EVENT`, `SURICATA\_ALERT`, `ZEEK\_CONNECTION`, `WAF\_EVENT`,
`THREAT\_INTELLIGENCE\_EVENT`, `FILE\_EVENT`, `REGISTRY\_EVENT`,
`SCHEDULED\_TASK\_EVENT`, `SERVICE\_EVENT`, `LOG\_CLEAR\_EVENT`.

Every event carries: `event\_id`, `event\_type`, `timestamp`, `source`, `sensor`,
plus context fields relevant to its type (source/destination IP \& port, user,
host, process/Sysmon fields, HTTP/WAF fields, a generic `raw` evidence bag, and
`tags`). Full field list: `aire\_detection/models.py::NormalizedEvent`.

**Important normalization design decision:** Zeek connection records are
normalized to the generic `NETWORK\_CONNECTION` type (not a Zeek-specific type),
because detection rules for port scanning, host discovery, SMB anomalies, and
exfiltration must fire identically regardless of which sensor produced the
connection telemetry. `source="zeek"` preserves provenance without requiring
rule-side special-casing. Suricata *alerts* (as opposed to raw connections) keep
their own `SURICATA\_ALERT` type since they're already a judgment (a firing
signature), not raw connection telemetry.

\---

## 6\. Detection pipeline

1. **Normalization** — caller's responsibility (or use `aire\_detection.normalization`)
2. **Detection** — 36 single-event rules (`rules/`) + Sigma subset (`sigma/`) evaluate every event
3. **Correlation** — 9 stateful rules (`correlation/engine.py`) track bounded,
expiring per-key state (sliding time windows, LRU key eviction, per-key item
caps) to catch multi-event patterns without unbounded memory growth
4. **Enrichment** — matches touching network indicators are enriched via
VirusTotal/AbuseIPDB (mock or live, see below)
5. **Severity classification** — deterministic composite scoring (see below)
6. **Incident construction** — final structured object, ready for the Response
Engine or a dashboard

\---

## 7\. Rule inventory (45 rules)

### Single-event rules (36)

|ID|Name|Severity|MITRE|
|-|-|-|-|
|AUTH-001|Failed Authentication|LOW|T1110|
|AUTH-006|Suspicious New Account|MEDIUM|T1136, T1136.001|
|ENDPOINT-001|Suspicious Process Creation|HIGH|T1105|
|ENDPOINT-002|Suspicious PowerShell Execution|MEDIUM|T1059, T1059.001|
|ENDPOINT-003|Suspicious PowerShell Parent/Child Chain|HIGH|T1059.001, T1204.002|
|ENDPOINT-004|Suspicious Windows Interpreter Execution|MEDIUM|T1218.005, T1059|
|ENDPOINT-005|Suspicious Process from Temporary Directory|MEDIUM|T1204.002|
|ENDPOINT-006|Suspicious Office Child Process|HIGH|T1204.002, T1566.001|
|ENDPOINT-007|Suspicious Rundll32 Execution|MEDIUM|T1218.011|
|ENDPOINT-008|Suspicious Regsvr32 Execution|HIGH|T1218.010, T1553.005|
|ENDPOINT-009|Suspicious Mshta Execution|HIGH|T1218.005|
|ENDPOINT-010|Suspicious Certutil Execution|MEDIUM|T1105, T1140|
|SCRIPT-001|Encoded PowerShell|HIGH|T1059.001, T1027|
|SCRIPT-002|PowerShell Download Activity|HIGH|T1105, T1059.001|
|SCRIPT-003|PowerShell Web Request|CRITICAL|T1105, T1059.001|
|SCRIPT-004|Suspicious Script Host Execution|MEDIUM|T1059|
|SCRIPT-005|Suspicious Base64 Command|MEDIUM|T1027, T1140|
|SCRIPT-006|Suspicious Command Obfuscation|MEDIUM|T1027.010|
|NETWORK-004|Suspicious Remote Service Connection|MEDIUM|T1021|
|NETWORK-005|SMB Connection Anomaly|MEDIUM|T1021.002|
|NETWORK-007|Suspicious DNS Activity|MEDIUM|T1071.004|
|WEB-001|WAF Request Blocked|LOW|T1190|
|WEB-002|SQL Injection Attempt|HIGH|T1190|
|WEB-003|Cross-Site Scripting Attempt|MEDIUM|T1190|
|WEB-004|Path Traversal Attempt|HIGH|T1190|
|WEB-005|Command Injection Attempt|CRITICAL|T1190, T1059|
|WEB-006|Local File Inclusion Attempt|HIGH|T1190|
|WEB-007|Suspicious Web Scanner Activity|MEDIUM|T1595.002|
|PRIV-001|Suspicious Privilege Escalation|HIGH|T1068, T1548|
|PRIV-002|Suspicious Service Creation|HIGH|T1543.003|
|PRIV-003|Suspicious Scheduled Task Creation|MEDIUM|T1053.005|
|PRIV-004|Suspicious Registry Run Key|MEDIUM|T1547.001|
|EVASION-001|Security Tool/Process Tampering|CRITICAL|T1562.001|
|EVASION-002|Windows Event Log Clearing|CRITICAL|T1070.001|
|EVASION-003|Suspicious File Deletion|MEDIUM|T1070.004|
|EXFIL-001|Large Outbound Transfer|HIGH|T1041, T1567|

### Correlation rules (9, bounded \& expiring)

|ID|Name|Severity|MITRE|Key dimension|Default threshold/window|
|-|-|-|-|-|-|
|AUTH-002|Repeated Failed Authentication|MEDIUM|T1110|user+host|5 / 300s|
|AUTH-003|Password Spraying|HIGH|T1110.003|source IP|8 distinct users / 600s|
|AUTH-004|**SSH Brute Force** (mandatory scenario 1)|HIGH|T1110|source IP+host|5 / 60s|
|AUTH-005|Account Lockout Spike|MEDIUM|T1110|domain/host|5 distinct accounts / 600s|
|NETWORK-001|**Port Scanning** (mandatory scenario 2)|MEDIUM|T1046|source+dest IP|15 distinct ports / 60s|
|NETWORK-002|Host Discovery Sweep|MEDIUM|T1018, T1046|source IP|20 distinct hosts / 60s|
|NETWORK-003|Excessive Connection Attempts|LOW|T1595|source IP|100 / 60s|
|NETWORK-006|RDP Brute Force|HIGH|T1110, T1021.001|source IP+host|5 / 60s|
|EXFIL-002|Suspicious Archive Before Transfer|HIGH|T1560.001, T1041|host|archive + ≥50MB transfer / 900s|

Every rule declares: unique ID, name, description, detection logic, severity,
confidence, evidence fields, MITRE mapping (validated against a curated real-ID
registry — invalid IDs raise at rule-registration time), false-positive notes,
and configurable thresholds where a threshold makes sense. See `tests/test\_rules\_\*.py`
and `tests/test\_correlation.py` for the full positive/negative/boundary test matrix.

\---

## 8\. Correlation engine design

`aire\_detection/correlation/engine.py` implements a `BoundedWindowStore`: a
per-key sliding time-window store with two independent memory bounds —
`max\_items\_per\_key` (per-key deque cap) and `max\_keys` (global LRU eviction) —
so a sustained flood from many distinct attacker IPs cannot grow memory
unboundedly. Expired entries are pruned lazily on every access rather than via
a background sweep, keeping the engine simple and dependency-free.

\---

## 9\. Severity classification

`aire\_detection/severity/classifier.py` computes a deterministic 0–100 score
from explicit, auditable factors — **no machine learning**:

* base score from the firing rule's declared severity
* detection confidence adjustment
* threat-intel reputation of any enriched indicators
* affected-asset criticality (configurable per-host lookup)
* a bonus if the finding is a correlated (multi-event) detection rather than a
single isolated event

Every `SeverityResult` carries a `reasons: list\[str]` explaining exactly how the
score was built, and a `factors: dict` with the raw numbers — see
`tests/test\_severity.py`.

\---

## 10\. Threat intelligence

`aire\_detection/enrichment/` provides VirusTotal and AbuseIPDB providers:

* **Live providers** read API keys exclusively from environment variables,
enforce a timeout, and **fail safe** (return a non-malicious, low-confidence
result with `error` populated) if the key is missing or the request fails —
a TI outage never blocks the detection pipeline.
* **Mock providers** (`MockVirusTotalProvider`, `MockAbuseIPDBProvider`) are
deterministic, offline doubles used throughout the test suite and for
demos — no Internet access required.
* Every `EnrichmentResult.mode` is explicitly `"REAL/LIVE"` or `"MOCK/TEST"` —
never ambiguous.
* A bounded TTL cache (`EnrichmentCache`) avoids exhausting free-tier API rate
limits under repeated lookups of the same indicator.

\---

## 11\. Sigma support (documented subset)

`aire\_detection/sigma/parser.py` implements a **practical subset** of the Sigma
specification — not the full spec. Supported: named selections with exact/list/
wildcard/`contains`/`startswith`/`endswith` field matching, and conditions of
the form `selection`, `not selection`, `sel1 and sel2`, `sel1 or sel2`,
`1 of sel\*`, `all of sel\*`. **Not supported:** aggregation (`count() by ...`),
timeframe/near correlation, regex modifiers — these are expressed as native
`Rule`/`CorrelationRule` classes instead. Example rules live in `sigma\_rules/`.

\---

## 12\. MITRE ATT\&CK

`aire\_detection/mitre/mapping.py` is a curated registry of real, published
ATT\&CK technique/sub-technique IDs. Every rule's `mitre\_techniques` list is
validated against this registry at construction time (`RuleMeta.\_\_post\_init\_\_`)
— an invalid or invented ID is a hard failure, not a silent typo.

\---

## 13\. Remote telemetry ingestion

`aire\_detection/ingestion/api.py` is a FastAPI service exposing
`POST /api/v1/ingest/events`:

* **Authentication required** — `X-API-Key` header checked against
`AIRE\_SENSOR\_KEYS`; there is no unauthenticated ingestion path
* **TLS-ready** — the app speaks plain HTTP; terminate TLS at a reverse proxy
(nginx/Caddy) or run behind `uvicorn --ssl-keyfile/--ssl-certfile` in any
non-local deployment
* **Bounded batch size** (`MAX\_EVENTS\_PER\_BATCH = 500`) and per-field
validation via Pydantic (`extra="forbid"` — unknown fields are rejected)
* **Per-sensor rate limiting** (token bucket, bounded to `max\_sensors` entries)
* **Per-event error isolation** — one malformed event in a batch never fails
the whole batch, and the pipeline error path never crashes the request
* Structured logging of accept/reject counts; the API key itself is never logged

\---

## 14\. Testing

```bash
pip install -r requirements.txt
python3 -m pytest -q
```

182 tests covering: model serialization, MITRE ID validation, every single-event
rule (positive/negative/boundary/malformed-event cases), all 9 correlation rules
(including bounded-state and window-expiration behavior), severity classification,
threat-intel enrichment (mocks + fail-safe live-provider paths, no network
access required), the Sigma subset parser, Sysmon/Suricata/Zeek normalization,
the authenticated ingestion API, and the **three mandatory end-to-end
scenarios** (SSH brute force, port scanning, malicious outbound IP) run through
the complete pipeline. See [`docs/LAB\_DEPLOYMENT.md`](docs/LAB_DEPLOYMENT.md)
for live-lab (non-unit-test) validation procedures.

\---

## 15\. False-positive considerations

Every rule's `false\_positive\_notes` field documents its known false-positive
sources (see the rule inventory table's linked source files). In general:

* Endpoint LOLBin rules (certutil, rundll32, mshta, regsvr32) can false-positive
on legitimate IT tooling that uses the same binaries unusually; scope by
signed-publisher allow-lists in production.
* Network correlation rules (port scan, host sweep) will false-positive on
authorized vulnerability scanners and monitoring systems; allow-list known
scanner source IPs via `asset\_criticality\_lookup` or a pre-filter.
* WEB-\* rules trust WAF/HTTP telemetry input; if the WAF itself has a high
false-positive rate, that propagates. WEB-001 is intentionally LOW severity
for this reason — it's a confirmation signal, not a standalone verdict.

\---

## 16\. Limitations

* Detection coverage is bounded by the rules and Sigma content actually
implemented; novel techniques without a matching rule/signature are not detected.
* The Sigma parser supports a documented subset only (no aggregation/timeframe
correlation) — see Section 11.
* The correlation engine emits a match on every window-evaluation cycle where
the threshold condition holds (not just once per "episode"); incident
de-duplication/aggregation across repeated firings is left to the Response
Engine / SOAR layer, which is expected to de-duplicate by evidence overlap
or a cool-down window.
* Live threat-intel enrichment depends on free-tier VirusTotal/AbuseIPDB rate
limits; the TTL cache mitigates but does not eliminate this at scale.
* This is a single-process, single-node reference implementation; horizontal
scaling of the correlation engine's in-memory state is a future-scope item.

\---

## 17\. Future improvements

* Persistent (Redis/DB-backed) correlation state for multi-process horizontal scaling
* Full Sigma aggregation/timeframe support
* Additional threat-intel providers (Shodan, GreyNoise)
* A pluggable asset-criticality/CMDB integration for the severity classifier
* Incident de-duplication/aggregation layer ahead of the Response Engine handoff

