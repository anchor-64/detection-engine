# AIRE Detection Engine

The **Detection Engine** component of AIRE (Automated Incident Response Engine) — a
production-quality, testable security event detection, correlation, enrichment, and
severity-classification pipeline, built as a standalone Python service that hands
finished **Incidents** off to a separately-developed **Response Engine**.

> **Scope boundary:** the Detection Engine determines *what happened*. It never
> executes response actions (no firewall blocks, no account disabling, no process
> termination). That is exclusively the Response Engine's job — see
> [`docs/INTEGRATION.md`](docs/INTEGRATION.md).

---

## 1. Architecture

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
translation point (`aire_detection/normalization/`), so the same rule fires
identically regardless of telemetry source.

### Package layout

```
aire_detection/
  models.py             NormalizedEvent, DetectionMatch, EnrichmentResult,
                         SeverityResult, Incident — all JSON-serializable
  mitre/mapping.py       Curated registry of real MITRE ATT&CK technique IDs
  rules/                 36 single-event detection rules (base.py + registry.py)
  correlation/engine.py  9 stateful, bounded/expiring correlation rules
  severity/classifier.py Deterministic severity scoring with full reasoning trail
  enrichment/            VirusTotal / AbuseIPDB providers (live + offline mocks) + cache
  sigma/parser.py        Practical Sigma rule subset (documented scope)
  normalization/         Sysmon / Suricata / Zeek → NormalizedEvent translators
  ingestion/api.py        Authenticated remote telemetry ingestion API (FastAPI)
  integration/client.py  Client that POSTs Incidents to the Response Engine
  pipeline.py            Orchestrates the full flow end-to-end
sigma_rules/              Example Sigma rule YAML files
tests/                    182 tests covering every rule, engine, and scenario
docs/
  INTEGRATION.md          Detection → Response Engine contract
  LAB_DEPLOYMENT.md        Same-network / VM / two-network test procedures
```

---

## 2. Installation

Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## 3. Configuration

All configuration is environment-variable based; nothing sensitive is hardcoded.

| Variable | Purpose | Required |
|---|---|---|
| `VT_API_KEY` | VirusTotal v3 API key | No — falls back to a safe, non-malicious mock result if absent |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | No — same safe fallback |
| `AIRE_SENSOR_KEYS` | Comma-separated `sensor_id:api_key` pairs for ingestion auth | Yes, for the ingestion API |
| `AIRE_RESPONSE_ENGINE_URL` | Base URL of the Response Engine | No — defaults to `http://localhost:8100` |
| `AIRE_RESPONSE_ENGINE_TOKEN` | Bearer token for the Response Engine | No, but recommended for any non-local deployment |

Example:

```bash
export AIRE_SENSOR_KEYS="pc-a-collector:$(openssl rand -hex 24)"
export VT_API_KEY="your-virustotal-key"          # optional
export ABUSEIPDB_API_KEY="your-abuseipdb-key"    # optional
export AIRE_RESPONSE_ENGINE_URL="http://localhost:8100"
```

---

## 4. Running

### As a library (embedded pipeline)

```python
from aire_detection.pipeline import DetectionPipeline
from aire_detection.models import NormalizedEvent, EventType, utc_now

pipeline = DetectionPipeline()
event = NormalizedEvent(
    event_type=EventType.AUTHENTICATION_FAILURE, timestamp=utc_now(),
    source="sshd", sensor="pc-a", source_ip="198.51.100.66",
    host="victim-host", user="root", destination_port=22, protocol="ssh",
)
incidents = pipeline.process_event(event)
for incident in incidents:
    print(incident.rule_id, incident.severity.value, incident.mitre_techniques)
```

### As a remote ingestion service

```bash
uvicorn aire_detection.ingestion.api:create_app --factory --host 0.0.0.0 --port 8000
```

Send telemetry:

```bash
curl -X POST http://localhost:8000/api/v1/ingest/events \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <sensor-api-key>" \
  -d '{
    "sensor_id": "pc-a-collector",
    "events": [{
      "event_type": "AUTHENTICATION_FAILURE",
      "timestamp": "2026-01-01T12:00:00Z",
      "source": "sshd", "sensor": "pc-a-collector",
      "source_ip": "198.51.100.66", "host": "victim-host",
      "user": "root", "destination_port": 22, "protocol": "ssh"
    }]
  }'
```

---

## 5. Event schema (normalized contract)

Every telemetry source is translated into a `NormalizedEvent` before any rule
evaluates it. Supported `event_type` values:

`AUTHENTICATION_FAILURE`, `AUTHENTICATION_SUCCESS`, `ACCOUNT_LOCKOUT`,
`ACCOUNT_CREATED`, `PROCESS_CREATE`, `NETWORK_CONNECTION`, `PORT_SCAN`,
`DNS_EVENT`, `HTTP_EVENT`, `SURICATA_ALERT`, `ZEEK_CONNECTION`, `WAF_EVENT`,
`THREAT_INTELLIGENCE_EVENT`, `FILE_EVENT`, `REGISTRY_EVENT`,
`SCHEDULED_TASK_EVENT`, `SERVICE_EVENT`, `LOG_CLEAR_EVENT`.

Every event carries: `event_id`, `event_type`, `timestamp`, `source`, `sensor`,
plus context fields relevant to its type (source/destination IP & port, user,
host, process/Sysmon fields, HTTP/WAF fields, a generic `raw` evidence bag, and
`tags`). Full field list: `aire_detection/models.py::NormalizedEvent`.

**Important normalization design decision:** Zeek connection records are
normalized to the generic `NETWORK_CONNECTION` type (not a Zeek-specific type),
because detection rules for port scanning, host discovery, SMB anomalies, and
exfiltration must fire identically regardless of which sensor produced the
connection telemetry. `source="zeek"` preserves provenance without requiring
rule-side special-casing. Suricata *alerts* (as opposed to raw connections) keep
their own `SURICATA_ALERT` type since they're already a judgment (a firing
signature), not raw connection telemetry.

---

## 6. Detection pipeline

1. **Normalization** — caller's responsibility (or use `aire_detection.normalization`)
2. **Detection** — 36 single-event rules (`rules/`) + Sigma subset (`sigma/`) evaluate every event
3. **Correlation** — 9 stateful rules (`correlation/engine.py`) track bounded,
   expiring per-key state (sliding time windows, LRU key eviction, per-key item
   caps) to catch multi-event patterns without unbounded memory growth
4. **Enrichment** — matches touching network indicators are enriched via
   VirusTotal/AbuseIPDB (mock or live, see below)
5. **Severity classification** — deterministic composite scoring (see below)
6. **Incident construction** — final structured object, ready for the Response
   Engine or a dashboard

---

## 7. Rule inventory (45 rules)

### Single-event rules (36)

| ID | Name | Severity | MITRE |
|---|---|---|---|
| AUTH-001 | Failed Authentication | LOW | T1110 |
| AUTH-006 | Suspicious New Account | MEDIUM | T1136, T1136.001 |
| ENDPOINT-001 | Suspicious Process Creation | HIGH | T1105 |
| ENDPOINT-002 | Suspicious PowerShell Execution | MEDIUM | T1059, T1059.001 |
| ENDPOINT-003 | Suspicious PowerShell Parent/Child Chain | HIGH | T1059.001, T1204.002 |
| ENDPOINT-004 | Suspicious Windows Interpreter Execution | MEDIUM | T1218.005, T1059 |
| ENDPOINT-005 | Suspicious Process from Temporary Directory | MEDIUM | T1204.002 |
| ENDPOINT-006 | Suspicious Office Child Process | HIGH | T1204.002, T1566.001 |
| ENDPOINT-007 | Suspicious Rundll32 Execution | MEDIUM | T1218.011 |
| ENDPOINT-008 | Suspicious Regsvr32 Execution | HIGH | T1218.010, T1553.005 |
| ENDPOINT-009 | Suspicious Mshta Execution | HIGH | T1218.005 |
| ENDPOINT-010 | Suspicious Certutil Execution | MEDIUM | T1105, T1140 |
| SCRIPT-001 | Encoded PowerShell | HIGH | T1059.001, T1027 |
| SCRIPT-002 | PowerShell Download Activity | HIGH | T1105, T1059.001 |
| SCRIPT-003 | PowerShell Web Request | CRITICAL | T1105, T1059.001 |
| SCRIPT-004 | Suspicious Script Host Execution | MEDIUM | T1059 |
| SCRIPT-005 | Suspicious Base64 Command | MEDIUM | T1027, T1140 |
| SCRIPT-006 | Suspicious Command Obfuscation | MEDIUM | T1027.010 |
| NETWORK-004 | Suspicious Remote Service Connection | MEDIUM | T1021 |
| NETWORK-005 | SMB Connection Anomaly | MEDIUM | T1021.002 |
| NETWORK-007 | Suspicious DNS Activity | MEDIUM | T1071.004 |
| WEB-001 | WAF Request Blocked | LOW | T1190 |
| WEB-002 | SQL Injection Attempt | HIGH | T1190 |
| WEB-003 | Cross-Site Scripting Attempt | MEDIUM | T1190 |
| WEB-004 | Path Traversal Attempt | HIGH | T1190 |
| WEB-005 | Command Injection Attempt | CRITICAL | T1190, T1059 |
| WEB-006 | Local File Inclusion Attempt | HIGH | T1190 |
| WEB-007 | Suspicious Web Scanner Activity | MEDIUM | T1595.002 |
| PRIV-001 | Suspicious Privilege Escalation | HIGH | T1068, T1548 |
| PRIV-002 | Suspicious Service Creation | HIGH | T1543.003 |
| PRIV-003 | Suspicious Scheduled Task Creation | MEDIUM | T1053.005 |
| PRIV-004 | Suspicious Registry Run Key | MEDIUM | T1547.001 |
| EVASION-001 | Security Tool/Process Tampering | CRITICAL | T1562.001 |
| EVASION-002 | Windows Event Log Clearing | CRITICAL | T1070.001 |
| EVASION-003 | Suspicious File Deletion | MEDIUM | T1070.004 |
| EXFIL-001 | Large Outbound Transfer | HIGH | T1041, T1567 |

### Correlation rules (9, bounded & expiring)

| ID | Name | Severity | MITRE | Key dimension | Default threshold/window |
|---|---|---|---|---|---|
| AUTH-002 | Repeated Failed Authentication | MEDIUM | T1110 | user+host | 5 / 300s |
| AUTH-003 | Password Spraying | HIGH | T1110.003 | source IP | 8 distinct users / 600s |
| AUTH-004 | **SSH Brute Force** (mandatory scenario 1) | HIGH | T1110 | source IP+host | 5 / 60s |
| AUTH-005 | Account Lockout Spike | MEDIUM | T1110 | domain/host | 5 distinct accounts / 600s |
| NETWORK-001 | **Port Scanning** (mandatory scenario 2) | MEDIUM | T1046 | source+dest IP | 15 distinct ports / 60s |
| NETWORK-002 | Host Discovery Sweep | MEDIUM | T1018, T1046 | source IP | 20 distinct hosts / 60s |
| NETWORK-003 | Excessive Connection Attempts | LOW | T1595 | source IP | 100 / 60s |
| NETWORK-006 | RDP Brute Force | HIGH | T1110, T1021.001 | source IP+host | 5 / 60s |
| EXFIL-002 | Suspicious Archive Before Transfer | HIGH | T1560.001, T1041 | host | archive + ≥50MB transfer / 900s |

Every rule declares: unique ID, name, description, detection logic, severity,
confidence, evidence fields, MITRE mapping (validated against a curated real-ID
registry — invalid IDs raise at rule-registration time), false-positive notes,
and configurable thresholds where a threshold makes sense. See `tests/test_rules_*.py`
and `tests/test_correlation.py` for the full positive/negative/boundary test matrix.

---

## 8. Correlation engine design

`aire_detection/correlation/engine.py` implements a `BoundedWindowStore`: a
per-key sliding time-window store with two independent memory bounds —
`max_items_per_key` (per-key deque cap) and `max_keys` (global LRU eviction) —
so a sustained flood from many distinct attacker IPs cannot grow memory
unboundedly. Expired entries are pruned lazily on every access rather than via
a background sweep, keeping the engine simple and dependency-free.

---

## 9. Severity classification

`aire_detection/severity/classifier.py` computes a deterministic 0–100 score
from explicit, auditable factors — **no machine learning**:

- base score from the firing rule's declared severity
- detection confidence adjustment
- threat-intel reputation of any enriched indicators
- affected-asset criticality (configurable per-host lookup)
- a bonus if the finding is a correlated (multi-event) detection rather than a
  single isolated event

Every `SeverityResult` carries a `reasons: list[str]` explaining exactly how the
score was built, and a `factors: dict` with the raw numbers — see
`tests/test_severity.py`.

---

## 10. Threat intelligence

`aire_detection/enrichment/` provides VirusTotal and AbuseIPDB providers:

- **Live providers** read API keys exclusively from environment variables,
  enforce a timeout, and **fail safe** (return a non-malicious, low-confidence
  result with `error` populated) if the key is missing or the request fails —
  a TI outage never blocks the detection pipeline.
- **Mock providers** (`MockVirusTotalProvider`, `MockAbuseIPDBProvider`) are
  deterministic, offline doubles used throughout the test suite and for
  demos — no Internet access required.
- Every `EnrichmentResult.mode` is explicitly `"REAL/LIVE"` or `"MOCK/TEST"` —
  never ambiguous.
- A bounded TTL cache (`EnrichmentCache`) avoids exhausting free-tier API rate
  limits under repeated lookups of the same indicator.

---

## 11. Sigma support (documented subset)

`aire_detection/sigma/parser.py` implements a **practical subset** of the Sigma
specification — not the full spec. Supported: named selections with exact/list/
wildcard/`contains`/`startswith`/`endswith` field matching, and conditions of
the form `selection`, `not selection`, `sel1 and sel2`, `sel1 or sel2`,
`1 of sel*`, `all of sel*`. **Not supported:** aggregation (`count() by ...`),
timeframe/near correlation, regex modifiers — these are expressed as native
`Rule`/`CorrelationRule` classes instead. Example rules live in `sigma_rules/`.

---

## 12. MITRE ATT&CK

`aire_detection/mitre/mapping.py` is a curated registry of real, published
ATT&CK technique/sub-technique IDs. Every rule's `mitre_techniques` list is
validated against this registry at construction time (`RuleMeta.__post_init__`)
— an invalid or invented ID is a hard failure, not a silent typo.

---

## 13. Remote telemetry ingestion

`aire_detection/ingestion/api.py` is a FastAPI service exposing
`POST /api/v1/ingest/events`:

- **Authentication required** — `X-API-Key` header checked against
  `AIRE_SENSOR_KEYS`; there is no unauthenticated ingestion path
- **TLS-ready** — the app speaks plain HTTP; terminate TLS at a reverse proxy
  (nginx/Caddy) or run behind `uvicorn --ssl-keyfile/--ssl-certfile` in any
  non-local deployment
- **Bounded batch size** (`MAX_EVENTS_PER_BATCH = 500`) and per-field
  validation via Pydantic (`extra="forbid"` — unknown fields are rejected)
- **Per-sensor rate limiting** (token bucket, bounded to `max_sensors` entries)
- **Per-event error isolation** — one malformed event in a batch never fails
  the whole batch, and the pipeline error path never crashes the request
- Structured logging of accept/reject counts; the API key itself is never logged

---

## 14. Testing

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
the complete pipeline. See [`docs/LAB_DEPLOYMENT.md`](docs/LAB_DEPLOYMENT.md)
for live-lab (non-unit-test) validation procedures.

---

## 15. False-positive considerations

Every rule's `false_positive_notes` field documents its known false-positive
sources (see the rule inventory table's linked source files). In general:

- Endpoint LOLBin rules (certutil, rundll32, mshta, regsvr32) can false-positive
  on legitimate IT tooling that uses the same binaries unusually; scope by
  signed-publisher allow-lists in production.
- Network correlation rules (port scan, host sweep) will false-positive on
  authorized vulnerability scanners and monitoring systems; allow-list known
  scanner source IPs via `asset_criticality_lookup` or a pre-filter.
- WEB-* rules trust WAF/HTTP telemetry input; if the WAF itself has a high
  false-positive rate, that propagates. WEB-001 is intentionally LOW severity
  for this reason — it's a confirmation signal, not a standalone verdict.

---

## 16. Limitations

- Detection coverage is bounded by the rules and Sigma content actually
  implemented; novel techniques without a matching rule/signature are not detected.
- The Sigma parser supports a documented subset only (no aggregation/timeframe
  correlation) — see Section 11.
- The correlation engine emits a match on every window-evaluation cycle where
  the threshold condition holds (not just once per "episode"); incident
  de-duplication/aggregation across repeated firings is left to the Response
  Engine / SOAR layer, which is expected to de-duplicate by evidence overlap
  or a cool-down window.
- Live threat-intel enrichment depends on free-tier VirusTotal/AbuseIPDB rate
  limits; the TTL cache mitigates but does not eliminate this at scale.
- This is a single-process, single-node reference implementation; horizontal
  scaling of the correlation engine's in-memory state is a future-scope item.

---

## 17. Future improvements

- Persistent (Redis/DB-backed) correlation state for multi-process horizontal scaling
- Full Sigma aggregation/timeframe support
- Additional threat-intel providers (Shodan, GreyNoise)
- A pluggable asset-criticality/CMDB integration for the severity classifier
- Incident de-duplication/aggregation layer ahead of the Response Engine handoff

---

============================================================
AIRE — 3 LIVE LAB SCENARIOS
COLLECTOR → DETECTION ENGINE
============================================================

IMPORTANT:
The collector's job is ONLY:

RAW TELEMETRY
    ↓
COLLECT
    ↓
NORMALIZE TO NormalizedEvent
    ↓
POST TO DETECTION ENGINE

Do NOT implement detection rules, MITRE mapping, severity,
correlation, or threat-intelligence logic in the collector.

Detection Engine handles those parts.

Detection Engine IP:
192.168.56.10

Kali IP:
192.168.56.30

Detection Engine API:
http://192.168.56.10:8000/api/v1/ingest/events


============================================================
SCENARIO 1 — SSH BRUTE FORCE
============================================================

GOAL:
Kali generates real SSH login failures.
Ubuntu collector reads SSH/journald logs.
Collector converts them to AUTHENTICATION_FAILURE events.
Detection Engine detects AUTH-004.

FLOW:

Kali
 ↓
Hydra
 ↓
Ubuntu SSH
 ↓
journald
 ↓
SSH Collector
 ↓
NormalizedEvent
 ↓
Detection Engine
 ↓
AUTH-004
 ↓
HIGH
 ↓
MITRE T1110
 ↓
Incident


STEP 1 — Start Detection Engine on Ubuntu

cd /home/ayu_det/aire-detection-engine/aire-detection-engine

export AIRE_SENSOR_KEYS="kali-lab:YOUR_API_KEY"

python3 -m uvicorn aire_detection.ingestion.api:create_app \
  --factory --host 0.0.0.0 --port 8000


STEP 2 — Test API from Kali

curl http://192.168.56.10:8000/health

Expected:

{"status":"ok"}


STEP 3 — Generate REAL SSH failures from Kali

printf 'wrong1\nwrong2\nwrong3\nwrong4\nwrong5\n' > /tmp/aire-ssh-test.txt

hydra -l fakeuser \
  -P /tmp/aire-ssh-test.txt \
  ssh://192.168.56.10 \
  -t 1 -V


STEP 4 — Verify raw SSH logs on Ubuntu

sudo journalctl -u ssh --since "5 minutes ago"


You should see failed SSH authentication entries from:

192.168.56.30


STEP 5 — COLLECTOR REQUIREMENT

The collector must read the SSH/journald events and create:

event_type:
AUTHENTICATION_FAILURE

Required useful fields:

source:
sshd

sensor:
<collector-id>

source_ip:
192.168.56.30

host:
detection

user:
fakeuser

destination_port:
22

protocol:
ssh

raw:
{
  "original_log": "...",
  "username_history": ["fakeuser"]
}


IMPORTANT SSH PARSING:

One failed SSH attempt can generate multiple log lines.

For example:

pam_unix ... authentication failure
Failed password ...

DO NOT count these as two independent authentication attempts.

Use the actual failed-password event as the canonical attempt and
keep the other line as supporting evidence/context.


STEP 6 — SEND NORMALIZED EVENTS

POST:

http://192.168.56.10:8000/api/v1/ingest/events

Header:

X-API-Key: YOUR_API_KEY

Example:

curl -X POST \
  http://192.168.56.10:8000/api/v1/ingest/events \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "sensor_id": "kali-lab",
    "events": [{
      "event_type": "AUTHENTICATION_FAILURE",
      "timestamp": "2026-09-15T12:00:00Z",
      "source": "sshd",
      "sensor": "kali-lab",
      "source_ip": "192.168.56.30",
      "host": "detection",
      "user": "fakeuser",
      "destination_port": 22,
      "protocol": "ssh",
      "raw": {
        "username_history": ["fakeuser"]
      }
    }]
  }'


DETECTION RESULT:

5 failed SSH authentication events
within 60 seconds
same source IP + host

        ↓

AUTH-004

        ↓

HIGH

        ↓

T1110 — Brute Force

        ↓

Incident



============================================================
SCENARIO 2 — PORT SCANNING
============================================================

GOAL:
Kali performs a real Nmap scan.
Network collector observes the connections.
Collector converts them into NETWORK_CONNECTION events.
Detection Engine detects NETWORK-001.

FLOW:

Kali
 ↓
Nmap
 ↓
Ubuntu network interface
 ↓
Network Collector
 ↓
NETWORK_CONNECTION events
 ↓
Detection Engine
 ↓
NETWORK-001
 ↓
MEDIUM
 ↓
MITRE T1046
 ↓
Incident


STEP 1 — Run Nmap from Kali

nmap -p 1-30 192.168.56.10


STEP 2 — Optional packet verification on Ubuntu

sudo tcpdump -ni ens37 \
  'tcp and host 192.168.56.30' \
  -c 40


You should see packets similar to:

192.168.56.30.xxxxx > 192.168.56.10.1: Flags [S]

192.168.56.30.xxxxx > 192.168.56.10.2: Flags [S]

etc.


STEP 3 — COLLECTOR REQUIREMENT

For each observed connection, generate:

event_type:
NETWORK_CONNECTION

source:
network-sensor

sensor:
<collector-id>

source_ip:
192.168.56.30

destination_ip:
192.168.56.10

destination_port:
<scanned-port>

protocol:
tcp


Example:

{
  "event_type": "NETWORK_CONNECTION",
  "timestamp": "2026-09-15T12:00:00Z",
  "source": "network-sensor",
  "sensor": "kali-lab",
  "source_ip": "192.168.56.30",
  "destination_ip": "192.168.56.10",
  "destination_port": 22,
  "protocol": "tcp"
}


STEP 4 — SEND EACH EVENT TO:

POST http://192.168.56.10:8000/api/v1/ingest/events

using:

X-API-Key: YOUR_API_KEY


DETECTION RESULT:

15 distinct destination ports
within 60 seconds
same source + destination IP

        ↓

NETWORK-001

        ↓

MEDIUM

        ↓

T1046 — Network Service Scanning

        ↓

Incident



============================================================
SCENARIO 3 — LARGE OUTBOUND TRANSFER
============================================================

GOAL:
Generate a REAL 600 MB transfer inside the lab.

Ubuntu:
192.168.56.10

Kali:
192.168.56.30

Direction:

Ubuntu
   ↓
600 MB
   ↓
Kali


FLOW:

Ubuntu
 ↓
600 MB HTTP transfer
 ↓
Network/flow collector
 ↓
NETWORK_CONNECTION
 + bytes_out
 ↓
Detection Engine
 ↓
EXFIL-001
 ↓
Severity/TI
 ↓
Incident


STEP 1 — Create 600 MB test file on Kali

On Kali:

cd /tmp

dd if=/dev/zero \
  of=/tmp/aire-test-600MB.bin \
  bs=1M count=600


STEP 2 — Start HTTP server on Kali

python3 -m http.server 8080 \
  --bind 192.168.56.30

KEEP THIS TERMINAL RUNNING.


STEP 3 — Download from Ubuntu

On Ubuntu:

curl -o /tmp/aire-test-600MB-from-kali.bin \
  http://192.168.56.30:8080/aire-test-600MB.bin


Expected:

100 600.0M


Kali's HTTP server should show:

192.168.56.10 - - "GET /aire-test-600MB.bin HTTP/1.1" 200 -


STEP 4 — Optional live packet capture

On Ubuntu:

sudo tcpdump -ni ens37 \
  'host 192.168.56.30'


This proves the transfer is actually occurring between the VMs.


STEP 5 — COLLECTOR REQUIREMENT

The collector must measure the network flow and create a
NETWORK_CONNECTION event containing the outbound byte count.

Required information:

event_type:
NETWORK_CONNECTION

source_ip:
192.168.56.10

destination_ip:
192.168.56.30

destination_port:
8080

protocol:
tcp

bytes_out:
>= 500 MB


For 600 MiB:

bytes_out = 629145600


The exact placement of bytes_out MUST match the actual
NormalizedEvent model in:

aire_detection/models.py


Do NOT invent a new field if the model already defines the
network byte field elsewhere.


Example information:

{
  "event_type": "NETWORK_CONNECTION",
  "source": "network-sensor",
  "sensor": "kali-lab",
  "source_ip": "192.168.56.10",
  "destination_ip": "192.168.56.30",
  "destination_port": 8080,
  "protocol": "tcp",
  "bytes_out": 629145600
}


STEP 6 — SEND TO:

POST http://192.168.56.10:8000/api/v1/ingest/events

with:

X-API-Key: YOUR_API_KEY


DETECTION RESULT:

Large outbound transfer
+
required telemetry
+
TI enrichment where applicable

        ↓

EXFIL-001

        ↓

Severity Classification

        ↓

Incident


IMPORTANT:

203.0.113.13 is a documentation/test IOC used by the existing
controlled TI tests.

DO NOT describe it as a real malicious Internet server.

DO NOT connect to real malicious infrastructure.


============================================================
FINAL VALIDATION
============================================================

After the collector is implemented, all three should follow:

REAL LAB ACTIVITY
        ↓
COLLECTOR
        ↓
NORMALIZED EVENT
        ↓
DETECTION ENGINE API
        ↓
DETECTION / CORRELATION
        ↓
MITRE
        ↓
THREAT INTELLIGENCE
        ↓
SEVERITY
        ↓
INCIDENT


EXPECTED RESULTS:

SCENARIO 1
AUTH-004
SSH Brute Force
HIGH
T1110


SCENARIO 2
NETWORK-001
Port Scanning
MEDIUM
T1046


SCENARIO 3
EXFIL-001
Large Outbound Transfer
HIGH base severity
with final severity determined by the existing severity/TI pipeline


============================================================
RESPONSIBILITY SPLIT
============================================================

COLLECTOR:
✓ Read logs
✓ Capture/receive network telemetry
✓ Parse raw data
✓ Normalize
✓ Send NormalizedEvent to API

DETECTION ENGINE:
✓ Detection rules
✓ Correlation
✓ MITRE mapping
✓ Threat intelligence
✓ Severity
✓ Incident generation

RESPONSE ENGINE:
✓ Response actions


DO NOT duplicate Detection Engine logic inside the collector.
============================================================