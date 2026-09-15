# Lab Deployment & Scenario Demonstrations

This document covers (1) the three supported lab network topologies and (2)
exact, repeatable procedures for the three mandatory detection scenarios.

**Safety notice:** every command below targets only systems you own and have
explicitly designated as lab machines (localhost, a VM you control, or a
second machine on a network you administer). Nothing here should ever be
pointed at a third party or public infrastructure.

---

## 1. Network visibility — read this first

A sensor can only detect what it can actually observe. Being on the same
Wi-Fi/Ethernet segment as a target does **not** automatically mean a collector
can sniff that target's traffic (switched networks isolate unicast traffic
by design; even Wi-Fi client isolation is common on modern APs). This project
does **not** assume promiscuous packet visibility. Instead:

- For **network-layer detections** (port scan, brute force over the wire),
  the sensor/collector must run *on the path* traffic actually takes: on the
  target host itself (e.g. a Zeek/Suricata instance monitoring the target's
  own interface), on a monitored service the target connects through, or on a
  switch SPAN/mirror port you control.
- For **endpoint-layer detections** (Sysmon process creation, registry, file
  events), the sensor runs *inside* the VM/host whose OS telemetry is being
  detected — it does not need network visibility into that host from outside.

---

## 2. Mode 1 — Same Ethernet/Wi-Fi (two physical machines)

```
PC-A (Detection Engine)              PC-B (controlled test machine)
     │                                        │
     └──────── same L2 segment ───────────────┘
                     │
        Sensor runs ON PC-B (or on PC-A if PC-B's
        traffic is actually routed/mirrored through PC-A)
                     │
              Normalized JSON events
                     │
                     ▼
        PC-A: Detection Engine ingestion API (port 8000)
```

**Setup:**

1. On **PC-A**, start the ingestion API:
   ```bash
   export AIRE_SENSOR_KEYS="pc-b-collector:$(openssl rand -hex 24)"
   uvicorn aire_detection.ingestion.api:create_app --factory --host 0.0.0.0 --port 8000
   ```
   Note PC-A's LAN IP (`ip addr` / `ipconfig`), e.g. `10.0.0.5`.

2. On **PC-B**, run a small collector (SSH auth log tailer, or a Zeek/Suricata
   instance monitoring PC-B's own interface) that POSTs normalized events to
   `http://10.0.0.5:8000/api/v1/ingest/events` with the sensor API key from
   step 1. A minimal example collector for SSH auth failures:

   ```bash
   # PC-B: tail sshd auth failures and forward them
   tail -F /var/log/auth.log | grep --line-buffered "Failed password" | while read -r line; do
     ip=$(echo "$line" | grep -oP '(?<=from )[\d.]+')
     user=$(echo "$line" | grep -oP '(?<=for )\S+')
     curl -s -X POST http://10.0.0.5:8000/api/v1/ingest/events \
       -H "Content-Type: application/json" -H "X-API-Key: <key-from-step-1>" \
       -d "{\"sensor_id\":\"pc-b-collector\",\"events\":[{
             \"event_type\":\"AUTHENTICATION_FAILURE\",
             \"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
             \"source\":\"sshd\",\"sensor\":\"pc-b-collector\",
             \"source_ip\":\"$ip\",\"host\":\"pc-b\",\"user\":\"$user\",
             \"destination_port\":22,\"protocol\":\"ssh\"}]}"
   done
   ```

This is the topology used for **Scenario 1 (SSH Brute Force)** below.

---

## 3. Mode 2 — Virtual Machine

```
Host PC
  ├── Detection Engine (ingestion API on host, port 8000)
  └── VM (VirtualBox/VMware/Hyper-V)
        └── Controlled test activity + sensor/collector
```

**VM networking mode guidance:**

| Mode | When to use |
|---|---|
| **NAT** | Endpoint detection only (Sysmon-style telemetry pushed *out* to the host's ingestion API over the NAT'd connection). The host cannot easily reach into the VM from outside NAT. |
| **Host-only** | Simplest for both endpoint and network detection in a fully isolated lab — host and VM share a private subnet, and the collector inside the VM can always reach the host's ingestion API. **Recommended default for this project.** |
| **Bridged** | Use when you specifically want the VM to appear as its own device on the physical LAN (e.g. to combine with Mode 1's same-network test using a VM instead of a second physical PC). |

**Setup (host-only, recommended):**

1. Configure the VM's network adapter as **Host-Only** (e.g. VirtualBox
   `vboxnet0`, typically `192.168.56.0/24`).
2. On the **host**, start the ingestion API bound to the host-only adapter's IP
   (or `0.0.0.0`):
   ```bash
   export AIRE_SENSOR_KEYS="vm-lab-collector:$(openssl rand -hex 24)"
   uvicorn aire_detection.ingestion.api:create_app --factory --host 0.0.0.0 --port 8000
   ```
3. Inside the **VM**, run Sysmon (Windows VM) or an auditd/process-tracking
   collector (Linux VM) and forward normalized `PROCESS_CREATE` events to the
   host's host-only IP, e.g. `http://192.168.56.1:8000/api/v1/ingest/events`.
4. For a network-detection test in this mode, run the port-scan source
   *inside* the VM against the host's host-only IP, so the traffic is
   observable by a sensor bound to that same host-only interface.

This is the topology used for **Scenario 2 (Port Scanning)** below.

---

## 4. Mode 3 — Two separate networks (advanced/documented)

```
PC-B (remote test machine, network 2)
      │
   Internet
      │
Sensor / monitored service (e.g. a cloud-hosted collector, or an
authenticated tunnel back to PC-A)
      │
Authenticated telemetry (TLS + API key)
      │
      ▼
PC-A (Detection Engine, network 1)
```

PC-A cannot assume it can observe arbitrary packets originating on PC-B's
private network. The only supported path is **authenticated telemetry
forwarding**: PC-B (or a sensor colocated with it) pushes normalized JSON
events to PC-A's ingestion API over the public Internet, secured with TLS
(terminated at a reverse proxy in front of the ingestion API — see
`docs/INTEGRATION.md` Section 2 for the auth model) and the same `X-API-Key`
mechanism used in Modes 1–2. This mode is documented as an advanced deployment
mode; live validation across two genuinely separate networks was not performed
in the development environment for this project, but the identical ingestion
API and auth path used in Modes 1–2 apply unchanged — only the network path
(public Internet + TLS reverse proxy) differs.

This is the topology conceptually used for **Scenario 3 (Malicious Outbound
Connection)** below, though the demonstration in this repository runs it
locally via the pipeline API directly (see Section 5.3) since it does not
require live network capture — it is driven by threat-intel enrichment of a
connection record, which can be generated locally or received via any of the
three modes above identically.

---

## 5. Three mandatory scenario demonstrations

Each scenario is also implemented as an automated end-to-end test
(`tests/test_e2e_*.py`) that runs the exact same pipeline code without
requiring live network capture or a live lab. The procedures below show how to
reproduce the same detection using the network topologies above, for a live
demo.

### 5.1 Scenario 1 — SSH Brute Force

1. **Test name:** SSH Brute Force Detection
2. **Purpose:** Demonstrate AUTH-004 firing on repeated failed SSH logins from one source.
3. **Lab topology:** Mode 1 (same Ethernet/Wi-Fi), two physical machines.
4. **Machine roles:** PC-A = Detection Engine; PC-B = controlled SSH client (attacker role).
5. **Sensor location:** On the SSH server host (could be PC-A itself running sshd, or a third lab VM); tails `/var/log/auth.log` and forwards to PC-A's ingestion API.
6. **Configuration:** `AUTH-004` default threshold = 5 attempts / 60 seconds.
7. **Exact command** (run from PC-B against a lab SSH server you control, e.g. PC-A itself with sshd enabled for the test):
   ```bash
   for i in $(seq 1 6); do
     ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
         wronguser@<lab-ssh-server-ip> exit
   done
   ```
8. **Expected telemetry:** 6 `AUTHENTICATION_FAILURE` events, `protocol="ssh"`, `destination_port=22`, same `source_ip`, same `host`.
9. **Expected rule:** `AUTH-004` (SSH Brute Force) fires once the 5th event lands within the 60s window.
10. **Expected severity:** `HIGH` at minimum; `CRITICAL` if the source IP is threat-intel-flagged.
11. **Expected MITRE technique:** `T1110` (Brute Force).
12. **Expected incident:** `Incident.rule_id == "AUTH-004"`, `source_ip` = PC-B's IP, `affected_host` = the SSH server's hostname, `correlated_event_ids` containing all 6 event IDs.
13. **Cleanup:** No persistent state on the SSH server (failed logins don't create accounts/files); restart the ingestion API process to clear in-memory correlation state if reusing the same lab session.

*(Automated equivalent: `tests/test_e2e_ssh_bruteforce.py`)*

### 5.2 Scenario 2 — Port Scanning

1. **Test name:** Port Scan Detection
2. **Purpose:** Demonstrate NETWORK-001 firing on a source probing many distinct ports on one destination.
3. **Lab topology:** Mode 2 (VM, host-only networking).
4. **Machine roles:** Host = Detection Engine + scan target service; VM = controlled scanner.
5. **Sensor location:** A Zeek instance (or equivalent conn-log collector) bound to the host-only interface on the **host**, observing inbound connections from the VM.
6. **Configuration:** `NETWORK-001` default threshold = 15 distinct ports / 60 seconds.
7. **Exact command** (run inside the VM, targeting the host's host-only IP only):
   ```bash
   nmap -p 1-100 --max-retries 0 -T4 192.168.56.1
   ```
8. **Expected telemetry:** ~20+ `NETWORK_CONNECTION` events (normalized from Zeek `conn.log`), same `source_ip` (VM), same `destination_ip` (host), many distinct `destination_port` values.
9. **Expected rule:** `NETWORK-001` (Port Scanning) fires once 15 distinct ports are observed within the 60s window.
10. **Expected severity:** `MEDIUM` baseline, elevated if the scanning source is threat-intel-flagged or the target asset is marked `critical`.
11. **Expected MITRE technique:** `T1046` (Network Service Discovery).
12. **Expected incident:** `Incident.rule_id == "NETWORK-001"`, `evidence.distinct_ports_contacted >= 15`.
13. **Cleanup:** No lasting state on either machine; the scan does not modify the target.

*(Automated equivalent: `tests/test_e2e_port_scan.py`)*

### 5.3 Scenario 3 — Malicious Outbound Connection

1. **Test name:** Malicious Outbound Connection Detection
2. **Purpose:** Demonstrate that a connection to a threat-intel-flagged IP is enriched and severity-escalated even when it wouldn't otherwise stand out.
3. **Lab topology:** Local pipeline invocation (no live network capture required — see Mode 3 discussion above for why this scenario is enrichment-driven rather than capture-driven) or Mode 1/2 with a controlled destination.
4. **Machine roles:** PC-A = Detection Engine running the enrichment pipeline; a lab host generates the outbound connection record.
5. **Sensor location:** A generic connection sensor (Zeek/NetFlow-style) producing a `NETWORK_CONNECTION` event with `bytes_out` and `destination_ip`.
6. **Configuration:** `EXFIL-001` default threshold = 500MB; for the mock demo, `MockVirusTotalProvider`/`MockAbuseIPDBProvider` denylist includes `198.51.100.66` and `203.0.113.13` (TEST-NET-2/3 documentation ranges, safe to use in a lab — never routable on the real Internet).
7. **Exact command** (Python, run against the local pipeline — no live traffic needed for the enrichment path itself):
   ```bash
   python3 - << 'PY'
   from aire_detection.pipeline import DetectionPipeline
   from aire_detection.enrichment.manager import EnrichmentManager
   from aire_detection.enrichment.virustotal import MockVirusTotalProvider
   from aire_detection.enrichment.abuseipdb import MockAbuseIPDBProvider
   from aire_detection.models import NormalizedEvent, EventType, utc_now

   pipeline = DetectionPipeline(enrichment_manager=EnrichmentManager(
       providers=[MockVirusTotalProvider(), MockAbuseIPDBProvider()]))
   event = NormalizedEvent(
       event_type=EventType.NETWORK_CONNECTION, timestamp=utc_now(),
       source="zeek", sensor="lab-sensor", host="workstation-07",
       source_ip="10.0.0.42", destination_ip="203.0.113.13",
       destination_port=443, bytes_out=600 * 1024 * 1024)
   for incident in pipeline.process_event(event):
       print(incident.rule_id, incident.severity.value, incident.enrichment)
   PY
   ```
   To exercise this against **live** VirusTotal/AbuseIPDB instead of mocks,
   set `VT_API_KEY`/`ABUSEIPDB_API_KEY` and use `VirusTotalProvider()`/
   `AbuseIPDBProvider()` in place of the Mock classes — direct the
   `destination_ip` at a real indicator you want to check the reputation of.
8. **Expected telemetry:** One `NETWORK_CONNECTION` event, `bytes_out >= 500MB`, `destination_ip` on the TI denylist (mock) or genuinely malicious (live).
9. **Expected rule:** `EXFIL-001` (Large Outbound Transfer).
10. **Expected severity:** `CRITICAL` (HIGH base + malicious enrichment boost).
11. **Expected MITRE technique:** `T1041` / `T1567` (Exfiltration).
12. **Expected incident:** `Incident.rule_id == "EXFIL-001"`, `enrichment` containing an entry with `is_malicious: true` and `mode: "MOCK/TEST"` (or `"REAL/LIVE"` if using real API keys).
13. **Cleanup:** None — no state is written outside the Detection Engine's own in-memory incident buffer.

*(Automated equivalent: `tests/test_e2e_malicious_ip.py`)*

---

## 6. Running the automated equivalents

All three scenarios (plus 179 other tests) run without any live lab, network
access, or API keys:

```bash
pip install -r requirements.txt
python3 -m pytest -q
# 182 passed
```
