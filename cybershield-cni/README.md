# CyberShield CNI — Prototype Implementation (v2, hardened)

A runnable full-stack prototype of the **AI-Driven Cyber Resilience Platform for India's
Critical National Infrastructure**, based on the ET AI Hackathon 2026 (Problem Statement 7)
design document. It implements the five core agents and safety constraints described in
that document as working code, not just diagrams.

**v2 adds:** JWT authentication with role-based access control, a real-time WebSocket feed,
an ensemble anomaly model (IsolationForest + PCA-reconstruction, standing in for the
IsolationForest+LSTM ensemble in the design doc), an expanded MITRE ATT&CK library with
confidence scoring, stateful digital-twin containment simulation, a tamper-evident audit
log, CSV export, request rate limiting, and pagination/filtering across the API.

## What's implemented

| Design doc section | Code |
|---|---|
| 3.1 Behavioural Anomaly Detection Engine | `backend/ml/anomaly_detector.py` — ensemble of IsolationForest + PCA-reconstruction-error (autoencoder stand-in), trained on synthetic IT/OT baselines |
| 3.2 APT Attribution & Prediction Agent | `backend/ml/mitre_attack.py` — rule-based stand-in for the RAG/MITRE ATT&CK lookup, now with per-rule confidence + kill-chain phase |
| 3.3 Autonomous Incident Response Orchestrator | `backend/main.py` (`/api/alerts/{id}/respond`) — human-in-the-loop approval flow, now requiring an authenticated `ot_operator`/`admin` for OT actions |
| 3.4 Vulnerability Prioritisation Agent | `backend/ml/vuln_prioritizer.py` — CVSS + exposure + exploit + campaign-match weighted scoring, with a remediation-status workflow |
| 3.5 Cyber Resilience Digital Twin | `backend/ml/digital_twin.py` — graph model + BFS blast-radius simulation + stateful node isolation/containment simulation |
| 2.4 OT/ICS safety rules | Enforced in `main.py` + `auth.py`: OT alerts always route to `awaiting_authorization` and can only be approved by a role-checked, JWT-authenticated `ot_operator`/`admin` |
| Section 10.2 human-in-the-loop / RBAC | `backend/auth.py` — JWT auth, PBKDF2 password hashing, three roles (`soc_analyst`, `ot_operator`, `admin`), full audit trail in `audit_log` |
| Section 11 scenario walkthroughs | `backend/ml/data_generator.py` — `hospital_ransomware`, `substation_probe`, `bulk_exfiltration`, `brute_force`, `ot_firmware_tamper`, `c2_beaconing` generators, triggerable from the dashboard |

## Project structure

```
cybershield-cni/
├── backend/
│   ├── main.py                 # FastAPI app, REST + WebSocket endpoints, alert lifecycle, rate limiting
│   ├── auth.py                 # JWT auth, PBKDF2 password hashing, RBAC dependency
│   ├── database.py             # SQLite schema + connection helper + audit log
│   ├── ml/
│   │   ├── anomaly_detector.py # IsolationForest + PCA ensemble anomaly engine
│   │   ├── mitre_attack.py     # Event -> MITRE ATT&CK technique mapping (+ confidence)
│   │   ├── vuln_prioritizer.py # CVE risk scoring
│   │   ├── digital_twin.py     # Network topology graph + blast radius + isolation simulation
│   │   └── data_generator.py   # Synthetic IT/OT telemetry + attack scenarios
│   └── requirements.txt
├── frontend/
│   ├── index.html              # Login screen + SOC dashboard shell
│   ├── css/style.css            # Midnight navy + teal theme
│   └── js/app.js               # Auth flow, WebSocket live feed, filters, twin isolation UI
└── README.md
```

## Running it

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Then open **http://localhost:8000/** — the FastAPI app serves the dashboard directly
(no separate frontend server or build step needed). You'll land on a login screen first.

## Using the dashboard

- **▶ Normal Traffic** — generates benign IT/OT telemetry so you can see the
  baseline anomaly score stay low.
- **🏥 Hospital Ransomware** — replays scenario 11.1: a phished vendor account moves
  laterally at odd hours, then triggers an encryption burst.
- **⚡ Substation Probe** — replays scenario 11.2: OT protocol traffic (Modbus/IEC61850)
  against an RTU/PLC. Because it's OT, the alert always lands in `awaiting_authorization`
  and can only be approved by an authorized OT operator or administrator.
- **📤 Data Exfiltration** — replays scenario 11.3: bulk outbound transfer to a
  medium-reputation destination, mapped to `T1020 Automated Exfiltration`.
- **🔑 Brute Force**, **🛠 Firmware Tamper**, **📡 C2 Beaconing** — three additional
  scenarios exercising the newly-expanded MITRE technique library.

The dashboard also runs a live background telemetry feed (pushed over WebSocket every
few seconds) so it keeps updating even without clicking anything — a toast pops up
whenever a high/critical alert is raised.

Click any node in the **Digital Twin** panel to simulate blast radius from that entry
point. Authorized OT operators and administrators can also **segment (isolate)**
a node to simulate a containment control and immediately see the blast radius shrink.

Alerts can be **Approved** (moves to `contained`) or **Dismissed**. OT-zone alerts show
a locked "OT auth required" state to any account without the `ot_operator`/`admin` role —
enforced server-side, not just hidden in the UI.

Every response, containment action, and vulnerability status change is written to the
**Audit Log** panel with the authenticated operator's username and role.

## Notes on the prototype vs. the full design

This is a hackathon-scale prototype standing in for the full production design:

- The anomaly model trains on **synthetic** data generated at startup, not live CICIDS2017/
  UNSW-NB15 feeds or a real SIEM/OT span-port ingest pipeline.
- The PCA-reconstruction-error model is a lightweight, dependency-free stand-in for the
  LSTM autoencoder mentioned in the design doc — it captures the same "reconstruct what's
  normal, flag what doesn't fit" idea without requiring a deep-learning stack.
- The MITRE ATT&CK / CERT-In attribution agent is a **rule-based lookup table**, not the
  full RAG pipeline over ATT&CK + CERT-In advisories + STIX/TAXII feeds described in
  section 3.2.
- SQLite is used for simplicity; a production deployment would use a horizontally
  scalable store as described in section 10.1 (redundant ingestion/scoring services).
- Auth is a self-contained JWT implementation over an in-memory user directory — a real
  deployment should sit behind an enterprise IdP (SAML/OIDC) tied into PAM/PIM.
- Rate limiting is a simple in-memory sliding window per process; a horizontally-scaled
  deployment needs a shared store (e.g. Redis) for this to work across replicas.

## Extending it

- Swap `ml/data_generator.py` for a real packet/log ingestion adapter to move from
  synthetic to live data.
- Replace the PCA-reconstruction component in `ml/anomaly_detector.py` with a real
  LSTM/Transformer autoencoder for genuinely time-series-aware detection.
- Replace `ml/mitre_attack.py` with a vector-store lookup (e.g. embeddings over the
  ATT&CK technique corpus + CERT-In advisories) for real RAG-based attribution.
- Swap `auth.py`'s in-memory user directory for a real IdP (OIDC/SAML) and a persistent
  user/role table.
- Move the in-memory rate limiter and WebSocket connection manager to a shared backing
  store (e.g. Redis pub/sub) before running more than one backend replica.
