"""
CyberShield CNI - FastAPI Backend
AI-driven Cyber Resilience Platform for Critical National Infrastructure
ET AI Hackathon 2026 - Problem Statement 7

Run with:  uvicorn main:app --reload --port 8000
"""
import asyncio
import csv
import io
import random
import datetime
import time
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse, Response
from pydantic import BaseModel
import os

from database import init_db, get_conn, dict_from_row, log_audit
from ml.anomaly_detector import engine
from ml.mitre_attack import map_event_to_technique
from ml.data_generator import generate_baseline_event, generate_scenario_event
from ml.vuln_prioritizer import build_prioritized_queue
from ml.digital_twin import get_graph, compute_blast_radius, NODES, valid_node_ids
import auth

app = FastAPI(
    title="CyberShield CNI API",
    description="AI-driven Cyber Resilience Platform for India's Critical National Infrastructure",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SEVERITY_BY_CONFIDENCE = [
    (0.9, "critical"),
    (0.75, "high"),
    (0.55, "medium"),
    (0.0, "low"),
]

VALID_VULN_STATUSES = ("open", "in_progress", "remediated", "accepted_risk")

# In-memory state for isolated ("segmented off") digital twin nodes.
# Persisted to the twin_isolated_nodes table so it survives dashboard reloads
# within the same server process.
ISOLATED_NODES: set = set()


def severity_for(confidence: float) -> str:
    for threshold, label in SEVERITY_BY_CONFIDENCE:
        if confidence >= threshold:
            return label
    return "low"


def build_narrative(event: dict, technique: dict) -> str:
    if technique["id"] is None:
        return "Event scored within normal behavioural baseline; no action required."
    return (
        f"Entity '{event['entity_id']}' in the {event['source_zone']} zone triggered a deviation "
        f"consistent with {technique['name']} ({technique['id']}, {technique['kill_chain_phase']}). "
        f"Attribution confidence: {int(technique['confidence'] * 100)}%. "
        f"Recommended mitigation: {technique['mitigation']}"
    )


# ---------------------------------------------------------------------------
# Simple in-memory sliding-window rate limiter (per client IP)
# ---------------------------------------------------------------------------
RATE_LIMIT_WINDOW_SECONDS = 60
# The dashboard performs six parallel read requests on each refresh. Keep a
# sensible local-development ceiling while still protecting the API from bursts.
RATE_LIMIT_MAX_REQUESTS = 600
_rate_buckets: dict = {}


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    bucket = _rate_buckets.setdefault(client_ip, [])
    # drop timestamps outside the window
    while bucket and bucket[0] < now - RATE_LIMIT_WINDOW_SECONDS:
        bucket.pop(0)
    if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Slow down and try again shortly."},
        )
    bucket.append(now)
    return await call_next(request)


# ---------------------------------------------------------------------------
# WebSocket connection manager for real-time dashboard push
# ---------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


@app.websocket("/ws/live")
async def ws_live(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            # We don't expect inbound messages; just keep the socket open.
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
@app.on_event("startup")
def startup():
    init_db(reset=True)
    engine.train()
    _seed_twin()
    _seed_vulnerabilities()
    # seed a small initial batch of live-looking events so the dashboard isn't empty
    for _ in range(15):
        _ingest_event(generate_baseline_event(random.choice(["IT", "OT"])))


@app.on_event("startup")
async def start_background_feed():
    async def _loop():
        while True:
            await asyncio.sleep(5)
            try:
                event = generate_baseline_event(random.choice(["IT", "OT"]))
                result = _ingest_event(event)
                await manager.broadcast({"type": "telemetry", "payload": result})
            except Exception as e:
                # Never let the background feed crash the app
                print(f"[background_feed] error: {e}")

    asyncio.create_task(_loop())


def _seed_twin():
    conn = get_conn()
    cur = conn.cursor()
    for n in NODES:
        cur.execute(
            "INSERT OR REPLACE INTO twin_nodes (id, label, zone, criticality, x, y) VALUES (?,?,?,?,?,?)",
            (n["id"], n["label"], n["zone"], n["criticality"], n["x"], n["y"]),
        )
    conn.commit()
    conn.close()


def _seed_vulnerabilities():
    conn = get_conn()
    cur = conn.cursor()
    for v in build_prioritized_queue():
        cur.execute(
            """INSERT INTO vulnerabilities
               (cve_id, asset, internet_facing, known_exploit, active_campaign_match, cvss_base, risk_score)
               VALUES (?,?,?,?,?,?,?)""",
            (v["cve_id"], v["asset"], v["internet_facing"], v["known_exploit"],
             v["active_campaign_match"], v["cvss_base"], v["risk_score"]),
        )
    conn.commit()
    conn.close()


def _ingest_event(event: dict) -> dict:
    """Score an event, persist it, and raise an alert if warranted."""
    result = engine.score(event)
    technique = map_event_to_technique(event)

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO events
           (timestamp, source_zone, entity_id, event_type, bytes_transferred, failed_logins,
            login_hour, process_count, protocol, dest_reputation, anomaly_score, is_anomaly)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (event["timestamp"], event["source_zone"], event["entity_id"], event["event_type"],
         event["bytes_transferred"], event["failed_logins"], event["login_hour"],
         event["process_count"], event["protocol"], event["dest_reputation"],
         result["anomaly_score"], int(result["is_anomaly"])),
    )
    event_id = cur.lastrowid

    alert = None
    # Raise an alert if the ML ensemble flags it OR the rule-based ATT&CK mapper found a named technique
    if result["is_anomaly"] or technique["id"] is not None:
        confidence = max(result["anomaly_score"], technique["confidence"])
        severity = severity_for(confidence)
        requires_auth = event["source_zone"] == "OT"  # OT actions always need human sign-off, per section 2.4
        status = "awaiting_authorization" if requires_auth else "open"
        playbook = (
            "Isolate host + reset credential + notify SOC analyst"
            if event["source_zone"] == "IT"
            else "Alert OT security team only — no automated action (OT safety policy)"
        )
        narrative = build_narrative(event, technique)

        cur.execute(
            """INSERT INTO alerts
               (created_at, event_id, title, severity, zone, mitre_technique_id, mitre_technique_name,
                confidence, status, requires_human_auth, recommended_playbook, narrative)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (datetime.datetime.utcnow().isoformat(), event_id,
             f"{technique['name'] if technique['id'] else 'Behavioural anomaly'} — {event['entity_id']}",
             severity, event["source_zone"], technique["id"], technique["name"],
             round(confidence, 3), status, int(requires_auth), playbook, narrative),
        )
        alert = {"id": cur.lastrowid, "severity": severity, "status": status}

    conn.commit()
    conn.close()
    return {"event_id": event_id, "anomaly": result, "technique": technique, "alert": alert}


# ---------------------------------------------------------------------------
# API Schemas
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str


class RespondRequest(BaseModel):
    action: str  # "approve" | "dismiss"
    reason: Optional[str] = None


class VulnUpdateRequest(BaseModel):
    status: str  # one of VALID_VULN_STATUSES


class IsolateRequest(BaseModel):
    isolate: bool  # True = segment node off, False = restore connectivity


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.post("/api/auth/login")
def login(req: LoginRequest):
    user = auth.authenticate(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = auth.create_access_token(user["username"], user["role"])
    log_audit(user["username"], user["role"], "login", detail="Successful login")
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user["username"],
        "full_name": user["full_name"],
        "role": user["role"],
        "expires_in": auth.JWT_TTL_SECONDS,
    }


@app.get("/api/auth/me")
def me(user: dict = Depends(auth.get_current_user)):
    full = auth.USERS.get(user["username"], {})
    return {"username": user["username"], "role": user["role"], "full_name": full.get("full_name")}


# ---------------------------------------------------------------------------
# Core routes
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return {"status": "ok", "service": "CyberShield CNI", "version": "2.0.0"}


@app.post("/api/telemetry/generate")
def generate_telemetry(count: int = 5, scenario: Optional[str] = None):
    """
    Simulates a burst of incoming telemetry.
    Pass `scenario` = hospital_ransomware | substation_probe | bulk_exfiltration |
    brute_force | ot_firmware_tamper | c2_beaconing
    to replay one of the scenario walkthroughs.
    """
    count = max(1, min(count, 50))  # guardrail against accidental huge bursts
    results = []
    for _ in range(count):
        if scenario:
            event = generate_scenario_event(scenario)
        else:
            event = generate_baseline_event(random.choice(["IT", "OT"]))
        results.append(_ingest_event(event))
    return {"ingested": len(results), "results": results}


@app.get("/api/dashboard/summary")
def dashboard_summary():
    conn = get_conn()
    cur = conn.cursor()
    total_events = cur.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    total_anomalies = cur.execute("SELECT COUNT(*) c FROM events WHERE is_anomaly=1").fetchone()["c"]
    open_alerts = cur.execute("SELECT COUNT(*) c FROM alerts WHERE status IN ('open','awaiting_authorization')").fetchone()["c"]
    critical_alerts = cur.execute("SELECT COUNT(*) c FROM alerts WHERE severity='critical'").fetchone()["c"]
    contained = cur.execute("SELECT COUNT(*) c FROM alerts WHERE status='contained'").fetchone()["c"]
    conn.close()

    # MTTD comparison figure, referencing Figure 2 in the design doc (illustrative demo values)
    mttd = {"traditional_soc_hours": 197, "cybershield_cni_minutes": 12}

    return {
        "total_events": total_events,
        "total_anomalies": total_anomalies,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "contained_incidents": contained,
        "mttd_comparison": mttd,
    }


@app.get("/api/events/recent")
def recent_events(limit: int = 40, offset: int = 0, zone: Optional[str] = None,
                   entity_id: Optional[str] = None, event_type: Optional[str] = None):
    limit = max(1, min(limit, 200))
    conn = get_conn()
    query = "SELECT * FROM events"
    conditions, params = [], []
    if zone:
        conditions.append("source_zone = ?")
        params.append(zone)
    if entity_id:
        conditions.append("entity_id LIKE ?")
        params.append(f"%{entity_id}%")
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    rows = conn.execute(query, params).fetchall()
    total = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    conn.close()
    return {"total": total, "count": len(rows), "items": [dict_from_row(r) for r in rows]}


@app.get("/api/alerts")
def list_alerts(status: Optional[str] = None, severity: Optional[str] = None,
                 zone: Optional[str] = None, limit: int = 100, offset: int = 0):
    limit = max(1, min(limit, 200))
    conn = get_conn()
    query = "SELECT * FROM alerts"
    conditions, params = [], []
    if status:
        conditions.append("status = ?")
        params.append(status)
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if zone:
        conditions.append("zone = ?")
        params.append(zone)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict_from_row(r) for r in rows]


@app.post("/api/alerts/{alert_id}/respond")
async def respond_to_alert(alert_id: int, req: RespondRequest, user: dict = Depends(auth.get_current_user)):
    conn = get_conn()
    alert = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    if req.action not in ("approve", "dismiss"):
        conn.close()
        raise HTTPException(status_code=400, detail="action must be 'approve' or 'dismiss'")

    # OT alerts always require an authenticated human with the ot_operator/admin role — section 2.4 / 10.2.
    # This is enforced server-side and cannot be bypassed from the client.
    if alert["requires_human_auth"] and req.action == "approve" and user["role"] not in ("ot_operator", "admin"):
        conn.close()
        raise HTTPException(
            status_code=403,
            detail="OT containment requires authorization from an ot_operator or admin role",
        )

    new_status = "contained" if req.action == "approve" else "dismissed"
    conn.execute("UPDATE alerts SET status=? WHERE id=?", (new_status, alert_id))
    conn.commit()
    conn.close()

    log_audit(
        user["username"], user["role"], f"alert_{req.action}", target=f"alert:{alert_id}",
        detail=req.reason or "",
    )
    await manager.broadcast({
        "type": "alert_update",
        "payload": {"alert_id": alert_id, "new_status": new_status, "authorized_by": user["username"]},
    })
    return {"alert_id": alert_id, "new_status": new_status, "authorized_by": user["username"]}


@app.get("/api/mitre/summary")
def mitre_summary():
    conn = get_conn()
    rows = conn.execute(
        """SELECT mitre_technique_id, mitre_technique_name, COUNT(*) as count
           FROM alerts WHERE mitre_technique_id IS NOT NULL
           GROUP BY mitre_technique_id ORDER BY count DESC"""
    ).fetchall()
    conn.close()
    return [dict_from_row(r) for r in rows]


@app.get("/api/vulnerabilities")
def vulnerabilities():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM vulnerabilities ORDER BY risk_score DESC").fetchall()
    conn.close()
    return [dict_from_row(r) for r in rows]


@app.patch("/api/vulnerabilities/{vuln_id}")
def update_vulnerability(vuln_id: int, req: VulnUpdateRequest, user: dict = Depends(auth.get_current_user)):
    if req.status not in VALID_VULN_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {VALID_VULN_STATUSES}")
    conn = get_conn()
    existing = conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vuln_id,)).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    conn.execute("UPDATE vulnerabilities SET status=? WHERE id=?", (req.status, vuln_id))
    conn.commit()
    conn.close()
    log_audit(user["username"], user["role"], "vuln_status_update",
              target=f"vuln:{vuln_id}", detail=f"-> {req.status}")
    return {"vuln_id": vuln_id, "status": req.status}


# ---------------------------------------------------------------------------
# Digital twin
# ---------------------------------------------------------------------------
@app.get("/api/digital-twin")
def digital_twin():
    return get_graph(ISOLATED_NODES)


@app.get("/api/digital-twin/blast-radius/{node_id}")
def digital_twin_blast(node_id: str):
    if node_id not in valid_node_ids():
        raise HTTPException(status_code=404, detail="Unknown node id")
    return compute_blast_radius(node_id, ISOLATED_NODES)


@app.post("/api/digital-twin/isolate/{node_id}")
async def isolate_node(node_id: str, req: IsolateRequest, user: dict = Depends(auth.require_role(
    "ot_operator", "admin"))):
    """Simulate applying (or lifting) a network-segmentation control on a node.
    Restricted to ot_operator/admin since this models a real containment action
    that could affect OT connectivity."""
    if node_id not in valid_node_ids():
        raise HTTPException(status_code=404, detail="Unknown node id")

    conn = get_conn()
    if req.isolate:
        ISOLATED_NODES.add(node_id)
        conn.execute(
            "INSERT OR REPLACE INTO twin_isolated_nodes (node_id, isolated_by, isolated_at) VALUES (?,?,?)",
            (node_id, user["username"], datetime.datetime.utcnow().isoformat()),
        )
    else:
        ISOLATED_NODES.discard(node_id)
        conn.execute("DELETE FROM twin_isolated_nodes WHERE node_id=?", (node_id,))
    conn.commit()
    conn.close()

    log_audit(user["username"], user["role"], "twin_isolate" if req.isolate else "twin_restore",
              target=f"node:{node_id}")
    await manager.broadcast({"type": "twin_update", "payload": {"node_id": node_id, "isolated": req.isolate}})
    return {"node_id": node_id, "isolated": req.isolate, "isolated_nodes": sorted(ISOLATED_NODES)}


# ---------------------------------------------------------------------------
# Audit log (admin / soc_analyst visibility)
# ---------------------------------------------------------------------------
@app.get("/api/audit-log")
def audit_log(limit: int = 100, user: dict = Depends(auth.require_role("admin", "soc_analyst", "ot_operator"))):
    limit = max(1, min(limit, 500))
    conn = get_conn()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict_from_row(r) for r in rows]


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------
def _csv_response(rows: list, filename: str) -> StreamingResponse:
    buffer = io.StringIO()
    if rows:
        writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/api/export/alerts.csv")
def export_alerts_csv():
    conn = get_conn()
    rows = [dict_from_row(r) for r in conn.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()]
    conn.close()
    return _csv_response(rows, "cybershield_alerts.csv")


@app.get("/api/export/vulnerabilities.csv")
def export_vulnerabilities_csv():
    conn = get_conn()
    rows = [dict_from_row(r) for r in conn.execute("SELECT * FROM vulnerabilities ORDER BY risk_score DESC").fetchall()]
    conn.close()
    return _csv_response(rows, "cybershield_vulnerabilities.csv")


# ---------------------------------------------------------------------------
# Serve the frontend (static dashboard) at "/"
# ---------------------------------------------------------------------------
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon():
        return Response(status_code=204)

    @app.get("/")
    def root():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
