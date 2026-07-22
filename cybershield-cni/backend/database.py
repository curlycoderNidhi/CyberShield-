"""
CyberShield CNI - Database layer
"""
import sqlite3
import json
import os
import threading

DB_PATH = os.path.join(os.path.dirname(__file__), "cybershield.db")
_lock = threading.Lock()


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(reset: bool = False):
    if reset and os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_zone TEXT NOT NULL,           -- IT / OT
        entity_id TEXT NOT NULL,             -- user / device / service account
        event_type TEXT NOT NULL,            -- login, file_read, modbus_cmd, data_transfer, etc.
        bytes_transferred REAL,
        failed_logins INTEGER,
        login_hour INTEGER,
        process_count INTEGER,
        protocol TEXT,
        dest_reputation REAL,                -- 0 = clean, 1 = known-bad
        anomaly_score REAL,
        is_anomaly INTEGER DEFAULT 0
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        event_id INTEGER,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,              -- low / medium / high / critical
        zone TEXT NOT NULL,                  -- IT / OT
        mitre_technique_id TEXT,
        mitre_technique_name TEXT,
        confidence REAL,
        status TEXT DEFAULT 'open',          -- open / awaiting_authorization / contained / dismissed
        requires_human_auth INTEGER DEFAULT 0,
        recommended_playbook TEXT,
        narrative TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        asset TEXT NOT NULL,
        internet_facing INTEGER,
        known_exploit INTEGER,
        active_campaign_match INTEGER,
        cvss_base REAL,
        risk_score REAL,
        status TEXT DEFAULT 'open'
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS twin_nodes (
        id TEXT PRIMARY KEY,
        label TEXT,
        zone TEXT,          -- IT / OT
        criticality TEXT,   -- low / medium / high / critical
        x REAL,
        y REAL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS twin_edges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT,
        target TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS twin_isolated_nodes (
        node_id TEXT PRIMARY KEY,
        isolated_by TEXT,
        isolated_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        actor TEXT NOT NULL,
        role TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT,
        detail TEXT
    )
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_zone ON events(source_zone)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_entity ON events(entity_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")

    conn.commit()
    conn.close()


def log_audit(actor: str, role: str, action: str, target: str = "", detail: str = ""):
    import datetime
    conn = get_conn()
    conn.execute(
        "INSERT INTO audit_log (timestamp, actor, role, action, target, detail) VALUES (?,?,?,?,?,?)",
        (datetime.datetime.utcnow().isoformat(), actor, role, action, target, detail),
    )
    conn.commit()
    conn.close()


def dict_from_row(row):
    return {k: row[k] for k in row.keys()} if row else None
