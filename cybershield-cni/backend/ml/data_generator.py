"""
CyberShield CNI - Synthetic telemetry generator

Generates baseline "normal" IT/OT telemetry plus injectable attack patterns that
mirror the three scenario walkthroughs in the design document:
  11.1 Ransomware against a hospital network (lateral movement -> encryption)
  11.2 Intrusion into a power substation OT network (protocol probing)
  11.3 Bulk data exfiltration from an exam/financial portal (low-and-slow)

Standing in for real CICIDS2017/UNSW-NB15 + live SIEM/OT span-port feeds referenced
in section 4.1 of the design document.
"""
import random
import datetime
import numpy as np

ENTITIES_IT = [f"user_{i:03d}" for i in range(1, 40)] + [f"svc_acct_{i:02d}" for i in range(1, 10)]
ENTITIES_OT = [f"rtu_{i:02d}" for i in range(1, 12)] + [f"plc_{i:02d}" for i in range(1, 8)]

FEATURE_ORDER = ["bytes_transferred", "failed_logins", "login_hour", "process_count", "dest_reputation"]


def _now_iso(offset_seconds=0):
    return (datetime.datetime.utcnow() + datetime.timedelta(seconds=offset_seconds)).isoformat()


def generate_baseline_event(zone="IT"):
    """A normal, benign event used both for training the anomaly model and for the live feed."""
    if zone == "IT":
        entity = random.choice(ENTITIES_IT)
        event_type = random.choice(["login", "file_read", "data_transfer", "process_start"])
        return {
            "timestamp": _now_iso(),
            "source_zone": "IT",
            "entity_id": entity,
            "event_type": event_type,
            "bytes_transferred": max(0, np.random.normal(50_000, 20_000)),
            "failed_logins": np.random.poisson(0.1),
            "login_hour": int(np.clip(np.random.normal(13, 3), 0, 23)),
            "process_count": int(np.clip(np.random.normal(40, 8), 5, 200)),
            "protocol": random.choice(["HTTPS", "SMB", "RDP"]),
            "dest_reputation": float(np.clip(np.random.normal(0.05, 0.05), 0, 1)),
        }
    else:
        entity = random.choice(ENTITIES_OT)
        event_type = random.choice(["modbus_cmd", "iec61850_cmd", "dnp3_cmd", "status_poll", "firmware_update"])
        return {
            "timestamp": _now_iso(),
            "source_zone": "OT",
            "entity_id": entity,
            "event_type": event_type,
            "bytes_transferred": max(0, np.random.normal(2_000, 500)),
            "failed_logins": 0,
            "login_hour": int(np.clip(np.random.normal(13, 4), 0, 23)),
            "process_count": int(np.clip(np.random.normal(6, 2), 1, 20)),
            "protocol": random.choice(["Modbus", "IEC61850", "DNP3"]),
            "dest_reputation": float(np.clip(np.random.normal(0.03, 0.03), 0, 1)),
        }


def generate_scenario_event(scenario: str):
    """Injects one event matching a specific attack scenario from the design doc."""
    if scenario == "hospital_ransomware":
        entity = "svc_acct_03"  # phished vendor credential, per 11.1
        event_type = random.choice(["login", "privilege_change", "file_encrypt_burst"])
        return {
            "timestamp": _now_iso(),
            "source_zone": "IT",
            "entity_id": entity,
            "event_type": event_type,
            "bytes_transferred": max(0, np.random.normal(300_000, 50_000)),
            "failed_logins": random.randint(3, 8),
            "login_hour": random.choice([1, 2, 3, 23]),
            "process_count": int(np.random.normal(150, 20)),
            "protocol": "RDP",
            "dest_reputation": float(np.random.uniform(0.4, 0.7)),
        }
    if scenario == "substation_probe":
        entity = random.choice(["rtu_04", "plc_02"])
        return {
            "timestamp": _now_iso(),
            "source_zone": "OT",
            "entity_id": entity,
            "event_type": random.choice(["modbus_cmd", "iec61850_cmd"]),
            "bytes_transferred": max(0, np.random.normal(9_000, 1_000)),
            "failed_logins": 0,
            "login_hour": random.choice([2, 3, 4]),
            "process_count": int(np.random.normal(15, 3)),
            "protocol": random.choice(["Modbus", "IEC61850"]),
            "dest_reputation": float(np.random.uniform(0.5, 0.9)),
        }
    if scenario == "bulk_exfiltration":
        entity = "user_017"  # portal / exam-board style account, per 11.3
        return {
            "timestamp": _now_iso(),
            "source_zone": "IT",
            "entity_id": entity,
            "event_type": "data_transfer",
            "bytes_transferred": max(0, np.random.normal(8_000_000, 1_000_000)),
            "failed_logins": 0,
            "login_hour": int(np.random.uniform(0, 23)),
            "process_count": int(np.random.normal(30, 5)),
            "protocol": "HTTPS",
            "dest_reputation": float(np.random.uniform(0.4, 0.8)),
        }
    if scenario == "brute_force":
        entity = random.choice(ENTITIES_IT)
        return {
            "timestamp": _now_iso(),
            "source_zone": "IT",
            "entity_id": entity,
            "event_type": "login",
            "bytes_transferred": max(0, np.random.normal(5_000, 1_000)),
            "failed_logins": random.randint(6, 15),
            "login_hour": int(np.random.uniform(0, 23)),
            "process_count": int(np.random.normal(20, 5)),
            "protocol": "RDP",
            "dest_reputation": float(np.random.uniform(0.1, 0.4)),
        }
    if scenario == "ot_firmware_tamper":
        entity = random.choice(["rtu_04", "plc_02"])
        return {
            "timestamp": _now_iso(),
            "source_zone": "OT",
            "entity_id": entity,
            "event_type": "firmware_update",
            "bytes_transferred": max(0, np.random.normal(40_000, 5_000)),
            "failed_logins": 0,
            "login_hour": random.choice([1, 2, 3]),
            "process_count": int(np.random.normal(8, 2)),
            "protocol": "Modbus",
            "dest_reputation": float(np.random.uniform(0.5, 0.9)),
        }
    if scenario == "c2_beaconing":
        entity = random.choice(ENTITIES_IT)
        return {
            "timestamp": _now_iso(),
            "source_zone": "IT",
            "entity_id": entity,
            "event_type": "outbound_beacon",
            "bytes_transferred": max(0, np.random.normal(15_000, 3_000)),
            "failed_logins": 0,
            "login_hour": int(np.random.uniform(0, 23)),
            "process_count": int(np.random.normal(45, 8)),
            "protocol": "HTTPS",
            "dest_reputation": float(np.random.uniform(0.5, 0.85)),
        }
    raise ValueError(f"Unknown scenario: {scenario}")


def generate_training_matrix(n=800):
    """Baseline-only matrix used to fit the IsolationForest (Agent 3.1)."""
    rows = []
    for _ in range(n):
        zone = "IT" if random.random() < 0.7 else "OT"
        e = generate_baseline_event(zone)
        rows.append([e[f] for f in FEATURE_ORDER])
    return np.array(rows)


def event_to_features(event: dict):
    return np.array([[event[f] for f in FEATURE_ORDER]])
