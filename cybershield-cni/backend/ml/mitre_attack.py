"""
CyberShield CNI - MITRE ATT&CK mapping (Agent 3.2: APT Campaign Attribution & Prediction Agent)

This is a simplified local lookup table standing in for the full RAG knowledge base
(MITRE ATT&CK Enterprise + ICS matrices + CERT-In advisories) described in the design doc.
Maps observed event patterns to the most likely ATT&CK technique, a kill-chain phase,
and a rule-confidence score reflecting how strong the behavioural evidence is.
"""

# Enterprise + ICS techniques relevant to the scenario walkthroughs in the doc,
# plus a few extra techniques so the frequency chart / attribution feel less canned.
TECHNIQUE_LIBRARY = {
    "credential_lateral_move": {
        "id": "T1021",
        "name": "Remote Services (Lateral Movement)",
        "matrix": "Enterprise",
        "kill_chain_phase": "Lateral Movement",
        "mitigation": "Restrict remote service usage, enforce MFA, monitor for atypical account activity.",
    },
    "privilege_escalation": {
        "id": "T1078",
        "name": "Valid Accounts",
        "matrix": "Enterprise",
        "kill_chain_phase": "Privilege Escalation",
        "mitigation": "Rotate credentials, enforce least privilege, audit new admin account creation.",
    },
    "ransomware_staging": {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "matrix": "Enterprise",
        "kill_chain_phase": "Impact",
        "mitigation": "Isolate affected hosts, verify immutable backups, activate incident response plan.",
    },
    "ot_protocol_probe": {
        "id": "T0846",
        "name": "Remote System Discovery (ICS)",
        "matrix": "ICS",
        "kill_chain_phase": "Discovery",
        "mitigation": "Segment OT network, alert OT security team, no automated response permitted.",
    },
    "ot_unauthorized_command": {
        "id": "T0855",
        "name": "Unauthorized Command Message (ICS)",
        "matrix": "ICS",
        "kill_chain_phase": "Impact",
        "mitigation": "Immediate human review; verify command against safe operating envelope.",
    },
    "bulk_exfiltration": {
        "id": "T1020",
        "name": "Automated Exfiltration",
        "matrix": "Enterprise",
        "kill_chain_phase": "Exfiltration",
        "mitigation": "Suspend account, block destination, review DLP rules and rate limits.",
    },
    "c2_beaconing": {
        "id": "T1071",
        "name": "Application Layer Protocol (C2)",
        "matrix": "Enterprise",
        "kill_chain_phase": "Command and Control",
        "mitigation": "Block destination IP/domain, capture PCAP for forensics, hunt for related hosts.",
    },
    "brute_force": {
        "id": "T1110",
        "name": "Brute Force",
        "matrix": "Enterprise",
        "kill_chain_phase": "Credential Access",
        "mitigation": "Enforce account lockout thresholds, enable MFA, alert on rapid failed-login bursts.",
    },
    "process_injection": {
        "id": "T1055",
        "name": "Process Injection",
        "matrix": "Enterprise",
        "kill_chain_phase": "Defense Evasion",
        "mitigation": "Enable EDR behavioural blocking, review process ancestry for the affected host.",
    },
    "ot_firmware_tamper": {
        "id": "T0857",
        "name": "System Firmware (ICS)",
        "matrix": "ICS",
        "kill_chain_phase": "Persistence",
        "mitigation": "Verify firmware signature/hash against golden image; do not auto-remediate OT devices.",
    },
    "benign": {
        "id": None,
        "name": "No technique matched",
        "matrix": None,
        "kill_chain_phase": None,
        "mitigation": None,
    },
}


def _result(key: str, confidence: float) -> dict:
    tech = dict(TECHNIQUE_LIBRARY[key])
    tech["confidence"] = round(confidence, 2)
    return tech


def map_event_to_technique(event: dict) -> dict:
    """
    Rule-based classifier standing in for the RAG-based attribution agent.
    In production this would query the vector store of ATT&CK + CERT-In + STIX/TAXII feeds
    described in section 3.2 of the design document. Each rule carries a confidence
    score reflecting how unambiguous the behavioural signature is.
    """
    zone = event.get("source_zone")
    event_type = event.get("event_type")
    bytes_transferred = event.get("bytes_transferred", 0)
    failed_logins = event.get("failed_logins", 0)
    dest_reputation = event.get("dest_reputation", 0)
    login_hour = event.get("login_hour", 12)
    process_count = event.get("process_count", 0)

    if zone == "OT":
        if event_type == "firmware_update" and dest_reputation > 0.4:
            return _result("ot_firmware_tamper", 0.9)
        if event_type == "modbus_cmd" and dest_reputation > 0.5:
            return _result("ot_unauthorized_command", 0.92)
        if event_type in ("modbus_cmd", "iec61850_cmd", "dnp3_cmd") and dest_reputation > 0.3:
            return _result("ot_protocol_probe", 0.75)

    if event_type == "login" and failed_logins >= 6:
        return _result("brute_force", 0.85)

    if event_type == "login" and failed_logins >= 3 and login_hour not in range(8, 19):
        return _result("credential_lateral_move", 0.8)

    if event_type == "privilege_change":
        return _result("privilege_escalation", 0.85)

    if event_type == "file_encrypt_burst":
        return _result("ransomware_staging", 0.95)

    if event_type == "process_start" and process_count > 120:
        return _result("process_injection", 0.6)

    if event_type == "data_transfer" and bytes_transferred > 5_000_000 and dest_reputation > 0.3:
        return _result("bulk_exfiltration", 0.85)

    if event_type == "outbound_beacon" and dest_reputation > 0.5:
        return _result("c2_beaconing", 0.8)

    return _result("benign", 0.0)
