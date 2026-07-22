"""
CyberShield CNI - Vulnerability Prioritisation Agent (section 3.4)

Maps a mock asset/CVE inventory to a live, risk-ranked remediation queue.
Risk score = weighted combination of CVSS base score, internet exposure,
known-exploit-in-the-wild status, and whether an active threat-actor campaign
targeting Indian CNI is known to use the CVE.
"""

MOCK_CVE_INVENTORY = [
    {"cve_id": "CVE-2024-3400", "asset": "Perimeter Firewall (Delhi DC)", "internet_facing": 1, "known_exploit": 1, "active_campaign_match": 1, "cvss_base": 10.0},
    {"cve_id": "CVE-2023-46604", "asset": "Hospital ERP Message Broker", "internet_facing": 1, "known_exploit": 1, "active_campaign_match": 1, "cvss_base": 9.8},
    {"cve_id": "CVE-2024-21762", "asset": "SSL-VPN Gateway (State Health Portal)", "internet_facing": 1, "known_exploit": 1, "active_campaign_match": 0, "cvss_base": 9.6},
    {"cve_id": "CVE-2022-36537", "asset": "Exam Board Portal Reporting Server", "internet_facing": 1, "known_exploit": 1, "active_campaign_match": 1, "cvss_base": 7.5},
    {"cve_id": "CVE-2023-34362", "asset": "File Transfer Appliance (Finance)", "internet_facing": 1, "known_exploit": 1, "active_campaign_match": 0, "cvss_base": 9.8},
    {"cve_id": "CVE-2021-44228", "asset": "Legacy SCADA Historian (Substation 12)", "internet_facing": 0, "known_exploit": 1, "active_campaign_match": 1, "cvss_base": 10.0},
    {"cve_id": "CVE-2024-27198", "asset": "Internal CI/CD Server", "internet_facing": 0, "known_exploit": 0, "active_campaign_match": 0, "cvss_base": 8.1},
    {"cve_id": "CVE-2020-1472", "asset": "Domain Controller (State DISCOM)", "internet_facing": 0, "known_exploit": 1, "active_campaign_match": 1, "cvss_base": 10.0},
]


def compute_risk_score(cve: dict) -> float:
    score = cve["cvss_base"] * 0.4
    score += cve["internet_facing"] * 2.5
    score += cve["known_exploit"] * 3.0
    score += cve["active_campaign_match"] * 4.0  # heaviest weight, per section 3.4
    return round(min(score, 20.0), 2)


def build_prioritized_queue():
    queue = []
    for cve in MOCK_CVE_INVENTORY:
        entry = dict(cve)
        entry["risk_score"] = compute_risk_score(cve)
        queue.append(entry)
    queue.sort(key=lambda x: x["risk_score"], reverse=True)
    return queue
