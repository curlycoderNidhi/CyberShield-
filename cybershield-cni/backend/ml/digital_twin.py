"""
CyberShield CNI - Cyber Resilience Digital Twin (section 3.5)

Graph-based model of a simplified IT/OT topology. Supports:
  - "blast radius" simulation: given a compromised entry node, what other
    nodes are reachable, and how many are critical.
  - stateful mitigation simulation: an operator can mark a node "isolated"
    (e.g. after a network segmentation control is applied) and blast-radius
    calculations will treat it as cut out of the graph, so the SOC can see
    the effect of a proposed containment action *before* committing to it.
"""

NODES = [
    {"id": "internet_gw", "label": "Internet Gateway", "zone": "IT", "criticality": "medium", "x": 60, "y": 260},
    {"id": "firewall", "label": "Perimeter Firewall", "zone": "IT", "criticality": "high", "x": 190, "y": 260},
    {"id": "vpn_gw", "label": "SSL-VPN Gateway", "zone": "IT", "criticality": "high", "x": 190, "y": 140},
    {"id": "dc", "label": "Domain Controller", "zone": "IT", "criticality": "critical", "x": 330, "y": 200},
    {"id": "hospital_erp", "label": "Hospital ERP", "zone": "IT", "criticality": "critical", "x": 460, "y": 100},
    {"id": "exam_portal", "label": "Exam Board Portal", "zone": "IT", "criticality": "high", "x": 460, "y": 220},
    {"id": "finance_srv", "label": "Financial Infra Server", "zone": "IT", "criticality": "critical", "x": 460, "y": 340},
    {"id": "ot_gateway", "label": "IT/OT Gateway (span port)", "zone": "OT", "criticality": "high", "x": 330, "y": 400},
    {"id": "scada_hist", "label": "SCADA Historian", "zone": "OT", "criticality": "critical", "x": 460, "y": 460},
    {"id": "rtu_04", "label": "RTU-04 (Substation 12)", "zone": "OT", "criticality": "critical", "x": 590, "y": 460},
    {"id": "plc_02", "label": "PLC-02 (Breaker Control)", "zone": "OT", "criticality": "critical", "x": 590, "y": 380},
]

EDGES = [
    ("internet_gw", "firewall"),
    ("firewall", "vpn_gw"),
    ("firewall", "dc"),
    ("dc", "hospital_erp"),
    ("dc", "exam_portal"),
    ("dc", "finance_srv"),
    ("dc", "ot_gateway"),
    ("ot_gateway", "scada_hist"),
    ("scada_hist", "rtu_04"),
    ("scada_hist", "plc_02"),
]

NODE_LOOKUP = {n["id"]: n for n in NODES}


def valid_node_ids() -> set:
    return set(NODE_LOOKUP.keys())


def get_graph(isolated_ids: set = frozenset()):
    return {
        "nodes": [
            {**n, "isolated": n["id"] in isolated_ids} for n in NODES
        ],
        "edges": [{"source": s, "target": t} for s, t in EDGES],
    }


def _adjacency(isolated_ids: set):
    """Build adjacency, excluding any edge touching an isolated node —
    an isolated node is treated as segmented off (can't propagate or be reached)."""
    adj = {}
    for s, t in EDGES:
        if s in isolated_ids or t in isolated_ids:
            continue
        adj.setdefault(s, []).append(t)
        adj.setdefault(t, []).append(s)
    return adj


def compute_blast_radius(entry_node_id: str, isolated_ids: set = frozenset()):
    """BFS reachability from a compromised entry point across the twin graph,
    honoring any currently-isolated (segmented) nodes as containment boundaries."""
    if entry_node_id not in NODE_LOOKUP:
        return None

    if entry_node_id in isolated_ids:
        # Entry point itself has already been segmented off — no propagation possible.
        affected = [NODE_LOOKUP[entry_node_id]]
        return {
            "entry_node": entry_node_id,
            "affected_nodes": affected,
            "total_affected": 1,
            "critical_assets_at_risk": 1 if NODE_LOOKUP[entry_node_id]["criticality"] == "critical" else 0,
            "isolated_nodes": sorted(isolated_ids),
            "contained": True,
        }

    adj = _adjacency(isolated_ids)
    visited = {entry_node_id}
    queue = [entry_node_id]
    while queue:
        cur = queue.pop(0)
        for nxt in adj.get(cur, []):
            if nxt not in visited:
                visited.add(nxt)
                queue.append(nxt)

    affected = [NODE_LOOKUP[n] for n in visited if n in NODE_LOOKUP]
    critical_count = sum(1 for n in affected if n["criticality"] == "critical")
    return {
        "entry_node": entry_node_id,
        "affected_nodes": affected,
        "total_affected": len(affected),
        "critical_assets_at_risk": critical_count,
        "isolated_nodes": sorted(isolated_ids),
        "contained": False,
    }


def unmitigated_blast_radius(entry_node_id: str):
    """Convenience: blast radius with no mitigations applied, for before/after comparison."""
    return compute_blast_radius(entry_node_id, isolated_ids=frozenset())
