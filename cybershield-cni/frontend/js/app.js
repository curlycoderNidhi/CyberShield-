const API = ""; // same-origin; change to "http://localhost:8000" if serving frontend separately

const CRITICALITY_COLOR = {
  low: "#4ade80",
  medium: "#facc15",
  high: "#fb923c",
  critical: "#f87171",
};

let anomalyChart, mttdChart, mitreChart;
let session = null; // { access_token, username, full_name, role }
let ws = null;
let latestTwinGraph = null;
let refreshInFlight = false;
let refreshQueued = false;
let refreshTimer = null;
let dashboardPollTimer = null;

// ---------------------------------------------------------------------------
// Session / auth
// ---------------------------------------------------------------------------
function loadSession() {
  try {
    const raw = sessionStorage.getItem("cybershield_session");
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function saveSession(s) {
  session = s;
  sessionStorage.setItem("cybershield_session", JSON.stringify(s));
}

function clearSession() {
  session = null;
  sessionStorage.removeItem("cybershield_session");
}

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (session && session.access_token) {
    headers["Authorization"] = `Bearer ${session.access_token}`;
  }
  const res = await fetch(API + path, { ...opts, headers });
  if (res.status === 401) {
    clearSession();
    showLogin("Session expired — please sign in again.");
    throw new Error("401 Unauthorized");
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `API error ${res.status} on ${path}`);
  }
  return res.json();
}

function fmtTime(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString();
}

// ---------------------------------------------------------------------------
// Login / logout
// ---------------------------------------------------------------------------
function showLogin(message) {
  document.getElementById("loginScreen").hidden = false;
  document.getElementById("dashboardRoot").hidden = true;
  const err = document.getElementById("loginError");
  if (message) {
    err.textContent = message;
    err.hidden = false;
  } else {
    err.hidden = true;
  }
  if (ws) { try { ws.close(); } catch {} ws = null; }
}

function showDashboard() {
  document.getElementById("loginScreen").hidden = true;
  document.getElementById("dashboardRoot").hidden = false;
  document.getElementById("sessionName").textContent = session.full_name;
  document.getElementById("sessionRole").textContent = session.role.replace("_", " ");
  initDashboard();
}

async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById("loginUsername").value.trim();
  const password = document.getElementById("loginPassword").value;
  try {
    const res = await fetch(API + "/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.detail || "Login failed");
    saveSession(body);
    showDashboard();
  } catch (err) {
    document.getElementById("loginError").textContent = err.message;
    document.getElementById("loginError").hidden = false;
  }
}

function logout() {
  clearSession();
  location.reload();
}

// ---------------------------------------------------------------------------
// Toasts
// ---------------------------------------------------------------------------
function showToast(title, body, severity = "medium") {
  const container = document.getElementById("toastContainer");
  const el = document.createElement("div");
  el.className = `toast ${severity}`;
  el.innerHTML = `<b>${title}</b>${body}`;
  container.appendChild(el);
  setTimeout(() => el.remove(), 7000);
}

// ---------------------------------------------------------------------------
// WebSocket live feed
// ---------------------------------------------------------------------------
function connectWebSocket() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${proto}//${location.host}/ws/live`;
  ws = new WebSocket(url);

  ws.onopen = () => setLiveDot(true);
  ws.onclose = () => { setLiveDot(false); setTimeout(() => { if (session) connectWebSocket(); }, 3000); };
  ws.onerror = () => setLiveDot(false);

  ws.onmessage = (msg) => {
    const data = JSON.parse(msg.data);
    if (data.type === "telemetry") {
      const alert = data.payload.alert;
      if (alert && (alert.severity === "critical" || alert.severity === "high")) {
        showToast(
          `${alert.severity.toUpperCase()} alert raised`,
          `New ${alert.status.replace("_", " ")} alert — check the Active Alerts panel.`,
          alert.severity,
        );
      }
      scheduleRefresh();
    } else if (data.type === "alert_update") {
      scheduleRefresh();
    } else if (data.type === "twin_update") {
      renderDigitalTwin();
    }
  };
}

function setLiveDot(online) {
  const dot = document.getElementById("liveDot");
  if (!dot) return;
  dot.classList.toggle("offline", !online);
  dot.title = online ? "Live feed connected" : "Live feed disconnected — retrying…";
}

// ---------------------------------------------------------------------------
// KPI cards
// ---------------------------------------------------------------------------
async function refreshSummary() {
  const s = await api("/api/dashboard/summary");
  const kpiRow = document.getElementById("kpiRow");
  kpiRow.innerHTML = `
    <div class="kpi-card"><div class="label">Total Events</div><div class="value">${s.total_events}</div></div>
    <div class="kpi-card"><div class="label">Anomalies Detected</div><div class="value">${s.total_anomalies}</div></div>
    <div class="kpi-card"><div class="label">Open Alerts</div><div class="value">${s.open_alerts}</div></div>
    <div class="kpi-card critical"><div class="label">Critical Alerts</div><div class="value">${s.critical_alerts}</div></div>
    <div class="kpi-card"><div class="label">Contained Incidents</div><div class="value">${s.contained_incidents}</div></div>
  `;

  if (!mttdChart) {
    mttdChart = new Chart(document.getElementById("mttdChart"), {
      type: "bar",
      data: {
        labels: ["Traditional SOC", "CyberShield CNI"],
        datasets: [{
          label: "Mean Time to Detect",
          data: [s.mttd_comparison.traditional_soc_hours * 60, s.mttd_comparison.cybershield_cni_minutes],
          backgroundColor: ["#f87171", "#2dd4bf"],
        }],
      },
      options: {
        indexAxis: "y",
        plugins: { legend: { display: false }, tooltip: { callbacks: {
          label: (ctx) => `${ctx.raw} minutes`
        } } },
        scales: {
          x: { title: { display: true, text: "Minutes to Detect (log-ish scale)", color: "#8b9bb4" }, ticks: { color: "#8b9bb4" }, grid: { color: "#223252" } },
          y: { ticks: { color: "#e6edf5" }, grid: { display: false } },
        },
      },
    });
  }
}

// ---------------------------------------------------------------------------
// Alerts table
// ---------------------------------------------------------------------------
function canApproveAlert(alert) {
  if (!alert.requires_human_auth) return true; // any authenticated user can act on IT alerts
  return session.role === "ot_operator" || session.role === "admin";
}

async function refreshAlerts() {
  const status = document.getElementById("alertStatusFilter").value;
  const severity = document.getElementById("alertSeverityFilter").value;
  const qs = new URLSearchParams();
  if (status) qs.set("status", status);
  if (severity) qs.set("severity", severity);
  const alerts = await api(`/api/alerts?${qs.toString()}`);
  document.getElementById("alertCountPill").textContent = alerts.length;
  const tbody = document.querySelector("#alertsTable tbody");
  tbody.innerHTML = alerts.map(a => {
    const finished = a.status === "contained" || a.status === "dismissed";
    const allowed = canApproveAlert(a);
    let actionCell;
    if (finished) {
      actionCell = "—";
    } else if (!allowed) {
      actionCell = `<span class="action-btn locked" title="Requires OT Operator or Admin role">🔒 OT auth required</span>`;
    } else {
      actionCell = `
        <button class="action-btn approve" onclick="respondAlert(${a.id}, 'approve')">Approve</button>
        <button class="action-btn dismiss" onclick="respondAlert(${a.id}, 'dismiss')">Dismiss</button>
      `;
    }
    return `
      <tr>
        <td class="sev-${a.severity}">${a.severity.toUpperCase()}</td>
        <td>${a.title}<span class="alert-narrative">${a.narrative || ""}</span></td>
        <td>${a.mitre_technique_id ? `${a.mitre_technique_id}` : "—"}</td>
        <td>${a.zone}</td>
        <td class="status-${a.status}">${a.status.replace("_", " ")}</td>
        <td>${actionCell}</td>
      </tr>
    `;
  }).join("") || `<tr><td colspan="6" style="color:var(--text-muted);">No alerts match this filter.</td></tr>`;
}

async function respondAlert(id, action) {
  try {
    await api(`/api/alerts/${id}/respond`, {
      method: "POST",
      body: JSON.stringify({ action }),
    });
    refreshAlerts();
    refreshSummary();
    refreshAuditLog();
  } catch (err) {
    showToast("Action denied", err.message, "critical");
  }
}

// ---------------------------------------------------------------------------
// Vulnerability queue
// ---------------------------------------------------------------------------
async function refreshVulns() {
  const vulns = await api("/api/vulnerabilities");
  const tbody = document.querySelector("#vulnTable tbody");
  tbody.innerHTML = vulns.map(v => `
    <tr>
      <td>${v.cve_id}</td>
      <td>${v.asset}</td>
      <td><b style="color:${v.risk_score > 15 ? '#f87171' : v.risk_score > 10 ? '#fb923c' : '#4ade80'}">${v.risk_score}</b></td>
      <td>${v.known_exploit ? "Yes" : "No"}</td>
      <td>${v.active_campaign_match ? "⚠ Yes" : "No"}</td>
      <td>
        <select onchange="updateVulnStatus(${v.id}, this.value)" ${v.status === "remediated" ? "class='remediated'" : ""}>
          ${["open", "in_progress", "remediated", "accepted_risk"].map(s =>
            `<option value="${s}" ${v.status === s ? "selected" : ""}>${s.replace("_", " ")}</option>`
          ).join("")}
        </select>
      </td>
    </tr>
  `).join("");
}

async function updateVulnStatus(vulnId, status) {
  try {
    await api(`/api/vulnerabilities/${vulnId}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    });
    showToast("Vulnerability updated", `Status set to "${status.replace("_", " ")}".`, "low");
    refreshAuditLog();
  } catch (err) {
    showToast("Update failed", err.message, "critical");
    refreshVulns();
  }
}

// ---------------------------------------------------------------------------
// MITRE ATT&CK chart
// ---------------------------------------------------------------------------
async function refreshMitre() {
  const data = await api("/api/mitre/summary");
  const labels = data.map(d => `${d.mitre_technique_id}`);
  const counts = data.map(d => d.count);

  if (!mitreChart) {
    mitreChart = new Chart(document.getElementById("mitreChart"), {
      type: "bar",
      data: { labels, datasets: [{ label: "Occurrences", data: counts, backgroundColor: "#2dd4bf" }] },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: "#8b9bb4" }, grid: { display: false } },
          y: { ticks: { color: "#8b9bb4" }, grid: { color: "#223252" }, beginAtZero: true },
        },
      },
    });
  } else {
    mitreChart.data.labels = labels;
    mitreChart.data.datasets[0].data = counts;
    mitreChart.update();
  }
}

// ---------------------------------------------------------------------------
// Recent events + anomaly score line chart
// ---------------------------------------------------------------------------
let eventsDebounceTimer = null;
function debouncedRefreshEvents() {
  clearTimeout(eventsDebounceTimer);
  eventsDebounceTimer = setTimeout(refreshEvents, 300);
}

async function refreshEvents() {
  const zone = document.getElementById("eventZoneFilter").value;
  const entity = document.getElementById("eventEntityFilter").value.trim();
  const qs = new URLSearchParams({ limit: "40" });
  if (zone) qs.set("zone", zone);
  if (entity) qs.set("entity_id", entity);
  const resp = await api(`/api/events/recent?${qs.toString()}`);
  // Newer API versions return a paginated object; older running instances
  // returned the array directly. Supporting both prevents a stale browser
  // cache or a rolling server update from breaking the dashboard.
  const events = Array.isArray(resp) ? resp : (Array.isArray(resp.items) ? resp.items : []);
  const tbody = document.querySelector("#eventsTable tbody");
  tbody.innerHTML = events.map(e => `
    <tr>
      <td>${fmtTime(e.timestamp)}</td>
      <td>${e.source_zone}</td>
      <td>${e.entity_id}</td>
      <td>${e.event_type}</td>
      <td style="color:${e.is_anomaly ? '#f87171' : '#4ade80'}">${e.anomaly_score.toFixed(3)}</td>
    </tr>
  `).join("") || `<tr><td colspan="5" style="color:var(--text-muted);">No events match this filter.</td></tr>`;

  const ordered = [...events].reverse();
  const labels = ordered.map(e => fmtTime(e.timestamp));
  const scores = ordered.map(e => e.anomaly_score);

  if (!anomalyChart) {
    anomalyChart = new Chart(document.getElementById("anomalyChart"), {
      type: "line",
      data: {
        labels,
        datasets: [{
          label: "Anomaly Score",
          data: scores,
          borderColor: "#2dd4bf",
          backgroundColor: "rgba(45,212,191,0.15)",
          tension: 0.3,
          fill: true,
          pointRadius: 2,
        }],
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: "#8b9bb4", maxTicksLimit: 8 }, grid: { display: false } },
          y: { min: 0, max: 1, ticks: { color: "#8b9bb4" }, grid: { color: "#223252" } },
        },
      },
    });
  } else {
    anomalyChart.data.labels = labels;
    anomalyChart.data.datasets[0].data = scores;
    anomalyChart.update();
  }
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------
async function refreshAuditLog() {
  try {
    const rows = await api("/api/audit-log?limit=30");
    const tbody = document.querySelector("#auditTable tbody");
    tbody.innerHTML = rows.map(r => `
      <tr>
        <td>${fmtTime(r.timestamp)}</td>
        <td>${r.actor}</td>
        <td>${r.role.replace("_", " ")}</td>
        <td>${r.action.replace("_", " ")}</td>
        <td>${r.target || "—"}</td>
        <td>${r.detail || "—"}</td>
      </tr>
    `).join("") || `<tr><td colspan="6" style="color:var(--text-muted);">No audit events yet.</td></tr>`;
  } catch {
    // audit log requires auth; silently skip if unavailable
  }
}

// ---------------------------------------------------------------------------
// Digital twin graph (rendered as raw SVG)
// ---------------------------------------------------------------------------
async function renderDigitalTwin() {
  const graph = await api("/api/digital-twin");
  latestTwinGraph = graph;
  const svg = document.getElementById("twinSvg");
  svg.innerHTML = "";

  const nodeById = Object.fromEntries(graph.nodes.map(n => [n.id, n]));

  graph.edges.forEach(e => {
    const a = nodeById[e.source], b = nodeById[e.target];
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", a.x); line.setAttribute("y1", a.y);
    line.setAttribute("x2", b.x); line.setAttribute("y2", b.y);
    line.setAttribute("class", "twin-edge");
    svg.appendChild(line);
  });

  graph.nodes.forEach(n => {
    const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
    g.setAttribute("class", `twin-node${n.isolated ? " isolated" : ""}`);
    g.setAttribute("transform", `translate(${n.x},${n.y})`);
    g.onclick = () => showBlastRadius(n.id);

    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("r", n.zone === "OT" ? 10 : 9);
    circle.setAttribute("fill", CRITICALITY_COLOR[n.criticality] || "#5eead4");
    if (n.zone === "OT") circle.setAttribute("stroke-dasharray", "2,1");
    g.appendChild(circle);

    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("x", 14); text.setAttribute("y", 4);
    text.textContent = n.label + (n.isolated ? " (segmented)" : "");
    g.appendChild(text);

    svg.appendChild(g);
  });
}

async function showBlastRadius(nodeId) {
  const result = await api(`/api/digital-twin/blast-radius/${nodeId}`);
  const canIsolateManage = session.role === "ot_operator" || session.role === "admin";
  const node = latestTwinGraph.nodes.find(n => n.id === nodeId);
  const isolateLabel = node.isolated ? "Restore connectivity" : "Segment this node (simulate containment)";
  const el = document.getElementById("blastResult");
  el.innerHTML = `
    ${result.contained ? '<div class="contained-banner">✅ Entry point already segmented — blast radius fully contained.</div>' : ""}
    <b>Entry point:</b> ${nodeId} &nbsp;|&nbsp;
    <b>Total affected nodes:</b> ${result.total_affected} &nbsp;|&nbsp;
    <b>Critical assets at risk:</b> ${result.critical_assets_at_risk}
    <br/>Reachable: ${result.affected_nodes.map(n => n.label).join(", ")}
    <br/>
    <span class="isolate-toggle ${canIsolateManage ? "" : "disabled"}"
          onclick="${canIsolateManage ? `toggleIsolation('${nodeId}', ${!node.isolated})` : ""}"
          title="${canIsolateManage ? "" : "Requires OT Operator or Admin role"}">
      ${canIsolateManage ? isolateLabel : "🔒 Segmentation requires OT Operator or Admin role"}
    </span>
  `;
}

async function toggleIsolation(nodeId, isolate) {
  try {
    await api(`/api/digital-twin/isolate/${nodeId}`, {
      method: "POST",
      body: JSON.stringify({ isolate }),
    });
    showToast(
      isolate ? "Node segmented" : "Node restored",
      `${nodeId} ${isolate ? "isolated from" : "reconnected to"} the network graph.`,
      "low",
    );
    await renderDigitalTwin();
    await showBlastRadius(nodeId);
  } catch (err) {
    showToast("Action denied", err.message, "critical");
  }
}

// ---------------------------------------------------------------------------
// Scenario / telemetry generation trigger
// ---------------------------------------------------------------------------
async function generateTelemetry(scenario) {
  const qs = scenario ? `?count=6&scenario=${scenario}` : `?count=6`;
  await api(`/api/telemetry/generate${qs}`, { method: "POST" });
  await refreshAll();
}

async function refreshAll() {
  if (refreshInFlight) {
    refreshQueued = true;
    return;
  }
  refreshInFlight = true;
  try {
    await Promise.all([
      refreshSummary(),
      refreshAlerts(),
      refreshVulns(),
      refreshMitre(),
      refreshEvents(),
      refreshAuditLog(),
    ]);
  } finally {
    refreshInFlight = false;
    if (refreshQueued) {
      refreshQueued = false;
      scheduleRefresh();
    }
  }
}

function scheduleRefresh(delay = 750) {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => {
    refreshAll().catch((err) => console.warn("Dashboard refresh failed:", err.message));
  }, delay);
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
async function initDashboard() {
  if (dashboardPollTimer) clearInterval(dashboardPollTimer);
  connectWebSocket();
  await renderDigitalTwin();
  await refreshAll();
  // Polling remains as a fallback in case the websocket drops and hasn't reconnected yet.
  dashboardPollTimer = setInterval(() => {
    if (!ws || ws.readyState !== WebSocket.OPEN) scheduleRefresh();
  }, 8000);
}

(function init() {
  document.getElementById("loginForm").addEventListener("submit", handleLogin);
  session = loadSession();
  if (session) {
    showDashboard();
  } else {
    showLogin();
  }
})();
