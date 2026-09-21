/*
  Sentinel IoT Threat Detection System
  Frontend JavaScript Logic
*/

let threatChartInstance = null;
let autoRefreshTimer = null;

document.addEventListener("DOMContentLoaded", () => {
  initChart();
  fetchDashboardData();
  renderRulesList();
  startAutoRefresh();
});

// Tab Switching
function switchTab(tabId) {
  document.querySelectorAll(".tab-content").forEach(el => el.classList.remove("active"));
  document.querySelectorAll(".nav-tab").forEach(el => el.classList.remove("active"));
  
  const targetTab = document.getElementById(tabId);
  if (targetTab) targetTab.classList.add("active");

  const activeBtn = Array.from(document.querySelectorAll(".nav-tab")).find(b => b.getAttribute("onclick")?.includes(tabId));
  if (activeBtn) activeBtn.classList.add("active");

  if (tabId === "soc-tab") fetchDashboardData();
  if (tabId === "devices-tab") fetchDevices();
  if (tabId === "logs-tab") fetchLogs();
}

// Chart Initialization
function initChart() {
  const ctx = document.getElementById("threatChart")?.getContext("2d");
  if (!ctx) return;

  threatChartInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Brute Force", "Port Scanning", "DoS Attack", "Tampering", "Suspicious IP", "ML Anomaly"],
      datasets: [{
        data: [0, 0, 0, 0, 0, 0],
        backgroundColor: [
          "#e11d48",
          "#d97706",
          "#dc2626",
          "#f97316",
          "#8b5cf6",
          "#0284c7"
        ],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            font: { family: "'Plus Jakarta Sans', sans-serif", size: 11 },
            usePointStyle: true
          }
        }
      },
      cutout: "68%"
    }
  });
}

// Fetch All Dashboard Data
async function fetchDashboardData() {
  try {
    const statsRes = await fetch("/api/stats");
    const stats = await statsRes.json();

    document.getElementById("kpi-total-logs").innerText = stats.total_logs;
    document.getElementById("kpi-active-threats").innerText = stats.active_threats;
    document.getElementById("kpi-total-devices").innerText = stats.total_devices;
    document.getElementById("kpi-compromised-devices").innerText = stats.compromised_devices;
    
    document.getElementById("threat-count-badge").innerText = `${stats.active_threats} Active`;

    // Update Chart
    if (threatChartInstance && stats.category_counts) {
      const categories = ["Brute Force Attack", "Port Scanning", "DoS Attack", "Configuration Tampering", "Suspicious IP Communication", "Abnormal Behavior (ML Flagged)"];
      const counts = categories.map(c => stats.category_counts[c] || 0);
      threatChartInstance.data.datasets[0].data = counts;
      threatChartInstance.update();
    }

    fetchThreats();
  } catch (err) {
    console.error("Error fetching stats:", err);
  }
}

// Fetch Threats Table
async function fetchThreats() {
  try {
    const res = await fetch("/api/threats?limit=25");
    const threats = await res.json();
    const tbody = document.getElementById("threats-table-body");
    
    if (!threats || threats.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">No active threats detected yet. System baseline normal.</td></tr>`;
      return;
    }

    tbody.innerHTML = threats.map(t => {
      const sevClass = `badge-${t.severity.toLowerCase()}`;
      const timeStr = new Date(t.timestamp).toLocaleTimeString();
      return `
        <tr>
          <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">${timeStr}</td>
          <td><strong>${t.device_id}</strong><br><span style="font-size: 0.75rem; color: var(--text-muted);">${t.device_name}</span></td>
          <td><strong>${t.threat_category}</strong></td>
          <td><span class="badge ${sevClass}">${t.severity}</span></td>
          <td><span style="font-size: 0.82rem;">${t.detection_method}</span></td>
          <td>
            <span style="font-size: 0.78rem; font-weight: 700; color: ${t.status === 'ACTIVE' ? 'var(--severity-critical)' : '#059669'};">
              ${t.status}
            </span>
          </td>
          <td>
            <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 0.78rem;" onclick='openEvidenceModal(${JSON.stringify(t)})'>
              <i class="fa-solid fa-magnifying-glass"></i> Evidence
            </button>
            ${t.status === 'ACTIVE' ? `
              <button class="btn btn-primary" style="padding: 4px 10px; font-size: 0.78rem;" onclick="resolveThreat('${t.event_id}')">
                Resolve
              </button>
            ` : ''}
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Error fetching threats:", err);
  }
}

// Fetch Devices Grid
async function fetchDevices() {
  try {
    const res = await fetch("/api/devices");
    const devices = await res.json();
    const grid = document.getElementById("device-cards-grid");

    if (!devices || devices.length === 0) {
      grid.innerHTML = `<p style="color: var(--text-muted);">No devices registered.</p>`;
      return;
    }

    grid.innerHTML = devices.map(d => {
      const statusBadge = d.status === "ONLINE" 
        ? `<span class="badge badge-online"><i class="fa-solid fa-circle"></i> Online</span>` 
        : `<span class="badge badge-critical"><i class="fa-solid fa-triangle-exclamation"></i> ${d.status}</span>`;

      let meterColor = "#059669";
      if (d.risk_score >= 70) meterColor = "#e11d48";
      else if (d.risk_score >= 40) meterColor = "#f97316";

      const iconMap = {
        "Smart Camera": "fa-video",
        "Smart Lock": "fa-lock",
        "Industrial Sensor": "fa-gauge-high",
        "IoT Gateway": "fa-router"
      };
      const icon = iconMap[d.device_type] || "fa-microchip";

      return `
        <div class="glass-panel device-card">
          <div class="device-card-header">
            <div class="device-icon-box">
              <i class="fa-solid ${icon}"></i>
            </div>
            ${statusBadge}
          </div>
          <h4 style="font-family: var(--font-display); font-size: 1.1rem; margin-bottom: 4px;">${d.name}</h4>
          <p style="font-size: 0.8rem; color: var(--text-muted); font-family: var(--font-mono);">${d.device_id} | ${d.ip_address}</p>
          <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 6px;"><i class="fa-solid fa-location-dot"></i> ${d.location}</p>

          <div style="margin-top: 16px;">
            <div style="display: flex; justify-content: space-between; font-size: 0.82rem; font-weight: 600;">
              <span>Threat Risk Score:</span>
              <span style="color: ${meterColor}">${d.risk_score}/100</span>
            </div>
            <div class="risk-meter-bar">
              <div class="risk-meter-fill" style="width: ${d.risk_score}%; background: ${meterColor};"></div>
            </div>
          </div>

          <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 18px; pt: 12px; border-top: 1px solid var(--glass-border-subtle);">
            <span style="font-size: 0.78rem; color: var(--text-muted);">Threats: <strong>${d.total_threats}</strong></span>
            <button class="btn btn-secondary" style="padding: 5px 12px; font-size: 0.78rem;" onclick="viewDeviceTimeline('${d.device_id}')">
              Timeline
            </button>
          </div>
        </div>
      `;
    }).join("");
  } catch (err) {
    console.error("Error fetching devices:", err);
  }
}

// Fetch Logs
async function fetchLogs() {
  try {
    const res = await fetch("/api/logs?limit=40");
    const logs = await res.json();
    const tbody = document.getElementById("logs-table-body");

    tbody.innerHTML = logs.map(l => `
      <tr>
        <td style="font-family: var(--font-mono); font-size: 0.78rem;">${l.log_id}</td>
        <td style="font-family: var(--font-mono); font-size: 0.78rem;">${new Date(l.timestamp).toLocaleTimeString()}</td>
        <td><strong>${l.device_id}</strong></td>
        <td><span class="badge" style="background: rgba(59, 130, 246, 0.1); color: #2563eb;">${l.log_type}</span></td>
        <td><strong>${l.action}</strong></td>
        <td style="font-family: var(--font-mono); font-size: 0.8rem;">${l.source_ip}</td>
        <td style="font-family: var(--font-mono); font-size: 0.8rem;">${l.target_port}</td>
        <td style="font-size: 0.82rem; color: var(--text-muted); font-family: var(--font-mono);">${l.payload}</td>
      </tr>
    `).join("");
  } catch (err) {
    console.error("Error fetching logs:", err);
  }
}

// Ingest Custom Log
async function submitCustomLog() {
  const device = document.getElementById("cust-device").value || "DEV-CAM-01";
  const log_type = document.getElementById("cust-log-type").value;
  const action = document.getElementById("cust-action").value || "TEST_EVENT";
  const payload = document.getElementById("cust-payload").value || "Manual telemetry ingest test";

  try {
    const res = await fetch("/api/logs/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        device_id: device,
        log_type: log_type,
        action: action,
        payload: payload,
        source_ip: "192.168.1.150",
        target_port: 80
      })
    });
    const data = await res.json();
    fetchDashboardData();
    switchTab("logs-tab");
  } catch (err) {
    alert("Error ingesting log: " + err.message);
  }
}

// Trigger Traffic Simulation
async function triggerSimulation(scenario, count) {
  try {
    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: scenario, count: count })
    });
    const data = await res.json();
    fetchDashboardData();
  } catch (err) {
    console.error("Error running simulation:", err);
  }
}

function runSelectedSimulation() {
  const scenario = document.getElementById("sim-scenario").value;
  triggerSimulation(scenario, 5);
}

// Resolve Threat Event Status
async function resolveThreat(eventId) {
  try {
    await fetch(`/api/threats/${eventId}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "RESOLVED" })
    });
    fetchDashboardData();
  } catch (err) {
    console.error("Error resolving threat:", err);
  }
}

// Open Evidence & Recommended Actions Modal
function openEvidenceModal(threat) {
  const modal = document.getElementById("evidence-modal");
  const modalTitle = document.getElementById("modal-title");
  const modalContent = document.getElementById("modal-content");

  modalTitle.innerText = `${threat.threat_category} - ${threat.device_id}`;
  
  const recActions = threat.recommended_actions || [];
  const recHtml = recActions.map(a => `
    <div class="action-step">
      <div class="action-step-num">${a.step}</div>
      <div style="font-size: 0.88rem; color: var(--text-main); font-weight: 500;">${a.action}</div>
    </div>
  `).join("");

  modalContent.innerHTML = `
    <div style="margin-bottom: 20px;">
      <div style="display: flex; gap: 12px; margin-bottom: 16px;">
        <span class="badge badge-${threat.severity.toLowerCase()}">${threat.severity} Severity</span>
        <span class="badge" style="background: rgba(139, 92, 246, 0.1); color: #8b5cf6;">Rule: ${threat.matched_rule}</span>
        <span class="badge" style="background: rgba(2, 132, 199, 0.1); color: #0284c7;">ML Score: ${threat.anomaly_score}</span>
      </div>

      <h5 style="font-size: 0.88rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 8px;">Evidence & Evidence Summary:</h5>
      <p style="font-size: 0.9rem; margin-bottom: 12px; font-weight: 500;">${threat.evidence.description || "Suspicious behavior detected."}</p>
      
      <div class="code-block">
        Raw Message: ${threat.evidence.raw_message || "N/A"}<br>
        Source IP: ${threat.source_ip} | Target Port: ${threat.target_port}<br>
        Payload: ${threat.evidence.payload || "N/A"}
      </div>
    </div>

    <div style="margin-top: 24px;">
      <h5 style="font-size: 0.88rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 12px;"><i class="fa-solid fa-list-check" style="color: var(--primary);"></i> Recommended Response Actions:</h5>
      ${recHtml}
    </div>
  `;

  modal.classList.add("active");
}

function closeModal() {
  document.getElementById("evidence-modal").classList.remove("active");
}

// Render Predefined Rules List in Tab 4
function renderRulesList() {
  const container = document.getElementById("rules-list-container");
  if (!container) return;

  const rules = [
    { id: "RULE-BF-01", name: "Repeated Failed Logins", cat: "Brute Force Attack", sev: "High", desc: "Flags >=5 failed logins in 60s window from single IP." },
    { id: "RULE-PS-01", name: "Port Scan Reconnaissance", cat: "Port Scanning", sev: "Medium", desc: "Detects sequential probing across >=6 distinct ports." },
    { id: "RULE-DOS-01", name: "High Volume Traffic Flood", cat: "DoS Attack", sev: "Critical", desc: "Flags packet flood exceeding bandwidth thresholds." },
    { id: "RULE-TMP-01", name: "Unauthorized Config Change", cat: "Configuration Tampering", sev: "High", desc: "Detects unauthenticated parameter/security disabling." },
    { id: "RULE-FW-01", name: "Firmware Flash Attempt", cat: "Firmware Tampering", sev: "Critical", desc: "Detects unsigned bootloader or binary flash writes." },
    { id: "RULE-SIP-01", name: "Suspicious IP Communication", cat: "Suspicious IP", sev: "High", desc: "Flags active sessions with untrusted external IP ranges." }
  ];

  container.innerHTML = rules.map(r => `
    <div style="padding: 16px; background: white; border: 1px solid var(--glass-border-subtle); border-radius: var(--radius-md); display: flex; align-items: center; justify-content: space-between;">
      <div>
        <span style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--primary); font-weight: 700;">${r.id}</span>
        <h4 style="font-size: 0.95rem; font-weight: 700; margin: 2px 0;">${r.name}</h4>
        <p style="font-size: 0.8rem; color: var(--text-muted);">${r.desc}</p>
      </div>
      <span class="badge badge-${r.sev.toLowerCase()}">${r.sev}</span>
    </div>
  `).join("");
}

// Run Automated pytest test suite directly from UI
async function runAutomatedTests() {
  const container = document.getElementById("test-results-container");
  container.innerHTML = `
    <div style="padding: 24px; text-align: center;">
      <i class="fa-solid fa-circle-notch fa-spin" style="font-size: 2rem; color: var(--primary);"></i>
      <p style="margin-top: 12px; font-weight: 600;">Running Sentinel Pytest Suite...</p>
    </div>
  `;

  try {
    const res = await fetch("/api/tests/run", { method: "POST" });
    const data = await res.json();

    const isSuccess = data.success;
    const badgeHtml = isSuccess 
      ? `<span class="badge badge-online" style="font-size: 0.9rem;"><i class="fa-solid fa-check"></i> ALL TESTS PASSED</span>`
      : `<span class="badge badge-critical" style="font-size: 0.9rem;"><i class="fa-solid fa-xmark"></i> TESTS FAILED</span>`;

    container.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px;">
        ${badgeHtml}
        <span style="font-size: 0.85rem; color: var(--text-muted);">Exit Code: ${data.exit_code}</span>
      </div>

      <div class="code-block" style="max-height: 400px;">
${data.stdout || data.error || data.stderr}
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div style="color: var(--severity-critical); font-weight: 600;">Error launching test runner: ${err.message}</div>`;
  }
}

// Auto Refresh Logic
function startAutoRefresh() {
  autoRefreshTimer = setInterval(() => {
    const toggle = document.getElementById("auto-refresh-toggle");
    if (toggle && toggle.checked) {
      fetchDashboardData();
    }
  }, 3000);
}

function toggleAutoRefresh() {
  // handeled by checkbox check
}
