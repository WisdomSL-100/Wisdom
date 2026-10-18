import os
from pathlib import Path
import json
from io import BytesIO
import requests
from zipfile import ZIP_DEFLATED, ZipFile
from xml.sax.saxutils import escape
from flask import Flask, Response, jsonify, render_template_string, request

app = Flask(__name__)
CLOUD_APP_URL = os.getenv("CLOUD_APP_URL", "http://cloud-app:5003")
PORT = int(os.getenv("PORT", "3000"))
SCAN_TIMEOUT_MARGIN_SECONDS = 330
OTA_PACKAGE_ROOT = Path(
    os.getenv(
        "OTA_PACKAGE_ROOT",
        str(Path(__file__).resolve().parents[1] / "ota packages"),
    )
).resolve()

LEGACY_INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Automotive Cybersecurity Dashboard</title>
  <style>
    body { font-family: Arial, sans-serif; background: #0b1020; color: #e6edf7; margin: 0; padding: 20px; }
    .container { max-width: 1200px; margin: 0 auto; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 20px; }
    .card { background: #111827; border: 1px solid #2f3b52; border-radius: 12px; padding: 20px; box-shadow: 0 10px 25px rgba(0,0,0,0.15); }
    .badge { padding: 6px 10px; border-radius: 999px; background: #1d4ed8; display: inline-block; margin-bottom: 12px; }
    .ok { color: #6ee7b7; }
    .warn { color: #fbbf24; }
    .danger { color: #f87171; }
    h1, h2, p { margin-top: 0; }
    pre { white-space: pre-wrap; font-size: 12px; }
    details { margin-top: 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 9px; border-bottom: 1px solid #2f3b52; text-align: left; }
    .table-wrap { overflow-x: auto; }
    select, button, input { padding: 10px 12px; margin: 4px 8px 4px 0; border-radius: 8px; border: 1px solid #2f3b52; }
    button { background: #2563eb; color: white; cursor: pointer; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Automotive Cybersecurity Scanner Dashboard</h1>
    <div class="badge">Vehicle Security Monitoring</div>

    <div class="card" style="margin-bottom:20px;">
      <h2>Launch Scan</h2>
      <p>Scans are simulation-only and require the vehicle to be in service. Choose target nodes below; the selected attack must be enabled as susceptible on every target.</p>
      <h3>Attack targets</h3>
      <div id="scan-targets">Loading simulated nodes...</div>
      <select id="attack-type">
        <option value="flooding">flooding</option>
        <option value="replay_attack">replay_attack</option>
        <option value="repudiation">repudiation</option>
        <option value="dos">dos</option>
        <option value="tampering">tampering</option>
        <option value="spoofing">spoofing</option>
      </select>
      <select id="severity">
        <option value="low">low</option>
        <option value="medium" selected>medium</option>
        <option value="high">high</option>
        <option value="critical">critical</option>
      </select>
      <label for="attack-duration">Attack duration (seconds, 1-60)</label>
      <input id="attack-duration" type="number" min="1" max="60" value="10">
      <button id="run-scan-button" onclick="runScan()" disabled>Run security scan</button>
      <p id="scan-feedback">Ready for next scan</p>
      <p>Each scan runs a bounded protocol probe suite against simulated nodes (CAN/CAN-FD, SOME/IP, DoIP, and UDS); no probes are sent to a physical vehicle.</p>
      <h3>Vehicle service state</h3>
      <p id="vehicle-service-state">Loading...</p>
      <select id="service-state-select">
        <option value="out_of_service" selected>Out of service</option>
        <option value="in_service">In service</option>
      </select>
      <button onclick="setVehicleServiceState()">Update service state</button>
      <p id="service-state-feedback"></p>
    </div>

    <div class="card" style="margin-bottom:20px;">
      <h2>ECU / ZCU / HPC Security Profiles</h2>
      <p>These enforced simulator profiles set susceptible attack types and a maximum permitted test severity. They persist in the vehicle-network configuration volume.</p>
      <p id="profile-feedback"></p>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Node</th><th>Role / zone / protocol</th><th>Security level</th><th>Max test severity</th><th>Susceptible attack cases</th><th>Action</th></tr></thead>
          <tbody id="security-profiles"><tr><td colspan="6">Loading simulator profiles...</td></tr></tbody>
        </table>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <h2>System Status</h2>
        <p id="system-status" class="ok">Loading...</p>
      </div>
      <div class="card">
        <h2>Current Risk</h2>
        <p id="risk-level" class="warn">Loading...</p>
      </div>
      <div class="card">
        <h2>Last Analysis</h2>
        <p id="last-analysis">Waiting for data</p>
      </div>
    </div>
    <div class="card" style="margin-top:20px;">
      <h2>Network sockets and live outcomes</h2>
      <p id="network-observability-status">Loading simulator socket status...</p>
      <button id="refresh-network-button" onclick="loadNetworkObservability()">Refresh socket and UDS data</button>
      <p id="network-observability-metadata"></p>
      <h3>Available simulator sockets</h3>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Socket / service</th><th>Transport and protocols</th><th>Endpoint</th><th>Status</th><th>Direction</th><th>Security</th></tr></thead>
          <tbody id="network-sockets"><tr><td colspan="6">Waiting for simulator socket inventory</td></tr></tbody>
        </table>
      </div>
      <h3>Network traffic and security events</h3>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Vehicle protocol</th><th>TX generated</th><th>TX delivered</th><th>RX accepted</th><th>Security events</th></tr></thead>
          <tbody id="network-traffic"><tr><td colspan="5">Waiting for live traffic data</td></tr></tbody>
        </table>
      </div>
      <p id="network-event-summary"></p>
      <h3>Live network-wide UDS diagnostics</h3>
      <p id="network-uds-summary">Waiting for diagnostic responses</p>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Positive</th><th>Negative</th><th>Timeout</th><th>Transport errors</th><th>Active DTCs</th><th>Availability</th><th>Mean / max latency</th><th>UDS catalog</th></tr></thead>
          <tbody id="network-uds"><tr><td colspan="8">Waiting for UDS results</td></tr></tbody>
        </table>
      </div>
      <h3>Latest attack outcome</h3>
      <p id="network-attack-outcome">No completed scan outcome is available yet.</p>
    </div>
    <div class="card" style="margin-top:20px;">
      <h2>Latest Scan Analytics</h2>
      <p id="ai-summary">Waiting for scan data</p>
      <p id="alert-action">Recommended action: none</p>
      <p id="protocol-probes">No protocol probe results yet</p>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Phase</th><th>Nodes assessed</th><th>UDS successful</th><th>Active DTCs</th><th>Behavior variations</th><th>Security events</th><th>Isolation Forest max</th><th>Deviating nodes</th><th>Risk</th></tr></thead>
          <tbody id="diagnostics"><tr><td colspan="9">No scan data</td></tr></tbody>
        </table>
      </div>
      <h2>Evidence phases</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Phase</th><th>Nodes / UDS</th><th>Message activity</th><th>Loss</th><th>Diagnostic latency / timeouts</th><th>Events / DTCs</th><th>Isolation Forest</th><th>Risk</th></tr></thead>
          <tbody id="evidence-phases"><tr><td colspan="8">No scan evidence</td></tr></tbody>
        </table>
      </div>
      <p id="evidence-metadata">No scan evidence loaded</p>
      <p id="evidence-comparison"></p>
      <p id="evidence-probes"></p>
      <p id="evidence-references"></p>
      <h2>Threat Explanation and Recommendations</h2>
      <p id="threat-report-status">No threat report yet</p>
      <h3 id="threat-report-title"></h3>
      <p id="threat-report-summary"></p>
      <p id="threat-report-explanation"></p>
      <h4>Recommended actions</h4>
      <ul id="threat-report-recommendations"></ul>
      <h4>Retrieved references and limitations</h4>
      <ul id="threat-report-citations"></ul>
      <p id="baseline-model-summary"></p>
      <details>
        <summary>All collected privacy-filtered evidence fields</summary>
        <pre id="evidence-json">No scan evidence loaded</pre>
      </details>
      <h2>Cloud-safe Service Summary</h2>
      <pre id="cloud-overview">Loading...</pre>
    </div>
    <div class="card" style="margin-top:20px;">
      <h2>Recent Scan History</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Time</th><th>Attack</th><th>Severity</th><th>Risk</th><th>Finding</th><th>Evidence</th></tr></thead>
          <tbody id="scan-history"><tr><td colspan="6">No scans recorded</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    let selectedEvidenceScanId = 'latest';
    let securityProfileData = null;
    const selectedTargetIds = new Set();
    const severityRank = {low: 0, medium: 1, high: 2, critical: 3};

    async function loadData() {
      try {
        const response = await fetch('/api/status');
        const data = await response.json();
        document.getElementById('system-status').textContent = data.status;
        document.getElementById('risk-level').textContent = data.risk_level || 'unknown';
        document.getElementById('last-analysis').textContent = data.last_analysis || 'no scan yet';
        document.getElementById('cloud-overview').textContent = JSON.stringify(data.cloud_overview || {}, null, 2);
        const serviceState = (data.cloud_overview || {}).vehicle_service_state || 'unknown';
        document.getElementById('vehicle-service-state').textContent = serviceState.replaceAll('_', ' ');
        if (serviceState === 'in_service' || serviceState === 'out_of_service') {
          document.getElementById('service-state-select').value = serviceState;
        }
        syncScanControls(serviceState);
        const scan = (data.cloud_overview || {}).last_scan || {};
        renderLatestAttackOutcome(scan);
        document.getElementById('ai-summary').textContent = scan.ai_summary || 'No analysis available';
        document.getElementById('alert-action').textContent = 'Recommended action: ' + (scan.alert_action || 'none');
        const probes = scan.probe_summary || {};
        const protocolSummary = Object.entries(probes.protocols || {})
          .map(([protocol, values]) => `${protocol}: ${values.rejected_count}/${values.attempted_count} rejected`)
          .join(', ');
        const categorySummary = Object.entries(probes.category_counts || {})
          .map(([category, count]) => `${category}=${count}`)
          .join(', ');
        document.getElementById('protocol-probes').textContent = probes.status
          ? `Simulator-only protocol probes: ${probes.rejected_count}/${probes.attempted_count} rejected; ${protocolSummary}. Categories: ${categorySummary || 'none'}`
          : 'No protocol probe results yet';
        renderThreatReport(scan.threat_report || {});
        renderBaselineModel(scan.baseline_model || {});
        const table = document.getElementById('diagnostics');
        table.replaceChildren();
        const phases = [
          ['Before attack', scan.before_attack],
          ['After attack', scan.after_attack]
        ].filter(([, phase]) => phase);
        if (!phases.length) {
          const row = table.insertRow();
          const cell = row.insertCell();
          cell.colSpan = 9;
          cell.textContent = 'No scan data';
        }
        phases.forEach(([phaseName, item]) => {
          const row = table.insertRow();
          [
            phaseName,
            item.network_node_count,
            item.uds_successful_count + '/' + item.uds_tested_node_count,
            item.active_dtc_count,
            item.behavior_variation_count,
            item.security_event_count,
            Number(item.isolation_forest_max_anomaly_score || 0).toFixed(3),
            item.isolation_forest_deviation_node_count,
            item.risk_level
          ].forEach(value => {
            row.insertCell().textContent = value;
          });
        });
        const historyResponse = await fetch('/api/history?limit=10');
        const historyData = await historyResponse.json();
        const historyTable = document.getElementById('scan-history');
        historyTable.replaceChildren();
        const scans = historyData.scans || [];
        if (!scans.length) {
          const row = historyTable.insertRow();
          const cell = row.insertCell();
          cell.colSpan = 5;
          cell.textContent = 'No scans recorded';
        }
        scans.forEach(scan => {
          const row = historyTable.insertRow();
          [new Date(scan.created_at).toLocaleString(), scan.attack_type, scan.severity, scan.risk_level, scan.summary].forEach(value => {
            row.insertCell().textContent = value || '';
          });
          const actionCell = row.insertCell();
          const evidenceButton = document.createElement('button');
          evidenceButton.textContent = 'View evidence';
          evidenceButton.dataset.scanId = scan.scan_id;
          evidenceButton.addEventListener('click', () => loadEvidence(scan.scan_id));
          actionCell.appendChild(evidenceButton);
        });
        await loadEvidence(selectedEvidenceScanId);
      } catch (error) {
        document.getElementById('cloud-overview').textContent = 'Unable to connect to cloud service: ' + error;
      }
    }

    function renderLatestAttackOutcome(scan) {
      const target = document.getElementById('network-attack-outcome');
      if (!scan || !scan.scan_id) {
        target.textContent = 'No completed scan outcome is available yet.';
        return;
      }
      const attack = scan.attack_summary || {};
      const during = scan.during_attack || {};
      const probes = scan.probe_summary || {};
      target.textContent = [
        `Scenario: ${scan.attack_type || 'unknown'} (${scan.severity || 'unknown'} severity)`,
        `Execution: ${attack.status || scan.test_execution_result || scan.scan_status || 'unknown'}`,
        `Target count: ${attack.affected_node_count ?? scan.target_summary?.target_count ?? 'not reported'}`,
        `Events: ${attack.event_count ?? during.security_event_count ?? 0}`,
        `Socket frames: ${attack.attack_frame_count ?? during.attack_frame_count ?? 0} attempted, ${attack.accepted_frame_count ?? during.accepted_frame_count ?? 0} accepted, ${attack.dropped_frame_count ?? during.dropped_frame_count ?? 0} dropped`,
        `Sockets: ${(attack.affected_sockets || during.affected_sockets || []).join(', ') || 'not reported'}`,
        `Probe outcomes: ${probes.rejected_count ?? 0}/${probes.attempted_count ?? 0} rejected`,
        `Risk: ${scan.risk_level || 'unknown'}`,
        `Recovery: ${scan.recovery_status || 'not assessed'}`
      ].join(' | ');
    }

    function renderNetworkObservability(data) {
      const socketsTable = document.getElementById('network-sockets');
      socketsTable.replaceChildren();
      (data.sockets || []).forEach(socket => {
        const row = socketsTable.insertRow();
        [
          socket.name,
          `${socket.transport}: ${(socket.protocols || []).join(', ')}`,
          `${socket.host}:${socket.port}`,
          socket.status,
          socket.direction,
          socket.security
        ].forEach(value => {
          row.insertCell().textContent = value || 'not reported';
        });
      });
      if (!socketsTable.rows.length) {
        const row = socketsTable.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 6;
        cell.textContent = 'No simulator sockets were reported';
      }

      const trafficTable = document.getElementById('network-traffic');
      trafficTable.replaceChildren();
      Object.entries(data.traffic_by_protocol || {}).forEach(([protocol, metrics]) => {
        const row = trafficTable.insertRow();
        [
          protocol,
          metrics.tx_generated ?? 0,
          metrics.tx_delivered ?? 0,
          metrics.rx_accepted ?? 0,
          metrics.security_event_count ?? 0
        ].forEach(value => {
          row.insertCell().textContent = value;
        });
      });
      if (!trafficTable.rows.length) {
        const row = trafficTable.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 5;
        cell.textContent = 'No simulator traffic counters were reported';
      }

      const eventSummary = data.security_events || {};
      const categories = Object.entries(eventSummary.category_counts || {})
        .map(([category, count]) => `${category}: ${count}`)
        .join(', ');
      document.getElementById('network-event-summary').textContent =
        `Retained security events: ${eventSummary.retained_event_count ?? 0}. Categories: ${categories || 'none'}.`;

      const uds = data.uds || {};
      const responseCategories = uds.response_categories || {};
      const udsTable = document.getElementById('network-uds');
      udsTable.replaceChildren();
      const row = udsTable.insertRow();
      [
        responseCategories.positive ?? uds.successful_count ?? 0,
        responseCategories.negative ?? 0,
        responseCategories.timeout ?? uds.timeout_count ?? 0,
        responseCategories.transport_error ?? 0,
        uds.active_dtc_count ?? 0,
        `${uds.ecu_availability_percent ?? 0}%`,
        `${uds.diagnostic_latency_mean_ms ?? 'n/a'} / ${uds.diagnostic_latency_max_ms ?? 'n/a'} ms`,
        `${uds.component_count ?? 0} nodes; ${uds.supported_service_count ?? 0} services; ${uds.did_count ?? 0} DIDs; ${uds.rid_count ?? 0} RIDs`
      ].forEach(value => {
        row.insertCell().textContent = value;
      });
      document.getElementById('network-uds-summary').textContent =
        `${uds.successful_count ?? 0}/${uds.component_count ?? 0} simulated components returned successful UDS diagnostics; ${uds.failed_count ?? 0} failed. Probe duration: ${uds.diagnostic_elapsed_ms ?? 'n/a'} ms.`;
      document.getElementById('network-observability-metadata').textContent =
        `Simulator network: ${data.network?.node_count ?? 'n/a'} nodes across ${data.network?.zone_count ?? 'n/a'} zones. Live counters are cumulative since simulator startup. Last refreshed: ${data.observed_at || 'unknown'}.`;
    }

    async function loadNetworkObservability() {
      const status = document.getElementById('network-observability-status');
      const button = document.getElementById('refresh-network-button');
      button.disabled = true;
      status.textContent = 'Refreshing socket status and running read-only network-wide UDS diagnostics...';
      try {
        const response = await fetch('/api/network/observability');
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Network observability request failed');
        renderNetworkObservability(data);
        status.textContent = 'Live simulator socket, traffic, security-event and UDS data loaded.';
      } catch (error) {
        status.textContent = `Unable to load live network data: ${error}`;
      } finally {
        button.disabled = false;
      }
    }

    function renderThreatReport(report) {
      document.getElementById('threat-report-status').textContent =
        report.status
          ? `Provider: ${report.provider || 'unknown'}; model: ${report.model || 'unknown'}; status: ${report.status}`
          : 'No threat report yet';
      document.getElementById('threat-report-title').textContent = report.title || '';
      document.getElementById('threat-report-summary').textContent =
        report.executive_summary || '';
      document.getElementById('threat-report-explanation').textContent =
        report.technical_explanation || '';
      const recommendations = document.getElementById('threat-report-recommendations');
      recommendations.replaceChildren();
      (report.recommendations || []).forEach(item => {
        const li = document.createElement('li');
        li.textContent = item;
        recommendations.appendChild(li);
      });
      const citations = document.getElementById('threat-report-citations');
      citations.replaceChildren();
      [...(report.evidence_citations || []), ...(report.limitations || [])].forEach(item => {
        const li = document.createElement('li');
        li.textContent = item;
        citations.appendChild(li);
      });
    }

    function renderBaselineModel(model) {
      document.getElementById('baseline-model-summary').textContent =
        model.algorithm
          ? `${model.algorithm} baseline: ${model.status}; trained before attack on ${model.training_node_count} observed node records and ${model.feature_count} features; synthetic training records: ${model.synthetic_training_samples}.`
          : 'Baseline model training metadata unavailable';
    }

    function selectedProfiles() {
      if (!securityProfileData) return [];
      return securityProfileData.nodes.filter(node => selectedTargetIds.has(node.node_id));
    }

    function syncScanControls(serviceState) {
      const targets = selectedProfiles();
      const scanButton = document.getElementById('run-scan-button');
      const attackSelect = document.getElementById('attack-type');
      const severitySelect = document.getElementById('severity');
      const attacks = targets.length
        ? targets.map(node => node.susceptible_attacks || [])
          .reduce((common, nodeAttacks) => common.filter(attack => nodeAttacks.includes(attack)))
        : [];
      const selectedAttack = attackSelect.value;
      attackSelect.replaceChildren();
      attacks.forEach(attack => {
        const option = document.createElement('option');
        option.value = attack;
        option.textContent = attack;
        attackSelect.appendChild(option);
      });
      if (attacks.includes(selectedAttack)) attackSelect.value = selectedAttack;
      const availableLevels = targets
        .map(node => securityProfileData.security_levels[node.security_level].maximum_severity)
        .map(level => severityRank[level]);
      const maximumRank = availableLevels.length ? Math.min(...availableLevels) : -1;
      [...severitySelect.options].forEach(option => {
        option.disabled = severityRank[option.value] > maximumRank;
      });
      if (maximumRank >= 0 && severityRank[severitySelect.value] > maximumRank) {
        severitySelect.value = Object.keys(severityRank).find(
          level => severityRank[level] === maximumRank
        );
      }
      scanButton.disabled = serviceState !== 'in_service'
        || targets.length === 0
        || attacks.length === 0;
      document.getElementById('scan-feedback').textContent =
        targets.length === 0
          ? 'Select at least one target node to configure the scan'
          : attacks.length === 0
            ? 'Selected nodes have no common susceptible attack; update their profiles or choose different targets'
            : `Ready to test ${targets.length} selected node(s); maximum allowed severity is ${maximumRank >= 0 ? Object.keys(severityRank).find(level => severityRank[level] === maximumRank) : 'none'}`;
    }

    function renderSecurityProfiles(data) {
      securityProfileData = data;
      const targetContainer = document.getElementById('scan-targets');
      const profileTable = document.getElementById('security-profiles');
      targetContainer.replaceChildren();
      profileTable.replaceChildren();
      const validIds = new Set(data.nodes.map(node => node.node_id));
      [...selectedTargetIds].forEach(nodeId => {
        if (!validIds.has(nodeId)) selectedTargetIds.delete(nodeId);
      });
      data.nodes.forEach(node => {
        const targetLabel = document.createElement('label');
        const targetCheckbox = document.createElement('input');
        targetCheckbox.type = 'checkbox';
        targetCheckbox.checked = selectedTargetIds.has(node.node_id);
        targetCheckbox.addEventListener('change', () => {
          if (targetCheckbox.checked) selectedTargetIds.add(node.node_id);
          else selectedTargetIds.delete(node.node_id);
          syncScanControls(
            document.getElementById('vehicle-service-state').textContent.replaceAll(' ', '_')
          );
        });
        targetLabel.append(targetCheckbox, ` ${node.display_name} (${node.role}) `);
        targetContainer.appendChild(targetLabel);

        const row = profileTable.insertRow();
        row.insertCell().textContent = `${node.display_name} [${node.node_id}]`;
        row.insertCell().textContent = `${node.role} / ${node.zone} / ${node.protocol}`;

        const levelCell = row.insertCell();
        const levelSelect = document.createElement('select');
        Object.keys(data.security_levels).forEach(level => {
          const option = document.createElement('option');
          option.value = level;
          option.textContent = level;
          levelSelect.appendChild(option);
        });
        levelSelect.value = node.security_level;
        levelCell.appendChild(levelSelect);

        const maxSeverityCell = row.insertCell();
        const updateSeverityCap = () => {
          maxSeverityCell.textContent =
            data.security_levels[levelSelect.value].maximum_severity;
        };
        levelSelect.addEventListener('change', updateSeverityCap);
        updateSeverityCap();

        const attackCell = row.insertCell();
        const attackInputs = new Map();
        data.attack_types.forEach(attack => {
          const label = document.createElement('label');
          label.style.display = 'inline-block';
          label.style.marginRight = '8px';
          const checkbox = document.createElement('input');
          checkbox.type = 'checkbox';
          checkbox.value = attack;
          checkbox.checked = node.susceptible_attacks.includes(attack);
          attackInputs.set(attack, checkbox);
          label.append(checkbox, ` ${attack}`);
          attackCell.appendChild(label);
        });

        const actionCell = row.insertCell();
        const saveButton = document.createElement('button');
        saveButton.textContent = 'Save profile';
        saveButton.addEventListener('click', async () => {
          saveButton.disabled = true;
          document.getElementById('profile-feedback').textContent =
            `Saving profile for ${node.display_name}...`;
          try {
            const response = await fetch('/api/security/profiles', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({
                node_id: node.node_id,
                security_level: levelSelect.value,
                susceptible_attacks: [...attackInputs.entries()]
                  .filter(([, checkbox]) => checkbox.checked)
                  .map(([attack]) => attack)
              })
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.message || 'Profile update failed');
            document.getElementById('profile-feedback').textContent =
              `Saved ${node.display_name} profile`;
            renderSecurityProfiles(result);
            syncScanControls(
              document.getElementById('vehicle-service-state').textContent.replaceAll(' ', '_')
            );
          } catch (error) {
            document.getElementById('profile-feedback').textContent =
              `Profile update failed: ${error}`;
            saveButton.disabled = false;
          }
        });
        actionCell.appendChild(saveButton);
      });
      syncScanControls(
        document.getElementById('vehicle-service-state').textContent.replaceAll(' ', '_')
      );
    }

    async function loadSecurityProfiles() {
      const response = await fetch('/api/security/profiles');
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || 'Security profile request failed');
      renderSecurityProfiles(data);
    }

    function displayValue(value, suffix = '') {
      return value === null || value === undefined || value === ''
        ? 'not measured'
        : String(value) + suffix;
    }

    function renderEvidence(evidence) {
      const phasesTable = document.getElementById('evidence-phases');
      phasesTable.replaceChildren();
      if (!evidence || !evidence.scan_id) {
        const row = phasesTable.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 8;
        cell.textContent = 'No scan evidence';
        document.getElementById('evidence-metadata').textContent = 'No scan evidence loaded';
        document.getElementById('evidence-comparison').textContent = '';
        document.getElementById('evidence-probes').textContent = '';
        document.getElementById('evidence-references').textContent = '';
        document.getElementById('evidence-json').textContent = 'No scan evidence loaded';
        return;
      }

      document.getElementById('evidence-json').textContent =
        JSON.stringify(evidence, null, 2);
      const metadata = [
        `Session: ${evidence.test_session_id || 'not provided'}`,
        `Scenario: ${evidence.test_scenario_id || 'not provided'}`,
        `Status: ${evidence.scan_status || 'unknown'}`,
        `Execution: ${evidence.test_execution_result || 'unknown'}`,
        `Security assessment: ${evidence.security_assessment_result || 'unknown'}`,
        `Recovery: ${evidence.recovery_status || 'unknown'}`,
        `Diagnostic coverage: ${displayValue(evidence.diagnostic_coverage_percent, '%')}`,
        `Started: ${evidence.started_at || 'not provided'}`,
        `Ended: ${evidence.ended_at || 'not provided'}`,
        `Timestamp precision: ${evidence.timestamp_precision || 'not provided'}`
      ];
      document.getElementById('evidence-metadata').textContent = metadata.join(' | ');

      const phaseEntries = [
        ['Before', evidence.before_attack],
        ['During', evidence.during_attack],
        ['After', evidence.after_attack]
      ].filter(([, phase]) => phase);
      phaseEntries.forEach(([phaseName, phase]) => {
        const during = phaseName === 'During';
        const row = phasesTable.insertRow();
        const diagnostics = during ? null : phase.diagnostic_record_count;
        const uds = during ? 'not sampled' : `${displayValue(phase.uds_successful_count)}/${displayValue(phase.uds_tested_node_count)}`;
        const nodes = during ? 'not sampled' : displayValue(phase.network_node_count);
        const messageCount = during ? phase.message_count : phase.sampled_message_count;
        const messageRate = during ? phase.message_rate_per_second : phase.sampled_message_rate_per_second;
        const latency = during
          ? 'not sampled'
          : `${displayValue(phase.diagnostic_latency_mean_ms)} / ${displayValue(phase.diagnostic_latency_max_ms)} ms`;
        const timeoutRate = during
          ? 'not sampled'
          : `${displayValue(phase.diagnostic_timeout_count)} / ${displayValue(phase.diagnostic_timeout_rate_percent, '%')}`;
        const eventCount = during
          ? phase.security_event_count
          : phase.security_event_count;
        const dtcCount = during ? 'not sampled' : phase.active_dtc_count;
        const score = during
          ? 'not scored'
          : `${displayValue(phase.isolation_forest_max_anomaly_score)} / ${displayValue(phase.isolation_forest_deviation_node_count)} deviating`;
        [
          phaseName,
          during
            ? 'not sampled'
            : `${nodes} nodes; ${displayValue(diagnostics)} diagnostics; UDS ${uds}`,
          `${displayValue(messageCount)} messages; ${displayValue(messageRate, '/s')}`,
          displayValue(phase.message_loss_percentage, '%'),
          `${latency}; timeouts ${timeoutRate}`,
          `${displayValue(eventCount)} events; ${displayValue(dtcCount)} DTCs`,
          score,
          during ? 'not scored' : displayValue(phase.risk_level)
        ].forEach(value => {
          row.insertCell().textContent = value;
        });
      });

      const comparison = evidence.comparison || {};
      document.getElementById('evidence-comparison').textContent =
        `Before/after comparison: change point ${displayValue(comparison.change_point_indicator)}; ` +
        `risk increased ${displayValue(comparison.risk_increased)}; ` +
        `Isolation Forest score delta ${displayValue(comparison.isolation_forest_score_delta)}; ` +
        `new events ${displayValue(comparison.new_security_event_count)}; ` +
        `new DTCs ${displayValue(comparison.new_active_dtc_count)}.`;

      const probes = evidence.probe_summary || {};
      const protocolCounts = Object.entries(probes.protocols || {})
        .map(([protocol, counts]) => `${protocol}: ${counts.rejected_count}/${counts.attempted_count} rejected`)
        .join('; ');
      const categories = Object.entries(probes.category_counts || {})
        .map(([category, count]) => `${category}=${count}`)
        .join(', ');
      document.getElementById('evidence-probes').textContent = probes.status
        ? `Protocol probes (${probes.status}): ${probes.rejected_count}/${probes.attempted_count} rejected across ${probes.target_node_count} targets. ${protocolCounts}. Categories: ${categories || 'none'}.`
        : 'Protocol probe evidence unavailable';
      document.getElementById('evidence-references').textContent =
        `Evidence references: ${(evidence.evidence_references || []).join(', ') || 'none'}; ` +
        `interfaces: ${((evidence.attack_summary || {}).affected_interfaces || []).join(', ') || 'none'}; ` +
        `sockets: ${((evidence.attack_summary || {}).affected_sockets || []).join(', ') || 'none'}; ` +
        `raw frames and direct vehicle identifiers are intentionally not uploaded.`;
    }

    async function loadEvidence(scanId = 'latest') {
      selectedEvidenceScanId = scanId;
      const path = scanId === 'latest'
        ? '/api/evidence/latest'
        : '/api/evidence/' + encodeURIComponent(scanId);
      try {
        const response = await fetch(path);
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Evidence request failed');
        renderEvidence(data.evidence || {});
      } catch (error) {
        document.getElementById('evidence-metadata').textContent = 'Unable to load scan evidence: ' + error;
        document.getElementById('evidence-json').textContent = 'Evidence request failed';
      }
    }

    async function runScan() {
      const attackType = document.getElementById('attack-type').value;
      const severity = document.getElementById('severity').value;
      const duration = Number(document.getElementById('attack-duration').value);
      const feedback = document.getElementById('scan-feedback');
      if (!Number.isInteger(duration) || duration < 1 || duration > 60) {
        feedback.textContent = 'Attack duration must be between 1 and 60 seconds';
        return;
      }
      feedback.textContent = 'Triggering scan...';

      try {
        const response = await fetch('/api/scan/run', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            attack_type: attackType,
            severity,
            duration_seconds: duration,
            target_node_ids: [...selectedTargetIds]
          })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Scan failed');
        selectedEvidenceScanId = 'latest';
        const scanStatus = (((data.result || {}).scan) || {}).scan_status;
        feedback.textContent = scanStatus === 'completed'
          ? 'Scan completed successfully'
          : 'Scan ended with status: ' + (scanStatus || data.message || 'unknown');
        await loadData();
      } catch (error) {
        feedback.textContent = 'Scan trigger failed: ' + error;
      }
    }

    async function setVehicleServiceState() {
      const serviceState = document.getElementById('service-state-select').value;
      const feedback = document.getElementById('service-state-feedback');
      feedback.textContent = 'Updating vehicle service state...';
      try {
        const response = await fetch('/api/vehicle/service-state', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ service_state: serviceState })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Service-state update failed');
        feedback.textContent = 'Vehicle is now ' + data.service_state.replaceAll('_', ' ');
        await loadData();
      } catch (error) {
        feedback.textContent = 'Service-state update failed: ' + error;
      }
    }

    loadData();
    loadSecurityProfiles().catch(error => {
      document.getElementById('profile-feedback').textContent =
        'Unable to load simulator security profiles: ' + error;
    });
    setInterval(loadData, 5000);
    loadNetworkObservability();
    setInterval(loadNetworkObservability, 30000);
  </script>
</body>
</html>
"""

INDEX_HTML = Path(__file__).with_name("dashboard.html").read_text(
    encoding="utf-8"
)


@app.get("/")
def index():
    return render_template_string(INDEX_HTML)


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "frontend"})


@app.get("/api/ota/packages")
def ota_packages():
    packages = []
    if OTA_PACKAGE_ROOT.exists():
        for path in sorted(OTA_PACKAGE_ROOT.rglob("*.json")):
            relative_path = path.relative_to(OTA_PACKAGE_ROOT).as_posix()
            try:
                package = json.loads(path.read_text(encoding="utf-8"))
                manifest = package.get("manifest", {})
                profile = manifest.get("software_profile", {})
                packages.append(
                    {
                        "path": relative_path,
                        "package_name": package.get("package_name", path.stem),
                        "set": path.parent.name,
                        "control": (
                            path.parent.name
                            if path.parent.parent.name == "Attack Prone Packages"
                            else "baseline_secure"
                        ),
                        "target_node_id": package.get("target_ecu_id"),
                        "version": manifest.get("version"),
                        "image_size": manifest.get("image_size"),
                        "disabled_controls": sorted(
                            key for key, value in profile.items() if value is False
                        ),
                    }
                )
            except (OSError, ValueError, TypeError):
                continue
    return jsonify({"status": "ok", "packages": packages, "package_root": str(OTA_PACKAGE_ROOT)})


@app.get("/api/ota/packages/<path:package_path>")
def get_ota_package(package_path: str):
    candidate = (OTA_PACKAGE_ROOT / package_path).resolve()
    if OTA_PACKAGE_ROOT not in candidate.parents or candidate.suffix.lower() != ".json":
        return jsonify({"status": "error", "message": "Invalid OTA package path"}), 400
    if not candidate.is_file():
        return jsonify({"status": "not_found", "message": "OTA package was not found"}), 404
    try:
        package = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return jsonify({"status": "error", "message": f"OTA package could not be read: {exc}"}), 422
    if not isinstance(package, dict):
        return jsonify({"status": "error", "message": "OTA package must be a JSON object"}), 422
    return jsonify(package)


@app.get("/api/status")
def status():
    try:
        cloud_response = requests.get(f"{CLOUD_APP_URL}/api/overview", timeout=5)
        cloud_data = cloud_response.json() if cloud_response.ok else {"status": "unavailable"}
    except Exception as exc:
        cloud_data = {"status": "error", "error": str(exc)}

    return jsonify(
        {
        "status": "ok" if cloud_data.get("status") == "ok" else "degraded",
            "service": "frontend",
            "risk_level": cloud_data.get("risk_level", "unknown"),
            "last_analysis": cloud_data.get("last_analysis", "no scan yet"),
            "cloud_overview": cloud_data,
        }
    )


@app.get("/api/network/observability")
def network_observability():
    try:
        response = requests.get(
            f"{CLOUD_APP_URL}/api/network/observability",
            timeout=20,
        )
        return jsonify(response.json()), response.status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/api/network/activity")
def network_activity():
    limit = request.args.get("limit", "100")
    if not limit.isdigit() or not 1 <= int(limit) <= 200:
        return jsonify(
            {
                "status": "error",
                "message": "limit must be an integer between 1 and 200",
            }
        ), 400
    try:
        response = requests.get(
            f"{CLOUD_APP_URL}/api/network/activity",
            params={"limit": int(limit)},
            timeout=10,
        )
        return jsonify(response.json()), response.status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.post("/api/ota/flash")
def flash_ota_package():
    maximum_request_bytes = 3_145_728
    if (
        request.content_length is not None
        and request.content_length > maximum_request_bytes
    ):
        return jsonify(
            {"status": "error", "message": "OTA package JSON exceeds 3 MiB"}
        ), 413
    package = request.get_json(silent=True)
    if not isinstance(package, dict):
        return jsonify(
            {"status": "error", "message": "Request body must be an OTA package object"}
        ), 400
    target_id = package.get("target_ecu_id")
    manifest = package.get("manifest")
    image_hex = package.get("image_hex")
    if (
        not isinstance(target_id, str)
        or not target_id
        or not isinstance(manifest, dict)
        or manifest.get("ecu_id") != target_id
        or not isinstance(image_hex, str)
        or not image_hex
        or len(image_hex) > 2_097_152
        or len(image_hex) % 2 != 0
        or any(character not in "0123456789abcdefABCDEF" for character in image_hex)
        or manifest.get("image_size") != len(image_hex) // 2
    ):
        return jsonify(
            {
                "status": "error",
                "message": "OTA target, manifest, image encoding, or image size is invalid",
            }
        ), 400
    try:
        response = requests.post(
            f"{CLOUD_APP_URL}/api/ota/flash",
            json=package,
            timeout=195,
        )
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Cloud service returned an invalid OTA response")
        return jsonify(result), response.status_code
    except requests.RequestException as exc:
        return jsonify({"status": "error", "message": f"OTA relay failed: {exc}"}), 503
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 502


@app.post("/api/diagnostics/sovd")
def sovd_diagnostics():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("component_id"), str):
        return jsonify(
            {"status": "error", "message": "component_id is required"}
        ), 400
    try:
        response = requests.post(
            f"{CLOUD_APP_URL}/api/diagnostics/sovd",
            json=payload,
            timeout=35,
        )
        return jsonify(response.json()), response.status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.post("/api/signals/read")
def read_signal():
    payload = request.get_json(silent=True)
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("target_node_id"), str)
        or not isinstance(payload.get("signal_name"), str)
    ):
        return jsonify(
            {
                "status": "error",
                "message": "target_node_id and signal_name are required",
            }
        ), 400
    try:
        response = requests.post(
            f"{CLOUD_APP_URL}/api/signals/read",
            json=payload,
            timeout=25,
        )
        return jsonify(response.json()), response.status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/api/signals/catalog")
def get_signal_catalog():
    target_node_id = request.args.get("target_node_id", "")
    if not target_node_id:
        return jsonify(
            {"status": "error", "message": "target_node_id is required"}
        ), 400
    try:
        response = requests.get(
            f"{CLOUD_APP_URL}/api/signals/catalog",
            params={"target_node_id": target_node_id},
            timeout=12,
        )
        return jsonify(response.json()), response.status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.post("/api/scan/run")
def trigger_scan():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Request body must be a JSON object"}), 400
    if not isinstance(data.get("attack_type"), str) or data["attack_type"] not in {"flooding", "replay_attack", "repudiation", "dos", "tampering", "spoofing", "unauthorized_diagnostics", "cross_zone_access", "invalid_firmware", "ids_auditability_regression"}:
        return jsonify({"status": "error", "message": "Unsupported attack type"}), 400
    if not isinstance(data.get("severity"), str) or data["severity"] not in {"low", "medium", "high", "critical"}:
        return jsonify({"status": "error", "message": "Unsupported severity"}), 400
    if "run_baseline_checks" in data and type(data["run_baseline_checks"]) is not bool:
        return jsonify({"status": "error", "message": "run_baseline_checks must be a boolean"}), 400
    try:
        duration_seconds = data.get("duration_seconds", 10)
        if type(duration_seconds) is not int or not 1 <= duration_seconds <= 60:
            return jsonify({"status": "error", "message": "Attack duration must be an integer between 1 and 60 seconds"}), 400
        response = requests.post(
            f"{CLOUD_APP_URL}/api/scan/start",
            json=data,
            timeout=duration_seconds + SCAN_TIMEOUT_MARGIN_SECONDS,
        )
        if 400 <= response.status_code < 500:
            return jsonify(response.json()), response.status_code
        response.raise_for_status()
        result = response.json()
        return jsonify({"status": "ok", "result": result})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.post("/api/reports/xlsx")
def export_scan_report_xlsx():
    if request.content_length is not None and request.content_length > 2_000_000:
        return jsonify({"status": "error", "message": "Report export request is too large"}), 413
    data = request.get_json(silent=True)
    rows = data.get("rows") if isinstance(data, dict) else None
    if not isinstance(rows, list) or not rows or len(rows) > 1000:
        return jsonify({"status": "error", "message": "Report rows must contain between 1 and 1000 entries"}), 400

    columns = ("section", "item", "value", "details")
    safe_rows = []
    for row in rows:
        if not isinstance(row, dict):
            return jsonify({"status": "error", "message": "Each report row must be an object"}), 400
        values = []
        for column in columns:
            value = row.get(column, "")
            if value is None:
                value = ""
            if not isinstance(value, (str, int, float, bool)):
                return jsonify({"status": "error", "message": f"Report field {column} must be text or a number"}), 400
            text = str(value)
            if len(text) > 20000:
                return jsonify({"status": "error", "message": f"Report field {column} is too long"}), 400
            values.append(text)
        safe_rows.append(values)

    def cell(reference, value):
        return (
            f'<c r="{reference}" t="inlineStr"><is><t xml:space="preserve">'
            f'{escape(value)}'
            "</t></is></c>"
        )

    sheet_rows = [
        "<row r=\"1\">"
        + "".join(
            cell(f"{column}1", title)
            for column, title in zip(("A", "B", "C", "D"), ("Section", "Item", "Result", "Details"))
        )
        + "</row>"
    ]
    for row_number, values in enumerate(safe_rows, start=2):
        sheet_rows.append(
            f'<row r="{row_number}">'
            + "".join(
                cell(f"{column}{row_number}", value)
                for column, value in zip(("A", "B", "C", "D"), values)
            )
            + "</row>"
        )
    worksheet = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        "<sheetData>"
        + "".join(sheet_rows)
        + "</sheetData></worksheet>"
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Assessment" sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    workbook_relationships = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/></Relationships>'
    )
    package_relationships = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/></Relationships>'
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '</Types>'
    )
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", package_relationships)
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", workbook_relationships)
        archive.writestr("xl/worksheets/sheet1.xml", worksheet)

    filename_id = str(data.get("scan_id", "latest-scan"))[:80]
    filename_id = "".join(
        char if char.isascii() and (char.isalnum() or char in "._-") else "_"
        for char in filename_id
    ) or "latest-scan"
    response = Response(
        output.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    response.headers["Content-Disposition"] = (
        f'attachment; filename="cybersecurity-assessment-{filename_id}.xlsx"'
    )
    return response


@app.post("/api/vehicle/service-state")
def update_vehicle_service_state():
    data = request.get_json(silent=True)
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("service_state"), str)
        or data["service_state"] not in {"in_service", "out_of_service"}
    ):
        return jsonify(
            {
                "status": "error",
                "message": "service_state must be in_service or out_of_service",
            }
        ), 400
    try:
        response = requests.post(
            f"{CLOUD_APP_URL}/api/vehicle/service-state",
            json={"service_state": data["service_state"]},
            timeout=10,
        )
        response.raise_for_status()
        return jsonify(response.json())
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.post("/api/scan/stop")
def stop_scan():
    try:
        response = requests.post(
            f"{CLOUD_APP_URL}/api/scan/stop",
            timeout=12,
        )
        return jsonify(response.json()), response.status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/api/history")
def scan_history():
    limit = request.args.get("limit", "20")
    try:
        response = requests.get(f"{CLOUD_APP_URL}/api/history", params={"limit": limit}, timeout=5)
        response.raise_for_status()
        return jsonify(response.json())
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/api/fleet/analytics")
def fleet_analytics():
    try:
        response = requests.get(f"{CLOUD_APP_URL}/api/fleet/analytics", timeout=10)
        return jsonify(response.json()), response.status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/api/cves")
def cve_catalog():
    try:
        response = requests.get(
            f"{CLOUD_APP_URL}/api/cves",
            params={"q": request.args.get("q", ""), "limit": request.args.get("limit", "100")},
            timeout=10,
        )
        return jsonify(response.json()), response.status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.post("/api/cves/import")
def import_cves():
    payload = request.get_json(silent=True)
    try:
        response = requests.post(
            f"{CLOUD_APP_URL}/api/cves/import",
            json=payload,
            timeout=20,
        )
        return jsonify(response.json()), response.status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.post("/api/cves/sync")
def sync_cves():
    payload = request.get_json(silent=True) or {}
    try:
        response = requests.post(
            f"{CLOUD_APP_URL}/api/cves/sync",
            json=payload,
            timeout=40,
        )
        return jsonify(response.json()), response.status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/api/security/profiles")
def get_security_profiles():
    try:
        response = requests.get(f"{CLOUD_APP_URL}/api/security/profiles", timeout=10)
        return jsonify(response.json()), response.status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.post("/api/security/profiles")
def save_security_profile():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Request body must be a JSON object"}), 400
    try:
        response = requests.post(
            f"{CLOUD_APP_URL}/api/security/profiles",
            json=data,
            timeout=10,
        )
        return jsonify(response.json()), response.status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/api/evidence/<scan_id>")
def scan_evidence(scan_id: str):
    try:
        response = requests.get(
            f"{CLOUD_APP_URL}/api/evidence/{scan_id}",
            timeout=5,
        )
        return jsonify(response.json()), response.status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/api/evidence/latest")
def latest_evidence():
    try:
        response = requests.get(f"{CLOUD_APP_URL}/api/evidence/latest", timeout=5)
        return jsonify(response.json()), response.status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/api/report/<scan_id>")
def get_scan_report(scan_id: str):
    try:
        audience = request.args.get("audience", "technician")
        response = requests.get(
            f"{CLOUD_APP_URL}/api/report/{scan_id}",
            params={"audience": audience},
            timeout=5,
        )
        return jsonify(response.json()), response.status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/api/report/latest")
def get_latest_report():
    audience = request.args.get("audience", "technician")
    try:
        response = requests.get(
            f"{CLOUD_APP_URL}/api/report/latest",
            params={"audience": audience},
            timeout=5,
        )
        return jsonify(response.json()), response.status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=os.getenv("FLASK_DEBUG", "0") == "1")
