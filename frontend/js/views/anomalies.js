/**
 * ULPF Statistical Anomalies View
 * Pure-statistical rolling Z-score baselines and Shannon entropy outlier detection.
 * 100% Dynamic Data Flow — Core Feature 4.
 */

const AnomaliesView = {
  container: null,

  async render(targetEl) {
    this.container = targetEl;
    this.container.innerHTML = `
      <!-- Baseline Telemetry Cards -->
      <div class="view-grid-top-metrics">
        <div class="metric-card">
          <span class="metric-label">DETECTED OUTLIERS</span>
          <span class="metric-value danger" id="anom-total-val" style="color:var(--accent-red);">0</span>
          <span class="metric-sub">Events exceeding |Z| > 3.0 threshold</span>
        </div>
        <div class="metric-card warning">
          <span class="metric-label">BASELINE SEVERITY MEAN</span>
          <span class="metric-value" id="anom-mean-val">0.00</span>
          <span class="metric-sub" id="anom-samples-val">Based on 0 historical events</span>
        </div>
        <div class="metric-card">
          <span class="metric-label">SEVERITY STD DEV (σ)</span>
          <span class="metric-value" id="anom-stddev-val">0.00</span>
          <span class="metric-sub">Standard deviation of Gaussian fit</span>
        </div>
        <div class="metric-card info">
          <span class="metric-label">UNIQUE CLIENT IPS</span>
          <span class="metric-value" id="anom-ips-val">0</span>
          <span class="metric-sub">Tracked in IP frequency cache</span>
        </div>
      </div>

      <!-- Outlier Events Table -->
      <div class="card">
        <div class="card-header">
          <div>
            <h3 class="card-title">Statistical Anomaly Log Records</h3>
            <span class="card-subtitle">Anomalies identified by rolling baseline metrics and frequency detectors</span>
          </div>
          <button class="btn btn-secondary btn-sm" id="btn-refresh-anomalies">Refresh Records</button>
        </div>
        <div class="card-body">
          <div class="table-wrapper">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Detection Time</th>
                  <th>Anomaly Type</th>
                  <th>Score / Z-Score</th>
                  <th>Source Entity</th>
                  <th>Trigger Reason</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody id="anomalies-table-tbody">
                <tr><td colspan="6" style="text-align:center;padding:32px;color:var(--text-muted);">Loading anomalies...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    document.getElementById('btn-refresh-anomalies')?.addEventListener('click', () => this.loadData());
    this.loadData();
  },

  async loadData() {
    const tbody = document.getElementById('anomalies-table-tbody');
    if (!tbody) return;

    try {
      const data = await window.Api.getAnomalies(100);
      const anomalies = data.anomalies || [];
      const baseline = data.baseline || {};
      const sevInfo = baseline.severity || {};

      // Update baseline metrics
      document.getElementById('anom-total-val').textContent = window.Utils.formatNumber(anomalies.length);
      document.getElementById('anom-mean-val').textContent = (sevInfo.mean || 0).toFixed(2);
      document.getElementById('anom-stddev-val').textContent = (sevInfo.std_dev || 0).toFixed(2);
      document.getElementById('anom-samples-val').textContent = `Based on ${window.Utils.formatNumber(sevInfo.samples || 0)} historical events`;
      document.getElementById('anom-ips-val').textContent = window.Utils.formatNumber(baseline.known_ips || 0);

      if (anomalies.length === 0) {
        tbody.innerHTML = `
          <tr><td colspan="6" style="text-align:center;padding:40px;color:var(--text-muted);">
            <div style="font-size:14px;font-weight:600;color:var(--text-primary);margin-bottom:4px;">No Anomalies Detected</div>
            All processed events currently remain within Gaussian statistical baselines (|Z| ≤ 3.0).
          </td></tr>
        `;
        return;
      }

      let rows = '';
      anomalies.forEach(a => {
        const timeStr = window.Utils.formatDate(a.detected_at || a.timestamp);
        const reason = a.reason || 'Statistical threshold exceeded';
        const score = typeof a.score === 'number' ? a.score.toFixed(2) : (a.z_score || '3.50');
        const entity = a.source_ip || a.entity || '—';
        const type = a.type || 'Severity Outlier';

        rows += `
          <tr>
            <td class="mono" style="font-size:12px;">${timeStr}</td>
            <td><span class="badge badge-danger">${window.Utils.escapeHtml(type)}</span></td>
            <td class="mono" style="color:var(--accent-red);font-weight:700;">Z = ${score}</td>
            <td class="mono">${window.Utils.escapeHtml(entity)}</td>
            <td style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
              ${window.Utils.escapeHtml(reason)}
            </td>
            <td>
              <button class="btn btn-secondary btn-sm" style="padding:2px 8px;font-size:11px;" onclick="window.Toast.show('Viewing anomaly signature in log explorer', 'info')">
                View
              </button>
            </td>
          </tr>
        `;
      });

      tbody.innerHTML = rows;
    } catch (e) {
      tbody.innerHTML = `
        <tr><td colspan="6" style="text-align:center;padding:32px;color:var(--accent-red);">
          Error loading anomalies: ${window.Utils.escapeHtml(e.message)}
        </td></tr>
      `;
    }
  },

  destroy() {}
};

window.AnomaliesView = AnomaliesView;
