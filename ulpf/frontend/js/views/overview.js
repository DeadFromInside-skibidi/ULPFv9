/**
 * ULPF Operational Overview View
 * Real-time telemetry, format breakdowns, and recent normalized stream.
 * 100% Dynamic Data Flow.
 */

const OverviewView = {
  container: null,
  unsubscribe: null,

  async render(targetEl) {
    this.container = targetEl;
    this.container.innerHTML = `
      <!-- Top Metrics Strip -->
      <div class="view-grid-top-metrics">
        <div class="metric-card" id="metric-total-events">
          <span class="metric-label">TOTAL NORMALIZED EVENTS</span>
          <span class="metric-value" id="val-total-events">0</span>
          <span class="metric-sub" id="sub-total-events">Stored in DuckDB Columnar</span>
        </div>
        <div class="metric-card" id="metric-pipeline-eps">
          <span class="metric-label">CURRENT INGESTION RATE</span>
          <span class="metric-value" id="val-pipeline-eps">0.0 EPS</span>
          <span class="metric-sub">Zero-Copy Batch Pipeline</span>
        </div>
        <div class="metric-card success" id="metric-success-rate">
          <span class="metric-label">PIPELINE SUCCESS RATE</span>
          <span class="metric-value" id="val-success-rate">100%</span>
          <span class="metric-sub" id="sub-success-counts">0 / 0 Parsed</span>
        </div>
        <div class="metric-card warning" id="metric-anomalies-count">
          <span class="metric-label">STATISTICAL ANOMALIES</span>
          <span class="metric-value" id="val-anomalies-count">0</span>
          <span class="metric-sub">Z-Score & Entropy Outliers</span>
        </div>
      </div>

      <!-- 2-Column Distribution Section -->
      <div class="view-grid-2col">
        <!-- Events by Source Format -->
        <div class="card">
          <div class="card-header">
            <div>
              <h3 class="card-title">Events by Source Format</h3>
              <span class="card-subtitle">Automatic jump-table classifier distribution</span>
            </div>
            <span class="badge badge-info" id="badge-fmt-count">0 Formats</span>
          </div>
          <div class="card-body" id="dist-formats-body">
            <div class="empty-state">
              <div class="empty-state-title">No format telemetry yet</div>
              <div class="empty-state-text">Ingest logs via the Ingestion Engine to view distribution.</div>
            </div>
          </div>
        </div>

        <!-- Events by Security Category -->
        <div class="card">
          <div class="card-header">
            <div>
              <h3 class="card-title">Events by Security Category</h3>
              <span class="card-subtitle">OCSF normalized taxonomy breakdown</span>
            </div>
            <span class="badge badge-info" id="badge-cat-count">0 Categories</span>
          </div>
          <div class="card-body" id="dist-categories-body">
            <div class="empty-state">
              <div class="empty-state-title">No category telemetry yet</div>
              <div class="empty-state-text">Log events will populate security classifications automatically.</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Severity Histogram & Processing Engine -->
      <div class="view-grid-2col">
        <div class="card">
          <div class="card-header">
            <div>
              <h3 class="card-title">Normalized Severity Distribution</h3>
              <span class="card-subtitle">Scale 0 (Informational / Unknown) to 10 (Catastrophic)</span>
            </div>
          </div>
          <div class="card-body">
            <div class="histogram-container" id="severity-histogram-bars">
              <!-- Rendered dynamically -->
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <div>
              <h3 class="card-title">Engine Health & Threat Cache</h3>
              <span class="card-subtitle">Air-gapped intelligence and syslog status</span>
            </div>
            <span class="badge badge-success">OPERATIONAL</span>
          </div>
          <div class="card-body" style="display:flex;flex-direction:column;gap:12px;font-size:13px;">
            <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border-subtle);">
              <span style="color:var(--text-secondary);">Embedded DuckDB OLAP:</span>
              <span class="mono" style="color:var(--accent-emerald);">Connected (Zero-Copy)</span>
            </div>
            <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border-subtle);">
              <span style="color:var(--text-secondary);">Syslog Daemon:</span>
              <span class="mono" id="overview-listener-val" style="color:var(--text-primary);">Standby</span>
            </div>
            <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border-subtle);">
              <span style="color:var(--text-secondary);">Air-Gapped Threat Intel:</span>
              <span class="mono" style="color:var(--accent-cyan);">Active (Local IOC/GeoIP)</span>
            </div>
            <div style="display:flex;justify-content:space-between;">
              <span style="color:var(--text-secondary);">Polling Frequency:</span>
              <span class="mono" style="color:var(--text-muted);">1,500ms reactive wakeup</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Recent Normalized Stream -->
      <div class="card">
        <div class="card-header">
          <div>
            <h3 class="card-title">Recent Normalized Events (Latest 5)</h3>
            <span class="card-subtitle">Live stream entering the columnar warehouse</span>
          </div>
          <a href="#explorer" class="btn btn-secondary btn-sm">Explore All Logs</a>
        </div>
        <div class="card-body">
          <div class="table-wrapper">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Time (UTC)</th>
                  <th>Format</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody id="recent-events-tbody">
                <tr><td colspan="7" style="text-align:center;padding:24px;color:var(--text-muted);">Loading events...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    // Subscribe to state updates
    this.unsubscribe = window.State.subscribe('stats', (stats) => this.updateTelemetry(stats));

    // Initial load
    const currentStats = window.State.get('stats');
    if (currentStats) {
      this.updateTelemetry(currentStats);
    }
    this.loadRecentEvents();
    this.loadAnomalyCount();
  },

  updateTelemetry(stats) {
    if (!stats || !document.getElementById('val-total-events')) return;

    const dbStats = stats.database || {};
    const pipeline = stats.pipeline || {};
    const total = dbStats.total_events || 0;
    const eps = pipeline.current_eps || 0.0;
    const successful = pipeline.successful || 0;
    const failed = pipeline.failed || 0;
    const totalProcessed = successful + failed;
    const successRate = totalProcessed > 0 ? (successful / totalProcessed) * 100 : 100;

    // Metric cards
    document.getElementById('val-total-events').textContent = window.Utils.formatNumber(total);
    document.getElementById('val-pipeline-eps').textContent = window.Utils.formatEps(eps);
    document.getElementById('val-success-rate').textContent = `${successRate.toFixed(1)}%`;
    document.getElementById('sub-success-counts').textContent = `${window.Utils.formatNumber(successful)} / ${window.Utils.formatNumber(totalProcessed)} Parsed`;

    // Syslog daemon status
    const lVal = document.getElementById('overview-listener-val');
    if (lVal && stats.listener) {
      lVal.textContent = stats.listener.is_running 
        ? `Active (Port ${stats.listener.port})` 
        : 'Standby';
      lVal.style.color = stats.listener.is_running ? 'var(--accent-emerald)' : 'var(--text-primary)';
    }

    // Format distribution
    this.renderDistribution('dist-formats-body', 'badge-fmt-count', dbStats.by_format || {}, total, 'FORMATS', [
      '#0EA5E9', '#8B5CF6', '#10B981', '#F59E0B', '#EC4899', '#6366F1'
    ]);

    // Category distribution
    this.renderDistribution('dist-categories-body', 'badge-cat-count', dbStats.by_category || {}, total, 'CATEGORIES', [
      '#38BDF8', '#2563EB', '#10B981', '#F59E0B', '#A855F7', '#64748B'
    ]);

    // Severity histogram
    this.renderSeverityHistogram(dbStats.by_severity || {});
  },

  renderDistribution(containerId, badgeId, distMap, totalEvents, badgeUnit, colors) {
    const el = document.getElementById(containerId);
    const badgeEl = document.getElementById(badgeId);
    if (!el) return;

    const entries = Object.entries(distMap).sort((a, b) => b[1] - a[1]);
    if (badgeEl) badgeEl.textContent = `${entries.length} ${badgeUnit}`;

    if (entries.length === 0 || totalEvents === 0) {
      el.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-title">No data recorded</div>
          <div class="empty-state-text">Pipeline is awaiting incoming telemetry.</div>
        </div>
      `;
      return;
    }

    let html = '';
    entries.slice(0, 5).forEach(([name, count], idx) => {
      const pct = totalEvents > 0 ? ((count / totalEvents) * 100).toFixed(1) : '0';
      const color = colors[idx % colors.length];
      html += `
        <div class="dist-bar-container">
          <div class="dist-bar-meta">
            <span style="font-weight:600;color:var(--text-primary);text-transform:uppercase;">${window.Utils.escapeHtml(name)}</span>
            <span class="mono" style="color:var(--text-secondary);">${window.Utils.formatNumber(count)} (${pct}%)</span>
          </div>
          <div class="dist-bar-track">
            <div class="dist-bar-fill" style="width:${pct}%;background-color:${color};"></div>
          </div>
        </div>
      `;
    });
    el.innerHTML = html;
  },

  renderSeverityHistogram(bySeverity) {
    const el = document.getElementById('severity-histogram-bars');
    if (!el) return;

    let maxCount = 1;
    for (let s = 0; s <= 10; s++) {
      const c = bySeverity[s] || 0;
      if (c > maxCount) maxCount = c;
    }

    let html = '';
    for (let s = 0; s <= 10; s++) {
      const count = bySeverity[s] || 0;
      const heightPct = Math.max(3, Math.round((count / maxCount) * 100));
      html += `
        <div class="histogram-col" title="Severity ${s}: ${count} events">
          <div class="histogram-bar" style="height:${heightPct}%;"></div>
          <span class="histogram-label">${s}</span>
        </div>
      `;
    }
    el.innerHTML = html;
  },

  async loadAnomalyCount() {
    try {
      const res = await window.Api.getAnomalies(50);
      const count = res?.count || (res?.anomalies ? res.anomalies.length : 0);
      const valEl = document.getElementById('val-anomalies-count');
      if (valEl) valEl.textContent = window.Utils.formatNumber(count);
      const badge = document.getElementById('badge-anom-count');
      if (badge) badge.textContent = count;
    } catch {
      // Non-fatal
    }
  },

  async loadRecentEvents() {
    const tbody = document.getElementById('recent-events-tbody');
    if (!tbody) return;

    try {
      const res = await window.Api.getEvents({ limit: 5 });
      const events = res?.events || [];

      if (events.length === 0) {
        tbody.innerHTML = `
          <tr><td colspan="7" style="text-align:center;padding:24px;color:var(--text-muted);">
            No events stored yet. Use the Ingestion Engine to ingest sample logs.
          </td></tr>
        `;
        return;
      }

      let rowsHtml = '';
      events.forEach((ev) => {
        const timeStr = window.Utils.formatDate(ev.timestamp);
        const fmtHtml = window.Utils.formatPillHtml(ev.raw_format);
        const sevHtml = window.Utils.severityBadgeHtml(ev.severity);
        const src = ev.source?.ip || '—';
        const dst = ev.destination?.ip || '—';

        rowsHtml += `
          <tr data-event-id="${window.Utils.escapeHtml(ev.event_id)}" style="cursor:pointer;">
            <td class="mono">${timeStr}</td>
            <td>${fmtHtml}</td>
            <td><span class="badge badge-info">${window.Utils.escapeHtml(ev.category || 'other')}</span></td>
            <td>${sevHtml}</td>
            <td class="mono">${window.Utils.escapeHtml(src)}</td>
            <td class="mono">${window.Utils.escapeHtml(dst)}</td>
            <td><span class="badge badge-neutral">${window.Utils.escapeHtml(ev.action || 'allow')}</span></td>
          </tr>
        `;
      });
      tbody.innerHTML = rowsHtml;

      // Attach row click listeners for inspection drawer
      tbody.querySelectorAll('tr').forEach((row, idx) => {
        row.addEventListener('click', () => {
          if (events[idx]) window.Drawer.inspect(events[idx]);
        });
      });
    } catch (e) {
      tbody.innerHTML = `
        <tr><td colspan="7" style="text-align:center;padding:24px;color:var(--accent-red);">
          Error retrieving recent events: ${window.Utils.escapeHtml(e.message)}
        </td></tr>
      `;
    }
  },

  destroy() {
    if (this.unsubscribe) {
      this.unsubscribe();
      this.unsubscribe = null;
    }
  }
};

window.OverviewView = OverviewView;
