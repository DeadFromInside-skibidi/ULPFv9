/**
 * ULPF Correlation Engine View
 * Multi-source temporal and indicator clustering with MITRE ATT&CK mapping.
 * 100% Dynamic Data Flow — Core Feature 1.
 */

const CorrelationView = {
  container: null,

  async render(targetEl) {
    this.container = targetEl;
    this.container.innerHTML = `
      <!-- Controls Toolbar -->
      <div class="filter-toolbar">
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;flex:1;">
          <div class="input-group" style="min-width:160px;">
            <label class="input-label">SLIDING TIME WINDOW</label>
            <select class="select-input" id="corr-window-select">
              <option value="60">1 Minute (60s)</option>
              <option value="300" selected>5 Minutes (300s)</option>
              <option value="600">10 Minutes (600s)</option>
              <option value="3600">1 Hour (3600s)</option>
            </select>
          </div>

          <div class="input-group" style="min-width:140px;">
            <label class="input-label">ANALYSIS DEPTH</label>
            <select class="select-input" id="corr-limit-select">
              <option value="50">Last 50 Events</option>
              <option value="150" selected>Last 150 Events</option>
              <option value="500">Last 500 Events</option>
            </select>
          </div>
        </div>

        <button class="btn btn-primary" id="btn-run-correlate">
          <span>⚡ Run Correlation Engine</span>
        </button>
      </div>

      <!-- Live Correlation Results Header -->
      <div class="view-grid-top-metrics">
        <div class="metric-card">
          <span class="metric-label">EVENTS ANALYZED</span>
          <span class="metric-value" id="corr-analyzed-val">0</span>
          <span class="metric-sub">Events within time window</span>
        </div>
        <div class="metric-card warning">
          <span class="metric-label">CORRELATION CLUSTERS</span>
          <span class="metric-value" id="corr-clusters-val">0</span>
          <span class="metric-sub">Shared indicators & temporal links</span>
        </div>
        <div class="metric-card danger">
          <span class="metric-label">MITRE ATT&CK PHASES</span>
          <span class="metric-value" id="corr-mitre-val">0</span>
          <span class="metric-sub">Kill chain stages identified</span>
        </div>
      </div>

      <!-- Clusters Container -->
      <div id="corr-clusters-container">
        <div class="card">
          <div class="card-body" style="text-align:center;padding:48px;color:var(--text-muted);">
            Running correlation analysis against DuckDB events...
          </div>
        </div>
      </div>
    `;

    document.getElementById('btn-run-correlate')?.addEventListener('click', () => this.runCorrelation());
    document.getElementById('corr-window-select')?.addEventListener('change', () => this.runCorrelation());
    document.getElementById('corr-limit-select')?.addEventListener('change', () => this.runCorrelation());

    this.runCorrelation();
  },

  async runCorrelation() {
    const container = document.getElementById('corr-clusters-container');
    const windowSec = parseFloat(document.getElementById('corr-window-select')?.value || '300');
    const limit = parseInt(document.getElementById('corr-limit-select')?.value || '150', 10);

    if (container) {
      container.innerHTML = `
        <div class="card">
          <div class="card-body" style="text-align:center;padding:40px;color:var(--text-muted);">
            <div style="font-size:14px;font-weight:600;color:var(--text-primary);margin-bottom:6px;">Correlating Events...</div>
            Scanning shared IPs, usernames, session IDs, and sliding windows.
          </div>
        </div>
      `;
    }

    try {
      const data = await window.Api.postCorrelate({
        limit: limit,
        time_window_seconds: windowSec
      });

      const analyzed = data.events_analysed || 0;
      const groups = data.groups || [];
      const groupCount = data.correlation_groups || groups.length;

      document.getElementById('corr-analyzed-val').textContent = window.Utils.formatNumber(analyzed);
      document.getElementById('corr-clusters-val').textContent = window.Utils.formatNumber(groupCount);

      // Collect all unique MITRE stages
      const allMitre = new Set();
      groups.forEach(g => {
        (g.mitre_tactics || g.mitre_stages || []).forEach(m => allMitre.add(m));
      });
      document.getElementById('corr-mitre-val').textContent = allMitre.size;

      if (!container) return;

      if (groups.length === 0) {
        container.innerHTML = `
          <div class="card">
            <div class="card-body empty-state">
              <div class="empty-state-title">No Correlation Clusters Detected</div>
              <div class="empty-state-text">
                ${analyzed > 0 
                  ? `Analyzed ${analyzed} events within ${windowSec}s window, but no shared indicators crossed the correlation threshold.`
                  : 'Database currently has no stored events to correlate. Ingest logs via Ingestion Engine first.'}
              </div>
            </div>
          </div>
        `;
        return;
      }

      let html = '';
      groups.forEach((grp, idx) => {
        const events = grp.events || [];
        const entities = grp.entities || grp.shared_indicators || [];
        const mitreList = grp.mitre_tactics || grp.mitre_stages || [];
        const title = grp.title || grp.description || `Correlation Group #${idx + 1}`;
        const confidence = grp.confidence ? `${(grp.confidence * 100).toFixed(0)}% Confidence` : 'Multi-Event Correlation';

        html += `
          <div class="correlation-group-card">
            <div class="correlation-group-header">
              <div>
                <div style="display:flex;align-items:center;gap:8px;">
                  <span style="font-size:14px;font-weight:700;color:#FFFFFF;">${window.Utils.escapeHtml(title)}</span>
                  <span class="badge badge-warning">${confidence}</span>
                  <span class="badge badge-info">${events.length} Events</span>
                </div>
                <div style="font-size:12px;color:var(--text-muted);margin-top:2px;">
                  Timespan: ${window.Utils.formatDate(grp.start_time || grp.time_range?.start)} → ${window.Utils.formatDate(grp.end_time || grp.time_range?.end)}
                </div>
              </div>
            </div>

            <div style="padding:16px 20px;">
              <!-- MITRE ATT&CK Stages -->
              ${mitreList.length > 0 ? `
                <div style="margin-bottom:12px;">
                  <div style="font-size:11px;font-weight:700;color:var(--text-muted);margin-bottom:6px;">MITRE ATT&CK KILL-CHAIN PHASES</div>
                  <div class="mitre-badge-row">
                    ${mitreList.map(m => `<span class="mitre-pill">${window.Utils.escapeHtml(m)}</span>`).join('')}
                  </div>
                </div>
              ` : ''}

              <!-- Shared Indicators -->
              ${entities.length > 0 ? `
                <div style="margin-bottom:14px;">
                  <div style="font-size:11px;font-weight:700;color:var(--text-muted);margin-bottom:4px;">CORRELATED ENTITIES / INDICATORS</div>
                  <div style="display:flex;flex-wrap:wrap;gap:6px;">
                    ${entities.map(ent => `<span class="mono badge badge-neutral">${window.Utils.escapeHtml(ent)}</span>`).join('')}
                  </div>
                </div>
              ` : ''}

              <!-- Event Sequence Table -->
              <div class="table-wrapper">
                <table class="data-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Format</th>
                      <th>Category</th>
                      <th>Severity</th>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>Message / Event</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${events.slice(0, 10).map(ev => `
                      <tr onclick="window.Drawer.inspect(${JSON.stringify(ev).replace(/"/g, '&quot;')})">
                        <td class="mono">${window.Utils.formatDate(ev.timestamp)}</td>
                        <td>${window.Utils.formatPillHtml(ev.raw_format)}</td>
                        <td><span class="badge badge-info">${window.Utils.escapeHtml(ev.category || 'other')}</span></td>
                        <td>${window.Utils.severityBadgeHtml(ev.severity)}</td>
                        <td class="mono">${window.Utils.escapeHtml(ev.source?.ip || '—')}</td>
                        <td class="mono">${window.Utils.escapeHtml(ev.destination?.ip || '—')}</td>
                        <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                          ${window.Utils.escapeHtml(ev.message || ev.raw_event || '—')}
                        </td>
                      </tr>
                    `).join('')}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        `;
      });

      container.innerHTML = html;
    } catch (e) {
      if (container) {
        container.innerHTML = `
          <div class="card">
            <div class="card-body" style="padding:32px;text-align:center;color:var(--accent-red);">
              Correlation error: ${window.Utils.escapeHtml(e.message)}
            </div>
          </div>
        `;
      }
    }
  },

  destroy() {}
};

window.CorrelationView = CorrelationView;
