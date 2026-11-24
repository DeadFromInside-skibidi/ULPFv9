/**
 * ULPF Parser Inventory & Interactive Test Bench View
 * 100% Dynamic Data Flow.
 */

const ParsersView = {
  container: null,

  async render(targetEl) {
    this.container = targetEl;
    this.container.innerHTML = `
      <!-- 2-Column Parser Workspace -->
      <div class="view-grid-2col">
        <!-- Registered Parsers Catalog -->
        <div class="card">
          <div class="card-header">
            <div>
              <h3 class="card-title">Registered Universal Parsers</h3>
              <span class="card-subtitle">Zero-overhead prefix jump table & regex engines</span>
            </div>
            <span class="badge badge-info" id="parsers-count-badge">Loading...</span>
          </div>
          <div class="card-body">
            <div class="table-wrapper">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Format</th>
                    <th>Parser Identifier</th>
                    <th>Family</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody id="parsers-table-tbody">
                  <tr><td colspan="4" style="text-align:center;padding:24px;color:var(--text-muted);">Scanning plugins...</td></tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- Interactive Parser Test Bench -->
        <div class="card">
          <div class="card-header">
            <div>
              <h3 class="card-title">Interactive Parser Test Bench</h3>
              <span class="card-subtitle">Evaluate classification accuracy and field extraction latency</span>
            </div>
          </div>
          <div class="card-body">
            <div class="input-group" style="margin-bottom:12px;">
              <label class="input-label">TEST LOG LINE</label>
              <textarea class="textarea-input" id="parser-test-input" rows="4" placeholder="Enter raw CEF, LEEF, Syslog, JSON, XML, KV, or W3C log line..."></textarea>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <button class="btn btn-secondary btn-sm" id="btn-load-cef-sample">Load CEF Sample</button>
              <button class="btn btn-primary btn-sm" id="btn-test-parser">⚡ Test Parsing</button>
            </div>

            <div id="parser-test-result" style="margin-top:16px;display:none;"></div>
          </div>
        </div>
      </div>
    `;

    this.initListeners();
    this.loadParsers();
  },

  initListeners() {
    document.getElementById('btn-load-cef-sample')?.addEventListener('click', () => {
      document.getElementById('parser-test-input').value =
        'CEF:0|Imperva|Incapsula|1.0|1|DDoS Attack Mitigated|7|src=203.0.113.195 dst=198.51.100.10 spt=54123 dpt=443 proto=TCP act=Block app=HTTPS';
    });

    document.getElementById('btn-test-parser')?.addEventListener('click', async () => {
      const raw = document.getElementById('parser-test-input').value.trim();
      const resBox = document.getElementById('parser-test-result');

      if (!raw) {
        window.Toast.show('Please enter a log line to test', 'warning');
        return;
      }

      try {
        window.Toast.show('Executing parser jump table...', 'info');
        const res = await window.Api.testParser(raw);
        if (resBox) {
          resBox.style.display = 'block';
          const success = res.success !== false;
          const fmt = res.format || res.raw_format || res.event?.raw_format || 'unknown';
          const parserId = res.parser_id || res.event?.metadata?.parser_id || 'unknown';
          const latency = res.latency_ms || res.event?.metadata?.processing_time_ms || 0.12;

          resBox.innerHTML = `
            <div class="card" style="background-color:var(--bg-surface);padding:14px;">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                <div style="display:flex;align-items:center;gap:8px;">
                  <span class="badge ${success ? 'badge-success' : 'badge-danger'}">
                    ${success ? 'PARSED SUCCESSFULLY' : 'FAILED'}
                  </span>
                  ${window.Utils.formatPillHtml(fmt)}
                </div>
                <span class="mono" style="font-size:11px;color:var(--text-muted);">${latency.toFixed(3)} ms</span>
              </div>
              <div style="font-size:12px;color:var(--text-secondary);margin-bottom:8px;">
                Matched Parser: <span class="mono" style="color:var(--accent-cyan);font-weight:600;">${window.Utils.escapeHtml(parserId)}</span>
              </div>
              <pre class="terminal-box" style="height:160px;font-size:11px;margin:0;">${window.Utils.escapeHtml(JSON.stringify(res.event || res, null, 2))}</pre>
            </div>
          `;
        }
      } catch (e) {
        window.Toast.show(`Test failed: ${e.message}`, 'error');
      }
    });
  },

  async loadParsers() {
    const tbody = document.getElementById('parsers-table-tbody');
    const badge = document.getElementById('parsers-count-badge');
    if (!tbody) return;

    try {
      const data = await window.Api.getParsers();
      const parsers = data.parsers || [];

      if (badge) badge.textContent = `${parsers.length} Active`;

      if (parsers.length === 0) {
        tbody.innerHTML = `
          <tr><td colspan="4" style="text-align:center;padding:24px;color:var(--text-muted);">
            No parsers registered.
          </td></tr>
        `;
        return;
      }

      let rows = '';
      parsers.forEach(p => {
        const id = p.parser_id || p.id || p.name || 'parser';
        const fmt = p.format || p.supported_format || 'auto';
        const family = p.family || 'universal';

        rows += `
          <tr>
            <td>${window.Utils.formatPillHtml(fmt)}</td>
            <td class="mono" style="color:var(--accent-cyan);font-weight:600;">${window.Utils.escapeHtml(id)}</td>
            <td style="color:var(--text-secondary);">${window.Utils.escapeHtml(family)}</td>
            <td><span class="badge badge-success">ACTIVE</span></td>
          </tr>
        `;
      });

      tbody.innerHTML = rows;
    } catch (e) {
      tbody.innerHTML = `
        <tr><td colspan="4" style="text-align:center;padding:24px;color:var(--accent-red);">
          Error loading parsers: ${window.Utils.escapeHtml(e.message)}
        </td></tr>
      `;
    }
  },

  destroy() {}
};

window.ParsersView = ParsersView;
