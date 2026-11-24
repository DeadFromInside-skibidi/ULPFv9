/**
 * ULPF Autonomous Parser Synthesis (Auto-Learn JIT) View
 * Template mining, invariant classification, and dynamic regex compilation.
 * 100% Dynamic Data Flow.
 */

const AutoLearnView = {
  container: null,

  async render(targetEl) {
    this.container = targetEl;
    this.container.innerHTML = `
      <!-- Action Workspace -->
      <div class="view-grid-2col">
        <!-- Synthesizer Input -->
        <div class="card">
          <div class="card-header">
            <div>
              <h3 class="card-title">Autonomous Template Synthesizer</h3>
              <span class="card-subtitle">Mine templates from unparsed log samples and generate JIT regex</span>
            </div>
          </div>
          <div class="card-body">
            <div class="input-group" style="margin-bottom:12px;">
              <div style="display:flex;justify-content:space-between;align-items:center;">
                <label class="input-label">UNPARSED LOG LINES (3+ RECOMMENDED)</label>
                <button class="btn btn-secondary btn-sm" id="btn-load-learn-sample" style="padding:2px 6px;font-size:10.5px;">Load Sample</button>
              </div>
              <textarea class="textarea-input" id="learn-lines-input" rows="5" placeholder="Paste 3 or more similar log lines from an unknown source to synthesize an automated parser..."></textarea>
            </div>
            <button class="btn btn-primary btn-sm" id="btn-run-autolearn">
              ⚡ Synthesize Auto-Parser
            </button>
            <div id="autolearn-result-box" style="margin-top:16px;display:none;"></div>
          </div>
        </div>

        <!-- Mined Specifications Inventory -->
        <div class="card">
          <div class="card-header">
            <div>
              <h3 class="card-title">Synthesized Parsers Catalog</h3>
              <span class="card-subtitle">Auto-generated configs persisted in learned_parsers</span>
            </div>
            <button class="btn btn-secondary btn-sm" id="btn-refresh-configs">Refresh</button>
          </div>
          <div class="card-body">
            <div id="configs-list-container">
              <div style="text-align:center;padding:32px;color:var(--text-muted);">
                Scanning learned parser catalog...
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    this.initListeners();
    this.loadConfigs();
  },

  initListeners() {
    document.getElementById('btn-load-learn-sample')?.addEventListener('click', () => {
      document.getElementById('learn-lines-input').value = [
        '2026-09-27 10:00:01 [AUTH] user=jdoe client=198.51.100.50 status=FAIL reason="invalid_token"',
        '2026-09-27 10:00:02 [AUTH] user=asmith client=198.51.100.51 status=FAIL reason="bad_password"',
        '2026-09-27 10:00:04 [AUTH] user=admin client=10.0.0.1 status=SUCCESS reason="authenticated"'
      ].join('\n');
    });

    document.getElementById('btn-refresh-configs')?.addEventListener('click', () => this.loadConfigs());

    document.getElementById('btn-run-autolearn')?.addEventListener('click', async () => {
      const raw = document.getElementById('learn-lines-input').value.trim();
      const lines = raw ? raw.split('\n').map(l => l.trim()).filter(l => l.length > 0) : [];
      const resBox = document.getElementById('autolearn-result-box');

      if (lines.length < 2) {
        window.Toast.show('Please provide at least 2 lines to mine common invariants', 'warning');
        return;
      }

      try {
        window.Toast.show('Mining structural template and compiling regex...', 'info');
        const res = await window.Api.autoLearn(lines);
        if (resBox) {
          resBox.style.display = 'block';
          resBox.innerHTML = `
            <div class="card" style="background-color:var(--bg-surface);padding:14px;border-color:var(--accent-cyan);">
              <div style="font-size:12px;font-weight:700;color:var(--accent-cyan);margin-bottom:6px;">SYNTHESIZED PARSER SPECIFICATION</div>
              <div style="display:flex;gap:10px;font-size:12px;margin-bottom:8px;">
                <span class="mono">ID: ${window.Utils.escapeHtml(res.parser_id || 'synthesized_parser')}</span>
                <span class="badge badge-success">${res.fields || 4} Extracted Fields</span>
              </div>
              <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px;">Mined Structural Template:</div>
              <pre class="terminal-box" style="height:70px;font-size:11px;margin:0;">${window.Utils.escapeHtml(res.template || '')}</pre>
            </div>
          `;
        }
        window.Toast.show('Parser synthesized successfully', 'success');
        this.loadConfigs();
      } catch (e) {
        window.Toast.show(`Synthesis failed: ${e.message}`, 'error');
      }
    });
  },

  async loadConfigs() {
    const container = document.getElementById('configs-list-container');
    if (!container) return;

    try {
      const data = await window.Api.getAutoLearnConfigs();
      const configs = data.configs || [];

      if (configs.length === 0) {
        container.innerHTML = `
          <div class="empty-state">
            <div class="empty-state-title">No Auto-Learned Parsers</div>
            <div class="empty-state-text">Paste sample log lines on the left to synthesize new parsers dynamically.</div>
          </div>
        `;
        return;
      }

      let html = '<div style="display:flex;flex-direction:column;gap:10px;">';
      configs.forEach(c => {
        const id = c.parser_id || (typeof c === 'string' ? c : 'auto_parser');
        const ver = c.version || 1;
        const fields = c.fields ? c.fields.length : '—';
        html += `
          <div class="card" style="padding:12px;background-color:var(--bg-surface);">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <span class="mono" style="color:var(--accent-cyan);font-weight:600;">${window.Utils.escapeHtml(id)} (v${ver})</span>
              <span class="badge badge-info">${fields} Fields</span>
            </div>
          </div>
        `;
      });
      html += '</div>';
      container.innerHTML = html;
    } catch {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-title">Autonomous Learning Plane Ready</div>
          <div class="empty-state-text">Synthesize parsers using the form on the left.</div>
        </div>
      `;
    }
  },

  destroy() {}
};

window.AutoLearnView = AutoLearnView;
