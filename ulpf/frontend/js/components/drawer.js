/**
 * ULPF Sliding Inspection Drawer Component
 * Deep forensic and semantic inspection of a single event.
 */

const Drawer = {
  container: null,

  init() {
    this.container = document.getElementById('drawer-container');
    if (this.container) {
      this.container.addEventListener('click', (e) => {
        if (e.target === this.container) {
          this.close();
        }
      });
    }
  },

  inspect(event) {
    if (!this.container) this.init();
    if (!this.container || !event) return;

    const eventId = event.event_id || 'unknown';
    const rawFmt = event.raw_format || 'unknown';
    const timestamp = event.timestamp || '';
    const rawEvent = event.raw_event || '';
    const category = event.category || 'other';
    const action = event.action || 'other';
    const severity = event.severity || 0;
    const rawHash = event.evidence?.raw_hash || event.metadata?.raw_hash_sha256 || '—';

    // Endpoints
    const srcIp = event.source?.ip || '—';
    const srcPort = event.source?.port || '—';
    const dstIp = event.destination?.ip || '—';
    const dstPort = event.destination?.port || '—';
    const proto = event.network?.protocol || '—';

    this.container.innerHTML = `
      <div class="drawer-panel">
        <div class="drawer-header">
          <div>
            <div style="font-size:11px;font-weight:700;color:var(--text-muted);letter-spacing:0.8px;">EVENT INSPECTOR</div>
            <h3 style="font-size:16px;font-weight:700;color:#FFFFFF;font-family:var(--font-mono);margin-top:2px;">
              ${window.Utils.escapeHtml(eventId.substring(0, 18))}...
            </h3>
          </div>
          <button class="btn btn-secondary btn-sm" id="drawer-close-btn" style="padding:4px 8px;">✕</button>
        </div>

        <div class="drawer-content">
          <!-- Overview Tags -->
          <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px;">
            ${window.Utils.formatPillHtml(rawFmt)}
            ${window.Utils.severityBadgeHtml(severity)}
            <span class="badge badge-info">${window.Utils.escapeHtml(category)}</span>
            <span class="badge badge-neutral">${window.Utils.escapeHtml(action)}</span>
          </div>

          <!-- Network Endpoints Section -->
          <div class="card" style="margin-bottom:16px;padding:14px;">
            <div style="font-size:11px;font-weight:700;color:var(--text-muted);margin-bottom:8px;">NETWORK CONTEXT</div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:12px;">
              <div>
                <span style="color:var(--text-muted);">Source:</span>
                <span class="mono" style="color:var(--text-primary);margin-left:4px;">${window.Utils.escapeHtml(srcIp)}:${window.Utils.escapeHtml(srcPort)}</span>
              </div>
              <div>
                <span style="color:var(--text-muted);">Destination:</span>
                <span class="mono" style="color:var(--text-primary);margin-left:4px;">${window.Utils.escapeHtml(dstIp)}:${window.Utils.escapeHtml(dstPort)}</span>
              </div>
              <div>
                <span style="color:var(--text-muted);">Protocol:</span>
                <span class="mono" style="color:var(--text-primary);margin-left:4px;">${window.Utils.escapeHtml(proto)}</span>
              </div>
              <div>
                <span style="color:var(--text-muted);">Normalized Time:</span>
                <span class="mono" style="color:var(--text-primary);margin-left:4px;">${window.Utils.formatDate(timestamp)}</span>
              </div>
            </div>
          </div>

          <!-- Cryptographic Hash Verification -->
          <div class="card" style="margin-bottom:16px;padding:14px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
              <span style="font-size:11px;font-weight:700;color:var(--text-muted);">SHA-256 PROVENANCE HASH</span>
              <button class="btn btn-secondary btn-sm" style="padding:2px 8px;font-size:11px;" id="btn-copy-hash">Copy</button>
            </div>
            <div class="mono" style="font-size:11px;color:var(--accent-cyan);word-break:break-all;">
              ${window.Utils.escapeHtml(rawHash)}
            </div>
          </div>

          <!-- Verbatim Raw Event -->
          <div class="card" style="margin-bottom:16px;padding:14px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
              <span style="font-size:11px;font-weight:700;color:var(--text-muted);">RAW EVENT PRESERVATION</span>
              <button class="btn btn-secondary btn-sm" style="padding:2px 8px;font-size:11px;" id="btn-copy-raw">Copy Raw</button>
            </div>
            <pre class="terminal-box" style="height:120px;font-size:11px;margin:0;">${window.Utils.escapeHtml(rawEvent)}</pre>
          </div>

          <!-- Normalized OCSF JSON -->
          <div class="card" style="padding:14px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
              <span style="font-size:11px;font-weight:700;color:var(--text-muted);">NORMALIZED OCSF JSON</span>
              <button class="btn btn-secondary btn-sm" style="padding:2px 8px;font-size:11px;" id="btn-copy-json">Copy JSON</button>
            </div>
            <pre class="terminal-box" style="height:240px;font-size:11px;margin:0;">${window.Utils.escapeHtml(JSON.stringify(event, null, 2))}</pre>
          </div>
        </div>
      </div>
    `;

    document.getElementById('drawer-close-btn')?.addEventListener('click', () => this.close());
    document.getElementById('btn-copy-hash')?.addEventListener('click', () => window.Utils.copyToClipboard(rawHash));
    document.getElementById('btn-copy-raw')?.addEventListener('click', () => window.Utils.copyToClipboard(rawEvent));
    document.getElementById('btn-copy-json')?.addEventListener('click', () => window.Utils.copyToClipboard(JSON.stringify(event, null, 2)));

    this.container.classList.remove('hidden');
  },

  close() {
    if (!this.container) this.init();
    if (this.container) {
      this.container.classList.add('hidden');
    }
  }
};

window.Drawer = Drawer;
