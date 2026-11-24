/**
 * ULPF Ingestion Engine View
 * File upload, batch stream injection, and network syslog daemon controls.
 * 100% Dynamic Data Flow.
 */

const IngestionView = {
  container: null,

  async render(targetEl) {
    this.container = targetEl;
    this.container.innerHTML = `
      <!-- Syslog Daemon Control Panel -->
      <div class="card" style="margin-bottom:20px;">
        <div class="card-header">
          <div>
            <h3 class="card-title">Network Syslog Ingestion Daemon</h3>
            <span class="card-subtitle">Asyncio UDP & TCP high-throughput socket listeners</span>
          </div>
          <span class="badge" id="listener-badge-status">CHECKING...</span>
        </div>
        <div class="card-body">
          <div class="listener-control-bar">
            <div style="display:flex;align-items:center;gap:16px;">
              <div>
                <span style="font-size:11px;font-weight:700;color:var(--text-muted);">HOST BIND</span>
                <div class="mono" style="font-size:13px;color:var(--text-primary);" id="lbl-listener-host">0.0.0.0</div>
              </div>
              <div>
                <span style="font-size:11px;font-weight:700;color:var(--text-muted);">PORT</span>
                <div class="mono" style="font-size:13px;color:var(--accent-cyan);" id="lbl-listener-port">5514</div>
              </div>
              <div>
                <span style="font-size:11px;font-weight:700;color:var(--text-muted);">PACKETS INGESTED</span>
                <div class="mono" style="font-size:13px;color:var(--accent-emerald);" id="lbl-listener-packets">0</div>
              </div>
            </div>
            <div style="display:flex;gap:10px;">
              <button class="btn btn-primary btn-sm" id="btn-toggle-listener">Start Daemon</button>
            </div>
          </div>
        </div>
      </div>

      <!-- 2-Column Ingestion Workspace -->
      <div class="view-grid-2col">
        <!-- Left: File Upload Dropzone -->
        <div class="card">
          <div class="card-header">
            <div>
              <h3 class="card-title">Log File Upload</h3>
              <span class="card-subtitle">Batch parse and insert into DuckDB (.log, .txt, .csv, .json)</span>
            </div>
          </div>
          <div class="card-body">
            <div class="dropzone" id="file-dropzone">
              <div class="dropzone-icon">⬢</div>
              <div class="dropzone-title">Click or drag log files here</div>
              <div class="dropzone-subtitle">Supports CEF, LEEF, Syslog, JSON, XML, Fortigate KV, W3C</div>
              <input type="file" id="file-input-el" style="display:none;" />
            </div>

            <div id="file-progress-container" style="display:none;margin-top:16px;">
              <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:6px;">
                <span id="file-progress-name">Uploading...</span>
                <span id="file-progress-pct" class="mono">Processing</span>
              </div>
              <div class="dist-bar-track">
                <div class="dist-bar-fill" id="file-progress-fill" style="width:100%;background-color:var(--accent-cyan);"></div>
              </div>
            </div>
          </div>
        </div>

        <!-- Right: Raw Log Stream Injection -->
        <div class="card">
          <div class="card-header">
            <div>
              <h3 class="card-title">Direct Stream Injection</h3>
              <span class="card-subtitle">Inject live raw log lines directly into the pipeline</span>
            </div>
          </div>
          <div class="card-body">
            <div class="input-group" style="margin-bottom:12px;">
              <div style="display:flex;justify-content:space-between;align-items:center;">
                <label class="input-label">RAW LOG BUFFER</label>
                <div style="display:flex;gap:6px;">
                  <button class="btn btn-secondary btn-sm" id="btn-load-cef" style="padding:2px 6px;font-size:10.5px;">CEF</button>
                  <button class="btn btn-secondary btn-sm" id="btn-load-leef" style="padding:2px 6px;font-size:10.5px;">LEEF</button>
                  <button class="btn btn-secondary btn-sm" id="btn-load-syslog" style="padding:2px 6px;font-size:10.5px;">Syslog</button>
                  <button class="btn btn-secondary btn-sm" id="btn-load-waf" style="padding:2px 6px;font-size:10.5px;">WAF JSON</button>
                </div>
              </div>
              <textarea class="textarea-input" id="raw-log-input" rows="5" placeholder="Paste single or multi-line raw logs..."></textarea>
            </div>
            <div style="display:flex;justify-content:flex-end;gap:10px;">
              <button class="btn btn-secondary btn-sm" id="btn-clear-buffer">Clear</button>
              <button class="btn btn-primary btn-sm" id="btn-submit-raw">Process & Ingest</button>
            </div>
          </div>
        </div>
      </div>

      <!-- Ingestion Pipeline Output Terminal -->
      <div class="card">
        <div class="card-header">
          <div>
            <h3 class="card-title">Live Ingestion Telemetry Output</h3>
            <span class="card-subtitle">Detailed parse metrics, classification latency, and anomaly results</span>
          </div>
          <button class="btn btn-secondary btn-sm" id="btn-clear-terminal">Clear Console</button>
        </div>
        <div class="card-body">
          <pre class="terminal-box" id="ingestion-console">> ULPF zero-copy columnar ingestion core ready.
> Waiting for log payloads or live socket stream...
</pre>
        </div>
      </div>
    `;

    this.initListeners();
    this.refreshDaemonStatus();
  },

  logConsole(msg) {
    const term = document.getElementById('ingestion-console');
    if (!term) return;
    const time = new Date().toISOString().substring(11, 19);
    term.textContent += `[${time}] ${msg}\n`;
    term.scrollTop = term.scrollHeight;
  },

  async refreshDaemonStatus() {
    try {
      const status = await window.Api.getListenerStatus();
      const badge = document.getElementById('listener-badge-status');
      const toggleBtn = document.getElementById('btn-toggle-listener');
      const hostEl = document.getElementById('lbl-listener-host');
      const portEl = document.getElementById('lbl-listener-port');
      const pktsEl = document.getElementById('lbl-listener-packets');

      if (!badge) return;

      if (status.running || status.is_running) {
        badge.className = 'badge badge-success';
        badge.textContent = 'RUNNING';
        if (toggleBtn) {
          toggleBtn.textContent = 'Stop Daemon';
          toggleBtn.className = 'btn btn-danger btn-sm';
        }
      } else {
        badge.className = 'badge badge-neutral';
        badge.textContent = 'STOPPED';
        if (toggleBtn) {
          toggleBtn.textContent = 'Start Daemon';
          toggleBtn.className = 'btn btn-primary btn-sm';
        }
      }

      if (hostEl) hostEl.textContent = status.host || '0.0.0.0';
      if (portEl) portEl.textContent = status.port || 5514;
      if (pktsEl) pktsEl.textContent = window.Utils.formatNumber(status.packets || status.packets_received || 0);
    } catch {
      // Non-fatal
    }
  },

  initListeners() {
    const dz = document.getElementById('file-dropzone');
    const fileInput = document.getElementById('file-input-el');

    if (dz && fileInput) {
      dz.addEventListener('click', () => fileInput.click());
      dz.addEventListener('dragover', (e) => {
        e.preventDefault();
        dz.classList.add('dragover');
      });
      dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
      dz.addEventListener('drop', (e) => {
        e.preventDefault();
        dz.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
          this.handleFileUpload(e.dataTransfer.files[0]);
        }
      });
      fileInput.addEventListener('change', () => {
        if (fileInput.files.length) {
          this.handleFileUpload(fileInput.files[0]);
        }
      });
    }

    // Toggle listener
    document.getElementById('btn-toggle-listener')?.addEventListener('click', async () => {
      try {
        const status = await window.Api.getListenerStatus();
        if (status.running || status.is_running) {
          await window.Api.stopListener();
          window.Toast.show('Network syslog daemon stopped', 'info');
        } else {
          const res = await window.Api.startListener({ host: '0.0.0.0', port: 5514, protocol: 'both' });
          if (res.success) {
            window.Toast.show('Syslog daemon started on port 5514', 'success');
          } else {
            window.Toast.show(`Failed to start: ${res.error}`, 'error');
          }
        }
        this.refreshDaemonStatus();
      } catch (e) {
        window.Toast.show(`Daemon error: ${e.message}`, 'error');
      }
    });

    // Sample loaders
    document.getElementById('btn-load-cef')?.addEventListener('click', () => {
      document.getElementById('raw-log-input').value =
        'CEF:0|Check Point|VPN-1 & FireWall-1|R81.20|Accept|Firewall Rule Accept|3|src=198.51.100.20 dst=10.0.1.50 spt=52341 dpt=443 proto=TCP act=Accept';
    });
    document.getElementById('btn-load-leef')?.addEventListener('click', () => {
      document.getElementById('raw-log-input').value =
        'LEEF:2.0|IBM|QRadar Network Security|5.4|10001|src=203.0.113.195\tdst=192.168.1.10\tspt=45123\tdpt=80\tproto=TCP\tdevTimeFormat=MMM dd yyyy HH:mm:ss\tdevTime=Sep 27 2026 10:14:00';
    });
    document.getElementById('btn-load-syslog')?.addEventListener('click', () => {
      document.getElementById('raw-log-input').value =
        '<134>1 2026-09-27T10:15:30.123Z border-gw-01.corp sshd 4129 - - Failed password for invalid user admin from 198.51.100.77 port 49152 ssh2';
    });
    document.getElementById('btn-load-waf')?.addEventListener('click', () => {
      document.getElementById('raw-log-input').value =
        '{"timestamp": "2026-09-27T10:15:30Z", "client_ip": "198.51.100.99", "uri": "/login.php", "method": "POST", "status": 403, "rule_id": "WAF_SQLI_01", "action": "block"}';
    });

    document.getElementById('btn-clear-buffer')?.addEventListener('click', () => {
      document.getElementById('raw-log-input').value = '';
    });

    document.getElementById('btn-clear-terminal')?.addEventListener('click', () => {
      document.getElementById('ingestion-console').textContent = '> Console cleared.\n';
    });

    // Submit raw
    document.getElementById('btn-submit-raw')?.addEventListener('click', async () => {
      const text = document.getElementById('raw-log-input').value.trim();
      if (!text) {
        window.Toast.show('Please enter at least one log line', 'warning');
        return;
      }

      const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 0);
      try {
        this.logConsole(`Transmitting payload of ${lines.length} event(s) to pipeline...`);
        let res;
        if (lines.length === 1) {
          res = await window.Api.ingestRaw(lines[0]);
          this.logConsole(`[SUCCESS] Normalized via ${res.event?.metadata?.parser_id || 'parser'}. Event ID: ${res.event?.event_id}`);
          if (res.anomalies && res.anomalies.length > 0) {
            this.logConsole(`[ANOMALY DETECTED] ${res.anomalies.map(a => a.reason).join(', ')}`);
          }
        } else {
          res = await window.Api.ingestBatch(lines);
          this.logConsole(`[BATCH INGESTED] Processed: ${res.total}, Success: ${res.successful}, Stored: ${res.stored}, Anomalies: ${res.anomalies_detected}`);
        }

        window.Toast.show(`Ingested ${lines.length} event(s) successfully`, 'success');
        document.getElementById('raw-log-input').value = '';
        window.State.fetchLatestStats();
      } catch (err) {
        this.logConsole(`[ERROR] Ingestion failed: ${err.message}`);
        window.Toast.show(`Ingestion failed: ${err.message}`, 'error');
      }
    });
  },

  async handleFileUpload(file) {
    if (!file) return;
    const progressBox = document.getElementById('file-progress-container');
    const progressName = document.getElementById('file-progress-name');
    if (progressBox) progressBox.style.display = 'block';
    if (progressName) progressName.textContent = `Uploading & Parsing ${file.name} (${window.Utils.formatBytes(file.size)})...`;

    this.logConsole(`Beginning streaming upload of file: ${file.name}...`);
    try {
      const res = await window.Api.ingestFile(file);
      this.logConsole(`[FILE COMPLETE] ${file.name} parsed: ${res.successful} events inserted into DuckDB in ${res.pipeline_metrics?.total_processing_time_ms?.toFixed(1) || '0'}ms.`);
      window.Toast.show(`Parsed ${res.successful} events from ${file.name}`, 'success');
      window.State.fetchLatestStats();
    } catch (e) {
      this.logConsole(`[FILE ERROR] Failed parsing ${file.name}: ${e.message}`);
      window.Toast.show(`Upload failed: ${e.message}`, 'error');
    } finally {
      if (progressBox) progressBox.style.display = 'none';
    }
  },

  destroy() {}
};

window.IngestionView = IngestionView;
