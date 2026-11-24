/**
 * ULPF Columnar Log Explorer View
 * Full-text search and multi-attribute filtering across normalized DuckDB tables.
 * 100% Dynamic Data Flow.
 */

const ExplorerView = {
  container: null,
  currentEvents: [],
  offset: 0,
  limit: 25,
  currentQuery: '',

  async render(targetEl) {
    this.container = targetEl;
    this.container.innerHTML = `
      <!-- Filter Toolbar -->
      <div class="filter-toolbar">
        <div class="search-input-wrapper">
          <span class="search-icon">🔍</span>
          <input type="text" class="input-text" id="exp-search-input" placeholder="Full-text search message, raw strings, IP, or UUID..." />
        </div>

        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          <select class="select-input" id="exp-fmt-filter">
            <option value="">All Formats</option>
            <option value="cef">CEF</option>
            <option value="leef">LEEF</option>
            <option value="syslog">Syslog</option>
            <option value="json">JSON</option>
            <option value="xml">XML</option>
            <option value="kv">KV</option>
            <option value="w3c">W3C</option>
          </select>

          <select class="select-input" id="exp-cat-filter">
            <option value="">All Categories</option>
            <option value="firewall">Firewall</option>
            <option value="ids">IDS / Threat</option>
            <option value="auth">Authentication</option>
            <option value="web">Web Application</option>
            <option value="network">Network Traffic</option>
            <option value="system">Host System</option>
            <option value="other">Other</option>
          </select>

          <select class="select-input" id="exp-sev-filter">
            <option value="">All Severities</option>
            <option value="8">High & Critical (8+)</option>
            <option value="5">Medium & Above (5+)</option>
            <option value="1">Low & Above (1+)</option>
          </select>

          <button class="btn btn-secondary btn-sm" id="btn-reset-filters">Reset</button>
          <button class="btn btn-primary btn-sm" id="btn-query-refresh">Run Query</button>
        </div>
      </div>

      <!-- Events Columnar Table Card -->
      <div class="card">
        <div class="card-header">
          <div>
            <h3 class="card-title">Normalized Security Events</h3>
            <span class="card-subtitle" id="exp-result-count">Querying DuckDB columnar engine...</span>
          </div>
          <div style="display:flex;gap:8px;align-items:center;">
            <button class="btn btn-secondary btn-sm" id="btn-prev-page" disabled>‹ Prev</button>
            <span class="mono" style="font-size:12px;color:var(--text-secondary);" id="lbl-page-info">Page 1</span>
            <button class="btn btn-secondary btn-sm" id="btn-next-page">Next ›</button>
          </div>
        </div>

        <div class="card-body">
          <div class="table-wrapper">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>Timestamp (UTC)</th>
                  <th>Format</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>Source IP</th>
                  <th>Dest IP</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody id="explorer-tbody">
                <tr><td colspan="8" style="text-align:center;padding:32px;color:var(--text-muted);">Fetching events...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    this.initListeners();
    this.executeFetch();
  },

  initListeners() {
    const searchInput = document.getElementById('exp-search-input');
    const debouncedSearch = window.Utils.debounce(() => {
      this.offset = 0;
      this.executeFetch();
    }, 400);

    searchInput?.addEventListener('input', () => {
      this.currentQuery = searchInput.value.trim();
      debouncedSearch();
    });

    document.getElementById('exp-fmt-filter')?.addEventListener('change', () => { this.offset = 0; this.executeFetch(); });
    document.getElementById('exp-cat-filter')?.addEventListener('change', () => { this.offset = 0; this.executeFetch(); });
    document.getElementById('exp-sev-filter')?.addEventListener('change', () => { this.offset = 0; this.executeFetch(); });

    document.getElementById('btn-reset-filters')?.addEventListener('click', () => {
      document.getElementById('exp-search-input').value = '';
      document.getElementById('exp-fmt-filter').value = '';
      document.getElementById('exp-cat-filter').value = '';
      document.getElementById('exp-sev-filter').value = '';
      this.currentQuery = '';
      this.offset = 0;
      this.executeFetch();
    });

    document.getElementById('btn-query-refresh')?.addEventListener('click', () => this.executeFetch());

    document.getElementById('btn-prev-page')?.addEventListener('click', () => {
      if (this.offset >= this.limit) {
        this.offset -= this.limit;
        this.executeFetch();
      }
    });

    document.getElementById('btn-next-page')?.addEventListener('click', () => {
      this.offset += this.limit;
      this.executeFetch();
    });
  },

  async executeFetch() {
    const tbody = document.getElementById('explorer-tbody');
    const countEl = document.getElementById('exp-result-count');
    const pageEl = document.getElementById('lbl-page-info');
    const prevBtn = document.getElementById('btn-prev-page');
    const nextBtn = document.getElementById('btn-next-page');

    if (!tbody) return;

    const fmt = document.getElementById('exp-fmt-filter')?.value || null;
    const cat = document.getElementById('exp-cat-filter')?.value || null;
    const sev = document.getElementById('exp-sev-filter')?.value;
    const sevMin = sev ? parseInt(sev, 10) : undefined;

    try {
      let data;
      if (this.currentQuery) {
        data = await window.Api.searchEvents(this.currentQuery, this.limit);
      } else {
        data = await window.Api.getEvents({
          raw_format: fmt,
          category: cat,
          severity_min: sevMin,
          limit: this.limit,
          offset: this.offset
        });
      }

      this.currentEvents = data.events || [];
      const retrievedCount = this.currentEvents.length;

      if (countEl) {
        countEl.textContent = this.currentQuery
          ? `Query "${this.currentQuery}" matched ${data.count || retrievedCount} records`
          : `Showing ${retrievedCount} records (offset ${this.offset})`;
      }

      const currentPage = Math.floor(this.offset / this.limit) + 1;
      if (pageEl) pageEl.textContent = `Page ${currentPage}`;
      if (prevBtn) prevBtn.disabled = this.offset === 0;
      if (nextBtn) nextBtn.disabled = retrievedCount < this.limit;

      if (this.currentEvents.length === 0) {
        tbody.innerHTML = `
          <tr><td colspan="8" style="text-align:center;padding:40px;color:var(--text-muted);">
            No events matched query filters.
          </td></tr>
        `;
        return;
      }

      let rows = '';
      this.currentEvents.forEach(ev => {
        const idShort = (ev.event_id || '').substring(0, 8);
        const timeStr = window.Utils.formatDate(ev.timestamp);
        const fmtHtml = window.Utils.formatPillHtml(ev.raw_format);
        const sevHtml = window.Utils.severityBadgeHtml(ev.severity);
        const src = ev.source?.ip || '—';
        const dst = ev.destination?.ip || '—';

        rows += `
          <tr data-event-id="${window.Utils.escapeHtml(ev.event_id)}">
            <td class="mono" style="color:var(--accent-cyan);font-weight:600;">${window.Utils.escapeHtml(idShort)}</td>
            <td class="mono" style="font-size:12px;">${timeStr}</td>
            <td>${fmtHtml}</td>
            <td><span class="badge badge-info">${window.Utils.escapeHtml(ev.category || 'other')}</span></td>
            <td>${sevHtml}</td>
            <td class="mono">${window.Utils.escapeHtml(src)}</td>
            <td class="mono">${window.Utils.escapeHtml(dst)}</td>
            <td><span class="badge badge-neutral">${window.Utils.escapeHtml(ev.action || 'allow')}</span></td>
          </tr>
        `;
      });
      tbody.innerHTML = rows;

      tbody.querySelectorAll('tr').forEach((row, i) => {
        row.addEventListener('click', () => {
          if (this.currentEvents[i]) window.Drawer.inspect(this.currentEvents[i]);
        });
      });
    } catch (err) {
      tbody.innerHTML = `
        <tr><td colspan="8" style="text-align:center;padding:32px;color:var(--accent-red);">
          Query execution error: ${window.Utils.escapeHtml(err.message)}
        </td></tr>
      `;
    }
  },

  destroy() {}
};

window.ExplorerView = ExplorerView;
