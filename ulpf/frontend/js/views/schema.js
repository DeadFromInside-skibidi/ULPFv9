/**
 * ULPF Unified Event Schema Definition View (OCSF Standardized)
 * Live attribute mapping coverage queried directly from DuckDB.
 * 100% Dynamic Data Flow — Core Feature 3.
 */

const SchemaView = {
  container: null,
  schemaData: null,
  activeCategory: 'ALL',
  searchQuery: '',

  async render(targetEl) {
    this.container = targetEl;
    this.container.innerHTML = `
      <!-- Toolbar & Stats -->
      <div class="card" style="margin-bottom:20px;">
        <div class="card-header">
          <div>
            <h3 class="card-title">OCSF Unified Security Event Schema Taxonomy</h3>
            <span class="card-subtitle">Harmonized target schema normalizing all heterogeneous security log sources</span>
          </div>
          <div style="display:flex;gap:10px;align-items:center;">
            <span class="badge badge-info" id="schema-total-attrs">45 Attributes</span>
            <span class="badge badge-success" id="schema-total-events">0 Events Mapped</span>
          </div>
        </div>
        <div class="card-body">
          <div style="display:flex;gap:12px;align-items:center;margin-bottom:16px;">
            <div class="search-input-wrapper" style="max-width:400px;">
              <span class="search-icon">🔍</span>
              <input type="text" class="input-text" id="schema-search-input" placeholder="Search schema attributes, descriptions, or data types..." />
            </div>
          </div>

          <!-- Category Filter Buttons -->
          <div class="schema-category-nav" id="schema-pills-row">
            <button class="schema-category-btn active" data-cat="ALL">All Categories</button>
          </div>
        </div>
      </div>

      <!-- Categories Container -->
      <div id="schema-categories-container" style="display:flex;flex-direction:column;gap:16px;">
        <div class="card">
          <div class="card-body" style="text-align:center;padding:40px;color:var(--text-muted);">
            Loading unified schema taxonomy and live DuckDB mapping metrics...
          </div>
        </div>
      </div>
    `;

    this.initListeners();
    this.loadSchema();
  },

  initListeners() {
    const searchInput = document.getElementById('schema-search-input');
    searchInput?.addEventListener('input', () => {
      this.searchQuery = searchInput.value.trim().toLowerCase();
      this.renderCategoryCards();
    });
  },

  async loadSchema() {
    try {
      this.schemaData = await window.Api.getSchema();
      const categories = (this.schemaData.groups && this.schemaData.groups[0]?.fields)
        ? this.schemaData.groups
        : (this.schemaData.categories && this.schemaData.categories[0]?.fields)
        ? this.schemaData.categories
        : (this.schemaData.groups || this.schemaData.categories || []);
      const totalEvents = this.schemaData.total_events || 0;

      // Calculate total attributes
      let totalAttrs = 0;
      categories.forEach(c => totalAttrs += (c.fields || []).length);

      document.getElementById('schema-total-attrs').textContent = `${totalAttrs} Attributes`;
      document.getElementById('schema-total-events').textContent = `${window.Utils.formatNumber(totalEvents)} Events in DB`;

      // Build category pills
      const pillsRow = document.getElementById('schema-pills-row');
      if (pillsRow) {
        let pillsHtml = `<button class="schema-category-btn active" data-cat="ALL">All Categories (${categories.length})</button>`;
        categories.forEach(c => {
          pillsHtml += `<button class="schema-category-btn" data-cat="${window.Utils.escapeHtml(c.category)}">${window.Utils.escapeHtml(c.category)}</button>`;
        });
        pillsRow.innerHTML = pillsHtml;

        pillsRow.querySelectorAll('.schema-category-btn').forEach(btn => {
          btn.addEventListener('click', () => {
            pillsRow.querySelectorAll('.schema-category-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            this.activeCategory = btn.getAttribute('data-cat');
            this.renderCategoryCards();
          });
        });
      }

      this.renderCategoryCards();
    } catch (e) {
      const container = document.getElementById('schema-categories-container');
      if (container) {
        container.innerHTML = `
          <div class="card">
            <div class="card-body" style="padding:32px;text-align:center;color:var(--accent-red);">
              Failed loading schema: ${window.Utils.escapeHtml(e.message)}
            </div>
          </div>
        `;
      }
    }
  },

  renderCategoryCards() {
    const container = document.getElementById('schema-categories-container');
    if (!container || !this.schemaData) return;

    const categories = (this.schemaData.groups && this.schemaData.groups[0]?.fields)
      ? this.schemaData.groups
      : (this.schemaData.categories && this.schemaData.categories[0]?.fields)
      ? this.schemaData.categories
      : (this.schemaData.groups || this.schemaData.categories || []);
    const coverageMap = this.schemaData.field_coverage || {};
    const totalEvents = this.schemaData.total_events || 0;

    const filteredCats = this.activeCategory === 'ALL'
      ? categories
      : categories.filter(c => c.category === this.activeCategory);

    let html = '';
    let renderedCards = 0;

    filteredCats.forEach(cat => {
      let fields = cat.fields || [];
      if (this.searchQuery) {
        fields = fields.filter(f =>
          f.name.toLowerCase().includes(this.searchQuery) ||
          f.description.toLowerCase().includes(this.searchQuery) ||
          f.type.toLowerCase().includes(this.searchQuery)
        );
      }

      if (fields.length === 0) return;
      renderedCards++;

      // Count mapped fields
      const mappedInCat = fields.filter(f => (coverageMap[f.name] || 0) > 0).length;
      const catCoveragePct = fields.length > 0 ? (mappedInCat / fields.length) * 100 : 0;

      html += `
        <div class="card" style="margin-bottom:12px;">
          <div class="card-header">
            <div>
              <h3 class="card-title">${window.Utils.escapeHtml(cat.category)}</h3>
              <span class="card-subtitle">${window.Utils.escapeHtml(cat.description)}</span>
            </div>
            <div style="display:flex;gap:8px;align-items:center;">
              ${totalEvents > 0 && mappedInCat > 0 ? `
                <span class="badge badge-success">${mappedInCat}/${fields.length} POPULATED (${catCoveragePct.toFixed(0)}%)</span>
              ` : ''}
              <span class="badge badge-info">${fields.length} ATTRIBUTES</span>
            </div>
          </div>
          <div class="card-body" style="padding:0;">
            <div class="table-wrapper" style="border:none;">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>ATTRIBUTE NAME</th>
                    <th>DATA TYPE</th>
                    <th>DESCRIPTION</th>
                    <th>EXAMPLE VALUE</th>
                    <th>LIVE COVERAGE</th>
                  </tr>
                </thead>
                <tbody>
                  ${fields.map(f => {
                    const covCount = coverageMap[f.name] || 0;
                    const covPct = totalEvents > 0 ? ((covCount / totalEvents) * 100).toFixed(0) : '0';
                    const hasCov = covCount > 0;

                    return `
                      <tr>
                        <td class="mono" style="color:var(--text-primary);font-weight:700;">${window.Utils.escapeHtml(f.name)}</td>
                        <td class="mono" style="color:var(--accent-cyan);">${window.Utils.escapeHtml(f.type)}</td>
                        <td style="color:var(--text-secondary);font-size:12.5px;">${window.Utils.escapeHtml(f.description)}</td>
                        <td class="mono" style="color:var(--text-muted);font-size:11.5px;">${window.Utils.escapeHtml(f.example || '—')}</td>
                        <td class="mono">
                          ${hasCov ? `
                            <span style="color:var(--accent-emerald);font-weight:700;">${window.Utils.formatNumber(covCount)} (${covPct}%)</span>
                          ` : `
                            <span style="color:var(--text-muted);">0 (0%)</span>
                          `}
                        </td>
                      </tr>
                    `;
                  }).join('')}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      `;
    });

    if (renderedCards === 0) {
      html = `
        <div class="card">
          <div class="card-body empty-state">
            <div class="empty-state-title">No Attributes Found</div>
            <div class="empty-state-text">No schema attributes match the filter "${window.Utils.escapeHtml(this.searchQuery)}".</div>
          </div>
        </div>
      `;
    }

    container.innerHTML = html;
  },

  destroy() {}
};

window.SchemaView = SchemaView;
