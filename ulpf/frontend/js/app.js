/**
 * ULPF Application Orchestrator & Hash Router
 * 100% Dynamic Backend Integration — Air-Gapped Operation.
 */

class AppRouter {
  constructor() {
    this.currentViewInstance = null;
    this.views = {
      overview: window.OverviewView,
      ingestion: window.IngestionView,
      explorer: window.ExplorerView,
      correlation: window.CorrelationView,
      logdna: window.LogDNAView,
      anomalies: window.AnomaliesView,
      forensics: window.ForensicsView,
      schema: window.SchemaView,
      parsers: window.ParsersView,
      autolearn: window.AutoLearnView,
    };

    this.titles = {
      overview: { title: 'Operational Overview', subtitle: 'Real-time telemetry and columnar analytics' },
      ingestion: { title: 'High-Throughput Ingestion Engine', subtitle: 'Network syslog daemon and batch stream injection' },
      explorer: { title: 'Columnar Log Explorer', subtitle: 'Full-text search and OCSF normalized event querying' },
      correlation: { title: 'Multi-Source Correlation Engine', subtitle: 'Temporal and indicator clustering with MITRE ATT&CK mapping' },
      logdna: { title: 'Log DNA Fingerprinting & Drift', subtitle: 'Shannon entropy analysis and format drift detection' },
      anomalies: { title: 'Pure-Statistical Anomaly Detection', subtitle: 'Gaussian rolling Z-scores and frequency outlier tracking' },
      forensics: { title: 'Cryptographic Forensics & Provenance', subtitle: 'SHA-256 Merkle chain evidence packages and legal custody' },
      schema: { title: 'OCSF Unified Event Schema', subtitle: 'Taxonomy definition with dynamic DuckDB mapping coverage' },
      parsers: { title: 'Universal Parser Inventory', subtitle: 'Zero-overhead jump table classifiers and test bench' },
      autolearn: { title: 'Autonomous Parser Synthesis', subtitle: 'JIT dynamic regex learning and template mining plane' },
    };
  }

  async init() {
    // 1. Initialize icons
    if (window.Icons) window.Icons.renderAll();

    // 2. Initialize UI components
    if (window.Modal) window.Modal.init();
    if (window.Drawer) window.Drawer.init();

    // 3. Introspect backend capabilities
    if (window.Capabilities) await window.Capabilities.init();

    // 4. Bind global top-header buttons
    document.getElementById('btn-open-export')?.addEventListener('click', () => {
      if (window.ExportModal) window.ExportModal.open();
    });

    document.getElementById('btn-quick-refresh')?.addEventListener('click', () => {
      window.State.fetchLatestStats();
      if (this.currentViewInstance && typeof this.currentViewInstance.render === 'function') {
        const target = document.getElementById('view-container');
        this.currentViewInstance.render(target);
      }
      window.Toast.show('Telemetry synchronized', 'info', 1500);
    });

    // 5. Start background state polling (1.5s interval)
    if (window.State) window.State.startPolling();

    // 6. Bind Hash routing
    window.addEventListener('hashchange', () => this.handleRoute());
    this.handleRoute();
  }

  handleRoute() {
    const rawHash = window.location.hash.replace(/^#\/?/, '').toLowerCase();
    const route = this.views[rawHash] ? rawHash : 'overview';

    // Update active nav styling
    document.querySelectorAll('.sidebar-nav .nav-item').forEach(item => {
      if (item.getAttribute('data-view') === route) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    // Update header title & subtitle
    const meta = this.titles[route] || { title: 'ULPF Dashboard', subtitle: 'Security Analytics' };
    const titleEl = document.getElementById('page-title');
    const subEl = document.getElementById('page-subtitle');
    if (titleEl) titleEl.textContent = meta.title;
    if (subEl) subEl.textContent = meta.subtitle;

    // Destroy prior view if needed
    if (this.currentViewInstance && typeof this.currentViewInstance.destroy === 'function') {
      this.currentViewInstance.destroy();
    }

    // Render new view
    const viewTarget = document.getElementById('view-container');
    if (viewTarget && this.views[route]) {
      this.currentViewInstance = this.views[route];
      this.currentViewInstance.render(viewTarget);
    }
  }
}

// Bootstrap application once DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  window.Router = new AppRouter();
  window.Router.init();
});
