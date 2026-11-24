/**
 * ULPF Reactive State Store (Pub/Sub)
 * Automatically polls backend every 1.5s to ensure live streaming data flow.
 * 100% Real Backend Data — Zero Hardcoding.
 */

class StateStore {
  constructor() {
    this.state = {
      stats: {
        total_events: 0,
        database: { total_events: 0, by_format: {}, by_category: {}, by_severity: {} },
        pipeline: { events_processed: 0, successful: 0, failed: 0, current_eps: 0.0 },
        anomaly_baseline: {},
        listener: { is_running: false, host: '0.0.0.0', port: 5514, packets_received: 0 }
      },
      currentView: 'overview',
      isOnline: true,
      lastUpdated: null,
      cachedEvents: [],
    };

    this.listeners = new Map();
    this.pollTimer = null;
    this.pollIntervalMs = 1500;
  }

  get(key) {
    return this.state[key];
  }

  set(key, value) {
    this.state[key] = value;
    this.notify(key, value);
  }

  subscribe(key, callback) {
    if (!this.listeners.has(key)) {
      this.listeners.set(key, new Set());
    }
    this.listeners.get(key).add(callback);
    return () => this.listeners.get(key).delete(callback);
  }

  notify(key, value) {
    if (this.listeners.has(key)) {
      this.listeners.get(key).forEach(cb => {
        try {
          cb(value, this.state);
        } catch (e) {
          console.error(`Subscriber error for key [${key}]:`, e);
        }
      });
    }
    if (this.listeners.has('*')) {
      this.listeners.get('*').forEach(cb => {
        try {
          cb(key, value, this.state);
        } catch (e) {
          console.error('Wildcard subscriber error:', e);
        }
      });
    }
  }

  async fetchLatestStats() {
    try {
      const stats = await window.Api.getStats();
      const prevTotal = this.state.stats?.database?.total_events || 0;
      const newTotal = stats?.database?.total_events || 0;

      this.state.stats = stats;
      this.state.isOnline = true;
      this.state.lastUpdated = new Date();

      this.notify('stats', stats);
      this.updateHeaderAndFooter(stats);

      // If new events were ingested, notify event updates
      if (newTotal !== prevTotal) {
        this.notify('new_data', { prevTotal, newTotal });
      }
    } catch (err) {
      this.state.isOnline = false;
      this.notify('offline', err);
      const dot = document.getElementById('sys-status-dot');
      const text = document.getElementById('sys-status-text');
      if (dot) dot.className = 'status-dot offline';
      if (text) text.textContent = 'Disconnected';
    }
  }

  updateHeaderAndFooter(stats) {
    const totalEvents = stats?.database?.total_events || 0;
    const eps = stats?.pipeline?.current_eps || 0.0;
    const listener = stats?.listener || {};

    const epsEl = document.getElementById('top-eps-value');
    if (epsEl) epsEl.textContent = window.Utils.formatEps(eps);

    const dbEl = document.getElementById('top-db-events');
    if (dbEl) dbEl.textContent = `${window.Utils.formatNumber(totalEvents)} Events`;

    const storageCountEl = document.getElementById('status-storage-count');
    if (storageCountEl) storageCountEl.textContent = `${window.Utils.formatNumber(totalEvents)} Rows`;

    const listenerEl = document.getElementById('status-listener-text');
    if (listenerEl) {
      listenerEl.textContent = listener.is_running
        ? `Syslog: Active (${listener.host}:${listener.port})`
        : 'Syslog: Standby';
    }

    const dot = document.getElementById('sys-status-dot');
    const text = document.getElementById('sys-status-text');
    if (dot) dot.className = 'status-dot online';
    if (text) text.textContent = 'Engine Operational';
  }

  startPolling() {
    if (this.pollTimer) clearInterval(this.pollTimer);
    this.fetchLatestStats();
    this.pollTimer = setInterval(() => {
      this.fetchLatestStats();
    }, this.pollIntervalMs);
  }

  stopPolling() {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }
}

window.State = new StateStore();
