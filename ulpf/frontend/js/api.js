/**
 * ULPF Unified REST API Client
 * Interfaces directly with FastAPI backend routes.
 * 100% Dynamic Data Flow — Zero Hardcoded Mocks.
 */

class ApiClient {
  constructor(baseUrl = '') {
    this.baseUrl = baseUrl;
  }

  async _request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = options.headers || {};

    if (!(options.body instanceof FormData) && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    const config = {
      ...options,
      headers,
    };

    try {
      const resp = await fetch(url, config);
      if (!resp.ok) {
        let errorDetails = `HTTP ${resp.status}`;
        try {
          const errJson = await resp.json();
          errorDetails = errJson.error || errJson.message || errJson.detail || errorDetails;
        } catch {
          errorDetails = await resp.text() || errorDetails;
        }
        throw new Error(errorDetails);
      }
      return await resp.json();
    } catch (err) {
      console.error(`API Error [${endpoint}]:`, err);
      throw err;
    }
  }

  /* ── Stats & Health ── */
  async getStats() {
    return this._request('/api/v1/stats');
  }

  /* ── Events Query & Search ── */
  async getEvents({ category, severity_min, severity_max, source_ip, raw_format, limit = 50, offset = 0 } = {}) {
    const params = new URLSearchParams();
    if (category) params.append('category', category);
    if (severity_min !== undefined) params.append('severity_min', severity_min);
    if (severity_max !== undefined) params.append('severity_max', severity_max);
    if (source_ip) params.append('source_ip', source_ip);
    if (raw_format) params.append('raw_format', raw_format);
    params.append('limit', limit);
    params.append('offset', offset);

    return this._request(`/api/v1/events?${params.toString()}`);
  }

  async getEvent(eventId) {
    return this._request(`/api/v1/events/${encodeURIComponent(eventId)}`);
  }

  async searchEvents(query, limit = 50) {
    const params = new URLSearchParams({ q: query, limit });
    return this._request(`/api/v1/search?${params.toString()}`);
  }

  /* ── Ingestion & Syslog Listener ── */
  async ingestRaw(raw) {
    return this._request('/api/v1/ingest', {
      method: 'POST',
      body: JSON.stringify({ raw }),
    });
  }

  async ingestBatch(lines) {
    return this._request('/api/v1/ingest/batch', {
      method: 'POST',
      body: JSON.stringify({ lines }),
    });
  }

  async ingestFile(file) {
    const formData = new FormData();
    formData.append('file', file);
    return this._request('/api/v1/ingest/file', {
      method: 'POST',
      body: formData,
    });
  }

  async getListenerStatus() {
    return this._request('/api/v1/listener');
  }

  async startListener(config = {}) {
    return this._request('/api/v1/listener/start', {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  async stopListener() {
    return this._request('/api/v1/listener/stop', {
      method: 'POST',
      body: JSON.stringify({}),
    });
  }

  /* ── Parsers ── */
  async getParsers() {
    return this._request('/api/v1/parsers');
  }

  async testParser(raw) {
    return this._request('/api/v1/parsers/test', {
      method: 'POST',
      body: JSON.stringify({ raw }),
    });
  }

  /* ── Auto-Learn Synthesis ── */
  async autoLearn(lines) {
    return this._request('/api/v1/auto-learn', {
      method: 'POST',
      body: JSON.stringify({ lines }),
    });
  }

  async getAutoLearnConfigs() {
    return this._request('/api/v1/auto-learn/configs');
  }

  /* ── Core Feature 1: Correlation ── */
  async getCorrelations(limit = 150, timeWindow = 60.0) {
    return this._request(`/api/v1/correlate?limit=${limit}&time_window_seconds=${timeWindow}`);
  }

  async postCorrelate(options = {}) {
    return this._request('/api/v1/correlate', {
      method: 'POST',
      body: JSON.stringify(options),
    });
  }

  /* ── Core Feature 2: Log DNA ── */
  async getFingerprints() {
    return this._request('/api/v1/fingerprints');
  }

  async generateFingerprint(lines, label = 'Log Source') {
    return this._request('/api/v1/fingerprint', {
      method: 'POST',
      body: JSON.stringify({ lines, label }),
    });
  }

  async matchFingerprint(lines) {
    return this._request('/api/v1/fingerprint/match', {
      method: 'POST',
      body: JSON.stringify({ lines }),
    });
  }

  async detectDrift(fingerprintId, lines) {
    return this._request('/api/v1/fingerprint/drift', {
      method: 'POST',
      body: JSON.stringify({ fingerprint_id: fingerprintId, lines }),
    });
  }

  /* ── Core Feature 3: Schema Mapping ── */
  async getSchema() {
    return this._request('/api/v1/schema');
  }

  /* ── Core Feature 4: Statistical Anomalies ── */
  async getAnomalies(limit = 50) {
    return this._request(`/api/v1/anomalies?limit=${limit}`);
  }

  /* ── Core Feature 5: Forensics & Provenance ── */
  async getForensicChains() {
    return this._request('/api/v1/forensic/chains');
  }

  async createForensicChain(eventIds, description = 'Evidence Chain', tags = ['live', 'audit']) {
    return this._request('/api/v1/forensic/chain', {
      method: 'POST',
      body: JSON.stringify({ event_ids: eventIds, description, tags }),
    });
  }

  async verifyForensicChain(chainId) {
    return this._request(`/api/v1/forensic/verify/${encodeURIComponent(chainId)}`);
  }

  async exportForensicPackage(chainId) {
    return this._request(`/api/v1/forensic/export/${encodeURIComponent(chainId)}`, {
      method: 'POST',
      body: JSON.stringify({}),
    });
  }

  /* ── Data Export ── */
  async exportData(format = 'json', limit = 1000) {
    return this._request(`/api/v1/export?format=${format}&limit=${limit}`);
  }
}

window.Api = new ApiClient();
