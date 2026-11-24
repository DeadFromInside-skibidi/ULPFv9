/**
 * ULPF Capabilities Introspection Engine
 * Dynamically audits OpenAPI endpoint routes to determine feature availability.
 */

class CapabilitiesEngine {
  constructor() {
    this.endpoints = new Set();
    this.initialized = false;
  }

  async init() {
    try {
      const resp = await fetch('/openapi.json');
      if (resp.ok) {
        const schema = await resp.json();
        if (schema && schema.paths) {
          Object.keys(schema.paths).forEach(path => this.endpoints.add(path));
        }
      }
    } catch (e) {
      console.warn('OpenAPI introspection note:', e);
    } finally {
      this.initialized = true;
    }
  }

  hasEndpoint(path) {
    return this.endpoints.has(path);
  }

  hasFeature(featureName) {
    switch (featureName) {
      case 'correlation':
        return this.hasEndpoint('/api/v1/correlate');
      case 'logdna':
        return this.hasEndpoint('/api/v1/fingerprints') || this.hasEndpoint('/api/v1/fingerprint');
      case 'schema':
        return this.hasEndpoint('/api/v1/schema');
      case 'anomalies':
        return this.hasEndpoint('/api/v1/anomalies');
      case 'forensics':
        return this.hasEndpoint('/api/v1/forensic/chains') || this.hasEndpoint('/api/v1/forensic/chain');
      case 'autolearn':
        return this.hasEndpoint('/api/v1/auto-learn');
      case 'listener':
        return this.hasEndpoint('/api/v1/listener/start');
      default:
        return true;
    }
  }
}

window.Capabilities = new CapabilitiesEngine();
