/**
 * ULPF Utilities & Formatting Helpers (Air-Gapped, Zero-Dependency)
 */

const Utils = {
  /**
   * Escape HTML to prevent XSS
   */
  escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  },

  /**
   * Format integer with thousands separators
   */
  formatNumber(num) {
    if (num === null || num === undefined || isNaN(num)) return '0';
    return Number(num).toLocaleString();
  },

  /**
   * Format throughput EPS
   */
  formatEps(eps) {
    if (eps === null || eps === undefined || isNaN(eps)) return '0.0 EPS';
    return `${Number(eps).toFixed(1)} EPS`;
  },

  /**
   * Format byte count
   */
  formatBytes(bytes, decimals = 2) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
  },

  /**
   * Format ISO date string into readable timestamp
   */
  formatDate(isoStr) {
    if (!isoStr) return '—';
    try {
      const d = new Date(isoStr);
      if (isNaN(d.getTime())) return isoStr;
      return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
    } catch {
      return isoStr;
    }
  },

  /**
   * Relative time description
   */
  timeAgo(isoStr) {
    if (!isoStr) return '';
    try {
      const d = new Date(isoStr);
      const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
      if (diffSec < 2) return 'just now';
      if (diffSec < 60) return `${diffSec}s ago`;
      if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
      if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
      return `${Math.floor(diffSec / 86400)}d ago`;
    } catch {
      return '';
    }
  },

  /**
   * Render format pill HTML
   */
  formatPillHtml(fmt) {
    const raw = (fmt || 'unknown').toLowerCase();
    return `<span class="format-pill" data-fmt="${this.escapeHtml(raw)}">${this.escapeHtml(raw.toUpperCase())}</span>`;
  },

  /**
   * Render severity badge HTML
   */
  severityBadgeHtml(sev) {
    const s = parseInt(sev, 10) || 0;
    let cls = 'badge-neutral';
    let label = 'Low';

    if (s >= 8) {
      cls = 'badge-danger';
      label = 'Critical';
    } else if (s >= 5) {
      cls = 'badge-warning';
      label = 'Medium';
    } else if (s >= 2) {
      cls = 'badge-info';
      label = 'Low';
    } else {
      cls = 'badge-neutral';
      label = 'Info';
    }

    return `<span class="badge ${cls}">${s} • ${label}</span>`;
  },

  /**
   * Copy text to OS clipboard
   */
  async copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      if (window.Toast) {
        window.Toast.show('Copied to clipboard', 'success');
      }
      return true;
    } catch (e) {
      console.warn('Clipboard write failed:', e);
      return false;
    }
  },

  /**
   * Debounce execution
   */
  debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }
};

window.Utils = Utils;
