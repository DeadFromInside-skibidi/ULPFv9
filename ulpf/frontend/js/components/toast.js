/**
 * ULPF Toast Notification Component
 */

const Toast = {
  show(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    const iconMap = {
      success: '✓',
      error: '✕',
      warning: '⚠',
      info: 'ℹ'
    };

    toast.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;">
        <span style="font-weight:bold;">${iconMap[type] || '•'}</span>
        <span>${window.Utils.escapeHtml(message)}</span>
      </div>
      <button style="color:var(--text-muted);font-size:14px;cursor:pointer;" onclick="this.parentElement.remove()">✕</button>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      if (toast.parentElement) {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.25s ease';
        setTimeout(() => toast.remove(), 250);
      }
    }, duration);
  }
};

window.Toast = Toast;
