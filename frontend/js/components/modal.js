/**
 * ULPF Modal Dialog Component
 */

const Modal = {
  container: null,

  init() {
    this.container = document.getElementById('modal-container');
    if (this.container) {
      this.container.addEventListener('click', (e) => {
        if (e.target === this.container) {
          this.close();
        }
      });
    }
  },

  open({ title, bodyHtml, footerHtml = '', onOpen = null }) {
    if (!this.container) this.init();
    if (!this.container) return;

    this.container.innerHTML = `
      <div class="modal-box">
        <div class="modal-header">
          <h3 class="card-title">${window.Utils.escapeHtml(title)}</h3>
          <button class="btn btn-secondary btn-sm" id="modal-close-btn" style="padding:4px 8px;">✕</button>
        </div>
        <div class="modal-body">
          ${bodyHtml}
        </div>
        ${footerHtml ? `<div class="modal-footer">${footerHtml}</div>` : ''}
      </div>
    `;

    document.getElementById('modal-close-btn')?.addEventListener('click', () => this.close());
    this.container.classList.remove('hidden');

    if (typeof onOpen === 'function') {
      onOpen(this.container);
    }
  },

  close() {
    if (!this.container) this.init();
    if (this.container) {
      this.container.classList.add('hidden');
      this.container.innerHTML = '';
    }
  }
};

window.Modal = Modal;
