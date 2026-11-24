/**
 * ULPF Export Modal Component
 * Triggers columnar datasets extraction in CSV and JSON formats.
 */

const ExportModal = {
  open() {
    window.Modal.open({
      title: 'Export Normalized Dataset',
      bodyHtml: `
        <div style="display:flex;flex-direction:column;gap:16px;">
          <p style="font-size:13px;color:var(--text-secondary);">
            Extract normalized log telemetry from the embedded DuckDB columnar storage engine.
          </p>

          <div class="input-group">
            <label class="input-label">EXPORT FORMAT</label>
            <select class="select-input" id="export-format-select">
              <option value="json">Normalized OCSF JSON Array</option>
              <option value="csv">Flattened Security Incident CSV</option>
            </select>
          </div>

          <div class="input-group">
            <label class="input-label">RECORD LIMIT</label>
            <select class="select-input" id="export-limit-select">
              <option value="100">Latest 100 Events</option>
              <option value="500">Latest 500 Events</option>
              <option value="2000">Latest 2,000 Events</option>
              <option value="10000">Latest 10,000 Events</option>
            </select>
          </div>
        </div>
      `,
      footerHtml: `
        <button class="btn btn-secondary" onclick="window.Modal.close()">Cancel</button>
        <button class="btn btn-primary" id="btn-perform-export">Download Dataset</button>
      `,
      onOpen: () => {
        document.getElementById('btn-perform-export')?.addEventListener('click', async () => {
          const fmt = document.getElementById('export-format-select').value;
          const limit = document.getElementById('export-limit-select').value;
          
          try {
            window.Toast.show('Generating export package from DuckDB...', 'info');
            const data = await window.Api.exportData(fmt, limit);
            
            let blob;
            let filename;
            if (fmt === 'json') {
              blob = new Blob([JSON.stringify(data.events || data, null, 2)], { type: 'application/json' });
              filename = `ulpf_export_${Date.now()}.json`;
            } else {
              blob = new Blob([data.csv || ''], { type: 'text/csv' });
              filename = `ulpf_export_${Date.now()}.csv`;
            }

            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            window.Toast.show('Export downloaded successfully', 'success');
            window.Modal.close();
          } catch (e) {
            window.Toast.show(`Export failed: ${e.message}`, 'error');
          }
        });
      }
    });
  }
};

window.ExportModal = ExportModal;
