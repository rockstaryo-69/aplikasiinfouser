/**
 * PDF / JSON Export Utility
 * Exports scan results as formatted PDF or raw JSON
 *
 * Used by: ExportButton component
 * Deps: jsPDF (bundler setup) OR html2canvas (CDN)
 */

/**
 * Export result object as formatted JSON file
 */
export function exportJSON(data, filename = 'cyberscope-export') {
  const blob = new Blob(
    [JSON.stringify(data, null, 2)],
    { type: 'application/json' }
  );
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${filename}-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Build a plain-text PDF report from a scan result object.
 * Uses jsPDF (bundler) or falls back to browser print dialog.
 */
export async function exportPDF(data, title = 'CyberScope Scan Report') {
  // Try jsPDF first (bundler setup)
  try {
    const { jsPDF } = await import('jspdf');
    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
    const margin = 15;
    let y = 20;
    const lineH = 7;
    const pageH = 297 - margin;

    const addLine = (text, size = 11, bold = false) => {
      if (y > pageH - 10) { doc.addPage(); y = 20; }
      doc.setFontSize(size);
      doc.setFont('helvetica', bold ? 'bold' : 'normal');
      doc.setTextColor(bold ? 20 : 60, bold ? 20 : 60, bold ? 20 : 60);
      doc.text(String(text), margin, y);
      y += lineH;
    };

    const addSection = (label) => {
      y += 3;
      doc.setFillColor(37, 99, 235);
      doc.rect(margin, y - 5, 180, 8, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(11);
      doc.setFont('helvetica', 'bold');
      doc.text(label, margin + 2, y);
      doc.setTextColor(60, 60, 60);
      y += lineH + 2;
    };

    // Header
    doc.setFillColor(7, 11, 20);
    doc.rect(0, 0, 210, 30, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(20);
    doc.setFont('helvetica', 'bold');
    doc.text('🔭 CyberScope', margin, 15);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text('OSINT Intelligence Report — For Authorized Use Only', margin, 22);
    y = 38;

    // Report info
    addLine(`Report Title:  ${title}`, 12, true);
    addLine(`Generated:     ${new Date().toLocaleString()}`, 10);
    addLine(`Platform:      CyberScope v1.0`, 10);
    y += 4;

    // Render data sections
    function renderObject(obj, depth = 0) {
      if (!obj || typeof obj !== 'object') return;
      Object.entries(obj).forEach(([key, val]) => {
        const indent = '  '.repeat(depth);
        if (val && typeof val === 'object' && !Array.isArray(val)) {
          addLine(`${indent}${key}:`, 10, true);
          renderObject(val, depth + 1);
        } else if (Array.isArray(val)) {
          addLine(`${indent}${key}: [${val.join(', ')}]`, 10);
        } else {
          addLine(`${indent}${key}: ${val}`, 10);
        }
      });
    }

    addSection('SCAN RESULTS');
    renderObject(data);

    // Legal footer
    doc.setFontSize(8);
    doc.setFont('helvetica', 'italic');
    doc.setTextColor(150, 150, 150);
    const pages = doc.getNumberOfPages();
    for (let i = 1; i <= pages; i++) {
      doc.setPage(i);
      doc.text('CONFIDENTIAL — For authorized security testing only. Unauthorized use is prohibited.', margin, 290);
      doc.text(`Page ${i} of ${pages}`, 190 - margin, 290, { align: 'right' });
    }

    doc.save(`cyberscope-report-${Date.now()}.pdf`);
  } catch {
    // Fallback: open print dialog with formatted HTML
    const win = window.open('', '_blank');
    win.document.write(`
      <html><head><title>${title}</title><style>
        body { font-family: monospace; font-size: 12px; padding: 20px; }
        h1 { color: #1e40af; } pre { background: #f1f5f9; padding: 12px; border-radius: 6px; }
        .footer { margin-top: 40px; color: #94a3b8; font-size: 10px; border-top: 1px solid #e2e8f0; padding-top: 8px; }
      </style></head><body>
        <h1>🔭 CyberScope — ${title}</h1>
        <p>Generated: ${new Date().toLocaleString()}</p>
        <pre>${JSON.stringify(data, null, 2)}</pre>
        <div class="footer">CONFIDENTIAL — For authorized security testing only.</div>
      </body></html>
    `);
    win.document.close();
    win.print();
  }
}

/**
 * Copy text to clipboard with fallback
 */
export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const el = document.createElement('textarea');
    el.value = text;
    document.body.appendChild(el);
    el.select();
    document.execCommand('copy');
    document.body.removeChild(el);
    return true;
  }
}
