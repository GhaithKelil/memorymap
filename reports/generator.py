"""
reports/generator.py
--------------------
Generates a self-contained HTML forensics report from:
  - AnalysisReport  (findings + risk score)
  - anomaly_summary (anomaly items)
  - region list     (memory map)

Usage:
    report_path = generate_report(report, anomalies, regions, output_dir="reports/output")
"""

import os
import json
import math
from datetime import datetime
from typing import List, Optional

# ── Inline styles & chart data are embedded directly ─────────────────────────
_REPORT_CSS = """
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

  :root {
    --bg:       #0d1117;
    --surface:  #161b22;
    --surface2: #21262d;
    --border:   #30363d;
    --text:     #e6edf3;
    --muted:    #8b949e;
    --accent:   #58a6ff;
    --green:    #3fb950;
    --yellow:   #d29922;
    --red:      #f85149;
    --purple:   #bc8cff;
    --critical: #ff4f4f;
    --high:     #f0a957;
    --medium:   #58a6ff;
    --low:      #8b949e;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'Inter', sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
  }

  /* Print overrides */
  @media print {
    body { background: #fff; color: #111; }
    .surface { background: #f6f8fa !important; border-color: #d0d7de !important; }
    .no-print { display: none !important; }
    .page-break { page-break-before: always; }
  }

  a { color: var(--accent); text-decoration: none; }

  /* Cover page */
  .cover {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    padding: 60px 40px;
    text-align: center;
    background: linear-gradient(160deg, #0d1117 0%, #161b22 60%, #0d1117 100%);
    position: relative;
    overflow: hidden;
  }

  .cover::before {
    content: '';
    position: absolute;
    inset: 0;
    background-image:
      linear-gradient(rgba(88,166,255,0.04) 1px, transparent 1px),
      linear-gradient(90deg, rgba(88,166,255,0.04) 1px, transparent 1px);
    background-size: 40px 40px;
  }

  .cover-inner { position: relative; z-index: 1; max-width: 700px; }

  .cover-logo {
    width: 80px; height: 80px;
    background: linear-gradient(135deg, #58a6ff, #bc8cff);
    border-radius: 20px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 38px;
    margin: 0 auto 28px;
    box-shadow: 0 0 60px rgba(88,166,255,0.3);
  }

  .cover h1 {
    font-size: 3rem;
    font-weight: 800;
    letter-spacing: -0.03em;
    background: linear-gradient(135deg, #e6edf3, #58a6ff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 8px;
  }

  .cover-subtitle { font-size: 1.1rem; color: var(--muted); margin-bottom: 40px; }

  .cover-meta {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    width: 100%;
    margin-top: 32px;
  }

  .cover-meta-item {
    background: rgba(255,255,255,0.03);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 20px;
    text-align: left;
  }

  .cover-meta-label { font-size: 0.7rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 4px; }
  .cover-meta-value { font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; color: var(--text); }

  .risk-banner {
    display: inline-flex;
    align-items: center;
    gap: 12px;
    padding: 16px 32px;
    border-radius: 12px;
    font-size: 1.4rem;
    font-weight: 700;
    margin-top: 32px;
    font-family: 'JetBrains Mono', monospace;
  }

  .risk-CRITICAL { background: rgba(248,81,73,0.15); border: 2px solid rgba(248,81,73,0.5); color: #ff4f4f; }
  .risk-HIGH     { background: rgba(240,169,87,0.15); border: 2px solid rgba(240,169,87,0.5); color: #f0a957; }
  .risk-MEDIUM   { background: rgba(88,166,255,0.15); border: 2px solid rgba(88,166,255,0.5); color: #58a6ff; }
  .risk-LOW      { background: rgba(139,148,158,0.1); border: 2px solid var(--border);         color: var(--muted); }
  .risk-CLEAN    { background: rgba(63,185,80,0.15);  border: 2px solid rgba(63,185,80,0.5);  color: #3fb950; }

  /* Content pages */
  .page { max-width: 1100px; margin: 0 auto; padding: 40px 32px; }

  /* Section headers */
  .section-h {
    font-size: 1.3rem;
    font-weight: 700;
    margin: 40px 0 20px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 10px;
  }

  /* Stat grid */
  .stat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
    gap: 14px;
    margin-bottom: 32px;
  }

  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px;
  }

  .stat-label { font-size: 0.72rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }
  .stat-value { font-size: 1.8rem; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
  .stat-sub   { font-size: 0.72rem; color: var(--muted); margin-top: 4px; }

  .col-critical { color: var(--critical); }
  .col-high     { color: var(--high); }
  .col-medium   { color: var(--accent); }
  .col-low      { color: var(--muted); }
  .col-clean    { color: var(--green); }
  .col-accent   { color: var(--accent); }

  /* Tables */
  .table-wrap { overflow-x: auto; margin-bottom: 28px; border: 1px solid var(--border); border-radius: 10px; }

  table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }

  th {
    background: var(--surface2);
    padding: 10px 14px;
    text-align: left;
    font-weight: 500;
    color: var(--muted);
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    border-bottom: 1px solid var(--border);
  }

  td { padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:nth-child(even) td { background: rgba(255,255,255,0.01); }

  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.68rem;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
    white-space: nowrap;
  }

  .badge-CRITICAL { background: rgba(248,81,73,0.15); color: var(--critical); border: 1px solid rgba(248,81,73,0.3); }
  .badge-HIGH     { background: rgba(240,169,87,0.15); color: var(--high);     border: 1px solid rgba(240,169,87,0.3); }
  .badge-MEDIUM   { background: rgba(88,166,255,0.15); color: var(--accent);   border: 1px solid rgba(88,166,255,0.3); }
  .badge-LOW      { background: rgba(139,148,158,0.1); color: var(--muted);    border: 1px solid var(--border); }
  .badge-CLEAN    { background: rgba(63,185,80,0.15);  color: var(--green);    border: 1px solid rgba(63,185,80,0.3); }

  .mono { font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: var(--accent); }
  .match-cell { font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: var(--muted); max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  /* Anomaly cards */
  .anomaly-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 12px;
    margin-bottom: 28px;
  }

  .anomaly-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 16px;
    display: flex;
    gap: 12px;
  }

  .anomaly-card.sev-CRITICAL { border-left: 3px solid var(--critical); }
  .anomaly-card.sev-HIGH     { border-left: 3px solid var(--high); }
  .anomaly-card.sev-MEDIUM   { border-left: 3px solid var(--accent); }
  .anomaly-card.sev-LOW      { border-left: 3px solid var(--muted); }

  .anomaly-icon { font-size: 1.3rem; flex-shrink: 0; }
  .anomaly-body { flex: 1; min-width: 0; }
  .anomaly-type  { font-size: 0.8rem; font-weight: 600; margin-bottom: 3px; }
  .anomaly-desc  { font-size: 0.72rem; color: var(--muted); margin-bottom: 6px; }
  .anomaly-detail {
    font-family: 'JetBrains Mono', monospace; font-size: 0.68rem;
    color: var(--accent);
    background: rgba(88,166,255,0.06);
    border: 1px solid rgba(88,166,255,0.15);
    border-radius: 4px; padding: 3px 7px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .anomaly-addr { font-family: 'JetBrains Mono', monospace; font-size: 0.65rem; color: var(--muted); margin-top: 4px; }

  /* Memory bar chart */
  .mem-bars { display: flex; flex-direction: column; gap: 3px; }
  .mem-row  { display: flex; align-items: center; gap: 8px; font-size: 0.72rem; }
  .mem-lbl  { width: 100px; color: var(--muted); font-family: 'JetBrains Mono', monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .mem-bar-wrap { flex: 1; background: var(--surface2); border-radius: 2px; height: 18px; overflow: hidden; }
  .mem-bar  { height: 100%; border-radius: 2px; display: flex; align-items: center; padding: 0 5px; font-size: 0.6rem; color: rgba(255,255,255,0.7); white-space: nowrap; overflow: hidden; }
  .mem-sz   { width: 55px; text-align: right; color: var(--muted); }

  /* Category pills */
  .cat-grid { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 24px; }
  .cat-pill {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 5px 14px;
    font-size: 0.78rem;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .cat-pill-count { font-family: 'JetBrains Mono', monospace; font-weight: 700; color: var(--accent); }

  /* Footer */
  .report-footer {
    text-align: center;
    color: var(--muted);
    font-size: 0.72rem;
    padding: 32px;
    border-top: 1px solid var(--border);
    margin-top: 40px;
  }

  /* Export button (visible in browser only) */
  .export-bar {
    position: fixed;
    bottom: 24px;
    right: 24px;
    z-index: 999;
    display: flex;
    gap: 10px;
  }

  .btn {
    padding: 10px 20px;
    border-radius: 8px;
    border: none;
    cursor: pointer;
    font-size: 0.85rem;
    font-weight: 600;
    font-family: 'Inter', sans-serif;
    transition: opacity 0.2s;
  }

  .btn:hover { opacity: 0.85; }

  .btn-print {
    background: var(--accent);
    color: #000;
  }
"""

ANOMALY_ICONS = {
    "HIGH_ENTROPY":   "🔐",
    "RWX_REGION":     "🔴",
    "PE_IN_PRIVATE":  "💉",
    "SUSPICIOUS_STR": "🕷️",
    "STACK_ANOMALY":  "📚",
    "UNBACKED_EXEC":  "👻",
    "HEAP_EXEC":      "⚠️",
}


def _html(text: str) -> str:
    """Escape HTML special characters."""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _badge(sev: str) -> str:
    return f'<span class="badge badge-{sev}">{sev}</span>'


def generate_report(
    report,           # AnalysisReport object
    anomalies: dict,  # anomaly_summary() dict
    regions:   list,  # list of MemoryRegion objects
    output_dir: str = "reports/output",
) -> str:
    """
    Build a self-contained HTML forensics report.
    Returns the absolute path to the generated file.
    """
    os.makedirs(output_dir, exist_ok=True)
    ts   = datetime.now()
    fname = f"memorymap_report_{report.pid}_{ts.strftime('%Y%m%d_%H%M%S')}.html"
    path  = os.path.join(output_dir, fname)

    html = _build_html(report, anomalies, regions, ts)

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    return path


def _build_html(report, anomalies: dict, regions: list, ts: datetime) -> str:
    risk_label = report.risk_label
    risk_score = report.risk_score
    proc_name  = report.process_name
    pid        = report.pid
    findings   = report.findings

    committed  = [r for r in regions if r.state == "COMMIT"]
    total_mb   = report.committed_mb

    # ── Cover page ─────────────────────────────────────────────────────────────
    cover = f"""
    <div class="cover">
      <div class="cover-inner">
        <div class="cover-logo">🧠</div>
        <h1>MemoryMap</h1>
        <p class="cover-subtitle">RAM Forensics &amp; Process Memory Analysis Report</p>

        <div class="risk-banner risk-{risk_label}">
          Risk Score: {risk_score}/100 &nbsp;·&nbsp; {risk_label}
        </div>

        <div class="cover-meta">
          <div class="cover-meta-item">
            <div class="cover-meta-label">Target Process</div>
            <div class="cover-meta-value">{_html(proc_name)}</div>
          </div>
          <div class="cover-meta-item">
            <div class="cover-meta-label">PID</div>
            <div class="cover-meta-value">{pid}</div>
          </div>
          <div class="cover-meta-item">
            <div class="cover-meta-label">Report Date</div>
            <div class="cover-meta-value">{ts.strftime('%Y-%m-%d %H:%M:%S')}</div>
          </div>
          <div class="cover-meta-item">
            <div class="cover-meta-label">Tool</div>
            <div class="cover-meta-value">MemoryMap v1.0</div>
          </div>
          <div class="cover-meta-item">
            <div class="cover-meta-label">Memory Scanned</div>
            <div class="cover-meta-value">{total_mb:.2f} MB</div>
          </div>
          <div class="cover-meta-item">
            <div class="cover-meta-label">Total Regions</div>
            <div class="cover-meta-value">{report.total_regions}</div>
          </div>
        </div>
      </div>
    </div>"""

    # ── Executive Summary ──────────────────────────────────────────────────────
    clean = risk_label == "CLEAN"
    summ_text = (
        f"This report presents the results of a live memory analysis performed against "
        f"<strong>{_html(proc_name)}</strong> (PID {pid}) on {ts.strftime('%B %d, %Y')}. "
        f"A total of <strong>{total_mb:.2f} MB</strong> of committed virtual memory across "
        f"<strong>{len(committed)} regions</strong> was scanned. "
    )
    if clean:
        summ_text += "No significant threats or sensitive data were identified in this process."
    else:
        summ_text += (
            f"The scan identified <strong>{report.total_findings} sensitive data finding(s)</strong> "
            f"(including {report.critical_count} CRITICAL, {report.high_count} HIGH) and "
            f"<strong>{anomalies.get('total', 0)} behavioral anomalie(s)</strong> in memory. "
            f"The overall risk score is <strong>{risk_score}/100 ({risk_label})</strong>."
        )

    exec_section = f"""
    <div class="page">
      <div class="section-h">📋 Executive Summary</div>
      <p style="color:var(--muted);margin-bottom:24px;line-height:1.8">{summ_text}</p>

      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-label">Risk Score</div>
          <div class="stat-value col-{risk_label.lower()}">{risk_score}</div>
          <div class="stat-sub">/ 100  [{risk_label}]</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Findings</div>
          <div class="stat-value col-accent">{report.total_findings}</div>
          <div class="stat-sub">unique patterns</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Critical</div>
          <div class="stat-value col-critical">{report.critical_count}</div>
          <div class="stat-sub">findings</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">High</div>
          <div class="stat-value col-high">{report.high_count}</div>
          <div class="stat-sub">findings</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Anomalies</div>
          <div class="stat-value col-high">{anomalies.get('total', 0)}</div>
          <div class="stat-sub">behavioral</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Memory</div>
          <div class="stat-value col-accent">{total_mb:.1f}</div>
          <div class="stat-sub">MB scanned</div>
        </div>
      </div>
    </div>"""

    # ── Findings section ───────────────────────────────────────────────────────
    if findings:
        # Category overview pills
        cats_html = "".join(
            f'<div class="cat-pill">'
            f'<span class="cat-pill-count">{cnt}</span> {_html(cat)}'
            f'</div>'
            for cat, cnt in report.category_map.items()
        )

        # Findings table rows
        rows_html = "".join(
            f"""<tr>
              <td>{_badge(f.severity)}</td>
              <td>{_html(f.category)}</td>
              <td class="mono">{f"0x{f.address:016X}"}</td>
              <td class="match-cell" title="{_html(f.match)}">{_html(f.truncated_match(80))}</td>
              <td style="color:var(--muted);font-size:0.72rem">{_html(f.pattern_name)}</td>
            </tr>"""
            for f in findings
        )

        findings_section = f"""
    <div class="page">
      <div class="section-h">🔍 Sensitive Data Findings</div>

      <div class="cat-grid">{cats_html}</div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Category</th>
              <th>Address</th>
              <th>Match (truncated)</th>
              <th>Pattern ID</th>
            </tr>
          </thead>
          <tbody>{rows_html}</tbody>
        </table>
      </div>
    </div>"""
    else:
        findings_section = """
    <div class="page">
      <div class="section-h">🔍 Sensitive Data Findings</div>
      <p style="color:var(--green);padding:24px;text-align:center">✔ No sensitive data found in memory.</p>
    </div>"""

    # ── Anomalies section ──────────────────────────────────────────────────────
    anom_items = anomalies.get("items", [])
    if anom_items:
        cards_html = "".join(
            f"""<div class="anomaly-card sev-{a['severity']}">
              <div class="anomaly-icon">{ANOMALY_ICONS.get(a['type'], '🔍')}</div>
              <div class="anomaly-body">
                <div class="anomaly-type">
                  {_badge(a['severity'])} {_html(a['type'].replace('_', ' '))}
                </div>
                <div class="anomaly-desc">{_html(a['description'])}</div>
                {f'<div class="anomaly-detail">{_html(a["detail"])}</div>' if a.get('detail') else ''}
                <div class="anomaly-addr">{_html(a['address'])} &nbsp;·&nbsp; {a['size_kb']} KB</div>
              </div>
            </div>"""
            for a in anom_items
        )
        anom_section = f"""
    <div class="page">
      <div class="section-h">🛡️ Behavioral Anomalies ({len(anom_items)} detected)</div>
      <div class="anomaly-grid">{cards_html}</div>
    </div>"""
    else:
        anom_section = """
    <div class="page">
      <div class="section-h">🛡️ Behavioral Anomalies</div>
      <p style="color:var(--green);padding:24px;text-align:center">✔ No behavioral anomalies detected.</p>
    </div>"""

    # ── Memory map section ─────────────────────────────────────────────────────
    top_regions = sorted(committed, key=lambda r: r.size, reverse=True)[:60]
    max_size    = max((r.size for r in top_regions), default=1)

    def _bar_color(r):
        if r.is_executable and r.is_writable:
            return "linear-gradient(90deg,#f85149,#f0a957)"
        if r.is_executable:
            return "linear-gradient(90deg,#bc8cff,#58a6ff)"
        if r.is_writable:
            return "linear-gradient(90deg,#3fb950,#58a6ff)"
        return "#21262d"

    bars_html = "".join(
        f"""<div class="mem-row">
          <div class="mem-lbl" title="0x{r.base_address:016X}">{r.base_address:08X}</div>
          <div class="mem-bar-wrap">
            <div class="mem-bar" style="width:{max(1,(r.size/max_size)*100):.1f}%;background:{_bar_color(r)}">
              {r.protect}
            </div>
          </div>
          <div class="mem-sz">{'%.1fMB'%(r.size/1048576) if r.size>=1048576 else '%.0fKB'%(r.size/1024)}</div>
        </div>"""
        for r in top_regions
    )

    mem_section = f"""
    <div class="page">
      <div class="section-h">🗺️ Memory Region Map (top {len(top_regions)} by size)</div>
      <div class="mem-bars">{bars_html}</div>
      <div style="margin-top:12px;font-size:0.72rem;color:var(--muted)">
        <span style="color:#bc8cff">■</span> Executable &nbsp;
        <span style="color:#3fb950">■</span> Writable &nbsp;
        <span style="color:#f85149">■</span> Exec+Write (suspicious) &nbsp;
        <span style="color:#30363d">■</span> Read-Only
      </div>
    </div>"""

    # ── Footer ─────────────────────────────────────────────────────────────────
    footer = f"""
    <div class="report-footer">
      MemoryMap &mdash; RAM Forensics Tool &nbsp;|&nbsp;
      Report generated {ts.strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
      Target: {_html(proc_name)} (PID {pid})
    </div>

    <!-- Print button (hidden on print) -->
    <div class="export-bar no-print">
      <button class="btn btn-print" onclick="window.print()">🖨️ Print / Save PDF</button>
    </div>"""

    # ── Assemble full document ─────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>MemoryMap Report — {_html(proc_name)} (PID {pid})</title>
  <style>{_REPORT_CSS}</style>
</head>
<body>
{cover}
{exec_section}
{findings_section}
{anom_section}
{mem_section}
{footer}
</body>
</html>"""
