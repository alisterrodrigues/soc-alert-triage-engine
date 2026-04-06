"""Self-contained HTML report generator for SOC alert triage results."""
import hashlib
import json
import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Priority label → (border color, background color)
PRIORITY_COLORS = {
    "INVESTIGATE_NOW":  ("#c0392b", "#fadbd8"),
    "INVESTIGATE_SOON": ("#e67e22", "#fdebd0"),
    "MONITOR":          ("#2980b9", "#d6eaf8"),
    "LOW_PRIORITY":     ("#7f8c8d", "#f2f3f4"),
}


def render_report(
    results: list,
    alerts: list,
    run_id: str,
    config: dict,
    output_path: str,
    incidents: Optional[list] = None,
) -> str:
    """Generate a self-contained HTML triage report and write it to disk.

    Builds the full HTML document as a string, writes it to output_path,
    and returns the path. Never raises — on any error, logs and returns "".

    The caller is responsible for ensuring the parent directory exists;
    this function does not auto-create arbitrary directory trees so that
    bad paths fail naturally and return "" rather than silently creating
    unexpected directories.

    Args:
        results: List of TriageResult dataclass instances, sorted by score desc.
        alerts: List of Alert dataclass instances in the same order as results.
        run_id: UUID string for this pipeline run.
        config: Full config dict (for scoring weights and reporting settings).
        output_path: File path to write the HTML file to.
        incidents: Optional list of CorrelatedIncident instances from the correlation engine.

    Returns:
        The output_path string on success, or "" on failure.
    """
    try:
        html = _build_html(results, alerts, run_id, config, incidents=incidents)
        path = Path(output_path)
        path.write_text(html, encoding="utf-8")
        logger.info(f"HTML report written to {output_path}")
        return output_path
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")
        return ""


def _build_html(
    results: list,
    alerts: list,
    run_id: str,
    config: dict,
    incidents: Optional[list] = None,
) -> str:
    """Assemble the full HTML document string.

    Args:
        results: List of TriageResult instances.
        alerts: List of Alert instances parallel to results.
        run_id: Pipeline run UUID.
        config: Full config dict.
        incidents: Optional list of CorrelatedIncident instances.

    Returns:
        Complete HTML document as a string.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    reporting_cfg = config.get("reporting", {})
    highlight_n = reporting_cfg.get("highlight_top_n", 5)
    weights = config.get("scoring", {}).get("weights", {})

    label_counts = Counter(r.priority_label for r in results)
    top_alerts = results[:highlight_n]

    alert_map = {a.alert_id: a for a in alerts}

    cards_html = _build_priority_cards(top_alerts, alert_map)
    table_html = _build_alert_table(results, alert_map)
    incidents_html = _build_incidents_section(incidents or [])
    weights_json = json.dumps(weights, indent=2)

    config_hash = hashlib.md5(json.dumps(config, sort_keys=True).encode()).hexdigest()[:8]

    incident_count = len(incidents) if incidents else 0
    kill_chain_count = sum(1 for i in (incidents or []) if i.kill_chain_detected)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Alert Triage Report \u2014 {now}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f6fa; color: #2c3e50; font-size: 14px; }}
  .page {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}
  .header {{ background: #1a252f; color: white; padding: 24px 32px; border-radius: 8px; margin-bottom: 24px; }}
  .header h1 {{ font-size: 22px; font-weight: 600; margin-bottom: 8px; }}
  .header .meta {{ font-size: 12px; color: #95a5a6; display: flex; gap: 24px; flex-wrap: wrap; }}
  .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
  .summary-card {{ background: white; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
  .summary-card .count {{ font-size: 32px; font-weight: 700; line-height: 1; }}
  .summary-card .label {{ font-size: 11px; color: #7f8c8d; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }}
  .inv-now   .count {{ color: #c0392b; }}
  .inv-soon  .count {{ color: #e67e22; }}
  .monitor   .count {{ color: #2980b9; }}
  .low-pri   .count {{ color: #7f8c8d; }}
  .section-title {{ font-size: 15px; font-weight: 600; margin-bottom: 16px; color: #2c3e50; border-left: 3px solid #3498db; padding-left: 10px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr)); gap: 16px; margin-bottom: 32px; }}
  .card {{ border-radius: 8px; padding: 18px 20px; border-left: 4px solid; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
  .card-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px; }}
  .card-name {{ font-weight: 600; font-size: 13px; flex: 1; margin-right: 12px; }}
  .card-score {{ font-size: 20px; font-weight: 700; white-space: nowrap; }}
  .card-label {{ font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.7; margin-bottom: 6px; }}
  .card-summary {{ font-size: 12px; color: #555; line-height: 1.5; margin-bottom: 10px; }}
  .card-meta {{ display: flex; gap: 8px; flex-wrap: wrap; font-size: 11px; color: #666; }}
  .tag {{ background: rgba(0,0,0,0.06); border-radius: 3px; padding: 2px 6px; }}
  .table-container {{ background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); overflow: hidden; margin-bottom: 24px; }}
  .table-controls {{ padding: 16px 20px; border-bottom: 1px solid #ecf0f1; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }}
  .filter-btn {{ padding: 5px 12px; border: 1px solid #ddd; border-radius: 4px; background: white; cursor: pointer; font-size: 12px; transition: all 0.15s; }}
  .filter-btn.active, .filter-btn:hover {{ background: #3498db; color: white; border-color: #3498db; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #f8f9fa; text-align: left; padding: 10px 14px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.4px; color: #7f8c8d; border-bottom: 1px solid #ecf0f1; cursor: pointer; user-select: none; white-space: nowrap; }}
  th:hover {{ background: #eef2f7; }}
  th .sort-icon {{ margin-left: 4px; opacity: 0.4; }}
  td {{ padding: 10px 14px; border-bottom: 1px solid #f0f0f0; vertical-align: top; font-size: 12px; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #fafbfc; }}
  tr.hidden {{ display: none; }}
  .score-cell {{ white-space: nowrap; }}
  .score-bar-wrap {{ display: flex; align-items: center; gap: 6px; }}
  .score-bar {{ height: 6px; border-radius: 3px; background: #ecf0f1; width: 80px; overflow: hidden; }}
  .score-fill {{ height: 100%; border-radius: 3px; }}
  .score-val {{ font-weight: 600; width: 32px; text-align: right; }}
  .badge {{ display: inline-block; font-size: 10px; font-weight: 600; padding: 2px 7px; border-radius: 3px; text-transform: uppercase; letter-spacing: 0.3px; white-space: nowrap; }}
  .badge-INVESTIGATE_NOW  {{ background: #fadbd8; color: #922b21; }}
  .badge-INVESTIGATE_SOON {{ background: #fdebd0; color: #a04000; }}
  .badge-MONITOR          {{ background: #d6eaf8; color: #1a5276; }}
  .badge-LOW_PRIORITY     {{ background: #f2f3f4; color: #566573; }}
  .expand-btn {{ cursor: pointer; color: #3498db; font-size: 11px; text-decoration: underline; background: none; border: none; padding: 0; }}
  .breakdown-row {{ display: none; }}
  .breakdown-row.open {{ display: table-row; }}
  .breakdown-inner {{ padding: 12px 14px; background: #f8f9fa; }}
  .breakdown-bars {{ display: flex; flex-direction: column; gap: 6px; }}
  .breakdown-item {{ display: flex; align-items: center; gap: 8px; font-size: 11px; }}
  .breakdown-name {{ width: 150px; color: #555; }}
  .breakdown-bar {{ flex: 1; height: 8px; background: #ecf0f1; border-radius: 4px; overflow: hidden; }}
  .breakdown-bar-fill {{ height: 100%; border-radius: 4px; background: #3498db; }}
  .breakdown-val {{ width: 36px; text-align: right; color: #333; font-weight: 600; }}
  .conf-high   {{ color: #27ae60; font-weight: 600; }}
  .conf-medium {{ color: #e67e22; font-weight: 600; }}
  .conf-low    {{ color: #e74c3c; font-weight: 600; }}
  .footer {{ font-size: 11px; color: #95a5a6; text-align: center; margin-top: 24px; padding: 16px; }}
  .footer code {{ background: #ecf0f1; padding: 1px 5px; border-radius: 3px; font-family: monospace; }}
  .incident-stats {{ display: flex; gap: 16px; margin-bottom: 16px; flex-wrap: wrap; }}
  .incident-stat {{ background: white; border-radius: 8px; padding: 14px 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); min-width: 140px; }}
  .incident-stat .icount {{ font-size: 26px; font-weight: 700; color: #2c3e50; }}
  .incident-stat .ilabel {{ font-size: 11px; color: #7f8c8d; text-transform: uppercase; letter-spacing: 0.4px; margin-top: 2px; }}
  .kill-chain-count .icount {{ color: #c0392b; }}
  .incident-table-wrap {{ background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); overflow: hidden; margin-bottom: 32px; }}
  .incident-table-wrap table {{ width: 100%; border-collapse: collapse; }}
  .incident-table-wrap th {{ background: #f8f9fa; text-align: left; padding: 10px 14px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.4px; color: #7f8c8d; border-bottom: 1px solid #ecf0f1; }}
  .incident-table-wrap td {{ padding: 10px 14px; border-bottom: 1px solid #f0f0f0; font-size: 12px; vertical-align: top; }}
  .incident-table-wrap tr:last-child td {{ border-bottom: none; }}
  .incident-table-wrap tr:hover td {{ background: #fafbfc; }}
  .kill-yes {{ color: #c0392b; font-weight: 600; }}
  .kill-no  {{ color: #95a5a6; }}
  .tactic-tag {{ display: inline-block; background: #eaf4fb; color: #1a5276; border-radius: 3px; padding: 1px 5px; font-size: 10px; margin: 1px; }}
</style>
</head>
<body>
<div class="page">

  <div class="header">
    <h1>SOC Alert Triage Report</h1>
    <div class="meta">
      <span>Generated: {now}</span>
      <span>Run ID: {run_id}</span>
      <span>Total alerts: {len(results)}</span>
      <span>Config hash: {config_hash}</span>
    </div>
  </div>

  <div class="summary">
    <div class="summary-card inv-now">
      <div class="count">{label_counts.get("INVESTIGATE_NOW", 0)}</div>
      <div class="label">Investigate Now</div>
    </div>
    <div class="summary-card inv-soon">
      <div class="count">{label_counts.get("INVESTIGATE_SOON", 0)}</div>
      <div class="label">Investigate Soon</div>
    </div>
    <div class="summary-card monitor">
      <div class="count">{label_counts.get("MONITOR", 0)}</div>
      <div class="label">Monitor</div>
    </div>
    <div class="summary-card low-pri">
      <div class="count">{label_counts.get("LOW_PRIORITY", 0)}</div>
      <div class="label">Low Priority</div>
    </div>
  </div>

  <div class="section-title">Top {highlight_n} Priority Alerts</div>
  <div class="cards">
    {cards_html}
  </div>

  <div class="section-title">Correlated Incidents</div>
  <div class="incident-stats">
    <div class="incident-stat">
      <div class="icount">{incident_count}</div>
      <div class="ilabel">Total Incidents</div>
    </div>
    <div class="incident-stat kill-chain-count">
      <div class="icount">{kill_chain_count}</div>
      <div class="ilabel">Kill Chain Detected</div>
    </div>
  </div>
  {incidents_html}

  <div class="section-title">All Alerts</div>
  <div class="table-container">
    <div class="table-controls">
      <span style="font-size:12px;color:#666;margin-right:4px;">Filter:</span>
      <button class="filter-btn active" onclick="filterTable(this, 'ALL')">All ({len(results)})</button>
      <button class="filter-btn" onclick="filterTable(this, 'INVESTIGATE_NOW')">Investigate Now ({label_counts.get("INVESTIGATE_NOW", 0)})</button>
      <button class="filter-btn" onclick="filterTable(this, 'INVESTIGATE_SOON')">Investigate Soon ({label_counts.get("INVESTIGATE_SOON", 0)})</button>
      <button class="filter-btn" onclick="filterTable(this, 'MONITOR')">Monitor ({label_counts.get("MONITOR", 0)})</button>
      <button class="filter-btn" onclick="filterTable(this, 'LOW_PRIORITY')">Low Priority ({label_counts.get("LOW_PRIORITY", 0)})</button>
    </div>
    {table_html}
  </div>

  <div class="footer">
    Scoring weights: <code>{_esc(weights_json)}</code> &nbsp;|&nbsp;
    Model version: 1.0 &nbsp;|&nbsp; Config hash: {config_hash}
  </div>

</div>
<script>
  function filterTable(btn, label) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('tr[data-label]').forEach(row => {{
      if (label === 'ALL' || row.dataset.label === label) {{
        row.classList.remove('hidden');
        const bdr = document.getElementById('bdr-' + row.dataset.id);
        if (bdr) bdr.classList.remove('hidden');
      }} else {{
        row.classList.add('hidden');
        const bdr = document.getElementById('bdr-' + row.dataset.id);
        if (bdr) {{ bdr.classList.add('hidden'); bdr.classList.remove('open'); }}
      }}
    }});
  }}

  function toggleBreakdown(id) {{
    const row = document.getElementById('bdr-' + id);
    if (!row) return;
    row.classList.toggle('open');
  }}

  let sortCol = -1, sortAsc = false;
  function sortTable(colIdx) {{
    const table = document.querySelector('table');
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr[data-label]'));
    if (sortCol === colIdx) {{ sortAsc = !sortAsc; }} else {{ sortCol = colIdx; sortAsc = false; }}
    rows.sort((a, b) => {{
      const av = a.cells[colIdx]?.dataset.val || a.cells[colIdx]?.textContent || '';
      const bv = b.cells[colIdx]?.dataset.val || b.cells[colIdx]?.textContent || '';
      const an = parseFloat(av), bn = parseFloat(bv);
      if (!isNaN(an) && !isNaN(bn)) return sortAsc ? an - bn : bn - an;
      return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
    }});
    rows.forEach(r => {{
      tbody.appendChild(r);
      const bdr = document.getElementById('bdr-' + r.dataset.id);
      if (bdr) tbody.appendChild(bdr);
    }});
  }}
</script>
</body>
</html>"""


def _build_priority_cards(top_results: list, alert_map: dict) -> str:
    """Build HTML for the top-N priority alert cards.

    Args:
        top_results: Subset of TriageResult instances to display as cards.
        alert_map: Dict mapping alert_id to Alert instances.

    Returns:
        HTML string containing all card div elements.
    """
    cards = []
    for r in top_results:
        border_color, bg_color = PRIORITY_COLORS.get(r.priority_label, ("#95a5a6", "#f8f9fa"))
        alert = alert_map.get(r.alert_id)
        src_ip = alert.source_ip if alert else "\u2014"
        severity = alert.severity.capitalize() if alert else "\u2014"
        category = alert.category.replace("_", " ").title() if alert else "\u2014"
        asset_tags = ", ".join(alert.asset_tags) if alert else "\u2014"
        alert_name = alert.alert_name if alert else r.alert_id

        cards.append(f"""
    <div class="card" style="border-left-color:{border_color};background:{bg_color};">
      <div class="card-label">{r.priority_label.replace("_", " ")}</div>
      <div class="card-header">
        <div class="card-name">{_esc(alert_name)}</div>
        <div class="card-score" style="color:{border_color};">{r.score:.2f}</div>
      </div>
      <div class="card-summary">{_esc(r.analyst_summary)}</div>
      <div class="card-meta">
        <span class="tag">ID: {_esc(r.alert_id)}</span>
        <span class="tag">{_esc(src_ip)}</span>
        <span class="tag">{_esc(severity)}</span>
        <span class="tag">{_esc(category)}</span>
        <span class="tag">{_esc(asset_tags)}</span>
        <span class="tag">conf: {_esc(r.confidence)}</span>
      </div>
    </div>""")
    return "\n".join(cards)


def _build_alert_table(results: list, alert_map: dict) -> str:
    """Build the full sortable/filterable HTML table of all alerts.

    Args:
        results: All TriageResult instances.
        alert_map: Dict mapping alert_id to Alert instances.

    Returns:
        HTML string containing the complete <table> element.
    """
    header = """
  <table>
    <thead>
      <tr>
        <th onclick="sortTable(0)">Alert ID <span class="sort-icon">\u21c5</span></th>
        <th onclick="sortTable(1)">Alert Name <span class="sort-icon">\u21c5</span></th>
        <th onclick="sortTable(2)">Source IP <span class="sort-icon">\u21c5</span></th>
        <th onclick="sortTable(3)">Severity <span class="sort-icon">\u21c5</span></th>
        <th onclick="sortTable(4)">Category <span class="sort-icon">\u21c5</span></th>
        <th onclick="sortTable(5)">Score <span class="sort-icon">\u21c5</span></th>
        <th onclick="sortTable(6)">Priority <span class="sort-icon">\u21c5</span></th>
        <th onclick="sortTable(7)">Confidence <span class="sort-icon">\u21c5</span></th>
        <th>Breakdown</th>
      </tr>
    </thead>
    <tbody>"""

    rows = []
    for r in results:
        alert = alert_map.get(r.alert_id)
        src_ip = _esc(alert.source_ip) if alert else "\u2014"
        severity = alert.severity.capitalize() if alert else "\u2014"
        category = _esc(alert.category.replace("_", " ")) if alert else "\u2014"
        alert_name = _esc(alert.alert_name if alert else r.alert_id)

        if r.score >= 0.80:
            bar_color = "#c0392b"
        elif r.score >= 0.55:
            bar_color = "#e67e22"
        elif r.score >= 0.30:
            bar_color = "#2980b9"
        else:
            bar_color = "#95a5a6"

        score_pct = int(r.score * 100)
        conf_class = f"conf-{r.confidence}"
        safe_id = _esc(r.alert_id).replace(" ", "_").replace("&", "").replace(";", "")

        breakdown_items = []
        max_val = max(r.score_breakdown.values()) if r.score_breakdown else 1.0
        for factor, val in r.score_breakdown.items():
            bar_w = int((val / max(max_val, 0.001)) * 100)
            breakdown_items.append(f"""
          <div class="breakdown-item">
            <div class="breakdown-name">{_esc(factor.replace("_", " "))}</div>
            <div class="breakdown-bar"><div class="breakdown-bar-fill" style="width:{bar_w}%"></div></div>
            <div class="breakdown-val">{val:.3f}</div>
          </div>""")

        breakdown_html = "\n".join(breakdown_items)

        rows.append(f"""
      <tr data-label="{r.priority_label}" data-id="{safe_id}">
        <td>{_esc(r.alert_id)}</td>
        <td title="{_esc(r.analyst_summary)}">{alert_name}</td>
        <td>{src_ip}</td>
        <td data-val="{_esc(severity)}">{_esc(severity)}</td>
        <td>{category}</td>
        <td class="score-cell" data-val="{r.score}">
          <div class="score-bar-wrap">
            <div class="score-bar"><div class="score-fill" style="width:{score_pct}%;background:{bar_color};"></div></div>
            <div class="score-val" style="color:{bar_color};">{r.score:.2f}</div>
          </div>
        </td>
        <td><span class="badge badge-{r.priority_label}">{_esc(r.priority_label.replace("_", " "))}</span></td>
        <td class="{conf_class}">{_esc(r.confidence)}</td>
        <td><button class="expand-btn" onclick="toggleBreakdown('{safe_id}')">details</button></td>
      </tr>
      <tr class="breakdown-row" id="bdr-{safe_id}">
        <td colspan="9">
          <div class="breakdown-inner">
            <div style="font-size:11px;color:#555;margin-bottom:8px;">{_esc(r.analyst_summary)}</div>
            <div class="breakdown-bars">{breakdown_html}</div>
          </div>
        </td>
      </tr>""")

    return header + "\n".join(rows) + "\n    </tbody>\n  </table>"


def _build_incidents_section(incidents: list) -> str:
    """Build an HTML table section listing all correlated incidents.

    Args:
        incidents: List of CorrelatedIncident instances, sorted by combined_score desc.

    Returns:
        HTML string for the incidents table, or an empty-state message if none.
    """
    if not incidents:
        return '<div style="color:#95a5a6;font-size:13px;padding:16px 0;">No correlated incidents detected.</div>'

    rows = []
    for inc in incidents:
        score_color = (
            "#c0392b" if inc.combined_score >= 0.80 else
            "#e67e22" if inc.combined_score >= 0.55 else
            "#2980b9" if inc.combined_score >= 0.30 else
            "#95a5a6"
        )
        tactic_tags = " ".join(
            f'<span class="tactic-tag">{_esc(t)}</span>' for t in inc.tactic_chain
        ) or "<span style='color:#aaa'>—</span>"
        kill_html = (
            '<span class="kill-yes">&#10003; Yes</span>'
            if inc.kill_chain_detected
            else '<span class="kill-no">No</span>'
        )
        short_id = inc.incident_id[:8]
        rows.append(f"""
      <tr>
        <td><code style="font-size:11px;">{_esc(short_id)}</code></td>
        <td>{_esc(inc.host)}</td>
        <td style="text-align:center;">{inc.alert_count}</td>
        <td style="font-weight:600;color:{score_color};">{inc.combined_score:.2f}</td>
        <td><span class="badge badge-{inc.priority_label}">{_esc(inc.priority_label.replace("_", " "))}</span></td>
        <td>{kill_html}</td>
        <td>{tactic_tags}</td>
        <td style="font-size:11px;color:#555;">{_esc(inc.summary)}</td>
      </tr>""")

    return f"""<div class="incident-table-wrap">
  <table>
    <thead>
      <tr>
        <th>Incident</th>
        <th>Host</th>
        <th>Alerts</th>
        <th>Score</th>
        <th>Priority</th>
        <th>Kill Chain</th>
        <th>Tactic Chain</th>
        <th>Summary</th>
      </tr>
    </thead>
    <tbody>{"".join(rows)}
    </tbody>
  </table>
</div>"""


def _esc(text) -> str:
    """Escape HTML special characters, casting non-strings to str first.

    Args:
        text: Value to escape; any type is accepted.

    Returns:
        HTML-safe string with &, <, >, and " escaped.
    """
    if not isinstance(text, str):
        text = str(text)
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
