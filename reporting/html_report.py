"""Self-contained HTML report generator for SOC alert triage results."""
import hashlib
import json
import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from scoring.constants import PRIORITY_LABELS

logger = logging.getLogger(__name__)

# Priority label → (border color, background color) — dark-theme tinted panels
PRIORITY_COLORS = {
    "INVESTIGATE_NOW":  ("#e55c4a", "#3d1c18"),
    "INVESTIGATE_SOON": ("#e8943a", "#3a2414"),
    "MONITOR":          ("#4aaddb", "#142840"),
    "LOW_PRIORITY":     ("#4e6880", "#1c2e40"),
}

# MITRE ATT&CK tactic → badge color
TACTIC_COLORS = {
    "RECONNAISSANCE":       "#8e44ad",
    "INITIAL_ACCESS":       "#c0392b",
    "EXECUTION":            "#e74c3c",
    "PERSISTENCE":          "#e67e22",
    "PRIVILEGE_ESCALATION": "#f39c12",
    "DEFENSE_EVASION":      "#27ae60",
    "CREDENTIAL_ACCESS":    "#16a085",
    "DISCOVERY":            "#2980b9",
    "LATERAL_MOVEMENT":     "#1a5276",
    "COLLECTION":           "#6c3483",
    "COMMAND_AND_CONTROL":  "#922b21",
    "EXFILTRATION":         "#7b241c",
    "IMPACT":               "#641e16",
}


def _score_to_color(score: float) -> str:
    """Return a hex color for the given score using standard priority thresholds."""
    if score >= 0.80:
        return "#c0392b"
    elif score >= 0.55:
        return "#e67e22"
    elif score >= 0.30:
        return "#2980b9"
    return "#95a5a6"


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
    incidents_panel_html = _build_incidents_panel(incidents or [])
    histogram_html = _build_score_histogram(results)
    weights_json = json.dumps(weights, indent=2)

    config_hash = hashlib.md5(json.dumps(config, sort_keys=True).encode()).hexdigest()[:8]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Alert Triage Report \u2014 {now}</title>
<style>
  :root {{
    --bg:          #0d1b2a;
    --panel:       #162232;
    --panel-alt:   #1a2b3d;
    --panel-hover: #1f3347;
    --border:      #243d55;
    --border-soft: #1e3249;
    --text:        #c8d8e8;
    --text-muted:  #7a96b0;
    --text-dim:    #4e6880;
    --accent:      #3498db;
    --shadow:      0 2px 8px rgba(0,0,0,0.35);
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); font-size: 14px; }}
  .page {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}
  .header {{ background: #0a1520; color: white; padding: 24px 32px; border-radius: 8px; margin-bottom: 24px; border: 1px solid var(--border); }}
  .header h1 {{ font-size: 22px; font-weight: 600; margin-bottom: 8px; }}
  .header .meta {{ font-size: 12px; color: var(--text-muted); display: flex; gap: 24px; flex-wrap: wrap; }}
  .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
  .summary-card {{ background: var(--panel); border-radius: 8px; padding: 20px; text-align: center; box-shadow: var(--shadow); border: 1px solid var(--border); }}
  .summary-card .count {{ font-size: 32px; font-weight: 700; line-height: 1; }}
  .summary-card .label {{ font-size: 11px; color: var(--text-muted); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }}
  .inv-now   .count {{ color: #e55c4a; }}
  .inv-soon  .count {{ color: #e8943a; }}
  .monitor   .count {{ color: #4aaddb; }}
  .low-pri   .count {{ color: var(--text-dim); }}
  .section-title {{ font-size: 15px; font-weight: 600; margin-bottom: 16px; color: var(--text); border-left: 3px solid var(--accent); padding-left: 10px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr)); gap: 16px; margin-bottom: 32px; }}
  .card {{ border-radius: 8px; padding: 18px 20px; border-left: 4px solid; box-shadow: var(--shadow); background: var(--panel); }}
  .card-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px; }}
  .card-name {{ font-weight: 600; font-size: 13px; flex: 1; margin-right: 12px; color: var(--text); }}
  .card-score {{ font-size: 20px; font-weight: 700; white-space: nowrap; }}
  .card-label {{ font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.6; margin-bottom: 6px; color: var(--text-muted); }}
  .card-summary {{ font-size: 12px; color: var(--text-muted); line-height: 1.5; margin-bottom: 10px; }}
  .card-meta {{ display: flex; gap: 8px; flex-wrap: wrap; font-size: 11px; color: var(--text-muted); }}
  .tag {{ background: rgba(255,255,255,0.06); border-radius: 3px; padding: 2px 6px; border: 1px solid var(--border-soft); }}
  .table-container {{ background: var(--panel); border-radius: 8px; box-shadow: var(--shadow); border: 1px solid var(--border); margin-bottom: 24px; overflow: hidden; }}
  .table-scroll {{ overflow-x: auto; }}
  .table-controls {{ padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }}
  .filter-btn {{ padding: 5px 12px; border: 1px solid var(--border); border-radius: 4px; background: var(--panel-alt); color: var(--text-muted); cursor: pointer; font-size: 12px; transition: all 0.15s; white-space: nowrap; }}
  .filter-btn.active, .filter-btn:hover {{ background: var(--accent); color: white; border-color: var(--accent); }}
  .search-box {{ padding: 5px 10px; border: 1px solid var(--border); border-radius: 4px; font-size: 12px; width: 220px; background: var(--panel-alt); color: var(--text); }}
  .search-box::placeholder {{ color: var(--text-dim); }}
  .search-box:focus {{ outline: none; border-color: var(--accent); box-shadow: 0 0 0 2px rgba(52,152,219,0.2); }}
  table {{ width: 100%; border-collapse: collapse; min-width: 900px; }}
  th {{ background: var(--panel-alt); text-align: left; padding: 10px 14px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.4px; color: var(--text-muted); border-bottom: 1px solid var(--border); cursor: pointer; user-select: none; white-space: nowrap; }}
  th:hover {{ background: var(--panel-hover); color: var(--text); }}
  th .sort-icon {{ margin-left: 4px; opacity: 0.3; }}
  td {{ padding: 10px 14px; border-bottom: 1px solid var(--border-soft); vertical-align: top; font-size: 12px; color: var(--text); }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: var(--panel-hover); }}
  tr.hidden {{ display: none; }}
  .score-cell {{ white-space: nowrap; }}
  .score-bar-wrap {{ display: flex; align-items: center; gap: 6px; }}
  .score-bar {{ height: 8px; border-radius: 4px; background: var(--border); width: 80px; overflow: hidden; }}
  .score-fill {{ height: 100%; border-radius: 4px; }}
  .score-val {{ font-weight: 600; width: 32px; text-align: right; }}
  .badge {{ display: inline-block; font-size: 10px; font-weight: 600; padding: 2px 7px; border-radius: 3px; text-transform: uppercase; letter-spacing: 0.3px; white-space: nowrap; }}
  .badge-INVESTIGATE_NOW  {{ background: rgba(192,57,43,0.25); color: #e55c4a; border: 1px solid rgba(192,57,43,0.4); }}
  .badge-INVESTIGATE_SOON {{ background: rgba(230,126,34,0.20); color: #e8943a; border: 1px solid rgba(230,126,34,0.35); }}
  .badge-MONITOR          {{ background: rgba(41,128,185,0.20); color: #4aaddb; border: 1px solid rgba(41,128,185,0.35); }}
  .badge-LOW_PRIORITY     {{ background: rgba(127,140,141,0.15); color: var(--text-dim); border: 1px solid var(--border); }}
  .tactic-badge {{ display: inline-block; font-size: 10px; font-weight: 600; padding: 2px 7px; border-radius: 3px; color: white; text-transform: uppercase; letter-spacing: 0.3px; white-space: nowrap; margin: 1px; opacity: 0.9; }}
  .expand-btn {{ cursor: pointer; color: var(--accent); font-size: 11px; text-decoration: underline; background: none; border: none; padding: 0; white-space: nowrap; }}
  .expand-btn:hover {{ color: #5dade2; }}
  .breakdown-row {{ display: none; }}
  .breakdown-row.open {{ display: table-row; }}
  .breakdown-inner {{ padding: 12px 14px; background: var(--panel-alt); border-top: 1px solid var(--border); }}
  .breakdown-bars {{ display: flex; flex-direction: column; gap: 6px; }}
  .breakdown-item {{ display: flex; align-items: center; gap: 8px; font-size: 11px; }}
  .breakdown-name {{ width: 150px; color: var(--text-muted); }}
  .breakdown-bar {{ flex: 1; height: 8px; background: var(--border); border-radius: 4px; overflow: hidden; }}
  .breakdown-bar-fill {{ height: 100%; border-radius: 4px; background: var(--accent); }}
  .breakdown-val {{ width: 36px; text-align: right; color: var(--text); font-weight: 600; }}
  .conf-high   {{ color: #2ecc71; font-weight: 600; }}
  .conf-medium {{ color: #e8943a; font-weight: 600; }}
  .conf-low    {{ color: #e55c4a; font-weight: 600; }}
  .sighting-first {{ color: #2ecc71; font-weight: 600; font-size: 11px; }}
  .sighting-low   {{ color: #e8943a; font-weight: 600; font-size: 11px; }}
  .sighting-high  {{ color: #e55c4a; font-weight: 600; font-size: 11px; }}
  .footer {{ font-size: 11px; color: var(--text-dim); text-align: center; margin-top: 24px; padding: 16px; }}
  .footer code {{ background: var(--panel-alt); padding: 1px 5px; border-radius: 3px; font-family: monospace; color: var(--text-muted); border: 1px solid var(--border); }}
  /* Incidents panel */
  .incidents-panel {{ margin-bottom: 28px; }}
  .incidents-panel-stats {{ display: flex; gap: 14px; margin-bottom: 16px; flex-wrap: wrap; }}
  .istat {{ background: var(--panel); border-radius: 8px; padding: 14px 20px; box-shadow: var(--shadow); min-width: 130px; border: 1px solid var(--border); }}
  .istat-num {{ font-size: 26px; font-weight: 700; color: var(--text); line-height: 1; }}
  .istat-lbl {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.4px; margin-top: 4px; }}
  .istat.kill .istat-num {{ color: #e55c4a; }}
  .incident-cards-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 14px; }}
  .incident-card {{ border-radius: 8px; padding: 16px 18px; border-left: 4px solid; box-shadow: var(--shadow); background: var(--panel); }}
  .incident-card-score {{ font-size: 28px; font-weight: 700; line-height: 1; margin-bottom: 6px; }}
  .incident-card-host {{ font-size: 14px; font-weight: 600; color: var(--text); margin-bottom: 4px; font-family: monospace; }}
  .incident-card-span {{ font-size: 11px; color: var(--text-muted); margin-bottom: 8px; }}
  .incident-card-tactics {{ display: flex; flex-wrap: wrap; gap: 2px; align-items: center; }}
  .kill-chain-badge {{ display: inline-block; background: #c0392b; color: white; font-size: 10px; font-weight: 700; padding: 2px 7px; border-radius: 3px; text-transform: uppercase; letter-spacing: 0.5px; margin-left: 4px; }}
  /* Histogram */
  .score-histogram-wrap {{ background: var(--panel); border-radius: 8px; box-shadow: var(--shadow); padding: 18px 20px; margin-bottom: 16px; border: 1px solid var(--border); }}
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

  {incidents_panel_html}

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

  <div class="section-title">All Alerts</div>
  {histogram_html}
  <div class="table-container">
    <div class="table-controls">
      <input type="text" id="search-box" class="search-box" placeholder="Search alerts\u2026" oninput="searchTable(this.value)">
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
    const q = (document.getElementById('search-box')?.value || '').toLowerCase();
    document.querySelectorAll('tr[data-label]').forEach(row => {{
      const labelMatch = label === 'ALL' || row.dataset.label === label;
      const searchMatch = !q || _rowMatchesSearch(row, q);
      const show = labelMatch && searchMatch;
      if (show) {{
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

  function _rowMatchesSearch(row, q) {{
    const text = [0, 1, 2].map(i => (row.cells[i]?.textContent || '')).join(' ').toLowerCase();
    return text.includes(q);
  }}

  function searchTable(val) {{
    const q = val.toLowerCase();
    const activeBtn = document.querySelector('.filter-btn.active');
    const activeLabel = activeBtn?.dataset?.filterLabel || 'ALL';
    document.querySelectorAll('tr[data-label]').forEach(row => {{
      const labelMatch = activeLabel === 'ALL' || row.dataset.label === activeLabel;
      const searchMatch = !q || _rowMatchesSearch(row, q);
      const show = labelMatch && searchMatch;
      if (show) {{
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

    Includes columns for MITRE ATT&CK tactic (colored badge) and Prior
    Sightings (baseline indicator showing first-seen vs repeat activity).

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
        <th onclick="sortTable(8)">MITRE Tactic <span class="sort-icon">\u21c5</span></th>
        <th onclick="sortTable(9)">Prior Sightings <span class="sort-icon">\u21c5</span></th>
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

        bar_color = _score_to_color(r.score)

        score_pct = int(r.score * 100)
        conf_class = f"conf-{r.confidence}"
        safe_id = _esc(r.alert_id).replace(" ", "_").replace("&", "").replace(";", "")

        # MITRE tactic cell
        mitre_tactic = getattr(alert, "mitre_tactic", None) if alert else None
        if mitre_tactic:
            tactic_color = TACTIC_COLORS.get(mitre_tactic.upper(), "#7f8c8d")
            mitre_cell = (
                f'<span class="tactic-badge" style="background:{tactic_color};">'
                f"{_esc(mitre_tactic)}</span>"
            )
        else:
            mitre_cell = "\u2014"

        # Prior sightings cell
        sightings = getattr(r, "prior_sightings_count", None)
        if sightings is None:
            sightings_cell = "\u2014"
        elif sightings == 0:
            sightings_cell = '<span class="sighting-first">First seen</span>'
        elif sightings <= 2:
            sightings_cell = f'<span class="sighting-low">{sightings} prior</span>'
        else:
            sightings_cell = f'<span class="sighting-high">{sightings} prior \u26a0</span>'

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
        <td>{mitre_cell}</td>
        <td>{sightings_cell}</td>
        <td><button class="expand-btn" onclick="toggleBreakdown('{safe_id}')">details</button></td>
      </tr>
      <tr class="breakdown-row" id="bdr-{safe_id}">
        <td colspan="11">
          <div class="breakdown-inner">
            <div style="font-size:11px;color:#555;margin-bottom:8px;">{_esc(r.analyst_summary)}</div>
            <div class="breakdown-bars">{breakdown_html}</div>
          </div>
        </td>
      </tr>""")

    return '<div class="table-scroll">' + header + "\n".join(rows) + "\n    </tbody>\n  </table></div>"


def _build_incidents_panel(incidents: list) -> str:
    """Build the correlated incidents summary panel HTML.

    Shows: incident count, kill chain count, a card per incident showing
    host, alert count, duration, combined score, tactic chain, kill chain badge.

    Only shows the top 10 incidents by combined_score.
    If incidents is empty, returns an empty string (section is hidden).

    Args:
        incidents: List of CorrelatedIncident instances.

    Returns:
        HTML for the incidents panel, or "" if incidents is empty.
    """
    if not incidents:
        return ""

    top10 = sorted(incidents, key=lambda i: i.combined_score, reverse=True)[:10]
    incident_count = len(incidents)
    kill_chain_count = sum(1 for i in incidents if i.kill_chain_detected)

    cards = []
    for inc in top10:
        score_color = _score_to_color(inc.combined_score)
        border_color, bg_color = PRIORITY_COLORS.get(inc.priority_label, ("#95a5a6", "#f8f9fa"))

        try:
            start_dt = datetime.fromisoformat(inc.start_time.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(inc.end_time.replace("Z", "+00:00"))
            duration_min = int((end_dt - start_dt).total_seconds() / 60)
        except Exception:
            duration_min = 0

        alert_word = "alert" if inc.alert_count == 1 else "alerts"
        span_text = f"{inc.alert_count} {alert_word} over {duration_min}min"

        tactic_badges = " ".join(
            f'<span class="tactic-badge" style="background:{TACTIC_COLORS.get(t.upper(), "#7f8c8d")};">'
            f"{_esc(t)}</span>"
            for t in inc.tactic_chain
        )
        kill_badge = (
            '<span class="kill-chain-badge">KILL CHAIN</span>'
            if inc.kill_chain_detected
            else ""
        )

        cards.append(f"""
    <div class="incident-card" style="border-left-color:{border_color};background:{bg_color};">
      <div class="incident-card-score" style="color:{score_color};">{inc.combined_score:.2f}</div>
      <div class="incident-card-host">{_esc(inc.host)}</div>
      <div class="incident-card-span">{span_text}</div>
      <div class="incident-card-tactics">{tactic_badges}{kill_badge}</div>
    </div>""")

    return f"""<div class="incidents-panel">
  <div class="section-title">Correlated Incidents</div>
  <div class="incidents-panel-stats">
    <div class="istat">
      <div class="istat-num">{incident_count}</div>
      <div class="istat-lbl">Total Incidents</div>
    </div>
    <div class="istat kill">
      <div class="istat-num">{kill_chain_count}</div>
      <div class="istat-lbl">Kill Chains Detected</div>
    </div>
  </div>
  <div class="incident-cards-grid">{"".join(cards)}
  </div>
</div>"""


def _build_score_histogram(results: list) -> str:
    """Build an inline SVG score distribution histogram.

    Groups alerts into 10 equal-width buckets (0.0–0.1, 0.1–0.2, … 0.9–1.0)
    and renders vertical bars sized proportionally to the count in each bucket.
    Bars are color-coded using the same priority thresholds as score bars.

    Args:
        results: All TriageResult instances.

    Returns:
        HTML string wrapping the SVG histogram, or "" if results is empty.
    """
    if not results:
        return ""

    buckets = [0] * 10
    for r in results:
        idx = min(int(r.score * 10), 9)
        buckets[idx] += 1

    max_count = max(buckets) if any(buckets) else 1

    bar_w = 28
    bar_gap = 6
    margin_left = 28
    margin_top = 8
    max_bar_h = 44
    label_h = 14
    svg_w = margin_left + (bar_w + bar_gap) * 10 - bar_gap + 4
    svg_h = margin_top + max_bar_h + label_h + 4

    bars = []
    for i, count in enumerate(buckets):
        x = margin_left + i * (bar_w + bar_gap)
        bar_h = int((count / max_count) * max_bar_h) if max_count > 0 else 0
        y = margin_top + max_bar_h - bar_h

        low = i * 0.1
        bucket_color = _score_to_color(low) if low > 0 else "#bdc3c7"

        bars.append(
            f'<rect x="{x}" y="{y}" width="{bar_w}" height="{bar_h}" '
            f'fill="{bucket_color}" rx="2" opacity="0.85"/>'
        )
        label_y = margin_top + max_bar_h + label_h
        bars.append(
            f'<text x="{x + bar_w // 2}" y="{label_y}" '
            f'text-anchor="middle" font-size="8" fill="#7a96b0">{low:.1f}</text>'
        )
        if count > 0:
            bars.append(
                f'<text x="{x + bar_w // 2}" y="{y - 2}" '
                f'text-anchor="middle" font-size="9" fill="#c8d8e8">{count}</text>'
            )

    svg = (
        f'<svg width="{svg_w}" height="{svg_h}" '
        f'style="display:block;" aria-label="Score distribution histogram">'
        + "".join(bars)
        + "</svg>"
    )

    return (
        f'<div class="score-histogram-wrap">'
        f'<div style="font-size:12px;font-weight:600;color:#7a96b0;margin-bottom:10px;'
        f'text-transform:uppercase;letter-spacing:0.4px;">Score Distribution</div>'
        f"{svg}"
        f"</div>"
    )


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
