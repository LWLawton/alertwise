"""
alertwise/reporter.py
======================
Report generation for AlertWise.

Produces:
  1. TXT report — plain text, full details, suitable for CLI piping / archiving
  2. HTML report — professional, responsive HTML with:
       - Executive summary banner
       - Per-alert cards with severity badges, score bars, TI results
       - SIEM tuning section
       - Inline charts (no external JS required for core layout)
       - Print-friendly styling
"""

import datetime
import html as html_mod
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Colour / badge helpers
# ---------------------------------------------------------------------------

DECISION_COLORS = {
    "ESCALATE":    ("#FF3B3B", "#fff"),
    "INVESTIGATE": ("#FF8C00", "#fff"),
    "MONITOR":     ("#2196F3", "#fff"),
    "SUPPRESS":    ("#6c757d", "#fff"),
    "BENIGN":      ("#28a745", "#fff"),
}

SEVERITY_COLORS = {
    "Critical": "#c0392b",
    "High":     "#e74c3c",
    "Medium":   "#f39c12",
    "Low":      "#27ae60",
    "Info":     "#3498db",
    "Unknown":  "#95a5a6",
}


def _decision_badge(decision: str) -> str:
    bg, fg = DECISION_COLORS.get(decision, ("#333", "#fff"))
    return (
        f'<span style="background:{bg};color:{fg};padding:3px 10px;border-radius:4px;'
        f'font-weight:700;font-size:0.78em;letter-spacing:0.05em;">'
        f'{html_mod.escape(decision)}</span>'
    )


def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#95a5a6")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:3px;'
        f'font-weight:600;font-size:0.75em;">'
        f'{html_mod.escape(severity)}</span>'
    )


def _score_bar(score: int) -> str:
    color = "#28a745" if score < 30 else "#f39c12" if score < 60 else "#e74c3c"
    return (
        f'<div style="display:inline-flex;align-items:center;gap:8px;">'
        f'<div style="width:120px;background:#e9ecef;border-radius:4px;height:10px;overflow:hidden;">'
        f'<div style="width:{score}%;background:{color};height:100%;border-radius:4px;"></div></div>'
        f'<span style="font-weight:700;color:{color};">{score}/100</span>'
        f'</div>'
    )


def _h(text: Any) -> str:
    """HTML-escape and stringify."""
    return html_mod.escape(str(text) if text is not None else "")


# ---------------------------------------------------------------------------
# TXT Report
# ---------------------------------------------------------------------------

def _txt_separator(char: str = "─", width: int = 80) -> str:
    return char * width


def generate_txt_report(results: list[dict], tuning: dict, output_path: str) -> str:
    """Write a plain-text triage report. Returns the file path."""
    lines: list[str] = []
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    lines += [
        "=" * 80,
        "  ALERTWISE — SIEM Alert Triage & Noise Reduction Engine",
        f"  Report Generated: {now}",
        "=" * 80,
        "",
        f"Total Alerts Processed : {len(results)}",
        f"Escalate               : {sum(1 for r in results if r['scoring']['decision'] == 'ESCALATE')}",
        f"Investigate            : {sum(1 for r in results if r['scoring']['decision'] == 'INVESTIGATE')}",
        f"Monitor                : {sum(1 for r in results if r['scoring']['decision'] == 'MONITOR')}",
        f"Suppress               : {sum(1 for r in results if r['scoring']['decision'] == 'SUPPRESS')}",
        f"Benign                 : {sum(1 for r in results if r['scoring']['decision'] == 'BENIGN')}",
        "",
        _txt_separator("─"),
        "ALERT TRIAGE DETAILS",
        _txt_separator("─"),
        "",
    ]

    for i, r in enumerate(results, 1):
        alert = r["alert"]
        scoring = r["scoring"]
        suppression = r["suppression"]
        enrichment = r["enrichment"]

        lines += [
            f"[{i}] {alert.get('title', 'Untitled')}",
            f"    Alert ID  : {alert.get('alert_id', 'N/A')}",
            f"    Severity  : {alert.get('severity', 'Unknown')}",
            f"    Score     : {scoring.get('score', 0)}/100",
            f"    Decision  : {scoring.get('decision', '?')} ({scoring.get('confidence', '?')} confidence)",
            f"    Source    : {alert.get('source_product', 'Unknown')}",
            f"    Timestamp : {alert.get('timestamp', 'N/A')}",
            f"    MITRE     : {alert.get('mitre_technique', 'N/A')} / {alert.get('mitre_tactic', 'N/A')}",
            "",
            "    Description:",
            f"      {alert.get('description', 'N/A')}",
            "",
        ]

        # Indicators
        ind = alert.get("indicators", {})
        flat_ind = []
        for k, v in ind.items():
            if v:
                flat_ind.append(f"{k}: {', '.join(str(x) for x in v[:5])}")
        if flat_ind:
            lines.append("    Indicators:")
            for i_line in flat_ind:
                lines.append(f"      • {i_line}")
            lines.append("")

        # Suppression
        if suppression.get("suppressed"):
            lines.append(f"    ⛔ SUPPRESSED: {suppression.get('reason', '')}")
        elif suppression.get("matched_rules"):
            lines.append(f"    ⚠  Rules matched (not suppressed): {', '.join(suppression['matched_rules'])}")

        # Reasoning
        lines.append("    Scoring Reasoning:")
        for reason in scoring.get("reasoning", []):
            lines.append(f"      • {reason}")

        # TI enrichment summary
        if enrichment.get("enabled") and enrichment.get("results"):
            lines.append(f"    Threat Intelligence ({enrichment.get('indicator_count', 0)} indicators):")
            for key, ti_results in enrichment["results"].items():
                for tr in ti_results:
                    if "error" not in tr:
                        lines.append(
                            f"      [{tr['provider'].upper():<12}] {key} → "
                            f"score={tr.get('score', 0)}, tags={tr.get('tags', [])}"
                        )

        lines += ["", _txt_separator("·"), ""]

    # SIEM Tuning
    lines += [
        "",
        _txt_separator("═"),
        "SIEM TUNING RECOMMENDATIONS",
        _txt_separator("═"),
        "",
        tuning.get("summary_text", "No recommendations available."),
        "",
    ]

    if tuning.get("noisy_rules"):
        lines.append("Noisy Rules:")
        for nr in tuning["noisy_rules"]:
            lines.append(
                f"  • {nr['rule_id']}: fired {nr['fire_count']}x, "
                f"suppressed {nr['suppress_count']}x, avg score {nr['avg_score']}"
            )
            lines.append(f"    → {nr['recommendation']}")
        lines.append("")

    if tuning.get("severity_miscalibrations"):
        lines.append("Severity Miscalibrations:")
        for sm in tuning["severity_miscalibrations"]:
            lines.append(f"  • {sm['suggestion']}")
        lines.append("")

    if tuning.get("whitelist_suggestions"):
        lines.append("Whitelist Suggestions:")
        for ws in tuning["whitelist_suggestions"]:
            lines.append(f"  • {ws['suggestion']}")
        lines.append("")

    lines += ["", "=" * 80, "  END OF REPORT — AlertWise", "=" * 80]

    report_text = "\n".join(lines)
    Path(output_path).write_text(report_text, encoding="utf-8")
    logger.info("TXT report written to %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------

def _build_alert_card(i: int, r: dict) -> str:
    alert = r["alert"]
    scoring = r["scoring"]
    suppression = r["suppression"]
    enrichment = r["enrichment"]

    title = _h(alert.get("title", "Untitled"))
    alert_id = _h(alert.get("alert_id", ""))
    severity = alert.get("severity", "Unknown")
    description = _h(alert.get("description", ""))
    score = scoring.get("score", 0)
    decision = scoring.get("decision", "?")
    confidence = scoring.get("confidence", "?")
    source = _h(alert.get("source_product", "Unknown"))
    timestamp = _h(alert.get("timestamp", "N/A"))
    mitre_t = _h(alert.get("mitre_technique", "—"))
    mitre_ta = _h(alert.get("mitre_tactic", "—"))

    # Severity left-border colour
    border_color = SEVERITY_COLORS.get(severity, "#95a5a6")

    # Indicators table
    ind = alert.get("indicators", {})
    ind_rows = ""
    for k, v in ind.items():
        if v:
            values_html = ", ".join(_h(x) for x in v[:8])
            ind_rows += f"<tr><td><b>{_h(k)}</b></td><td>{values_html}</td></tr>"

    # TI results table
    ti_rows = ""
    if enrichment.get("enabled") and enrichment.get("results"):
        for key, ti_list in enrichment["results"].items():
            for tr_result in ti_list:
                provider = _h(tr_result.get("provider", ""))
                ti_score = tr_result.get("score", 0)
                tags = ", ".join(_h(t) for t in tr_result.get("tags", []))
                err = _h(tr_result.get("error", ""))
                score_cell = f'<span style="color:{"#e74c3c" if ti_score > 50 else "#27ae60"}"><b>{ti_score}</b></span>' if not err else f'<span style="color:#999">{err}</span>'
                ti_rows += (
                    f"<tr><td><b>{provider.upper()}</b></td>"
                    f"<td>{_h(key)}</td>"
                    f"<td>{score_cell}</td>"
                    f"<td>{tags or '—'}</td></tr>"
                )

    # Reasoning bullets
    reasoning_html = "".join(
        f"<li>{_h(r_str)}</li>" for r_str in scoring.get("reasoning", [])
    )

    # Suppression notice
    suppress_html = ""
    if suppression.get("suppressed"):
        suppress_html = (
            f'<div class="suppress-notice">⛔ <b>Suppressed:</b> {_h(suppression.get("reason", ""))}</div>'
        )
    elif suppression.get("matched_rules"):
        rules_str = ", ".join(suppression["matched_rules"])
        suppress_html = (
            f'<div class="warn-notice">⚠ Rule(s) matched (override active): {_h(rules_str)}</div>'
        )

    return f"""
<div class="alert-card" id="alert-{i}" style="border-left:4px solid {border_color}">
  <div class="alert-header">
    <span class="alert-num">#{i}</span>
    <span class="alert-title">{title}</span>
    <span class="badge-group">
      {_severity_badge(severity)}
      {_decision_badge(decision)}
    </span>
  </div>
  <div class="alert-meta">
    <span>🆔 <b>{alert_id}</b></span>
    <span>📡 {source}</span>
    <span>🕐 {timestamp}</span>
    <span>🛡 MITRE: <code>{mitre_t}</code> / {mitre_ta}</span>
    <span>Confidence: <b>{_h(confidence)}</b></span>
  </div>
  <p class="alert-desc">{description}</p>
  {suppress_html}
  <div class="score-row">
    <b>Risk Score:</b>&nbsp; {_score_bar(score)}
  </div>

  <details>
    <summary>📊 Scoring Breakdown</summary>
    <ul class="reason-list">{reasoning_html}</ul>
  </details>

  {"<details><summary>🔍 Indicators</summary><table class='detail-table'><thead><tr><th>Type</th><th>Values</th></tr></thead><tbody>" + ind_rows + "</tbody></table></details>" if ind_rows else ""}

  {"<details><summary>🌐 Threat Intelligence Results</summary><table class='detail-table'><thead><tr><th>Provider</th><th>Indicator</th><th>Score</th><th>Tags</th></tr></thead><tbody>" + ti_rows + "</tbody></table></details>" if ti_rows else "<p class='ti-disabled'><em>TI enrichment disabled or no results</em></p>"}
</div>
"""


def generate_html_report(results: list[dict], tuning: dict, output_path: str) -> str:
    """Write a professional HTML triage report. Returns the file path."""
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    total = len(results)

    counts = {d: 0 for d in ("ESCALATE", "INVESTIGATE", "MONITOR", "SUPPRESS", "BENIGN")}
    for r in results:
        d = r.get("scoring", {}).get("decision", "BENIGN")
        counts[d] = counts.get(d, 0) + 1

    # Summary bar data for JS chart
    chart_labels = list(counts.keys())
    chart_values = list(counts.values())
    chart_colors = [DECISION_COLORS[k][0] for k in chart_labels]

    # Build alert cards
    cards_html = "\n".join(_build_alert_card(i + 1, r) for i, r in enumerate(results))

    # Tuning section
    tuning_html = _build_tuning_section(tuning)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AlertWise Triage Report — {now}</title>
<style>
:root {{
  --bg: #0f1117;
  --card-bg: #1a1d27;
  --border: #2a2d3e;
  --text: #e2e8f0;
  --text-muted: #8892a4;
  --accent: #4fc3f7;
  --font: 'Segoe UI', system-ui, -apple-system, sans-serif;
  --mono: 'Cascadia Code', 'Fira Code', monospace;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: var(--font);
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  padding: 0;
}}
a {{ color: var(--accent); }}

/* HEADER */
.aw-header {{
  background: linear-gradient(135deg, #0d1b2a 0%, #1a1d27 50%, #0d1b2a 100%);
  border-bottom: 1px solid var(--border);
  padding: 32px 40px 24px;
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
}}
.aw-logo {{
  font-size: 2rem;
  font-weight: 800;
  letter-spacing: -0.03em;
  color: var(--accent);
}}
.aw-logo span {{ color: #f59e0b; }}
.aw-meta {{ color: var(--text-muted); font-size: 0.85rem; text-align: right; }}

/* SUMMARY STATS */
.summary-bar {{
  display: flex;
  gap: 0;
  padding: 0 40px;
  margin: 24px 0;
  flex-wrap: wrap;
  gap: 12px;
}}
.stat-card {{
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px 24px;
  flex: 1;
  min-width: 120px;
  text-align: center;
}}
.stat-card .num {{ font-size: 2rem; font-weight: 800; }}
.stat-card .lbl {{ font-size: 0.78rem; color: var(--text-muted); letter-spacing: 0.05em; text-transform: uppercase; }}
.stat-escalate {{ border-top: 3px solid #FF3B3B; }}
.stat-investigate {{ border-top: 3px solid #FF8C00; }}
.stat-monitor {{ border-top: 3px solid #2196F3; }}
.stat-suppress {{ border-top: 3px solid #6c757d; }}
.stat-benign {{ border-top: 3px solid #28a745; }}
.stat-total {{ border-top: 3px solid var(--accent); }}

/* CHART */
.chart-section {{
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin: 0 40px 24px;
  padding: 20px 24px;
}}
.chart-title {{ font-size: 0.9rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 12px; }}
.chart-bars {{ display: flex; gap: 12px; align-items: flex-end; height: 80px; }}
.chart-bar-wrap {{ display: flex; flex-direction: column; align-items: center; gap: 4px; flex: 1; }}
.chart-bar {{ width: 100%; border-radius: 4px 4px 0 0; transition: opacity 0.2s; cursor: default; min-height: 4px; }}
.chart-bar:hover {{ opacity: 0.8; }}
.chart-bar-lbl {{ font-size: 0.65rem; color: var(--text-muted); text-align: center; }}
.chart-bar-val {{ font-size: 0.75rem; font-weight: 700; }}

/* MAIN CONTENT */
.content {{ padding: 0 40px 40px; }}
.section-title {{
  font-size: 1.1rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--accent);
  margin: 32px 0 16px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}}

/* ALERT CARDS */
.alert-card {{
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px 24px;
  margin-bottom: 16px;
  transition: box-shadow 0.2s;
}}
.alert-card:hover {{ box-shadow: 0 4px 24px rgba(0,0,0,0.4); }}
.alert-header {{
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 10px;
}}
.alert-num {{ color: var(--text-muted); font-size: 0.85rem; font-weight: 700; min-width: 28px; }}
.alert-title {{ font-size: 1rem; font-weight: 700; flex: 1; }}
.badge-group {{ display: flex; gap: 6px; flex-wrap: wrap; }}
.alert-meta {{
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
  font-size: 0.8rem;
  color: var(--text-muted);
  margin-bottom: 10px;
}}
.alert-meta code {{ font-family: var(--mono); color: var(--accent); font-size: 0.85em; }}
.alert-desc {{
  font-size: 0.88rem;
  color: var(--text-muted);
  margin: 8px 0 12px;
  line-height: 1.5;
}}
.score-row {{ margin: 12px 0; font-size: 0.9rem; }}
.suppress-notice {{
  background: rgba(108,117,125,0.15);
  border: 1px solid #6c757d;
  border-radius: 4px;
  padding: 8px 12px;
  font-size: 0.85rem;
  margin: 8px 0;
}}
.warn-notice {{
  background: rgba(255,140,0,0.1);
  border: 1px solid #FF8C00;
  border-radius: 4px;
  padding: 8px 12px;
  font-size: 0.85rem;
  margin: 8px 0;
}}
.ti-disabled {{ font-size: 0.82rem; color: var(--text-muted); margin: 8px 0; }}

/* Details / summary */
details {{ margin: 8px 0; }}
summary {{
  cursor: pointer;
  font-size: 0.88rem;
  font-weight: 600;
  color: var(--accent);
  padding: 6px 0;
  user-select: none;
  list-style: none;
}}
summary::-webkit-details-marker {{ display: none; }}
summary::before {{ content: "▶ "; font-size: 0.7em; }}
details[open] summary::before {{ content: "▼ "; }}
.reason-list {{ padding: 8px 0 4px 20px; }}
.reason-list li {{ font-size: 0.84rem; color: var(--text-muted); margin-bottom: 4px; }}

/* Tables */
.detail-table {{
  width: 100%;
  border-collapse: collapse;
  margin-top: 10px;
  font-size: 0.82rem;
}}
.detail-table th {{
  background: rgba(255,255,255,0.05);
  padding: 6px 10px;
  text-align: left;
  font-weight: 600;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
}}
.detail-table td {{
  padding: 5px 10px;
  border-bottom: 1px solid rgba(255,255,255,0.04);
  vertical-align: top;
  word-break: break-all;
}}
.detail-table tr:last-child td {{ border-bottom: none; }}
.detail-table tr:hover td {{ background: rgba(255,255,255,0.03); }}

/* Tuning section */
.tuning-block {{
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px 24px;
  margin-bottom: 16px;
}}
.tuning-block h3 {{
  font-size: 0.9rem;
  font-weight: 700;
  color: var(--accent);
  margin-bottom: 12px;
  text-transform: uppercase;
}}
.tuning-summary {{
  font-size: 0.9rem;
  color: var(--text-muted);
  margin-bottom: 16px;
  padding: 12px 16px;
  background: rgba(79,195,247,0.05);
  border-left: 3px solid var(--accent);
  border-radius: 0 4px 4px 0;
}}
.rec-item {{
  background: rgba(255,255,255,0.03);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 10px 14px;
  margin-bottom: 8px;
  font-size: 0.85rem;
}}
.rec-item .ri-label {{ font-weight: 700; color: var(--text); }}
.rec-item .ri-rec {{ color: var(--text-muted); margin-top: 4px; }}

/* FOOTER */
.aw-footer {{
  text-align: center;
  padding: 24px 40px;
  color: var(--text-muted);
  font-size: 0.8rem;
  border-top: 1px solid var(--border);
  margin-top: 40px;
}}

/* Print */
@media print {{
  body {{ background: white; color: black; }}
  .aw-header, .summary-bar .stat-card, .alert-card, .tuning-block {{ border: 1px solid #ccc; }}
  details {{ display: block; }}
  summary {{ display: none; }}
}}
</style>
</head>
<body>

<div class="aw-header">
  <div>
    <div class="aw-logo">Alert<span>Wise</span></div>
    <div style="font-size:0.82rem;color:#8892a4;margin-top:4px;">SIEM Alert Triage &amp; Noise Reduction Engine</div>
  </div>
  <div class="aw-meta">
    Generated: {_h(now)}<br>
    Total Alerts: <b>{total}</b>
  </div>
</div>

<!-- SUMMARY STATS -->
<div class="summary-bar">
  <div class="stat-card stat-total"><div class="num">{total}</div><div class="lbl">Total</div></div>
  <div class="stat-card stat-escalate"><div class="num" style="color:#FF3B3B">{counts['ESCALATE']}</div><div class="lbl">Escalate</div></div>
  <div class="stat-card stat-investigate"><div class="num" style="color:#FF8C00">{counts['INVESTIGATE']}</div><div class="lbl">Investigate</div></div>
  <div class="stat-card stat-monitor"><div class="num" style="color:#2196F3">{counts['MONITOR']}</div><div class="lbl">Monitor</div></div>
  <div class="stat-card stat-suppress"><div class="num" style="color:#6c757d">{counts['SUPPRESS']}</div><div class="lbl">Suppressed</div></div>
  <div class="stat-card stat-benign"><div class="num" style="color:#28a745">{counts['BENIGN']}</div><div class="lbl">Benign</div></div>
</div>

<!-- DISTRIBUTION CHART -->
<div class="chart-section">
  <div class="chart-title">Decision Distribution</div>
  <div class="chart-bars" id="chartBars">
    <!-- Filled by JS -->
  </div>
</div>

<div class="content">
  <div class="section-title">🚨 Alert Triage Results</div>
  {cards_html}

  <div class="section-title">🔧 SIEM Tuning Recommendations</div>
  {tuning_html}
</div>

<div class="aw-footer">
  AlertWise v1.0.0 · Open Source SIEM Triage Engine · Report generated {_h(now)}
</div>

<script>
// Render distribution bar chart
const labels = {json.dumps(chart_labels)};
const values = {json.dumps(chart_values)};
const colors = {json.dumps(chart_colors)};
const maxVal = Math.max(...values, 1);
const container = document.getElementById('chartBars');
labels.forEach((lbl, i) => {{
  const heightPct = Math.round((values[i] / maxVal) * 100);
  const wrap = document.createElement('div');
  wrap.className = 'chart-bar-wrap';
  wrap.innerHTML = `
    <span class="chart-bar-val" style="color:${{colors[i]}}">${{values[i]}}</span>
    <div class="chart-bar" style="height:${{Math.max(heightPct, 5)}}%;background:${{colors[i]}};" title="${{lbl}}: ${{values[i]}}"></div>
    <span class="chart-bar-lbl">${{lbl}}</span>
  `;
  container.appendChild(wrap);
}});
</script>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    logger.info("HTML report written to %s", output_path)
    return output_path


def _build_tuning_section(tuning: dict) -> str:
    parts: list[str] = []

    summary = _h(tuning.get("summary_text", "No tuning data available."))
    parts.append(f'<div class="tuning-summary">{summary}</div>')

    # Noisy rules
    noisy = tuning.get("noisy_rules", [])
    if noisy:
        rows = ""
        for nr in noisy:
            rows += (
                f'<div class="rec-item">'
                f'<div class="ri-label">📣 {_h(nr["rule_id"])} — fired <b>{nr["fire_count"]}×</b>, '
                f'suppressed <b>{nr["suppress_count"]}×</b>, avg score <b>{nr["avg_score"]}/100</b></div>'
                f'<div class="ri-rec">→ {_h(nr["recommendation"])}</div>'
                f'</div>'
            )
        parts.append(f'<div class="tuning-block"><h3>🔊 Noisy Rules</h3>{rows}</div>')

    # Suppression candidates
    sc = tuning.get("suppression_candidates", [])
    if sc:
        rows = ""
        for item in sc:
            rows += (
                f'<div class="rec-item">'
                f'<div class="ri-label">⛔ {_h(item["rule_id"])} — '
                f'{int(item["suppress_ratio"] * 100)}% suppression rate</div>'
                f'<div class="ri-rec">→ {_h(item["suggestion"])}</div>'
                f'</div>'
            )
        parts.append(f'<div class="tuning-block"><h3>🔕 Suppression Candidates</h3>{rows}</div>')

    # Severity miscalibrations
    sm = tuning.get("severity_miscalibrations", [])
    if sm:
        rows = ""
        for item in sm:
            rows += (
                f'<div class="rec-item">'
                f'<div class="ri-label">⚖ {_h(item["rule_id"])} — '
                f'Severity: {_h(item["declared_severity"])}, Avg Score: {item["avg_risk_score"]}/100</div>'
                f'<div class="ri-rec">→ {_h(item["suggestion"])}</div>'
                f'</div>'
            )
        parts.append(f'<div class="tuning-block"><h3>⚖ Severity Miscalibrations</h3>{rows}</div>')

    # Whitelist suggestions
    ws = tuning.get("whitelist_suggestions", [])
    if ws:
        rows = ""
        for item in ws[:10]:
            rows += (
                f'<div class="rec-item">'
                f'<div class="ri-label">📋 [{_h(item["type"].upper())}] {_h(item["value"])} — '
                f'seen {item["frequency"]}×</div>'
                f'<div class="ri-rec">→ {_h(item["suggestion"])}</div>'
                f'</div>'
            )
        parts.append(f'<div class="tuning-block"><h3>✅ Whitelist Suggestions</h3>{rows}</div>')

    if not parts[1:]:
        parts.append('<div class="tuning-block"><p style="color:var(--text-muted)">No significant tuning recommendations at this time. Run with more alerts for better analysis.</p></div>')

    return "\n".join(parts)
