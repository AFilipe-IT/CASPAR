"""
core/report_dashboard.py
-------------------------
Dashboard HTML self-contained (consola de auditoria) a partir de um ScanResult.
Gráficos SVG inline — 100% offline. Cada issue abre um drawer lateral com
toda a informação rica (narrativa, justificações por métrica, cenário, snippet).

Uso:
    from config_assessment.reports.report_dashboard import generate_dashboard
    html = generate_dashboard(result, resolved=resolved)
"""

from __future__ import annotations
import json as _json
import math

_AV_DESC = {"L": "Local", "A": "Adjacent", "N": "Network"}
_AU_DESC = {"M": "Multiple", "S": "Single", "N": "None"}
_AC_DESC = {"H": "High complexity", "M": "Medium complexity", "L": "Low complexity"}
_CIA_DESC = {"N": "None", "P": "Partial", "C": "Complete"}
_GEL_DESC = {"N": "None", "L": "Low", "M": "Medium", "H": "High", "ND": "Not Defined"}
_GRL_DESC = {"U": "Unavailable", "W": "Workaround", "H": "Official (CIS)", "ND": "Not Defined"}


def _sev_class(s):
    if s >= 9: return "critical"
    if s >= 7: return "high"
    if s >= 4: return "medium"
    if s > 0:  return "low"
    return "none"

def _sev_label(s):
    if s >= 9: return "Critical"
    if s >= 7: return "High"
    if s >= 4: return "Medium"
    if s > 0:  return "Low"
    return "None"

def _e(t):
    return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def _display_value(issue):
    """Return the display string for the bad_value field.
    Absence issues (rule_type='absence') have bad_value='' — show a badge instead."""
    if getattr(issue, "rule_type", "value") == "absence":
        return '<span style="font-style:italic;color:var(--mt)">[not configured]</span>'
    return _e(issue.bad_value)

def _strip_metric_prefix(text):
    import re
    t = str(text).strip()
    t = re.sub(r"^(?:Why\s+)?(?:AV|Au|AC|C|I|A|GEL|GRL)\s*=\s*[A-Za-z]+\s*:\s*", "", t)
    return t.strip()

def _strip_code(text):
    import re
    t = str(text)
    t = re.sub(r"</?code>", "", t)
    t = re.sub(r"</?pre>", "", t)
    t = re.sub(r"```[a-zA-Z]*", "", t)
    return t.strip()


def _av_why(av, rationale=""):
    b = {"N": "The service listens on non-loopback addresses, reachable by any remote attacker.",
         "A": "Reachable only from the local network segment.",
         "L": "Only listens on loopback; needs local shell or physical access."}.get(av, "")
    return (b + (f" Detected: {rationale}" if rationale else "")).strip()

def _au_why(au, rationale=""):
    b = {"N": "No authentication directives detected; unauthenticated access permitted.",
         "S": "One set of valid credentials required.",
         "M": "Multiple authentication steps required."}.get(au, "")
    return (b + (f" Detected: {rationale}" if rationale else "")).strip()


def _group_issues(issues):
    from collections import OrderedDict
    g = OrderedDict()
    for issue in issues:
        k = (issue.directive, issue.bad_value)
        if k not in g:
            g[k] = {"issue": issue, "contexts": []}
        src = issue.source_directive
        if src and src.source_file:
            ctx = f"{src.source_file}:{src.line_number}"
            if src.context and src.context != "global":
                ctx += f" [{src.context}]"
            if ctx not in g[k]["contexts"]:
                g[k]["contexts"].append(ctx)
    return list(g.values())


def _dedup_chains(chains):
    seen, out = set(), []
    for c in chains:
        k = frozenset(c.triggered_by)
        if k not in seen:
            seen.add(k); out.append(c)
    return out


def _read_snippet(file_path, line_number, context=2):
    try:
        from pathlib import Path
        lines = Path(file_path).read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    if not line_number or line_number < 1 or line_number > len(lines):
        return []
    start = max(1, line_number - context)
    end = min(len(lines), line_number + context)
    return [(i, lines[i - 1], i == line_number) for i in range(start, end + 1)]


def _svg_gauge(score):
    cls = _sev_class(score)
    frac = max(0.0, min(1.0, score / 10.0))
    cx, cy, r = 130, 130, 100
    sa = math.pi
    ea = math.pi - frac * math.pi
    x1 = cx + r * math.cos(sa); y1 = cy - r * math.sin(sa)
    x2 = cx + r * math.cos(ea); y2 = cy - r * math.sin(ea)
    bx2 = cx + r * math.cos(0); by2 = cy - r * math.sin(0)
    track = f"M {x1:.1f} {y1:.1f} A {r} {r} 0 0 1 {bx2:.1f} {by2:.1f}"
    arc = f"M {x1:.1f} {y1:.1f} A {r} {r} 0 0 1 {x2:.1f} {y2:.1f}"
    return f'''<svg viewBox="0 0 260 160" class="gauge" role="img" aria-label="Score {score:.1f}">
  <path d="{track}" class="gauge-track" fill="none" stroke-width="14" stroke-linecap="round"/>
  <path d="{arc}" class="gauge-arc gauge-{cls}" fill="none" stroke-width="14" stroke-linecap="round"/>
  <text x="130" y="116" class="gauge-score gauge-text-{cls}" text-anchor="middle">{score:.1f}</text>
  <text x="130" y="142" class="gauge-max" text-anchor="middle">/ 10.0</text>
</svg>'''


def _svg_donut(counts):
    order = [("Critical", "critical"), ("High", "high"), ("Medium", "medium"), ("Low", "low")]
    total = sum(counts.get(k, 0) for k, _ in order)
    if total == 0:
        return '<div class="empty-chart">No issues detected</div>'
    cx, cy, r, stroke = 90, 90, 64, 24
    circ = 2 * math.pi * r
    segs, offset = [], 0.0
    for label, cls in order:
        n = counts.get(label, 0)
        if n == 0:
            continue
        seg_len = (n / total) * circ
        segs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" class="donut-seg donut-{cls}" '
            f'stroke-width="{stroke}" stroke-dasharray="{seg_len:.2f} {circ - seg_len:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})"/>'
        )
        offset += seg_len
    legend = ""
    for label, cls in order:
        n = counts.get(label, 0)
        if n:
            legend += (f'<div class="legend-row"><span class="legend-dot dot-{cls}"></span>'
                       f'<span class="legend-label">{label}</span><span class="legend-val">{n}</span></div>')
    return f'''<div class="donut-wrap">
  <svg viewBox="0 0 180 180" class="donut">
    <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" class="donut-track" stroke-width="{stroke}"/>
    {"".join(segs)}
    <text x="{cx}" y="{cy - 2}" class="donut-total" text-anchor="middle">{total}</text>
    <text x="{cx}" y="{cy + 17}" class="donut-total-label" text-anchor="middle">issues</text>
  </svg>
  <div class="donut-legend">{legend}</div>
</div>'''


def _svg_trend_line(scores, width=680, height=140):
    """Line chart of worst-case score over time (0..10 scale), for the
    Infrastructure overview's global trend panel. `scores` is oldest-first."""
    if len(scores) < 2:
        return '<div class="empty-chart">Not enough history yet — needs at least 2 scans.</div>'
    pad_l, pad_r, pad_t, pad_b = 8, 8, 12, 22
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    n = len(scores)
    xs = [pad_l + (i / (n - 1)) * plot_w for i in range(n)]
    ys = [pad_t + (1 - min(s, 10.0) / 10.0) * plot_h for s in scores]
    line = " ".join(f"{'M' if i == 0 else 'L'} {x:.1f} {y:.1f}" for i, (x, y) in enumerate(zip(xs, ys)))
    area = line + f" L {xs[-1]:.1f} {pad_t + plot_h:.1f} L {xs[0]:.1f} {pad_t + plot_h:.1f} Z"
    grid = "".join(
        f'<line x1="{pad_l}" y1="{pad_t + f * plot_h:.1f}" x2="{width - pad_r}" y2="{pad_t + f * plot_h:.1f}" class="trend-grid"/>'
        for f in (0.0, 0.5, 1.0)
    )
    dots = "".join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" class="trend-dot"/>' for x, y in zip(xs, ys))
    return f'''<svg viewBox="0 0 {width} {height}" class="trend-chart" role="img" aria-label="Score trend, {scores[0]:.1f} to {scores[-1]:.1f}">
  {grid}
  <path d="{area}" class="trend-area"/>
  <path d="{line}" class="trend-line"/>
  {dots}
  <text x="{pad_l}" y="{height - 4}" class="trend-axis-label">oldest</text>
  <text x="{width - pad_r}" y="{height - 4}" class="trend-axis-label" text-anchor="end">latest</text>
</svg>'''


_CIA_RANK = {"C": 2, "P": 1, "N": 0}

def _svg_score_bars(groups, rank_key="score"):
    """rank_key: 'score' (temporal score) or 'c'/'i'/'a' (CIA impact submetric)."""
    if rank_key in ("c", "i", "a"):
        candidates = [g for g in groups if _CIA_RANK.get(getattr(g["issue"], rank_key), 0) > 0]
        items = sorted(
            candidates,
            key=lambda g: (-_CIA_RANK[getattr(g["issue"], rank_key)], -g["issue"].temporal_score),
        )[:10]
    else:
        items = sorted(groups, key=lambda g: -g["issue"].temporal_score)[:10]
    if not items:
        return '<div class="empty-chart">No issues</div>'
    rows = ""
    for g in items:
        issue = g["issue"]
        s = issue.temporal_score
        cls = _sev_class(s)
        label = _e(issue.directive)
        if len(label) > 20:
            label = label[:19] + "\u2026"
        if rank_key in ("c", "i", "a"):
            val_label = _CIA_DESC.get(getattr(issue, rank_key), "")
        else:
            val_label = f"{s:.1f}"
        rows += (f'<div class="sbar-row"><span class="sbar-label" title="{_e(issue.directive)}">{label}</span>'
                 f'<span class="sbar-track"><span class="sbar-fill sbar-{cls}" style="width:{s / 10 * 100:.0f}%"></span></span>'
                 f'<span class="sbar-val sbar-text-{cls}">{val_label}</span></div>')
    return f'<div class="sbar-chart">{rows}</div>'



DASHBOARD_CSS = '''
:root{
  --bg:#15171a;--panel:#1c1f23;--panel2:#22262b;--panel3:#0f1113;
  --bd:#33373d;--bd2:#2a2d32;
  --tx:#e8e7e1;--mt:#a8a89f;--dim:#686a63;
  --critical:#e08a86;--critical-bg:#3a1e1c;--critical-bd:#5c2d29;
  --high:#e0b17e;--high-bg:#3a2c16;--high-bd:#5c451f;
  --medium:#8fbcdb;--medium-bg:#16283a;--medium-bd:#234057;
  --low:#93c79d;--low-bg:#1a2f1e;--low-bd:#274a2e;
  --none:#a3a49b;--none-bg:#262723;--none-bd:#3a3b35;
  --accent:#5ba3b3;--accent-ink:#bfe3ea;
  --hue-c:#c39be0;--hue-i:#7fc3d3;--hue-a:#e0b17e;
  --mono:"IBM Plex Mono",ui-monospace,"JetBrains Mono","Cascadia Code","Roboto Mono",Menlo,Consolas,monospace;
  --disp:"Oswald","Arial Narrow",sans-serif;
  --sans:-apple-system,BlinkMacSystemFont,"Inter","Segoe UI",Helvetica,Arial,sans-serif;
  --r:6px;
}
@media(prefers-color-scheme:light){
  :root{
    --bg:#f3f1ec;--panel:#fbfaf7;--panel2:#efece4;--panel3:#e9e6de;
    --bd:#d8d4c8;--bd2:#e3e0d6;
    --tx:#23241f;--mt:#5a5b54;--dim:#9a9a90;
    --critical:#a8322f;--critical-bg:#f6e5e2;--critical-bd:#dcb2ab;
    --high:#a9631a;--high-bg:#f5ead9;--high-bd:#e0bd8b;
    --medium:#2f6690;--medium-bg:#e2ecf1;--medium-bd:#a9c6d8;
    --low:#3f7a4f;--low-bg:#e5efe4;--low-bd:#aecfae;
    --none:#6b6f70;--none-bg:#e7e6e2;--none-bd:#c7c6bf;
    --accent:#1d5f6e;--accent-ink:#0d3138;
    --hue-c:#7a4fa0;--hue-i:#1d5f6e;--hue-a:#a9631a;
  }
}
:root[data-theme="dark"]{
  --bg:#15171a;--panel:#1c1f23;--panel2:#22262b;--panel3:#0f1113;
  --bd:#33373d;--bd2:#2a2d32;
  --tx:#e8e7e1;--mt:#a8a89f;--dim:#686a63;
  --critical:#e08a86;--critical-bg:#3a1e1c;--critical-bd:#5c2d29;
  --high:#e0b17e;--high-bg:#3a2c16;--high-bd:#5c451f;
  --medium:#8fbcdb;--medium-bg:#16283a;--medium-bd:#234057;
  --low:#93c79d;--low-bg:#1a2f1e;--low-bd:#274a2e;
  --none:#a3a49b;--none-bg:#262723;--none-bd:#3a3b35;
  --accent:#5ba3b3;--accent-ink:#bfe3ea;
  --hue-c:#c39be0;--hue-i:#7fc3d3;--hue-a:#e0b17e;
}
:root[data-theme="light"]{
  --bg:#f3f1ec;--panel:#fbfaf7;--panel2:#efece4;--panel3:#e9e6de;
  --bd:#d8d4c8;--bd2:#e3e0d6;
  --tx:#23241f;--mt:#5a5b54;--dim:#9a9a90;
  --critical:#a8322f;--critical-bg:#f6e5e2;--critical-bd:#dcb2ab;
  --high:#a9631a;--high-bg:#f5ead9;--high-bd:#e0bd8b;
  --medium:#2f6690;--medium-bg:#e2ecf1;--medium-bd:#a9c6d8;
  --low:#3f7a4f;--low-bg:#e5efe4;--low-bd:#aecfae;
  --none:#6b6f70;--none-bg:#e7e6e2;--none-bd:#c7c6bf;
  --accent:#1d5f6e;--accent-ink:#0d3138;
  --hue-c:#7a4fa0;--hue-i:#1d5f6e;--hue-a:#a9631a;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:var(--sans);background:var(--bg);color:var(--tx);font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased}
.wrap{max-width:1200px;margin:0 auto;padding:28px 24px 80px}

.topbar{display:flex;align-items:center;gap:10px;padding-bottom:18px;margin-bottom:22px;border-bottom:1px solid var(--bd)}
.logo{font-family:var(--disp);text-transform:uppercase;letter-spacing:.04em;font-weight:600;font-size:16px}
.logo .b{color:var(--accent)}
.topbar-meta{margin-left:auto;font-family:var(--mono);font-size:11.5px;color:var(--mt);text-align:right;line-height:1.7;font-variant-numeric:tabular-nums}

/* hero */
.hero{display:grid;grid-template-columns:260px 1fr;gap:28px;margin-bottom:22px;background:var(--panel);border:1px solid var(--bd);border-radius:var(--r);padding:28px;box-shadow:0 1px 2px rgba(0,0,0,.15)}
.hero-gauge{display:flex;flex-direction:column;align-items:center;justify-content:center;border-right:1px solid var(--bd);padding-right:28px}
.gauge{width:100%;max-width:230px}
.gauge-track{stroke:var(--bd)}
.gauge-critical{stroke:var(--critical)}.gauge-high{stroke:var(--high)}.gauge-medium{stroke:var(--medium)}.gauge-low{stroke:var(--low)}.gauge-none{stroke:var(--none)}
.gauge-score{font-family:var(--mono);font-size:44px;font-weight:700;fill:var(--tx);font-variant-numeric:tabular-nums}
.gauge-text-critical{fill:var(--critical)}.gauge-text-high{fill:var(--high)}.gauge-text-medium{fill:var(--medium)}.gauge-text-low{fill:var(--low)}.gauge-text-none{fill:var(--none)}
.gauge-max{font-family:var(--mono);font-size:12px;fill:var(--mt)}
.hero-verdict{margin-top:6px;font-family:var(--mono);font-size:11.5px;font-weight:600;padding:5px 16px;border-radius:20px;text-transform:uppercase;letter-spacing:.08em}
.verdict-critical{color:var(--critical);background:var(--critical-bg)}
.verdict-high{color:var(--high);background:var(--high-bg)}
.verdict-medium{color:var(--medium);background:var(--medium-bg)}
.verdict-low{color:var(--low);background:var(--low-bg)}
.verdict-none{color:var(--low);background:var(--low-bg)}
.hero-info{display:flex;flex-direction:column;gap:18px}
.hero-title h1{font-family:var(--disp);text-transform:uppercase;letter-spacing:.02em;font-size:20px;font-weight:600;margin-bottom:5px}
.hero-title .target{font-family:var(--mono);font-size:13px;color:var(--mt)}
.hero-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:auto}
.info-cell{background:var(--panel2);border:1px solid var(--bd2);border-radius:4px;padding:11px 13px}
.info-cell .k{font-size:10px;color:var(--mt);text-transform:uppercase;letter-spacing:.07em;margin-bottom:4px;font-weight:600}
.info-cell .v{font-family:var(--mono);font-size:13px;font-weight:600;font-variant-numeric:tabular-nums}

/* cards */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:12px;margin-bottom:22px}
.card{background:var(--panel);border:1px solid var(--bd);border-radius:var(--r);padding:17px 19px;position:relative;overflow:hidden}
.card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent)}
.card.c-critical::before{background:var(--critical)}.card.c-high::before{background:var(--high)}
.card.c-medium::before{background:var(--medium)}.card.c-low::before{background:var(--low)}
.card .num{font-family:var(--mono);font-size:32px;font-weight:700;line-height:1;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.card.c-critical .num{color:var(--critical)}.card.c-high .num{color:var(--high)}
.card.c-medium .num{color:var(--medium)}.card.c-low .num{color:var(--low)}
.card .lbl{font-size:11px;color:var(--mt);margin-top:7px;text-transform:uppercase;letter-spacing:.06em;font-weight:600}

/* charts */
.charts{display:grid;grid-template-columns:1fr 1.35fr;gap:14px;margin-bottom:22px}
.panel{background:var(--panel);border:1px solid var(--bd);border-radius:var(--r);padding:22px}
.panel-title{font-family:var(--disp);font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--mt);margin-bottom:18px;display:flex;align-items:center;gap:8px}
.panel-title::before{content:"";width:6px;height:6px;border-radius:50%;background:var(--accent)}
.panel-title-row{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px;flex-wrap:wrap}
.panel-title-row .panel-title{margin-bottom:0}
.tabs{display:flex;gap:4px;flex-wrap:wrap}
.tbtn{font-family:var(--mono);font-size:11px;padding:4px 10px;border-radius:20px;cursor:pointer;background:var(--panel2);border:1px solid var(--bd);color:var(--mt);transition:all .12s}
.tbtn:hover{color:var(--tx);border-color:var(--accent)}
.tbtn.active{background:var(--accent);color:var(--panel3);border-color:var(--accent);font-weight:600}
.top-panel{display:none}
.top-panel.active{display:block}
.donut-wrap{display:flex;align-items:center;gap:22px}
.donut{width:150px;height:150px;flex-shrink:0}
.donut-track{stroke:var(--bd)}
.donut-critical{stroke:var(--critical)}.donut-high{stroke:var(--high)}.donut-medium{stroke:var(--medium)}.donut-low{stroke:var(--low)}
.donut-total{font-family:var(--mono);font-size:28px;font-weight:700;fill:var(--tx)}
.donut-total-label{font-size:10.5px;fill:var(--mt)}
.donut-legend{display:flex;flex-direction:column;gap:9px;flex:1}
.legend-row{display:flex;align-items:center;gap:9px;font-size:13px}
.legend-dot{width:10px;height:10px;border-radius:3px;flex-shrink:0}
.dot-critical{background:var(--critical)}.dot-high{background:var(--high)}.dot-medium{background:var(--medium)}.dot-low{background:var(--low)}
.legend-label{color:var(--tx)}.legend-val{margin-left:auto;font-family:var(--mono);font-weight:600;color:var(--mt);font-variant-numeric:tabular-nums}
.sbar-chart{display:flex;flex-direction:column;gap:8px}
.sbar-row{display:flex;align-items:center;gap:11px}
.sbar-label{font-family:var(--mono);font-size:12px;width:140px;flex-shrink:0;color:var(--tx);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sbar-track{flex:1;height:7px;background:var(--bd);border-radius:4px;overflow:hidden}
.sbar-fill{display:block;height:100%;border-radius:4px}
.sbar-critical{background:var(--critical)}.sbar-high{background:var(--high)}.sbar-medium{background:var(--medium)}.sbar-low{background:var(--low)}
.sbar-val{font-family:var(--mono);font-size:12px;font-weight:600;width:60px;text-align:right;font-variant-numeric:tabular-nums}
.sbar-text-critical{color:var(--critical)}.sbar-text-high{color:var(--high)}.sbar-text-medium{color:var(--medium)}.sbar-text-low{color:var(--low)}
.empty-chart{color:var(--mt);font-size:13px;padding:24px;text-align:center}

/* table */
.table-panel{background:var(--panel);border:1px solid var(--bd);border-radius:var(--r);padding:22px;margin-bottom:22px}
.table-head{display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.table-head .panel-title{margin-bottom:0}
.filters{margin-left:auto;display:flex;gap:6px;flex-wrap:wrap}
.fbtn{font-family:var(--mono);font-size:11.5px;padding:5px 13px;border-radius:20px;cursor:pointer;background:var(--panel2);border:1px solid var(--bd);color:var(--tx);transition:all .12s}
.fbtn:hover{border-color:var(--accent);color:var(--accent)}
.fbtn.active{background:var(--accent);color:var(--panel3);border-color:var(--accent);font-weight:600}
table{width:100%;border-collapse:collapse;font-size:13px}
thead th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--mt);padding:9px 11px;border-bottom:1px solid var(--bd);cursor:pointer;user-select:none;white-space:nowrap;font-weight:600}
thead th:hover{color:var(--tx)}
thead th.nosort{cursor:default}
thead th.nosort:hover{color:var(--mt)}
.arr{opacity:.35;font-size:9px}
tbody td{padding:10px 11px;border-bottom:1px solid var(--bd2);vertical-align:middle}
tbody tr{transition:background .1s}
tbody tr:hover{background:var(--panel2)}
.t-score{font-family:var(--mono);font-weight:700;font-size:14px;font-variant-numeric:tabular-nums}
.t-critical{color:var(--critical)}.t-high{color:var(--high)}.t-medium{color:var(--medium)}.t-low{color:var(--low)}
.t-dir{font-family:var(--mono);font-weight:600}
.t-val{font-family:var(--mono);color:var(--mt);font-size:12px}
.t-pill{display:inline-block;font-size:10px;font-weight:600;padding:3px 9px;border-radius:11px;font-family:var(--mono);text-transform:uppercase;letter-spacing:.03em}
.pill-critical{color:var(--critical);background:var(--critical-bg)}
.pill-high{color:var(--high);background:var(--high-bg)}
.pill-medium{color:var(--medium);background:var(--medium-bg)}
.pill-low{color:var(--low);background:var(--low-bg)}
.t-metrics{font-family:var(--mono);font-size:11px;color:var(--mt)}
.t-cia{font-family:var(--mono);font-size:12px;font-weight:700;text-align:center;width:28px;border-radius:4px}
.t-cia-c{color:var(--hue-c)}.t-cia-i{color:var(--hue-i)}.t-cia-a{color:var(--hue-a)}
.t-cia-dim{color:var(--dim);font-weight:400}
.t-cve{font-family:var(--mono);font-size:11px;color:var(--high)}
.details-btn{font-family:var(--mono);font-size:11px;padding:4px 11px;border-radius:20px;cursor:pointer;background:transparent;border:1px solid var(--bd);color:var(--accent);transition:all .12s;white-space:nowrap}
.details-btn:hover{background:var(--accent);color:var(--panel3);border-color:var(--accent)}

/* chains */
.chains-panel{background:var(--panel);border:1px solid var(--bd);border-radius:var(--r);padding:22px}
.chain-item{border:1px solid var(--bd);border-radius:4px;padding:15px 17px;margin-bottom:10px;background:var(--panel2)}
.chain-item:last-child{margin-bottom:0}
.chain-top{display:flex;align-items:center;gap:12px;margin-bottom:9px}
.chain-score{font-family:var(--mono);font-size:18px;font-weight:700;font-variant-numeric:tabular-nums}
.chain-name{font-family:var(--mono);font-weight:600;font-size:13px;flex:1}
.chain-dirs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:9px;align-items:center}
.chain-dir{font-family:var(--mono);font-size:11px;padding:3px 9px;border-radius:4px;background:var(--bg);border:1px solid var(--bd);color:var(--tx)}
.chain-plus{color:var(--dim);font-size:11px}
.chain-just{font-size:12.5px;color:var(--mt);line-height:1.55}

.footer{margin-top:34px;padding-top:18px;border-top:1px solid var(--bd);font-family:var(--mono);font-size:11px;color:var(--dim);text-align:center}

/* drawer */
.drawer-overlay{position:fixed;inset:0;background:rgba(10,10,8,.55);opacity:0;visibility:hidden;transition:opacity .2s;z-index:90}
.drawer-overlay.open{opacity:1;visibility:visible}
.drawer{position:fixed;top:0;right:0;bottom:0;width:min(560px,92vw);background:var(--panel);border-left:1px solid var(--bd);
  transform:translateX(100%);transition:transform .25s cubic-bezier(.4,0,.2,1);z-index:100;overflow-y:auto;box-shadow:-12px 0 40px rgba(0,0,0,.3)}
.drawer.open{transform:translateX(0)}
.drawer-header{position:sticky;top:0;background:var(--panel);border-bottom:1px solid var(--bd);padding:20px 24px;z-index:2}
.drawer-close{position:absolute;top:18px;right:20px;width:30px;height:30px;border-radius:4px;border:1px solid var(--bd);background:var(--panel2);color:var(--mt);font-size:16px;cursor:pointer;line-height:1;transition:all .12s}
.drawer-close:hover{color:var(--tx);border-color:var(--accent)}
.drawer-score-row{display:flex;align-items:center;gap:14px;margin-bottom:8px}
.drawer-score{font-family:var(--mono);font-size:34px;font-weight:700;line-height:1;font-variant-numeric:tabular-nums}
.drawer-dir{font-family:var(--mono);font-size:16px;font-weight:600;margin-bottom:2px}
.drawer-val{font-family:var(--mono);font-size:13px;color:var(--mt)}
.drawer-body{padding:24px}
.dsec{margin-bottom:24px}
.dsec:last-child{margin-bottom:0}
.dsec-title{font-family:var(--disp);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--mt);margin-bottom:10px}
.dsec-desc{font-size:13.5px;line-height:1.65;color:var(--tx);background:var(--panel2);border-radius:4px;padding:14px 16px;border-left:3px solid var(--bd)}
.dscore-boxes{display:flex;gap:10px;margin-bottom:4px}
.dscore-box{flex:1;background:var(--panel2);border:1px solid var(--bd2);border-radius:4px;padding:12px 14px;text-align:center}
.dscore-box .n{font-family:var(--mono);font-size:24px;font-weight:700;line-height:1;font-variant-numeric:tabular-nums}
.dscore-box .l{font-size:10.5px;color:var(--mt);margin-top:4px;text-transform:uppercase;letter-spacing:.04em}
.dmetrics{display:flex;flex-direction:column;gap:0}
.dmetric{display:grid;grid-template-columns:42px 150px 1fr;gap:10px;padding:9px 0;border-bottom:1px solid var(--bd2);align-items:start}
.dmetric:last-child{border-bottom:none}
.dm-key{font-family:var(--mono);font-weight:700;font-size:13px}
.dm-val{font-size:12px}
.dm-val b{font-family:var(--mono);font-weight:600}
.dm-val .vd{color:var(--mt);margin-left:5px}
.dm-why{font-size:12px;color:var(--mt);line-height:1.5}
.dimpact{list-style:none;margin:0;padding:0}
.dimpact li{font-size:13px;padding:6px 0;border-bottom:1px solid var(--bd2);display:flex;gap:9px;align-items:flex-start;line-height:1.5}
.dimpact li:last-child{border-bottom:none}
.dimpact li::before{content:"\\2192";color:var(--high);flex-shrink:0;font-weight:600}
.dscenario{background:var(--panel2);border-radius:4px;padding:14px 16px}
.dprereqs{list-style:none;margin:0 0 12px;padding:0}
.dprereqs li{font-size:12.5px;padding:3px 0;display:flex;gap:7px;color:var(--tx)}
.dprereqs li::before{content:"\\2022";color:var(--mt)}
.dexample{background:var(--bg);border:1px solid var(--bd);border-radius:4px;padding:12px 14px;font-family:var(--mono);font-size:12px;white-space:pre-wrap;word-break:break-word;margin:10px 0;color:var(--tx);line-height:1.5}
.dresult{font-size:12.5px;color:var(--mt);margin-top:8px;line-height:1.5}
.dresult b{color:var(--tx)}
.drec{background:var(--low-bg);border-left:3px solid var(--low);border-radius:0 4px 4px 0;padding:13px 16px;font-size:13px;line-height:1.55}
.dsnippet{border:1px solid var(--bd);border-radius:4px;overflow:hidden;margin-top:6px}
.dsnippet-hdr{background:var(--panel3);font-family:var(--mono);font-size:11px;color:var(--mt);padding:6px 12px;border-bottom:1px solid var(--bd)}
.dsnippet-body{background:var(--bg);font-family:var(--mono);font-size:12px;line-height:1.6}
.dsnip-row{display:flex;padding:1px 12px}
.dsnip-row.target{background:var(--high-bg)}
.dsnip-ln{color:var(--dim);width:34px;text-align:right;padding-right:12px;flex-shrink:0;user-select:none}
.dsnip-tx{white-space:pre;color:var(--tx)}
.dsnip-row.target .dsnip-tx{color:var(--high);font-weight:600}
.dtags{display:flex;flex-wrap:wrap;gap:6px}
.dtag{font-family:var(--mono);font-size:11px;padding:3px 9px;border-radius:20px;background:var(--panel2);border:1px solid var(--bd);color:var(--mt)}
.dtag.cve{color:var(--high);border-color:var(--high-bd)}

/* exploit alert + panel */
.exploit-badge{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:11px;font-weight:600;padding:4px 11px;border-radius:20px;color:var(--critical);background:var(--critical-bg);border:1px solid var(--critical-bd);text-transform:uppercase;letter-spacing:.04em}
.exploits-panel{background:var(--panel);border:1px solid var(--critical-bd);border-radius:var(--r);padding:22px;margin-bottom:22px}
.exploits-panel .panel-title::before{background:var(--critical)}
.exploit-item{display:flex;align-items:center;gap:11px;border:1px solid var(--bd);border-radius:4px;padding:11px 14px;margin-bottom:8px;background:var(--panel2)}
.exploit-item:last-child{margin-bottom:0}
.exploit-edb{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--critical);flex-shrink:0}
.exploit-title{font-size:13px;color:var(--tx);flex:1;line-height:1.4}
.exploit-cve{font-family:var(--mono);font-size:11px;color:var(--high);flex-shrink:0}
.exploit-verified{font-size:10px;font-weight:600;font-family:var(--mono);padding:2px 7px;border-radius:10px;color:var(--low);background:var(--low-bg);flex-shrink:0}
.dexploit{display:flex;align-items:center;gap:9px;font-size:12.5px;padding:7px 0;border-bottom:1px solid var(--bd2)}
.dexploit:last-child{border-bottom:none}
.dexploit .e-edb{font-family:var(--mono);font-weight:700;color:var(--critical)}
.exploit-badge.badge-unknown{color:var(--high);background:var(--high-bg);border-color:var(--high-bd)}
.exploits-panel.exploits-unknown{border-color:var(--high-bd)}
.exploits-panel.exploits-unknown .panel-title::before{background:var(--high)}
.exploit-note{font-size:12.5px;color:var(--mt);line-height:1.6}
.exploit-note b{color:var(--high)}
.exploits-panel.exploits-clean{border-color:var(--low-bd)}
.exploits-panel.exploits-clean .panel-title::before{background:var(--low)}
.exploits-panel.exploits-clean .exploit-note b{color:var(--low)}
@media(max-width:820px){
  .hero{grid-template-columns:1fr}
  .hero-gauge{border-right:none;border-bottom:1px solid var(--bd);padding-right:0;padding-bottom:22px}
  .charts{grid-template-columns:1fr}
  .t-metrics,.t-cve{display:none}
}
'''

def _build_detail_html(g, av_rat, au_rat, detected_version=None, version_exploits=None):
    """Build the rich detail HTML for one issue (shown in the drawer)."""
    issue = g["issue"]
    contexts = g["contexts"]
    cls = _sev_class(issue.temporal_score)

    narrative = {}
    raw = getattr(issue, "narrative", "{}")
    if raw and raw != "{}":
        try:
            narrative = _json.loads(raw)
        except Exception:
            pass

    mjust = narrative.get("metric_justifications", {})
    desc = narrative.get("description", "") or issue.justification or ""
    impact = narrative.get("potential_impact", [])
    scen = narrative.get("exploitation_scenario", {})
    prereqs = scen.get("prerequisites", [])
    example = scen.get("example", "")
    res = scen.get("result", "")

    def dmetric(key, val, vdesc, why):
        return (f'<div class="dmetric"><span class="dm-key">{key}</span>'
                f'<span class="dm-val"><b>{_e(val)}</b><span class="vd">{_e(vdesc)}</span></span>'
                f'<span class="dm-why">{_e(_strip_metric_prefix(why))}</span></div>')

    exploit_rows = (
        dmetric("AV", issue.av, _AV_DESC.get(issue.av, ""), _av_why(issue.av, av_rat)) +
        dmetric("Au", issue.au, _AU_DESC.get(issue.au, ""), _au_why(issue.au, au_rat)) +
        dmetric("AC", issue.ac, _AC_DESC.get(issue.ac, ""), mjust.get("ac", "") or _AC_DESC.get(issue.ac, ""))
    )
    impact_rows = (
        dmetric("C", issue.c, _CIA_DESC.get(issue.c, ""), mjust.get("c", "") or "") +
        dmetric("I", issue.i, _CIA_DESC.get(issue.i, ""), mjust.get("i", "") or "") +
        dmetric("A", issue.a, _CIA_DESC.get(issue.a, ""), mjust.get("a", "") or "") +
        dmetric("GEL", issue.gel, _GEL_DESC.get(issue.gel, ""), mjust.get("gel", "") or "") +
        dmetric("GRL", issue.grl, _GRL_DESC.get(issue.grl, ""), mjust.get("grl", "") or "")
    )
    # F1: version-aware amplification — only when applied (factor > 1.0).
    vamp = getattr(issue, "version_amplification", 1.0)
    if vamp > 1.0:
        note = getattr(issue, "version_risk_note", "") or (
            f"{detected_version or 'version'} is exploitable — score amplified")
        impact_rows += dmetric("Version Risk", f"×{vamp:.1f}", "", note)

    parts = []
    parts.append(f'<div class="drawer-score-row"><span class="drawer-score t-{cls}">{issue.temporal_score:.1f}</span>'
                 f'<span class="t-pill pill-{cls}">{_sev_label(issue.temporal_score)}</span></div>'
                 f'<div class="drawer-dir">{_e(issue.directive)}</div>'
                 f'<div class="drawer-val">= {_display_value(issue)}</div>')
    header = "".join(parts)

    body = ""
    if desc:
        body += f'<div class="dsec"><div class="dsec-title">Description</div><div class="dsec-desc">{_e(desc)}</div></div>'

    body += (f'<div class="dsec"><div class="dsec-title">Scores</div><div class="dscore-boxes">'
             f'<div class="dscore-box"><div class="n t-{cls}">{issue.temporal_score:.1f}</div><div class="l">Temporal</div></div>'
             f'<div class="dscore-box"><div class="n" style="color:var(--mt)">{issue.base_score:.1f}</div><div class="l">Base</div></div>'
             f'</div></div>')

    body += f'<div class="dsec"><div class="dsec-title">Exploitability</div><div class="dmetrics">{exploit_rows}</div></div>'
    body += f'<div class="dsec"><div class="dsec-title">Impact &amp; Temporal</div><div class="dmetrics">{impact_rows}</div></div>'

    # F1: public exploits — shown in the drawer of the version-exposing issue.
    if version_exploits and vamp > 1.0:
        ex_items = ""
        for e in version_exploits:
            verified = " ✓" if e.get("verified") else ""
            ex_items += (f'<div class="dexploit"><span class="e-edb">EDB-'
                         f'{_e(str(e.get("edb_id", "")))}</span>'
                         f'<span>{_e(e.get("title", ""))}{verified}</span></div>')
        body += (f'<div class="dsec"><div class="dsec-title">⚠ Public Exploits '
                 f'({len(version_exploits)})</div>{ex_items}</div>')

    if impact:
        items = "".join(f"<li>{_e(str(x))}</li>" for x in impact)
        body += f'<div class="dsec"><div class="dsec-title">Potential Impact</div><ul class="dimpact">{items}</ul></div>'

    if prereqs or example or res:
        sc = ""
        if prereqs:
            pr = "".join(f"<li>{_e(str(p))}</li>" for p in prereqs)
            sc += f'<div class="dsec-title" style="margin-bottom:7px">Prerequisites</div><ul class="dprereqs">{pr}</ul>'
        if example:
            sc += f'<div class="dsec-title" style="margin:10px 0 6px">Example</div><div class="dexample">{_e(_strip_code(example))}</div>'
        if res:
            sc += f'<div class="dresult"><b>Result:</b> {_e(res)}</div>'
        body += f'<div class="dsec"><div class="dsec-title">Exploitation Scenario</div><div class="dscenario">{sc}</div></div>'

    if issue.recommendation:
        body += f'<div class="dsec"><div class="dsec-title">Recommendation</div><div class="drec">{_e(issue.recommendation)}</div></div>'

    # Config snippet (primary occurrence)
    if getattr(issue, "rule_type", "value") == "absence":
        body += (f'<div class="dsec"><div class="dsec-title">Location in File</div>'
                 f'<div class="dsec-desc" style="font-style:italic;color:var(--mt)">'
                 f'Directive absent — no source location to show.</div></div>')
    elif issue.source_directive and issue.source_directive.source_file:
        snip = _read_snippet(issue.source_directive.source_file, issue.source_directive.line_number)
        if snip:
            hdr = f"{issue.source_directive.source_file}:{issue.source_directive.line_number}"
            rows = ""
            for ln, txt, is_t in snip:
                t = " target" if is_t else ""
                rows += f'<div class="dsnip-row{t}"><span class="dsnip-ln">{ln}</span><span class="dsnip-tx">{_e(txt)}</span></div>'
            body += (f'<div class="dsec"><div class="dsec-title">Location in File</div>'
                     f'<div class="dsnippet"><div class="dsnippet-hdr">{_e(hdr)}</div>'
                     f'<div class="dsnippet-body">{rows}</div></div></div>')

    # References + CVEs
    tags = []
    if issue.cis_section:
        tags.append(f'<span class="dtag">CIS {_e(issue.cis_section)}</span>')
    if issue.cce_id:
        tags.append(f'<span class="dtag">{_e(issue.cce_id)}</span>')
    for cve in issue.cves:
        tags.append(f'<span class="dtag cve">{_e(cve)}</span>')
    if tags:
        body += f'<div class="dsec"><div class="dsec-title">References</div><div class="dtags">{"".join(tags)}</div></div>'

    return header, body


def generate_dashboard(result, resolved=None):
    """Generate a self-contained HTML dashboard with detail drawer."""
    groups = _group_issues(sorted(result.issues, key=lambda x: -x.temporal_score))
    active_chains = sorted(_dedup_chains([c for c in result.chains if c.active]), key=lambda x: -x.amplified_score)

    counts = {}
    for g in groups:
        lbl = _sev_label(g["issue"].temporal_score)
        counts[lbl] = counts.get(lbl, 0) + 1

    score = result.global_temporal_score
    scls = _sev_class(score)
    slabel = _sev_label(score)
    scan_time = result.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    mode_label = {"file": "File", "directory": "Directory", "live": "Live service", "docker": "Docker image"}.get(
        resolved.mode if resolved else "file", "File")

    input_src = result.input_path
    if resolved:
        if resolved.mode == "docker":
            input_src = resolved.metadata.get("image", result.input_path)
        elif resolved.mode == "live":
            svc = resolved.metadata.get("service", ""); ver = resolved.metadata.get("version", "")
            input_src = f"{svc} {ver}".strip() if ver and ver != "unknown" else svc

    av_rat = getattr(result.profile, "rationale_av", "")
    au_rat = getattr(result.profile, "rationale_au", "")

    gauge = _svg_gauge(score)
    # F1 exploit alert: public exploits for the detected version's CVEs.
    exploits = getattr(result, "version_exploits", []) or []
    ver = getattr(result, "detected_version", None)
    lookup_failed = getattr(result, "exploit_lookup_failed", False)
    exploit_badge = ""
    if exploits:
        exploit_badge = (
            f'<span class="exploit-badge" title="Public exploits available for '
            f'{_e(result.target_name)} {_e(ver or "")}">⚠ {len(exploits)} '
            f'public exploit{"s" if len(exploits) != 1 else ""}</span>'
        )
    elif lookup_failed and ver:
        exploit_badge = (
            '<span class="exploit-badge badge-unknown" '
            'title="The CVE/exploit lookup could not be completed (e.g. NVD '
            'timeout). Exploit availability is unknown, not confirmed absent.">'
            '⚠ exploit check unavailable</span>'
        )

    hero = f'''<div class="hero">
  <div class="hero-gauge">{gauge}<div class="hero-verdict verdict-{scls}">{slabel}</div></div>
  <div class="hero-info">
    <div class="hero-title"><h1>Security Configuration Audit {exploit_badge}</h1><div class="target">{_e(result.target_name)}{(" · v" + _e(ver)) if ver else ""}</div></div>
    <div class="hero-grid">
      <div class="info-cell"><div class="k">Highest Issue</div><div class="v t-{_sev_class(result.highest_issue_score)}">{result.highest_issue_score:.1f}</div></div>
      <div class="info-cell"><div class="k">Highest Chain</div><div class="v t-{_sev_class(result.highest_chain_score)}">{result.highest_chain_score:.1f}</div></div>
      <div class="info-cell"><div class="k">Overall (from {result.overall_driver})</div><div class="v t-{scls}">{score:.1f}</div></div>
      <div class="info-cell"><div class="k">Mode</div><div class="v">{mode_label}</div></div>
      <div class="info-cell"><div class="k">Access Vector</div><div class="v">{_AV_DESC.get(result.profile.av, "?")}</div></div>
      <div class="info-cell"><div class="k">Auth</div><div class="v">{_AU_DESC.get(result.profile.au, "?")}</div></div>
      <div class="info-cell"><div class="k">Directives</div><div class="v">{result.total_directives_scanned}</div></div>
      <div class="info-cell"><div class="k">Scanned</div><div class="v">{scan_time}</div></div>
      <div class="info-cell"><div class="k">Standard</div><div class="v">CCSS / 7502</div></div>
    </div>
  </div>
</div>'''

    def card(num, lbl, cls=""):
        c = f" c-{cls}" if cls else ""
        return f'<div class="card{c}"><div class="num">{num}</div><div class="lbl">{lbl}</div></div>'

    cards = (f'<div class="cards">{card(len(groups), "Total Issues")}{card(len(active_chains), "Attack Chains")}'
             f'{card(counts.get("Critical", 0), "Critical", "critical")}{card(counts.get("High", 0), "High", "high")}'
             f'{card(counts.get("Medium", 0), "Medium", "medium")}{card(counts.get("Low", 0), "Low", "low")}</div>')

    _top_tabs = [("score", "Score"), ("c", "Confidentiality"), ("i", "Integrity"), ("a", "Availability")]
    _top_panels = "".join(
        f'<div class="top-panel{" active" if key == "score" else ""}" data-top="{key}">{_svg_score_bars(groups, key)}</div>'
        for key, _ in _top_tabs
    )
    _top_tab_btns = "".join(
        f'<button class="tbtn{" active" if key == "score" else ""}" data-top-tab="{key}">{lbl}</button>'
        for key, lbl in _top_tabs
    )
    charts = (f'<div class="charts"><div class="panel"><div class="panel-title">Severity Distribution</div>{_svg_donut(counts)}</div>'
              f'<div class="panel"><div class="panel-title-row"><div class="panel-title">Top 10 Issues by</div>'
              f'<div class="tabs">{_top_tab_btns}</div></div>{_top_panels}</div></div>')

    # Table + collect detail payloads
    _cia_rank = {"C": 2, "P": 1, "N": 0}
    rows = ""
    details = {}
    for idx, g in enumerate(groups):
        issue = g["issue"]
        cls = _sev_class(issue.temporal_score)
        lbl = _sev_label(issue.temporal_score)
        cves = " ".join(_e(c) for c in issue.cves) if issue.cves else ""
        # Dominant CCSS impact submetric \u2014 highest of C/I/A (ties: C > I > A).
        dominant = max(("c", "i", "a"), key=lambda k: _cia_rank.get(getattr(issue, k), 0))
        def cia_td(val, hue):
            weight_cls = "" if val == "C" else " t-cia-dim"
            return f'<td class="t-cia t-cia-{hue}{weight_cls}" title="{_CIA_DESC.get(val, val)}">{val}</td>'
        rows += (f'<tr data-sev="{cls}" data-score="{issue.temporal_score}" '
                 f'data-c="{issue.c}" data-i="{issue.i}" data-a="{issue.a}" data-dominant="{dominant}">'
                 f'<td class="t-score t-{cls}">{issue.temporal_score:.1f}</td>'
                 f'<td><span class="t-pill pill-{cls}">{lbl}</span></td>'
                 f'<td class="t-dir">{_e(issue.directive)}</td>'
                 f'<td class="t-val">{_display_value(issue)}</td>'
                 f'{cia_td(issue.c, "c")}{cia_td(issue.i, "i")}{cia_td(issue.a, "a")}'
                 f'<td class="t-cve">{cves}</td>'
                 f'<td><button class="details-btn" onclick="openDrawer({idx})">Details</button></td>'
                 f'</tr>')
        hdr, body = _build_detail_html(
            g, av_rat, au_rat, getattr(result, "detected_version", None),
            getattr(result, "version_exploits", None),
        )
        details[idx] = {"header": hdr, "body": body}

    fbuttons = '<button class="fbtn active" data-filter="all">All</button>'
    for lbl, cls in [("Critical", "critical"), ("High", "high"), ("Medium", "medium"), ("Low", "low")]:
        if counts.get(lbl, 0):
            fbuttons += f'<button class="fbtn" data-filter="{cls}">{lbl}</button>'

    impact_buttons = '<button class="fbtn active" data-impact="all">All impact</button>'
    for lbl, key in [("Confidentiality", "c"), ("Integrity", "i"), ("Availability", "a")]:
        n = sum(1 for g in groups if getattr(g["issue"], key) == "C")
        if n:
            impact_buttons += f'<button class="fbtn" data-impact="{key}">{lbl} ({n})</button>'

    table = (f'<div class="table-panel"><div class="table-head"><div class="panel-title">Issues</div>'
             f'<div class="filters">{fbuttons}</div></div>'
             f'<div class="table-head" style="margin-top:-8px"><div class="panel-title">Impact on</div>'
             f'<div class="filters">{impact_buttons}</div></div>'
             f'<table id="issues-table"><thead><tr>'
             f'<th data-sort="score">Score <span class="arr">\u2195</span></th>'
             f'<th data-sort="sev">Severity <span class="arr">\u2195</span></th>'
             f'<th data-sort="dir">Directive <span class="arr">\u2195</span></th>'
             f'<th class="nosort">Value</th>'
             f'<th data-sort="c" title="Confidentiality impact">C <span class="arr">\u2195</span></th>'
             f'<th data-sort="i" title="Integrity impact">I <span class="arr">\u2195</span></th>'
             f'<th data-sort="a" title="Availability impact">A <span class="arr">\u2195</span></th>'
             f'<th class="nosort">CVEs</th><th class="nosort"></th>'
             f'</tr></thead><tbody>{rows}</tbody></table></div>')

    chain_items = ""
    for chain in active_chains:
        cls = _sev_class(chain.amplified_score)
        dirs = '<span class="chain-plus">+</span>'.join(f'<span class="chain-dir">{_e(d)}</span>' for d in chain.triggered_by)
        just = _e(chain.justification or "")
        chain_items += (f'<div class="chain-item"><div class="chain-top">'
                        f'<span class="chain-score t-{cls}">{chain.amplified_score:.1f}</span>'
                        f'<span class="chain-name">{_e(chain.chain_id)}</span>'
                        f'<span class="t-pill pill-{cls}">{_sev_label(chain.amplified_score)}</span></div>'
                        f'<div class="chain-dirs">{dirs}</div><div class="chain-just">{just}</div></div>')
    chains_section = ""
    if chain_items:
        chains_section = f'<div class="chains-panel"><div class="panel-title">Attack Chains</div>{chain_items}</div>'

    # F1: Public Exploits panel — visible alert when the detected version has
    # public exploits in Exploit-DB.
    exploits_section = ""
    if exploits:
        items = ""
        for e in exploits:
            edb = _e(str(e.get("edb_id", "")))
            verified = ('<span class="exploit-verified">verified</span>'
                        if e.get("verified") else "")
            cve = _e(e.get("cve", ""))
            items += (f'<div class="exploit-item">'
                      f'<span class="exploit-edb">EDB-{edb}</span>'
                      f'<span class="exploit-title">{_e(e.get("title", ""))}</span>'
                      f'<span class="exploit-cve">{cve}</span>{verified}</div>')
        ver_lbl = f" for {_e(result.target_name)} {_e(ver or '')}" if ver else ""
        exploits_section = (
            f'<div class="exploits-panel"><div class="panel-title">'
            f'⚠ Public Exploits{ver_lbl} ({len(exploits)})</div>{items}</div>'
        )
    elif lookup_failed and ver:
        # Explicit "could not check" state — distinct from "no exploits".
        exploits_section = (
            f'<div class="exploits-panel exploits-unknown">'
            f'<div class="panel-title">Exploit Check Unavailable</div>'
            f'<div class="exploit-note">The CVE/exploit lookup for '
            f'{_e(result.target_name)} {_e(ver)} could not be completed '
            f'(e.g. NVD timeout). Exploit availability is <b>unknown</b> — '
            f'this is not a confirmation that the version is exploit-free. '
            f'Re-run the scan when the NVD is reachable.</div></div>'
        )
    elif ver and getattr(result, "version_cves_checked", 0) > 0:
        # Checked and clean: CVEs examined, no public exploit found.
        n = result.version_cves_checked
        exploits_section = (
            f'<div class="exploits-panel exploits-clean">'
            f'<div class="panel-title">Exploit Availability</div>'
            f'<div class="exploit-note">No public exploit currently indexed in '
            f'Exploit-DB for {_e(result.target_name)} {_e(ver)}. '
            f'<b>{n} known CVE{"s" if n != 1 else ""}</b> '
            f'{"were" if n != 1 else "was"} evaluated. '
            f'This reflects public exploit indexing, not the absence of risk.'
            f'</div></div>'
        )
    elif not ver:
        # No version available — CVE/exploit cross-reference was not possible.
        # Be explicit so the absence of an exploit panel is never read as
        # "no CVEs exist". Tell the user how to supply the version.
        exploits_section = (
            f'<div class="exploits-panel exploits-unknown">'
            f'<div class="panel-title">CVE / Exploit Check — Version Unknown</div>'
            f'<div class="exploit-note">The service version could not be '
            f'determined for {_e(result.target_name)}, so known CVEs and public '
            f'exploits were <b>not checked</b>. This is not a confirmation that '
            f'the version is exploit-free. Re-run with '
            f'<b>--service-version &lt;x.y.z&gt;</b> (e.g. '
            f'<b>caspar scan &lt;path&gt; --service-version 2.4.58</b>) to enable '
            f'the version-aware CVE/exploit cross-reference.</div></div>'
        )

    details_json = _json.dumps(details)

    js = '''
const DETAILS = __DETAILS__;
document.querySelectorAll(".tbtn[data-top-tab]").forEach(btn => {
  btn.addEventListener("click", () => {
    const key = btn.dataset.topTab;
    document.querySelectorAll(".tbtn[data-top-tab]").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    document.querySelectorAll(".top-panel").forEach(p => p.classList.toggle("active", p.dataset.top === key));
  });
});
const tbody = document.querySelector("#issues-table tbody");
const rows = Array.from(tbody.querySelectorAll("tr"));

let sevFilter = "all";
let impactFilter = "all";
function applyFilters() {
  rows.forEach(r => {
    const sevOk = (sevFilter === "all" || r.dataset.sev === sevFilter);
    const impactOk = (impactFilter === "all" || r.dataset[impactFilter] === "C");
    r.style.display = (sevOk && impactOk) ? "" : "none";
  });
}
document.querySelectorAll(".fbtn[data-filter]").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".fbtn[data-filter]").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    sevFilter = btn.dataset.filter;
    applyFilters();
  });
});
document.querySelectorAll(".fbtn[data-impact]").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".fbtn[data-impact]").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    impactFilter = btn.dataset.impact;
    applyFilters();
  });
});

let sortState = {};
const sevRank = {critical:4, high:3, medium:2, low:1, none:0};
const ciaRank = {C:2, P:1, N:0};
document.querySelectorAll("th[data-sort]").forEach(th => {
  th.addEventListener("click", () => {
    const key = th.dataset.sort;
    const asc = !sortState[key];
    sortState = {[key]: asc};
    const sorted = rows.slice().sort((a, b) => {
      let va, vb;
      if (key === "score") { va = parseFloat(a.dataset.score); vb = parseFloat(b.dataset.score); }
      else if (key === "sev") { va = sevRank[a.dataset.sev]; vb = sevRank[b.dataset.sev]; }
      else if (key === "c" || key === "i" || key === "a") { va = ciaRank[a.dataset[key]]; vb = ciaRank[b.dataset[key]]; }
      else { va = a.children[2].textContent.toLowerCase(); vb = b.children[2].textContent.toLowerCase(); }
      if (va < vb) return asc ? -1 : 1;
      if (va > vb) return asc ? 1 : -1;
      return 0;
    });
    sorted.forEach(r => tbody.appendChild(r));
  });
});

const overlay = document.getElementById("drawer-overlay");
const drawer = document.getElementById("drawer");
const dHeader = document.getElementById("drawer-header-content");
const dBody = document.getElementById("drawer-body");

function openDrawer(idx) {
  const d = DETAILS[idx];
  if (!d) return;
  dHeader.innerHTML = d.header;
  dBody.innerHTML = d.body;
  drawer.classList.add("open");
  overlay.classList.add("open");
  drawer.scrollTop = 0;
}
function closeDrawer() {
  drawer.classList.remove("open");
  overlay.classList.remove("open");
}
overlay.addEventListener("click", closeDrawer);
document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });
'''
    js = js.replace("__DETAILS__", details_json)

    drawer_html = ('<div class="drawer-overlay" id="drawer-overlay"></div>'
                   '<div class="drawer" id="drawer">'
                   '<div class="drawer-header"><button class="drawer-close" onclick="closeDrawer()">\u2715</button>'
                   '<div id="drawer-header-content"></div></div>'
                   '<div class="drawer-body" id="drawer-body"></div></div>')

    return (
        "<!DOCTYPE html>\n<html lang=\"en\"><head>\n"
        "<meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
        f"<title>CCSS Dashboard \u2014 {_e(result.target_name)} \u2014 {score:.1f}</title>\n"
        f"<style>{DASHBOARD_CSS}</style></head><body>\n"
        "<div class=\"wrap\">\n"
        "<div class=\"topbar\"><span class=\"logo\"><span class=\"b\">[</span> CASPAR <span class=\"b\">]</span></span>\n"
        f"<div class=\"topbar-meta\">{mode_label} &middot; {_e(input_src)}<br>{scan_time}</div></div>\n"
        + hero + cards + charts + table + chains_section + exploits_section +
        f"<div class=\"footer\">Generated by CCSS-Scan \u00b7 NISTIR 7502 \u00b7 target: {_e(result.target_name)} \u00b7 offline report</div>\n"
        "</div>\n"
        + drawer_html +
        f"<script>{js}</script>\n</body></html>"
    )
