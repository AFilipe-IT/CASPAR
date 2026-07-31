"""
core/report_dashboard_online.py
---------------------------------
Variante ONLINE do dashboard. Usa ECharts via CDN para gráficos interactivos
(gauge animado, donut com tooltips, radar das métricas CIA, treemap de
directivas, scatter score-vs-exploitabilidade).

REQUER INTERNET para carregar a biblioteca. O dashboard offline
(report_dashboard.py) continua a ser o formato auditável/reprodutível.

Reutiliza os helpers e o construtor de drawer do dashboard offline para não
duplicar lógica — só os gráficos mudam.

Uso:
    from config_assessment.reports.report_dashboard_online import generate_dashboard_online
    html = generate_dashboard_online(result, resolved=resolved)
"""

from __future__ import annotations
import json as _json

# Reutilizar tudo o que já existe no dashboard offline
from config_assessment.reports.report_dashboard import (
    _sev_class, _sev_label, _e, _group_issues, _dedup_chains,
    _build_detail_html, _AV_DESC, _AU_DESC,
    DASHBOARD_CSS,
)

ECHARTS_CDN = "https://cdn.jsdelivr.net/npm/echarts@5.5.0/dist/echarts.min.js"

# Severity colours shared with ECharts (hex, since ECharts can't read CSS vars)
_SEV_COLORS = {
    "critical": "#ff6b6b",
    "high": "#f5a35e",
    "medium": "#5aa6ff",
    "low": "#6fd6a0",
    "none": "#8b95a5",
}

_METRIC_VAL = {"N": 0, "P": 0.5, "C": 1.0,  # CIA
               "L": 0.33, "M": 0.66, "H": 1.0}  # AC/complexity-like


def _exploitability_proxy(issue):
    """Numeric proxy for exploitability (for the scatter chart)."""
    av_w = {"L": 0.3, "A": 0.6, "N": 1.0}.get(issue.av, 0.5)
    au_w = {"M": 0.3, "S": 0.6, "N": 1.0}.get(issue.au, 0.5)
    ac_w = {"H": 0.3, "M": 0.6, "L": 1.0}.get(issue.ac, 0.5)
    return round((av_w + au_w + ac_w) / 3 * 10, 1)


def _impact_value(v):
    return {"N": 0, "P": 0.5, "C": 1.0}.get(v, 0)


EXTRA_CSS = """
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:22px}
.chart-grid .panel{margin:0}
.echart{width:100%;height:280px}
.echart-tall{width:100%;height:320px}
.online-badge{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:11px;
  color:var(--low);background:var(--low-bg);padding:3px 10px;border-radius:20px;margin-left:8px}
.online-badge::before{content:"";width:6px;height:6px;border-radius:50%;background:var(--low);
  animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.fallback-note{background:var(--high-bg);border:1px solid var(--high-bd);border-radius:10px;
  padding:14px 18px;margin-bottom:22px;font-size:13px;color:var(--high);display:none}
.fallback-note.show{display:block}
@media(max-width:820px){.chart-grid{grid-template-columns:1fr}}
"""


def generate_dashboard_online(result, resolved=None):
    """Generate an online (ECharts) dashboard. Requires internet for the CDN."""
    groups = _group_issues(sorted(result.issues, key=lambda x: -x.temporal_score))
    active_chains = sorted(_dedup_chains([c for c in result.chains if c.active]),
                           key=lambda x: -x.amplified_score)

    counts = {}
    for g in groups:
        lbl = _sev_label(g["issue"].temporal_score)
        counts[lbl] = counts.get(lbl, 0) + 1

    score = result.global_temporal_score
    scls = _sev_class(score)
    slabel = _sev_label(score)
    scan_time = result.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    mode_label = {"file": "File", "directory": "Directory", "live": "Live service",
                  "docker": "Docker image"}.get(resolved.mode if resolved else "file", "File")

    input_src = result.input_path
    if resolved:
        if resolved.mode == "docker":
            input_src = resolved.metadata.get("image", result.input_path)
        elif resolved.mode == "live":
            svc = resolved.metadata.get("service", ""); ver = resolved.metadata.get("version", "")
            input_src = f"{svc} {ver}".strip() if ver and ver != "unknown" else svc

    av_rat = getattr(result.profile, "rationale_av", "")
    au_rat = getattr(result.profile, "rationale_au", "")

    # ── Hero (gauge is now an ECharts chart) ──
    hero = f'''<div class="hero">
  <div class="hero-gauge"><div id="gauge" class="echart" style="height:200px"></div>
    <div class="hero-verdict verdict-{scls}">{slabel}</div></div>
  <div class="hero-info">
    <div class="hero-title"><h1>Security Configuration Audit <span class="online-badge">live</span></h1>
      <div class="target">{_e(result.target_name)}</div></div>
    <div class="hero-grid">
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

    # ── Chart grid: donut, radar, treemap, scatter ──
    chart_grid = '''<div class="chart-grid">
  <div class="panel"><div class="panel-title">Severity Distribution</div><div id="donut" class="echart"></div></div>
  <div class="panel"><div class="panel-title">Aggregate Impact (C/I/A)</div><div id="radar" class="echart"></div></div>
  <div class="panel"><div class="panel-title">Directives by Severity</div><div id="treemap" class="echart-tall"></div></div>
  <div class="panel"><div class="panel-title">Score vs Exploitability</div><div id="scatter" class="echart-tall"></div></div>
</div>'''

    # ── Table + details (reuse offline drawer builder) ──
    rows = ""
    details = {}
    for idx, g in enumerate(groups):
        issue = g["issue"]
        cls = _sev_class(issue.temporal_score)
        lbl = _sev_label(issue.temporal_score)
        cves = " ".join(_e(c) for c in issue.cves) if issue.cves else ""
        metrics = f"{issue.av}{issue.au}{issue.ac}/{issue.c}{issue.i}{issue.a}"
        rows += (f'<tr data-sev="{cls}" data-score="{issue.temporal_score}">'
                 f'<td class="t-score t-{cls}">{issue.temporal_score:.1f}</td>'
                 f'<td><span class="t-pill pill-{cls}">{lbl}</span></td>'
                 f'<td class="t-dir">{_e(issue.directive)}</td>'
                 f'<td class="t-val">{_e(issue.bad_value)}</td>'
                 f'<td class="t-metrics">{metrics}</td>'
                 f'<td class="t-cve">{cves}</td>'
                 f'<td><button class="details-btn" onclick="openDrawer({idx})">Details</button></td></tr>')
        hdr, body = _build_detail_html(g, av_rat, au_rat)
        details[idx] = {"header": hdr, "body": body}

    fbuttons = '<button class="fbtn active" data-filter="all">All</button>'
    for lbl, cls in [("Critical", "critical"), ("High", "high"), ("Medium", "medium"), ("Low", "low")]:
        if counts.get(lbl, 0):
            fbuttons += f'<button class="fbtn" data-filter="{cls}">{lbl}</button>'

    table = (f'<div class="table-panel"><div class="table-head"><div class="panel-title">Issues</div>'
             f'<div class="filters">{fbuttons}</div></div>'
             f'<table id="issues-table"><thead><tr>'
             f'<th data-sort="score">Score <span class="arr">\u2195</span></th>'
             f'<th data-sort="sev">Severity <span class="arr">\u2195</span></th>'
             f'<th data-sort="dir">Directive <span class="arr">\u2195</span></th>'
             f'<th class="nosort">Value</th><th class="nosort">Metrics</th>'
             f'<th class="nosort">CVEs</th><th class="nosort"></th>'
             f'</tr></thead><tbody>{rows}</tbody></table></div>')

    chain_items = ""
    for chain in active_chains:
        cls = _sev_class(chain.amplified_score)
        dirs = '<span class="chain-plus">+</span>'.join(f'<span class="chain-dir">{_e(d)}</span>' for d in chain.triggered_by)
        chain_items += (f'<div class="chain-item"><div class="chain-top">'
                        f'<span class="chain-score t-{cls}">{chain.amplified_score:.1f}</span>'
                        f'<span class="chain-name">{_e(chain.chain_id)}</span>'
                        f'<span class="t-pill pill-{cls}">{_sev_label(chain.amplified_score)}</span></div>'
                        f'<div class="chain-dirs">{dirs}</div>'
                        f'<div class="chain-just">{_e(chain.justification or "")}</div></div>')
    chains_section = f'<div class="chains-panel"><div class="panel-title">Attack Chains</div>{chain_items}</div>' if chain_items else ""

    drawer_html = ('<div class="drawer-overlay" id="drawer-overlay"></div>'
                   '<div class="drawer" id="drawer">'
                   '<div class="drawer-header"><button class="drawer-close" onclick="closeDrawer()">\u2715</button>'
                   '<div id="drawer-header-content"></div></div>'
                   '<div class="drawer-body" id="drawer-body"></div></div>')

    # ── Chart data payloads ──
    sev_data = [{"name": k, "value": counts.get(k, 0), "itemStyle": {"color": _SEV_COLORS[c]}}
                for k, c in [("Critical", "critical"), ("High", "high"), ("Medium", "medium"), ("Low", "low")]
                if counts.get(k, 0)]

    # Aggregate CIA across issues (average severity contribution)
    def agg(metric):
        if not groups:
            return 0
        total = sum(_impact_value(getattr(g["issue"], metric)) for g in groups)
        return round(total / len(groups) * 10, 1)
    radar_data = [agg("c"), agg("i"), agg("a")]

    # Treemap: directives sized by score, coloured by severity
    treemap_data = []
    for g in groups:
        issue = g["issue"]
        cls = _sev_class(issue.temporal_score)
        treemap_data.append({
            "name": issue.directive,
            "value": round(issue.temporal_score, 1),
            "itemStyle": {"color": _SEV_COLORS[cls]},
        })

    # Scatter: x=exploitability proxy, y=temporal score
    scatter_data = []
    for g in groups:
        issue = g["issue"]
        cls = _sev_class(issue.temporal_score)
        scatter_data.append({
            "name": issue.directive,
            "value": [_exploitability_proxy(issue), round(issue.temporal_score, 1)],
            "itemStyle": {"color": _SEV_COLORS[cls]},
        })

    chart_payload = _json.dumps({
        "score": round(score, 1),
        "scoreColor": _SEV_COLORS[scls],
        "sevData": sev_data,
        "radar": radar_data,
        "treemap": treemap_data,
        "scatter": scatter_data,
    })

    details_json = _json.dumps(details)

    return _render_online_html(
        result, score, scls, mode_label, input_src, scan_time,
        hero, cards, chart_grid, table, chains_section, drawer_html,
        chart_payload, details_json,
    )


def _echarts_theme():
    """Return a JS object literal string with shared ECharts styling."""
    return '''{
      textStyle: { fontFamily: "ui-monospace, monospace", color: cssVar("--mt") },
      tooltip: { backgroundColor: cssVar("--panel"), borderColor: cssVar("--bd"),
                 textStyle: { color: cssVar("--tx") } }
    }'''


def _render_online_html(result, score, scls, mode_label, input_src, scan_time,
                        hero, cards, chart_grid, table, chains_section, drawer_html,
                        chart_payload, details_json):

    js = '''
const DETAILS = __DETAILS__;
const CHART = __CHART__;

function cssVar(n){ return getComputedStyle(document.documentElement).getPropertyValue(n).trim() || "#888"; }

// ── Drawer (same behaviour as offline) ──
const tbody = document.querySelector("#issues-table tbody");
const rows = Array.from(tbody.querySelectorAll("tr"));
document.querySelectorAll(".fbtn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".fbtn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    const f = btn.dataset.filter;
    rows.forEach(r => { r.style.display = (f === "all" || r.dataset.sev === f) ? "" : "none"; });
  });
});
let sortState = {};
const sevRank = {critical:4, high:3, medium:2, low:1, none:0};
document.querySelectorAll("th[data-sort]").forEach(th => {
  th.addEventListener("click", () => {
    const key = th.dataset.sort; const asc = !sortState[key]; sortState = {[key]: asc};
    const sorted = rows.slice().sort((a, b) => {
      let va, vb;
      if (key === "score") { va = parseFloat(a.dataset.score); vb = parseFloat(b.dataset.score); }
      else if (key === "sev") { va = sevRank[a.dataset.sev]; vb = sevRank[b.dataset.sev]; }
      else { va = a.children[2].textContent.toLowerCase(); vb = b.children[2].textContent.toLowerCase(); }
      if (va < vb) return asc ? -1 : 1;
      if (va > vb) return asc ? 1 : -1; return 0;
    });
    sorted.forEach(r => tbody.appendChild(r));
  });
});
const overlay = document.getElementById("drawer-overlay");
const drawer = document.getElementById("drawer");
const dHeader = document.getElementById("drawer-header-content");
const dBody = document.getElementById("drawer-body");
function openDrawer(idx){ const d = DETAILS[idx]; if(!d) return;
  dHeader.innerHTML = d.header; dBody.innerHTML = d.body;
  drawer.classList.add("open"); overlay.classList.add("open"); drawer.scrollTop = 0; }
function closeDrawer(){ drawer.classList.remove("open"); overlay.classList.remove("open"); }
overlay.addEventListener("click", closeDrawer);
document.addEventListener("keydown", e => { if(e.key === "Escape") closeDrawer(); });

// ── ECharts ──
function initCharts(){
  if (typeof echarts === "undefined"){
    document.getElementById("fallback-note").classList.add("show");
    return;
  }
  const charts = [];
  const mk = (id, opt) => { const el = document.getElementById(id); if(!el) return;
    const c = echarts.init(el, null, {renderer:"canvas"}); c.setOption(opt); charts.push(c); };

  // Gauge
  mk("gauge", {
    series: [{
      type: "gauge", startAngle: 180, endAngle: 0, min: 0, max: 10, radius: "100%",
      center: ["50%", "75%"], splitNumber: 5,
      progress: { show: true, width: 14, itemStyle: { color: CHART.scoreColor } },
      axisLine: { lineStyle: { width: 14, color: [[1, cssVar("--bd")]] } },
      axisTick: { show: false }, splitLine: { show: false },
      axisLabel: { distance: -8, fontSize: 9, color: cssVar("--mt") },
      pointer: { show: false },
      anchor: { show: false },
      detail: { valueAnimation: true, fontSize: 38, fontFamily: "ui-monospace, monospace",
                fontWeight: "bold", offsetCenter: [0, "-12%"], color: CHART.scoreColor,
                formatter: v => v.toFixed(1) },
      data: [{ value: CHART.score }],
      title: { show: false }
    }]
  });

  // Donut
  mk("donut", {
    tooltip: { trigger: "item", formatter: "{b}: {c} ({d}%)",
               backgroundColor: cssVar("--panel"), borderColor: cssVar("--bd"),
               textStyle: { color: cssVar("--tx") } },
    legend: { bottom: 0, textStyle: { color: cssVar("--mt") } },
    series: [{
      type: "pie", radius: ["45%", "70%"], center: ["50%", "44%"],
      avoidLabelOverlap: true, label: { show: false }, labelLine: { show: false },
      data: CHART.sevData
    }]
  });

  // Radar (CIA)
  mk("radar", {
    tooltip: {},
    radar: {
      indicator: [
        { name: "Confidentiality", max: 10 },
        { name: "Integrity", max: 10 },
        { name: "Availability", max: 10 }
      ],
      radius: "62%", center: ["50%", "52%"],
      axisName: { color: cssVar("--mt"), fontSize: 11 },
      splitLine: { lineStyle: { color: cssVar("--bd") } },
      splitArea: { areaStyle: { color: ["transparent"] } },
      axisLine: { lineStyle: { color: cssVar("--bd") } }
    },
    series: [{
      type: "radar",
      data: [{ value: CHART.radar, name: "Aggregate Impact",
               areaStyle: { color: CHART.scoreColor, opacity: 0.25 },
               lineStyle: { color: CHART.scoreColor }, itemStyle: { color: CHART.scoreColor } }]
    }]
  });

  // Treemap
  mk("treemap", {
    tooltip: { formatter: i => i.name + ": " + i.value,
               backgroundColor: cssVar("--panel"), borderColor: cssVar("--bd"),
               textStyle: { color: cssVar("--tx") } },
    series: [{
      type: "treemap", roam: false, nodeClick: false, breadcrumb: { show: false },
      label: { show: true, fontSize: 11, fontFamily: "ui-monospace, monospace", color: "#fff" },
      itemStyle: { borderColor: cssVar("--bg"), borderWidth: 2, gapWidth: 2 },
      data: CHART.treemap
    }]
  });

  // Scatter
  mk("scatter", {
    tooltip: { formatter: i => i.data.name + "<br>Score: " + i.data.value[1] + "<br>Exploitability: " + i.data.value[0],
               backgroundColor: cssVar("--panel"), borderColor: cssVar("--bd"),
               textStyle: { color: cssVar("--tx") } },
    grid: { left: 50, right: 24, top: 24, bottom: 44 },
    xAxis: { name: "Exploitability", nameLocation: "middle", nameGap: 26, min: 0, max: 10,
             nameTextStyle: { color: cssVar("--mt") },
             axisLine: { lineStyle: { color: cssVar("--bd") } },
             axisLabel: { color: cssVar("--mt") }, splitLine: { lineStyle: { color: cssVar("--bd2") } } },
    yAxis: { name: "Score", min: 0, max: 10, nameTextStyle: { color: cssVar("--mt") },
             axisLine: { lineStyle: { color: cssVar("--bd") } },
             axisLabel: { color: cssVar("--mt") }, splitLine: { lineStyle: { color: cssVar("--bd2") } } },
    series: [{ type: "scatter", symbolSize: 16, data: CHART.scatter }]
  });

  window.addEventListener("resize", () => charts.forEach(c => c.resize()));
}
if (document.readyState === "loading")
  document.addEventListener("DOMContentLoaded", initCharts);
else initCharts();
'''
    js = js.replace("__DETAILS__", details_json).replace("__CHART__", chart_payload)

    fallback = ('<div class="fallback-note" id="fallback-note">'
                'Charts require an internet connection to load the visualization library. '
                'The data and details below are fully available offline \u2014 '
                'use the standard <code>--format dashboard</code> for a 100% offline report.</div>')

    return (
        "<!DOCTYPE html>\n<html lang=\"en\"><head>\n"
        "<meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
        f"<title>CCSS Dashboard (online) \u2014 {_e(result.target_name)} \u2014 {score:.1f}</title>\n"
        f"<style>{DASHBOARD_CSS}{EXTRA_CSS}</style>\n"
        f'<script src="{ECHARTS_CDN}"></script>\n'
        "</head><body>\n<div class=\"wrap\">\n"
        "<div class=\"topbar\"><span class=\"logo\"><span class=\"b\">[</span> CASPAR <span class=\"b\">]</span></span>\n"
        f"<div class=\"topbar-meta\">{mode_label} &middot; {_e(input_src)}<br>{scan_time}</div></div>\n"
        + fallback + hero + cards + chart_grid + table + chains_section +
        "<div class=\"footer\">Generated by CCSS-Scan \u00b7 NISTIR 7502 \u00b7 online dashboard (ECharts via CDN)</div>\n"
        "</div>\n" + drawer_html +
        f"<script>{js}</script>\n</body></html>"
    )
