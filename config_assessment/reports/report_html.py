"""
core/report_html.py
HTML report generator with narrative support.
"""
from __future__ import annotations
from pathlib import Path
import json as _json
import re

_AV_DESC={"L":"Local","A":"Adjacent","N":"Network"}
_AU_DESC={"M":"Multiple","S":"Single","N":"None"}
_AC_DESC={"H":"High complexity","M":"Medium complexity","L":"Low complexity"}
_CIA_DESC={"N":"None","P":"Partial","C":"Complete"}
_GEL_DESC={"N":"None","L":"Low","M":"Medium","H":"High","ND":"Not Defined"}
_GRL_DESC={"U":"Unavailable","W":"Workaround","H":"Official (CIS)","ND":"Not Defined"}


def _sev_class(s):
    if s>=9: return "critical"
    if s>=7: return "high"
    if s>=4: return "medium"
    if s>0:  return "low"
    return "none"

def _bar(score):
    p=score/10*100; cls=_sev_class(score)
    return f'<div class="bar-wrap"><div class="bar bar-{cls}" style="width:{p:.1f}%"></div></div>'

def _badge(score, label=None):
    cls=_sev_class(score)
    return f'<span class="badge badge-{cls}">{label or cls.capitalize()}</span>'

def _strip_metric_prefix(text):
    """Remove redundant 'Why AC=M:' / 'AC=M:' prefix from a metric
    justification — the metric key and value are already shown in their
    own columns, so the prefix is noise."""
    import re as _re
    t = str(text).strip()
    # Matches: optional "Why ", metric name, =, value, optional space, colon
    t = _re.sub(
        r'^(?:Why\s+)?(?:AV|Au|AC|C|I|A|GEL|GRL)\s*=\s*[A-Za-z]+\s*:\s*',
        '',
        t,
    )
    return t.strip()


def _e(t):
    return str(t).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def _display_value(issue):
    """Return the display string for the bad_value field.
    Absence issues (rule_type='absence') have bad_value='' — show a badge instead."""
    if getattr(issue, "rule_type", "value") == "absence":
        return '<span style="font-style:italic;color:var(--mt)">[not configured]</span>'
    return _e(issue.bad_value)

def _nl2br(t):
    return _e(t).replace("\n","<br>")

def _strip_code_tags(t):
    """Remove literal <code>/<pre> tags and markdown code fences the LLM
    sometimes includes — the example-box already renders monospace."""
    t = str(t)
    t = re.sub(r"</?code>", "", t)
    t = re.sub(r"</?pre>", "", t)
    # Markdown fences: ```bash\n...\n``` or ```\n...\n```
    t = re.sub(r"^```[a-zA-Z]*\n?", "", t, flags=re.MULTILINE)
    t = re.sub(r"\n?```$", "", t, flags=re.MULTILINE)
    t = re.sub(r"```", "", t)  # any remaining stray fences
    return t.strip()

def _group_issues(issues):
    from collections import OrderedDict
    g=OrderedDict()
    for issue in issues:
        k=(issue.directive,issue.bad_value)
        if k not in g: g[k]={"issue":issue,"contexts":[]}
        src=issue.source_directive
        if src and src.source_file:
            ctx=f"{src.source_file}:{src.line_number}"
            if src.context and src.context!="global": ctx+=f" [{src.context}]"
            if ctx not in g[k]["contexts"]: g[k]["contexts"].append(ctx)
    return list(g.values())

def _dedup_chains(chains):
    seen=set(); out=[]
    for c in chains:
        k=frozenset(c.triggered_by)
        if k not in seen: seen.add(k); out.append(c)
    return out


def _read_snippet(file_path, line_number, context=2):
    """
    Read a few lines of the actual config file around the directive.
    Returns a list of (line_no, text, is_target) tuples, or [] if the
    file can't be read (e.g. a temp dir already cleaned up).
    """
    try:
        lines = Path(file_path).read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    if not line_number or line_number < 1 or line_number > len(lines):
        return []
    start = max(1, line_number - context)
    end = min(len(lines), line_number + context)
    return [(i, lines[i - 1], i == line_number) for i in range(start, end + 1)]


def _render_snippet_html(file_path, line_number, context_label=""):
    """Render a small code block showing the config around the directive."""
    snippet = _read_snippet(file_path, line_number)
    header = f"{file_path}:{line_number}"
    if context_label:
        header += f" [{context_label}]"

    if not snippet:
        return f'<span class="loc-tag">{_e(header)}</span>'

    rows = ""
    for line_no, text, is_target in snippet:
        cls = " snippet-target" if is_target else ""
        rows += (
            f'<div class="snippet-row{cls}">'
            f'<span class="snippet-lineno">{line_no}</span>'
            f'<span class="snippet-text">{_e(text)}</span>'
            "</div>"
        )

    return (
        f'<div class="snippet-block">'
        f'<div class="snippet-header">{_e(header)}</div>'
        f'<div class="snippet-body">{rows}</div>'
        "</div>"
    )


def _av_why(av, rationale=""):
    b={"N":"Network (AV=N): the service listens on non-loopback addresses — any remote unauthenticated attacker can reach it directly.",
       "A":"Adjacent (AV=A): the service is reachable only from the local network segment — attacker must be on the same subnet.",
       "L":"Local (AV=L): the service only listens on loopback (127.0.0.1) — attacker needs local shell or physical access."
    }.get(av,f"AV={av}: determined at scan time.")
    if rationale: b+=f" Scan detected: {rationale}"
    return b

def _au_why(au, rationale=""):
    b={"N":"None (Au=N): no authentication directives (AuthType + Require) were detected in the configuration — the service accepts unauthenticated requests.",
       "S":"Single (Au=S): one set of valid credentials must be provided to access the service.",
       "M":"Multiple (Au=M): multiple authentication steps are required to access the service."
    }.get(au,f"Au={au}: determined at scan time.")
    if rationale: b+=f" Scan detected: {rationale}"
    return b

CSS = '''
:root{
  --bg:#f3f1ec;--bg2:#fbfaf7;--bg3:#e9e6de;--bd:#d8d4c8;--bd2:#e3e0d6;--tx:#23241f;--mt:#5a5b54;--mtt:#8a8b82;
  --accent:#1d5f6e;--accent-ink:#0d3138;--accent-soft:#dce9ea;--accent-line:#a9c7cb;
  --cc:#a8322f;--ccb:#f6e5e2;--cbd:#dcb2ab;--ch:#a9631a;--chb:#f5ead9;--hbd:#e0bd8b;
  --cm:#2f6690;--cmb:#e2ecf1;--mbd:#a9c6d8;--cl:#3f7a4f;--clb:#e5efe4;--lbd:#aecfae;
  --cn:#6b6f70;--cnb:#e7e6e2;--nbd:#c7c6bf;
  --hue-c:#7a4fa0;--hue-i:#1d5f6e;--hue-a:#a9631a;
  --font-d:"Oswald","Arial Narrow",sans-serif;--font-m:"IBM Plex Mono",monospace;
  --shadow-1:0 1px 2px rgba(30,28,20,.06);--shadow-2:0 4px 14px rgba(30,28,20,.10);
}
@media(prefers-color-scheme:dark){:root{
  --bg:#15171a;--bg2:#1c1f23;--bg3:#0f1113;--bd:#33373d;--bd2:#2a2d32;--tx:#e8e7e1;--mt:#a8a89f;--mtt:#74756e;
  --accent:#5ba3b3;--accent-ink:#bfe3ea;--accent-soft:#1c3237;--accent-line:#2e4d54;
  --cc:#e08a86;--ccb:#3a1e1c;--cbd:#5c2d29;--ch:#e0b17e;--chb:#3a2c16;--hbd:#5c451f;
  --cm:#8fbcdb;--cmb:#16283a;--mbd:#234057;--cl:#93c79d;--clb:#1a2f1e;--lbd:#274a2e;
  --cn:#a3a49b;--cnb:#262723;--nbd:#3a3b35;
  --hue-c:#c39be0;--hue-i:#7fc3d3;--hue-a:#e0b17e;
  --shadow-1:0 1px 2px rgba(0,0,0,.3);--shadow-2:0 8px 24px rgba(0,0,0,.4);
}}
:root[data-theme="dark"]{
  --bg:#15171a;--bg2:#1c1f23;--bg3:#0f1113;--bd:#33373d;--bd2:#2a2d32;--tx:#e8e7e1;--mt:#a8a89f;--mtt:#74756e;
  --accent:#5ba3b3;--accent-ink:#bfe3ea;--accent-soft:#1c3237;--accent-line:#2e4d54;
  --cc:#e08a86;--ccb:#3a1e1c;--cbd:#5c2d29;--ch:#e0b17e;--chb:#3a2c16;--hbd:#5c451f;
  --cm:#8fbcdb;--cmb:#16283a;--mbd:#234057;--cl:#93c79d;--clb:#1a2f1e;--lbd:#274a2e;
  --cn:#a3a49b;--cnb:#262723;--nbd:#3a3b35;
  --hue-c:#c39be0;--hue-i:#7fc3d3;--hue-a:#e0b17e;
  --shadow-1:0 1px 2px rgba(0,0,0,.3);--shadow-2:0 8px 24px rgba(0,0,0,.4);
}
:root[data-theme="light"]{
  --bg:#f3f1ec;--bg2:#fbfaf7;--bg3:#e9e6de;--bd:#d8d4c8;--bd2:#e3e0d6;--tx:#23241f;--mt:#5a5b54;--mtt:#8a8b82;
  --accent:#1d5f6e;--accent-ink:#0d3138;--accent-soft:#dce9ea;--accent-line:#a9c7cb;
  --cc:#a8322f;--ccb:#f6e5e2;--cbd:#dcb2ab;--ch:#a9631a;--chb:#f5ead9;--hbd:#e0bd8b;
  --cm:#2f6690;--cmb:#e2ecf1;--mbd:#a9c6d8;--cl:#3f7a4f;--clb:#e5efe4;--lbd:#aecfae;
  --cn:#6b6f70;--cnb:#e7e6e2;--nbd:#c7c6bf;
  --hue-c:#7a4fa0;--hue-i:#1d5f6e;--hue-a:#a9631a;
  --shadow-1:0 1px 2px rgba(30,28,20,.06);--shadow-2:0 4px 14px rgba(30,28,20,.10);
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:14px;line-height:1.6;color:var(--tx);background:var(--bg)}
.page{max-width:1040px;margin:0 auto;padding:2rem 1.5rem 4rem}
h1{font-family:var(--font-d);text-transform:uppercase;letter-spacing:.03em;font-size:21px;font-weight:600}
h2{font-family:var(--font-d);text-transform:uppercase;letter-spacing:.04em;font-size:14px;font-weight:600;margin:2.25rem 0 .85rem;padding-bottom:.5rem;border-bottom:1px solid var(--bd);color:var(--mt)}
.muted{color:var(--mt);font-size:13px}code{font-family:var(--font-m);font-size:12px;background:var(--bg3);padding:1px 5px;border-radius:3px}
.header{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:0}
.score-num{font-family:var(--font-d);font-size:52px;font-weight:700;line-height:1}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:0;margin:1.5rem 0 0;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);box-shadow:var(--shadow-1);overflow:hidden}
.stat{padding:14px 16px;border-right:1px solid var(--bd);border-bottom:1px solid var(--bd)}
.stat-label{font-size:10.5px;text-transform:uppercase;letter-spacing:.07em;color:var(--mtt);margin-bottom:5px;font-weight:600}
.stat-value{font-family:var(--font-m);font-size:22px;font-weight:700;font-variant-numeric:tabular-nums}
.bar-wrap{background:var(--bg3);border-radius:4px;height:7px;overflow:hidden;margin:6px 0}.bar{height:100%;border-radius:4px}
.bar-critical{background:var(--cc)}.bar-high{background:var(--ch)}.bar-medium{background:var(--cm)}.bar-low{background:var(--cl)}.bar-none{background:var(--cn)}
.badge{display:inline-block;font-family:var(--font-m);font-size:10.5px;font-weight:600;text-transform:uppercase;letter-spacing:.03em;padding:3px 10px;border-radius:20px;vertical-align:middle}
.badge-critical{background:var(--ccb);color:var(--cc);border:1px solid var(--cbd)}.badge-high{background:var(--chb);color:var(--ch);border:1px solid var(--hbd)}
.badge-medium{background:var(--cmb);color:var(--cm);border:1px solid var(--mbd)}.badge-low{background:var(--clb);color:var(--cl);border:1px solid var(--lbd)}
.badge-none{background:var(--cnb);color:var(--cn);border:1px solid var(--nbd)}
.score-critical{color:var(--cc)}.score-high{color:var(--ch)}.score-medium{color:var(--cm)}.score-low{color:var(--cl)}.score-none{color:var(--cn)}
.issue-card{border:1px solid var(--bd);border-radius:4px;margin-bottom:10px;overflow:hidden;background:var(--bg2);box-shadow:var(--shadow-1);position:relative}
.issue-card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px}
.issue-card.card-critical::before{background:var(--cc)}.issue-card.card-high::before{background:var(--ch)}
.issue-card.card-medium::before{background:var(--cm)}.issue-card.card-low::before{background:var(--cl)}
.issue-hdr{display:flex;align-items:center;gap:10px;padding:13px 16px 13px 19px;cursor:pointer;user-select:none}
.issue-hdr:hover{background:var(--bg3)}.i-score{font-family:var(--font-m);font-size:18px;font-weight:700;min-width:34px;font-variant-numeric:tabular-nums}
.i-dir{font-family:var(--font-m);font-size:13px;font-weight:600;flex:1}.i-val{font-family:var(--font-m);font-size:12px;color:var(--mt)}
.chevron{color:var(--mt);font-size:15px;transition:transform .2s}.chevron.open{transform:rotate(180deg)}
.issue-body{display:none;padding:20px 20px 20px 23px;border-top:1px solid var(--bd)}.issue-body.open{display:block}
.desc-block{font-size:14px;line-height:1.7;margin-bottom:1.25rem;padding:14px 16px;background:var(--bg3);border-radius:4px;border-left:3px solid var(--bd)}
.scores-row{display:flex;gap:10px;margin-bottom:1.25rem;flex-wrap:wrap}
.score-box{background:var(--bg3);border-radius:4px;padding:12px 18px;text-align:center;min-width:100px}
.score-box-num{font-family:var(--font-m);font-size:26px;font-weight:700;line-height:1}.score-box-sub{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--mtt);margin-top:4px}
.metrics-block{margin-bottom:1.25rem}.block-title{font-size:10.5px;font-weight:600;color:var(--mtt);text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px}
.mtable{width:100%;border-collapse:collapse;font-size:13px}.mtable tr{border-bottom:1px solid var(--bd2)}.mtable tr:last-child{border-bottom:none}
.mtable td{padding:8px 10px;vertical-align:top}.mtable td:first-child{font-family:var(--font-m);font-weight:700;width:44px;white-space:nowrap}
.mtable td:nth-child(2){white-space:nowrap;width:170px}.m-val{font-family:var(--font-m);font-weight:600}.m-desc{color:var(--mt);font-size:12px;margin-left:4px}.m-why{font-size:12px;color:var(--mt);line-height:1.5}
.impact-list{list-style:none;margin:0;padding:0}.impact-list li{font-size:13px;padding:5px 0;border-bottom:1px solid var(--bd2);display:flex;gap:8px;align-items:flex-start}
.impact-list li:last-child{border-bottom:none}.impact-list li::before{content:"\\2192";color:var(--ch);font-weight:600;flex-shrink:0;margin-top:1px}
.scenario-block{background:var(--bg3);border-radius:4px;padding:14px 16px;margin-bottom:1.25rem}
.prereqs{list-style:none;margin:0 0 12px;padding:0}.prereqs li{font-size:13px;padding:3px 0;display:flex;gap:6px}.prereqs li::before{content:"\\2022";color:var(--mt)}
.example-box{background:var(--bg);border:1px solid var(--bd);border-radius:4px;padding:12px 14px;font-family:var(--font-m);font-size:12px;white-space:pre-wrap;word-break:break-word;margin:10px 0}
.result-box{font-size:13px;color:var(--mt);margin-top:8px}
.rec-box{background:var(--clb);border-left:3px solid var(--cl);border-radius:0 4px 4px 0;padding:12px 16px;font-size:13px;margin-bottom:1.25rem}
.cve-tag{display:inline-block;background:var(--chb);color:var(--ch);border:1px solid var(--hbd);border-radius:4px;font-family:var(--font-m);font-size:12px;padding:2px 8px;margin:2px}
.loc-tag{font-family:var(--font-m);font-size:11px;color:var(--mt);background:var(--bg3);border-radius:4px;padding:3px 8px;display:inline-block;margin:2px}
hr.sec{border:none;border-top:1px solid var(--bd2);margin:1.25rem 0}
.chain-card{border:1px solid var(--bd);border-radius:4px;margin-bottom:10px;padding:16px;background:var(--bg2);box-shadow:var(--shadow-1)}
.chain-hdr{display:flex;align-items:center;gap:10px;margin-bottom:10px}.c-score{font-family:var(--font-m);font-size:18px;font-weight:700;min-width:34px}.c-id{font-family:var(--font-m);font-size:13px;font-weight:600;flex:1}
.amp{background:var(--chb);color:var(--ch);border:1px solid var(--hbd);border-radius:20px;font-size:11px;font-weight:600;padding:2px 9px}
.dir-tag{background:var(--bg3);border:1px solid var(--bd);border-radius:4px;font-family:var(--font-m);font-size:12px;padding:3px 9px}
.explore{display:flex;flex-direction:column;gap:10px;background:var(--bg2);border:1px solid var(--bd);border-radius:4px;padding:14px 16px;margin-bottom:16px;position:sticky;top:10px;z-index:10;box-shadow:var(--shadow-2)}
.explore-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.explore-label{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--mtt);font-weight:600;width:60px;flex-shrink:0}
.filter-bar{display:flex;gap:6px;flex-wrap:wrap}
.filter-btn{font-family:var(--font-m);background:var(--bg);border:1px solid var(--bd);border-radius:20px;padding:4px 12px;font-size:11.5px;cursor:pointer;color:var(--mt)}
.filter-btn:hover{border-color:var(--mtt)}.filter-btn.active{border-color:var(--accent-line);color:var(--accent-ink);background:var(--accent-soft);font-weight:600}
.explore-search{flex:1;min-width:160px;font-family:var(--font-m);font-size:12.5px;background:var(--bg);border:1px solid var(--bd);border-radius:20px;padding:6px 14px;color:var(--tx)}
.explore-search::placeholder{color:var(--mtt)}
.explore-search:focus{outline:2px solid var(--accent-line);outline-offset:1px;border-color:var(--accent)}
.result-count{font-family:var(--font-m);font-size:11px;color:var(--mtt);margin-left:auto}
.sev-sep{display:flex;align-items:center;gap:8px;margin:1.5rem 0 .75rem}.sev-line{flex:1;height:1px;background:var(--bd)}
.itbl{width:100%;border-collapse:collapse;font-size:13px}.itbl td{padding:6px 0;border-bottom:1px solid var(--bd2)}.itbl td:first-child{color:var(--mt);width:180px}.itbl tr:last-child td{border-bottom:none}
.snippet-block{border:1px solid var(--bd);border-radius:4px;overflow:hidden;margin:4px 0;max-width:100%}
.snippet-header{background:var(--bg3);font-family:var(--font-m);font-size:11px;color:var(--mt);padding:5px 10px;border-bottom:1px solid var(--bd)}
.snippet-body{background:var(--bg);font-family:var(--font-m);font-size:12px;line-height:1.5;overflow-x:auto}
.snippet-row{display:flex;padding:1px 10px}
.snippet-row.snippet-target{background:var(--chb)}
.snippet-lineno{color:var(--mt);width:32px;text-align:right;padding-right:10px;flex-shrink:0;user-select:none}
.snippet-text{white-space:pre;color:var(--tx)}
.snippet-row.snippet-target .snippet-text{color:var(--ch);font-weight:600}
@media print{.issue-body{display:block!important}.chevron,.explore{display:none}}
'''


def generate_html(result, resolved=None):
    from config_assessment.core.ccss import severity_label

    groups = _group_issues(sorted(result.issues, key=lambda x: -x.temporal_score))
    active_chains = sorted(
        _dedup_chains([c for c in result.chains if c.active]),
        key=lambda x: -x.amplified_score,
    )
    counts = {}
    for g in groups:
        sev = severity_label(g["issue"].temporal_score)
        counts[sev] = counts.get(sev, 0) + 1

    mode_label = {"file":"File","directory":"Directory","live":"Live service","docker":"Docker image"}.get(
        resolved.mode if resolved else "file","File")
    scan_time = result.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    score = result.global_temporal_score
    sev_cls = _sev_class(score)
    input_src = result.input_path
    if resolved:
        if resolved.mode == "docker":
            input_src = resolved.metadata.get("image", result.input_path)
        elif resolved.mode == "live":
            svc=resolved.metadata.get("service",""); ver=resolved.metadata.get("version","")
            input_src = f"{svc} {ver}".strip() if ver and ver != "unknown" else svc

    av_rationale = getattr(result.profile, "rationale_av", "")
    au_rationale = getattr(result.profile, "rationale_au", "")

    def mrow(key, val, vdesc, why):
        return (f'<tr><td>{key}</td>'
                f'<td><span class="m-val">{_e(val)}</span><span class="m-desc">{_e(vdesc)}</span></td>'
                f'<td><span class="m-why">{_e(_strip_metric_prefix(why))}</span></td></tr>')

    def render_issue(g, idx):
        issue = g["issue"]; contexts = g["contexts"]
        sev = severity_label(issue.temporal_score); cls = _sev_class(issue.temporal_score)

        narrative = {}
        raw = getattr(issue, "narrative", "{}")
        if raw and raw != "{}":
            try: narrative = _json.loads(raw)
            except Exception: pass

        mjust = narrative.get("metric_justifications", {})
        desc = narrative.get("description","") or issue.justification or ""
        impact_items = narrative.get("potential_impact", [])
        scenario = narrative.get("exploitation_scenario", {})
        prereqs = scenario.get("prerequisites", [])
        example = scenario.get("example", "")
        result_text = scenario.get("result", "")

        exploit_rows = (
            mrow("AV", issue.av, _AV_DESC.get(issue.av,""), _av_why(issue.av, av_rationale)) +
            mrow("Au", issue.au, _AU_DESC.get(issue.au,""), _au_why(issue.au, au_rationale)) +
            mrow("AC", issue.ac, _AC_DESC.get(issue.ac,""), mjust.get("ac","") or ("AC=" + issue.ac + ": " + _AC_DESC.get(issue.ac,"")))
        )
        impact_rows = (
            mrow("C",   issue.c,   _CIA_DESC.get(issue.c,""),  mjust.get("c","")   or f"C={issue.c}") +
            mrow("I",   issue.i,   _CIA_DESC.get(issue.i,""),  mjust.get("i","")   or f"I={issue.i}") +
            mrow("A",   issue.a,   _CIA_DESC.get(issue.a,""),  mjust.get("a","")   or f"A={issue.a}") +
            mrow("GEL", issue.gel, _GEL_DESC.get(issue.gel,""),mjust.get("gel","") or f"GEL={issue.gel}") +
            mrow("GRL", issue.grl, _GRL_DESC.get(issue.grl,""),mjust.get("grl","") or f"GRL={issue.grl}")
        )

        impact_html = ""
        if impact_items:
            li = "".join(f"<li>{_e(str(i))}</li>" for i in impact_items)
            impact_html = f'<hr class="sec"><div class="metrics-block"><div class="block-title">Potential impact</div><ul class="impact-list">{li}</ul></div>'

        scenario_html = ""
        if prereqs or example:
            pr = "".join(f"<li>{_e(str(p))}</li>" for p in prereqs) if prereqs else ""
            pr_s = f'<div class="block-title" style="margin-bottom:6px">Prerequisites</div><ul class="prereqs">{pr}</ul>' if pr else ""
            ex_s = f'<div class="block-title" style="margin-bottom:6px;margin-top:10px">Example</div><div class="example-box">{_nl2br(_strip_code_tags(example))}</div>' if example else ""
            re_s = f'<p class="result-box"><strong>Result:</strong> {_e(result_text)}</p>' if result_text else ""
            scenario_html = f'<hr class="sec"><div class="metrics-block"><div class="block-title">Exploitation scenario</div><div class="scenario-block">{pr_s}{ex_s}{re_s}</div></div>'

        refs = [r for r in [f"CIS {issue.cis_section}" if issue.cis_section else "", issue.cce_id] if r]
        refs_html = " &nbsp;·&nbsp; ".join(f'<span class="muted">{r}</span>' for r in refs)
        cves_html = "".join(f'<span class="cve-tag">{_e(c)}</span>' for c in issue.cves) if issue.cves else ""
        snippet_blocks = []
        is_absence = getattr(issue, "rule_type", "value") == "absence"
        if is_absence:
            snippet_blocks.append(
                '<span class="loc-tag" style="font-style:italic">'
                'Directive absent — no source location</span>'
            )
        elif getattr(issue, "source_directive", None) and issue.source_directive.source_file:
            primary_ctx = issue.source_directive.context if issue.source_directive.context != "global" else ""
            snippet_blocks.append(_render_snippet_html(
                issue.source_directive.source_file,
                issue.source_directive.line_number,
                primary_ctx,
            ))
            extra_contexts = contexts[1:] if len(contexts) > 1 else []
            for c in extra_contexts:
                snippet_blocks.append(f'<span class="loc-tag">{_e(c)}</span>')
        locs_html = "".join(snippet_blocks)
        meta_parts = [x for x in [refs_html, cves_html] if x]
        meta_html = '<hr class="sec">' + "".join(f'<div style="margin-bottom:6px">{x}</div>' for x in meta_parts) if meta_parts else ""
        loc_html = f'<hr class="sec"><div class="metrics-block"><div class="block-title">Location in file</div>{locs_html}</div>' if locs_html else ""

        desc_html = f'<p class="desc-block">{_e(desc)}</p>' if desc else ""
        return (
            f'<div class="issue-card" data-sev="{sev.lower()}" '
            f'data-c="{issue.c}" data-i="{issue.i}" data-a="{issue.a}" id="issue-{idx}">' +
            f'<div class="issue-hdr" onclick="toggle({idx})">' +
            f'<span class="i-score score-{cls}">{issue.temporal_score:.1f}</span>' +
            f'<div style="flex:1;max-width:180px">{_bar(issue.temporal_score)}</div>' +
            f'<span class="i-dir">{_e(issue.directive)}</span>' +
            f'<span class="i-val">= {_display_value(issue)}</span>' +
            f'{_badge(issue.temporal_score, sev)}' +
            f'<span class="chevron" id="chev-{idx}">&#9662;</span></div>' +
            f'<div class="issue-body" id="body-{idx}">' +
            desc_html +
            f'<div class="scores-row">' +
            f'<div class="score-box"><div class="score-box-num score-{cls}">{issue.temporal_score:.1f}</div><div class="score-box-sub">Temporal Score</div>{_bar(issue.temporal_score)}</div>' +
            f'<div class="score-box"><div class="score-box-num" style="color:var(--mt)">{issue.base_score:.1f}</div><div class="score-box-sub">Base Score</div>{_bar(issue.base_score)}</div></div>' +
            '<hr class="sec">' +
            f'<div class="metrics-block"><div class="block-title">Exploitability — how the attacker reaches this</div><table class="mtable"><tbody>{exploit_rows}</tbody></table></div>' +
            '<hr class="sec">' +
            f'<div class="metrics-block"><div class="block-title">Impact &amp; Temporal</div><table class="mtable"><tbody>{impact_rows}</tbody></table></div>' +
            impact_html + scenario_html +
            '<hr class="sec">' +
            f'<div class="metrics-block"><div class="block-title">Recommendation</div><div class="rec-box">{_e(issue.recommendation or chr(8212))}</div></div>' +
            meta_html + loc_html +
            '</div></div>'
        )

    issues_html = ""
    idx = 0
    for sev_name in ["Critical","High","Medium","Low"]:
        sg = [g for g in groups if severity_label(g["issue"].temporal_score) == sev_name]
        if not sg: continue
        issues_html += (f'<div class="sev-sep"><span class="badge badge-{sev_name.lower()}">{sev_name}</span>' +
                        f'<span class="muted">({len(sg)})</span><div class="sev-line"></div></div>')
        for g in sorted(sg, key=lambda x: -x["issue"].temporal_score):
            issues_html += render_issue(g, idx); idx += 1

    chains_html = ""
    for chain in active_chains:
        cls = _sev_class(chain.amplified_score)
        dirs = " ".join(f'<span class="dir-tag">{_e(d)}</span>' for d in chain.triggered_by)
        chains_html += (
            f'<div class="chain-card"><div class="chain-hdr">' +
            f'<span class="c-score score-{cls}">{chain.amplified_score:.1f}</span>' +
            f'<div style="flex:1;max-width:160px">{_bar(chain.amplified_score)}</div>' +
            f'<span class="c-id">{_e(chain.chain_id)}</span>' +
            f'{_badge(chain.amplified_score)}</div>' +
            f'<div style="margin-bottom:10px">{dirs}</div>' +
            f'<p style="font-size:13px;color:var(--mt)">{_e(chain.justification or chr(8212))}</p></div>'
        )

    def stat(label, value, cls=""):
        clr = f'class="stat-value score-{cls}"' if cls else 'class="stat-value"'
        return f'<div class="stat"><div class="stat-label">{label}</div><div {clr}>{value}</div></div>'

    stats_html = (
        stat("Global score", f"{score:.1f}", sev_cls) +
        stat("Directives", result.total_directives_scanned) +
        stat("Issues", len(groups)) + stat("Chains", len(active_chains)) +
        stat("Critical", counts.get("Critical",0), "critical" if counts.get("Critical") else "") +
        stat("High", counts.get("High",0), "high" if counts.get("High") else "") +
        stat("Medium", counts.get("Medium",0), "medium" if counts.get("Medium") else "") +
        stat("Low", counts.get("Low",0), "low" if counts.get("Low") else "")
    )

    info_rows = (
        f"<tr><td>Target</td><td>{_e(result.target_name)}</td></tr>" +
        f"<tr><td>Input</td><td><code>{_e(input_src)}</code></td></tr>" +
        f"<tr><td>Mode</td><td>{mode_label}</td></tr>" +
        f"<tr><td>AV / Au</td><td>{_AV_DESC.get(result.profile.av,'?')} / {_AU_DESC.get(result.profile.au,'?')}</td></tr>" +
        f"<tr><td>Scan time</td><td>{scan_time}</td></tr>" +
        "<tr><td>Standard</td><td>NISTIR 7502 (CCSS) &#183; CIS Apache HTTP Server 2.4</td></tr>"
    )

    fbtns = f'<button class="filter-btn active" onclick="filterSev(\'all\',this)">All ({len(groups)})</button>'
    for sn, sc2 in [("Critical","critical"),("High","high"),("Medium","medium"),("Low","low")]:
        n = counts.get(sn,0)
        if n: fbtns += f'<button class="filter-btn" onclick="filterSev(\'{sc2}\',this)">{sn} ({n})</button>'

    ibtns = '<button class="filter-btn active" onclick="filterImpact(\'all\',this)">All impact</button>'
    for lbl, key in [("Confidentiality","c"),("Integrity","i"),("Availability","a")]:
        n = sum(1 for g in groups if getattr(g["issue"], key) == "C")
        if n: ibtns += f'<button class="filter-btn" onclick="filterImpact(\'{key}\',this)">{lbl} ({n})</button>'

    js = """
function toggle(i){var b=document.getElementById('body-'+i),c=document.getElementById('chev-'+i),o=b.classList.toggle('open');c.classList.toggle('open',o);}
var _sevF='all', _impF='all';
function applyFilters(){
  document.querySelectorAll('.issue-card').forEach(function(c){
    var sevOk=(_sevF==='all'||c.dataset.sev===_sevF);
    var impOk=(_impF==='all'||c.dataset[_impF]==='C');
    c.style.display=(sevOk&&impOk)?'':'none';
  });
  document.querySelectorAll('.sev-sep').forEach(function(h){
    var n=h.nextElementSibling,v=false;
    while(n&&n.classList.contains('issue-card')){if(n.style.display!=='none')v=true;n=n.nextElementSibling;}
    h.style.display=v?'':'none';
  });
}
function filterSev(s,btn){
  _sevF=s;
  btn.parentElement.querySelectorAll('.filter-btn').forEach(function(b){b.classList.remove('active');});
  btn.classList.add('active');
  applyFilters();
}
function filterImpact(k,btn){
  _impF=k;
  btn.parentElement.querySelectorAll('.filter-btn').forEach(function(b){b.classList.remove('active');});
  btn.classList.add('active');
  applyFilters();
}"""

    return (
        "<!DOCTYPE html>\n<html lang=\"en\"><head>\n" +
        "<meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n" +
        f"<title>CASPAR &#8212; {_e(result.target_name)} &#8212; {score:.1f} {result.severity}</title>\n" +
        f"<style>{CSS}</style></head><body>\n<div class=\"page\">\n" +
        '<div class="header"><div>\n' +
        f'<h1>CASPAR Security Report</h1>\n' +
        f'<p class="muted" style="margin-top:4px">{_e(result.target_name)} &nbsp;&#183;&nbsp; {scan_time}</p>\n' +
        f'<p class="muted">{mode_label}: <code>{_e(input_src)}</code></p>\n' +
        f'<div style="margin-top:12px;max-width:360px">{_bar(score)}</div>\n' +
        '</div><div style="text-align:right">\n' +
        f'<div class="score-num score-{sev_cls}">{score:.1f}</div>\n' +
        '<div class="muted" style="font-size:13px;margin-top:2px">/ 10.0</div>\n' +
        f'<div style="margin-top:8px">{_badge(score, result.severity)}</div>\n' +
        '</div></div>\n' +
        f'<div class="stats">{stats_html}</div>\n' +
        '<h2>Scan information</h2>\n' +
        f'<table class="itbl"><tbody>{info_rows}</tbody></table>\n' +
        '<h2>Issues found</h2>\n' +
        f'<div class="filter-bar">{fbtns}</div>\n' +
        f'<div class="filter-bar" style="margin-top:-.5rem">{ibtns}</div>\n' +
        (issues_html or '<p class="muted">No issues detected.</p>') +
        '\n<h2>Attack chains</h2>\n' +
        (chains_html or '<p class="muted">No chains detected.</p>') +
        f'\n</div>\n<script>{js}</script>\n</body></html>'
    )
