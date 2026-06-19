"""
fix_snippet_wiring.py
-----------------------
Completa os passos 3 e 4 do fix_show_config_snippet.py que falharam
porque o ficheiro real tinha formatação diferente:
  - locs_html usa "<br>".join (não "".join)
  - CSS está em string de aspas simples (não triple-quote)

Os helpers _read_snippet e _render_snippet_html já foram inseridos
com sucesso pelo script anterior. Este script só liga-os.

Uso:
    python3 fix_snippet_wiring.py
"""

from __future__ import annotations
import sys
from pathlib import Path

path = Path("core/report_html.py")
if not path.exists():
    print("ERROR: core/report_html.py not found. Run from ~/ccss_scan.")
    sys.exit(1)

content = path.read_text(encoding="utf-8")
original = content

# ── Sanity: helpers must already be present ─────────────────────────
if "_render_snippet_html" not in content:
    print("ERROR: _render_snippet_html not found — run fix_show_config_snippet.py first.")
    sys.exit(1)

# ── Fix 1: replace the locs_html line — indentation-tolerant regex ──
import re as _re

# Match the locs_html assignment regardless of indentation or whether it
# uses "".join or "<br>".join
locs_re = _re.compile(
    r'^(?P<indent>[ \t]*)locs_html\s*=\s*"(?:<br>)?"\.join\(\s*f\'<span class="loc-tag">\{_e\(c\)\}</span>\'\s+for c in contexts\)\s+if contexts else ""\s*$',
    _re.MULTILINE,
)

def _build_new_locs(indent):
    L = indent
    return (
        f'{L}snippet_blocks = []\n'
        f'{L}if getattr(issue, "source_directive", None) and issue.source_directive.source_file:\n'
        f'{L}    primary_ctx = issue.source_directive.context if issue.source_directive.context != "global" else ""\n'
        f'{L}    snippet_blocks.append(_render_snippet_html(\n'
        f'{L}        issue.source_directive.source_file,\n'
        f'{L}        issue.source_directive.line_number,\n'
        f'{L}        primary_ctx,\n'
        f'{L}    ))\n'
        f'{L}extra_contexts = contexts[1:] if len(contexts) > 1 else []\n'
        f'{L}for c in extra_contexts:\n'
        f"{L}    snippet_blocks.append(f'<span class=\"loc-tag\">{{_e(c)}}</span>')\n"
        f'{L}locs_html = "".join(snippet_blocks)'
    )

m = locs_re.search(content)
if m:
    indent = m.group("indent")
    content = content[:m.start()] + _build_new_locs(indent) + content[m.end():]
    print("✓ Fix 1: replaced locs_html with snippet rendering")
elif "snippet_blocks" in content:
    print("✓ Fix 1: snippet wiring already present — skipping")
else:
    print("⚠ Fix 1: could not match locs_html line via regex.")
    print("  Expected something like: locs_html = \"<br>\".join(... for c in contexts) if contexts else \"\"")

# ── Fix 2: inject CSS into the single-quote CSS string ──────────────
# The CSS string ends with: ...display:none;}}\n'
# We insert our rules right before the closing @media print block.
css_rules = (
    ".snippet-block{border:.5px solid var(--bd);border-radius:6px;overflow:hidden;margin:4px 0;max-width:100%}\\n"
    ".snippet-header{background:var(--bg3);font-family:monospace;font-size:11px;color:var(--mt);padding:5px 10px;border-bottom:.5px solid var(--bd)}\\n"
    ".snippet-body{background:var(--bg);font-family:monospace;font-size:12px;line-height:1.5;overflow-x:auto}\\n"
    ".snippet-row{display:flex;padding:1px 10px}\\n"
    ".snippet-row.snippet-target{background:var(--chb)}\\n"
    ".snippet-lineno{color:var(--mt);width:32px;text-align:right;padding-right:10px;flex-shrink:0;user-select:none}\\n"
    ".snippet-text{white-space:pre;color:var(--tx)}\\n"
    ".snippet-row.snippet-target .snippet-text{color:var(--ch);font-weight:500}\\n"
)

# The CSS string contains '@media print{...}\n' near the end as literal text.
media_marker = "@media print{.issue-body{display:block!important}.chevron,.filter-bar{display:none}}"

if ".snippet-block" in content:
    print("✓ Fix 2: snippet CSS already present — skipping")
elif media_marker in content:
    content = content.replace(media_marker, css_rules + media_marker, 1)
    print("✓ Fix 2: injected snippet CSS before @media print rule")
else:
    print("⚠ Fix 2: could not find @media print marker in CSS — add rules manually.")

# ── Write + verify ──────────────────────────────────────────────────
if content == original:
    print("\nNo changes made.")
    sys.exit(0)

path.write_text(content, encoding="utf-8")

import ast
try:
    ast.parse(path.read_text(encoding="utf-8"))
    print("\nSyntax OK. Re-run the scan:")
    print("  ccss scan docker://ccss-test-apache:vulnerable --report --output ~/relatorios/")
except SyntaxError as e:
    print(f"\nFAIL line {e.lineno}: {e.msg} — restoring original")
    path.write_text(original, encoding="utf-8")
