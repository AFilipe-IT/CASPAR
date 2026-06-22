"""
fix_show_config_snippet.py
-----------------------------
Adiciona pré-visualização do bloco de configuração real (ficheiro + linhas
de contexto, não só "ficheiro:linha") na secção "Location in file" do
relatório HTML.

Em vez de:
    /tmp/test_httpd.conf:4

Passa a mostrar um bloco de código com a linha da directiva destacada e
2 linhas de contexto acima/abaixo.

Lê directamente do ficheiro de configuração (já está em disco no momento
da geração do relatório — mesmo no caso Docker, o directório temporário
só é limpo DEPOIS do scan completar, incluindo a geração do HTML).

Uso:
    python3 fix_show_config_snippet.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

report_path = Path("core/report_html.py")
if not report_path.exists():
    print(f"ERROR: {report_path} not found. Run from project root (~/ccss_scan).")
    sys.exit(1)

content = report_path.read_text(encoding="utf-8")
original_content = content

# ── 1. Ensure pathlib is imported ───────────────────────────────────

if re.search(r'^from pathlib import Path', content, re.MULTILINE) is None:
    content = re.sub(
        r'(from __future__ import annotations\n)',
        r'\1from pathlib import Path\n',
        content,
        count=1,
    )
    print("✓ Added 'from pathlib import Path'")
else:
    print("✓ pathlib already imported — skipping")

# ── 2. Insert snippet helper functions (idempotent) ─────────────────

SNIPPET_HELPERS = '''

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
        return f\'<span class="loc-tag">{_e(header)}</span>\'

    rows = ""
    for line_no, text, is_target in snippet:
        cls = " snippet-target" if is_target else ""
        rows += (
            f\'<div class="snippet-row{cls}">\'
            f\'<span class="snippet-lineno">{line_no}</span>\'
            f\'<span class="snippet-text">{_e(text)}</span>\'
            "</div>"
        )

    return (
        f\'<div class="snippet-block">\'
        f\'<div class="snippet-header">{_e(header)}</div>\'
        f\'<div class="snippet-body">{rows}</div>\'
        "</div>"
    )

'''

if "_read_snippet" not in content:
    # Insert right after the _dedup_chains function definition, found via regex
    # that tolerates any internal formatting.
    pattern = re.compile(
        r'(def _dedup_chains\(chains\):.*?\n(?:    .*\n)+)',
        re.MULTILINE,
    )
    match = pattern.search(content)
    if match:
        insert_at = match.end()
        content = content[:insert_at] + SNIPPET_HELPERS + content[insert_at:]
        print("✓ Inserted _read_snippet() and _render_snippet_html() after _dedup_chains()")
    else:
        # Fallback: insert right before "CSS = " or "def generate_html"
        fallback_pattern = re.compile(r'\ndef generate_html\(')
        m2 = fallback_pattern.search(content)
        if m2:
            content = content[:m2.start()] + SNIPPET_HELPERS + content[m2.start():]
            print("✓ Inserted snippet helpers before generate_html() (fallback insertion point)")
        else:
            print("✗ Could not find any insertion point. Aborting — no changes written.")
            sys.exit(1)
else:
    print("✓ _read_snippet already present — skipping helper insertion")

# ── 3. Replace plain loc-tag rendering with snippet rendering ───────

# Match the typical pattern used for locs_html, regardless of exact
# variable names used around it, as long as it builds a loc-tag string
# from `contexts`.
locs_pattern = re.compile(
    r'locs_html\s*=\s*"".join\(f\'<span class="loc-tag">\{_e\(c\)\}</span>\' for c in contexts\) if contexts else ""'
)

if locs_pattern.search(content):
    replacement = '''snippet_blocks = []
        if getattr(issue, "source_directive", None) and issue.source_directive.source_file:
            primary_ctx = issue.source_directive.context if issue.source_directive.context != "global" else ""
            snippet_blocks.append(_render_snippet_html(
                issue.source_directive.source_file,
                issue.source_directive.line_number,
                primary_ctx,
            ))
        extra_contexts = contexts[1:] if len(contexts) > 1 else []
        for c in extra_contexts:
            snippet_blocks.append(f'<span class="loc-tag">{_e(c)}</span>')
        locs_html = "".join(snippet_blocks)'''
    content = locs_pattern.sub(replacement, content, count=1)
    print("✓ Replaced plain location tags with config snippet rendering")
else:
    print("⚠ Could not find the exact locs_html assignment pattern.")
    print("  No changes made to location rendering — check core/report_html.py manually.")
    print("  Look for the line building 'loc-tag' spans from `contexts` and replace it with:")
    print()
    print(replacement if 'replacement' in dir() else "  (see SNIPPET_HELPERS usage above)")

# ── 4. Add CSS for the snippet block ─────────────────────────────────

CSS_ADDITION = """
.snippet-block{border:.5px solid var(--bd);border-radius:6px;overflow:hidden;margin:4px 0;max-width:100%}
.snippet-header{background:var(--bg3);font-family:monospace;font-size:11px;color:var(--mt);padding:5px 10px;border-bottom:.5px solid var(--bd)}
.snippet-body{background:var(--bg);font-family:monospace;font-size:12px;line-height:1.5;overflow-x:auto}
.snippet-row{display:flex;padding:1px 10px}
.snippet-row.snippet-target{background:var(--chb)}
.snippet-lineno{color:var(--mt);width:32px;text-align:right;padding-right:10px;flex-shrink:0;user-select:none}
.snippet-text{white-space:pre;color:var(--tx)}
.snippet-row.snippet-target .snippet-text{color:var(--ch);font-weight:500}
"""

if ".snippet-block" not in content:
    # Try to append right before the closing triple-quote of the CSS variable,
    # tolerant of whatever the last rule in CSS is.
    css_var_pattern = re.compile(r'(CSS\s*=\s*""".*?)(""")', re.DOTALL)
    m3 = css_var_pattern.search(content)
    if m3:
        content = content[:m3.end(1)] + CSS_ADDITION + content[m3.end(1):]
        print("✓ Added snippet CSS into the CSS variable")
    else:
        print("⚠ Could not find the CSS variable to append styles into.")
        print("  Add these rules manually to your stylesheet:")
        print(CSS_ADDITION)
else:
    print("✓ Snippet CSS already present — skipping")

# ── 5. Write and verify ──────────────────────────────────────────────

if content == original_content:
    print("\nNo changes were made (file may already be patched, or patterns didn't match).")
    sys.exit(0)

report_path.write_text(content, encoding="utf-8")

import ast
try:
    ast.parse(report_path.read_text(encoding="utf-8"))
    print("\nSyntax OK. Re-run a scan to see the config snippets:")
    print("  ccss scan docker://ccss-test-apache:vulnerable --report --output ~/relatorios/")
except SyntaxError as e:
    print(f"\nFAIL: syntax error at line {e.lineno}: {e.msg}")
    print("Restoring original file...")
    report_path.write_text(original_content, encoding="utf-8")
    print("Original file restored. No changes applied — paste the error here.")
