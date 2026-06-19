"""
fix_strip_why_prefix.py
-------------------------
Remove o prefixo redundante "Why AC=M:" / "AC=M:" do início das
justificações de métrica no relatório HTML. O LLM segue o template do
prompt ("Why AC={ac}: ...") e o prefixo fica colado no texto.

A limpeza é feita dentro da função mrow(), por isso aplica-se às 6
métricas (AV, Au, AC, C, I, A, GEL, GRL) de uma vez e funciona
retroactivamente nas narrativas já gravadas, sem re-gerar nada.

Uso:
    python3 fix_strip_why_prefix.py
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

# ── 1. Add the _strip_metric_prefix helper (idempotent) ─────────────

if "_strip_metric_prefix" not in content:
    # Insert before the _e() function (always present, near top)
    helper = '''def _strip_metric_prefix(text):
    """Remove redundant 'Why AC=M:' / 'AC=M:' prefix from a metric
    justification — the metric key and value are already shown in their
    own columns, so the prefix is noise."""
    import re as _re
    t = str(text).strip()
    # Matches: optional "Why ", metric name, =, value, optional space, colon
    t = _re.sub(
        r'^(?:Why\\s+)?(?:AV|Au|AC|C|I|A|GEL|GRL)\\s*=\\s*[A-Za-z]+\\s*:\\s*',
        '',
        t,
    )
    return t.strip()


'''
    # Find "def _e(t):" and insert before it
    marker = "def _e(t):"
    if marker in content:
        content = content.replace(marker, helper + marker, 1)
        print("\u2713 Added _strip_metric_prefix() helper")
    else:
        print("\u26a0 Could not find def _e(t): to anchor helper insertion")
        sys.exit(1)
else:
    print("\u2713 _strip_metric_prefix already present — skipping")

# ── 2. Apply it inside mrow() ───────────────────────────────────────

# Current mrow signature/body uses `why` directly. We wrap it.
old_mrow_use = 'f\'<td><span class="m-why">{_e(why)}</span></td></tr>\')'
new_mrow_use = 'f\'<td><span class="m-why">{_e(_strip_metric_prefix(why))}</span></td></tr>\')'

if old_mrow_use in content:
    content = content.replace(old_mrow_use, new_mrow_use, 1)
    print("\u2713 Applied _strip_metric_prefix inside mrow()")
elif "_strip_metric_prefix(why)" in content:
    print("\u2713 mrow already uses _strip_metric_prefix — skipping")
else:
    print("\u26a0 Could not find the mrow m-why rendering line — check line 168 manually")

# ── 3. Write + verify ───────────────────────────────────────────────

if content == original:
    print("\nNo changes made.")
    sys.exit(0)

path.write_text(content, encoding="utf-8")

import ast
try:
    ast.parse(path.read_text(encoding="utf-8"))
    print("\nSyntax OK. Re-run the scan to see clean justifications:")
    print("  ccss scan docker://ccss-test-apache:vulnerable --report --output ~/relatorios/")
except SyntaxError as e:
    print(f"\nFAIL line {e.lineno}: {e.msg} — restoring original")
    path.write_text(original, encoding="utf-8")
