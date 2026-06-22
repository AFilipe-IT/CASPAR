"""
fix_add_dashboard_format.py
-----------------------------
Adiciona o formato 'dashboard' ao comando scan do CLI.

Uso:
    python3 fix_add_dashboard_format.py
"""

from __future__ import annotations
import re
import sys
from pathlib import Path

path = Path("cli/main.py")
if not path.exists():
    print("ERROR: cli/main.py not found. Run from ~/ccss_scan.")
    sys.exit(1)

content = path.read_text(encoding="utf-8")
original = content

# 1. Add 'dashboard' to the --format choices
choice_re = re.compile(r'type=click\.Choice\(\[([^\]]*)\]')
m = choice_re.search(content)
if m and "dashboard" not in m.group(1):
    inner = m.group(1)
    # Insert 'dashboard' after 'html' if present, else at the front
    if '"html"' in inner:
        new_inner = inner.replace('"html"', '"html", "dashboard"', 1)
    elif "'html'" in inner:
        new_inner = inner.replace("'html'", "'html', 'dashboard'", 1)
    else:
        new_inner = '"dashboard", ' + inner
    content = content.replace(f"click.Choice([{inner}]", f"click.Choice([{new_inner}]", 1)
    print("\u2713 Added 'dashboard' to --format choices")
elif m and "dashboard" in m.group(1):
    print("\u2713 'dashboard' already in choices")
else:
    print("\u26a0 Could not find --format Choice list")

# 2. Add the elif branch for dashboard generation.
# Find the html branch and add dashboard right after it.
html_branch_re = re.compile(
    r'(if fmt == "html":\n'
    r'\s+from core\.report_html import generate_html\n'
    r'\s+p = od / f"ccss_\{stem\}_\{ts\}\.html"\n'
    r'\s+p\.write_text\(generate_html\(result, resolved=resolved\), encoding="utf-8"\)\n'
    r'\s+click\.echo\(f"  HTML: \{click\.style\(str\(p\), fg=.cyan.\)\}"\))'
)

m2 = html_branch_re.search(content)
if m2 and 'report_dashboard' not in content:
    dashboard_branch = m2.group(1) + '''
        elif fmt == "dashboard":
            from core.report_dashboard import generate_dashboard
            p = od / f"ccss_{stem}_{ts}_dashboard.html"
            p.write_text(generate_dashboard(result, resolved=resolved), encoding="utf-8")
            click.echo(f"  Dashboard: {click.style(str(p), fg='cyan')}")'''
    content = content.replace(m2.group(1), dashboard_branch, 1)
    print("\u2713 Added dashboard generation branch")
elif 'report_dashboard' in content:
    print("\u2713 Dashboard branch already present")
else:
    print("\u26a0 Could not find the html generation branch to anchor dashboard.")
    print("  Add this elif manually after the html branch in the scan command:")
    print('''        elif fmt == "dashboard":
            from core.report_dashboard import generate_dashboard
            p = od / f"ccss_{stem}_{ts}_dashboard.html"
            p.write_text(generate_dashboard(result, resolved=resolved), encoding="utf-8")
            click.echo(f"  Dashboard: {click.style(str(p), fg='cyan')}")''')

if content == original:
    print("\nNo changes made.")
    sys.exit(0)

path.write_text(content, encoding="utf-8")

import ast
try:
    ast.parse(path.read_text(encoding="utf-8"))
    print("\nSyntax OK. Generate a dashboard with:")
    print("  ccss scan docker://ccss-test-apache:vulnerable --report --format dashboard --output ~/relatorios/")
except SyntaxError as e:
    print(f"\nFAIL line {e.lineno}: {e.msg} — restoring original")
    path.write_text(original, encoding="utf-8")
