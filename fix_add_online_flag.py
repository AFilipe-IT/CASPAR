"""
fix_add_online_flag.py
------------------------
Adiciona a flag --online ao comando scan. Quando usada com
--format dashboard, gera o dashboard com gráficos ECharts (via CDN)
em vez do dashboard SVG offline.

Uso:
    python3 fix_add_online_flag.py
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

# 1. Add the --online click option. Anchor on the --format option line.
if "--online" not in content:
    # Find a click.option for format/output to anchor near
    fmt_opt = re.search(r'@click\.option\("--format"[^\n]*\n(?:[^\n]*\n)*?[^\n]*\)\n', content)
    # Simpler: anchor on the scan function's @click.option for --output or --threshold
    anchor = re.search(r'(@click\.option\("--threshold"[^)]*\)\n)', content)
    if not anchor:
        anchor = re.search(r'(@click\.option\("--output"[^)]*\)\n)', content)
    if anchor:
        online_opt = ('@click.option("--online", is_flag=True, default=False,\n'
                      '              help="Use online charts (ECharts via CDN) for the dashboard format.")\n')
        content = content.replace(anchor.group(1), anchor.group(1) + online_opt, 1)
        print("\u2713 Added --online click option")
    else:
        print("\u26a0 Could not find an anchor option (--threshold/--output) to add --online")
        print("  Add manually:")
        print('  @click.option("--online", is_flag=True, default=False,')
        print('                help="Use online charts (ECharts via CDN) for the dashboard format.")')
else:
    print("\u2713 --online option already present")

# 2. Add 'online' to the scan function signature.
# Find the def scan(...) signature and add online param.
if "online" not in content.split("def scan(")[1].split(")")[0]:
    sig = re.search(r'(def scan\([^)]*)\)', content)
    if sig:
        new_sig = sig.group(1).rstrip()
        if not new_sig.endswith(","):
            new_sig += ","
        new_sig += " online"
        content = content.replace(sig.group(0), new_sig + ")", 1)
        print("\u2713 Added 'online' to scan() signature")
    else:
        print("\u26a0 Could not find scan() signature")
else:
    print("\u2713 'online' already in signature")

# 3. Modify the dashboard branch to pick generator based on --online.
old_branch = '''        elif fmt == "dashboard":
            from core.report_dashboard import generate_dashboard
            p = od / f"ccss_{stem}_{ts}_dashboard.html"
            p.write_text(generate_dashboard(result, resolved=resolved), encoding="utf-8")
            click.echo(f"  Dashboard: {click.style(str(p), fg='cyan')}")'''

new_branch = '''        elif fmt == "dashboard":
            if online:
                from core.report_dashboard_online import generate_dashboard_online as _gen_dash
                _suffix = "dashboard_online"
            else:
                from core.report_dashboard import generate_dashboard as _gen_dash
                _suffix = "dashboard"
            p = od / f"ccss_{stem}_{ts}_{_suffix}.html"
            p.write_text(_gen_dash(result, resolved=resolved), encoding="utf-8")
            _label = "Dashboard (online)" if online else "Dashboard"
            click.echo(f"  {_label}: {click.style(str(p), fg='cyan')}")'''

if old_branch in content:
    content = content.replace(old_branch, new_branch, 1)
    print("\u2713 Updated dashboard branch to honour --online")
elif "report_dashboard_online" in content:
    print("\u2713 Dashboard branch already honours --online")
else:
    print("\u26a0 Could not find the exact dashboard branch. Update it manually to:")
    print(new_branch)

if content == original:
    print("\nNo changes made.")
    sys.exit(0)

path.write_text(content, encoding="utf-8")

import ast
try:
    ast.parse(path.read_text(encoding="utf-8"))
    print("\nSyntax OK. Generate an online dashboard with:")
    print("  ccss scan docker://ccss-test-apache:vulnerable --report --format dashboard --online --output ~/relatorios/")
except SyntaxError as e:
    print(f"\nFAIL line {e.lineno}: {e.msg} — restoring original")
    path.write_text(original, encoding="utf-8")
