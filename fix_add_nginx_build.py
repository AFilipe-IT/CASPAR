"""
fix_add_nginx_build.py
------------------------
Adiciona o branch 'nginx' ao comando build do CLI.

O build tinha apenas: if target == "apache-httpd": ... else: "não implementado".
Este patch acrescenta um branch elif para nginx, chamando o run_build do
plugin Nginx.

Uso:
    python3 fix_add_nginx_build.py
"""

from __future__ import annotations
import sys
from pathlib import Path

path = Path("cli/main.py")
if not path.exists():
    print("ERROR: cli/main.py not found. Run from ~/ccss_scan.")
    sys.exit(1)

content = path.read_text(encoding="utf-8")
original = content

if 'from plugins.nginx.build_nginx import run_build' in content:
    print("\u2713 Nginx build branch already present — skipping")
    sys.exit(0)

# Anchor: the else branch that says "não implementado"
anchor = '''        click.echo(click.style(f"  Concluído: {count} misconfigurations.", fg="green"))
    else:
        click.echo(f"Target '{target}' não implementado.", err=True)
        sys.exit(1)'''

replacement = '''        click.echo(click.style(f"  Concluído: {count} misconfigurations.", fg="green"))
    elif target == "nginx":
        from plugins.nginx.build_nginx import run_build
        click.echo(f"  A construir '{target}' com {model}...")
        count = run_build(
            benchmark_path=benchmark,
            db_path=ctx.obj["db_path"],
            model=model,
            ollama_url=ollama_url,
            dry_run=dry_run,
        )
        click.echo(click.style(f"  Concluído: {count} misconfigurations.", fg="green"))
    else:
        click.echo(f"Target '{target}' não implementado.", err=True)
        sys.exit(1)'''

if anchor in content:
    content = content.replace(anchor, replacement, 1)
    print("\u2713 Added nginx branch to build command")
else:
    print("\u26a0 Could not find the exact anchor. Showing the build else-branch area:")
    import re
    for m in re.finditer(r'não implementado', content):
        start = content.rfind('\n', 0, m.start() - 100)
        print(content[start:m.end()+30])
    sys.exit(1)

if content == original:
    print("No changes made.")
    sys.exit(0)

path.write_text(content, encoding="utf-8")

import ast
try:
    ast.parse(path.read_text(encoding="utf-8"))
    print("\nSyntax OK. Build Nginx with:")
    print("  ccss build --target nginx --benchmark plugins/nginx/CIS_NGINX_Benchmark_v3.0.0.pdf")
except SyntaxError as e:
    print(f"\nFAIL line {e.lineno}: {e.msg} — restoring original")
    path.write_text(original, encoding="utf-8")
