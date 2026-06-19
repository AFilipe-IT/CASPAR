"""
fix_nginx_entry_point.py
-------------------------
Corrige a resolução de directório para reconhecer nginx.conf como ponto de
entrada, e torna o fallback robusto a fragmentos de config.

PROBLEMA: _ENTRY_POINTS só tinha nomes Apache (apache2.conf, httpd.conf, ...).
Num directório Nginx, o resolver não encontrava o ponto de entrada e caía no
fallback "primeiro .conf alfabético". Em imagens como bitnami/nginx, esse
primeiro .conf é fastcgi.conf (um fragmento de mappings FastCGI, não um
nginx.conf principal) -> nenhum plugin o reconhece -> crash.

CORREÇÃO (2 partes):
  1. Adicionar nginx.conf (e variantes) aos _ENTRY_POINTS.
  2. No fallback, ignorar fragmentos conhecidos que nunca são pontos de entrada
     (fastcgi.conf, scgi_params, uwsgi_params, mime.types, etc.).

Uso:
    python3 fix_nginx_entry_point.py
"""

from __future__ import annotations
import sys
from pathlib import Path

path = Path("core/input_resolver.py")
if not path.exists():
    print("ERROR: core/input_resolver.py not found. Run from ~/ccss_scan.")
    sys.exit(1)

c = path.read_text(encoding="utf-8")
orig = c
changes = 0

# ── 1. Adicionar nginx.conf aos entry points ──
old_entries = '''_ENTRY_POINTS = [
    "apache2.conf",
    "httpd.conf",
    "apache.conf",
    "httpd-ssl.conf",
]'''
new_entries = '''_ENTRY_POINTS = [
    "nginx.conf",
    "apache2.conf",
    "httpd.conf",
    "apache.conf",
    "httpd-ssl.conf",
]

# Config fragments that are NEVER a main entry point. Used to filter the
# directory fallback so we don't pick e.g. fastcgi.conf as the root config.
_CONFIG_FRAGMENTS = {
    "fastcgi.conf", "fastcgi_params", "scgi_params", "uwsgi_params",
    "mime.types", "proxy_params", "koi-win", "koi-utf", "win-utf",
}'''
if old_entries in c:
    c = c.replace(old_entries, new_entries, 1)
    changes += 1
    print("\u2713 1: nginx.conf added to entry points + fragment list defined")
elif '"nginx.conf",' in c:
    print("\u2713 1: nginx.conf already in entry points")
else:
    print("\u26a0 1: _ENTRY_POINTS block not found verbatim")

# ── 2. Tornar o fallback robusto a fragmentos ──
old_fallback = '''    # Fallback: primeiro .conf no directório
    conf_files = sorted(p.glob("*.conf"))
    if conf_files:'''
new_fallback = '''    # Fallback: primeiro .conf no directório que NÃO seja um fragmento conhecido
    conf_files = [
        f for f in sorted(p.glob("*.conf"))
        if f.name not in _CONFIG_FRAGMENTS
    ]
    if conf_files:'''
if old_fallback in c:
    c = c.replace(old_fallback, new_fallback, 1)
    changes += 1
    print("\u2713 2: fallback now skips known config fragments")
else:
    print("\u26a0 2: fallback block not found verbatim")

# ── 3. Mensagem de erro genérica (não diz só "Apache") ──
old_err = '''    raise FileNotFoundError(
        f"Nenhum ficheiro de configuração Apache encontrado em: {path}\\n"
        f"Esperado: {', '.join(_ENTRY_POINTS)}"
    )'''
new_err = '''    raise FileNotFoundError(
        f"Nenhum ficheiro de configuração reconhecido encontrado em: {path}\\n"
        f"Esperado um de: {', '.join(_ENTRY_POINTS)}"
    )'''
if old_err in c:
    c = c.replace(old_err, new_err, 1)
    changes += 1
    print("\u2713 3: error message is now target-agnostic")

if changes == 0:
    print("\nNo changes made.")
    sys.exit(0)

path.write_text(c, encoding="utf-8")

import ast
try:
    ast.parse(path.read_text(encoding="utf-8"))
    print(f"\n{changes} change(s) applied. Syntax OK.")
except SyntaxError as e:
    print(f"\nFAIL line {e.lineno}: {e.msg} — restoring original")
    path.write_text(orig, encoding="utf-8")
    sys.exit(1)
