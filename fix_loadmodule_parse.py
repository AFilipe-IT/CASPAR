"""
fix_loadmodule_parse.py  (v2 — anchor corrigido)
-------------------------
Corrige a deteção de LoadModule.

PROBLEMA: o parser guardava value = "dav_module modules/mod_dav.so" (linha
toda). O lookup procura bad_value = "dav_module" EXACTO, por isso nunca casava
num Apache real (que tem sempre o caminho .so). As 5 misconfigurations de
módulos perigosos nunca eram detectadas.

CORREÇÃO: para LoadModule, value = nome do módulo (1º token).

Uso:
    python3 fix_loadmodule_parse.py
"""

from __future__ import annotations
import sys
from pathlib import Path

path = Path("plugins/apache_httpd/parser.py")
if not path.exists():
    print("ERROR: plugins/apache_httpd/parser.py not found. Run from ~/ccss_scan.")
    sys.exit(1)

content = path.read_text(encoding="utf-8")
original = content

if 'LoadModule' in content and 'value = value.split(None, 1)[0]' in content:
    print("\u2713 LoadModule normalisation already present — skipping")
    sys.exit(0)

# Anchor on the inline-comment strip line, which is distinctive.
# Insert the normalisation right AFTER it (and before the blank line + Directive).
anchor = '        value = re.sub(r"\\s+#.*$", "", value).strip()'

normalisation = '''        value = re.sub(r"\\s+#.*$", "", value).strip()
        # LoadModule: keep only the module name (1st token), not the .so path.
        # "LoadModule dav_module modules/mod_dav.so" -> "dav_module", so DB
        # lookup by module name matches real configs (which include the path).
        if _canonical(name) == "LoadModule" and value:
            value = value.split(None, 1)[0]'''

if anchor in content:
    content = content.replace(anchor, normalisation, 1)
    print("\u2713 Added LoadModule value normalisation in parser")
else:
    # Fallback: try matching with flexible whitespace via regex
    import re as _re
    pat = _re.compile(r'^([ \\t]*)value = re\\.sub\\(r"\\\\s\\+#\\.\\*\\$", "", value\\)\\.strip\\(\\)\\s*$', _re.MULTILINE)
    m = pat.search(content)
    if m:
        indent = m.group(1)
        block = (m.group(0) + "\\n" +
                 f'{indent}# LoadModule: keep only the module name (1st token), not the .so path.\\n'
                 f'{indent}if _canonical(name) == "LoadModule" and value:\\n'
                 f'{indent}    value = value.split(None, 1)[0]')
        content = content[:m.start()] + block + content[m.end():]
        print("\u2713 Added LoadModule normalisation (via regex fallback)")
    else:
        print("\u26a0 Could not find the inline-comment strip line. Showing context:")
        for i, line in enumerate(content.splitlines(), 1):
            if "Remove inline comments" in line or "re.sub" in line:
                print(f"  L{i}: {line!r}")
        sys.exit(1)

if content == original:
    print("No changes made.")
    sys.exit(0)

path.write_text(content, encoding="utf-8")

import ast
try:
    ast.parse(path.read_text(encoding="utf-8"))
    print("\nSyntax OK. LoadModule now matches by module name.")
    print("Re-run: ccss scan ~/ccss_scan/test_target/httpd.conf")
except SyntaxError as e:
    print(f"\nFAIL line {e.lineno}: {e.msg} — restoring original")
    path.write_text(original, encoding="utf-8")
