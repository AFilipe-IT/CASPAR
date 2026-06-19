"""
fix_rag_multilevel_sections.py
--------------------------------
Corrige o parser de benchmark (core/rag.py) para reconhecer IDs de secção
com 2 OU MAIS níveis.

PROBLEMA: o regex usava \\d+\\.\\d+ (exactamente 2 níveis, ex: "8.1" do
Apache). O CIS NGINX Benchmark v3.0.0 usa 3 níveis (ex: "2.2.2", "2.5.1").
Resultado: das secções Nginx, quase nenhuma casava — o índice ficava com 4
secções em vez de ~50, e o LLM gerava narrativas sem contexto CIS real.

CORREÇÃO: \\d+(?:\\.\\d+)+ casa "8.1" (Apache) E "2.2.2" (Nginx).
Dois sítios: _SECTION_RE e o re.match dentro de parse_benchmark.

Uso:
    python3 fix_rag_multilevel_sections.py
"""

from __future__ import annotations
import sys
from pathlib import Path

path = Path("core/rag.py")
if not path.exists():
    print("ERROR: core/rag.py not found. Run from ~/ccss_scan.")
    sys.exit(1)

content = path.read_text(encoding="utf-8")
original = content
changes = 0

# Fix 1: _SECTION_RE module-level pattern
old1 = r"r'^(\d+\.\d+)\s+Ensure\s+(.+?)(?:\s*\((?:Automated|Manual)\))?$'"
new1 = r"r'^(\d+(?:\.\d+)+)\s+Ensure\s+(.+?)(?:\s*\((?:Automated|Manual)\))?$'"
if old1 in content:
    content = content.replace(old1, new1, 1)
    changes += 1
    print("\u2713 Fixed _SECTION_RE (module-level)")
elif new1 in content:
    print("\u2713 _SECTION_RE already multi-level")
else:
    print("\u26a0 _SECTION_RE pattern not found verbatim — check manually")

# Fix 2: the re.match inside parse_benchmark loop
old2 = "re.match(r'^(\\d+\\.\\d+)\\s+Ensure\\s+(.+)', line)"
new2 = "re.match(r'^(\\d+(?:\\.\\d+)+)\\s+Ensure\\s+(.+)', line)"
if old2 in content:
    content = content.replace(old2, new2, 1)
    changes += 1
    print("\u2713 Fixed inline re.match in parse_benchmark")
elif new2 in content:
    print("\u2713 inline re.match already multi-level")
else:
    print("\u26a0 inline re.match pattern not found verbatim — check manually")

if changes == 0 and content == original:
    print("\nNo changes made (already patched or patterns differ).")
    sys.exit(0)

path.write_text(content, encoding="utf-8")

import ast
try:
    ast.parse(path.read_text(encoding="utf-8"))
    print(f"\n{changes} change(s) applied. Syntax OK.")
    print("Verify section extraction with the diagnostic, then rebuild nginx.")
except SyntaxError as e:
    print(f"\nFAIL line {e.lineno}: {e.msg} — restoring original")
    path.write_text(original, encoding="utf-8")
