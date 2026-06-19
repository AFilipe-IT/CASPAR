"""
fix_build_narratives_service.py
---------------------------------
Faz o build_narratives.py passar o service_name correcto ao NarrativePipeline,
mapeado a partir do --target. Sem isto, mesmo com o pipeline target-agnostic,
as narrativas Nginx sairiam com o nome default (Apache).

Uso:
    python3 fix_build_narratives_service.py
"""

from __future__ import annotations
import sys
from pathlib import Path

path = Path("plugins/apache_httpd/build_narratives.py")
if not path.exists():
    print("ERROR: build_narratives.py not found. Run from ~/ccss_scan.")
    sys.exit(1)

content = path.read_text(encoding="utf-8")
original = content

if "_SERVICE_NAMES" in content:
    print("\u2713 Already maps service names — skipping")
    sys.exit(0)

# 1. Add a target->display-name map near the top (after imports).
anchor_import = "from plugins.apache_httpd.narrative_pipeline import NarrativePipeline"
service_map = '''from plugins.apache_httpd.narrative_pipeline import NarrativePipeline

# Map internal target name -> human-readable service name for narrative prompts.
_SERVICE_NAMES = {
    "apache-httpd": "Apache HTTP Server",
    "nginx": "Nginx",
}'''
if anchor_import in content:
    content = content.replace(anchor_import, service_map, 1)
    print("\u2713 1: added _SERVICE_NAMES map")
else:
    print("\u26a0 1: import anchor not found")

# 2. Pass service_name to NarrativePipeline.
old_pipe = "    pipeline = NarrativePipeline(llm=llm)"
new_pipe = '''    service_name = _SERVICE_NAMES.get(target, "Apache HTTP Server")
    logger.info("Generating %s narratives", service_name)
    pipeline = NarrativePipeline(llm=llm, service_name=service_name)'''
if old_pipe in content:
    content = content.replace(old_pipe, new_pipe, 1)
    print("\u2713 2: NarrativePipeline receives service_name")
else:
    print("\u26a0 2: NarrativePipeline instantiation not found verbatim")

path.write_text(content, encoding="utf-8")

import ast
try:
    ast.parse(path.read_text(encoding="utf-8"))
    print("\nSyntax OK. Generate Nginx narratives with:")
    print("  python3 -m plugins.apache_httpd.build_narratives --db ccss.db --target nginx")
except SyntaxError as e:
    print(f"\nFAIL line {e.lineno}: {e.msg} — restoring original")
    path.write_text(original, encoding="utf-8")
