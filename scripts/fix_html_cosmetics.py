"""
fix_html_cosmetics.py
-----------------------
Dois fixes cosméticos no relatório HTML:
  1. Remove tags <code> literais que o LLM por vezes inclui no campo 'example'
     (o example-box já tem estilo monospace, não precisa de <code> dentro)
  2. Adiciona quebra de linha entre location tags (estavam coladas)

Corre uma vez:
    python3 fix_html_cosmetics.py
"""

from pathlib import Path
import re

path = Path("core/report_html.py")
content = path.read_text(encoding="utf-8")

# ── Fix 1: strip <code> tags from LLM-generated example text ───────
if "_strip_code_tags" not in content:
    # Add helper function after _nl2br
    old = 'def _nl2br(t):\n    return _e(t).replace("\\n","<br>")'
    new = (
        'def _nl2br(t):\n'
        '    return _e(t).replace("\\n","<br>")\n\n'
        'def _strip_code_tags(t):\n'
        '    """Remove literal <code>/<pre> tags the LLM sometimes includes — '
        'the example-box already renders monospace."""\n'
        '    t = re.sub(r"</?code>", "", str(t))\n'
        '    t = re.sub(r"</?pre>", "", t)\n'
        '    return t.strip()'
    )
    if old in content:
        content = content.replace(old, new, 1)
        # Add import re at top if missing
        if "import re" not in content.split("\n\n")[0] and "\nimport re\n" not in content:
            content = content.replace(
                "from __future__ import annotations\nimport json as _json",
                "from __future__ import annotations\nimport json as _json\nimport re",
                1,
            )
        print("✓ Added _strip_code_tags helper")
    else:
        print("⚠ Could not find insertion point for _strip_code_tags")

# Apply _strip_code_tags before _nl2br on the example field
old_example = 'ex_s = f\'<div class="block-title" style="margin-bottom:6px;margin-top:10px">Example</div><div class="example-box">{_nl2br(example)}</div>\' if example else ""'
new_example = 'ex_s = f\'<div class="block-title" style="margin-bottom:6px;margin-top:10px">Example</div><div class="example-box">{_nl2br(_strip_code_tags(example))}</div>\' if example else ""'
if old_example in content:
    content = content.replace(old_example, new_example, 1)
    print("✓ Applied _strip_code_tags to example rendering")
else:
    print("⚠ Could not find example rendering line — check manually")

# ── Fix 2: separate location tags with line breaks ──────────────────
old_locs = 'locs_html = "".join(f\'<span class="loc-tag">{_e(c)}</span>\' for c in contexts) if contexts else ""'
new_locs = 'locs_html = "<br>".join(f\'<span class="loc-tag">{_e(c)}</span>\' for c in contexts) if contexts else ""'
if old_locs in content:
    content = content.replace(old_locs, new_locs, 1)
    print("✓ Added line breaks between location tags")
else:
    print("⚠ Could not find locs_html line — check manually")

path.write_text(content, encoding="utf-8")

import ast
try:
    ast.parse(content)
    print("\nSyntax OK. Re-run the scan to see the fixes:")
    print("  ccss scan docker://ccss-test-apache:vulnerable --report --output ~/relatorios/")
except SyntaxError as e:
    print(f"\nFAIL: {e}")
