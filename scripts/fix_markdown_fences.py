"""
fix_markdown_fences.py
------------------------
Remove markdown code fences (```) que o LLM por vezes usa em vez de <code>
no campo 'example' das narrativas. O example-box já é monospace via CSS.

Corre uma vez:
    python3 fix_markdown_fences.py
"""

from pathlib import Path

path = Path("core/report_html.py")
content = path.read_text(encoding="utf-8")

old = '''def _strip_code_tags(t):
    """Remove literal <code>/<pre> tags the LLM sometimes includes — the example-box already renders monospace."""
    t = re.sub(r"</?code>", "", str(t))
    t = re.sub(r"</?pre>", "", t)
    return t.strip()'''

new = '''def _strip_code_tags(t):
    """Remove literal <code>/<pre> tags and markdown code fences the LLM
    sometimes includes — the example-box already renders monospace."""
    t = str(t)
    t = re.sub(r"</?code>", "", t)
    t = re.sub(r"</?pre>", "", t)
    # Markdown fences: ```bash\\n...\\n``` or ```\\n...\\n```
    t = re.sub(r"^```[a-zA-Z]*\\n?", "", t, flags=re.MULTILINE)
    t = re.sub(r"\\n?```$", "", t, flags=re.MULTILINE)
    t = re.sub(r"```", "", t)  # any remaining stray fences
    return t.strip()'''

if old in content:
    content = content.replace(old, new, 1)
    path.write_text(content, encoding="utf-8")
    print("✓ Updated _strip_code_tags to also remove markdown fences")
else:
    print("⚠ Could not find _strip_code_tags — checking if already patched or named differently")
    if "```" in content and "_strip_code_tags" in content:
        print("  _strip_code_tags exists but pattern differs — manual check needed")
    else:
        print("  _strip_code_tags not found at all — run fix_html_cosmetics.py first")

import ast
try:
    ast.parse(open("core/report_html.py").read())
    print("\\nSyntax OK. Re-run the scan to see the fix:")
    print("  ccss scan docker://ccss-test-apache:vulnerable --report --output ~/relatorios/")
except SyntaxError as e:
    print(f"\\nFAIL: {e}")
