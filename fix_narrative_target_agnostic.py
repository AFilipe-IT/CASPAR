"""
fix_narrative_target_agnostic.py
----------------------------------
Torna o Stage 3 (narrative_pipeline.py) target-agnostic.

PROBLEMA: o _SYSTEM_PROMPT e _build_prompt têm "Apache HTTP Server" e "httpd.conf"
hardcoded. Ao gerar narrativas para Nginx, sai terminologia Apache errada.

CORREÇÃO: introduz um service_name configurável (default "Apache HTTP Server",
para o Apache continuar idêntico). O _SYSTEM_PROMPT passa a função, _build_prompt
recebe service_name, e o fallback do exemplo usa o nome do serviço.
O NarrativePipeline aceita service_name no construtor e propaga-o.

Uso:
    python3 fix_narrative_target_agnostic.py
"""

from __future__ import annotations
import sys
from pathlib import Path

path = Path("plugins/apache_httpd/narrative_pipeline.py")
if not path.exists():
    print("ERROR: narrative_pipeline.py not found. Run from ~/ccss_scan.")
    sys.exit(1)

content = path.read_text(encoding="utf-8")
original = content
changes = 0

if "service_name" in content:
    print("\u2713 Already target-agnostic — skipping")
    sys.exit(0)

# ── 1. Convert _SYSTEM_PROMPT from a constant string to a function ──
old_sysprompt = '''_SYSTEM_PROMPT = """\\
You are a senior Apache HTTP Server security expert writing a detailed security report.

For each Apache misconfiguration you receive, write a structured technical narrative
that will be shown to a security engineer in a professional audit report.'''

new_sysprompt = '''def _system_prompt(service_name: str = "Apache HTTP Server") -> str:
    return f"""\\
You are a senior {service_name} security expert writing a detailed security report.

For each {service_name} misconfiguration you receive, write a structured technical narrative
that will be shown to a security engineer in a professional audit report.'''

if old_sysprompt in content:
    content = content.replace(old_sysprompt, new_sysprompt, 1)
    changes += 1
    print("\u2713 1: _SYSTEM_PROMPT -> _system_prompt(service_name) function header")
else:
    print("\u26a0 1: could not find _SYSTEM_PROMPT header")

# The _SYSTEM_PROMPT string ends with a closing """ — we need it to stay a
# function body. The body after the header is plain text ending in '"""'.
# Since we changed the header to start a function returning an f-string, the
# trailing """ now closes the f-string inside the function. That works as long
# as the body has no stray braces. The consistency-rule text uses single words,
# but it DOES contain examples with no braces — safe. However f-strings treat
# { and } specially. Check: the body contains "AC=L" etc, no literal braces.
# It's safe. But we must ensure the closing of the function. The original ended:
#   Output ONLY valid JSON. No markdown, no preamble.
#   """
# After our change it becomes the f-string return value, properly closed by """.

# ── 2. _build_prompt signature + the two "Apache" mentions ──
old_buildsig = "def _build_prompt(m: Misconfiguration) -> str:"
new_buildsig = 'def _build_prompt(m: Misconfiguration, service_name: str = "Apache HTTP Server") -> str:'
if old_buildsig in content:
    content = content.replace(old_buildsig, new_buildsig, 1)
    changes += 1
    print("\u2713 2a: _build_prompt signature accepts service_name")

old_genline = 'return f"""Generate a detailed security narrative for this Apache misconfiguration:'
new_genline = 'return f"""Generate a detailed security narrative for this {service_name} misconfiguration:'
if old_genline in content:
    content = content.replace(old_genline, new_genline, 1)
    changes += 1
    print("\u2713 2b: _build_prompt body uses {service_name}")

# ── 3. Fallback example: "# Set in httpd.conf" -> generic ──
old_fallback = 'or f"# Set in httpd.conf\\n{m.directive} {m.bad_value}"'
new_fallback = 'or f"# Configuration\\n{m.directive} {m.bad_value}"'
if old_fallback in content:
    content = content.replace(old_fallback, new_fallback, 1)
    changes += 1
    print("\u2713 3: fallback example no longer says httpd.conf")

# ── 4. NarrativePipeline.__init__ accepts service_name ──
old_init = '''    def __init__(self, llm: LLMClient, max_retries: int = 2) -> None:
        self.llm = llm
        self.max_retries = max_retries'''
new_init = '''    def __init__(self, llm: LLMClient, max_retries: int = 2,
                 service_name: str = "Apache HTTP Server") -> None:
        self.llm = llm
        self.max_retries = max_retries
        self.service_name = service_name'''
if old_init in content:
    content = content.replace(old_init, new_init, 1)
    changes += 1
    print("\u2713 4: NarrativePipeline.__init__ accepts service_name")

# ── 5. generate_narrative uses service_name for prompt + system ──
old_gen = '''        prompt = _build_prompt(m)

        for attempt in range(self.max_retries):
            try:
                if hasattr(self.llm, "timeout"):
                    self.llm.timeout = 300
                raw_text = self.llm.complete(prompt, system=_SYSTEM_PROMPT)'''
new_gen = '''        prompt = _build_prompt(m, self.service_name)

        for attempt in range(self.max_retries):
            try:
                if hasattr(self.llm, "timeout"):
                    self.llm.timeout = 300
                raw_text = self.llm.complete(prompt, system=_system_prompt(self.service_name))'''
if old_gen in content:
    content = content.replace(old_gen, new_gen, 1)
    changes += 1
    print("\u2713 5: generate_narrative threads service_name into prompt + system")

path.write_text(content, encoding="utf-8")

import ast
try:
    ast.parse(path.read_text(encoding="utf-8"))
    print(f"\n{changes} changes applied. Syntax OK.")
except SyntaxError as e:
    print(f"\nFAIL line {e.lineno}: {e.msg} — restoring original")
    path.write_text(original, encoding="utf-8")
    sys.exit(1)
