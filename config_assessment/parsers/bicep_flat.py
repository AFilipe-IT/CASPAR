"""
config_assessment/parsers/bicep_flat.py
---------------------------------------
Bicep parser — stdlib only, hand-rolled subset.

Flattens .bicep files into flat Directives (ARM property vocabulary):

  resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
    name: 'mystore'
    properties: {
      supportsHttpsTrafficOnly: false            ← the finding
      minimumTlsVersion: 'TLS1_0'
    }
  }

  → Directive(name="supportsHttpsTrafficOnly", value="false",
              context="Microsoft.Storage/storageAccounts.sa.properties")

Supported subset: resource/param/var/output declarations, nested object
literals `{ key: value }` (flattened), arrays (one directive per scalar
element), // and /* */ comments, single-quoted strings. Expressions are kept
as raw text. No evaluation, no security judgement — flat Directives out.
"""

from __future__ import annotations

import re
from pathlib import Path

from config_assessment.core.models import Directive

_RESOURCE_RE = re.compile(
    r"^\s*resource\s+(\w+)\s+'([^'@]+)(?:@[^']*)?'\s*=?\s*(\{)?\s*$|"
    r"^\s*resource\s+(\w+)\s+'([^'@]+)(?:@[^']*)?'\s*=\s*\{\s*$")
_PARAM_RE = re.compile(r"^\s*(param|var|output)\s+(\w+)\s+\w+\s*=\s*(.+)$")
_KEY_RE = re.compile(r"^\s*(\w+)\s*:\s*(.*)$")


def _strip_comments(text: str) -> list[str]:
    out, in_block = [], False
    for raw in text.splitlines():
        line, res, j = raw, [], 0
        while j < len(line):
            if in_block:
                end = line.find("*/", j)
                if end == -1:
                    j = len(line)
                else:
                    in_block, j = False, end + 2
                continue
            if line[j:j + 2] == "/*":
                in_block = True
                j += 2
                continue
            if line[j:j + 2] == "//":
                break
            if line[j] == "'":                    # don't kill // inside strings
                end = line.find("'", j + 1)
                end = len(line) - 1 if end == -1 else end
                res.append(line[j:end + 1])
                j = end + 1
                continue
            res.append(line[j])
            j += 1
        out.append("".join(res))
    return out


def _unquote(v: str) -> str:
    v = v.strip().rstrip(",")
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    return v


def parse_file(path: str) -> list[Directive]:
    lines = _strip_comments(
        Path(path).read_text(encoding="utf-8", errors="replace"))

    out: list[Directive] = []
    stack: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        lineno = i + 1
        s = line.strip()
        if not s:
            i += 1
            continue

        m = _RESOURCE_RE.match(line)
        if m:
            sym = m.group(1) or m.group(4)
            rtype = m.group(2) or m.group(5)
            stack.append(f"{rtype}.{sym}")
            if "{" not in line:                   # `= {` on the next line
                while i + 1 < len(lines) and "{" not in lines[i + 1]:
                    i += 1
                i += 1
            i += 1
            continue

        m = _PARAM_RE.match(line)
        if m:
            out.append(Directive(
                name=m.group(2), value=_unquote(m.group(3)),
                context=m.group(1), source_file=path, line_number=lineno))
            i += 1
            continue

        if s in ("}", "}]", "},"):
            if stack:
                stack.pop()
            i += 1
            continue

        m = _KEY_RE.match(line)
        if m:
            key, rhs = m.group(1), m.group(2).strip()
            if rhs in ("{", "["):                 # nested object/array opens
                stack.append(key)
            elif rhs.startswith("[") and rhs.endswith("]"):
                inner = rhs[1:-1]
                for item in inner.split(","):
                    if item.strip():
                        out.append(Directive(
                            name=key, value=_unquote(item),
                            context=".".join(stack) or "global",
                            source_file=path, line_number=lineno))
            elif rhs and rhs != "{":
                out.append(Directive(
                    name=key, value=_unquote(rhs),
                    context=".".join(stack) or "global",
                    source_file=path, line_number=lineno))
            i += 1
            continue

        i += 1
    return out
