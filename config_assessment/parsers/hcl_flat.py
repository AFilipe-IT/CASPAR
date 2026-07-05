"""
config_assessment/parsers/hcl_flat.py
-------------------------------------
Terraform / HCL parser — stdlib only, hand-rolled subset.

Flattens .tf files into the framework's flat Directive model:

  resource "azurerm_storage_account" "sa" {
    https_traffic_only_enabled = false          ← the finding
    blob_properties {
      delete_retention_policy { days = 7 }
    }
  }

  → Directive(name="https_traffic_only_enabled", value="false",
              context="azurerm_storage_account.sa")
  → Directive(name="days", value="7",
              context="azurerm_storage_account.sa.blob_properties.delete_retention_policy")

Supported subset (covers the shape of real-world azurerm configs):
  - blocks:      type "label" "label" { … }   (resource/provider/variable/…)
  - nested blocks and `attr = { … }` object values (both flattened)
  - assignments: attr = <scalar | "string" | [list] | expression>
    · scalars/strings → raw value, quotes stripped
    · [list of scalars] → ONE directive per element (token rules fire per item)
    · expressions (var.x, azurerm_….id, function calls) → raw text, so the
      unknown-directive layers still see the attribute
  - comments: #, //, /* … */ ; heredocs (<<EOF) captured as raw text

Not a full HCL2 grammar (no interpolation evaluation — deliberately: raw text
in, deterministic match against rules, no semantics). Like every parser here:
no security evaluation.
"""

from __future__ import annotations

import re
from pathlib import Path

from config_assessment.core.models import Directive

_BLOCK_RE = re.compile(
    r'^\s*([A-Za-z_][\w-]*)((?:\s+"[^"]*")*)\s*\{\s*$')
_ASSIGN_RE = re.compile(r'^\s*([A-Za-z_][\w-]*)\s*=\s*(.*)$')
_BARE_BLOCK_RE = re.compile(r'^\s*([A-Za-z_][\w-]*)\s*\{\s*$')
_HEREDOC_RE = re.compile(r'<<-?\s*([A-Za-z_]\w*)\s*$')


def _strip_comments(text: str) -> list[str]:
    """Remove /* */ and line comments, preserving line count (for numbers)."""
    out, i, n = [], 0, len(text)
    in_block = False
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
            ch2 = line[j:j + 2]
            if ch2 == "/*":
                in_block = True
                j += 2
                continue
            if ch2 == "//" or line[j] == "#":
                break
            if line[j] == '"':                       # don't kill # inside strings
                end = j + 1
                while end < len(line):
                    if line[end] == '"' and line[end - 1] != "\\":
                        break
                    end += 1
                res.append(line[j:end + 1])
                j = end + 1
                continue
            res.append(line[j])
            j += 1
        out.append("".join(res))
    return out


def _unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def _emit(out, name, value, path, src, lineno):
    out.append(Directive(
        name=name, value=_unquote(str(value)),
        context=".".join(path) or "global",
        source_file=src, line_number=lineno))


def _split_list(body: str) -> list[str]:
    """Split a [ … ] body on top-level commas."""
    items, depth, cur = [], 0, ""
    for ch in body:
        if ch in "[{(":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        if ch == "," and depth == 0:
            items.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        items.append(cur)
    return [i.strip() for i in items if i.strip()]


def parse_file(path: str) -> list[Directive]:
    lines = _strip_comments(
        Path(path).read_text(encoding="utf-8", errors="replace"))

    out: list[Directive] = []
    stack: list[str] = []      # context path
    i = 0
    while i < len(lines):
        line = lines[i]
        lineno = i + 1
        s = line.strip()
        if not s:
            i += 1
            continue

        if s == "}" or s == "},":
            if stack:
                stack.pop()
            i += 1
            continue

        m = _BLOCK_RE.match(line)
        if m:
            # `resource "azurerm_x" "name" {` → context azurerm_x.name
            # `provider "azurerm" {`          → context provider.azurerm
            kind = m.group(1)
            labels = re.findall(r'"([^"]*)"', m.group(2))
            if kind == "resource" and len(labels) >= 2:
                stack.append(f"{labels[0]}.{labels[1]}")
            elif labels:
                stack.append(".".join([kind] + labels))
            else:
                stack.append(kind)
            i += 1
            continue

        m = _BARE_BLOCK_RE.match(line)
        if m:                                     # nested block: blob_properties {
            stack.append(m.group(1))
            i += 1
            continue

        m = _ASSIGN_RE.match(line)
        if m:
            name, rhs = m.group(1), m.group(2).strip()

            hd = _HEREDOC_RE.search(rhs)
            if hd:                                # heredoc: capture until marker
                marker, body = hd.group(1), []
                i += 1
                while i < len(lines) and lines[i].strip() != marker:
                    body.append(lines[i])
                    i += 1
                _emit(out, name, "\n".join(body).strip(), stack, path, lineno)
                i += 1
                continue

            # Balance braces/brackets across lines (obj/list spanning lines).
            def _balance(txt): return (txt.count("{") - txt.count("}")
                                       + txt.count("[") - txt.count("]"))
            while _balance(rhs) > 0 and i + 1 < len(lines):
                i += 1
                rhs += "\n" + lines[i]

            r = rhs.strip().rstrip(",")
            if r.startswith("{"):                 # attr = { k = v, … } → flatten
                inner = r[1:r.rfind("}")] if "}" in r else r[1:]
                stack.append(name)
                for part in re.split(r"[,\n]", inner):
                    pm = _ASSIGN_RE.match(part)
                    if pm:
                        _emit(out, pm.group(1), pm.group(2).strip().rstrip(","),
                              stack, path, lineno)
                    else:
                        cm = re.match(r'\s*"?([\w-]+)"?\s*:\s*(.+)$', part)
                        if cm:                    # map syntax  "k" : v
                            _emit(out, cm.group(1), cm.group(2).strip().rstrip(","),
                                  stack, path, lineno)
                stack.pop()
            elif r.startswith("["):               # list → one directive per item
                inner = r[1:r.rfind("]")] if "]" in r else r[1:]
                items = _split_list(inner)
                if items:
                    for item in items:
                        _emit(out, name, item, stack, path, lineno)
                else:
                    _emit(out, name, "", stack, path, lineno)
            else:
                _emit(out, name, r, stack, path, lineno)
            i += 1
            continue

        i += 1
    return out
