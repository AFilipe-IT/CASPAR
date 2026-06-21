"""
core/parsers/key_value.py
--------------------------
Generic parser for "key = value" / "key value" configuration files.

This is the canonical key-value parser, reusable by any plugin whose config is a
flat list of `key value` or `key = value` lines (PostgreSQL, Redis, many daemons).
The SSH parser predates this module and can be refactored to delegate here later;
this is the single source of truth for the format.

Supported:
  - `key value` and `key = value` (the `=` is optional, with or without spaces)
  - comments with `#` (to end of line; blank lines ignored)
  - quoted values: `key = "value with spaces"` / `key = 'v'`  → quotes stripped
  - include directives: `include /path/*.conf` (glob, resolved recursively)
  - case-insensitive keys, normalised to lowercase (the canonical form)

The parser performs NO security evaluation — that is the runtime engine's job.
It returns a flat list of Directive objects.
"""

from __future__ import annotations

import glob
import os
import re
from pathlib import Path

from core.models import Directive

_INCLUDE = re.compile(r"^include(?:_dir)?\s+(.+)$", re.IGNORECASE)
# key, optional '=' (with optional surrounding spaces) or whitespace, then value.
_KV = re.compile(r"^(\S+?)\s*=\s*(.*)$|^(\S+)\s+(.*)$")


def _strip_inline_comment(value: str) -> str:
    """Drop an unquoted trailing `# comment` from a value."""
    in_quote = ""
    for i, ch in enumerate(value):
        if ch in ('"', "'"):
            if not in_quote:
                in_quote = ch
            elif in_quote == ch:
                in_quote = ""
        elif ch == "#" and not in_quote:
            return value[:i].rstrip()
    return value


def _unquote(value: str) -> str:
    # Strip surrounding whitespace only to locate the quotes; content inside the
    # quotes (including trailing spaces) is preserved verbatim.
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
        return v[1:-1]
    return v


def _resolve_includes(pattern: str, base_dir: str) -> list[str]:
    if not os.path.isabs(pattern):
        pattern = os.path.join(base_dir, pattern)
    return sorted(glob.glob(pattern))


def parse_file(path: str, context: str = "global",
               visited: set | None = None) -> list[Directive]:
    """Parse a key-value config file (recursively following `include`)."""
    if visited is None:
        visited = set()
    abs_path = str(Path(path).resolve())
    if abs_path in visited:
        return []
    visited.add(abs_path)
    if not os.path.isfile(abs_path):
        return []

    base_dir = str(Path(abs_path).parent)
    directives: list[Directive] = []

    with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            m_inc = _INCLUDE.match(line)
            if m_inc:
                for inc in _resolve_includes(m_inc.group(1).strip().strip("'\""), base_dir):
                    directives.extend(parse_file(inc, context, visited))
                continue

            m = _KV.match(line)
            if not m:
                continue
            # Either the '=' branch (groups 1,2) or the whitespace branch (3,4).
            key = m.group(1) if m.group(1) is not None else m.group(3)
            val = m.group(2) if m.group(1) is not None else m.group(4)
            value = _unquote(_strip_inline_comment(val))

            directives.append(Directive(
                name=key.lower(),          # canonical: lowercase
                value=value,
                context=context,
                source_file=abs_path,
                line_number=lineno,
            ))

    return directives
