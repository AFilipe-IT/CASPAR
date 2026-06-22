"""
plugins/ssh/parser.py
----------------------
Parser for OpenSSH server configuration (sshd_config).

SSH syntax is the simplest of the three targets:
  - One directive per line:                 `PermitRootLogin no`
  - Keyword and value separated by whitespace (one or more spaces/tabs);
    the keyword is case-insensitive, the value preserves its case.
  - Comments start with `#`; blank lines are ignored.
  - `Include /etc/ssh/sshd_config.d/*.conf` pulls in fragment files (glob),
    resolved recursively relative to the including file's directory. This is
    how modern Ubuntu/Debian ships sshd_config.

LIMITATION — Match blocks are NOT evaluated. A `Match <criteria>` line opens a
conditional scope; directives inside it apply only when the criteria match at
connection time. We record the Match context on those directives (so they are
visible) but the runtime evaluates only global-scope directives. Modelling the
full conditional semantics is out of scope; only the global configuration is
analysed.

The parser performs NO security evaluation — that is the runtime engine's job.
It returns a flat list of Directive objects (worst-case principle: record
everything seen at global scope).
"""

from __future__ import annotations

import glob
import os
import re
from pathlib import Path

from config_assessment.core.models import Directive

_INCLUDE = re.compile(r"^include\s+(.+)$", re.IGNORECASE)
_MATCH = re.compile(r"^match\s+(.+)$", re.IGNORECASE)

# Canonical spelling of every keyword we care about (lowercase → canonical).
# sshd treats keywords case-insensitively; we normalise so the runtime lookup
# and the DB agree on one spelling. Unknown keywords keep their original case.
_CANONICAL = {
    k.lower(): k for k in (
        "Include", "Match", "ListenAddress", "Port", "Banner",
        "PermitRootLogin", "PasswordAuthentication", "PermitEmptyPasswords",
        "PubkeyAuthentication", "HostbasedAuthentication", "GSSAPIAuthentication",
        "Ciphers", "MACs", "KexAlgorithms", "IgnoreRhosts", "UsePAM",
        "PermitUserEnvironment", "LogLevel", "MaxAuthTries", "MaxStartups",
        "MaxSessions", "LoginGraceTime", "ClientAliveInterval",
        "ClientAliveCountMax", "DisableForwarding", "AllowTcpForwarding",
        "X11Forwarding", "AllowUsers", "AllowGroups", "DenyUsers", "DenyGroups",
    )
}


def _canonical(keyword: str) -> str:
    return _CANONICAL.get(keyword.lower(), keyword)


def _resolve_includes(pattern: str, base_dir: str) -> list[str]:
    if not os.path.isabs(pattern):
        pattern = os.path.join(base_dir, pattern)
    return sorted(glob.glob(pattern))


def parse_file(path: str, visited: set | None = None) -> list[Directive]:
    """
    Parse a single sshd_config file (recursively following `Include`) and return
    a flat list of Directive objects. Directives inside Match blocks carry a
    "Match(<criteria>)" context and are excluded from runtime evaluation.
    """
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
    # Once a Match block opens, every following line stays in Match scope until
    # EOF (sshd has no explicit close; a new Match replaces the criteria).
    match_context = "global"

    with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            m_inc = _INCLUDE.match(line)
            if m_inc and match_context == "global":
                for inc in _resolve_includes(m_inc.group(1).strip(), base_dir):
                    directives.extend(parse_file(inc, visited))
                continue

            m_match = _MATCH.match(line)
            if m_match:
                match_context = f"Match({m_match.group(1).strip()})"
                continue

            # Keyword value — split on the first run of whitespace.
            parts = line.split(None, 1)
            keyword = _canonical(parts[0])
            value = parts[1].strip() if len(parts) > 1 else ""
            directives.append(Directive(
                name=keyword,
                value=value,
                context=match_context,
                source_file=abs_path,
                line_number=lineno,
            ))

    return directives
