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

Match blocks ARE evaluated, under the worst-case principle, not by simulating
a live connection. A `Match <criteria>` line opens a conditional scope;
directives inside it apply only when the criteria match at connection time.
Rather than modelling live connection state (which would require an active
probe against a real session — out of scope for a static, offline analyser),
we ask a narrower and fully static question: could an unauthenticated remote
attacker ever satisfy this Match's criteria? `User`/`Group`/`Address` criteria
are attacker-controlled or attacker-reachable by construction (an attacker
picks which username to attempt, and can originate from any address unless
the criteria demonstrably restrict to a non-public range) — so a directive
inside such a block is folded into the flat directive list exactly like a
global one, worst case. Criteria that are NOT attacker-controlled (e.g.
`Match Address 10.0.0.0/8` restricting to a private range) mark the block as
inapplicable to a generic remote attacker, and its directives are kept for
visibility (context recorded) but excluded from evaluation. See
`_match_applies_worst_case` for the exact rule.

The parser performs NO CCSS scoring — that is the runtime engine's job. It
returns a flat list of Directive objects (worst-case principle: record
everything an attacker could plausibly trigger).
"""

from __future__ import annotations

import glob
import os
import re
from pathlib import Path

from config_assessment.core.models import Directive

_INCLUDE = re.compile(r"^include\s+(.+)$", re.IGNORECASE)
_MATCH = re.compile(r"^match\s+(.+)$", re.IGNORECASE)

# Private/loopback ranges a Match Address criterion can restrict to. If every
# address token in a `Match Address ...` criterion falls in one of these, a
# generic remote (public) attacker cannot satisfy it, so the block is not
# worst-case-applicable. Any other address (including wildcards like "*") is
# treated as attacker-reachable.
_PRIVATE_ADDRESS_PREFIXES = (
    "10.", "127.", "169.254.", "192.168.", "::1", "fc", "fd", "localhost",
)
_PRIVATE_172_RANGE = range(16, 32)  # 172.16.0.0/12


def _address_token_is_private(token: str) -> bool:
    tok = token.strip().lstrip("!").strip("[]").lower()
    if tok.startswith("172."):
        parts = tok.split(".")
        if len(parts) > 1 and parts[1].isdigit():
            return int(parts[1]) in _PRIVATE_172_RANGE
        return False
    return any(tok == pfx or tok.startswith(pfx) for pfx in _PRIVATE_ADDRESS_PREFIXES)


def _match_applies_worst_case(criteria: str) -> bool:
    """
    Decide whether a `Match <criteria>` block could be satisfied by a generic,
    unauthenticated remote attacker — i.e. whether its directives should be
    folded into the flat (worst-case) directive list.

    `Match <criteria>` is a sequence of `<Keyword> <value>` pairs (User, Group,
    Host, Address, LocalAddress, LocalPort, RDomain). We only special-case
    `Address`/`LocalAddress`, the one criterion that can genuinely be
    attacker-*inapplicable* (restricted to a private range): every other
    criterion (User, Group, Host/RDomain) is either attacker-chosen (an
    attacker picks which username or group membership to attempt) or
    unverifiable statically (reverse-DNS Host), so worst case treats it as
    satisfiable. If an Address/LocalAddress criterion is present and EVERY
    token in it is private/loopback, the block cannot be reached by a generic
    remote attacker and is excluded from worst-case evaluation.
    """
    tokens = criteria.split()
    i = 0
    while i < len(tokens) - 1:
        keyword = tokens[i].lower()
        if keyword in ("address", "localaddress"):
            value = tokens[i + 1]
            addr_tokens = value.split(",")
            if addr_tokens and all(_address_token_is_private(t) for t in addr_tokens):
                return False
            i += 2
        else:
            i += 2
    return True

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
    a flat list of Directive objects. Directives inside a Match block whose
    criteria a generic remote attacker could satisfy (see
    `_match_applies_worst_case`) are folded in with `context="global"`, same as
    top-level directives, so the runtime scans them like any other. Directives
    inside a block restricted to a private/loopback range keep their
    "Match(<criteria>)" context for visibility but are not worst-case-applicable.
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
    match_applies = True

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
                criteria = m_match.group(1).strip()
                match_context = f"Match({criteria})"
                match_applies = _match_applies_worst_case(criteria)
                continue

            # Keyword value — split on the first run of whitespace.
            parts = line.split(None, 1)
            keyword = _canonical(parts[0])
            value = parts[1].strip() if len(parts) > 1 else ""
            directives.append(Directive(
                name=keyword,
                value=value,
                context="global" if match_applies else match_context,
                source_file=abs_path,
                line_number=lineno,
            ))

    return directives
