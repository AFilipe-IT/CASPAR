"""
plugins/nginx/parser.py
------------------------
Parser for Nginx configuration files.

Nginx syntax differs fundamentally from Apache:
  - Directives end with a semicolon:           `worker_processes 1;`
  - Blocks use braces and nest:                `http { server { ... } }`
  - Block directives (http, server, location, events, upstream, ...) create
    a context scope; the parser tracks the nesting as the directive context.
  - Comments start with `#`.
  - `include` directives pull in other files (glob patterns), resolved
    recursively relative to the including file's directory.

The parser returns a flat list of Directive objects. Each simple directive
(name + value, terminated by `;`) becomes one Directive. Block headers
(e.g. `server {`) are NOT emitted as directives themselves — they only set
the context for the directives inside them. The context string captures the
nesting, e.g. "http>server>location(/backup/)".

The parser performs NO security evaluation — that is the runtime engine's job
(worst-case principle: we record everything we see, including inside blocks).
"""

from __future__ import annotations

import glob
import os
import re
from collections import defaultdict, deque
from pathlib import Path

from config_assessment.core.models import Directive

# Block-directive names that open a context scope in Nginx.
_BLOCK_DIRECTIVES = {
    "events", "http", "server", "location", "upstream", "mail", "stream",
    "if", "limit_except", "map", "geo", "split_clients", "types",
}

_INCLUDE = re.compile(r"^include\s+(.+);$", re.IGNORECASE)


def _tokenize(raw: str) -> list[str]:
    """
    Tokenize Nginx config into a stream of meaningful tokens: '{', '}', ';',
    and directive words. Comments (# to end of line) are stripped. Quoted
    strings are kept intact as single tokens.
    """
    tokens: list[str] = []
    i = 0
    n = len(raw)
    current = ""

    def flush():
        nonlocal current
        if current.strip():
            tokens.append(current.strip())
        current = ""

    while i < n:
        ch = raw[i]
        if ch == "#":
            # Comment: skip to end of line
            flush()
            while i < n and raw[i] != "\n":
                i += 1
            continue
        if ch in ('"', "'"):
            # Quoted string: consume until matching quote
            flush()
            quote = ch
            j = i + 1
            buf = ""
            while j < n and raw[j] != quote:
                buf += raw[j]
                j += 1
            tokens.append(buf)
            i = j + 1
            continue
        if ch in "{};":
            flush()
            tokens.append(ch)
            i += 1
            continue
        if ch.isspace():
            flush()
            i += 1
            continue
        current += ch
        i += 1
    flush()
    return tokens


def _resolve_includes(pattern: str, base_dir: str) -> list[str]:
    if not os.path.isabs(pattern):
        pattern = os.path.join(base_dir, pattern)
    return sorted(glob.glob(pattern))


def parse_file(path: str, context: str = "", visited: set | None = None) -> list[Directive]:
    """
    Parse a single Nginx config file (recursively following `include`) and
    return a flat list of Directive objects with nesting context.
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
    try:
        raw = Path(abs_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    tokens = _tokenize(raw)
    directives: list[Directive] = []
    # Context stack: list of (block_name, optional_arg)
    ctx_stack: list[str] = []
    # We need approximate line numbers; recompute by mapping token positions.
    # Simpler robust approach: re-scan the file line by line for the line of
    # each simple directive. Since tokenization loses positions, we instead
    # track line numbers during a second, line-aware pass below.

    # Build current statement (list of word tokens) until ';' or '{' or '}'.
    statement: list[str] = []
    line_counter = _LineTracker(raw)

    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if tok == "{":
            # Statement so far is a block header: name [args...]
            if statement:
                block_name = statement[0].lower()
                block_arg = " ".join(statement[1:]).strip()
                label = block_name
                if block_arg:
                    label = f"{block_name}({block_arg})"
                ctx_stack.append(label)
            statement = []
            idx += 1
            continue
        if tok == "}":
            if ctx_stack:
                ctx_stack.pop()
            statement = []
            idx += 1
            continue
        if tok == ";":
            # Statement is a simple directive: name [value...]
            if statement:
                name = statement[0]
                value = " ".join(statement[1:]).strip()
                ctx = ">".join(ctx_stack) if ctx_stack else "global"
                # Handle include specially
                if name.lower() == "include" and value:
                    pattern = value.strip().strip('"').strip("'")
                    for inc in _resolve_includes(pattern, base_dir):
                        directives.extend(
                            parse_file(inc, context=ctx, visited=visited)
                        )
                else:
                    directives.append(Directive(
                        name=_canonical(name),
                        value=value,
                        context=ctx,
                        source_file=abs_path,
                        line_number=line_counter.line_of(name, value),
                    ))
            statement = []
            idx += 1
            continue
        # Regular word token
        statement.append(tok)
        idx += 1

    return directives


# ------------------------------------------------------------------ #
# Canonical directive-name normalisation                              #
# ------------------------------------------------------------------ #
# Nginx directive names are lowercase with underscores; we keep them as-is
# but normalise case so lookups are stable.
_CANONICAL: dict[str, str] = {
    "server_tokens": "server_tokens",
    "autoindex": "autoindex",
    "ssl_protocols": "ssl_protocols",
    "ssl_ciphers": "ssl_ciphers",
    "add_header": "add_header",
    "client_max_body_size": "client_max_body_size",
    "server_name_in_redirect": "server_name_in_redirect",
    "keepalive_timeout": "keepalive_timeout",
    "listen": "listen",
    "root": "root",
    "alias": "alias",
    "proxy_pass": "proxy_pass",
    "location": "location",
    "auth_basic": "auth_basic",
    "limit_req": "limit_req",
    "ssl_session_tickets": "ssl_session_tickets",
    "ssl_prefer_server_ciphers": "ssl_prefer_server_ciphers",
}


def _canonical(name: str) -> str:
    return _CANONICAL.get(name.lower(), name.lower())


class _LineTracker:
    """
    Best-effort line-number resolver. Tokenization discards positions, so we
    pre-index non-comment lines by the (lowercased) first word they contain,
    then hand back the earliest not-yet-claimed candidate line whose content
    also contains the value (if findable). This is approximate but good
    enough for report display; it never fails the parse.

    Indexed by first-word so lookups stay near O(1) per directive instead of
    rescanning the whole file each time (that rescan was O(directives x
    lines), i.e. quadratic in file size for configs with many directives).
    Each per-name bucket is consumed from the front (deque.popleft) as lines
    are matched, so a call never re-walks lines already claimed by earlier
    calls for the same name — keeping repeat directives (e.g. many
    `listen` lines) O(1) amortised instead of O(remaining candidates).
    """

    def __init__(self, raw: str) -> None:
        self._lines = raw.splitlines()
        self._by_word: dict[str, deque[int]] = defaultdict(deque)
        for i, line in enumerate(self._lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            first_word = stripped.split(None, 1)[0].rstrip("{};")
            self._by_word[first_word.lower()].append(i)

    def line_of(self, name: str, value: str) -> int:
        candidates = self._by_word.get(name.lower())
        if not candidates:
            return 0
        value_head = value.split()[0] if value else ""
        if not value_head:
            return candidates.popleft()
        # Scan from the front for a value match, holding aside any skipped
        # (non-matching) entries so they remain available for later calls.
        skipped: list[int] = []
        match = None
        while candidates:
            i = candidates.popleft()
            if value_head in self._lines[i - 1]:
                match = i
                break
            skipped.append(i)
        if match is not None:
            for i in reversed(skipped):
                candidates.appendleft(i)
            return match
        # No value match anywhere in the bucket: consume the first candidate
        # as a best-effort fallback, put the rest back.
        if not skipped:
            return 0
        fallback, rest = skipped[0], skipped[1:]
        for i in reversed(rest):
            candidates.appendleft(i)
        return fallback
