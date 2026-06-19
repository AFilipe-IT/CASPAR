"""
plugins/apache_httpd/parser.py
-------------------------------
Parser for Apache HTTP Server 2.4 configuration files.

Handles:
  - httpd.conf (main config)
  - Include / IncludeOptional directives (recursive resolution)
  - <VirtualHost>, <Directory>, <Location>, <Files> block contexts
  - Continuation lines (trailing backslash)
  - Comments (# prefix)
  - Case-insensitive directive names (normalised to canonical form)

Returns a flat list of Directive objects with context and source info.
The parser does NOT evaluate conditionals (<IfModule>, <IfDefine>) —
it includes all directives found in any branch, which is the correct
approach for a security scanner (worst-case principle).
"""

from __future__ import annotations

import glob
import os
import re
from pathlib import Path

from core.models import Directive

# ------------------------------------------------------------------ #
# Canonical name normalisation                                         #
# ------------------------------------------------------------------ #

# Map lowercase directive name → canonical (CIS/CCE) form
_CANONICAL: dict[str, str] = {
    "servertokens": "ServerTokens",
    "serversignature": "ServerSignature",
    "timeout": "Timeout",
    "keepalive": "KeepAlive",
    "keepalivetimeout": "KeepAliveTimeout",
    "maxkeepaliverequests": "MaxKeepAliveRequests",
    "traceenable": "TraceEnable",
    "serveradmin": "ServerAdmin",
    "servername": "ServerName",
    "listen": "Listen",
    "user": "User",
    "group": "Group",
    "loglevel": "LogLevel",
    "errorlog": "ErrorLog",
    "customlog": "CustomLog",
    "logformat": "LogFormat",
    "options": "Options",
    "allowoverride": "AllowOverride",
    "order": "Order",
    "allow": "Allow",
    "deny": "Deny",
    "require": "Require",
    "loadmodule": "LoadModule",
    "limitrequestline": "LimitRequestLine",
    "limitrequestfields": "LimitRequestFields",
    "limitrequestfieldsize": "LimitRequestFieldSize",
    "limitrequestbody": "LimitRequestBody",
    "sslprotocol": "SSLProtocol",
    "sslciphersuite": "SSLCipherSuite",
    "sslhonorcipherorder": "SSLHonorCipherOrder",
    "sslcompression": "SSLCompression",
    "sslsessiontickets": "SSLSessionTickets",
    "sslstapling": "SSLStapling",
    "header": "Header",
    "requestheader": "RequestHeader",
    "etag": "FileETag",
    "fileetag": "FileETag",
    "directoryindex": "DirectoryIndex",
    "userdir": "UserDir",
    "indexoptions": "IndexOptions",
    "extendedstatus": "ExtendedStatus",
    "serverroot": "ServerRoot",
    "documentroot": "DocumentRoot",
    "scriptalias": "ScriptAlias",
    "alias": "Alias",
    "coredumpdirectory": "CoreDumpDirectory",
    "pidfile": "PidFile",
    "lockfile": "LockFile",
    "scoreboardfile": "ScoreboardFile",
    "htaccess": "HTAccess",
    "requestreadtimeout": "RequestReadTimeout",
}

# Block directives that create a context scope
_BLOCK_OPEN = re.compile(
    r"^<(VirtualHost|Directory|DirectoryMatch|Location|LocationMatch|Files|FilesMatch|IfModule|IfDefine|Proxy|ProxyMatch)\s*(.*?)>$",
    re.IGNORECASE,
)
_BLOCK_CLOSE = re.compile(r"^</(VirtualHost|Directory|DirectoryMatch|Location|LocationMatch|Files|FilesMatch|IfModule|IfDefine|Proxy|ProxyMatch)>$", re.IGNORECASE)

# Include directives
_INCLUDE = re.compile(r"^(Include|IncludeOptional)\s+(.+)$", re.IGNORECASE)


def _canonical(name: str) -> str:
    return _CANONICAL.get(name.lower(), name)


def _resolve_includes(pattern: str, base_dir: str) -> list[str]:
    """Resolve an Include glob pattern relative to base_dir."""
    if not os.path.isabs(pattern):
        pattern = os.path.join(base_dir, pattern)
    return sorted(glob.glob(pattern))


def parse_file(path: str, context: str = "global", visited: set | None = None) -> list[Directive]:
    """
    Parse a single Apache config file and return a flat list of Directive objects.

    Recursively follows Include / IncludeOptional directives.
    The *visited* set prevents infinite loops from circular includes.
    """
    if visited is None:
        visited = set()

    abs_path = str(Path(path).resolve())
    if abs_path in visited:
        return []
    visited.add(abs_path)

    if not os.path.isfile(abs_path):
        return []

    directives: list[Directive] = []
    base_dir = str(Path(abs_path).parent)
    current_context = context

    try:
        raw = Path(abs_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    # Join continuation lines
    raw = re.sub(r"\\\n\s*", " ", raw)

    lines = raw.splitlines()
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            continue

        # Check for block open
        m_open = _BLOCK_OPEN.match(stripped)
        if m_open:
            block_type = m_open.group(1)
            block_arg = m_open.group(2).strip()
            current_context = f"{block_type}({block_arg})" if block_arg else block_type
            continue

        # Check for block close
        if _BLOCK_CLOSE.match(stripped):
            current_context = "global"
            continue

        # Check for Include
        m_inc = _INCLUDE.match(stripped)
        if m_inc:
            optional = m_inc.group(1).lower() == "includeoptional"
            pattern = m_inc.group(2).strip().strip('"').strip("'")
            included = _resolve_includes(pattern, base_dir)
            if not included and not optional:
                pass  # mandatory include not found — still parse what we have
            for inc_path in included:
                directives.extend(
                    parse_file(inc_path, context=current_context, visited=visited)
                )
            continue

        # Parse as a regular directive: name [value...]
        parts = stripped.split(None, 1)
        if not parts:
            continue
        name = parts[0]
        value = parts[1].strip() if len(parts) > 1 else ""

        # Remove inline comments from value
        value = re.sub(r"\s+#.*$", "", value).strip()
        # LoadModule: keep only the module name (1st token), not the .so path.
        # "LoadModule dav_module modules/mod_dav.so" -> "dav_module", so DB
        # lookup by module name matches real configs (which include the path).
        if _canonical(name) == "LoadModule" and value:
            value = value.split(None, 1)[0]

        directives.append(Directive(
            name=_canonical(name),
            value=value,
            context=current_context,
            source_file=abs_path,
            line_number=lineno,
        ))

    return directives
