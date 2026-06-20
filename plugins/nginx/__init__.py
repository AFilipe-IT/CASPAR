"""
plugins/nginx/__init__.py
--------------------------
Nginx plugin.

Implements the Target interface for Nginx configuration files. This is the
Phase 3 plugin demonstrating that the core abstraction generalises beyond the
Apache reference plugin to a server with fundamentally different config syntax
(brace blocks + semicolons instead of Apache's key-value style).

File detection:
  - Any file named nginx.conf
  - Any .conf file inside a directory named nginx/, conf.d/, sites-available/,
    sites-enabled/
  - Heuristic: a .conf file whose content contains Nginx-specific markers
    (server { , location , listen , worker_processes, ...)

Runtime (always deterministic):
  detect() -> parse_config() -> get_profile()

Note on attack chains: chains.json is loaded here if present; otherwise the
plugin runs without static chains (the build pipeline can still generate them).
"""

from __future__ import annotations

import json
from pathlib import Path

from core.models import AttackChain, Directive, SystemProfile, TargetMetadata
from core.runtime import register_plugin
from core.target import (
    Target,
    CONFIDENCE_EXACT_FILENAME,
    CONFIDENCE_SYNTAX_MARKER,
    CONFIDENCE_DIRECTORY,
)
from plugins.nginx.parser import parse_file
from plugins.nginx.rules import infer_profile

# Load chains.json at import time if it exists (optional for Nginx).
_CHAINS_PATH = Path(__file__).parent / "chains.json"
CHAINS: list[AttackChain] = []
if _CHAINS_PATH.exists():
    try:
        _raw = json.loads(_CHAINS_PATH.read_text(encoding="utf-8"))
        CHAINS = [
            AttackChain(
                chain_id=c["chain_id"],
                target_name=c["target_name"],
                misconfig_directives=c["misconfig_directives"],
                amplification=c["amplification"],
                justification=c["justification"],
                cross_target=c.get("cross_target", False),
            )
            for c in _raw
        ]
    except Exception:
        CHAINS = []

# Canonical Nginx config filenames
_NGINX_FILENAMES = {
    "nginx.conf",
    "default.conf",
}

# Directory names that typically contain Nginx config
_NGINX_DIRS = {
    "nginx",
    "conf.d",
    "sites-available",
    "sites-enabled",
}

# Markers that strongly indicate an Nginx config file
_NGINX_MARKERS = [
    "worker_processes",
    "worker_connections",
    "server {",
    "location ",
    "fastcgi_pass",
    "proxy_pass",
    "server_tokens",
    "ssl_protocols",
]


class NginxPlugin(Target):
    """
    Nginx target plugin.

    Covers CIS NGINX Benchmark v3.0.0 (subset, Phase 3).
    """

    def detect(self, path: str) -> bool:
        p = Path(path)

        if p.is_dir():
            return p.name.lower() in _NGINX_DIRS or any(
                (p / fname).exists() for fname in _NGINX_FILENAMES
            )

        if p.is_file():
            name_lower = p.name.lower()
            if name_lower in _NGINX_FILENAMES:
                return True
            if p.parent.name.lower() in _NGINX_DIRS and p.suffix.lower() == ".conf":
                return True
            # Content heuristic: distinguish from Apache .conf files.
            if p.suffix.lower() == ".conf" or "nginx" in name_lower:
                try:
                    sample = p.read_text(encoding="utf-8", errors="replace")[:4096]
                    # Apache-specific markers that should NOT be here
                    apache_only = ("LoadModule", "<VirtualHost", "DocumentRoot", "ServerTokens")
                    if any(m in sample for m in apache_only):
                        return False
                    return any(marker in sample for marker in _NGINX_MARKERS)
                except OSError:
                    pass

        return False

    def parse_config(self, path: str) -> list[Directive]:
        p = Path(path)
        if p.is_dir():
            directives: list[Directive] = []
            entry = p / "nginx.conf"
            if entry.exists():
                directives.extend(parse_file(str(entry)))
            if not directives:
                for conf in sorted(p.rglob("*.conf")):
                    directives.extend(parse_file(str(conf)))
            return directives
        return parse_file(path)

    def get_profile(self, directives: list[Directive]) -> SystemProfile:
        return infer_profile(directives)

    def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            name="nginx",
            display_name="Nginx",
            version="3.0",
            benchmark_source="CIS NGINX Benchmark v3.0.0",
            priority=100,
            version_exposing_directives=("server_tokens",),
            # Versions with public exploits in Exploit-DB.
            prefetch_versions=("1.4.0", "1.11.1", "1.20.0"),
        )

    def detection_confidence(self, path: str) -> int:
        p = Path(path)

        if p.is_dir():
            return CONFIDENCE_DIRECTORY

        if not p.is_file():
            return 0

        # Unambiguously Nginx filename
        if p.name.lower() in _NGINX_FILENAMES:
            return CONFIDENCE_EXACT_FILENAME

        # Nginx-specific syntax markers (detect() already excluded Apache markers)
        try:
            sample = p.read_text(encoding="utf-8", errors="replace")[:4096]
            if any(m in sample for m in _NGINX_MARKERS):
                return CONFIDENCE_SYNTAX_MARKER
        except OSError:
            pass

        # Directory-based match
        return CONFIDENCE_DIRECTORY


# Auto-register when this module is imported
register_plugin(NginxPlugin())
