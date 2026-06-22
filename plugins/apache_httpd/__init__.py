"""
plugins/apache_httpd/__init__.py
---------------------------------
Apache HTTP Server 2.4 plugin.

Implements the Target interface for Apache httpd configuration files.
This is the Phase 2 reference plugin — it validates the core abstraction
and provides the ground truth for MAE validation against the CCE XLS.

File detection:
  - Any file named httpd.conf, apache2.conf, apache.conf
  - Any file with .conf extension inside a directory named
    apache2/, httpd/, conf/, conf.d/, sites-available/, sites-enabled/

Build time (Phase 2):
  The plugin's chains.json is pre-loaded here.  The LLM-populated
  misconfigurations are populated by core.build via the build pipeline.

Runtime (always):
  detect() → parse_config() → get_profile() are all deterministic.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from core.models import AttackChain, Directive, SystemProfile, TargetMetadata
from core.runtime import register_plugin
from core.target import (
    Target,
    CONFIDENCE_EXACT_FILENAME,
    CONFIDENCE_SYNTAX_MARKER,
    CONFIDENCE_DIRECTORY,
    CONFIDENCE_WEAK,
)
from plugins.apache_httpd.parser import parse_file
from plugins.apache_httpd.rules import infer_profile

# Load chains.json at import time (build time + runtime)
_CHAINS_PATH = Path(__file__).parent / "chains.json"
_CHAINS_RAW: list[dict] = json.loads(_CHAINS_PATH.read_text(encoding="utf-8"))
CHAINS: list[AttackChain] = [
    AttackChain(
        chain_id=c["chain_id"],
        target_name=c["target_name"],
        misconfig_directives=c["misconfig_directives"],
        amplification=c["amplification"],
        justification=c["justification"],
        cross_target=c.get("cross_target", False),
    )
    for c in _CHAINS_RAW
]

# Filenames that unambiguously identify Apache (used for high-confidence detection)
_APACHE_FILENAMES_STRONG = {
    "httpd.conf",
    "apache2.conf",
    "apache.conf",
    "httpd-ssl.conf",
    "httpd-default.conf",
    "httpd-vhosts.conf",
}
# Generic names Apache uses but that may also belong to other services
_APACHE_FILENAMES_WEAK = {
    "ssl.conf",
    "security.conf",
}
_APACHE_FILENAMES = _APACHE_FILENAMES_STRONG | _APACHE_FILENAMES_WEAK

# Directory names that typically contain Apache config
_APACHE_DIRS = {
    "apache2",
    "httpd",
    "conf",
    "conf.d",
    "conf.modules.d",
    "sites-available",
    "sites-enabled",
    "mods-available",
    "mods-enabled",
}


class ApachePlugin(Target):
    """
    Apache HTTP Server 2.4 target plugin.

    Covers CIS Apache HTTP Server 2.4 Benchmark v2.3.0.
    """

    def detect(self, path: str) -> bool:
        """
        Return True if *path* looks like an Apache config file or directory.
        """
        p = Path(path)

        if p.is_dir():
            # Check if the directory name suggests Apache
            return p.name.lower() in _APACHE_DIRS or any(
                (p / fname).exists() for fname in _APACHE_FILENAMES
            )

        if p.is_file():
            name_lower = p.name.lower()
            # Explicit filename match
            if name_lower in _APACHE_FILENAMES:
                return True
            # Any .conf file inside an Apache-looking directory
            if p.suffix.lower() == ".conf" and p.parent.name.lower() in _APACHE_DIRS:
                return True
            # Heuristic: file contains Apache-specific directives
            if p.suffix.lower() == ".conf":
                try:
                    sample = p.read_text(encoding="utf-8", errors="replace")[:4096]
                    apache_markers = [
                        "ServerTokens", "ServerSignature", "LoadModule",
                        "DocumentRoot", "VirtualHost",
                        # "httpd" and "apache" removed — too generic, match comments
                    ]
                    return any(marker.lower() in sample.lower() for marker in apache_markers)
                except OSError:
                    pass

        return False

    def parse_config(self, path: str) -> list[Directive]:
        """
        Parse an Apache config file (or directory of configs) into directives.
        """
        p = Path(path)
        if p.is_dir():
            directives: list[Directive] = []
            # Try canonical entry points first
            for fname in ["httpd.conf", "apache2.conf", "apache.conf"]:
                entry = p / fname
                if entry.exists():
                    directives.extend(parse_file(str(entry)))
            if not directives:
                # Fall back to parsing all .conf files
                for conf in sorted(p.rglob("*.conf")):
                    directives.extend(parse_file(str(conf)))
            return directives
        else:
            return parse_file(path)

    def get_profile(self, directives: list[Directive]) -> SystemProfile:
        """
        Infer system-level AV and Au from Apache directives.
        """
        return infer_profile(directives)

    def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            name="apache-httpd",
            display_name="Apache HTTP Server",
            version="2.4",
            benchmark_source="CIS Apache HTTP Server 2.4 Benchmark v2.3.0",
            priority=100,
            version_exposing_directives=("ServerTokens",),
            # 2.4.49/.50/.66 have public exploits in Exploit-DB; 2.4.58 is a
            # commonly deployed version (demonstrates the "checked & clean" path).
            prefetch_versions=("2.2.31", "2.2.34", "2.4.49", "2.4.50", "2.4.58", "2.4.66"),
        )

    def detection_confidence(self, path: str) -> int:
        p = Path(path)

        if p.is_dir():
            return CONFIDENCE_DIRECTORY

        if not p.is_file():
            return CONFIDENCE_WEAK

        name_lower = p.name.lower()

        # Unambiguously Apache filename
        if name_lower in _APACHE_FILENAMES_STRONG:
            return CONFIDENCE_EXACT_FILENAME

        # Apache-specific syntax — cannot appear in Nginx/SSH configs
        try:
            sample = p.read_text(encoding="utf-8", errors="replace")[:4096]
            if any(m in sample for m in ("<VirtualHost", "LoadModule ", "DocumentRoot ")):
                return CONFIDENCE_SYNTAX_MARKER
        except OSError:
            pass

        # Weak filename (ssl.conf, security.conf) or directory-based match
        return CONFIDENCE_DIRECTORY


# Auto-register when this module is imported
register_plugin(ApachePlugin())
