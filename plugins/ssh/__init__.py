"""
plugins/ssh/__init__.py
------------------------
OpenSSH (sshd) plugin.

Implements the Target interface for sshd_config. This is the third target,
chosen to demonstrate that the core abstraction generalises beyond web servers
(Apache, Nginx) to a system daemon with a different operational model and a
simple `Keyword value` config syntax.

File detection:
  - Files named sshd_config / ssh_config            → exact filename
  - .conf files inside a sshd_config.d/ directory    → directory evidence
  - Content with SSH-only markers (PermitRootLogin,
    PubkeyAuthentication, Ciphers, KexAlgorithms)    → syntax marker
  - Files carrying Apache/Nginx markers are rejected explicitly (return 0).

Runtime (always deterministic):
  detect() -> parse_config() -> get_profile()
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
from plugins.ssh.parser import parse_file
from plugins.ssh.rules import infer_profile

# Load chains.json at import time if it exists (optional; built later).
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

# Canonical sshd config filenames.
_SSH_FILENAMES = {"sshd_config", "ssh_config"}

# Directory whose .conf fragments belong to sshd.
_SSH_DIRS = {"sshd_config.d", "ssh_config.d"}

# Markers that only an SSH config contains.
_SSH_MARKERS = [
    "PermitRootLogin",
    "PubkeyAuthentication",
    "PasswordAuthentication",
    "KexAlgorithms",
    "Ciphers ",
    "ChallengeResponseAuthentication",
    "HostKey",
]

# Markers from other targets — their presence means this is NOT an SSH config.
_FOREIGN_MARKERS = (
    "ServerTokens", "LoadModule", "<VirtualHost", "DocumentRoot",  # Apache
    "worker_processes", "worker_connections", "server {", "ssl_protocols",  # Nginx
)


def _has_foreign_markers(sample: str) -> bool:
    return any(m in sample for m in _FOREIGN_MARKERS)


class SSHPlugin(Target):
    """OpenSSH target plugin (CIS Ubuntu 24.04 Benchmark, Section 5.1)."""

    def detect(self, path: str) -> bool:
        p = Path(path)

        if p.is_dir():
            return p.name.lower() in _SSH_DIRS or any(
                (p / fname).exists() for fname in _SSH_FILENAMES
            )

        if p.is_file():
            name_lower = p.name.lower()
            if name_lower in _SSH_FILENAMES:
                return True
            if p.parent.name.lower() in _SSH_DIRS and p.suffix.lower() == ".conf":
                return True
            # Content heuristic — only when not an obvious other-target file.
            try:
                sample = p.read_text(encoding="utf-8", errors="replace")[:4096]
            except OSError:
                return False
            if _has_foreign_markers(sample):
                return False
            return any(m in sample for m in _SSH_MARKERS)

        return False

    def parse_config(self, path: str) -> list[Directive]:
        p = Path(path)
        if p.is_dir():
            entry = p / "sshd_config"
            if entry.exists():
                return parse_file(str(entry))
            directives: list[Directive] = []
            frag_dir = p / "sshd_config.d"
            if frag_dir.is_dir():
                for conf in sorted(frag_dir.glob("*.conf")):
                    directives.extend(parse_file(str(conf)))
            return directives
        return parse_file(path)

    def get_profile(self, directives: list[Directive]) -> SystemProfile:
        return infer_profile(directives)

    def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            name="ssh",
            display_name="OpenSSH Server",
            version="9.0",
            benchmark_source="CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.0 — Section 5.1",
            priority=100,
            version_exposing_directives=("Banner",),
            prefetch_versions=("7.4", "8.0", "9.0"),
        )

    def detection_confidence(self, path: str) -> int:
        p = Path(path)

        if p.is_dir():
            return CONFIDENCE_DIRECTORY

        if not p.is_file():
            return 0

        if p.name.lower() in _SSH_FILENAMES:
            return CONFIDENCE_EXACT_FILENAME

        try:
            sample = p.read_text(encoding="utf-8", errors="replace")[:4096]
            if not _has_foreign_markers(sample) and any(m in sample for m in _SSH_MARKERS):
                return CONFIDENCE_SYNTAX_MARKER
        except OSError:
            pass

        return CONFIDENCE_DIRECTORY


# Auto-register when this module is imported.
register_plugin(SSHPlugin())
