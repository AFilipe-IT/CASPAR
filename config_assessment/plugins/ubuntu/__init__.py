"""
plugins/ubuntu/__init__.py
--------------------------
Ubuntu OS hardening plugin — the CONFIG-BASED subset of the CIS Ubuntu 22.04
Benchmark (Level 1 Server): kernel/network sysctl hardening and /etc/login.defs
password policy.

Scope is deliberate (see rules.py): this target exists to enable a FAIR
comparison with OpenSCAP on the controls both tools can evaluate from config
files. Whole-system state checks (file permissions, kernel modules, running
services) are OpenSCAP's domain, out of scope here — documented as a limitation.

Separate from the `ssh` plugin (which already covers CIS Ubuntu §5.1 sshd_config);
kept apart so the validated SSH target is untouched.

File detection (by canonical filename — these files are unambiguous):
  - sysctl.conf, or *.conf inside a sysctl.d/ directory
  - login.defs
  - a directory containing any of the above
"""

from __future__ import annotations

from pathlib import Path

from config_assessment.core.models import Directive, SystemProfile, TargetMetadata
from config_assessment.core.runtime import register_plugin
from config_assessment.core.target import (
    Target, CONFIDENCE_EXACT_FILENAME, CONFIDENCE_DIRECTORY)
from config_assessment.plugins.ubuntu.parser import parse_file
from config_assessment.plugins.ubuntu.rules import infer_profile

CHAINS: list = []

_FILENAMES = {"sysctl.conf", "login.defs"}
_DIRS = {"sysctl.d"}


def _is_ubuntu_conf(p: Path) -> bool:
    n = p.name.lower()
    if n in _FILENAMES:
        return True
    # a .conf fragment inside sysctl.d/
    return p.suffix.lower() == ".conf" and p.parent.name.lower() in _DIRS


class UbuntuPlugin(Target):
    """Ubuntu OS hardening — config-based subset (CIS Ubuntu 22.04 L1, curated)."""

    def detect(self, path: str) -> bool:
        p = Path(path)
        if p.is_file():
            return _is_ubuntu_conf(p)
        if p.is_dir():
            if p.name.lower() in _DIRS:
                return True
            return any((p / f).exists() for f in _FILENAMES)
        return False

    def detection_confidence(self, path: str) -> int:
        p = Path(path)
        if p.is_file() and p.name.lower() in _FILENAMES:
            return CONFIDENCE_EXACT_FILENAME
        return CONFIDENCE_DIRECTORY

    def parse_config(self, path: str) -> list[Directive]:
        p = Path(path)
        if p.is_dir():
            directives: list[Directive] = []
            for f in _FILENAMES:
                if (p / f).is_file():
                    directives.extend(parse_file(str(p / f)))
            sysctl_d = p / "sysctl.d"
            if sysctl_d.is_dir():
                for frag in sorted(sysctl_d.glob("*.conf")):
                    directives.extend(parse_file(str(frag)))
            return directives
        return parse_file(path)

    def get_profile(self, directives: list[Directive]) -> SystemProfile:
        return infer_profile(directives)

    def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            name="ubuntu",
            display_name="Ubuntu OS hardening (sysctl, login.defs)",
            version="22.04",
            benchmark_source="CIS Ubuntu 22.04 LTS Benchmark L1 Server "
                             "(config-based subset, curated)",
        )


register_plugin(UbuntuPlugin())
