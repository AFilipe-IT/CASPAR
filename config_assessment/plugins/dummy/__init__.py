"""
plugins/dummy/__init__.py
--------------------------
Fictitious plugin used ONLY to validate the Phase 1 core interface.

This plugin handles files ending in '.dummy' and simulates a single
misconfiguration ("DangerousOption=on").  It is not a real security target.

Criterion of Phase 1 completion (from the spec):
  "A plugin of ~20 lines implements the Target interface and passes through
   the runtime engine from start to finish (input → parse → profile → scan
   → scoring → chain detection → ScanResult) without modifying a single
   line of the config_assessment.core."

This file is that plugin.
"""

from __future__ import annotations

from config_assessment.core.models import Directive, SystemProfile, TargetMetadata
from config_assessment.core.runtime import register_plugin
from config_assessment.core.target import Target


class DummyPlugin(Target):

    def detect(self, path: str) -> bool:
        return path.endswith(".dummy")

    def parse_config(self, path: str) -> list[Directive]:
        lines = open(path).read().splitlines()
        directives = []
        for i, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                name, _, value = line.partition("=")
                directives.append(Directive(
                    name=name.strip(),
                    value=value.strip(),
                    context="global",
                    source_file=path,
                    line_number=i,
                ))
        return directives

    def get_profile(self, directives: list[Directive]) -> SystemProfile:
        # Worst-case: any Listen directive → Network; no auth → Au=None
        has_network = any(d.name == "Listen" for d in directives)
        has_auth = any(d.name == "AuthRequired" and d.value == "on" for d in directives)
        return SystemProfile(
            av="N" if has_network else "L",
            au="N" if not has_auth else "S",
            rationale_av="Network: Listen directive present" if has_network else "Local only",
            rationale_au="No authentication required" if not has_auth else "Single auth",
        )

    def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            name="dummy",
            display_name="Dummy Test Target",
            version="1.0",
            benchmark_source="CCSS-Scan Phase 1 test fixture",
            priority=10,
            version_exposing_directives=("DangerousOption",),
        )


# Auto-register when the module is imported
register_plugin(DummyPlugin())
