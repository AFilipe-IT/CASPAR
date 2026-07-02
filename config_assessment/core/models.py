"""
core/models.py
--------------
Shared data models.

NOTE (Phase 1 bootstrap): uses Python stdlib dataclasses + TypedDict
because the environment has no network access for pip.
The public interface is intentionally designed to be a drop-in swap
to Pydantic v2 models: field names, types, and defaults are identical.
Migration: replace @dataclass with BaseModel, remove field() defaults
where Pydantic infers them, and the rest of the codebase is unaffected.

Naming conventions
  - Literal types use SHORT UPPERCASE strings matching the CCSS spec.
  - Fields filled at LLM build time are annotated  # build-time.
  - Fields computed at runtime are annotated        # runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal, Optional
from uuid import uuid4

# ------------------------------------------------------------------ #
# CCSS metric value types                                              #
# ------------------------------------------------------------------ #

AVValue  = Literal["L", "A", "N"]
AuValue  = Literal["M", "S", "N"]
ACValue  = Literal["H", "M", "L"]
CIAValue = Literal["N", "P", "C"]
GELValue = Literal["N", "L", "M", "H", "ND"]
GRLValue = Literal["U", "W", "H", "ND"]
SeverityLabel = Literal["None", "Low", "Medium", "High", "Critical"]


# ------------------------------------------------------------------ #
# Plugin / target metadata                                             #
# ------------------------------------------------------------------ #

@dataclass
class TargetMetadata:
    name: str
    display_name: str
    version: str
    benchmark_source: str
    priority: int = 100
    # Directives that disclose the service version (e.g. ("ServerTokens",)).
    # The plugin declares them; the runtime amplifies only these misconfigs when
    # the detected version is exploitable (F1). The core never hardcodes names.
    version_exposing_directives: tuple[str, ...] = ()
    # Curated versions to pre-fetch exploitability for (F1, `ccss fetch-exploits`).
    # Versions known to have public exploits + commonly deployed ones.
    prefetch_versions: tuple[str, ...] = ()


# ------------------------------------------------------------------ #
# Directive                                                            #
# ------------------------------------------------------------------ #

@dataclass
class Directive:
    name: str
    value: str
    context: str = "global"
    source_file: str = ""
    line_number: Optional[int] = None

    def __post_init__(self):
        self.name = str(self.name).strip()
        self.value = str(self.value).strip()


# ------------------------------------------------------------------ #
# SystemProfile                                                        #
# ------------------------------------------------------------------ #

@dataclass
class SystemProfile:
    av: AVValue
    au: AuValue
    rationale_av: str = ""
    rationale_au: str = ""


# ------------------------------------------------------------------ #
# Misconfiguration                                                     #
# ------------------------------------------------------------------ #

@dataclass
class Misconfiguration:
    target_name: str
    directive: str
    bad_value: str
    ac: ACValue
    c: CIAValue
    i: CIAValue
    a: CIAValue
    good_value: str = ""
    id: str = field(default_factory=lambda: str(uuid4()))
    av: AVValue = "N"             # runtime
    au: AuValue = "N"             # runtime
    base_score: float = 0.0
    temporal_score: float = 0.0
    gel: GELValue = "ND"          # build-time
    grl: GRLValue = "ND"          # build-time
    cves: list = field(default_factory=list)
    cce_id: str = ""
    cis_section: str = ""
    justification: str = ""
    recommendation: str = ""
    rule_type: str = "value"    # "value" (lookup) | "absence" (missing directive)
    required_when: str = "always"  # condition: "always" | "if_directive:X"
    expected_value_prefix: str = ""  # for multi-instance directives (e.g. add_header)
    detected_in_scan: bool = False   # runtime
    source_directive: Optional[Directive] = None  # runtime
    version_amplification: float = 1.0  # runtime — F1 version-aware factor applied (1.0 = none)
    version_risk_note: str = ""  # runtime — human-readable reason for the amplification
    narrative: str = "{}"  # JSON string — rich narrative from Stage 3 LLM pipeline

    def model_dump(self) -> dict:
        """Compatibility shim — matches Pydantic's .model_dump() API."""
        import dataclasses
        d = dataclasses.asdict(self)
        # source_directive contains a Directive — convert to dict already done by asdict
        return d


# ------------------------------------------------------------------ #
# AttackChain                                                          #
# ------------------------------------------------------------------ #

@dataclass
class AttackChain:
    chain_id: str
    target_name: str
    misconfig_directives: list = field(default_factory=list)
    amplification: float = 1.0
    justification: str = ""
    cross_target: bool = False
    active: bool = False
    triggered_by: list = field(default_factory=list)
    amplified_score: float = 0.0

    def model_dump(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)


# ------------------------------------------------------------------ #
# ScanResult                                                           #
# ------------------------------------------------------------------ #

@dataclass
class ScanResult:
    target_name: str
    input_path: str
    input_hash: str
    profile: SystemProfile
    scan_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    issues: list = field(default_factory=list)
    chains: list = field(default_factory=list)
    global_base_score: float = 0.0
    global_temporal_score: float = 0.0
    severity: SeverityLabel = "None"
    total_directives_scanned: int = 0
    total_issues_found: int = 0
    total_chains_detected: int = 0
    # Service version detected for the scanned target (e.g. "2.4.51"), or None
    # when the input mode cannot reveal it (a bare config file). Drives the
    # version-aware scoring in F1.
    detected_version: str | None = None
    # Public exploits (Exploit-DB) for the detected version's CVEs (F1 extension).
    # Each entry is a dict (edb_id, title, type, verified, cve, path). Empty when
    # there is no version, no exploits, or searchsploit is unavailable.
    version_exploits: list = field(default_factory=list)
    # True when the CVE/exploit lookup could not run (e.g. NVD timeout). Lets the
    # report distinguish "no exploits found" from "could not check".
    exploit_lookup_failed: bool = False
    # Number of CVEs the exploit lookup examined (>0 with no exploits = checked
    # and clean). Drives the "no public exploits found" report state.
    version_cves_checked: int = 0
    # Directives present in the config that the knowledge base has NO rule for
    # (unknown-directive detection). Deterministic surfacing + heuristic triage;
    # each is an UnknownDirective. NEVER folded into the CCSS scores — these are
    # coverage gaps, not scored issues. LLM assessment (Layer 3) fills the
    # optional llm_* fields only when the caller opts in.
    unknown_directives: list = field(default_factory=list)

    def model_dump_json(self, indent: int = 2) -> str:
        """Compatibility shim — matches Pydantic's .model_dump_json() API."""
        import json
        import dataclasses

        def default(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if dataclasses.is_dataclass(obj):
                return dataclasses.asdict(obj)
            return str(obj)

        return json.dumps(dataclasses.asdict(self), indent=indent, default=default)
