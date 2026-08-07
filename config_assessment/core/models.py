"""
core/models.py
--------------
Shared data models (Pydantic v2 BaseModel).

These are the models the CVM Core, CLI, REST API, and Dashboard all share —
FastAPI uses them directly as request/response schemas, with no adapter layer.

Naming conventions
  - Literal types use SHORT UPPERCASE strings matching the CCSS spec.
  - Fields filled at LLM build time are annotated  # build-time.
  - Fields computed at runtime are annotated        # runtime.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

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

class TargetMetadata(BaseModel):
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

class Directive(BaseModel):
    name: str
    value: str
    context: str = "global"
    source_file: str = ""
    line_number: Optional[int] = None

    @field_validator("name", "value", mode="after")
    @classmethod
    def _strip(cls, v: str) -> str:
        return str(v).strip()


# ------------------------------------------------------------------ #
# SystemProfile                                                        #
# ------------------------------------------------------------------ #

class SystemProfile(BaseModel):
    av: AVValue
    au: AuValue
    rationale_av: str = ""
    rationale_au: str = ""


# ------------------------------------------------------------------ #
# Misconfiguration                                                     #
# ------------------------------------------------------------------ #

class Misconfiguration(BaseModel):
    target_name: str
    directive: str
    bad_value: str
    ac: ACValue
    c: CIAValue
    i: CIAValue
    a: CIAValue
    good_value: str = ""
    id: str = Field(default_factory=lambda: str(uuid4()))
    av: AVValue = "N"             # runtime
    au: AuValue = "N"             # runtime
    base_score: float = 0.0
    temporal_score: float = 0.0
    gel: GELValue = "ND"          # build-time
    grl: GRLValue = "ND"          # build-time
    cves: list = Field(default_factory=list)
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
    confidence: float = 1.0  # build-time — self-consistency agreement rate (1.0 = no LLM/unanimous, 0.0 = fallback)


# ------------------------------------------------------------------ #
# AttackChain                                                          #
# ------------------------------------------------------------------ #

class AttackChain(BaseModel):
    chain_id: str
    target_name: str
    misconfig_directives: list = Field(default_factory=list)
    amplification: float = 1.0
    justification: str = ""
    cross_target: bool = False
    active: bool = False
    triggered_by: list = Field(default_factory=list)
    amplified_score: float = 0.0


# ------------------------------------------------------------------ #
# ScanResult                                                           #
# ------------------------------------------------------------------ #

class ScanResult(BaseModel):
    target_name: str
    input_path: str
    input_hash: str
    profile: SystemProfile
    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    issues: list[Misconfiguration] = Field(default_factory=list)
    chains: list[AttackChain] = Field(default_factory=list)
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
    version_exploits: list = Field(default_factory=list)
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
    unknown_directives: list = Field(default_factory=list)
    # Reproducibility manifest (core/manifest.py): CASPAR version, SHA-256 of
    # the knowledge base, target + rule count, Python version. Matching
    # manifests + matching input_hash ⇒ identical scores, by construction —
    # makes the determinism claim auditable from the report itself.
    manifest: dict = Field(default_factory=dict)

    @property
    def highest_issue_score(self) -> float:
        """Top individual misconfiguration score (0.0 if none)."""
        return max((m.temporal_score for m in self.issues), default=0.0)

    @property
    def highest_chain_score(self) -> float:
        """Top active attack-chain amplified score (0.0 if none)."""
        return max((c.amplified_score for c in self.chains
                    if getattr(c, "active", True)), default=0.0)

    @property
    def overall_driver(self) -> str:
        """Whether the global score is driven by an 'issue' or a 'chain' — lets
        the report say *what* produced the headline number, so a 9.9 overall
        with a 7.1 top issue is explained (it came from a chain), not confusing."""
        return "chain" if self.highest_chain_score > self.highest_issue_score else "issue"
