"""
core/build.py
-------------
Build-time pipeline (skeleton).

Responsibility: given a plugin's metadata and benchmark source, populate
the misconfigurations table in the database with pre-calculated CCSS scores.

In Phase 1 this is a parameterised skeleton — the LLM and CVE-lookup
components are stubbed out with clear TODO markers.  Phase 2 will fill in
the Apache implementation; subsequent phases will validate that this
generic pipeline works for every new target without modification.

Pipeline stages
---------------
1. load_benchmark()     — load CIS Benchmark PDF and CCE XLS into LlamaIndex
2. extract_findings()   — LLM + RAG: for each directive, infer AC/C/I/A + justification
3. enrich_cves()        — NVD API + CISA KEV: compute GEL, GRL, attach CVE IDs
4. persist()            — write to misconfigurations table
5. build_chains()       — LLM: identify attack-chain combinations, write to attack_chains

The pipeline is idempotent: re-running it for the same target overwrites
existing entries (upsert by directive + bad_value).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from config_assessment.core.models import (
    ACValue,
    AuValue,
    AVValue,
    CIAValue,
    GELValue,
    GRLValue,
    Misconfiguration,
    AttackChain,
)

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Configuration for one build run                                      #
# ------------------------------------------------------------------ #

@dataclass
class BuildConfig:
    """
    All the inputs the pipeline needs to build the database for one target.

    Pass this to BuildPipeline.run().
    """

    target_name: str
    benchmark_pdf_path: str          # CIS Benchmark PDF
    cce_xls_path: str = ""           # Ground-truth XLS (optional; used for validation)
    llm_model: str = "claude-sonnet-4-20250514"
    nvd_api_key: str = ""            # Leave empty to use unauthenticated NVD (rate-limited)
    output_db_path: str = "ccss.db"
    dry_run: bool = False            # If True, don't write to DB — just return findings


# ------------------------------------------------------------------ #
# Pipeline result                                                       #
# ------------------------------------------------------------------ #

@dataclass
class BuildResult:
    target_name: str
    misconfigurations: list[Misconfiguration] = field(default_factory=list)
    chains: list[AttackChain] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return len(self.errors) == 0


# ------------------------------------------------------------------ #
# Stage protocol — each stage is an injectable callable                #
# ------------------------------------------------------------------ #

StageCallable = Callable[[BuildConfig, BuildResult], None]


# ------------------------------------------------------------------ #
# Individual pipeline stages (stubs — Phase 2 will implement)          #
# ------------------------------------------------------------------ #

def stage_load_benchmark(cfg: BuildConfig, result: BuildResult) -> None:
    """
    Stage 1: Load CIS Benchmark PDF + CCE XLS into a LlamaIndex VectorStoreIndex.

    TODO (Phase 2):
      - Use LlamaIndex SimpleDirectoryReader to ingest the PDF.
      - Chunk by section (H1 / H2 headings).
      - Build a VectorStoreIndex backed by a local ChromaDB or FAISS store.
      - If CCE XLS is provided, parse it with openpyxl and build a
        dict[directive → CCEEntry] for cross-validation.
      - Store the index handle in result so subsequent stages can query it.
    """
    logger.info("[build:%s] Stage 1 — load benchmark (stub)", cfg.target_name)
    if not Path(cfg.benchmark_pdf_path).exists():
        result.errors.append(f"Benchmark PDF not found: {cfg.benchmark_pdf_path}")


def stage_extract_findings(cfg: BuildConfig, result: BuildResult) -> None:
    """
    Stage 2: For each CIS finding, use LLM + RAG to assign AC, C, I, A values.

    TODO (Phase 2):
      - For each directive in the CIS Benchmark:
          1. Retrieve the 3 most relevant chunks from the index.
          2. Send to Claude Sonnet with a structured JSON prompt.
          3. Validate the JSON response with Pydantic (Misconfiguration model).
          4. Append to result.misconfigurations.
      - Retry on LLM failures (max 3 attempts).
      - Log a warning (not error) if confidence < threshold and use
        conservative defaults (AC=L, C=P, I=P, A=P).
    """
    logger.info("[build:%s] Stage 2 — LLM extraction (stub)", cfg.target_name)


def stage_enrich_cves(cfg: BuildConfig, result: BuildResult) -> None:
    """
    Stage 3: Enrich misconfigurations with CVE data from NVD + CISA KEV.

    TODO (Phase 2):
      - For each misconfiguration in result.misconfigurations:
          1. Query NVD REST API v2 with product/version + directive keyword.
          2. If CVE found → set gel = "M" (or keep existing if higher).
          3. Check CISA KEV JSON (https://www.cisa.gov/known-exploited-vulnerabilities-catalog):
             if any CVE is in KEV → force gel = "H" (actively exploited).
          4. Determine grl: if CIS Benchmark has a Remediation subsection → "H".
      - Respect NVD rate limits (without API key: 5 req/30s).
      - Cache NVD responses locally to avoid re-fetching on re-builds.
    """
    logger.info("[build:%s] Stage 3 — CVE enrichment (stub)", cfg.target_name)


def stage_build_chains(cfg: BuildConfig, result: BuildResult) -> None:
    """
    Stage 4: Identify attack chains using the LLM.

    TODO (Phase 2):
      - Send the full list of misconfigurations to Claude Sonnet.
      - Prompt: "Given these misconfigurations for Apache, identify combinations
        that together form a complete attack chain (recon → exploit).
        Return JSON array of AttackChain objects."
      - Validate response against AttackChain model.
      - Also load any hand-curated chains from plugins/<target>/chains.json.
      - Merge LLM-generated + hand-curated, dedup by chain_id.
    """
    logger.info("[build:%s] Stage 4 — chain identification (stub)", cfg.target_name)


def stage_persist(cfg: BuildConfig, result: BuildResult) -> None:
    """
    Stage 5: Write findings to the SQLite database.

    TODO (Phase 2):
      - Import config_assessment.core.db.database and call upsert_misconfigurations().
      - Use target_name + directive + bad_value as the upsert key.
      - Write attack chains to attack_chains table.
      - Log a summary: N misconfigurations written, M chains written.
    """
    if cfg.dry_run:
        logger.info("[build:%s] Stage 5 — dry run, skipping persist", cfg.target_name)
        return
    logger.info("[build:%s] Stage 5 — persist to DB (stub)", cfg.target_name)


# ------------------------------------------------------------------ #
# Pipeline orchestrator                                                #
# ------------------------------------------------------------------ #

class BuildPipeline:
    """
    Runs the build-time pipeline for a single target.

    Stages are injected as callables so that individual stages can be
    replaced in tests without subclassing.
    """

    DEFAULT_STAGES: list[StageCallable] = [
        stage_load_benchmark,
        stage_extract_findings,
        stage_enrich_cves,
        stage_build_chains,
        stage_persist,
    ]

    def __init__(self, stages: list[StageCallable] | None = None) -> None:
        self._stages = stages if stages is not None else list(self.DEFAULT_STAGES)

    def run(self, cfg: BuildConfig) -> BuildResult:
        """
        Execute all pipeline stages in order.

        Stops early if any stage appends to result.errors.
        """
        result = BuildResult(target_name=cfg.target_name)
        logger.info("[build:%s] Starting build pipeline (%d stages)", cfg.target_name, len(self._stages))

        for stage in self._stages:
            stage(cfg, result)
            if not result.success:
                logger.error("[build:%s] Pipeline aborted at stage %s", cfg.target_name, stage.__name__)
                break

        if result.success:
            logger.info(
                "[build:%s] Pipeline complete — %d misconfigs, %d chains",
                cfg.target_name,
                len(result.misconfigurations),
                len(result.chains),
            )
        return result
