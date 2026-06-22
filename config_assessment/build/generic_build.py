"""
core/generic_build.py
----------------------
Target-agnostic build pipeline used by scaffolded plugins and `ccss plugin add`.

Reuses the existing Apache pipelines (LLMBuildPipeline, generate_chains,
NarrativePipeline) — this does NOT reinvent the build; it just wires the three
stages for a plugin whose ENTRIES come from the scaffolder/extractor.
"""

from __future__ import annotations

import logging
from pathlib import Path

from config_assessment.core.db.database import Database
from config_assessment.build.llm_client import make_client
from config_assessment.core.models import TargetMetadata

logger = logging.getLogger(__name__)


def run_generic_build(
    target_id: str,
    service_name: str,
    benchmark_source: str,
    benchmark_path: str,
    entries: list,
    db_path: str = "ccss.db",
    model: str = "qwen2.5:14b",
    ollama_url: str = "http://localhost:11434",
    dry_run: bool = False,
    stub: bool = False,
    with_narratives: bool = True,
) -> dict:
    """Run Stage 1 (metrics) + 2 (chains) + 3 (narratives) for a target.

    Returns {misconfigs, chains, narratives}.
    """
    from config_assessment.plugins.apache_httpd.llm_pipeline import LLMBuildPipeline
    from config_assessment.build.chain_pipeline import generate_chains
    from config_assessment.plugins.apache_httpd.narrative_pipeline import NarrativePipeline

    backend = "stub" if stub else "ollama"
    llm = make_client(backend=backend, model=model, base_url=ollama_url,
                      fallback_to_stub=True)

    with Database(db_path) as db:
        db.upsert_target(TargetMetadata(
            name=target_id,
            display_name=service_name,
            version="1.0",
            benchmark_source=benchmark_source,
        ))

        # Stage 1 — metrics
        pipeline = LLMBuildPipeline(benchmark_path=benchmark_path, llm=llm)
        results = pipeline.run(entries, db, dry_run=dry_run)

        # Stage 2 — chains (JSON-first; LLM bootstrap if no chains.json)
        chains_path = Path("config_assessment") / "plugins" / target_id / "chains.json"
        chains = generate_chains(
            misconfigs=results, llm=llm, merge_with_fallback=False,
            timeout=300, chains_json_path=chains_path,
        )
        if not dry_run:
            for chain in chains:
                db.upsert_attack_chain(chain)

        # Stage 3 — narratives
        n_narr = 0
        if with_narratives and not dry_run:
            np = NarrativePipeline(llm=llm, service_name=service_name)
            n_narr = np.run(results, db, dry_run=False)

    return {
        "misconfigs": len(results),
        "chains": len(chains) if not dry_run else 0,
        "narratives": n_narr,
    }
