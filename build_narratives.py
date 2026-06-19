"""
plugins/apache_httpd/build_narratives.py
-----------------------------------------
Stage 3 entry point: gerar narrativas detalhadas para todas as
misconfigurations no banco usando LLM local (Ollama).

Corre depois do build_llm.py (Stage 1 + Stage 2):
    python3 -m plugins.apache_httpd.build_narratives \\
        --db ccss.db \\
        --model qwen2.5:14b \\
        [--dry-run]

Pode ser integrado no ccss build com a flag --narratives:
    ccss build --benchmark Benchmark.pdf --narratives

Tempo estimado: ~90s para 30 misconfigs com qwen2.5:14b (3s/narrative).
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.db.database import Database
from core.llm_client import StubLLMClient, make_client
from plugins.apache_httpd.narrative_pipeline import NarrativePipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def run_narratives(
    db_path: str,
    model: str = "qwen2.5:14b",
    ollama_url: str = "http://localhost:11434",
    dry_run: bool = False,
    stub: bool = False,
    target: str = "apache-httpd",
) -> int:
    """Generate narratives for all misconfigurations. Returns count written."""

    llm = make_client(
        backend="stub" if stub else "ollama",
        model=model,
        base_url=ollama_url,
        fallback_to_stub=True,
    )

    if stub:
        logger.warning("STUB mode — narratives are synthetic placeholders")

    with Database(db_path) as db:
        misconfigs = db.get_all_misconfigurations(target)

    if not misconfigs:
        logger.error("No misconfigurations found for '%s'. Run build first.", target)
        return 0

    logger.info("Generating narratives for %d misconfigurations...", len(misconfigs))

    pipeline = NarrativePipeline(llm=llm)

    with Database(db_path) as db:
        count = pipeline.run(misconfigs, db, dry_run=dry_run)

    logger.info("Stage 3 complete: %d narratives %s", count, "previewed" if dry_run else "written")
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Stage 3: generate rich narratives for Apache misconfigurations"
    )
    parser.add_argument("--db",        default="ccss.db",           help="SQLite database")
    parser.add_argument("--model",     default="qwen2.5:14b",       help="Ollama model")
    parser.add_argument("--ollama-url",default="http://localhost:11434")
    parser.add_argument("--target",    default="apache-httpd")
    parser.add_argument("--dry-run",   action="store_true",          help="Preview without writing")
    parser.add_argument("--stub",      action="store_true",          help="Use stub LLM (no Ollama)")
    args = parser.parse_args()

    count = run_narratives(
        db_path=args.db,
        model=args.model,
        ollama_url=args.ollama_url,
        dry_run=args.dry_run,
        stub=args.stub,
        target=args.target,
    )

    print(f"\n{'='*50}")
    print(f"Stage 3 — Narrative Generation")
    print(f"{'='*50}")
    print(f"  Narratives {'previewed' if args.dry_run else 'written'}: {count}")
    print(f"\nNext step:")
    print(f"  ccss scan /path/to/httpd.conf --report --format html")
