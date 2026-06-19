"""
plugins/apache_httpd/build_llm.py
-----------------------------------
Entry point para o build com LLM local (Ollama).

Substitui build_apache.py (métricas hard-coded) pelo pipeline LLM completo.
As entradas (directive + cis_section + cce_id) são mantidas aqui como ground truth;
o que o LLM atribui é AC/C/I/A + justificação + GEL/GRL + CVEs.

Uso:
    # Certificar que Ollama está a correr:
    # ollama serve
    # ollama pull qwen2.5:14b

    python3 -m plugins.apache_httpd.build_llm \
        --benchmark CIS_Apache_HTTP_Server_2_4_Benchmark_V2_3_0.pdf \
        --db ccss.db \
        [--model qwen2.5:14b] \
        [--dry-run] \
        [--ollama-url http://localhost:11434]

Após correr, validar com:
    python3 -m plugins.apache_httpd.validate_mae --db ccss.db --cce cce.xls
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.db.database import Database
from core.llm_client import make_client
from core.models import TargetMetadata
from plugins.apache_httpd import ApachePlugin
from plugins.apache_httpd.llm_pipeline import LLMBuildPipeline, MisconfigEntry
from plugins.apache_httpd.chain_pipeline import generate_chains

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Entradas: (directive, bad_value, good_value, cis_section, cce_id)   #
# Estas são o "esqueleto" — o LLM preenche AC/C/I/A/justificação      #
# ------------------------------------------------------------------ #

ENTRIES: list[MisconfigEntry] = [
    # Secção 8 — Information Leakage
    MisconfigEntry("ServerTokens",   "Full",    "Prod",              "8.1",  "CCE-27380-5"),
    MisconfigEntry("ServerTokens",   "OS",      "Prod",              "8.1",  "CCE-27380-5"),
    MisconfigEntry("ServerTokens",   "Minor",   "Prod",              "8.1",  "CCE-27380-5"),
    MisconfigEntry("ServerSignature","On",       "Off",              "8.2",  "CCE-27883-8"),
    MisconfigEntry("FileETag",       "All",      "MTime Size",       "8.4",  ""),

    # Secção 9 — DoS Mitigations
    MisconfigEntry("Timeout",            "300",  "10",               "9.1",  "CCE-27688-1"),
    MisconfigEntry("KeepAlive",          "Off",  "On",               "9.2",  "CCE-27456-3"),
    MisconfigEntry("MaxKeepAliveRequests","0",   "100",              "9.3",  "CCE-27830-9"),
    MisconfigEntry("KeepAliveTimeout",   "300",  "15",               "9.4",  "CCE-27330-0"),

    # Secção 10 — Request Limits
    MisconfigEntry("LimitRequestLine",      "0", "8190",             "10.1", "CCE-27426-6"),
    MisconfigEntry("LimitRequestFields",    "0", "100",              "10.2", "CCE-27741-8"),
    MisconfigEntry("LimitRequestFieldSize", "0", "8190",             "10.3", "CCE-27554-5"),
    MisconfigEntry("LimitRequestBody",      "0", "102400",           "10.4", "CCE-27618-8"),

    # Secção 5 — Features and Options
    MisconfigEntry("TraceEnable",    "On",       "Off",              "5.8",  "CCE-27531-3"),
    MisconfigEntry("Options",        "Indexes",  "None",             "5.2",  "CCE-27657-6"),
    MisconfigEntry("Options",        "FollowSymLinks","SymLinksIfOwnerMatch","5.3","CCE-27877-0"),
    MisconfigEntry("Options",        "All",      "None",             "5.1",  "CCE-27877-0"),
    MisconfigEntry("AllowOverride",  "All",      "None",             "4.4",  "CCE-27536-2"),

    # Secção 2 — Modules
    MisconfigEntry("LoadModule", "dav_module",        "#LoadModule dav_module",        "2.3",  "CCE-27132-0"),
    MisconfigEntry("LoadModule", "status_module",     "#LoadModule status_module",     "2.4",  "CCE-27357-3"),
    MisconfigEntry("LoadModule", "info_module",       "#LoadModule info_module",       "2.8",  "CCE-27852-3"),
    MisconfigEntry("LoadModule", "autoindex_module",  "#LoadModule autoindex_module",  "2.5",  ""),
    MisconfigEntry("LoadModule", "userdir_module",    "#LoadModule userdir_module",    "2.7",  "CCE-27682-4"),

    # Secção 7 — TLS/SSL
    MisconfigEntry("SSLProtocol",    "All",      "TLSv1.2 TLSv1.3", "7.4",  "CCE-27740-0"),
    MisconfigEntry("SSLProtocol",    "+SSLv3",   "TLSv1.2 TLSv1.3", "7.4",  "CCE-27740-0"),
    MisconfigEntry("SSLCompression", "On",        "Off",             "7.7",  ""),

    # Secção 3 — Permissions
    MisconfigEntry("User",  "root", "apache",                        "3.1",  "CCE-27756-6"),
    MisconfigEntry("Group", "root", "apache",                        "3.1",  "CCE-27566-9"),

    # Secção 6 — Logging
    MisconfigEntry("LogLevel", "emerg", "warn",                      "6.1",  "CCE-27879-6"),

    # Secção 4 — Access Control
    MisconfigEntry("Order", "Allow,Deny", "Deny,Allow",              "4.1",  "CCE-27510-7"),
]


def run_build(
    benchmark_path: str,
    db_path: str,
    model: str = "qwen2.5:14b",
    ollama_url: str = "http://localhost:11434",
    dry_run: bool = False,
    stub: bool = False,
) -> int:
    """
    Run the LLM build pipeline. Returns the number of entries processed.
    """
    # Build LLM client
    backend = "stub" if stub else "ollama"
    llm = make_client(backend=backend, model=model, base_url=ollama_url, fallback_to_stub=True)

    if stub:
        logger.warning("Running in STUB mode — LLM responses are synthetic")

    # Open DB and register target
    with Database(db_path) as db:
        meta = ApachePlugin().metadata()
        db.upsert_target(TargetMetadata(
            name=meta.name,
            display_name=meta.display_name,
            version=meta.version,
            benchmark_source=meta.benchmark_source,
        ))

        # Run LLM pipeline
        # Idempotency: drop misconfigs no longer in ENTRIES before inserting.
        keep_pairs = [(e.directive, e.bad_value, "") for e in ENTRIES]
        removed = db.delete_misconfigurations_not_in(meta.name, keep_pairs)
        if removed:
            logger.info("Removed %d orphaned misconfiguration(s) not in ENTRIES", removed)

        pipeline = LLMBuildPipeline(
            benchmark_path=benchmark_path,
            llm=llm,
        )
        results = pipeline.run(ENTRIES, db, dry_run=dry_run)

        # Stage 2: generate attack chains via LLM
        # timeout=300: the chain prompt contains all 30 misconfigs — needs more time
        # than individual metric calls (which use the default 120s)
        logger.info("Stage 2 — generating attack chains via LLM...")
        chains = generate_chains(
            misconfigs=results,
            llm=llm,
            merge_with_fallback=False,
            timeout=300,
        )

        if not dry_run:
            for chain in chains:
                db.upsert_attack_chain(chain)
            logger.info("Wrote %d attack chains", len(chains))

    logger.info(
        "Build %s: %d misconfigurations, %d chains",
        "dry-run" if dry_run else "complete",
        len(results),
        len(chains) if not dry_run else 0,
    )
    return len(results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Build Apache CCSS database using local LLM (Ollama)"
    )
    parser.add_argument("--benchmark", required=True, help="CIS Benchmark PDF path")
    parser.add_argument("--db",        default="ccss.db", help="SQLite database path")
    parser.add_argument("--model",     default="qwen2.5:14b", help="Ollama model tag")
    parser.add_argument("--ollama-url",default="http://localhost:11434", help="Ollama server URL")
    parser.add_argument("--dry-run",   action="store_true", help="Don't write to DB")
    parser.add_argument("--stub",      action="store_true", help="Use stub LLM (no Ollama needed)")
    args = parser.parse_args()

    count = run_build(
        benchmark_path=args.benchmark,
        db_path=args.db,
        model=args.model,
        ollama_url=args.ollama_url,
        dry_run=args.dry_run,
        stub=args.stub,
    )
    print(f"\nDone: {count} entries processed.")
    print(f"\nNext step — validate:")
    print(f"  python3 -m plugins.apache_httpd.validate_mae --db {args.db} --cce <path/to/cce.xls>")
