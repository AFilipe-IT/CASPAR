"""
plugins/nginx/build_nginx.py
-----------------------------
Entry point for the Nginx LLM build (mirrors apache_httpd/build_llm.py).

The ENTRIES list below is the ground truth: the directives we evaluate, with
their bad_value, good_value, and CIS section. CCE IDs are intentionally empty —
unlike Apache, Nginx has no widely-published CCE ground truth, so Nginx is
validated by manual review rather than MAE against CCE (documented design
decision for Phase 3). The LLM assigns AC/C/I/A + justification + GEL/GRL + CVEs.

Sections reference the CIS NGINX Benchmark v3.0.0.

Usage:
    python3 -m plugins.nginx.build_nginx \\
        --benchmark plugins/nginx/CIS_NGINX_Benchmark_v3.0.0.pdf \\
        --db ccss.db \\
        [--model qwen2.5:14b] [--dry-run] [--ollama-url http://localhost:11434]
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.db.database import Database
from core.llm_client import make_client
from core.models import Misconfiguration, TargetMetadata
from plugins.nginx import NginxPlugin
from plugins.apache_httpd.llm_pipeline import LLMBuildPipeline, MisconfigEntry
from plugins.apache_httpd.chain_pipeline import generate_chains

logger = logging.getLogger(__name__)

_TARGET = "nginx"

# ────────────────────────────────────────────────────────────────────
# Absence rules — Phase 1 pilot (3 SSL directives)
# Metrics are manually pre-scored; no LLM pass needed.
# bad_value="" + rule_type="absence" is the sentinel for absence detection.
# ────────────────────────────────────────────────────────────────────
ABSENCE_RULES: list[Misconfiguration] = [
    Misconfiguration(
        target_name=_TARGET,
        directive="ssl_protocols",
        bad_value="",
        good_value="ssl_protocols TLSv1.2 TLSv1.3;",
        rule_type="absence",
        required_when="if_directive:ssl_certificate",
        ac="M", c="P", i="N", a="N",
        gel="L", grl="W",
        cis_section="4.1.4",
        justification=(
            "Without an explicit ssl_protocols directive, Nginx uses the OpenSSL "
            "default which historically includes TLSv1.0 and TLSv1.1. Explicit "
            "configuration is required to exclude deprecated protocol versions."
        ),
        recommendation="Add 'ssl_protocols TLSv1.2 TLSv1.3;' to the http block.",
    ),
    Misconfiguration(
        target_name=_TARGET,
        directive="ssl_session_tickets",
        bad_value="",
        good_value="ssl_session_tickets off;",
        rule_type="absence",
        required_when="if_directive:ssl_certificate",
        ac="H", c="P", i="N", a="N",
        gel="L", grl="W",
        cis_section="4.1.11",
        justification=(
            "When ssl_session_tickets is absent, Nginx defaults to ON. Session "
            "tickets allow servers to resume TLS sessions without re-running the "
            "full handshake, but they undermine Perfect Forward Secrecy: a "
            "compromised ticket key can decrypt all past and future sessions."
        ),
        recommendation="Add 'ssl_session_tickets off;' to the server block.",
    ),
    Misconfiguration(
        target_name=_TARGET,
        directive="ssl_stapling",
        bad_value="",
        good_value="ssl_stapling on; ssl_stapling_verify on;",
        rule_type="absence",
        required_when="if_directive:ssl_certificate",
        ac="M", c="P", i="N", a="N",
        gel="L", grl="W",
        cis_section="4.1.7",
        justification=(
            "Without OCSP stapling, clients must perform live OCSP lookups to the "
            "CA to verify certificate validity. This leaks browsing activity to the "
            "CA, degrades performance, and may allow revocation checks to be "
            "suppressed if the OCSP responder is unavailable."
        ),
        recommendation=(
            "Add 'ssl_stapling on; ssl_stapling_verify on; resolver 8.8.8.8;' "
            "to the server block."
        ),
    ),
]

# ────────────────────────────────────────────────────────────────────
# Ground-truth misconfigurations for Nginx (CIS NGINX Benchmark v3.0.0)
# CCE IDs intentionally empty (no published CCE ground truth for Nginx).
# ────────────────────────────────────────────────────────────────────
ENTRIES: list[MisconfigEntry] = [
    # Each entry is anchored to a REAL section of the CIS NGINX Benchmark
    # v3.0.0 (verified against the indexed PDF). Directives without a dedicated
    # CIS section (e.g. autoindex, ssl_prefer_server_ciphers) were deliberately
    # excluded to keep every misconfiguration traceable to the benchmark.

    # ── Information disclosure (CIS 2.5) ──
    MisconfigEntry("server_tokens", "on", "off", "2.5.1", "", _TARGET),

    # ── Network / DoS hardening (CIS 2.4) ──
    MisconfigEntry("keepalive_timeout", "65", "10", "2.4.3", "", _TARGET),
    MisconfigEntry("keepalive_timeout", "0", "10", "2.4.3", "", _TARGET),
    MisconfigEntry("send_timeout", "0", "10", "2.4.4", "", _TARGET),

    # ── Request limits (CIS 5.2) ──
    MisconfigEntry("client_max_body_size", "0", "100k", "5.2.2", "", _TARGET),

    # ── TLS / SSL (CIS 4.1) ──
    MisconfigEntry("ssl_protocols", "TLSv1 TLSv1.1", "TLSv1.2 TLSv1.3", "4.1.4", "", _TARGET),
    MisconfigEntry("ssl_protocols", "SSLv3", "TLSv1.2 TLSv1.3", "4.1.4", "", _TARGET),

    # ── Reverse proxy / SSRF surface (CIS 2.5.4) ──
    MisconfigEntry("proxy_pass", "http://127.0.0.1:8080", "https://backend with restrictions", "2.5.4", "", _TARGET),
]


def run_build(
    benchmark_path: str,
    db_path: str,
    model: str = "qwen2.5:14b",
    ollama_url: str = "http://localhost:11434",
    dry_run: bool = False,
    stub: bool = False,
) -> int:
    """Run the Nginx LLM build pipeline. Returns the number of entries processed."""
    backend = "stub" if stub else "ollama"
    llm = make_client(backend=backend, model=model, base_url=ollama_url, fallback_to_stub=True)
    if stub:
        logger.warning("Running in STUB mode — LLM responses are synthetic")

    with Database(db_path) as db:
        meta = NginxPlugin().metadata()
        db.upsert_target(TargetMetadata(
            name=meta.name,
            display_name=meta.display_name,
            version=meta.version,
            benchmark_source=meta.benchmark_source,
        ))

        # Idempotency: drop misconfigs no longer in ENTRIES or ABSENCE_RULES before inserting.
        keep_pairs = (
            [(e.directive, e.bad_value) for e in ENTRIES]
            + [(r.directive, r.bad_value) for r in ABSENCE_RULES]
        )
        removed = db.delete_misconfigurations_not_in(meta.name, keep_pairs)
        if removed:
            logger.info("Removed %d orphaned misconfiguration(s) not in ENTRIES", removed)

        pipeline = LLMBuildPipeline(
            benchmark_path=benchmark_path,
            llm=llm,
        )
        results = pipeline.run(ENTRIES, db, dry_run=dry_run)

        # Absence rules are pre-scored manually and inserted directly (no LLM pass).
        for rule in ABSENCE_RULES:
            if not dry_run:
                db.upsert_misconfiguration(rule)
                logger.info(
                    "Absence rule upserted: %s (required_when=%s)",
                    rule.directive, rule.required_when,
                )
        results = results + ABSENCE_RULES

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


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Nginx misconfigurations via LLM")
    parser.add_argument("--benchmark", required=True, help="Path to CIS NGINX Benchmark PDF")
    parser.add_argument("--db", default="ccss.db", help="Path to the SQLite database")
    parser.add_argument("--model", default="qwen2.5:14b", help="Ollama model name")
    parser.add_argument("--ollama-url", default="http://localhost:11434", help="Ollama base URL")
    parser.add_argument("--dry-run", action="store_true", help="Run without writing to the DB")
    parser.add_argument("--stub", action="store_true", help="Use synthetic LLM responses (no GPU)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    count = run_build(
        benchmark_path=args.benchmark,
        db_path=args.db,
        model=args.model,
        ollama_url=args.ollama_url,
        dry_run=args.dry_run,
        stub=args.stub,
    )
    print(f"Done: {count} Nginx misconfigurations processed.")


if __name__ == "__main__":
    main()
