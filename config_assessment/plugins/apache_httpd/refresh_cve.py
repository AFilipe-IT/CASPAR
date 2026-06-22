"""
plugins/apache_httpd/refresh_cve.py
-------------------------------------
Actualiza GEL/GRL no banco com dados reais da NVD + CISA KEV.

API key lida automaticamente de:
  1. Variável de ambiente: export NVD_API_KEY=<key>
  2. Ficheiro .env na raiz do projecto: NVD_API_KEY=<key>
  3. Argumento --nvd-key (sobrepõe os anteriores)

Uso:
    # Modo normal (lê key do .env automaticamente)
    python3 -m config_assessment.plugins.apache_httpd.refresh_cve --db ccss.db

    # Ver o que mudaria sem escrever no banco
    python3 -m config_assessment.plugins.apache_httpd.refresh_cve --db ccss.db --dry-run

    # Forçar key específica (sobrepõe .env)
    python3 -m config_assessment.plugins.apache_httpd.refresh_cve --db ccss.db --nvd-key <key>
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from config_assessment.core.ccss import temporal_score
from config_assessment.enrichment.cve_enricher import enrich_all, get_nvd_api_key
from config_assessment.core.db.database import Database

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def refresh_cve(
    db_path: str,
    api_key: str = "",
    dry_run: bool = False,
    target: str = "apache-httpd",
) -> dict:
    with Database(db_path) as db:
        misconfigs = db.get_all_misconfigurations(target)

    if not misconfigs:
        logger.warning("No misconfigurations found for '%s'", target)
        return {}

    logger.info("Enriching %d misconfigurations for '%s'", len(misconfigs), target)

    # Se não foi passada key explicitamente, lê do .env / env var
    if not api_key:
        api_key = get_nvd_api_key()
        if api_key:
            logger.info("NVD API key loaded from .env / environment")

    enrichment = enrich_all(misconfigs, api_key=api_key, dry_run=dry_run)

    changes = []
    gel_counts: dict[str, int] = {}

    for m in misconfigs:
        key = (m.directive, m.bad_value)
        result = enrichment.get(key)
        if not result:
            continue

        gel_counts[result.gel] = gel_counts.get(result.gel, 0) + 1

        changed = (m.gel != result.gel) or (set(m.cves) != set(result.cve_ids))
        if changed:
            changes.append({
                "directive": m.directive,
                "bad_value": m.bad_value,
                "old_gel": m.gel,
                "new_gel": result.gel,
                "old_cves": len(m.cves),
                "new_cves": len(result.cve_ids),
                "notes": result.notes[:80],
            })

    if changes:
        logger.info("\n%d changes detected:", len(changes))
        logger.info("  %-25s %-20s %8s → %8s  CVEs  Notes", "DIRECTIVE", "BAD_VALUE", "GEL", "GEL")
        logger.info("  " + "─" * 80)
        for c in changes:
            logger.info(
                "  %-25s %-20s %8s → %8s  %d→%d  %s",
                c["directive"], c["bad_value"],
                c["old_gel"], c["new_gel"],
                c["old_cves"], c["new_cves"],
                c["notes"],
            )
    else:
        logger.info("No changes detected.")

    if not dry_run and changes:
        with Database(db_path) as db:
            for m in misconfigs:
                key = (m.directive, m.bad_value)
                result = enrichment.get(key)
                if not result:
                    continue
                m.gel = result.gel
                m.grl = result.grl
                m.cves = result.cve_ids
                m.temporal_score = temporal_score(m.base_score, m.gel, m.grl)
                db.upsert_misconfiguration(m)
        logger.info("Database updated: %d misconfigurations refreshed", len(misconfigs))

    return {
        "total": len(misconfigs),
        "updated": len(changes),
        "gel_h":  gel_counts.get("H", 0),
        "gel_m":  gel_counts.get("M", 0),
        "gel_l":  gel_counts.get("L", 0),
        "gel_nd": gel_counts.get("ND", 0),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Refresh CVE enrichment — reads NVD_API_KEY from .env automatically"
    )
    parser.add_argument("--db",      default="ccss.db",      help="SQLite database path")
    parser.add_argument("--target",  default="apache-httpd", help="Target name")
    parser.add_argument("--nvd-key", default="",             help="NVD API key (overrides .env)")
    parser.add_argument("--dry-run", action="store_true",    help="Show changes without writing")
    args = parser.parse_args()

    stats = refresh_cve(
        db_path=args.db,
        api_key=args.nvd_key,
        dry_run=args.dry_run,
        target=args.target,
    )

    print(f"\n{'='*50}")
    print(f"CVE Enrichment {'(dry-run) ' if args.dry_run else ''}Summary")
    print(f"{'='*50}")
    print(f"  Misconfigurations:  {stats.get('total', 0)}")
    print(f"  Updated:            {stats.get('updated', 0)}")
    print(f"  GEL = High  (KEV):  {stats.get('gel_h', 0)}")
    print(f"  GEL = Medium:       {stats.get('gel_m', 0)}")
    print(f"  GEL = Low:          {stats.get('gel_l', 0)}")
    print(f"  GEL = ND:           {stats.get('gel_nd', 0)}")
    print(f"{'='*50}")
    if stats.get("gel_h", 0) > 0:
        print(f"\n  ⚠  {stats['gel_h']} misconfiguration(s) in CISA KEV — actively exploited!")
