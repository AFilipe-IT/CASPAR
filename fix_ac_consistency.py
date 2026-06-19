"""
fix_ac_consistency.py
-----------------------
Verifica as 30 narrativas já existentes no banco contra a heurística de
consistência AC, e corrige APENAS as que têm contradição — sem re-gerar
as 30 via LLM (evita outra hora de espera).

A correcção é determinística (não chama o LLM): substitui o texto da
justificação 'ac' por uma versão coerente com o valor real da métrica,
mantendo description / potential_impact / exploitation_scenario intactos.

Uso:
    python3 fix_ac_consistency.py --db ccss.db
    python3 fix_ac_consistency.py --db ccss.db --dry-run
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.db.database import Database
from plugins.apache_httpd.narrative_pipeline import (
    _ac_text_contradicts_value,
    _fix_ac_justification,
)


def main(db_path: str, target: str, dry_run: bool) -> None:
    with Database(db_path) as db:
        misconfigs = db.get_all_misconfigurations(target)

    if not misconfigs:
        print(f"No misconfigurations found for '{target}'.")
        return

    checked = 0
    fixed = 0

    for m in misconfigs:
        raw = m.narrative if m.narrative and m.narrative != "{}" else None
        if not raw:
            continue
        checked += 1

        try:
            narrative = json.loads(raw)
        except Exception:
            print(f"  SKIP {m.directive}={m.bad_value}: narrative JSON invalid")
            continue

        mjust = narrative.get("metric_justifications", {})
        ac_text = str(mjust.get("ac", ""))

        if _ac_text_contradicts_value(m.ac, ac_text):
            new_text = _fix_ac_justification(m)
            print(f"  FIX  {m.directive}={m.bad_value}  (AC={m.ac})")
            print(f"       was: {ac_text[:90]}")
            print(f"       now: {new_text[:90]}")

            if not dry_run:
                mjust["ac"] = new_text
                narrative["metric_justifications"] = mjust
                with Database(db_path) as db:
                    db.update_narrative(m.directive, m.bad_value, target, narrative)
            fixed += 1

    print()
    print(f"{'='*50}")
    print(f"AC Consistency Check {'(dry-run)' if dry_run else ''}")
    print(f"{'='*50}")
    print(f"  Narratives checked: {checked}")
    print(f"  Contradictions found and fixed: {fixed}")
    if fixed == 0:
        print("  All narratives are internally consistent.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check and fix AC justification consistency in existing narratives")
    parser.add_argument("--db", default="ccss.db")
    parser.add_argument("--target", default="apache-httpd")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    main(args.db, args.target, args.dry_run)
