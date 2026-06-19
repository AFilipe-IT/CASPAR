"""
fix_narrative_wiring.py
-------------------------
Corrige a ligação narrative entre banco e runtime:
  1. Adiciona o campo `narrative` à dataclass Misconfiguration em core/models.py
  2. Adiciona narrative=row["narrative"] em _row_to_misconfiguration em core/db/database.py

Corre uma vez:
    python3 fix_narrative_wiring.py
"""

from pathlib import Path
import sys

# ── 1. models.py ────────────────────────────────────────────────
models_path = Path("core/models.py")
if not models_path.exists():
    print("ERROR: core/models.py not found. Run from project root.")
    sys.exit(1)

content = models_path.read_text(encoding="utf-8")

if "narrative: str" not in content:
    old = '    source_directive: Optional[Directive] = None  # runtime'
    new = (
        '    source_directive: Optional[Directive] = None  # runtime\n'
        '    narrative: str = "{}"  # JSON string — rich narrative from Stage 3 LLM pipeline'
    )
    if old in content:
        content = content.replace(old, new, 1)
        models_path.write_text(content, encoding="utf-8")
        print("✓ Added narrative field to Misconfiguration dataclass in models.py")
    else:
        print("⚠ Could not find insertion point in models.py — add manually:")
        print('    narrative: str = "{}"')
        sys.exit(1)
else:
    print("✓ narrative field already present in models.py — skipping")

# ── 2. database.py ───────────────────────────────────────────────
db_path = Path("core/db/database.py")
if not db_path.exists():
    print("ERROR: core/db/database.py not found.")
    sys.exit(1)

content = db_path.read_text(encoding="utf-8")

if 'narrative=row["narrative"]' not in content:
    old = '            recommendation=row["recommendation"],'
    new = (
        '            recommendation=row["recommendation"],\n'
        '            narrative=row["narrative"] if "narrative" in row.keys() else "{}",'
    )
    if old in content:
        content = content.replace(old, new, 1)
        db_path.write_text(content, encoding="utf-8")
        print("✓ Added narrative=row[\"narrative\"] to _row_to_misconfiguration in database.py")
    else:
        print("⚠ Could not find insertion point in database.py — add manually after recommendation=row[\"recommendation\"],:")
        print('            narrative=row["narrative"] if "narrative" in row.keys() else "{}",')
        sys.exit(1)
else:
    print("✓ narrative wiring already present in database.py — skipping")

print("\nDone. Now re-run the scan:")
print("  ccss scan docker://ccss-test-apache:vulnerable --report --output ~/relatorios/")
