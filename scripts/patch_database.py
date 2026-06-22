#!/usr/bin/env python3
"""
patch_database.py
-----------------
Adds narrative support to core/db/database.py.
Run once from the project root:
    python3 patch_database.py

What this adds:
  1. update_narrative() method — writes narrative JSON to the DB
  2. _migrate() method — adds the narrative column to existing DBs
  3. Calls _migrate() in __enter__ so it runs automatically on DB open
  4. Reads narrative in get_all_misconfigurations() so it's available at runtime
"""

from pathlib import Path
import sys

db_path = Path("core/db/database.py")
if not db_path.exists():
    print(f"ERROR: {db_path} not found. Run from project root.")
    sys.exit(1)

content = db_path.read_text(encoding="utf-8")

# ── 1. Add _migrate() call in __enter__ ───────────────────────────
# Find the __enter__ method and add _migrate() call after connection setup
if "_migrate" not in content:
    # Add migration call — find where __enter__ returns self
    old = "        return self"
    new = "        self._migrate()\n        return self"
    if old in content:
        content = content.replace(old, new, 1)
        print("✓ Added _migrate() call in __enter__")
    else:
        print("⚠ Could not find __enter__ return — add self._migrate() manually in __enter__")

# ── 2. Add update_narrative() and _migrate() methods ──────────────
methods = '''
    def update_narrative(
        self,
        directive: str,
        bad_value: str,
        target_name: str,
        narrative: dict,
    ) -> None:
        """Update the narrative JSON for a misconfiguration (Stage 3)."""
        import json as _json
        self._conn.execute(
            """UPDATE misconfigurations
               SET narrative = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
               WHERE target_name = ? AND directive = ? AND bad_value = ?""",
            (_json.dumps(narrative, ensure_ascii=False), target_name, directive, bad_value),
        )
        self._conn.commit()

    def get_narrative(self, target_name: str, directive: str, bad_value: str) -> dict:
        """Retrieve narrative JSON for a misconfiguration."""
        import json as _json
        cur = self._conn.execute(
            "SELECT narrative FROM misconfigurations "
            "WHERE target_name = ? AND directive = ? AND bad_value = ?",
            (target_name, directive, bad_value),
        )
        row = cur.fetchone()
        if row and row[0]:
            try:
                return _json.loads(row[0])
            except Exception:
                pass
        return {}

    def _migrate(self) -> None:
        """Apply schema migrations to existing databases (idempotent)."""
        import logging
        _log = logging.getLogger(__name__)
        migrations = [
            ("narrative",
             "ALTER TABLE misconfigurations ADD COLUMN narrative TEXT NOT NULL DEFAULT '{}'"),
        ]
        for col_name, sql in migrations:
            try:
                self._conn.execute(sql)
                self._conn.commit()
                _log.info("Migration applied: added column '%s'", col_name)
            except Exception:
                pass  # Column already exists — safe to ignore
'''

if "update_narrative" not in content:
    # Insert before the last line of the class (before the closing of the file)
    # Find a good insertion point — before __exit__ or at end of class
    if "def __exit__" in content:
        old = "    def __exit__"
        new = methods + "\n    def __exit__"
        content = content.replace(old, new, 1)
        print("✓ Added update_narrative(), get_narrative(), _migrate() methods")
    else:
        # Append to end of file
        content = content.rstrip() + "\n" + methods + "\n"
        print("✓ Appended methods to end of file")
else:
    print("✓ update_narrative() already present — skipping")

# ── 3. Update get_all_misconfigurations to include narrative ───────
# Find the SELECT in get_all_misconfigurations and ensure narrative is included
if "narrative" not in content:
    # Try to patch the SELECT statement
    old_select = "SELECT * FROM misconfigurations WHERE target_name = ?"
    if old_select in content:
        print("ℹ SELECT uses *, narrative will be available automatically")
    else:
        print("⚠ Check get_all_misconfigurations() — ensure it selects narrative column")

db_path.write_text(content, encoding="utf-8")
print(f"\nDone. Patched {db_path}")
print("\nNext: run Stage 3")
print("  python3 -m plugins.apache_httpd.build_narratives --db ccss.db --model qwen2.5:14b")
