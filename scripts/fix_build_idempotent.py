"""
fix_build_idempotent.py
------------------------
Torna o build idempotente: adiciona um método de DB para apagar
misconfigurations órfãs (que já não estão na lista ENTRIES atual) e liga-o
aos builds Apache e Nginx.

PROBLEMA: o build fazia upsert mas nunca apagava. Reduzir a lista ENTRIES
deixava entradas-fantasma no banco (ex.: ao reduzir Nginx de 11→8, ficaram
3 órfãs que continuavam a disparar no scan).

CORREÇÃO (2 partes):
  1. core/db/database.py: novo método delete_misconfigurations_not_in(
     target_name, keep_pairs) que apaga as misconfigs do target cujo
     (directive, bad_value) não está na lista a manter. Como a narrativa vive
     na própria linha (campo narrative), o DELETE limpa tudo junto.
  2. Os run_build (Apache e Nginx) chamam este método logo após upsert_target,
     passando os pares das ENTRIES — antes de inserir/atualizar.

Uso:
    python3 fix_build_idempotent.py
"""

from __future__ import annotations
import sys
from pathlib import Path

# ── Parte 1: adicionar método ao database.py ──────────────────────────
db_path = Path("core/db/database.py")
if not db_path.exists():
    print("ERROR: core/db/database.py not found. Run from ~/ccss_scan.")
    sys.exit(1)

db_content = db_path.read_text(encoding="utf-8")
db_original = db_content

if "def delete_misconfigurations_not_in" in db_content:
    print("\u2713 1: delete_misconfigurations_not_in already present")
else:
    # Insert right after upsert_misconfiguration ends (its commit) and before
    # get_misconfigurations. Anchor on the def get_misconfigurations line.
    anchor = "    def get_misconfigurations(\n"
    method = '''    def delete_misconfigurations_not_in(
        self,
        target_name: str,
        keep_pairs: list,
    ) -> int:
        """
        Delete misconfigurations for *target_name* whose (directive, bad_value)
        is NOT in *keep_pairs* (a list of (directive, bad_value) tuples).

        Makes the build idempotent: rebuilding with a smaller ENTRIES list
        removes orphaned entries instead of leaving them in the DB. The
        narrative lives in the same row, so it is removed together.

        Returns the number of rows deleted.
        """
        existing = self.get_all_misconfigurations(target_name)
        keep = {(d, v) for d, v in keep_pairs}
        to_delete = [
            (m.directive, m.bad_value)
            for m in existing
            if (m.directive, m.bad_value) not in keep
        ]
        for directive, bad_value in to_delete:
            self._conn.execute(
                "DELETE FROM misconfigurations "
                "WHERE target_name = ? AND directive = ? AND bad_value = ?",
                (target_name, directive, bad_value),
            )
        self._conn.commit()
        return len(to_delete)

'''
    if anchor in db_content:
        db_content = db_content.replace(anchor, method + anchor, 1)
        print("\u2713 1: added delete_misconfigurations_not_in to database.py")
    else:
        print("\u26a0 1: could not find 'def get_misconfigurations(' anchor")
        sys.exit(1)

    db_path.write_text(db_content, encoding="utf-8")
    import ast
    try:
        ast.parse(db_path.read_text(encoding="utf-8"))
    except SyntaxError as e:
        print(f"FAIL database.py line {e.lineno}: {e.msg} — restoring")
        db_path.write_text(db_original, encoding="utf-8")
        sys.exit(1)


# ── Parte 2: ligar ao build Apache e Nginx ─────────────────────────────
def wire_build(build_file: str, label: str) -> None:
    p = Path(build_file)
    if not p.exists():
        print(f"\u26a0 {label}: {build_file} not found — skipping")
        return
    c = p.read_text(encoding="utf-8")
    orig = c
    if "delete_misconfigurations_not_in" in c:
        print(f"\u2713 {label}: already idempotent")
        return
    # Anchor: right after upsert_target(...) block, before pipeline.run.
    # The upsert_target call spans multiple lines ending with '))'. We anchor on
    # the line that creates the pipeline.
    anchor = "        pipeline = LLMBuildPipeline("
    inject = (
        "        # Idempotency: drop misconfigs no longer in ENTRIES before inserting.\n"
        "        keep_pairs = [(e.directive, e.bad_value) for e in ENTRIES]\n"
        "        removed = db.delete_misconfigurations_not_in(meta.name, keep_pairs)\n"
        "        if removed:\n"
        "            logger.info(\"Removed %d orphaned misconfiguration(s) not in ENTRIES\", removed)\n\n"
        "        pipeline = LLMBuildPipeline("
    )
    if anchor in c:
        c = c.replace(anchor, inject, 1)
        p.write_text(c, encoding="utf-8")
        import ast
        try:
            ast.parse(p.read_text(encoding="utf-8"))
            print(f"\u2713 {label}: build now idempotent")
        except SyntaxError as e:
            print(f"FAIL {label} line {e.lineno}: {e.msg} — restoring")
            p.write_text(orig, encoding="utf-8")
    else:
        print(f"\u26a0 {label}: could not find pipeline anchor — skipping")


wire_build("plugins/apache_httpd/build_llm.py", "Apache")
wire_build("plugins/nginx/build_nginx.py", "Nginx")

print("\nDone. Rebuilds now remove orphaned entries automatically.")
