#!/usr/bin/env python3
"""Clona ccss.db e duplica todas as regras em targets fantasma até atingir
~N regras totais, para §5.2 (KB crescente) do protocolo de validação.

As regras fantasma são cópias de todos os targets existentes, inseridas sob
nomes de target sintéticos (ghost_0, ghost_1, ...) para não colidir com
nenhum target real. Isto não afeta os findings de nenhum scan (o parser só
casa directive/bad_value por target_name do plugin ativo), só o tamanho
total da tabela `misconfigurations` que o motor de deteção varre.
"""
import argparse
import shutil
import sqlite3
import uuid


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="ccss.db")
    ap.add_argument("--dst", required=True)
    ap.add_argument("--target-rows", type=int, required=True)
    args = ap.parse_args()

    shutil.copyfile(args.src, args.dst)
    conn = sqlite3.connect(args.dst)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(misconfigurations)")]
    non_id_cols = [c for c in cols if c != "id"]

    cur = conn.execute("SELECT COUNT(*) FROM misconfigurations")
    current = cur.fetchone()[0]
    print(f"linhas iniciais: {current}")

    # base rows to clone from (snapshot before we start inserting ghosts)
    base_rows = conn.execute(
        f"SELECT {', '.join(non_id_cols)} FROM misconfigurations"
    ).fetchall()

    ghost_target_id = 90000
    insert_sql = (
        f"INSERT INTO misconfigurations (id, {', '.join(non_id_cols)}) "
        f"VALUES (?, {', '.join(['?'] * len(non_id_cols))})"
    )
    insert_target_sql = (
        "INSERT INTO targets (id, name, display_name, version, benchmark_source) "
        "VALUES (?, ?, ?, ?, ?)"
    )
    target_id_col = non_id_cols.index("target_id")
    target_name_col = non_id_cols.index("target_name")

    # A UNIQUE constraint sobre (target_name, directive, bad_value,
    # expected_value_prefix) impede reusar o mesmo target_name fantasma para
    # todo um lote de base_rows (muitas linhas partilham directive+bad_value
    # entre targets originais diferentes). Por isso cada linha inserida vai
    # para o seu próprio target fantasma (1 target sintético por linha
    # clonada) — garante unicidade sem alterar directive/bad_value.
    n_ghost_targets = 0
    while current < args.target_rows:
        for row in base_rows:
            ghost_name = f"ghost_{ghost_target_id}"
            conn.execute(
                insert_target_sql,
                (ghost_target_id, ghost_name, ghost_name, "synthetic", "synthetic"),
            )
            row = list(row)
            row[target_id_col] = ghost_target_id
            row[target_name_col] = ghost_name
            new_id = str(uuid.uuid4())
            conn.execute(insert_sql, [new_id] + row)
            ghost_target_id += 1
            n_ghost_targets += 1
            current += 1
            if current >= args.target_rows:
                break

    conn.commit()
    final = conn.execute("SELECT COUNT(*) FROM misconfigurations").fetchone()[0]
    print(f"linhas finais: {final} ({n_ghost_targets} targets fantasma criados)")
    conn.close()


if __name__ == "__main__":
    main()
