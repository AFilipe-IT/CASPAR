"""
core/db/database.py
-------------------
Database access layer.

Wraps SQLite (development) with a thin abstraction that makes migration
to PostgreSQL straightforward in production.

Public surface area is intentionally minimal:
  - Database(path)               — open/create database
  - db.upsert_target(meta)       — register a target
  - db.upsert_misconfiguration(m)— write one finding (upsert)
  - db.upsert_attack_chain(c)    — write one chain (upsert)
  - db.get_misconfigurations(…)  — O(1) lookup by (target, directive, value)
  - db.get_attack_chains(…)      — get all chains for a target
  - db.save_scan_result(result)  — persist a completed ScanResult
  - db.close()                   — close connection

All reads return fully-typed Pydantic models (Misconfiguration, AttackChain,
ScanResult).  The caller never touches raw SQL rows.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path

from core.models import (
    AttackChain,
    Misconfiguration,
    ScanResult,
    TargetMetadata,
)

logger = logging.getLogger(__name__)

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class Database:
    """
    Thin typed wrapper around a SQLite connection.

    Usage::

        db = Database("ccss.db")
        misconfigs = db.get_misconfigurations("apache-httpd", "ServerTokens", "Full")
        db.close()

    Or as a context manager::

        with Database("ccss.db") as db:
            ...
    """

    def __init__(self, path: str = ":memory:") -> None:
        self._path = path
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row
        # Enable WAL for better concurrent read performance
        self._conn.execute("PRAGMA journal_mode=WAL")
        # Enforce FK constraints
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    # ------------------------------------------------------------------ #
    # Context manager support                                              #
    # ------------------------------------------------------------------ #

    def __enter__(self) -> "Database":
        self._migrate()
        return self


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

        # Simple ADD COLUMN migrations (idempotent: SQLite raises on duplicate column)
        simple_migrations = [
            ("narrative",
             "ALTER TABLE misconfigurations ADD COLUMN narrative TEXT NOT NULL DEFAULT '{}'"),
            ("rule_type",
             "ALTER TABLE misconfigurations ADD COLUMN rule_type TEXT NOT NULL DEFAULT 'value'"),
            ("required_when",
             "ALTER TABLE misconfigurations ADD COLUMN required_when TEXT NOT NULL DEFAULT 'always'"),
        ]
        for col_name, sql in simple_migrations:
            try:
                self._conn.execute(sql)
                self._conn.commit()
                _log.info("Migration applied: added column '%s'", col_name)
            except Exception:
                pass  # Column already exists — safe to ignore

        # Table-recreation migration: add expected_value_prefix + widen UNIQUE constraint.
        # Cannot use ALTER TABLE ADD COLUMN because the UNIQUE constraint must change.
        existing_cols = {r[1] for r in self._conn.execute(
            "PRAGMA table_info(misconfigurations)"
        ).fetchall()}
        if "expected_value_prefix" in existing_cols:
            return  # Already migrated — idempotent

        _log.info("Migration: adding expected_value_prefix (table recreation)")
        before = self._conn.execute(
            "SELECT COUNT(*) FROM misconfigurations"
        ).fetchone()[0]

        self._conn.execute("PRAGMA foreign_keys=OFF")
        try:
            self._conn.execute("BEGIN")
            self._conn.execute("""
                CREATE TABLE misconfigurations_new (
                    id               TEXT    PRIMARY KEY,
                    target_id        INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    target_name      TEXT    NOT NULL,
                    directive        TEXT    NOT NULL,
                    bad_value        TEXT    NOT NULL,
                    good_value       TEXT    NOT NULL DEFAULT '',
                    av               TEXT    NOT NULL DEFAULT 'N',
                    au               TEXT    NOT NULL DEFAULT 'N',
                    ac               TEXT    NOT NULL,
                    c                TEXT    NOT NULL,
                    i                TEXT    NOT NULL,
                    a                TEXT    NOT NULL,
                    base_score       REAL    NOT NULL DEFAULT 0.0,
                    temporal_score   REAL    NOT NULL DEFAULT 0.0,
                    gel              TEXT    NOT NULL DEFAULT 'ND',
                    grl              TEXT    NOT NULL DEFAULT 'ND',
                    cves             TEXT    NOT NULL DEFAULT '[]',
                    cce_id           TEXT    NOT NULL DEFAULT '',
                    cis_section      TEXT    NOT NULL DEFAULT '',
                    justification    TEXT    NOT NULL DEFAULT '',
                    recommendation   TEXT    NOT NULL DEFAULT '',
                    created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                    updated_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                    narrative        TEXT    NOT NULL DEFAULT '{}',
                    rule_type        TEXT    NOT NULL DEFAULT 'value',
                    required_when    TEXT    NOT NULL DEFAULT 'always',
                    expected_value_prefix TEXT NOT NULL DEFAULT '',
                    UNIQUE (target_name, directive, bad_value, expected_value_prefix)
                )
            """)
            self._conn.execute("""
                INSERT INTO misconfigurations_new
                    SELECT id, target_id, target_name,
                           directive, bad_value, good_value,
                           av, au, ac, c, i, a,
                           base_score, temporal_score,
                           gel, grl, cves, cce_id, cis_section,
                           justification, recommendation,
                           created_at, updated_at,
                           narrative, rule_type, required_when,
                           ''
                    FROM misconfigurations
            """)
            after = self._conn.execute(
                "SELECT COUNT(*) FROM misconfigurations_new"
            ).fetchone()[0]
            if before != after:
                self._conn.execute("DROP TABLE IF EXISTS misconfigurations_new")
                self._conn.rollback()
                raise RuntimeError(
                    f"Migration aborted: {before} rows before, {after} after — "
                    "original table unchanged."
                )
            self._conn.execute("DROP TABLE misconfigurations")
            self._conn.execute(
                "ALTER TABLE misconfigurations_new RENAME TO misconfigurations"
            )
            self._conn.execute(
                "CREATE INDEX idx_misconf_lookup "
                "ON misconfigurations (target_name, directive, bad_value)"
            )
            self._conn.execute(
                "CREATE INDEX idx_misconf_target ON misconfigurations (target_name)"
            )
            self._conn.commit()
            _log.info(
                "Migration applied: expected_value_prefix added (%d rows preserved)", after
            )
        except Exception:
            self._conn.rollback()
            raise
        finally:
            self._conn.execute("PRAGMA foreign_keys=ON")

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    # ------------------------------------------------------------------ #
    # Schema init                                                          #
    # ------------------------------------------------------------------ #

    def _init_schema(self) -> None:
        sql = _SCHEMA_PATH.read_text(encoding="utf-8")
        self._conn.executescript(sql)
        self._conn.commit()
        logger.debug("Schema initialised at %s", self._path)

    # ------------------------------------------------------------------ #
    # targets                                                              #
    # ------------------------------------------------------------------ #

    def upsert_target(self, meta: TargetMetadata) -> int:
        """Insert or update a target row.  Returns the target's row id."""
        cur = self._conn.execute(
            """
            INSERT INTO targets (name, display_name, version, benchmark_source)
            VALUES (:name, :display_name, :version, :benchmark_source)
            ON CONFLICT(name) DO UPDATE SET
                display_name     = excluded.display_name,
                version          = excluded.version,
                benchmark_source = excluded.benchmark_source,
                updated_at       = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            RETURNING id
            """,
            {
                "name": meta.name,
                "display_name": meta.display_name,
                "version": meta.version,
                "benchmark_source": meta.benchmark_source,
            },
        )
        row = cur.fetchone()
        self._conn.commit()
        return row["id"]

    def get_target_id(self, target_name: str) -> int | None:
        cur = self._conn.execute(
            "SELECT id FROM targets WHERE name = ?", (target_name,)
        )
        row = cur.fetchone()
        return row["id"] if row else None

    # ------------------------------------------------------------------ #
    # misconfigurations                                                    #
    # ------------------------------------------------------------------ #

    def upsert_misconfiguration(self, m: Misconfiguration) -> None:
        """Insert or update a single misconfiguration."""
        target_id = self.get_target_id(m.target_name)
        if target_id is None:
            raise ValueError(
                f"Target '{m.target_name}' not found in DB. "
                "Call upsert_target() first."
            )
        self._conn.execute(
            """
            INSERT INTO misconfigurations (
                id, target_id, target_name,
                directive, bad_value, good_value,
                av, au, ac, c, i, a,
                base_score, temporal_score,
                gel, grl, cves, cce_id, cis_section,
                justification, recommendation,
                rule_type, required_when, expected_value_prefix
            ) VALUES (
                :id, :target_id, :target_name,
                :directive, :bad_value, :good_value,
                :av, :au, :ac, :c, :i, :a,
                :base_score, :temporal_score,
                :gel, :grl, :cves, :cce_id, :cis_section,
                :justification, :recommendation,
                :rule_type, :required_when, :expected_value_prefix
            )
            ON CONFLICT(target_name, directive, bad_value, expected_value_prefix) DO UPDATE SET
                good_value            = excluded.good_value,
                av                    = excluded.av,
                au                    = excluded.au,
                ac                    = excluded.ac,
                c                     = excluded.c,
                i                     = excluded.i,
                a                     = excluded.a,
                base_score            = excluded.base_score,
                temporal_score        = excluded.temporal_score,
                gel                   = excluded.gel,
                grl                   = excluded.grl,
                cves                  = excluded.cves,
                cce_id                = excluded.cce_id,
                cis_section           = excluded.cis_section,
                justification         = excluded.justification,
                recommendation        = excluded.recommendation,
                rule_type             = excluded.rule_type,
                required_when         = excluded.required_when,
                expected_value_prefix = excluded.expected_value_prefix,
                updated_at            = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            """,
            {
                "id": m.id,
                "target_id": target_id,
                "target_name": m.target_name,
                "directive": m.directive,
                "bad_value": m.bad_value,
                "good_value": m.good_value,
                "av": m.av,
                "au": m.au,
                "ac": m.ac,
                "c": m.c,
                "i": m.i,
                "a": m.a,
                "base_score": m.base_score,
                "temporal_score": m.temporal_score,
                "gel": m.gel,
                "grl": m.grl,
                "cves": json.dumps(m.cves),
                "cce_id": m.cce_id,
                "cis_section": m.cis_section,
                "justification": m.justification,
                "recommendation": m.recommendation,
                "rule_type": m.rule_type,
                "required_when": m.required_when,
                "expected_value_prefix": m.expected_value_prefix,
            },
        )
        self._conn.commit()

    def delete_misconfigurations_not_in(
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

    def get_misconfigurations(
        self,
        target_name: str,
        directive: str,
        bad_value: str,
    ) -> list[Misconfiguration]:
        """
        Lookup misconfigurations by (target_name, directive, bad_value).

        This is the hot path in runtime.  The indexed query is O(1).
        Returns an empty list when nothing matches (not an error).
        """
        cur = self._conn.execute(
            """
            SELECT * FROM misconfigurations
            WHERE target_name = ? AND directive = ? AND bad_value = ?
            """,
            (target_name, directive, bad_value),
        )
        rows = cur.fetchall()
        return [self._row_to_misconfiguration(r) for r in rows]

    def get_absence_rules(self, target_name: str) -> list[Misconfiguration]:
        """Return all absence rules for a target (rule_type = 'absence')."""
        cur = self._conn.execute(
            "SELECT * FROM misconfigurations WHERE target_name = ? AND rule_type = 'absence'",
            (target_name,),
        )
        return [self._row_to_misconfiguration(r) for r in cur.fetchall()]

    def get_all_misconfigurations(self, target_name: str) -> list[Misconfiguration]:
        """Return every misconfiguration for a target (used by the build validator)."""
        cur = self._conn.execute(
            "SELECT * FROM misconfigurations WHERE target_name = ?",
            (target_name,),
        )
        return [self._row_to_misconfiguration(r) for r in cur.fetchall()]

    @staticmethod
    def _row_to_misconfiguration(row: sqlite3.Row) -> Misconfiguration:
        return Misconfiguration(
            id=row["id"],
            target_name=row["target_name"],
            directive=row["directive"],
            bad_value=row["bad_value"],
            good_value=row["good_value"],
            av=row["av"],
            au=row["au"],
            ac=row["ac"],
            c=row["c"],
            i=row["i"],
            a=row["a"],
            base_score=row["base_score"],
            temporal_score=row["temporal_score"],
            gel=row["gel"],
            grl=row["grl"],
            cves=json.loads(row["cves"]),
            cce_id=row["cce_id"],
            cis_section=row["cis_section"],
            justification=row["justification"],
            recommendation=row["recommendation"],
            narrative=row["narrative"] if "narrative" in row.keys() else "{}",
            rule_type=row["rule_type"] if "rule_type" in row.keys() else "value",
            required_when=row["required_when"] if "required_when" in row.keys() else "always",
            expected_value_prefix=row["expected_value_prefix"] if "expected_value_prefix" in row.keys() else "",
        )

    # ------------------------------------------------------------------ #
    # attack_chains                                                        #
    # ------------------------------------------------------------------ #

    def upsert_attack_chain(self, chain: AttackChain) -> None:
        target_id = self.get_target_id(chain.target_name)
        if target_id is None:
            raise ValueError(f"Target '{chain.target_name}' not found in DB.")
        self._conn.execute(
            """
            INSERT INTO attack_chains (
                target_id, target_name, chain_id,
                misconfig_directives, amplification,
                justification, cross_target
            ) VALUES (
                :target_id, :target_name, :chain_id,
                :misconfig_directives, :amplification,
                :justification, :cross_target
            )
            ON CONFLICT(target_name, chain_id) DO UPDATE SET
                misconfig_directives = excluded.misconfig_directives,
                amplification        = excluded.amplification,
                justification        = excluded.justification,
                cross_target         = excluded.cross_target
            """,
            {
                "target_id": target_id,
                "target_name": chain.target_name,
                "chain_id": chain.chain_id,
                "misconfig_directives": json.dumps(chain.misconfig_directives),
                "amplification": chain.amplification,
                "justification": chain.justification,
                "cross_target": int(chain.cross_target),
            },
        )
        self._conn.commit()

    def get_attack_chains(self, target_name: str) -> list[AttackChain]:
        cur = self._conn.execute(
            "SELECT * FROM attack_chains WHERE target_name = ?",
            (target_name,),
        )
        return [self._row_to_chain(r) for r in cur.fetchall()]

    @staticmethod
    def _row_to_chain(row: sqlite3.Row) -> AttackChain:
        return AttackChain(
            chain_id=row["chain_id"],
            target_name=row["target_name"],
            misconfig_directives=json.loads(row["misconfig_directives"]),
            amplification=row["amplification"],
            justification=row["justification"],
            cross_target=bool(row["cross_target"]),
        )

    # ------------------------------------------------------------------ #
    # scan_results                                                         #
    # ------------------------------------------------------------------ #

    def save_scan_result(self, result: ScanResult) -> None:
        self._conn.execute(
            """
            INSERT INTO scan_results (
                id, target_name, input_path, input_hash,
                profile_av, profile_au,
                global_base_score, global_temporal_score, severity,
                total_directives, total_issues, total_chains,
                issues_json, chains_json
            ) VALUES (
                :id, :target_name, :input_path, :input_hash,
                :profile_av, :profile_au,
                :global_base_score, :global_temporal_score, :severity,
                :total_directives, :total_issues, :total_chains,
                :issues_json, :chains_json
            )
            """,
            {
                "id": result.scan_id,
                "target_name": result.target_name,
                "input_path": result.input_path,
                "input_hash": result.input_hash,
                "profile_av": result.profile.av,
                "profile_au": result.profile.au,
                "global_base_score": result.global_base_score,
                "global_temporal_score": result.global_temporal_score,
                "severity": result.severity,
                "total_directives": result.total_directives_scanned,
                "total_issues": result.total_issues_found,
                "total_chains": result.total_chains_detected,
                "issues_json": json.dumps([i.model_dump() for i in result.issues], default=str),
                "chains_json": json.dumps([c.model_dump() for c in result.chains], default=str),
            },
        )
        self._conn.commit()

    def get_scan_result(self, scan_id: str) -> ScanResult | None:
        cur = self._conn.execute(
            "SELECT * FROM scan_results WHERE id = ?", (scan_id,)
        )
        row = cur.fetchone()
        if not row:
            return None
        return ScanResult(
            scan_id=row["id"],
            target_name=row["target_name"],
            input_path=row["input_path"],
            input_hash=row["input_hash"],
            profile={"av": row["profile_av"], "au": row["profile_au"]},
            global_base_score=row["global_base_score"],
            global_temporal_score=row["global_temporal_score"],
            severity=row["severity"],
            total_directives_scanned=row["total_directives"],
            total_issues_found=row["total_issues"],
            total_chains_detected=row["total_chains"],
            issues=json.loads(row["issues_json"]),
            chains=json.loads(row["chains_json"]),
        )
