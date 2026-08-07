"""
core/engines/knowledge.py
---------------------------
Knowledge Engine (CVM Core).

A read-oriented façade over the Knowledge Base (Database): rules, attack
chain definitions, targets, benchmarks. The REST API and Dashboard should
call this instead of reaching into Database directly, so "browsing the
knowledge base" stays one seam regardless of how it is stored.

Build-time knowledge construction (LLM/RAG ingestion) is a separate concern
(config_assessment/build/, config_assessment/fetch/) — this engine only
reads what build-time already produced.
"""

from __future__ import annotations

from config_assessment.core.db.database import Database
from config_assessment.core.models import AttackChain, Misconfiguration


class KnowledgeEngine:
    """Read façade over a Database handle."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def list_targets(self) -> list[str]:
        return self._db.get_target_names()

    def get_rules_for_target(
        self, target_name: str, directive: str | None = None,
    ) -> list[Misconfiguration]:
        """All rules (value + absence) known for a target, optionally
        filtered to a single directive name."""
        rules = self._db.get_all_misconfigurations(target_name)
        if directive:
            rules = [r for r in rules if r.directive.lower() == directive.lower()]
        return rules

    def get_rule_detail(self, target_name: str, rule_id: str) -> Misconfiguration | None:
        for rule in self._db.get_all_misconfigurations(target_name):
            if rule.id == rule_id:
                return rule
        return None

    def list_chains_for_target(self, target_name: str) -> list[AttackChain]:
        return self._db.get_attack_chains(target_name)

    def list_benchmarks(self) -> list[dict]:
        """Distinct benchmark sources across registered targets, one row
        per target (name, version, benchmark_source)."""
        rows = []
        for name in self._db.get_target_names():
            tid = self._db.get_target_id(name)
            if tid is None:
                continue
            cur = self._db.conn.execute(
                "SELECT name, version, benchmark_source FROM targets WHERE id = ?",
                (tid,),
            )
            row = cur.fetchone()
            if row:
                rows.append(dict(row))
        return rows
