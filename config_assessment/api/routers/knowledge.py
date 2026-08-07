"""
config_assessment/api/routers/knowledge.py
----------------------------------------------
GET /api/v1/knowledge/... — Knowledge Base explorer, backed by the
Knowledge Engine (a read façade over Database).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from config_assessment.api.deps import get_db
from config_assessment.core.db.database import Database
from config_assessment.core.engines.knowledge import KnowledgeEngine
from config_assessment.core.models import AttackChain, Misconfiguration

router = APIRouter(prefix="/api/v1/knowledge", tags=["knowledge"])


@router.get("/benchmarks")
def list_benchmarks(db: Database = Depends(get_db)) -> list[dict]:
    """The security benchmarks the knowledge base was built from (CIS, STIG,
    vendor guides) — the provenance behind every rule and score."""
    return KnowledgeEngine(db).list_benchmarks()


@router.get("/targets/{target}/rules", response_model=list[Misconfiguration])
def list_rules(
    target: str, directive: str | None = None, db: Database = Depends(get_db),
) -> list[Misconfiguration]:
    """Every rule CVM knows for one service: the misconfiguration it detects,
    its CCSS vectors and scores, and the remediation. This is the knowledge
    base itself, not the findings of any particular scan. Pass `directive` to
    look up the rules covering a single configuration option."""
    return KnowledgeEngine(db).get_rules_for_target(target, directive=directive)


@router.get("/targets/{target}/rules/{rule_id}", response_model=Misconfiguration)
def get_rule(target: str, rule_id: str, db: Database = Depends(get_db)) -> Misconfiguration:
    """One rule in full — the same content `caspar explain` renders, including
    the scoring justification and the benchmark section it derives from."""
    rule = KnowledgeEngine(db).get_rule_detail(target, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return rule


@router.get("/targets/{target}/chains", response_model=list[AttackChain])
def list_chains(target: str, db: Database = Depends(get_db)) -> list[AttackChain]:
    """The attack chains defined for a service: combinations of findings whose
    combined risk exceeds the sum of their parts, with the amplification
    factor applied when every directive in the chain is present."""
    return KnowledgeEngine(db).list_chains_for_target(target)
