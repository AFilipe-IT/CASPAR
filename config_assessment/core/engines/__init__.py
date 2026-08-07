"""
config_assessment/core/engines
--------------------------------
CVM Core — the six engines shared by every interface (CLI, REST API,
Dashboard). None of these contain plugin-specific (Apache/SSH/Kubernetes/...)
logic; that lives entirely in config_assessment/plugins/.

  Assessment Engine   detect / parse / profile / match rules -> issues
  Scoring Engine      CCSS base/temporal score math (NISTIR 7502)
  Aggregation Engine  worst-case rollups: per-scan, per-input trend, per-host
  Attack Chain Engine subset-match + amplify composite-risk chains
  Knowledge Engine    read façade over the Knowledge Base (rules/chains/targets)
  Reporting Engine    render a ScanResult (HTML report, dashboard, diff, badge)

Every interface (cli/, config_assessment/api/) should call these engines —
never re-implement scoring/detection/aggregation.
"""

from __future__ import annotations

from config_assessment.core.engines.aggregation import (
    HostRollup,
    TrendSeries,
    aggregate_hosts,
    aggregate_scan,
    aggregate_trend,
    sparkline,
)
from config_assessment.core.engines.assessment import (
    check_condition,
    detect_absences,
    hash_input,
    match_value_rules,
    register_plugin,
    registered_plugins,
    score_issues,
    select_plugin,
)
from config_assessment.core.engines.attack_chain import amplify_chains, detect_chains
from config_assessment.core.engines.knowledge import KnowledgeEngine
from config_assessment.core.engines.reporting import (
    badge_markdown,
    badge_url,
    diff_scans,
    generate_dashboard,
    generate_dashboard_online,
    generate_html,
    load_scan,
)
from config_assessment.core.engines.scoring import (
    adjust_av_au,
    aggregate,
    amplified_score,
    base_score,
    full_score,
    impact_capped_score,
    severity_label,
    temporal_score,
    worst_au,
    worst_av,
)

__all__ = [
    # assessment
    "register_plugin", "registered_plugins", "select_plugin", "hash_input",
    "check_condition", "match_value_rules", "detect_absences", "score_issues",
    # scoring
    "base_score", "temporal_score", "adjust_av_au", "aggregate",
    "severity_label", "amplified_score", "impact_capped_score", "full_score",
    "worst_av", "worst_au",
    # attack chain
    "detect_chains", "amplify_chains",
    # aggregation
    "aggregate_scan", "aggregate_trend", "aggregate_hosts",
    "TrendSeries", "HostRollup", "sparkline",
    # knowledge
    "KnowledgeEngine",
    # reporting
    "generate_html", "generate_dashboard", "generate_dashboard_online",
    "diff_scans", "load_scan", "badge_url", "badge_markdown",
]
