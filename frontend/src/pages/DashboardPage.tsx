import { useMemo } from "react";
import { useQueries } from "@tanstack/react-query";
import { ShieldAlert, Layers, FileWarning, Siren } from "lucide-react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card } from "@/components/ui/Card";
import { SkeletonBlock } from "@/components/ui/Skeleton";
import { ScoreGauge } from "@/components/dashboard/ScoreGauge";
import { ServiceScoreList } from "@/components/dashboard/ServiceScoreList";
import { FindingsTable } from "@/components/dashboard/FindingsTable";
import { AttackChainsList } from "@/components/dashboard/AttackChainsList";
import { RecentAssessmentsList } from "@/components/dashboard/RecentAssessmentsList";
import { QuickActions } from "@/components/dashboard/QuickActions";
import { KpiTile } from "@/components/dashboard/KpiTile";
import { useScans } from "@/api/scans";
import { useHostsRollup } from "@/api/hosts";
import { api } from "@/api/client";
import type { ScanResult } from "@/api/types";

export function DashboardPage() {
  const { data: scans, isLoading: scansLoading } = useScans({ limit: 50 });
  const { data: rollup, isLoading: rollupLoading } = useHostsRollup();

  // One scan per input_path (most recent) — the same "latest per target"
  // rule the Jinja2 overview uses — fetched in full for per-service scores,
  // findings, and chains.
  const latestByInput = useMemo(() => {
    const map = new Map<string, string>();
    for (const scan of scans ?? []) {
      if (!map.has(scan.input_path)) map.set(scan.input_path, scan.id);
    }
    return [...map.values()];
  }, [scans]);

  const scanDetailQueries = useQueries({
    queries: latestByInput.map((id) => ({
      queryKey: ["scan", id],
      queryFn: () => api.get<ScanResult>(`/scans/${id}`),
      enabled: !!id,
    })),
  });

  const details = scanDetailQueries.map((q) => q.data).filter((d): d is ScanResult => !!d);
  const detailsLoading = scanDetailQueries.some((q) => q.isLoading);

  const worstScore = rollup?.worst_score ?? 0;
  const services = details
    .map((d) => ({ name: d.target_name, score: d.global_temporal_score }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);

  const topFindings = details
    .flatMap((d) => d.issues.map((issue) => ({ finding: issue, service: d.target_name })))
    .sort((a, b) => b.finding.temporal_score - a.finding.temporal_score)
    .slice(0, 5);

  const allChains = details.flatMap((d) => d.chains);
  const totalDirectives = details.reduce((sum, d) => sum + d.total_directives_scanned, 0);

  const isLoading = scansLoading || rollupLoading || detailsLoading;

  return (
    <>
      <PageHeader
        title="Home / Overview"
        description="Overall configuration vulnerability posture across every assessed service."
      />

      <div className="grid-kpi">
        <KpiTile label="Services assessed" value={details.length} icon={<Layers size={18} />} />
        <KpiTile label="Directives scanned" value={totalDirectives} icon={<FileWarning size={18} />} />
        <KpiTile
          label="Rules evaluated"
          value={rollup?.scans ?? 0}
          icon={<ShieldAlert size={18} />}
        />
        <KpiTile
          label="Critical findings"
          value={topFindings.filter((f) => f.finding.temporal_score >= 9).length}
          icon={<Siren size={18} />}
          tone="critical"
        />
      </div>

      <div className="grid-2">
        <Card title="Overall Configuration Vulnerability Score">
          {isLoading ? <SkeletonBlock rows={4} /> : <ScoreGauge score={worstScore} />}
        </Card>
        <Card title="Score by Service (Top 5)">
          {isLoading ? (
            <SkeletonBlock rows={5} />
          ) : services.length === 0 ? (
            <span style={{ color: "var(--text-muted)", fontSize: "var(--fs-sm)" }}>
              No assessments recorded yet.
            </span>
          ) : (
            <ServiceScoreList services={services} />
          )}
        </Card>
      </div>

      <div className="grid-2">
        <Card title="Top Findings">
          {isLoading ? <SkeletonBlock rows={5} /> : <FindingsTable rows={topFindings} />}
        </Card>
        <Card title="Attack Chains (Top Risk)">
          {isLoading ? <SkeletonBlock rows={3} /> : <AttackChainsList chains={allChains} />}
        </Card>
      </div>

      <div className="grid-2">
        <Card title="Recent Assessments">
          {scansLoading ? <SkeletonBlock rows={5} /> : <RecentAssessmentsList scans={(scans ?? []).slice(0, 6)} />}
        </Card>
        <Card title="Quick Actions">
          <QuickActions />
        </Card>
      </div>
    </>
  );
}
