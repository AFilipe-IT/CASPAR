import { useMemo } from "react";
import { useQueries } from "@tanstack/react-query";
import { ShieldAlert, Layers, FileWarning, Siren, Bug, RefreshCw } from "lucide-react";
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
import { summarise } from "@/lib/dashboard";
import { useScans } from "@/api/scans";
import { useHostsRollup } from "@/api/hosts";
import { api } from "@/api/client";
import type { ScanResult } from "@/api/types";
import styles from "./DashboardPage.module.css";

/**
 * Quando é que estes números foram lidos.
 *
 * Um painel que se actualiza sozinho e não o diz é indistinguível de um que
 * não se actualiza: os números são os mesmos enquanto nada muda, e quem olha
 * não tem como saber se está a ver o sistema ou uma fotografia antiga. Daí a
 * hora, e não uma barra de progresso.
 */
function Freshness({ at, isFetching }: { at: number; isFetching: boolean }) {
  if (!at) return null;
  const time = new Date(at).toLocaleTimeString();
  return (
    <span className={styles.freshness} aria-live="polite">
      <RefreshCw
        size={12}
        className={isFetching ? styles.spinning : undefined}
        aria-hidden
      />
      {isFetching ? "Updating…" : `Updated ${time}`}
    </span>
  );
}

export function DashboardPage() {
  const {
    data: scans, isLoading: scansLoading, dataUpdatedAt, isFetching,
  } = useScans({ limit: 50 }, true);
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

  // Sem poll, de propósito: um scan gravado é imutável, portanto voltar a
  // pedi-lo daria sempre o mesmo. O que muda com o tempo é *quais* scans são
  // os mais recentes, e isso vem da lista acima — quando ela traz um id novo,
  // aparece aqui uma query nova e os totais acompanham.
  const scanDetailQueries = useQueries({
    queries: latestByInput.map((id) => ({
      queryKey: ["scan", id],
      queryFn: () => api.get<ScanResult>(`/scans/${id}`),
      enabled: !!id,
      staleTime: Infinity,
    })),
  });

  const details = scanDetailQueries.map((q) => q.data).filter((d): d is ScanResult => !!d);
  const detailsLoading = scanDetailQueries.some((q) => q.isLoading);

  const worstScore = rollup?.worst_score ?? 0;
  // Toda a agregação vive em lib/dashboard.ts: é lá que estão as decisões
  // fáceis de enganar (o que conta como "em aberto", o que se deduplica) e
  // aqui não eram testáveis, presas ao `useQueries`.
  const {
    services, topFindings, cveFindings, allChains, allIssues,
    totalDirectives, openIssues, criticalFindings, cveCount,
    // `details` é um array novo a cada render, portanto a dependência é o que
    // nele muda de facto: quais scans já chegaram.
  } = useMemo(() => summarise(details), [details.map((d) => d.scan_id).join(",")]); // eslint-disable-line react-hooks/exhaustive-deps

  const isLoading = scansLoading || rollupLoading || detailsLoading;

  return (
    <>
      <PageHeader
        title="Home / Overview"
        description="Overall configuration vulnerability posture across every assessed service."
        actions={<Freshness at={dataUpdatedAt} isFetching={isFetching} />}
      />

      <div className="grid-kpi">
        <KpiTile label="Services assessed" value={details.length} icon={<Layers size={18} />} />
        <KpiTile label="Directives scanned" value={totalDirectives} icon={<FileWarning size={18} />} />
        <KpiTile
          label="Open issues"
          value={openIssues}
          icon={<ShieldAlert size={18} />}
        />
        {/* Contava dentro de `topFindings`, que já está cortado nos 5 primeiros
            — o máximo possível era 5, e dava 0 mesmo com um scan Critical 10.0
            na base de dados. Tem de varrer todos os problemas em aberto. */}
        {/* CVEs distintos ligados às configurações avaliadas. Estavam na
            resposta e não tinham onde aparecer; e como quase só as directivas
            de TLS os trazem, ficavam fora do corte por score das Top Findings
            e não havia sinal nenhum de que existiam. */}
        <KpiTile label="Related CVEs" value={cveCount} icon={<Bug size={18} />} />
        <KpiTile
          label="Critical findings"
          value={criticalFindings}
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

      {/* Painel próprio, e não mais linhas nas Top Findings: os achados com
          CVE são quase todos de TLS e pontuam baixo, pelo que nunca sobrevivem
          a um corte por score. Sem lista própria, o KPI dizia que existiam seis
          e não havia como chegar a nenhum deles. Só aparece quando há. */}
      {cveFindings.length > 0 && (
        <Card
          title="Findings with known CVEs"
          subtitle="Configuration weaknesses that map to a published vulnerability. Open one for the references."
        >
          <FindingsTable rows={cveFindings} />
        </Card>
      )}

      <div className="grid-2">
        <Card title="Top Findings">
          {isLoading ? <SkeletonBlock rows={5} /> : <FindingsTable rows={topFindings} />}
        </Card>
        <Card title="Attack Chains (Top Risk)">
          {isLoading ? <SkeletonBlock rows={3} /> : <AttackChainsList chains={allChains} findings={allIssues} />}
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
