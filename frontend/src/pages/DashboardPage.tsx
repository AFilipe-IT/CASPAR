import { useMemo } from "react";
import { useQueries } from "@tanstack/react-query";
import {
  ShieldAlert, Layers, FileWarning, Siren, Bug, RefreshCw, Link2, ListChecks,
} from "lucide-react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card } from "@/components/ui/Card";
import { SkeletonBlock } from "@/components/ui/Skeleton";
import { ScoreGauge } from "@/components/dashboard/ScoreGauge";
import { ScoreTrendChart } from "@/components/dashboard/ScoreTrendChart";
import { SeverityDonut } from "@/components/dashboard/SeverityDonut";
import { StatRow } from "@/components/dashboard/StatRow";
import { ServiceScoreList } from "@/components/dashboard/ServiceScoreList";
import { FindingsTable } from "@/components/dashboard/FindingsTable";
import { AttackChainsList } from "@/components/dashboard/AttackChainsList";
import { RecentAssessmentsList } from "@/components/dashboard/RecentAssessmentsList";
import { QuickActions } from "@/components/dashboard/QuickActions";
import { KpiTile } from "@/components/dashboard/KpiTile";
import { summarise } from "@/lib/dashboard";
import { useScans } from "@/api/scans";
import { useHostsRollup } from "@/api/hosts";
import { useTrends } from "@/api/trends";
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
  const { data: trends, isLoading: trendsLoading } = useTrends();

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

  // Variação do pior score desde a avaliação anterior. `TrendSeries.delta` é
  // por `input_path`; a postura global segue o alvo que fixa o score actual —
  // é a série desse alvo que explica porque é que o gauge está onde está.
  const worstDelta = useMemo(() => {
    if (!trends?.length) return undefined;
    const worstSeries = [...trends].sort((a, b) => b.last - a.last)[0];
    // Uma leitura só não tem variação: `delta` vinha 0 e lia-se como
    // "estável", quando ainda não há termo de comparação nenhum.
    if (worstSeries.scores.length < 2) return undefined;
    return worstSeries.delta;
  }, [trends]);

  return (
    <>
      <PageHeader
        title="Home / Overview"
        description="Overall configuration vulnerability posture across every assessed service."
        actions={<Freshness at={dataUpdatedAt} isFetching={isFetching} />}
      />

      {/* A faixa de topo responde à pergunta principal — "qual é o risco, e
          está a melhorar?" — antes de qualquer detalhe: o score em grande, o
          que mudou desde a última avaliação, e a curva no tempo. */}
      <div className={styles.scoreBand}>
        <Card title="Configuration Vulnerability Score" className={styles.gaugeCard}>
          {isLoading ? <SkeletonBlock rows={4} /> : <ScoreGauge score={worstScore} />}
        </Card>

        <Card title="Since last assessment">
          {isLoading ? (
            <SkeletonBlock rows={3} />
          ) : (
            <>
              <StatRow
                label="Score change"
                hint="Worst-scoring target"
                icon={<ShieldAlert size={17} />}
                value={worstScore.toFixed(1)}
                delta={worstDelta}
              />
              <StatRow
                label="Open findings"
                hint="Current state, all targets"
                icon={<ListChecks size={17} />}
                value={openIssues}
              />
              <StatRow
                label="Attack chains"
                hint="Findings that compound"
                icon={<Link2 size={17} />}
                value={allChains.length}
              />
            </>
          )}
        </Card>

        <Card title="Score over time" subtitle="Highest-scoring target, across its assessments">
          {trendsLoading ? <SkeletonBlock rows={5} /> : <ScoreTrendChart trends={trends ?? []} />}
        </Card>
      </div>

      <div className="grid-kpi">
        <KpiTile label="Services assessed" value={details.length} icon={<Layers size={18} />} />
        <KpiTile label="Directives scanned" value={totalDirectives} icon={<FileWarning size={18} />} />
        <KpiTile
          label="Open findings"
          value={openIssues}
          icon={<ShieldAlert size={18} />}
        />
        <KpiTile label="Attack chains" value={allChains.length} icon={<Link2 size={18} />} />
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
          {isLoading ? (
            <SkeletonBlock rows={3} />
          ) : (
            /* Seis, para emparelhar com as seis Top Findings ao lado — os dois
               cartões partilham a linha e crescer só um deixava o outro a
               olhar para um vazio de mil pixels. */
            <AttackChainsList chains={allChains} findings={allIssues} limit={6} />
          )}
        </Card>
      </div>

      <div className="grid-bottom">
        <Card title="Top risk services" subtitle="Highest scoring targets">
          {isLoading ? (
            <SkeletonBlock rows={5} />
          ) : services.length === 0 ? (
            <span className={styles.placeholder}>No assessments recorded yet.</span>
          ) : (
            <ServiceScoreList services={services} />
          )}
        </Card>
        <Card title="Severity distribution" subtitle="Open findings by severity">
          {isLoading ? <SkeletonBlock rows={4} /> : <SeverityDonut issues={allIssues} />}
        </Card>
        <Card title="Recent assessments">
          {scansLoading ? (
            <SkeletonBlock rows={5} />
          ) : (
            <RecentAssessmentsList scans={(scans ?? []).slice(0, 6)} />
          )}
        </Card>
      </div>

      {/* Recent Assessments está agora na faixa de baixo, junto aos outros dois
          resumos — aparecia aqui uma segunda vez com exactamente a mesma lista. */}
      <Card title="Quick actions">
        <QuickActions />
      </Card>
    </>
  );
}
