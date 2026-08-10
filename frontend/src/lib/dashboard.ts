import type { Misconfiguration, ScanResult } from "@/api/types";

export interface ServiceRow {
  name: string;
  score: number;
  input: string;
}

export interface FindingRow {
  finding: Misconfiguration;
  service: string;
}

export interface DashboardSummary {
  services: ServiceRow[];
  topFindings: FindingRow[];
  openIssues: number;
  criticalFindings: number;
  /** CVEs DISTINTOS. Contar achados inflaciona: o mesmo CVE-2011-3389
   *  aparece em cada configuração TLS avaliada. */
  cveCount: number;
  /** Achados com CVE, deduplicados como os do topo. Precisam de lista própria:
   *  na prática só as directivas de TLS trazem CVE e essas pontuam baixo, pelo
   *  que nunca sobreviviam ao corte por score das Top Findings. */
  cveFindings: FindingRow[];
  totalDirectives: number;
  allChains: ScanResult["chains"];
  allIssues: Misconfiguration[];
}

/**
 * O resumo do painel, a partir do scan mais recente de cada `input_path`.
 *
 * Vive fora do componente porque é aqui que estão as decisões que se enganam
 * com facilidade — o que conta como "em aberto", o que se deduplica, o que é
 * um CVE distinto — e no componente ficavam presas a `useQueries`, que não
 * corre em ambiente de teste.
 */
export function summarise(details: ScanResult[]): DashboardSummary {
  // O caminho vai junto: vários alvos partilham `target_name` (o apache do
  // sistema, uma fixture, uma cópia de trabalho) e a lista mostrava
  // "apache-httpd" quatro vezes sem dizer qual era qual.
  const services = details
    .map((d) => ({
      name: d.target_name,
      score: d.global_temporal_score,
      input: d.input_path,
    }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);

  const rows = details.flatMap((d) =>
    d.issues.map((issue) => ({ finding: issue, service: d.target_name })),
  );

  // Deduplicado por directiva+serviço: o mesmo `User=root` aparecia três vezes
  // porque três configurações distintas partilham o nome do alvo, e as linhas
  // do topo gastavam-se a repetir dois problemas. Cada lista dedupica com o
  // seu próprio registo — partilhar um só faria a segunda perder linhas que a
  // primeira já tinha visto.
  const byScoreDeduped = (source: FindingRow[]): FindingRow[] => {
    const seen = new Set<string>();
    return [...source]
      .sort((a, b) => b.finding.temporal_score - a.finding.temporal_score)
      .filter((r) => {
        const key = `${r.service}:${r.finding.directive}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
  };

  const topFindings = byScoreDeduped(rows).slice(0, 6);
  const cveFindings = byScoreDeduped(rows.filter((r) => (r.finding.cves ?? []).length > 0));

  const allIssues = details.flatMap((d) => d.issues);

  return {
    services,
    topFindings,
    cveFindings,
    allChains: details.flatMap((d) => d.chains),
    allIssues,
    totalDirectives: details.reduce((sum, d) => sum + d.total_directives_scanned, 0),
    // Problemas em aberto no estado ACTUAL de cada configuração — uma leitura
    // por `input_path`, a mais recente. O `rollup.total_issues` agrega o
    // histórico todo (até 200 scans), pelo que somava avaliações já
    // substituídas: num ambiente de testes dava 6158 quando o estado actual
    // tinha algumas dezenas. Um KPI de postura descreve o presente.
    openIssues: allIssues.length,
    criticalFindings: allIssues.filter((i) => i.temporal_score >= 9).length,
    cveCount: new Set(allIssues.flatMap((i) => i.cves ?? [])).size,
  };
}
