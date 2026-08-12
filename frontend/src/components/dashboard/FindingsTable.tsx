import { useState } from "react";
import { Badge, severityTone } from "@/components/ui/Badge";
import { Table, type Column } from "@/components/ui/Table";
import { EmptyState } from "@/components/ui/EmptyState";
import { Modal } from "@/components/ui/Modal";
import { FindingDetail } from "@/components/knowledge/FindingDetail";
import { ShieldOff } from "lucide-react";
import type { Misconfiguration } from "@/api/types";
import styles from "./FindingsTable.module.css";

interface FindingRow {
  finding: Misconfiguration;
  service: string;
}

function severityFromScore(score: number): string {
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  return "Low";
}

export function FindingsTable({ rows }: { rows: FindingRow[] }) {
  // A tabela só dizia a directiva e a severidade; o porquê, o impacto e a
  // remediação vinham na resposta e não tinham onde ser vistos. Clicar numa
  // linha abre exactamente o mesmo detalhe da Knowledge Base.
  const [selected, setSelected] = useState<FindingRow | null>(null);

  if (rows.length === 0) {
    return <EmptyState icon={<ShieldOff size={22} />} title="No findings recorded yet" />;
  }

  const columns: Column<FindingRow>[] = [
    {
      key: "severity",
      header: "Severity",
      width: "110px",
      render: (r) => {
        const sev = severityFromScore(r.finding.temporal_score);
        return <Badge tone={severityTone(sev)}>{sev}</Badge>;
      },
    },
    {
      key: "finding",
      header: "Finding",
      // O CVE fica no detalhe, mas sem uma marca na linha não há forma de
      // saber que ele existe sem abrir tudo à vez. Na prática são as
      // directivas de TLS que os têm, e essas raramente estão no topo por
      // score — o crachá é o que as torna encontráveis.
      render: (r) => (
        <span className={styles.finding}>
          {r.finding.directive}
          {r.finding.cves?.length > 0 && (
            <span className={styles.cveTag} title={r.finding.cves.join(", ")}>
              {r.finding.cves.length === 1 ? r.finding.cves[0] : `${r.finding.cves.length} CVEs`}
            </span>
          )}
        </span>
      ),
    },
    // A severidade sozinha não distingue as linhas: doze achados "Medium"
    // ficavam todos iguais, quando o que responde a "qual é que fixa o score
    // global?" é o número — o global é o pior temporal individual, e sem ele
    // a lista ordenada por peso não mostrava por que peso estava ordenada.
    {
      key: "score",
      header: "Score",
      width: "80px",
      render: (r) => (
        <span className={styles.score}>{r.finding.temporal_score.toFixed(1)}</span>
      ),
    },
    { key: "service", header: "Service", render: (r) => r.service },
  ];

  return (
    <>
      {/* O `id` é o da regra, não o da ocorrência: a mesma directiva mal posta
          em dois sítios chega duas vezes com o mesmo id (num scan real do
          apache2.conf são 10 ids para 12 achados). Como chave de React isso
          são chaves repetidas, que o React avisa e cujo resultado é
          explicitamente indefinido — pode omitir linhas. A posição desempata
          sem inventar identidade nenhuma. */}
      <Table
        columns={columns}
        rows={rows}
        rowKey={(r, i) => `${r.finding.id}:${i}`}
        onRowClick={(r) => setSelected(r)}
      />
      {selected && (
        <Modal
          title={selected.finding.directive}
          subtitle={`${selected.service} · temporal ${selected.finding.temporal_score.toFixed(1)}`}
          onClose={() => setSelected(null)}
        >
          <FindingDetail rule={selected.finding} />
        </Modal>
      )}
    </>
  );
}
