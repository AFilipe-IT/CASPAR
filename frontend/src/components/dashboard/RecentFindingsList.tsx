import { Badge, severityTone } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { ShieldCheck } from "lucide-react";
import { ServiceIcon } from "./ServiceIcon";
import { scoreToSeverity } from "@/lib/severity";
import type { FindingRow } from "@/lib/dashboard";
import styles from "./RecentFindingsList.module.css";

/**
 * O impacto do achado, em duas palavras, a partir do vector CCSS.
 *
 * O campo `justification` é um parágrafo inteiro — cortado a 40 caracteres
 * ficava a meio de uma frase e dizia menos que nada. O vector C/I/A já traz
 * esta informação de forma estruturada, e é a mesma que alimenta o score:
 * a linha passa a explicar *porquê* sem inventar texto nenhum.
 */
function impactLabel({ c, i, a }: { c: string; i: string; a: string }): string {
  const hit = (v: string) => v === "P" || v === "C";
  const parts: string[] = [];
  if (hit(c)) parts.push("Information disclosure");
  if (hit(i)) parts.push("Integrity loss");
  if (hit(a)) parts.push("Service disruption");
  // Sem nenhum dos três, o achado é de boas práticas e não de impacto
  // directo — dizer "sem impacto" seria falso, dizer nada é honesto.
  return parts.length ? parts.join(" · ") : "Hardening gap";
}

interface RecentFindingsListProps {
  findings: FindingRow[];
  limit?: number;
}

export function RecentFindingsList({ findings, limit = 6 }: RecentFindingsListProps) {
  if (findings.length === 0) {
    return (
      <EmptyState
        icon={<ShieldCheck size={22} />}
        title="No open findings"
        description="Every assessed directive matches its benchmark."
      />
    );
  }

  const shown = findings.slice(0, limit);

  return (
    <div className={styles.list}>
      {shown.map(({ finding, service }) => {
        const sev = scoreToSeverity(finding.temporal_score);
        return (
          <div key={`${service}:${finding.directive}:${finding.bad_value}`} className={styles.row}>
            <div className={styles.main}>
              <span className={styles.title}>
                {finding.directive}
                {finding.bad_value && <span className={styles.value}> is set to {finding.bad_value}</span>}
              </span>
              <span className={styles.impact}>{impactLabel(finding)}</span>
            </div>
            <span className={styles.service}>
              <ServiceIcon name={service} size={13} />
              {service}
            </span>
            <Badge tone={severityTone(sev)}>{sev}</Badge>
          </div>
        );
      })}
    </div>
  );
}
