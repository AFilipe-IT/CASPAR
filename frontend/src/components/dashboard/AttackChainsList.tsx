import { Link2Off } from "lucide-react";
import { Badge, severityTone } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { scoreToSeverity } from "@/lib/severity";
import type { AttackChain } from "@/api/types";
import styles from "./AttackChainsList.module.css";

export function AttackChainsList({ chains }: { chains: AttackChain[] }) {
  const active = chains.filter((c) => c.active).sort((a, b) => b.amplified_score - a.amplified_score);

  if (active.length === 0) {
    return <EmptyState icon={<Link2Off size={22} />} title="No active attack chains detected" />;
  }

  return (
    <ul className={styles.list}>
      {active.map((chain) => {
        const sev = scoreToSeverity(chain.amplified_score);
        return (
          <li key={chain.chain_id} className={styles.item}>
            <span className={styles.name}>{chain.justification || chain.chain_id}</span>
            <Badge tone={severityTone(sev)}>{chain.amplified_score.toFixed(1)}</Badge>
          </li>
        );
      })}
    </ul>
  );
}
