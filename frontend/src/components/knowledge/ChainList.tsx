import { Link2 } from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import type { AttackChain } from "@/api/types";
import styles from "./ChainList.module.css";

export function ChainList({ chains }: { chains: AttackChain[] }) {
  if (chains.length === 0) {
    return <EmptyState icon={<Link2 size={22} />} title="No attack chains defined for this benchmark" />;
  }

  return (
    <ul className={styles.list}>
      {chains.map((chain) => (
        <li key={chain.chain_id} className={styles.item}>
          <div className={styles.head}>
            <span className={styles.name}>{chain.justification || chain.chain_id}</span>
            <Badge tone="accent">×{chain.amplification.toFixed(1)}</Badge>
          </div>
          <p className={styles.directives}>{chain.misconfig_directives.join(" → ")}</p>
        </li>
      ))}
    </ul>
  );
}
