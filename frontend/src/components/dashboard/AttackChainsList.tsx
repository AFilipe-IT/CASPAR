import { useState } from "react";
import { Link2Off } from "lucide-react";
import { Badge, severityTone } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Modal } from "@/components/ui/Modal";
import { ChainDetail } from "./ChainDetail";
import { scoreToSeverity } from "@/lib/severity";
import type { AttackChain, Misconfiguration } from "@/api/types";
import styles from "./AttackChainsList.module.css";

export function AttackChainsList({
  chains,
  findings = [],
}: {
  chains: AttackChain[];
  /** Achados do mesmo scan, para o detalhe ligar cada directiva da cadeia ao
   *  problema concreto. Opcional: sem eles a cadeia mostra-se à mesma. */
  findings?: Misconfiguration[];
}) {
  const [selected, setSelected] = useState<AttackChain | null>(null);
  const active = chains.filter((c) => c.active).sort((a, b) => b.amplified_score - a.amplified_score);

  if (active.length === 0) {
    return <EmptyState icon={<Link2Off size={22} />} title="No active attack chains detected" />;
  }

  return (
    <>
      <ul className={styles.list}>
        {active.map((chain) => {
          const sev = scoreToSeverity(chain.amplified_score);
          return (
            <li key={chain.chain_id} className={styles.item}>
              {/* Um botão, não um <li> com onClick: a cadeia é accionável por
                  teclado e anuncia-se como tal aos leitores de ecrã. */}
              <button
                type="button"
                className={styles.trigger}
                onClick={() => setSelected(chain)}
              >
                <span className={styles.name}>{chain.justification || chain.chain_id}</span>
                <Badge tone={severityTone(sev)}>{chain.amplified_score.toFixed(1)}</Badge>
              </button>
            </li>
          );
        })}
      </ul>

      {selected && (
        <Modal onClose={() => setSelected(null)} title="Attack chain">
          <ChainDetail chain={selected} findings={findings} />
        </Modal>
      )}
    </>
  );
}
