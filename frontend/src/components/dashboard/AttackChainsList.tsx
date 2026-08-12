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
  limit,
}: {
  chains: AttackChain[];
  /** Achados do mesmo scan, para o detalhe ligar cada directiva da cadeia ao
   *  problema concreto. Opcional: sem eles a cadeia mostra-se à mesma. */
  findings?: Misconfiguration[];
  /** Quantas mostrar. Sem limite no detalhe de um scan, onde a lista completa
   *  é o assunto da página; com limite no painel, onde 50 cadeias — muitas
   *  delas o mesmo padrão repetido por vários alvos — empurravam o resto da
   *  página para fora do ecrã e deixavam meio painel em branco ao lado. */
  limit?: number;
}) {
  const [selected, setSelected] = useState<AttackChain | null>(null);
  const active = chains.filter((c) => c.active).sort((a, b) => b.amplified_score - a.amplified_score);

  if (active.length === 0) {
    return <EmptyState icon={<Link2Off size={22} />} title="No active attack chains detected" />;
  }

  const shown = limit ? active.slice(0, limit) : active;
  const hidden = active.length - shown.length;

  return (
    <>
      <ul className={styles.list}>
        {shown.map((chain) => {
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

      {/* Dizer quantas ficaram de fora: sem isto a lista cortada era
          indistinguível de uma lista completa. */}
      {hidden > 0 && (
        <p className={styles.more}>
          {hidden} more active {hidden === 1 ? "chain" : "chains"} — open a scan for the full list.
        </p>
      )}

      {selected && (
        <Modal onClose={() => setSelected(null)} title="Attack chain">
          <ChainDetail chain={selected} findings={findings} />
        </Modal>
      )}
    </>
  );
}
