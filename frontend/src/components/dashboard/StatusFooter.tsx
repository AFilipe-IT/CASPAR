import { CalendarClock, Database, Boxes, ShieldCheck } from "lucide-react";
import type { ScanListItem, ServerSettings } from "@/api/types";
import styles from "./StatusFooter.module.css";

/**
 * A faixa de contexto no fundo do painel.
 *
 * Os números acima não dizem de onde vêm: qual foi a última avaliação, contra
 * que base de conhecimento, com que versão. Sem isso, dois painéis com scores
 * diferentes são indistinguíveis de um que mudou — e é essa a pergunta a
 * seguir a "está mau?".
 *
 * O mockup tem aqui um quarto campo, "Reproducible", com o SHA256 da base e o
 * manifesto do scan. Fica de fora de propósito: o `manifest` vem vazio nos
 * scans gravados e não há endpoint que dê o hash da base. Inventar um número
 * de reprodutibilidade era precisamente o que não se pode fazer.
 */
interface StatusFooterProps {
  lastScan?: ScanListItem;
  settings?: ServerSettings;
  /** Directivas avaliadas na leitura actual — o tamanho do que foi coberto. */
  directives?: number;
}

function formatWhen(ts: string): string {
  try {
    return new Date(ts).toLocaleString(undefined, {
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  } catch {
    return ts;
  }
}

export function StatusFooter({ lastScan, settings, directives }: StatusFooterProps) {
  return (
    <div className={styles.bar}>
      <div className={styles.item}>
        <span className={styles.icon}><CalendarClock size={18} /></span>
        <div className={styles.body}>
          <span className={styles.label}>Last assessment</span>
          <span className={styles.value}>
            {lastScan ? formatWhen(lastScan.timestamp) : "None yet"}
          </span>
          {lastScan && <span className={styles.meta}>{lastScan.target_name}</span>}
        </div>
      </div>

      <div className={styles.item}>
        <span className={styles.icon}><Database size={18} /></span>
        <div className={styles.body}>
          <span className={styles.label}>Knowledge base</span>
          <span className={styles.value}>{settings?.db_path ?? "—"}</span>
          {directives !== undefined && (
            <span className={styles.meta}>{directives} directives assessed</span>
          )}
        </div>
      </div>

      <div className={styles.item}>
        <span className={styles.icon}><Boxes size={18} /></span>
        <div className={styles.body}>
          <span className={styles.label}>Coverage</span>
          <span className={styles.value}>
            {settings?.registered_plugins?.length ?? 0} technologies
          </span>
          <span className={styles.meta}>Benchmarks installed on this server</span>
        </div>
      </div>

      <div className={styles.item}>
        <span className={styles.icon}><ShieldCheck size={18} /></span>
        <div className={styles.body}>
          <span className={styles.label}>Engine</span>
          <span className={styles.value}>CVM v{settings?.caspar_version ?? "—"}</span>
          <span className={styles.meta}>
            {settings?.api_key_required ? "API key enforced" : "API key not enforced"}
          </span>
        </div>
      </div>
    </div>
  );
}
