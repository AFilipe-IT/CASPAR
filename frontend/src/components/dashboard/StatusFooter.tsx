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
 * O campo "Reproducible" mostra o manifesto do scan — versão do código e
 * sha256 do conteúdo da base que produziram estes scores. Dois scans com o
 * mesmo manifesto e o mesmo input têm de dar o mesmo resultado; é o que torna
 * um número auditável em vez de uma afirmação. Só aparece quando o scan o
 * traz: os scans anteriores à coluna `manifest_json` não o têm, e escrever
 * ali um hash inventado destruía exactamente a garantia que o campo dá.
 */
interface StatusFooterProps {
  lastScan?: ScanListItem;
  settings?: ServerSettings;
  /** Directivas avaliadas na leitura actual — o tamanho do que foi coberto. */
  directives?: number;
  /** Manifesto do último scan (`core/manifest.py`), vazio nos scans antigos. */
  manifest?: Record<string, unknown>;
}

/** O sha256 da base, cortado como o CLI o corta — 12 caracteres chegam para
 *  comparar dois scans ao olho, e o valor completo fica no `title`. */
function shortHash(v: unknown): string | null {
  return typeof v === "string" && v.length >= 12 ? v.slice(0, 12) : null;
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

export function StatusFooter({
  lastScan, settings, directives, manifest,
}: StatusFooterProps) {
  const kbHash = shortHash(manifest?.db_sha256);
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
          {/* O hash identifica a base melhor do que o nome do ficheiro: dois
              `ccss.db` com regras diferentes dão scores diferentes e só isto
              os distingue. Ao lado das directivas porque é a mesma pergunta —
              contra o quê é que isto foi avaliado. */}
          {directives !== undefined && (
            <span className={styles.meta}>
              {directives} directives assessed
              {kbHash && (
                <>
                  {" · "}
                  <code
                    className={styles.hash}
                    title={`sha256 ${String(manifest?.db_sha256)}`}
                  >
                    {kbHash}
                  </code>
                </>
              )}
            </span>
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
          {/* Com manifesto, o resultado é auditável: quem o quiser confirmar
              tem a versão e a base com que foi produzido. Sem manifesto não se
              afirma o contrário — afirma-se que não se sabe, que é diferente. */}
          <span className={styles.meta}>
            {kbHash
              ? "Reproducible · manifest recorded"
              : "No manifest on this scan"}
          </span>
        </div>
      </div>
    </div>
  );
}
