import { ShieldOff } from "lucide-react";
import { FindingsTable } from "@/components/dashboard/FindingsTable";
import { AttackChainsList } from "@/components/dashboard/AttackChainsList";
import { EmptyState } from "@/components/ui/EmptyState";
import { SkeletonBlock } from "@/components/ui/Skeleton";
import { useScan } from "@/api/scans";
import styles from "./WatchEventDetail.module.css";

/**
 * As directivas por trás do score de um evento do watch.
 *
 * A sessão mostrava só o número global, e um número que não se mexe não diz
 * porquê. Cada evento é um scan guardado por inteiro, portanto basta a sua
 * chave para chegar aos achados concretos — os mesmos componentes do resto da
 * consola, para o detalhe ser o mesmo em todo o lado.
 */
export function WatchEventDetail({ scanId }: { scanId: string }) {
  const { data: scan, isLoading, isError, error } = useScan(scanId);

  if (isLoading) return <SkeletonBlock rows={5} />;
  if (isError) {
    return (
      <EmptyState
        icon={<ShieldOff size={22} />}
        title="Could not load this event"
        description={(error as Error).message}
      />
    );
  }
  if (!scan) return null;

  return (
    <div className={styles.wrap}>
      <div className={styles.meta}>
        <span>{scan.total_directives_scanned} directives scanned</span>
        <span>{scan.issues.length} issues</span>
        <span>{scan.chains.length} attack chains</span>
        {scan.detected_version && <span>Version {scan.detected_version}</span>}
      </div>

      <section className={styles.section}>
        <h4>Findings driving the score</h4>
        {/* Ordenados pelo peso: a primeira linha é a que fixa o score global,
            porque o global é o pior achado individual. Ver a lista assim
            responde directamente a "porque é que isto não desce?". */}
        <FindingsTable
          rows={[...scan.issues]
            .sort((a, b) => b.temporal_score - a.temporal_score)
            .map((finding) => ({ finding, service: scan.target_name }))}
        />
      </section>

      {scan.chains.length > 0 && (
        <section className={styles.section}>
          <h4>Attack chains</h4>
          <AttackChainsList chains={scan.chains} findings={scan.issues} />
        </section>
      )}
    </div>
  );
}
