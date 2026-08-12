import { useState } from "react";
import { ArrowRight, GitCompare, ShieldCheck, ShieldAlert } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { KpiTile } from "@/components/dashboard/KpiTile";
import { EmptyState } from "@/components/ui/EmptyState";
import { SkeletonBlock } from "@/components/ui/Skeleton";
import { useScans } from "@/api/scans";
import { useDiffScans } from "@/api/reports";
import styles from "@/pages/AssessmentPage.module.css";

export function CompareView() {
  const { data: scans } = useScans({ limit: 100 });
  const [oldId, setOldId] = useState("");
  const [newId, setNewId] = useState("");
  const diff = useDiffScans();

  function label(id: string): string {
    const s = scans?.find((x) => x.id === id);
    return s ? `${s.target_name} · ${new Date(s.timestamp).toLocaleString()}` : id;
  }

  function handleCompare() {
    if (oldId && newId) diff.mutate({ oldId, newId });
  }

  return (
    <Card title="Compare assessments" subtitle="See what changed between two persisted assessments.">
      <div className={styles.compareRow}>
        <div className={styles.field}>
          <span className={styles.label}>Baseline</span>
          <select className={styles.select} value={oldId} onChange={(e) => setOldId(e.target.value)}>
            <option value="">Select an assessment…</option>
            {scans?.map((s) => (
              <option key={s.id} value={s.id}>{label(s.id)}</option>
            ))}
          </select>
        </div>
        <div className={styles.compareArrow}>
          <ArrowRight size={18} />
        </div>
        <div className={styles.field}>
          <span className={styles.label}>Compare to</span>
          <select className={styles.select} value={newId} onChange={(e) => setNewId(e.target.value)}>
            <option value="">Select an assessment…</option>
            {scans?.map((s) => (
              <option key={s.id} value={s.id}>{label(s.id)}</option>
            ))}
          </select>
        </div>
      </div>

      <Button variant="primary" icon={<GitCompare size={15} />} disabled={!oldId || !newId} onClick={handleCompare}>
        Compare
      </Button>

      {diff.isPending && <div style={{ marginTop: "var(--sp-5)" }}><SkeletonBlock rows={3} /></div>}

      {diff.data && (
        <div className={styles.diffGrid} style={{ marginTop: "var(--sp-5)" }}>
          {/* Aqui a cor não é identidade, é resultado: piorar pinta de
              vermelho, resolver pinta de verde. Daí variar com os dados,
              ao contrário dos indicadores do painel. */}
          <KpiTile label="Score change" value={`${diff.data.old_score.toFixed(1)} → ${diff.data.new_score.toFixed(1)}`}
            icon={<GitCompare size={20} />}
            delta={diff.data.score_delta}
            deltaLabel="pts"
            tone={diff.data.score_delta > 0 ? "red" : "teal"}
          />
          <KpiTile label="Resolved issues" value={(diff.data.resolved ?? []).length} icon={<ShieldCheck size={20} />} tone="teal" />
          <KpiTile label="New issues" value={(diff.data.new_issues ?? []).length} icon={<ShieldAlert size={20} />}
            tone={(diff.data.new_issues ?? []).length > 0 ? "red" : "teal"} />
        </div>
      )}

      {!diff.data && !diff.isPending && (
        <div style={{ marginTop: "var(--sp-5)" }}>
          <EmptyState icon={<GitCompare size={22} />} title="Select two assessments to compare" />
        </div>
      )}
    </Card>
  );
}
