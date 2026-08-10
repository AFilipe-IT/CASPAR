import { useState } from "react";
import { ArrowRight, GitCompare } from "lucide-react";
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
          <KpiTile label="Score change" value={`${diff.data.old_score.toFixed(1)} → ${diff.data.new_score.toFixed(1)}`}
            icon={<GitCompare size={18} />}
            delta={diff.data.score_delta}
            deltaLabel="pts"
            tone={diff.data.score_delta > 0 ? "critical" : "neutral"}
          />
          <KpiTile label="Resolved issues" value={(diff.data.resolved ?? []).length} icon={<GitCompare size={18} />} />
          <KpiTile label="New issues" value={(diff.data.new_issues ?? []).length} icon={<GitCompare size={18} />}
            tone={(diff.data.new_issues ?? []).length > 0 ? "critical" : "neutral"} />
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
