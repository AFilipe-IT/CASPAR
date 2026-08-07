import { useState } from "react";
import { History } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge, severityTone } from "@/components/ui/Badge";
import { Table, type Column } from "@/components/ui/Table";
import { EmptyState } from "@/components/ui/EmptyState";
import { SkeletonBlock } from "@/components/ui/Skeleton";
import { useScans } from "@/api/scans";
import type { ScanListItem } from "@/api/types";
import styles from "@/pages/AssessmentPage.module.css";

function formatTimestamp(ts: string): string {
  try {
    return new Date(ts).toLocaleString(undefined, {
      year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
    });
  } catch {
    return ts;
  }
}

export function HistoryView({ onSelect }: { onSelect?: (scan: ScanListItem) => void }) {
  const [target, setTarget] = useState("");
  const [severityMin, setSeverityMin] = useState("");

  const { data: scans, isLoading } = useScans({
    target: target || undefined,
    severity_min: severityMin ? Number(severityMin) : undefined,
    limit: 100,
  });

  const columns: Column<ScanListItem>[] = [
    { key: "timestamp", header: "Assessed", render: (s) => formatTimestamp(s.timestamp) },
    { key: "target", header: "Service", render: (s) => s.target_name },
    { key: "input", header: "Source", render: (s) => s.input_path },
    {
      key: "severity", header: "Severity", width: "100px",
      render: (s) => <Badge tone={severityTone(s.severity)}>{s.severity}</Badge>,
    },
    { key: "score", header: "Score", width: "80px", render: (s) => s.global_temporal_score.toFixed(1) },
    { key: "issues", header: "Issues", width: "80px", render: (s) => s.total_issues },
    { key: "chains", header: "Chains", width: "80px", render: (s) => s.total_chains },
  ];

  return (
    <Card title="Assessment history" subtitle="Every persisted assessment, filterable by service and severity.">
      <div className={styles.filterRow}>
        <input
          className={styles.input}
          placeholder="Filter by service name…"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
        />
        <select className={styles.select} value={severityMin} onChange={(e) => setSeverityMin(e.target.value)}>
          <option value="">Any severity</option>
          <option value="9">Critical only (&ge;9)</option>
          <option value="7">High and up (&ge;7)</option>
          <option value="4">Medium and up (&ge;4)</option>
        </select>
      </div>

      {isLoading ? <SkeletonBlock rows={6} /> : scans && scans.length > 0 ? (
        <Table columns={columns} rows={scans} rowKey={(s) => s.id} onRowClick={onSelect} />
      ) : (
        <EmptyState icon={<History size={22} />} title="No assessments match these filters" />
      )}
    </Card>
  );
}
