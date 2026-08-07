import { Badge, severityTone } from "@/components/ui/Badge";
import { Table, type Column } from "@/components/ui/Table";
import { EmptyState } from "@/components/ui/EmptyState";
import { ShieldOff } from "lucide-react";
import type { Misconfiguration } from "@/api/types";

interface FindingRow {
  finding: Misconfiguration;
  service: string;
}

function severityFromScore(score: number): string {
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  return "Low";
}

export function FindingsTable({ rows }: { rows: FindingRow[] }) {
  if (rows.length === 0) {
    return <EmptyState icon={<ShieldOff size={22} />} title="No findings recorded yet" />;
  }

  const columns: Column<FindingRow>[] = [
    {
      key: "severity",
      header: "Severity",
      width: "110px",
      render: (r) => {
        const sev = severityFromScore(r.finding.temporal_score);
        return <Badge tone={severityTone(sev)}>{sev}</Badge>;
      },
    },
    { key: "finding", header: "Finding", render: (r) => r.finding.directive },
    { key: "service", header: "Service", render: (r) => r.service },
  ];

  return <Table columns={columns} rows={rows} rowKey={(r) => r.finding.id} />;
}
