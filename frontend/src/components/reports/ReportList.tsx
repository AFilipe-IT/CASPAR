import { FileText } from "lucide-react";
import { Badge, severityTone } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Table, type Column } from "@/components/ui/Table";
import { EmptyState } from "@/components/ui/EmptyState";
import type { ScanListItem } from "@/api/types";
import { Eye, Download, Trash2 } from "lucide-react";

interface ReportListProps {
  scans: ScanListItem[];
  onPreview: (scan: ScanListItem) => void;
  onDownload: (scan: ScanListItem) => void;
  onDelete: (scan: ScanListItem) => void;
  downloadingId: string | null;
  deletingId: string | null;
}

function formatTimestamp(ts: string): string {
  try {
    return new Date(ts).toLocaleString(undefined, {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return ts;
  }
}

export function ReportList({
  scans, onPreview, onDownload, onDelete, downloadingId, deletingId,
}: ReportListProps) {
  if (scans.length === 0) {
    return (
      <EmptyState
        icon={<FileText size={22} />}
        title="No assessments to report on yet"
        description="Reports are generated on demand from persisted assessments."
      />
    );
  }

  const columns: Column<ScanListItem>[] = [
    { key: "timestamp", header: "Assessed", render: (s) => formatTimestamp(s.timestamp) },
    { key: "target", header: "Service", render: (s) => s.target_name },
    { key: "input", header: "Source", render: (s) => s.input_path },
    {
      key: "severity",
      header: "Severity",
      width: "100px",
      render: (s) => <Badge tone={severityTone(s.severity)}>{s.severity}</Badge>,
    },
    { key: "score", header: "Score", width: "70px", render: (s) => s.global_temporal_score.toFixed(1) },
    {
      key: "actions",
      header: "",
      width: "210px",
      render: (s) => (
        <div style={{ display: "flex", gap: "8px" }}>
          <Button variant="ghost" icon={<Eye size={14} />} onClick={() => onPreview(s)}>
            Preview
          </Button>
          <Button
            variant="ghost"
            icon={<Download size={14} />}
            disabled={downloadingId === s.id}
            onClick={() => onDownload(s)}
          >
            {downloadingId === s.id ? "…" : "HTML"}
          </Button>
          {/* Apagar é irreversível e a linha não diz que a avaliação também
              alimenta a Home e as tendências — daí a confirmação nomear o que
              desaparece, em vez de perguntar só "tem a certeza?". */}
          <Button
            variant="ghost"
            icon={<Trash2 size={14} />}
            disabled={deletingId === s.id}
            title="Delete this assessment from the database"
            onClick={() => {
              if (window.confirm(
                `Delete the ${s.target_name} assessment of ${s.input_path}?\n\n`
                + "It is removed from the database for good, and stops "
                + "counting in the Home totals and the trends.",
              )) onDelete(s);
            }}
          >
            {deletingId === s.id ? "…" : "Delete"}
          </Button>
        </div>
      ),
    },
  ];

  return <Table columns={columns} rows={scans} rowKey={(s) => s.id} />;
}
