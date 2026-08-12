import { FileSearch } from "lucide-react";
import { Badge, severityTone } from "@/components/ui/Badge";
import { Table, type Column } from "@/components/ui/Table";
import { EmptyState } from "@/components/ui/EmptyState";
import { scoreToSeverity } from "@/lib/severity";
import type { Misconfiguration } from "@/api/types";

interface RuleTableProps {
  rules: Misconfiguration[];
  onSelect: (rule: Misconfiguration) => void;
}

export function RuleTable({ rules, onSelect }: RuleTableProps) {
  if (rules.length === 0) {
    return <EmptyState icon={<FileSearch size={22} />} title="No rules found for this benchmark" />;
  }

  const columns: Column<Misconfiguration>[] = [
    { key: "directive", header: "Directive", render: (r) => r.directive },
    { key: "bad_value", header: "Insecure value", render: (r) => r.bad_value || "—" },
    {
      key: "severity",
      header: "Severity",
      width: "110px",
      render: (r) => {
        const sev = scoreToSeverity(r.base_score);
        return <Badge tone={severityTone(sev)}>{sev}</Badge>;
      },
    },
    { key: "cis_section", header: "CIS section", width: "120px", render: (r) => r.cis_section || "—" },
  ];

  return <Table columns={columns} rows={rules} rowKey={(r) => r.id} onRowClick={onSelect} capped />;
}
