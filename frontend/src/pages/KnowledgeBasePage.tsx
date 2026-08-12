import { useMemo, useState } from "react";
import { Library, ListChecks, Fingerprint, Link2 } from "lucide-react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card } from "@/components/ui/Card";
import { SkeletonBlock } from "@/components/ui/Skeleton";
import { BenchmarkList } from "@/components/knowledge/BenchmarkList";
import { RuleTable } from "@/components/knowledge/RuleTable";
import { RuleDetailPanel } from "@/components/knowledge/RuleDetailPanel";
import { ChainList } from "@/components/knowledge/ChainList";
import { KpiTile } from "@/components/dashboard/KpiTile";
import { useBenchmarks, useTargetRules, useTargetChains } from "@/api/knowledge";
import type { Misconfiguration } from "@/api/types";
import styles from "./KnowledgeBasePage.module.css";

type Tab = "rules" | "chains";

export function KnowledgeBasePage() {
  const { data: benchmarks, isLoading: benchmarksLoading } = useBenchmarks();
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("rules");
  const [selectedRule, setSelectedRule] = useState<Misconfiguration | null>(null);

  const activeTarget = selected ?? benchmarks?.[0]?.name;

  const { data: rules, isLoading: rulesLoading } = useTargetRules(
    tab === "rules" ? activeTarget : undefined,
  );
  const { data: chains, isLoading: chainsLoading } = useTargetChains(
    tab === "chains" ? activeTarget : undefined,
  );

  const ccssVectorCount = useMemo(() => new Set((rules ?? []).map((r) => `${r.ac}${r.c}${r.i}${r.a}`)).size, [
    rules,
  ]);

  return (
    <>
      <PageHeader title="Knowledge Base" description="Explore benchmarks, rules, and CCSS vectors — read-only." />

      <div className="grid-kpi">
        {/* Quatro ícones iguais não distinguiam nada: cada indicador leva
            agora o seu glifo e a sua cor, como no painel. */}
        <KpiTile label="Benchmarks" value={benchmarks?.length ?? 0} icon={<Library size={20} />} tone="blue" />
        <KpiTile label="Rules in view" value={rules?.length ?? 0} icon={<ListChecks size={20} />} tone="teal" />
        <KpiTile label="Distinct CCSS vectors" value={ccssVectorCount} icon={<Fingerprint size={20} />} tone="orange" />
        <KpiTile label="Attack chains" value={chains?.length ?? 0} icon={<Link2 size={20} />} tone="purple" />
      </div>

      <div className={styles.layout}>
        <Card title="Benchmarks">
          {benchmarksLoading ? <SkeletonBlock rows={4} /> : (
            <BenchmarkList
              benchmarks={benchmarks ?? []}
              selected={activeTarget ?? null}
              onSelect={(name) => {
                setSelected(name);
                setSelectedRule(null);
              }}
            />
          )}
        </Card>

        <Card
          title={activeTarget ? activeTarget : "Select a benchmark"}
          action={
            <div className={styles.tabs}>
              <button
                className={[styles.tab, tab === "rules" ? styles.tabActive : ""].join(" ")}
                onClick={() => setTab("rules")}
              >
                Rules
              </button>
              <button
                className={[styles.tab, tab === "chains" ? styles.tabActive : ""].join(" ")}
                onClick={() => setTab("chains")}
              >
                Attack chains
              </button>
            </div>
          }
        >
          {tab === "rules" && (rulesLoading ? <SkeletonBlock rows={6} /> : (
            <RuleTable rules={rules ?? []} onSelect={setSelectedRule} />
          ))}
          {tab === "chains" && (chainsLoading ? <SkeletonBlock rows={4} /> : (
            <ChainList chains={chains ?? []} />
          ))}
        </Card>

        {selectedRule && (
          <Card>
            <RuleDetailPanel rule={selectedRule} onClose={() => setSelectedRule(null)} />
          </Card>
        )}
      </div>
    </>
  );
}
