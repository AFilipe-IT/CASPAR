import { useCallback, useState } from "react";
import { Download, Package, Puzzle } from "lucide-react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { SkeletonBlock } from "@/components/ui/Skeleton";
import { JobConsole } from "@/components/jobs/JobConsole";
import { useInstallPlugin, useInvalidateAfterJob, usePlugins } from "@/api/jobs";
import styles from "./JobsShared.module.css";

type Tab = "installed" | "available" | "manual";

export function PluginsPage() {
  const [tab, setTab] = useState<Tab>("installed");
  const [activeJobId, setActiveJobId] = useState<string | undefined>();
  const [source, setSource] = useState("");
  const [manual, setManual] = useState("");
  const [model, setModel] = useState("qwen2.5:14b");
  const [noLlm, setNoLlm] = useState(false);
  const [dryRun, setDryRun] = useState(false);

  const { data, isLoading, refetch } = usePlugins();
  const installPlugin = useInstallPlugin();
  const invalidateAfterJob = useInvalidateAfterJob();

  const handleFinished = useCallback(() => {
    invalidateAfterJob();
    refetch();
  }, [invalidateAfterJob, refetch]);

  function install(params: { source: string; manual?: string; no_llm?: boolean; dry_run?: boolean }) {
    installPlugin.mutate(
      { model, ...params },
      { onSuccess: (res) => setActiveJobId(res.job_id) },
    );
  }

  return (
    <>
      <PageHeader
        title="Plugins"
        description="Manage the technologies CVM can assess — install from the catalog or a local benchmark."
      />

      <div className={styles.tabs}>
        <button
          className={[styles.tab, tab === "installed" ? styles.tabActive : ""].join(" ")}
          onClick={() => setTab("installed")}
        >
          Installed{data ? ` (${data.installed.length})` : ""}
        </button>
        <button
          className={[styles.tab, tab === "available" ? styles.tabActive : ""].join(" ")}
          onClick={() => setTab("available")}
        >
          Available{data ? ` (${data.available.length})` : ""}
        </button>
        <button
          className={[styles.tab, tab === "manual" ? styles.tabActive : ""].join(" ")}
          onClick={() => setTab("manual")}
        >
          From benchmark file
        </button>
      </div>

      {tab === "installed" && (
        <Card title="Installed plugins" subtitle="Technologies this server can assess right now.">
          {isLoading ? (
            <SkeletonBlock rows={4} />
          ) : data && data.installed.length > 0 ? (
            <div className={styles.pluginGrid}>
              {data.installed.map((p) => (
                <div key={p.name} className={styles.pluginCard}>
                  <span className={styles.pluginName}>{p.display_name}</span>
                  <span className={styles.pluginMeta}>{p.benchmark_source}</span>
                  <div className={styles.pluginFoot}>
                    <code className={styles.pluginMeta}>{p.name}</code>
                    <Badge tone="ok">v{p.version}</Badge>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState icon={<Puzzle size={22} />} title="No plugins installed" />
          )}
        </Card>
      )}

      {tab === "available" && (
        <Card
          title="Available from catalog"
          subtitle="Public benchmarks CVM can fetch and install automatically (via stigviewer.com)."
        >
          {isLoading ? (
            <SkeletonBlock rows={4} />
          ) : data && data.available.length > 0 ? (
            <div className={styles.pluginGrid}>
              {data.available.map((p) => (
                <div key={p.service} className={styles.pluginCard}>
                  <span className={styles.pluginName}>{p.service_name}</span>
                  <span className={styles.pluginMeta}>
                    {p.sources.map((s) => s.type).join(", ") || "no source"}
                  </span>
                  <div className={styles.pluginFoot}>
                    <code className={styles.pluginMeta}>{p.service}</code>
                    <Button
                      icon={<Download size={14} />}
                      disabled={installPlugin.isPending}
                      onClick={() => install({ source: p.service })}
                    >
                      Install
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState icon={<Package size={22} />} title="Everything in the catalog is installed" />
          )}
        </Card>
      )}

      {tab === "manual" && (
        <Card
          title="Install from a benchmark file"
          subtitle="Point at a CIS Benchmark PDF or DISA STIG XCCDF already on the server."
        >
          <div className={styles.form}>
            <div className={styles.field}>
              <label className={styles.label} htmlFor="source">
                Benchmark path
              </label>
              <input
                id="source"
                className={styles.input}
                placeholder="/benchmarks/CIS_nginx.pdf"
                value={source}
                onChange={(e) => setSource(e.target.value)}
              />
            </div>

            <div className={styles.field}>
              <label className={styles.label} htmlFor="manual">
                Service manual (optional)
              </label>
              <input
                id="manual"
                className={styles.input}
                placeholder="https://nginx.org/en/docs/dirindex.pdf"
                value={manual}
                onChange={(e) => setManual(e.target.value)}
              />
              <span className={styles.hint}>
                A local path or URL, ingested into the plugin's knowledge base at install
                time and retrieved on every future scan.
              </span>
            </div>

            <div className={styles.field}>
              <label className={styles.label} htmlFor="pmodel">
                LLM model
              </label>
              <input
                id="pmodel"
                className={styles.input}
                value={model}
                onChange={(e) => setModel(e.target.value)}
              />
            </div>

            <label className={styles.checkboxRow}>
              <input type="checkbox" checked={noLlm} onChange={(e) => setNoLlm(e.target.checked)} />
              Heuristic extraction only — skip the LLM for ambiguous controls
            </label>

            <label className={styles.checkboxRow}>
              <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />
              Dry run — show the extracted spec without installing
            </label>

            {installPlugin.isError && (
              <div className={styles.error}>{(installPlugin.error as Error).message}</div>
            )}

            <div className={styles.actions}>
              <Button
                variant="primary"
                icon={<Download size={16} />}
                disabled={!source || installPlugin.isPending}
                onClick={() =>
                  install({
                    source,
                    manual: manual || undefined,
                    no_llm: noLlm,
                    dry_run: dryRun,
                  })
                }
              >
                {installPlugin.isPending ? "Starting…" : "Install plugin"}
              </Button>
            </div>
          </div>
        </Card>
      )}

      <Card title="Install output" subtitle="Streams while an install job runs.">
        <JobConsole
          jobId={activeJobId}
          onFinished={handleFinished}
          placeholder="Install a plugin to stream its output here."
        />
      </Card>
    </>
  );
}
