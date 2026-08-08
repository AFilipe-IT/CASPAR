import { useState } from "react";
import { Moon, Sun, Stethoscope, CheckCircle2, RotateCcw, ShieldOff } from "lucide-react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Table } from "@/components/ui/Table";
import { EmptyState } from "@/components/ui/EmptyState";
import { SkeletonBlock } from "@/components/ui/Skeleton";
import { SuppressionsPanel } from "@/components/settings/SuppressionsPanel";
import { useDoctor, usePromoteStats, useSettings } from "@/api/manage";
import type { PromoteStatsRow } from "@/api/types";
import { useTheme } from "@/context/ThemeContext";
import { usePreferences, type EnvProfile } from "@/context/PreferencesContext";
import styles from "./SettingsPage.module.css";

function ConfigRow({ label, value }: { label: string; value: string | null }) {
  return (
    <div className={styles.configRow}>
      <span className={styles.configKey}>{label}</span>
      <span className={styles.configValue}>
        {value ?? <span className={styles.unset}>not set</span>}
      </span>
    </div>
  );
}

function EffectiveConfig() {
  const { data, isLoading, isError } = useSettings();

  if (isLoading) return <SkeletonBlock />;
  if (isError || !data) {
    return <EmptyState title="Could not read server settings" description="The API did not respond." />;
  }

  return (
    <div>
      {/* The JSON field stays `caspar_version` — the REST contract is
          additive-only — but the label the operator reads says CVM. */}
      <ConfigRow label="CVM version" value={data.caspar_version} />
      <ConfigRow label="Database" value={data.db_path} />
      <ConfigRow label="Plugins directory" value={data.plugins_dir} />
      <ConfigRow label="Data directory" value={data.data_dir} />
      <div className={styles.configRow}>
        <span className={styles.configKey}>API key</span>
        <span className={styles.configValue}>
          {/* The endpoint reports only whether a key is enforced — the value
              is never sent to the browser. */}
          <Badge tone={data.api_key_required ? "ok" : "neutral"}>
            {data.api_key_required ? "Required" : "Not enforced"}
          </Badge>
        </span>
      </div>
      <div className={styles.configRow}>
        <span className={styles.configKey}>Registered plugins</span>
        <span className={styles.pluginTags}>
          {data.registered_plugins.length === 0 ? (
            <span className={styles.unset}>none</span>
          ) : (
            data.registered_plugins.map((p) => (
              <Badge key={p} tone="accent">
                {p}
              </Badge>
            ))
          )}
        </span>
      </div>
    </div>
  );
}

function AssessmentPreferences() {
  const { preferences, setPreferences, resetPreferences } = usePreferences();

  return (
    <>
      <label className={styles.field}>
        <span className={styles.label}>Default environment profile</span>
        <select
          className={styles.select}
          value={preferences.envProfile}
          onChange={(e) => setPreferences({ envProfile: e.target.value as EnvProfile })}
        >
          <option value="">No default</option>
          <option value="production">Production</option>
          <option value="internal">Internal</option>
          <option value="dev">Development</option>
        </select>
      </label>

      <label className={styles.field}>
        <span className={styles.label}>Default CI threshold</span>
        <input
          className={styles.input}
          type="number"
          min={0}
          max={10}
          step={0.1}
          placeholder="No gate"
          value={preferences.threshold}
          onChange={(e) => setPreferences({ threshold: e.target.value })}
        />
        <span className={styles.hint}>
          Pre-fills the assessment form. Leave empty to run without a pass/fail gate.
        </span>
      </label>

      <Button variant="ghost" icon={<RotateCcw size={15} />} onClick={resetPreferences}>
        Reset to defaults
      </Button>
    </>
  );
}

function DoctorPanel() {
  const [strict, setStrict] = useState(false);
  const { data, isLoading, isError, refetch, isFetching } = useDoctor(strict);

  return (
    <>
      <div className={styles.doctorHead}>
        <label className={styles.checkRow}>
          <input type="checkbox" checked={strict} onChange={(e) => setStrict(e.target.checked)} />
          Strict mode (also audits rule narratives)
        </label>
        <Button variant="ghost" onClick={() => refetch()} disabled={isFetching}>
          {isFetching ? "Checking…" : "Re-run check"}
        </Button>
      </div>

      {isLoading && <SkeletonBlock />}
      {isError && <EmptyState title="Could not run the check" description="The API did not respond." />}

      {data && (
        <>
          <div className={styles.doctorHead}>
            <Badge tone={data.errors > 0 ? "Critical" : data.warnings > 0 ? "Medium" : "ok"}>
              {data.errors > 0 ? "Errors found" : data.warnings > 0 ? "Warnings only" : "Healthy"}
            </Badge>
            <span className={styles.counts}>
              <span>{data.errors} errors</span>
              <span>{data.warnings} warnings</span>
            </span>
          </div>

          {data.findings.length === 0 ? (
            <EmptyState
              icon={<CheckCircle2 size={24} />}
              title="No integrity problems"
              description="Every knowledge-base check passed."
            />
          ) : (
            <div className={styles.findingList}>
              {data.findings.map((f, i) => (
                <div key={i} className={[styles.finding, styles[f.severity]].filter(Boolean).join(" ")}>
                  <span className={styles.stripe} aria-hidden="true" />
                  <span className={styles.findingMeta}>
                    {f.severity} · {f.category}
                  </span>
                  <span className={styles.findingMessage}>{f.message}</span>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </>
  );
}

const PROMOTE_COLUMNS = [
  { key: "target", header: "Target", render: (r: PromoteStatsRow) => r.target },
  { key: "rules", header: "Rules", render: (r: PromoteStatsRow) => r.rules },
  { key: "promoted", header: "Promoted", render: (r: PromoteStatsRow) => r.promoted },
  {
    key: "needs_review",
    header: "Needs review",
    render: (r: PromoteStatsRow) =>
      r.needs_review > 0 ? <Badge tone="Medium">{r.needs_review}</Badge> : r.needs_review,
  },
];

function PromoteScoreboard() {
  const { data, isLoading } = usePromoteStats();

  if (isLoading) return <SkeletonBlock />;
  if (!data || data.length === 0) {
    return <EmptyState title="No knowledge yet" description="Build a benchmark to populate the knowledge base." />;
  }
  return <Table columns={PROMOTE_COLUMNS} rows={data} rowKey={(r) => r.target} />;
}

export function SettingsPage() {
  const { theme, toggleTheme } = useTheme();

  return (
    <>
      <PageHeader title="Settings" description="Console preferences and environment configuration." />

      <Card title="Appearance" subtitle="Applies instantly, saved to this browser.">
        <Button icon={theme === "dark" ? <Sun size={16} /> : <Moon size={16} />} onClick={toggleTheme}>
          Switch to {theme === "dark" ? "light" : "dark"} theme
        </Button>
      </Card>

      <Card title="Assessment defaults" subtitle="Pre-fills the assessment form. Saved to this browser, not the server.">
        <AssessmentPreferences />
      </Card>

      <Card
        title="Environment"
        subtitle="How this server was launched. Read-only — changing server paths over HTTP is a separate, security-relevant decision."
      >
        <EffectiveConfig />
      </Card>

      <Card
        title="Accepted risks"
        subtitle="Findings excluded from threshold decisions, each with the reason it was accepted — the same file `caspar suppress` writes."
        icon={<ShieldOff size={18} />}
      >
        <SuppressionsPanel />
      </Card>

      <Card
        title="Knowledge base health"
        subtitle="The same checks as `caspar doctor`."
        icon={<Stethoscope size={18} />}
      >
        <DoctorPanel />
      </Card>

      <Card title="Learning loop" subtitle="Rules promoted from unknown-directive assessment, per target.">
        <PromoteScoreboard />
      </Card>
    </>
  );
}
