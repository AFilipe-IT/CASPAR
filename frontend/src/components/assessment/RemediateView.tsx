import { useState } from "react";
import { Wrench, FileWarning, Terminal } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge, severityTone } from "@/components/ui/Badge";
import { Table } from "@/components/ui/Table";
import { EmptyState } from "@/components/ui/EmptyState";
import { SkeletonBlock } from "@/components/ui/Skeleton";
import { useFixPreview } from "@/api/manage";
import { ApiError } from "@/api/client";
import { scoreToSeverity } from "@/lib/severity";
import styles from "@/pages/AssessmentPage.module.css";
import remediate from "./RemediateView.module.css";

/**
 * Remediation preview.
 *
 * Read-only by design: this renders the patch CVM would apply but never writes
 * it. Applying stays a CLI operation, because `caspar fix --in-place` rewrites
 * a real config file with no backup and this API's auth is a no-op unless
 * CASPAR_API_KEY is set. The command to run is shown instead, so the operator
 * reviews the diff here and applies it deliberately.
 */
export function RemediateView() {
  const [path, setPath] = useState("");
  const [live, setLive] = useState(false);
  const fix = useFixPreview();

  function handlePreview() {
    if (path.trim()) fix.mutate({ input_path: path.trim(), live });
  }

  const result = fix.data;

  return (
    <>
      <Card
        title="Preview remediation"
        subtitle="See the exact changes that would fix a configuration — nothing is written."
      >
        <div className={styles.field}>
          <span className={styles.label}>Configuration path (on the server)</span>
          <input
            className={styles.input}
            value={path}
            placeholder="/etc/nginx/nginx.conf"
            onChange={(e) => setPath(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handlePreview()}
          />
        </div>

        <label className={styles.checkboxRow}>
          <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
          Resolve as a live service name rather than a file path
        </label>

        <Button
          variant="primary"
          icon={<Wrench size={15} />}
          disabled={!path.trim() || fix.isPending}
          onClick={handlePreview}
        >
          {fix.isPending ? "Analysing…" : "Preview fix"}
        </Button>

        {fix.isError && (
          <div className={styles.error} style={{ marginTop: "var(--sp-4)" }}>
            {fix.error instanceof ApiError ? fix.error.message : "Could not build a fix plan."}
          </div>
        )}
      </Card>

      {fix.isPending && (
        <div style={{ marginTop: "var(--sp-6)" }}>
          <SkeletonBlock rows={4} />
        </div>
      )}

      {result && (
        <div style={{ marginTop: "var(--sp-6)" }}>
          <Card
            title="Automatic edits"
            subtitle={
              result.edits.length === 0
                ? "No line can be rewritten automatically."
                : `${result.edits.length} line${result.edits.length === 1 ? "" : "s"} in ${result.target_name ?? "this configuration"} would be rewritten.`
            }
          >
            {result.edits.length === 0 ? (
              <EmptyState
                title="Nothing to rewrite"
                description="Either the configuration is already compliant, or every finding needs a human decision — check the manual steps below."
              />
            ) : (
              <>
                <div className={remediate.diff}>
                  {result.edits.map((e, i) => (
                    <div key={`${e.file}:${e.line_number}:${i}`} className={remediate.hunk}>
                      <div className={remediate.hunkHead}>
                        {e.file}:{e.line_number}
                        <Badge tone="neutral">{e.directive}</Badge>
                      </div>
                      <pre className={remediate.line} data-kind="removed">
                        <span className={remediate.sign}>-</span>
                        {e.old_line}
                      </pre>
                      <pre className={remediate.line} data-kind="added">
                        <span className={remediate.sign}>+</span>
                        {e.new_line}
                      </pre>
                    </div>
                  ))}
                </div>

                <div className={remediate.applyNote}>
                  <Terminal size={15} />
                  <div>
                    <strong>Nothing was written.</strong> Review the diff above, then apply it
                    from a shell on the server:
                    <code className={remediate.cmd}>
                      caspar fix {live ? "--live " : ""}
                      {path.trim()} --in-place
                    </code>
                    The file is overwritten with no backup, so take one first if you need it.
                  </div>
                </div>
              </>
            )}
          </Card>
        </div>
      )}

      {result && result.manual.length > 0 && (
        <div style={{ marginTop: "var(--sp-6)" }}>
          <Card
            title="Manual steps"
            subtitle="Findings CVM will not rewrite for you — each needs a decision about your environment."
          >
            <Table
              rows={result.manual}
              rowKey={(m) => m.directive}
              columns={[
                {
                  key: "directive",
                  header: "Directive",
                  width: "22%",
                  render: (m) => (
                    <span className={remediate.mono}>
                      <FileWarning size={13} /> {m.directive}
                    </span>
                  ),
                },
                {
                  key: "good_value",
                  header: "Recommended",
                  width: "18%",
                  render: (m) => <span className={remediate.mono}>{m.good_value || "—"}</span>,
                },
                {
                  key: "score",
                  header: "Score",
                  width: "10%",
                  // Via scoreToSeverity so a 7.5 here reads as the same band it
                  // does on a scan result, rather than inventing thresholds.
                  render: (m) => (
                    <Badge tone={severityTone(scoreToSeverity(m.score))}>
                      {m.score.toFixed(1)}
                    </Badge>
                  ),
                },
                {
                  key: "why",
                  header: "Why",
                  render: (m) => <span>{m.recommendation || m.reason}</span>,
                },
              ]}
            />
          </Card>
        </div>
      )}
    </>
  );
}
