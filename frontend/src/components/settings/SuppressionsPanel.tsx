import { useState } from "react";
import { ShieldOff, Trash2, Plus } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Table } from "@/components/ui/Table";
import { EmptyState } from "@/components/ui/EmptyState";
import { SkeletonBlock } from "@/components/ui/Skeleton";
import {
  useSuppressions,
  useCreateSuppression,
  useDeleteSuppression,
} from "@/api/manage";
import { ApiError } from "@/api/client";
import { usePreferences } from "@/context/PreferencesContext";
import type { SuppressionItem } from "@/api/types";
import styles from "@/pages/SettingsPage.module.css";
import panel from "./SuppressionsPanel.module.css";

/**
 * Accepted risks: directives deliberately excluded from threshold decisions.
 *
 * The suppression file is a path on the *server*. The API refuses to guess it
 * (the CLI's cwd-relative default is meaningless for a long-running process),
 * so it is asked for here once and remembered in browser preferences.
 */
export function SuppressionsPanel() {
  const { preferences, setPreferences } = usePreferences();
  const suppressFile = preferences.suppressFile;

  const list = useSuppressions(suppressFile);
  const create = useCreateSuppression(suppressFile);
  const remove = useDeleteSuppression(suppressFile);

  const [directive, setDirective] = useState("");
  const [reason, setReason] = useState("");
  const [badValue, setBadValue] = useState("");

  const canSubmit = Boolean(suppressFile && directive.trim() && reason.trim());

  function handleCreate() {
    if (!canSubmit) return;
    create.mutate(
      {
        directive: directive.trim(),
        reason: reason.trim(),
        bad_value: badValue.trim(),
      },
      {
        onSuccess: () => {
          setDirective("");
          setReason("");
          setBadValue("");
        },
      },
    );
  }

  const columns = [
    {
      key: "directive",
      header: "Directive",
      width: "24%",
      render: (s: SuppressionItem) => <span className={panel.mono}>{s.directive}</span>,
    },
    {
      key: "bad_value",
      header: "Value",
      width: "16%",
      render: (s: SuppressionItem) =>
        s.bad_value ? (
          <span className={panel.mono}>{s.bad_value}</span>
        ) : (
          // No value means the whole directive is accepted, not just one
          // setting of it — worth saying rather than showing a blank cell.
          <Badge tone="neutral">any value</Badge>
        ),
    },
    { key: "reason", header: "Reason", render: (s: SuppressionItem) => s.reason },
    {
      key: "date",
      header: "Accepted",
      width: "12%",
      render: (s: SuppressionItem) => s.date || "—",
    },
    {
      key: "actions",
      header: "",
      width: "1%",
      render: (s: SuppressionItem) => (
        <Button
          variant="ghost"
          icon={<Trash2 size={14} />}
          disabled={remove.isPending}
          onClick={() => remove.mutate(s.directive)}
          aria-label={`Withdraw suppression for ${s.directive}`}
        >
          Withdraw
        </Button>
      ),
    },
  ];

  return (
    <>
      <label className={styles.field}>
        <span className={styles.label}>Suppression file (path on the server)</span>
        <input
          className={styles.input}
          value={suppressFile}
          placeholder="/etc/cvm/.caspar-suppress.json"
          onChange={(e) => setPreferences({ suppressFile: e.target.value })}
        />
        <span className={styles.hint}>
          Saved to this browser. The API has no default: a path relative to the server's
          working directory would mean something different for every deployment.
        </span>
      </label>

      {!suppressFile ? (
        <EmptyState
          icon={<ShieldOff size={24} />}
          title="No suppression file set"
          description="Enter the path above to view and manage accepted risks."
        />
      ) : (
        <>
          {list.isLoading && <SkeletonBlock />}

          {list.isError && (
            <div className={styles.error}>
              {list.error instanceof ApiError
                ? list.error.message
                : "Could not read that suppression file."}
            </div>
          )}

          {list.data &&
            (list.data.length === 0 ? (
              <EmptyState
                title="No accepted risks"
                description="Every finding in this file counts against your thresholds."
              />
            ) : (
              <Table columns={columns} rows={list.data} rowKey={(s) => s.directive} />
            ))}

          <div className={panel.form}>
            <span className={panel.formTitle}>Accept a risk</span>

            <div className={panel.formRow}>
              <label className={styles.field}>
                <span className={styles.label}>Directive</span>
                <input
                  className={styles.input}
                  value={directive}
                  placeholder="ServerTokens"
                  onChange={(e) => setDirective(e.target.value)}
                />
              </label>

              <label className={styles.field}>
                <span className={styles.label}>Value (optional)</span>
                <input
                  className={styles.input}
                  value={badValue}
                  placeholder="Leave empty to accept any value"
                  onChange={(e) => setBadValue(e.target.value)}
                />
              </label>
            </div>

            <label className={styles.field}>
              <span className={styles.label}>Reason (required)</span>
              <input
                className={styles.input}
                value={reason}
                placeholder="Compensating control: fronted by a WAF that strips the header"
                onChange={(e) => setReason(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleCreate()}
              />
              <span className={styles.hint}>
                Stored with the entry. A suppression with no stated justification is
                indistinguishable from an oversight a year from now.
              </span>
            </label>

            {create.isError && (
              <div className={styles.error}>
                {create.error instanceof ApiError
                  ? create.error.message
                  : "Could not save the suppression."}
              </div>
            )}

            <Button
              variant="primary"
              icon={<Plus size={15} />}
              disabled={!canSubmit || create.isPending}
              onClick={handleCreate}
            >
              {create.isPending ? "Saving…" : "Accept risk"}
            </Button>
          </div>
        </>
      )}
    </>
  );
}
