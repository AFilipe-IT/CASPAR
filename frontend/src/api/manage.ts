import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";
import type {
  DoctorReport,
  FixPreview,
  PromoteStatsRow,
  ServerSettings,
  SuppressionItem,
} from "./types";

/**
 * Effective server configuration. Never changes while the page is open (it
 * reflects how the process was launched), so it isn't polled.
 */
export function useSettings() {
  return useQuery({
    queryKey: ["settings"],
    queryFn: () => api.get<ServerSettings>("/settings"),
    staleTime: Infinity,
  });
}

/**
 * DB integrity check. Always 200 when the check *ran* — the verdict is in
 * `errors`/`warnings`, not the HTTP status, so don't treat a report with
 * findings as a request failure.
 */
export function useDoctor(strict: boolean) {
  return useQuery({
    queryKey: ["doctor", strict],
    queryFn: () => api.get<DoctorReport>(`/doctor?strict=${strict}`),
  });
}

/** The learning-loop scoreboard behind `caspar promote --stats`. */
export function usePromoteStats() {
  return useQuery({
    queryKey: ["promote-stats"],
    queryFn: () => api.get<PromoteStatsRow[]>("/promote/stats"),
  });
}

// ── suppressions ──────────────────────────────────────────────────────

/**
 * Accepted risks in a suppression file.
 *
 * `suppressFile` is a path on the *server*, and the API deliberately has no
 * default for it, so the query stays disabled until one is set — an empty
 * path would otherwise produce a 400 on every render.
 */
export function useSuppressions(suppressFile: string) {
  return useQuery({
    queryKey: ["suppressions", suppressFile],
    queryFn: () =>
      api.get<SuppressionItem[]>(
        `/suppressions?suppress_file=${encodeURIComponent(suppressFile)}`,
      ),
    enabled: Boolean(suppressFile),
  });
}

export interface CreateSuppressionInput {
  directive: string;
  reason: string;
  bad_value?: string;
}

/** Accept a risk. `reason` is mandatory server-side and enforced in the form. */
export function useCreateSuppression(suppressFile: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateSuppressionInput) =>
      api.post<SuppressionItem>("/suppressions", {
        ...input,
        bad_value: input.bad_value ?? "",
        suppress_file: suppressFile,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["suppressions", suppressFile] }),
  });
}

/** Withdraw an accepted risk, so the directive counts against thresholds again. */
export function useDeleteSuppression(suppressFile: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (directive: string) =>
      api.delete<{ removed: number }>(
        `/suppressions/${encodeURIComponent(directive)}` +
          `?suppress_file=${encodeURIComponent(suppressFile)}`,
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["suppressions", suppressFile] }),
  });
}

// ── fix preview ───────────────────────────────────────────────────────

/**
 * The remediation diff for a config file. A mutation rather than a query
 * because it re-scans the file server-side: it is a request to compute
 * something now, not a cacheable read of stored state.
 *
 * Nothing is written — `applied` always comes back false. Applying the patch
 * stays a CLI operation (`caspar fix --in-place`).
 */
export function useFixPreview() {
  return useMutation({
    mutationFn: (input: { input_path: string; live: boolean }) =>
      api.post<FixPreview>("/fix/preview", input),
  });
}
