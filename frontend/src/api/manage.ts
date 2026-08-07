import { useQuery } from "@tanstack/react-query";
import { api } from "./client";
import type { DoctorReport, PromoteStatsRow, ServerSettings } from "./types";

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
