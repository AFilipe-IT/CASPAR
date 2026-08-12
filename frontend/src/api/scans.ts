import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, overviewQueryOptions } from "./client";
import type { AttackChain, ScanListItem, ScanResponse, ScanResult } from "./types";

interface ListScansParams {
  target?: string;
  input_path?: string;
  severity_min?: number;
  limit?: number;
  offset?: number;
}

export interface RunScanParams {
  input_path: string;
  live?: boolean;
  version?: string;
  env_profile?: "production" | "internal" | "dev";
  host?: string;
  threshold?: number;
  suppress_file?: string;
  assess_unknown?: boolean;
  docs_path?: string;
}

export interface UploadScanParams {
  file: File;
  env_profile?: "production" | "internal" | "dev";
  host?: string;
  threshold?: number;
}

async function uploadScan(params: UploadScanParams): Promise<ScanResponse> {
  const form = new FormData();
  form.append("file", params.file);
  if (params.env_profile) form.append("env_profile", params.env_profile);
  if (params.host) form.append("host", params.host);
  if (params.threshold !== undefined) form.append("threshold", String(params.threshold));

  const res = await fetch("/api/v1/scans/upload", { method: "POST", body: form });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {
      // no JSON body
    }
    throw new ApiError(res.status, detail);
  }
  return res.json();
}

function toQuery(params: ListScansParams): string {
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") usp.set(k, String(v));
  }
  const qs = usp.toString();
  return qs ? `?${qs}` : "";
}

/**
 * @param live mantém a lista a acompanhar o sistema (a Home). Opcional porque
 *   o Assessment usa a mesma hook para um histórico que o utilizador está a
 *   filtrar à mão — aí recarregar por baixo dos pés seria pior que útil.
 */
export function useScans(params: ListScansParams = {}, live = false) {
  return useQuery({
    queryKey: ["scans", params],
    queryFn: () => api.get<ScanListItem[]>(`/scans${toQuery(params)}`),
    ...(live ? overviewQueryOptions : {}),
  });
}

export function useScan(scanId: string | undefined) {
  return useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => api.get<ScanResult>(`/scans/${scanId}`),
    enabled: !!scanId,
  });
}

export function useScanChains(scanId: string | undefined) {
  return useQuery({
    queryKey: ["scan", scanId, "chains"],
    queryFn: () => api.get<AttackChain[]>(`/scans/${scanId}/chains`),
    enabled: !!scanId,
  });
}

// Server-path / --live mode — mirrors `caspar scan CONFIG [--live]`.
export function useRunScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (params: RunScanParams) => api.post<ScanResponse>("/scans", params),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["hosts"] });
      qc.invalidateQueries({ queryKey: ["trends"] });
    },
  });
}

// Browser upload mode — the file lives client-side, so it can't be a
// server-side path like RunScanParams.input_path; POST /scans/upload stages
// it to disk server-side then runs the same scan path.
export function useUploadScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: uploadScan,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["hosts"] });
      qc.invalidateQueries({ queryKey: ["trends"] });
    },
  });
}
