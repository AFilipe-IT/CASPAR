import { useQuery } from "@tanstack/react-query";
import { api, overviewQueryOptions } from "./client";
import type { HostRollup } from "./types";

// A resposta de GET /hosts é o rollup tal e qual. Havia aqui um `scans: number`
// a redeclarar o campo, o que anulava o tipo real e deixava passar o erro.
export type HostsRollupResponse = HostRollup;

export function useHostsRollup() {
  return useQuery({
    queryKey: ["hosts", "rollup"],
    queryFn: () => api.get<HostsRollupResponse>("/hosts"),
    ...overviewQueryOptions,
  });
}

export function useHostRegistry() {
  return useQuery({
    queryKey: ["hosts", "registry"],
    queryFn: () => api.get<{ id: number; label: string }[]>("/hosts/registry"),
  });
}
