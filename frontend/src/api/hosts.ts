import { useQuery } from "@tanstack/react-query";
import { api } from "./client";
import type { HostRollup } from "./types";

export interface HostsRollupResponse extends HostRollup {
  scans: number;
}

export function useHostsRollup() {
  return useQuery({
    queryKey: ["hosts", "rollup"],
    queryFn: () => api.get<HostsRollupResponse>("/hosts"),
  });
}

export function useHostRegistry() {
  return useQuery({
    queryKey: ["hosts", "registry"],
    queryFn: () => api.get<{ id: number; label: string }[]>("/hosts/registry"),
  });
}
