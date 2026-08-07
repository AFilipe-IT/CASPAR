import { useQuery } from "@tanstack/react-query";
import { api } from "./client";
import type { TrendSeries } from "./types";

export function useTrends(inputPath?: string) {
  return useQuery({
    queryKey: ["trends", inputPath],
    queryFn: () =>
      api.get<TrendSeries[]>(`/trends${inputPath ? `?input_path=${encodeURIComponent(inputPath)}` : ""}`),
  });
}
