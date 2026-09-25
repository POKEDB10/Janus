import { useQuery } from "@tanstack/react-query";
import { getAnalysisResults, getHealth, getModelInfo } from "./client";
import { getRecordedAnalysis } from "./recorded";
import { getCaptureContext, isRecordedSample } from "../lib/capture-session";

export function useBackendStatus() {
  return useQuery({
    queryKey: ["backend-health"],
    queryFn: getHealth,
    retry: false,
    staleTime: 15_000,
    refetchInterval: 30_000,
    refetchOnWindowFocus: false,
  });
}

export function useModelStatus(enabled: boolean) {
  return useQuery({
    queryKey: ["model-info"],
    queryFn: getModelInfo,
    enabled,
    retry: false,
    staleTime: 120_000,
    refetchOnWindowFocus: false,
  });
}

export function useCaptureResults(captureId: string, search: string) {
  const recorded = isRecordedSample(search);
  const context = getCaptureContext(captureId);
  return useQuery({
    queryKey: ["capture-results", captureId, recorded ? "recorded" : "live"],
    queryFn: () => recorded ? getRecordedAnalysis(captureId) : getAnalysisResults(captureId, context.captureToken),
    enabled: Boolean(captureId),
    retry: false,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
    refetchOnWindowFocus: false,
  });
}
