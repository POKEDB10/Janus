import { useQuery } from "@tanstack/react-query";
import { getAnalysisResults, getAnalysisStatus, getHealth, getModelInfo } from "./client";
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
    queryFn: async () => {
      if (recorded) return getRecordedAnalysis(captureId);
      // For live captures, if the pipeline was just enqueued, poll status until DONE
      const maxAttempts = 20;
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        try {
          return await getAnalysisResults(captureId, context.captureToken);
        } catch (err: any) {
          try {
            const st = await getAnalysisStatus(captureId, context.captureToken);
            if (st.status === "ERROR") {
              throw new Error(st.error || st.message || "Pipeline execution failed.");
            }
            if (st.status !== "DONE") {
              // Still running, wait and poll again
              await new Promise((resolve) => setTimeout(resolve, 600));
              continue;
            }
          } catch {
            if (attempt >= 2) throw err;
          }
          if (attempt >= maxAttempts - 1) throw err;
          await new Promise((resolve) => setTimeout(resolve, 600));
        }
      }
      return getAnalysisResults(captureId, context.captureToken);
    },
    enabled: Boolean(captureId),
    retry: 1,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
    refetchOnWindowFocus: false,
  });
}
