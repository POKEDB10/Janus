import axios, { type AxiosProgressEvent } from "axios";
import type {
  AnalysisResults,
  AnalysisStatus,
  ComplianceReport,
  ExplainerResponse,
  Finding,
  FlowResult,
  GenerateReportResponse,
  HealthResponse,
  ModelInfo,
  PaginatedFlows,
  ReportNarrativeResponse,
  ReportStatus,
  SamplePcap,
  UploadResponse,
} from "../types";
import { getCaptureContext } from "../lib/capture-session";

export const API_BASE_URL = import.meta.env.VITE_API_URL !== undefined 
  ? import.meta.env.VITE_API_URL 
  : (import.meta.env.PROD ? "" : "http://127.0.0.1:9000");

export const API_KEY = import.meta.env.VITE_API_KEY ?? "";

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
    ...(API_KEY ? { "X-API-Key": API_KEY } : {}),
  },
  timeout: 15_000,
});

apiClient.interceptors.request.use((config) => {
  if (!config.headers["X-Capture-Token"]) {
    // Automatically match capture_id from route URLs e.g. /api/report/:id, /api/analysis/:id
    const match = config.url?.match(/\/(?:analysis|report|compliance)\/([a-zA-Z0-9_\-]+)/);
    if (match && match[1]) {
      const captureId = match[1];
      const context = getCaptureContext(captureId);
      if (context?.captureToken) {
        config.headers["X-Capture-Token"] = context.captureToken;
      }
    }
  }
  return config;
});

function captureHeaders(captureToken?: string): Record<string, string> {
  return captureToken ? { "X-Capture-Token": captureToken } : {};
}

export async function getHealth(): Promise<HealthResponse> {
  const { data } = await apiClient.get<HealthResponse>("/health", { timeout: 10_000 });
  return data;
}

export async function getModelInfo(): Promise<ModelInfo> {
  const { data } = await apiClient.get<ModelInfo>("/api/model/info", { timeout: 10_000 });
  return data;
}

export async function uploadPcap(
  file: File,
  onProgress?: (percent: number) => void,
): Promise<UploadResponse> {
  const form = new FormData();
  form.append("file", file);
  const { data } = await apiClient.post<UploadResponse>("/api/captures/upload", form, {
    headers: { "Content-Type": "multipart/form-data" },
    onUploadProgress: (event: AxiosProgressEvent) => {
      if (event.total && onProgress) onProgress(Math.round((event.loaded / event.total) * 100));
    },
  });
  return data;
}

export async function getAnalysisStatus(captureId: string, captureToken?: string): Promise<AnalysisStatus> {
  const { data } = await apiClient.get<AnalysisStatus>(`/api/analysis/${encodeURIComponent(captureId)}/status`, {
    headers: captureHeaders(captureToken),
  });
  return data;
}

export async function getAnalysisResults(captureId: string, captureToken?: string): Promise<AnalysisResults> {
  const { data } = await apiClient.get<AnalysisResults>(`/api/analysis/${encodeURIComponent(captureId)}/results`, {
    headers: captureHeaders(captureToken),
  });
  return data;
}

export async function getFlows(
  captureId: string,
  page: number,
  pageSize: number,
  captureToken?: string,
): Promise<PaginatedFlows> {
  const { data } = await apiClient.get<PaginatedFlows>(`/api/analysis/${encodeURIComponent(captureId)}/flows`, {
    headers: captureHeaders(captureToken),
    params: { page, page_size: pageSize },
  });
  return data;
}

export async function getFlowDetail(captureId: string, flowId: string, captureToken?: string): Promise<FlowResult> {
  const { data } = await apiClient.get<FlowResult>(
    `/api/analysis/${encodeURIComponent(captureId)}/flows/${encodeURIComponent(flowId)}`,
    { headers: captureHeaders(captureToken) },
  );
  return data;
}

/** The embedded value in analysis results is the canonical frontend compliance source. */
export async function getCaptureCompliance(captureId: string, captureToken?: string): Promise<ComplianceReport | null> {
  const result = await getAnalysisResults(captureId, captureToken);
  return result.compliance ?? null;
}

/** @deprecated Use getAnalysisResults and consume its embedded compliance object. */
export async function getComplianceReport(captureId: string, captureToken?: string): Promise<ComplianceReport> {
  const compliance = await getCaptureCompliance(captureId, captureToken);
  if (!compliance) throw new Error("No configuration verdict was returned for this capture.");
  return compliance;
}

export async function runAdHocEvaluation(params: {
  esp_encryption: string;
  esp_auth?: string;
  dh_group?: number;
  pfs_enabled?: boolean;
  sa_lifetime_seconds?: number;
  rsa_key_bits?: number;
  ike_version?: "IKEv1" | "IKEv2";
}): Promise<ComplianceReport> {
  const { data } = await apiClient.post<ComplianceReport>("/api/compliance/adhoc", params);
  return data;
}

export async function getReportStatus(captureId: string, captureToken?: string): Promise<ReportStatus> {
  const { data } = await apiClient.get<ReportStatus>(`/api/report/${encodeURIComponent(captureId)}/status`, {
    headers: captureHeaders(captureToken),
  });
  return data;
}

export async function generateReport(captureId: string, captureToken?: string): Promise<GenerateReportResponse> {
  const { data } = await apiClient.post<GenerateReportResponse>(
    `/api/report/${encodeURIComponent(captureId)}/generate`,
    undefined,
    { headers: captureHeaders(captureToken) },
  );
  return data;
}

export function getExecutiveReportUrl(captureId: string, captureToken?: string): string {
  const token = captureToken || getCaptureContext(captureId).captureToken;
  const q = token ? `?token=${encodeURIComponent(token)}` : "";
  return `${API_BASE_URL}/api/report/${encodeURIComponent(captureId)}/executive${q}`;
}

export function getTechnicalReportUrl(captureId: string, captureToken?: string): string {
  const token = captureToken || getCaptureContext(captureId).captureToken;
  const q = token ? `?token=${encodeURIComponent(token)}` : "";
  return `${API_BASE_URL}/api/report/${encodeURIComponent(captureId)}/technical${q}`;
}

export function getFlowsCsvUrl(captureId: string, captureToken?: string): string {
  const token = captureToken || getCaptureContext(captureId).captureToken;
  const q = token ? `?token=${encodeURIComponent(token)}` : "";
  return `${API_BASE_URL}/api/analysis/${encodeURIComponent(captureId)}/export/csv${q}`;
}

export async function explainFinding(finding: Finding, topK = 3, captureToken?: string): Promise<ExplainerResponse> {
  const { data } = await apiClient.post<ExplainerResponse>(
    "/api/compliance/explain",
    { finding, top_k: topK },
    { headers: captureHeaders(captureToken) },
  );
  return data;
}

export async function draftReportNarrative(captureId: string, captureToken?: string): Promise<ReportNarrativeResponse> {
  const token = captureToken || getCaptureContext(captureId).captureToken;
  const { data } = await apiClient.post<ReportNarrativeResponse>(
    `/api/report/${encodeURIComponent(captureId)}/draft-narrative`,
    undefined,
    { headers: captureHeaders(token) },
  );
  return data;
}

export async function getSamplePcaps(): Promise<SamplePcap[]> {
  const { data } = await apiClient.get<SamplePcap[]>("/api/samples");
  return data;
}

export async function analyzeSample(sampleId: string): Promise<UploadResponse> {
  const { data } = await apiClient.post<UploadResponse>(
    `/api/samples/${encodeURIComponent(sampleId)}/analyze`,
  );
  return data;
}

export type StreamProgress = Pick<AnalysisStatus, "status" | "progress_pct" | "message" | "logs"> & { error?: string | null };

export function streamAnalysisProgress(
  captureId: string,
  captureToken: string | undefined,
  handlers: {
    onProgress: (data: StreamProgress) => void;
    onDone: (data: StreamProgress) => void;
    onFailure: (message: string) => void;
  },
): EventSource {
  const params = new URLSearchParams();
  if (captureToken) params.set("token", captureToken);
  const query = params.size ? `?${params.toString()}` : "";
  const stream = new EventSource(`${API_BASE_URL}/api/analysis/${encodeURIComponent(captureId)}/stream${query}`);
  let failed = false;

  const parse = (event: MessageEvent<string>): StreamProgress | null => {
    try { return JSON.parse(event.data) as StreamProgress; } catch { return null; }
  };
  const fail = (message: string) => {
    if (failed) return;
    failed = true;
    handlers.onFailure(message);
    stream.close();
  };

  stream.addEventListener("progress", (event) => {
    const data = parse(event as MessageEvent<string>);
    if (data) handlers.onProgress(data);
  });
  stream.addEventListener("done", (event) => {
    const data = parse(event as MessageEvent<string>);
    if (data) handlers.onDone(data);
    stream.close();
  });
  stream.addEventListener("error", (event) => {
    const data = parse(event as MessageEvent<string>);
    fail(data?.error ?? data?.message ?? "The live progress stream disconnected.");
  });
  stream.onerror = () => {
    fail("The live progress stream disconnected.");
  };
  return stream;
}
