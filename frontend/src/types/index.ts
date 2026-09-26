export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type AnalysisPipelineStatus =
  | "INIT"
  | "PARSING"
  | "CLASSIFYING"
  | "SCORING"
  | "DONE"
  | "ERROR";

export type GuardrailStatus =
  | "VERIFIED"
  | "LOW_CONFIDENCE_REJECTED"
  | "OUT_OF_DISTRIBUTION_ANOMALY";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonRecord = Record<string, JsonValue>;

export interface UploadResponse { capture_id: string; filename: string; size_bytes: number; status: string; capture_token?: string | null; }
export interface CaptureContext { captureId: string; filename?: string; sizeBytes?: number; captureToken?: string; }
export interface AnalysisStatus { capture_id: string; status: AnalysisPipelineStatus; error?: string | null; progress_pct: number; message?: string | null; logs: string[]; }
export interface SamplePcap { id: string; filename: string; title: string; category: string; rfc_status: string; cipher: string; description: string; download_url: string; external_url: string; size_bytes: number; }

export interface SHAPContribution { feature_name: string; feature_value: number; shap_value: number; contribution: "POSITIVE" | "NEGATIVE" | string; }
export interface SHAPExplanation { base_value: number; predicted_class?: string; output_value?: number; shap_values?: Record<string, number>; contributions?: SHAPContribution[]; }
export interface ObfuscationDetails { status?: GuardrailStatus | string; raw_prediction?: string; confidence?: number; detected_mechanism?: string; pkt_len_variance?: number; iat_cv?: number; entropy?: number; details?: string; }
export interface ClassificationResult { label?: string; traffic_type?: string; confidence?: number; calibrated_confidence?: number; raw_confidence?: number; is_obfuscated?: boolean; obfuscation_details?: ObfuscationDetails | null; shap?: SHAPExplanation | null; }

export interface FlowResult {
  flow_id: string; src_ip?: string; dst_ip?: string; spi: string; packet_count: number; duration_s: number;
  byte_count?: number; src_port?: number; dst_port?: number; protocol?: string; dscp?: number; risk_level?: RiskLevel;
  is_obfuscated?: boolean; features?: Record<string, number>; packet_trace?: number[][]; classification?: ClassificationResult | null;
}
export interface PaginatedFlows { total: number; page: number; page_size: number; flows: FlowResult[]; }

export interface Transform { transform_type: string; transform_id: string; key_length?: number | null; raw_attributes?: JsonRecord; }
export interface IKEProposal { proposal_num: number; protocol_id: string; spi?: string | null; transforms: Transform[]; }
export interface IKESession {
  session_id: string; initiator_spi: string; responder_spi: string; version: string; exchange_types: string[];
  proposals_offered: IKEProposal[]; selected_proposal?: IKEProposal | null; child_sa_proposals: IKEProposal[];
  selected_child_proposal?: IKEProposal | null; auth_method: string; rsa_key_bits?: number | null;
  sa_lifetime_seconds: number; pfs_enabled: boolean; nat_detected: boolean;
}

export interface Finding {
  rule_id: string; severity: RiskLevel | string; category?: string; parameter: string; value?: string; description: string;
  recommendation?: string; remediation?: string; references?: string[]; vulnerability_tag?: string | null;
  cve_id?: string | null; cwe_id?: string | null; cvss_score?: number | null; nvd_url?: string | null;
}
export interface ThreatMatrixItem { technique_id: string; tactic: string; technique_name: string; severity: RiskLevel | string; status: string; details: string; affected_parameter?: string; }
export interface ComplianceReport {
  capture_id?: string; overall_score: number | null; grade: string; status?: "INDETERMINATE" | string; summary?: string;
  indeterminate_reason?: string; findings: Finding[]; threat_matrix?: ThreatMatrixItem[]; evaluated_parameters?: Record<string, JsonValue>;
  remediation_config?: string | null; pqc_status?: string; pqc_advisory?: string; generated_at?: string;
}
export interface ReportLinks { executive_pdf?: string; technical_pdf?: string; executive_url?: string; technical_url?: string; }
export interface AnalysisResults {
  capture_id: string; filename?: string; status?: "INDETERMINATE" | string; reason?: string; total_flows: number;
  overall_risk?: RiskLevel; traffic_distribution?: Record<string, number>; ike_sessions: IKESession[]; flows: FlowResult[];
  compliance?: ComplianceReport | null; reports?: ReportLinks;
}

export interface ReportStatus { capture_id: string; executive_ready: boolean; technical_ready: boolean; executive_url?: string | null; technical_url?: string | null; }
export interface GenerateReportResponse { status: string; report_id: string; executive_url?: string; technical_url?: string; }
export interface CitationItem { raw_citation: string; document: string; section: string; verified: boolean; matching_chunk_id?: string; clause_title?: string; }
export interface RetrievedChunk { chunk_id: string; document: string; section: string; title: string; category: string; text: string; score: number; }
export interface StandardCitedItem { id: string; note: string; }
export interface ExplainerResponse {
  rule_id: string; parameter: string; severity: string; explanation: string;
  citations: CitationItem[]; retrieved_chunks: RetrievedChunk[]; groundedness_score: number;
  is_fallback: boolean; latency_ms: number; model_name: string; warning?: string;
  summary?: string; standardsCited?: StandardCitedItem[]; standards_cited?: StandardCitedItem[];
  riskNote?: string; risk_note?: string; remediation?: string; compound_narrative?: string;
}
export interface ReportNarrativeResponse {
  capture_id: string; overall_score: number | null; grade: string;
  executive_narrative: string; technical_narrative: string; citations: CitationItem[];
  is_grounded: boolean; latency_ms: number;
  summary?: string; standardsCited?: StandardCitedItem[]; standards_cited?: StandardCitedItem[];
  riskNote?: string; risk_note?: string; remediation?: string;
}
export interface HealthResponse { status: string; version: string; service: string; }
export interface ModelInfo {
  model_name: string; architecture: string; training_data: { source: string; total_flows: number; flows_per_class: number; scenarios: number; note: string; };
  evaluation: Record<string, JsonValue>; features: number; feature_type: string; classes: string[]; explainability: string;
  ood_protection: Record<string, JsonValue>; team: string; hackathon: string; problem_id: string;
}

export function getFlowLabel(flow: FlowResult): string { return flow.classification?.label ?? flow.classification?.traffic_type ?? "—"; }

export function getFlowDisposition(flow: FlowResult): "ABSTAINED" | "OBFUSCATED" | "LOW_CONFIDENCE" | "VERIFIED" {
  if (flow.classification?.is_obfuscated || flow.is_obfuscated) return "OBFUSCATED";
  const guardrail = flow.classification?.obfuscation_details?.status;
  if (guardrail === "OUT_OF_DISTRIBUTION_ANOMALY") return "ABSTAINED";
  if (guardrail === "LOW_CONFIDENCE_REJECTED") return "LOW_CONFIDENCE";
  return "VERIFIED";
}

export interface PacketTrace { signed_normalized_length: number[]; normalized_length: number[]; log_iat: number[]; }
export function getPacketTrace(flow: FlowResult): PacketTrace | null {
  const trace = flow.packet_trace;
  if (!trace || trace.length < 3) return null;
  return { signed_normalized_length: trace[0] ?? [], normalized_length: trace[1] ?? [], log_iat: trace[2] ?? [] };
}
