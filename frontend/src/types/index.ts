// ─── Traffic & Risk Enumerations ────────────────────────────────────────────

export type TrafficType =
  | "VoIP"
  | "Video"
  | "Web"
  | "Email"
  | "ICMP"
  | "Obfuscated";

export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type AnalysisPipelineStatus =
  | "INIT"
  | "PARSING"
  | "CLASSIFYING"
  | "SCORING"
  | "DONE"
  | "ERROR";

// ─── Upload ─────────────────────────────────────────────────────────────────

export interface UploadResponse {
  capture_id: string;
  filename: string;
  size_bytes: number;
  status: AnalysisPipelineStatus | string;
  message?: string;
}

// ─── Analysis Status ─────────────────────────────────────────────────────────

export interface AnalysisStatus {
  capture_id: string;
  status: AnalysisPipelineStatus;
  progress?: number; // 0-100
  progress_pct?: number;
  message?: string;
  logs?: string[];
  started_at?: string | null;
  completed_at?: string | null;
  error?: string | null;
}

export interface SamplePcap {
  id: string;
  filename: string;
  title: string;
  category: string;
  rfc_status: string;
  cipher: string;
  description: string;
  download_url: string;
  external_url: string;
  size_bytes: number;
}

// ─── Classification & SHAP ───────────────────────────────────────────────────

export interface SHAPExplanation {
  /** Feature name → SHAP contribution value */
  shap_values: Record<string, number>;
  /** Expected model output before feature contributions */
  base_value: number;
  /** Final model output (sum of base + all shap values) */
  output_value: number;
}

export interface ClassificationResult {
  traffic_type: TrafficType;
  /** Confidence in [0, 1] */
  confidence: number;
  shap: SHAPExplanation;
}

// ─── Flow ────────────────────────────────────────────────────────────────────

export interface FlowResult {
  flow_id: string;
  /** Security Parameter Index (hex string) */
  spi: string;
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  protocol?: string;
  /** DSCP value 0-63 */
  dscp?: number;
  /** Flow duration in seconds */
  duration_s: number;
  packet_count: number;
  byte_count?: number;
  classification: ClassificationResult;
  risk_level?: RiskLevel;
  is_obfuscated: boolean;
}

export interface FlowDetail extends FlowResult {
  /** Packet IAT samples in ms */
  iat_samples?: number[];
  /** Packet size samples in bytes */
  packet_sizes?: number[];
}

export interface PaginatedFlows {
  flows: FlowResult[];
  total: number;
  page: number;
  page_size: number;
}

export interface AnalysisResults {
  capture_id: string;
  total_flows: number;
  overall_risk?: RiskLevel;
  traffic_distribution?: Record<TrafficType, number>;
  flows: FlowResult[];
  ike_sessions?: any[];
  compliance?: any;
  reports?: any;
}

// ─── Compliance ──────────────────────────────────────────────────────────────

export type ComplianceDimension =
  | "ESP_ENC"
  | "ESP_AUTH"
  | "IKE_KX"
  | "PFS"
  | "LIFETIME";

export interface AlgorithmComparison {
  parameter: string;
  found: string;
  expected: string;
  /** true = compliant, false = non-compliant */
  compliant: boolean;
}

export interface Finding {
  finding_id?: string;
  rule_id?: string;
  title?: string;
  parameter?: string;
  severity?: RiskLevel | string;
  risk_level?: RiskLevel;
  description: string;
  remediation?: string;
  recommendation?: string;
  references?: string[];
  vulnerability_tag?: string;
  dimension?: ComplianceDimension;
}

export type ComplianceFinding = Finding;

export interface ThreatMatrixItem {
  technique_id: string;
  tactic: string;
  technique_name: string;
  severity: string;
  status: string;
  details: string;
  affected_parameter?: string;
}

export type ThreatMatrix = ThreatMatrixItem[] | Partial<Record<RiskLevel, Partial<Record<ComplianceDimension, number>>>>;

export interface ComplianceReport {
  capture_id: string;
  overall_score: number; // 0-100
  grade?: string;
  summary?: string;
  overall_risk?: RiskLevel;
  dimension_scores?: Record<ComplianceDimension, number>;
  findings: Finding[];
  algorithm_comparisons?: AlgorithmComparison[];
  threat_matrix?: ThreatMatrix;
  evaluated_parameters?: Record<string, any>;
  remediation_config?: string;
  generated_at: string;
}

// ─── Report ──────────────────────────────────────────────────────────────────

export interface GenerateReportResponse {
  status: string;
  report_id: string;
}

export interface ReportStatus {
  status: string;
  download_url?: string;
}

// ─── Compliance-RAG Explainer ────────────────────────────────────────────────

export interface CitationItem {
  raw_citation: string;
  document: string;
  section: string;
  verified: boolean;
  matching_chunk_id?: string;
  clause_title?: string;
}

export interface RetrievedChunk {
  chunk_id: string;
  document: string;
  section: string;
  title: string;
  category: string;
  text: string;
  score: number;
}

export interface ExplainerResponse {
  rule_id: string;
  parameter: string;
  severity: string;
  explanation: string;
  citations: CitationItem[];
  retrieved_chunks: RetrievedChunk[];
  groundedness_score: number;
  is_fallback: boolean;
  latency_ms: number;
  model_name: string;
  warning?: string;
}

export interface ReportNarrativeResponse {
  capture_id: string;
  overall_score: number;
  grade: string;
  executive_narrative: string;
  technical_narrative: string;
  citations: CitationItem[];
  is_grounded: boolean;
  latency_ms: number;
}

