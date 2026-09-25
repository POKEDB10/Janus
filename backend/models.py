"""
Janus API – Pydantic v2 Data Models
===================================
Request and response schemas for all REST API endpoints.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field


class PipelineStatus(str, Enum):
    INIT = "INIT"
    PARSING = "PARSING"
    CLASSIFYING = "CLASSIFYING"
    SCORING = "SCORING"
    DONE = "DONE"
    ERROR = "ERROR"


class IKEVersion(str, Enum):
    V1 = "IKEv1"
    V2 = "IKEv2"


class UploadResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    capture_id: str = Field(..., description="Unique identifier for this capture session.")
    filename: str = Field(..., description="Original filename as uploaded by client.")
    size_bytes: int = Field(..., description="Size of uploaded file in bytes.")
    status: str = Field(default="uploaded", description="Upload status.")
    capture_token: Optional[str] = Field(default=None, description="Ownership token for BOLA protection.")


class AnalysisStatus(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    capture_id: str = Field(..., description="Capture session identifier.")
    status: PipelineStatus = Field(..., description="Current pipeline status.")
    error: Optional[str] = Field(default=None, description="Error message if pipeline failed.")
    progress_pct: float = Field(default=0.0, ge=0.0, le=100.0, description="Pipeline progress percentage.")
    message: Optional[str] = Field(default=None, description="Current status message.")
    logs: list[str] = Field(default_factory=list, description="Real-time execution log messages.")


class SHAPContributionModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    feature_name: str
    feature_value: float
    shap_value: float
    contribution: str


class SHAPExplanationModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    base_value: float
    predicted_class: str
    contributions: list[SHAPContributionModel] = Field(default_factory=list)


class ClassificationResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    label: str = Field(..., description="Predicted traffic class label.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score.")
    is_obfuscated: bool = Field(default=False, description="True if RFC 9347 IP-TFS detected.")
    obfuscation_details: Optional[dict[str, Any]] = None
    shap: Optional[SHAPExplanationModel] = None


class FlowResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    flow_id: str
    src_ip: str
    dst_ip: str
    spi: str
    packet_count: int
    duration_s: float
    features: dict[str, Any] = Field(default_factory=dict)
    classification: Optional[ClassificationResult] = None


class PaginatedFlowsResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    total: int
    page: int
    page_size: int
    flows: list[FlowResult]


class AnalysisResults(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    capture_id: str
    total_flows: int = 0
    ike_sessions: list[dict[str, Any]] = Field(default_factory=list)
    flows: list[FlowResult] = Field(default_factory=list)
    compliance: Optional[dict[str, Any]] = None
    reports: Optional[dict[str, Any]] = None


class FindingResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    rule_id: str
    severity: str
    category: str
    parameter: str
    value: str
    description: str
    recommendation: str
    references: list[str] = Field(default_factory=list)
    vulnerability_tag: Optional[str] = None


class ThreatMatrixItemResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    technique_id: str
    tactic: str
    technique_name: str
    severity: str
    status: str
    details: str
    affected_parameter: str


class ComplianceReportResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    capture_id: str
    overall_score: float
    grade: str
    summary: str
    findings: list[FindingResponse] = Field(default_factory=list)
    threat_matrix: list[ThreatMatrixItemResponse] = Field(default_factory=list)
    evaluated_parameters: dict[str, Any] = Field(default_factory=dict)
    remediation_config: Optional[str] = None
    generated_at: str


class AdHocComplianceRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    esp_encryption: str = Field(..., description="ESP Cipher, e.g. AES-256-GCM, 3DES, Blowfish")
    esp_auth: Optional[str] = Field(default=None, description="ESP HMAC / Auth algorithm, e.g. HMAC-SHA256, HMAC-MD5")
    dh_group: Optional[int] = Field(default=19, description="Diffie-Hellman Group Number (e.g. 2, 14, 19, 20)")
    pfs_enabled: bool = Field(default=True, description="Perfect Forward Secrecy enabled")
    sa_lifetime_seconds: int = Field(default=3600, description="SA lifetime in seconds (1h to 8h window)")
    rsa_key_bits: Optional[int] = Field(default=3072, description="RSA key length in bits")
    ike_version: IKEVersion = Field(default=IKEVersion.V2, description="IKE version")


class ReportStatusResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    capture_id: str
    executive_ready: bool
    technical_ready: bool
    executive_url: Optional[str] = None
    technical_url: Optional[str] = None


# --- Compliance-RAG Explainer Schemas ---

class ExplainFindingRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    finding: dict[str, Any] = Field(..., description="Compliance finding object containing rule_id, parameter, severity, etc.")
    top_k: int = Field(default=3, description="Number of primary standards context clauses to retrieve")


class CitationItemResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    raw_citation: str
    document: str
    section: str
    verified: bool
    matching_chunk_id: Optional[str] = None
    clause_title: Optional[str] = None


class ExplainerResponseModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    rule_id: str
    parameter: str
    severity: str
    explanation: str
    citations: list[dict[str, Any]] = Field(default_factory=list)
    retrieved_chunks: list[dict[str, Any]] = Field(default_factory=list)
    groundedness_score: float
    is_fallback: bool
    latency_ms: float
    model_name: str
    warning: Optional[str] = None


class ReportNarrativeRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    capture_id: str


class ReportNarrativeResponseModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    capture_id: str
    overall_score: float
    grade: str
    executive_narrative: str
    technical_narrative: str
    citations: list[dict[str, Any]] = Field(default_factory=list)
    is_grounded: bool
    latency_ms: float


class ExplainCompoundRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    capture_id: str = Field(..., description="Capture session ID to evaluate")
    findings: Optional[list[dict[str, Any]]] = Field(default=None, description="Optional explicit findings list override")
    top_k: int = Field(default=5, description="Number of primary standards context clauses to retrieve")
    model_size: str = Field(default="4b", description="Model size tier (4b or 8b)")


class CompoundExplainerResponseModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    capture_id: str
    total_findings: int
    compound_narrative: str
    citations: list[dict[str, Any]] = Field(default_factory=list)
    retrieved_chunks: list[dict[str, Any]] = Field(default_factory=list)
    groundedness_score: float
    is_fallback: bool
    latency_ms: float
    model_name: str
    warning: Optional[str] = None


