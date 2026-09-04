"""
backend/routes/explainer.py
===========================
FastAPI endpoints for the Janus Compliance-RAG Explainer Model.

Endpoints:
- POST /api/compliance/explain: Generate grounded explanation for any finding.
- POST /api/compliance/{capture_id}/explain-finding/{rule_id}: Explain a specific session finding.
- POST /api/report/{capture_id}/draft-narrative: Draft executive & technical narrative prose.
"""

from __future__ import annotations

import logging
from typing import Any
from fastapi import APIRouter, HTTPException, status

from models import (
    ExplainFindingRequest,
    ExplainerResponseModel,
    ReportNarrativeRequest,
    ReportNarrativeResponseModel,
    ExplainCompoundRequest,
    CompoundExplainerResponseModel,
)
from rag.engine.explainer import explainer
from rag.engine.narrative_writer import narrative_writer
from routes.analysis import _state_store

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Compliance-RAG Explainer"])


@router.post(
    "/compliance/explain",
    response_model=ExplainerResponseModel,
    summary="Explain compliance finding using RFC/NIST RAG",
)
async def explain_finding_endpoint(
    req: ExplainFindingRequest,
    model_size: str = "4b",
) -> ExplainerResponseModel:
    """
    Generate natural language explanation for why a compliance finding is Critical/High/Medium/Low,
    citing exact RFC 8221, RFC 8247, RFC 9347, or NIST SP 800-77 Rev. 1 clauses.
    """
    try:
        res = explainer.explain(finding=req.finding, top_k=req.top_k, model_size=model_size)
        return ExplainerResponseModel(**res.to_dict())
    except Exception as exc:
        logger.error("Explainer failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Compliance explainer error: {str(exc)}",
        )


@router.post(
    "/compliance/{capture_id}/explain-finding/{rule_id}",
    response_model=ExplainerResponseModel,
    summary="Explain a specific session finding by rule ID",
)
async def explain_session_finding_endpoint(
    capture_id: str,
    rule_id: str,
    top_k: int = 3,
    model_size: str = "4b",
) -> ExplainerResponseModel:
    """
    Retrieve finding from capture session and explain with authoritative standards citations.
    """
    if capture_id not in _state_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture session '{capture_id}' not found.",
        )

    entry = _state_store[capture_id]
    results = entry.get("results") or {}
    comp = results.get("compliance") or {}
    findings = comp.get("findings", [])

    target_finding = next((f for f in findings if f.get("rule_id") == rule_id), None)
    if not target_finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{rule_id}' not found in session '{capture_id}'.",
        )

    res = explainer.explain(finding=target_finding, top_k=top_k, model_size=model_size)
    return ExplainerResponseModel(**res.to_dict())


@router.post(
    "/compliance/{capture_id}/explain-compound",
    response_model=CompoundExplainerResponseModel,
    summary="Explain compound blast-radius for multiple concurrent session findings",
)
async def explain_compound_endpoint(
    capture_id: str,
    top_k: int = 5,
    model_size: str = "4b",
) -> CompoundExplainerResponseModel:
    """
    Analyze the interacting attack surface and compound blast radius across all
    findings detected in this IPsec capture session.
    """
    findings = []
    if capture_id in _state_store:
        entry = _state_store[capture_id]
        results = entry.get("results") or {}
        comp = results.get("compliance") or {}
        findings = comp.get("findings", [])

    if not findings:
        # Default baseline findings for ad-hoc / scenario demo
        findings = [
            {
                "rule_id": "RFC8221-ENCR_3DES",
                "severity": "HIGH",
                "parameter": "ESP Encryption",
                "description": "64-bit block cipher susceptible to SWEET32 collisions.",
            },
            {
                "rule_id": "RFC8247-DH_GROUP_2",
                "severity": "CRITICAL",
                "parameter": "Diffie-Hellman Group",
                "description": "1024-bit MODP group vulnerable to Logjam precomputation.",
            },
        ]

    try:
        res = explainer.explain_compound(
            capture_id=capture_id,
            findings=findings,
            top_k=top_k,
            model_size=model_size,
        )
        return CompoundExplainerResponseModel(**res.to_dict())
    except Exception as exc:
        logger.error("Compound explainer failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Compound explainer error: {str(exc)}",
        )


@router.post(
    "/report/{capture_id}/draft-narrative",
    response_model=ReportNarrativeResponseModel,
    summary="Draft executive and technical report narrative prose",
)
async def draft_report_narrative_endpoint(
    capture_id: str,
) -> ReportNarrativeResponseModel:
    """
    Draft grounded executive summary narrative and technical assessment prose around
    the deterministic findings table.
    """
    # Look up session compliance data, or use demo baseline if not yet analyzed
    comp_data = None
    analysis_data = None

    if capture_id in _state_store:
        entry = _state_store[capture_id]
        results = entry.get("results") or {}
        comp_data = results.get("compliance")
        analysis_data = results

    if not comp_data:
        # Provide representative demo baseline if ad-hoc or scenario
        comp_data = {
            "overall_score": 88.0,
            "grade": "B",
            "summary": "Baseline IPsec configuration with minor legacy cipher parameters.",
            "findings": [
                {
                    "rule_id": "RFC8221-ENCR_AES_CBC",
                    "severity": "LOW",
                    "parameter": "ESP Encryption",
                    "description": "AES-CBC lacks AEAD authenticated encryption.",
                    "recommendation": "Upgrade to AES-256-GCM AEAD.",
                }
            ],
            "evaluated_parameters": {
                "esp_encryption": "ENCR_AES_CBC",
                "esp_auth": "AUTH_HMAC_SHA2_256_128",
                "dh_group": 19,
            },
        }

    res = narrative_writer.draft_narrative(
        capture_id=capture_id,
        compliance_data=comp_data,
        analysis_data=analysis_data,
    )
    return ReportNarrativeResponseModel(**res.to_dict())
