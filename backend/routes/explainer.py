"""
backend/routes/explainer.py
===========================
FastAPI endpoints for the Janus Compliance-RAG Explainer Model.

Endpoints:
- POST /api/compliance/explain: Generate grounded explanation for any finding.
- POST /api/compliance/{capture_id}/explain-finding/{rule_id}: Explain a specific session finding.
- POST /api/report/{capture_id}/draft-narrative: Draft executive & technical narrative prose.
"""

import json
import logging
from pathlib import Path
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status

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
from routes.analysis import _get_entry, _state_store
from security import verify_auth_or_token

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Compliance-RAG Explainer"])


def _get_capture_results(capture_id: str) -> dict[str, Any] | None:
    """Retrieve capture analysis results from cache, SQLite audit store, or fixture data."""
    entry = _get_entry(capture_id)
    if entry and entry.get("results"):
        return entry["results"]

    if capture_id in _state_store:
        st_entry = _state_store[capture_id]
        if st_entry.get("results"):
            return st_entry["results"]

    fixture_path = Path("frontend/src/fixtures") / f"{capture_id}.results.json"
    if fixture_path.exists():
        try:
            with open(fixture_path, encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.warning("Failed loading fixture %s: %s", fixture_path, exc)

    fixtures_dir = Path("frontend/src/fixtures")
    if fixtures_dir.exists():
        for f in fixtures_dir.glob("*.results.json"):
            if capture_id in f.stem or f.stem.startswith(capture_id):
                try:
                    with open(f, encoding="utf-8") as fp:
                        return json.load(fp)
                except Exception:
                    pass

    return None


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
    dependencies=[Depends(verify_auth_or_token)],
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
    results = _get_capture_results(capture_id)
    if not results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture session '{capture_id}' not found.",
        )

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
    dependencies=[Depends(verify_auth_or_token)],
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
    results = _get_capture_results(capture_id)
    if results:
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
    dependencies=[Depends(verify_auth_or_token)],
)
async def draft_report_narrative_endpoint(
    capture_id: str,
) -> ReportNarrativeResponseModel:
    """
    Draft grounded executive summary narrative and technical assessment prose around
    the deterministic findings table.
    """
    results = _get_capture_results(capture_id)
    if not results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Completed analysis for capture session '{capture_id}' not found.",
        )

    comp_data = results.get("compliance") or {}
    analysis_data = results

    res = narrative_writer.draft_narrative(
        capture_id=capture_id,
        compliance_data=comp_data,
        analysis_data=analysis_data,
    )
    return ReportNarrativeResponseModel(**res.to_dict())
