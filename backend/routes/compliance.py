"""
Janus Backend — Compliance Routes
=================================
Endpoints for retrieving capture compliance reports and running ad-hoc parameter assessments.
"""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status

import json
from pathlib import Path
from compliance.score import evaluator
from models import AdHocComplianceRequest, ComplianceReportResponse
from routes.analysis import _get_entry, _state_store
from security import verify_auth_or_token

router = APIRouter()


@router.get(
    "/compliance/{capture_id}",
    response_model=ComplianceReportResponse,
    summary="Get compliance report for a capture",
    dependencies=[Depends(verify_auth_or_token)],
)
async def get_compliance_report(capture_id: str) -> ComplianceReportResponse:
    """Retrieve full RFC 8221 / RFC 8247 compliance audit and threat matrix for a capture."""
    entry = _get_entry(capture_id)
    if entry:
        results = entry.get("results") or {}
        comp = results.get("compliance")
        if comp and comp.get("overall_score") is not None:
            return ComplianceReportResponse(
                capture_id=capture_id,
                overall_score=comp["overall_score"],
                grade=comp["grade"],
                summary=comp["summary"],
                findings=comp.get("findings", []),
                threat_matrix=comp.get("threat_matrix", []),
                evaluated_parameters=comp.get("evaluated_parameters", {}),
                remediation_config=comp.get("remediation_config", ""),
                generated_at=comp.get("generated_at", ""),
            )

    candidates = [
        Path("frontend/src/fixtures") / f"{capture_id}.results.json",
        Path("/app/frontend/src/fixtures") / f"{capture_id}.results.json",
        Path("fixtures") / f"{capture_id}.results.json",
    ]
    fixture_path = next((p for p in candidates if p.exists()), None)
    if fixture_path:
        try:
            with open(fixture_path, encoding="utf-8") as fp:
                data = json.load(fp)
            comp = data.get("compliance", {})
            return ComplianceReportResponse(
                capture_id=capture_id,
                overall_score=comp.get("overall_score", 0.0),
                grade=comp.get("grade", "N/A"),
                summary=comp.get("summary", ""),
                findings=comp.get("findings", []),
                threat_matrix=comp.get("threat_matrix", []),
                evaluated_parameters=comp.get("evaluated_parameters", {}),
                remediation_config=comp.get("remediation_config", ""),
                generated_at=comp.get("generated_at", ""),
            )
        except Exception:
            pass

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Completed compliance report for capture session '{capture_id}' not found.",
    )


@router.post(
    "/compliance/adhoc",
    response_model=ComplianceReportResponse,
    summary="Evaluate custom cryptographic parameters",
)
async def evaluate_adhoc_parameters(req: AdHocComplianceRequest) -> ComplianceReportResponse:
    """
    Instantly evaluate custom IKE/ESP parameters against RFC 8221, RFC 8247, and NIST rules.
    Does not require a PCAP upload.
    """
    report = evaluator.evaluate(
        esp_encryption=req.esp_encryption,
        esp_auth=req.esp_auth,
        dh_group=req.dh_group,
        pfs_enabled=req.pfs_enabled,
        sa_lifetime_seconds=req.sa_lifetime_seconds,
        rsa_key_bits=req.rsa_key_bits,
        ike_version=req.ike_version.value,
    )

    data = report.to_dict()
    return ComplianceReportResponse(
        capture_id="adhoc_evaluation",
        overall_score=data["overall_score"],
        grade=data["grade"],
        summary=data["summary"],
        findings=data.get("findings", []),
        threat_matrix=data.get("threat_matrix", []),
        evaluated_parameters=data.get("evaluated_parameters", {}),
        generated_at=data.get("generated_at", ""),
    )
