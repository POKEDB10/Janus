"""
Janus Backend — Report Routes
=============================
Endpoints for generating and downloading Executive and Technical PDF security reports.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse

from models import ReportStatusResponse
from reports.generator import generate_all_reports
from routes.analysis import _state_store

router = APIRouter()


@router.get(
    "/report/{capture_id}/status",
    response_model=ReportStatusResponse,
    summary="Get report generation status",
)
async def get_report_status(capture_id: str) -> ReportStatusResponse:
    """Check if Executive and Technical PDF reports are generated and ready for download."""
    if capture_id not in _state_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture session '{capture_id}' not found.",
        )

    exec_path = Path("reports/output") / capture_id / "executive_summary.pdf"
    tech_path = Path("reports/output") / capture_id / "technical_assessment.pdf"

    exec_ready = exec_path.exists()
    tech_ready = tech_path.exists()

    return ReportStatusResponse(
        capture_id=capture_id,
        executive_ready=exec_ready,
        technical_ready=tech_ready,
        executive_url=f"/api/report/{capture_id}/executive" if exec_ready else None,
        technical_url=f"/api/report/{capture_id}/technical" if tech_ready else None,
    )


@router.get(
    "/report/{capture_id}/executive",
    summary="Download Executive Summary PDF",
)
async def download_executive_report(capture_id: str):
    """Download the 1-2 page Executive Summary PDF report."""
    pdf_path = Path("reports/output") / capture_id / "executive_summary.pdf"
    if not pdf_path.exists():
        # Check if results are available to generate on demand
        if capture_id in _state_store and _state_store[capture_id].get("status") == "DONE":
            entry = _state_store[capture_id]
            generate_all_reports(
                capture_id=capture_id,
                compliance_data=entry["results"]["compliance"],
                analysis_data=entry["results"],
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Executive report not found or not yet generated.",
            )

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"Janus_Executive_Report_{capture_id[:8]}.pdf",
    )


@router.get(
    "/report/{capture_id}/technical",
    summary="Download Technical Assessment PDF",
)
async def download_technical_report(capture_id: str):
    """Download the comprehensive Technical Protocol Audit PDF report."""
    pdf_path = Path("reports/output") / capture_id / "technical_assessment.pdf"
    if not pdf_path.exists():
        if capture_id in _state_store and _state_store[capture_id].get("status") == "DONE":
            entry = _state_store[capture_id]
            generate_all_reports(
                capture_id=capture_id,
                compliance_data=entry["results"]["compliance"],
                analysis_data=entry["results"],
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Technical report not found or not yet generated.",
            )

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"Janus_Technical_Report_{capture_id[:8]}.pdf",
    )
