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


from sample_data import ensure_reports_generated


@router.get(
    "/report/{capture_id}/status",
    response_model=ReportStatusResponse,
    summary="Get report generation status",
)
async def get_report_status(capture_id: str) -> ReportStatusResponse:
    """Check if Executive and Technical PDF reports are generated and ready for download."""
    exec_path = Path("reports/output") / capture_id / "executive_summary.pdf"
    tech_path = Path("reports/output") / capture_id / "technical_assessment.pdf"

    if not exec_path.exists() or not tech_path.exists():
        if capture_id in _state_store and _state_store[capture_id].get("status") == "DONE":
            entry = _state_store[capture_id]
            generate_all_reports(
                capture_id=capture_id,
                compliance_data=entry["results"]["compliance"],
                analysis_data=entry["results"],
            )
        else:
            ensure_reports_generated(capture_id)

    exec_ready = exec_path.exists()
    tech_ready = tech_path.exists()

    return ReportStatusResponse(
        capture_id=capture_id,
        executive_ready=exec_ready,
        technical_ready=tech_ready,
        executive_url=f"/api/report/{capture_id}/executive" if exec_ready else None,
        technical_url=f"/api/report/{capture_id}/technical" if tech_ready else None,
    )


@router.post(
    "/report/{capture_id}/generate",
    summary="Trigger on-demand report generation",
)
async def trigger_generate_report(capture_id: str) -> dict[str, Any]:
    """Trigger generation of both Executive and Technical PDF reports."""
    if capture_id in _state_store and _state_store[capture_id].get("status") == "DONE":
        entry = _state_store[capture_id]
        generate_all_reports(
            capture_id=capture_id,
            compliance_data=entry["results"]["compliance"],
            analysis_data=entry["results"],
        )
    else:
        ensure_reports_generated(capture_id)

    return {
        "status": "ready",
        "report_id": capture_id,
        "executive_url": f"/api/report/{capture_id}/executive",
        "technical_url": f"/api/report/{capture_id}/technical",
    }


@router.get(
    "/report/{capture_id}/executive",
    summary="Download Executive Summary PDF",
)
async def download_executive_report(capture_id: str):
    """Download the 1-2 page Executive Summary PDF report."""
    pdf_path = Path("reports/output") / capture_id / "executive_summary.pdf"
    if not pdf_path.exists():
        if capture_id in _state_store and _state_store[capture_id].get("status") == "DONE":
            entry = _state_store[capture_id]
            generate_all_reports(
                capture_id=capture_id,
                compliance_data=entry["results"]["compliance"],
                analysis_data=entry["results"],
            )
        else:
            ensure_reports_generated(capture_id)

    if not pdf_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Executive report not found or could not be generated.",
        )

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"Janus_Executive_Report_{capture_id[:16]}.pdf",
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
            ensure_reports_generated(capture_id)

    if not pdf_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Technical report not found or could not be generated.",
        )

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"Janus_Technical_Report_{capture_id[:16]}.pdf",
    )
