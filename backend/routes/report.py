"""
Janus Backend — Report Routes
=============================
Endpoints for generating and downloading Executive and Technical PDF security reports.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse

from models import ReportStatusResponse
from reports.generator import generate_all_reports
from routes.analysis import _get_entry, _state_store
from security import verify_auth_or_token

router = APIRouter(dependencies=[Depends(verify_auth_or_token)])


def _ensure_report_generated(capture_id: str) -> tuple[Path, Path]:
    """Ensure both Executive and Technical reports are generated for capture_id."""
    exec_path = Path("reports/output") / capture_id / "executive_summary.pdf"
    tech_path = Path("reports/output") / capture_id / "technical_assessment.pdf"

    if exec_path.exists() and tech_path.exists():
        return exec_path, tech_path

    # 1. Check in-memory or persistent SQLite audit record
    entry = _get_entry(capture_id)
    if entry and entry.get("status") == "DONE":
        generate_all_reports(
            capture_id=capture_id,
            compliance_data=entry["results"]["compliance"],
            analysis_data=entry["results"],
        )
        return exec_path, tech_path

    # 2. Check offline fixture results for demo captures
    candidates = [
        Path("frontend/src/fixtures") / f"{capture_id}.results.json",
        Path("/app/frontend/src/fixtures") / f"{capture_id}.results.json",
        Path("fixtures") / f"{capture_id}.results.json",
    ]
    fixture_path = next((p for p in candidates if p.exists()), None)
    if fixture_path:
        import json
        with open(fixture_path, encoding="utf-8") as f:
            fixture_data = json.load(f)
        generate_all_reports(
            capture_id=capture_id,
            compliance_data=fixture_data.get("compliance", {}),
            analysis_data=fixture_data,
        )
        return exec_path, tech_path

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Completed analysis for capture session '{capture_id}' not found.",
    )


@router.get(
    "/report/{capture_id}/status",
    response_model=ReportStatusResponse,
    summary="Get report generation status",
)
@router.get(
    "/report/{capture_id}/status/{report_id}",
    response_model=ReportStatusResponse,
    summary="Get report generation status (with report_id)",
)
async def get_report_status(capture_id: str, report_id: str = "") -> ReportStatusResponse:
    """Check if Executive and Technical PDF reports are generated and ready for download."""
    exec_path, tech_path = _ensure_report_generated(capture_id)
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
    _ensure_report_generated(capture_id)
    return {
        "status": "ready",
        "report_id": capture_id,
        "executive_url": f"/api/report/{capture_id}/executive",
        "technical_url": f"/api/report/{capture_id}/technical",
    }


@router.get(
    "/report/{capture_id}/executive",
    summary="Download or Preview Executive Summary PDF",
)
async def download_executive_report(capture_id: str, download: bool = False):
    """Serve the 1-2 page Executive Summary PDF report (inline preview by default, or attachment)."""
    exec_path, _ = _ensure_report_generated(capture_id)
    if not exec_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Executive report not found or could not be generated.",
        )

    return FileResponse(
        path=str(exec_path),
        media_type="application/pdf",
        filename=f"Janus_Executive_Report_{capture_id[:16]}.pdf",
        content_disposition_type="attachment" if download else "inline",
    )


@router.get(
    "/report/{capture_id}/technical",
    summary="Download or Preview Technical Assessment PDF",
)
async def download_technical_report(capture_id: str, download: bool = False):
    """Serve the comprehensive Technical Protocol Audit PDF report (inline preview by default, or attachment)."""
    _, tech_path = _ensure_report_generated(capture_id)
    if not tech_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Technical report not found or could not be generated.",
        )

    return FileResponse(
        path=str(tech_path),
        media_type="application/pdf",
        filename=f"Janus_Technical_Report_{capture_id[:16]}.pdf",
        content_disposition_type="attachment" if download else "inline",
    )
