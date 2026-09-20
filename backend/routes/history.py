"""
Janus Backend — Audit History & Compliance Trends Routes
=========================================================
Endpoints for querying historical audit records, compliance score trends over time,
and retrieving individual capture audit snapshots.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

try:
    from database import get_audit_by_id, get_audit_history, get_compliance_trend
except ImportError:
    from backend.database import get_audit_by_id, get_audit_history, get_compliance_trend

try:
    from security import verify_auth_or_token
except ImportError:
    from backend.security import verify_auth_or_token

router = APIRouter(dependencies=[Depends(verify_auth_or_token)])


@router.get(
    "/history",
    summary="Get paginated audit history",
    response_description="List of audit history records",
)
async def list_audit_history(
    limit: int = Query(50, ge=1, le=500, description="Maximum number of records to return"),
    offset: int = Query(0, ge=0, description="Number of records to skip"),
) -> list[dict[str, Any]]:
    """Retrieve a paginated chronological list of evaluated audit records."""
    return get_audit_history(limit=limit, offset=offset)


@router.get(
    "/history/trend",
    summary="Get chronological compliance score trends",
    response_description="List of chronological compliance score data points",
)
async def get_history_trend() -> list[dict[str, Any]]:
    """Retrieve chronological compliance score and status trends for charting."""
    return get_compliance_trend()


@router.get(
    "/history/{capture_id}",
    summary="Get full audit record by capture ID",
    response_description="Detailed audit record including full results JSON",
)
async def get_history_record(capture_id: str) -> dict[str, Any]:
    """Retrieve full audit record and stored results for a specific capture ID."""
    record = get_audit_by_id(capture_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit record for capture session '{capture_id}' not found.",
        )
    return record
