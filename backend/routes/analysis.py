"""
Janus Backend — Analysis Routes
===============================
Endpoints for querying analysis status, flow classifications, SHAP explainability,
IKE handshake results, Server-Sent Events live progress, and CSV export.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import Response, StreamingResponse

from models import AnalysisResults, AnalysisStatus, FlowResult, PaginatedFlowsResponse, PipelineStatus

router = APIRouter()

# In-memory session store shared across API workers
_state_store: dict[str, dict[str, Any]] = {}


@router.get(
    "/analysis/{capture_id}/status",
    response_model=AnalysisStatus,
    summary="Get capture analysis progress",
)
async def get_analysis_status(capture_id: str) -> AnalysisStatus:
    """Retrieve progress and current stage of the background analysis pipeline."""
    if capture_id not in _state_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture session '{capture_id}' not found.",
        )

    entry = _state_store[capture_id]
    return AnalysisStatus(
        capture_id=capture_id,
        status=PipelineStatus(entry.get("status", "INIT")),
        error=entry.get("error"),
        progress_pct=float(entry.get("progress_pct", 0.0)),
    )


@router.get(
    "/analysis/{capture_id}/stream",
    summary="Server-Sent Events stream for live analysis progress",
    response_class=StreamingResponse,
)
async def stream_analysis_progress(capture_id: str) -> StreamingResponse:
    """
    SSE endpoint streaming analysis progress events.
    Clients should use ``EventSource('/api/analysis/{id}/stream')``.

    Events emitted:
      - ``progress`` — JSON with ``{status, progress_pct, message}``
      - ``done``     — JSON with full results summary when pipeline completes
      - ``error``    — JSON with ``{error}`` if pipeline fails
    """
    if capture_id not in _state_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture session '{capture_id}' not found.",
        )

    async def event_generator():
        """Poll state store and emit SSE events until terminal state."""
        _STATUS_MESSAGES: dict[str, str] = {
            "INIT":       "Initialising pipeline...",
            "PARSING":    "Parsing IKE handshakes & extracting ESP flows...",
            "CLASSIFYING": "Running FlowDeepNet Ensemble + SHAP attribution...",
            "SCORING":    "Evaluating RFC 8221 / RFC 8247 / NIST SP 800-77 compliance...",
            "DONE":       "Analysis complete — all results ready.",
            "ERROR":      "Pipeline encountered an error.",
        }
        last_pct = -1.0
        timeout_seconds = 300  # 5-minute max SSE lifetime
        elapsed = 0

        while elapsed < timeout_seconds:
            entry = _state_store.get(capture_id, {})
            current_status = entry.get("status", "INIT")
            current_pct = float(entry.get("progress_pct", 0.0))

            # Only emit when something changes
            if current_pct != last_pct:
                last_pct = current_pct
                payload = {
                    "status": current_status,
                    "progress_pct": current_pct,
                    "message": _STATUS_MESSAGES.get(current_status, current_status),
                }

                if current_status == "DONE":
                    results = entry.get("results") or {}
                    payload["summary"] = {
                        "total_flows": results.get("total_flows", 0),
                        "capture_id": capture_id,
                    }
                    yield f"event: done\ndata: {json.dumps(payload)}\n\n"
                    return

                if current_status == "ERROR":
                    payload["error"] = entry.get("error", "Unknown error")
                    yield f"event: error\ndata: {json.dumps(payload)}\n\n"
                    return

                yield f"event: progress\ndata: {json.dumps(payload)}\n\n"

            await asyncio.sleep(0.8)
            elapsed += 0.8

        # Timeout — send a final status and close
        yield f"event: error\ndata: {json.dumps({'error': 'SSE timeout after 5 minutes'})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering
            "Connection": "keep-alive",
        },
    )


@router.get(
    "/analysis/{capture_id}/results",
    summary="Get full analysis results",
)
async def get_analysis_results(capture_id: str) -> dict[str, Any]:
    """Retrieve complete analysis results including IKE sessions, flows, and compliance."""
    if capture_id not in _state_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture session '{capture_id}' not found.",
        )

    entry = _state_store[capture_id]
    if entry.get("status") != "DONE":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Analysis is not complete (current status: {entry.get('status')}).",
        )

    return entry.get("results", {})


@router.get(
    "/analysis/{capture_id}/export/csv",
    summary="Export flow classifications as CSV",
)
async def export_flows_csv(capture_id: str) -> StreamingResponse:
    """
    Download all classified flows as a CSV file.
    Judges can open this in Excel to verify AI predictions independently.
    """
    if capture_id not in _state_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture session '{capture_id}' not found.",
        )

    entry = _state_store[capture_id]
    results = entry.get("results") or {}
    flows = results.get("flows", [])

    if not flows:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No flows available to export.",
        )

    # Build CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "flow_id", "spi", "src_ip", "dst_ip",
        "packet_count", "duration_s", "byte_count",
        "predicted_class", "confidence_pct", "is_obfuscated", "ood_status",
        "top_shap_feature", "top_shap_value",
    ])

    for flow in flows:
        cls = flow.get("classification", {})
        shap = cls.get("shap") or {}
        shap_vals = shap.get("shap_values") or {}
        top_feat, top_val = "", ""
        if shap_vals:
            top_feat = max(shap_vals, key=lambda k: abs(shap_vals[k]))
            top_val = f"{shap_vals[top_feat]:.4f}"

        obf_details = flow.get("classification", {}).get("obfuscation_details") or {}
        ood_status = obf_details.get("status", "VERIFIED") if obf_details else "VERIFIED"

        writer.writerow([
            flow.get("flow_id", ""),
            flow.get("spi", ""),
            flow.get("src_ip", ""),
            flow.get("dst_ip", ""),
            flow.get("packet_count", ""),
            flow.get("duration_s", ""),
            flow.get("byte_count", ""),
            cls.get("label") or cls.get("traffic_type", ""),
            f"{(cls.get('confidence', 0) * 100):.1f}",
            flow.get("is_obfuscated", False),
            ood_status,
            top_feat,
            top_val,
        ])

    csv_content = output.getvalue()
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=janus_flows_{capture_id[:8]}.csv"
        },
    )


@router.get(
    "/analysis/{capture_id}/flows",
    response_model=PaginatedFlowsResponse,
    summary="Get paginated flow list",
)
async def get_flows(
    capture_id: str,
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
) -> PaginatedFlowsResponse:
    """Retrieve paginated flow classifications for the capture."""
    if capture_id not in _state_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture session '{capture_id}' not found.",
        )

    entry = _state_store[capture_id]
    results = entry.get("results") or {}
    flows = results.get("flows", [])

    total = len(flows)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paged_flows = flows[start_idx:end_idx]

    return PaginatedFlowsResponse(
        total=total,
        page=page,
        page_size=page_size,
        flows=paged_flows,
    )


@router.get(
    "/analysis/{capture_id}/flows/{flow_id}",
    summary="Get details for a specific flow",
)
async def get_flow_detail(capture_id: str, flow_id: str) -> dict[str, Any]:
    """Retrieve detailed flow information including stats and classification."""
    if capture_id not in _state_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture session '{capture_id}' not found.",
        )

    results = _state_store[capture_id].get("results") or {}
    flows = results.get("flows", [])
    for f in flows:
        if f.get("flow_id") == flow_id:
            return f

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Flow '{flow_id}' not found in capture '{capture_id}'.",
    )


@router.get(
    "/analysis/{capture_id}/shap/{flow_id}",
    summary="Get SHAP explanation for a specific flow",
)
async def get_flow_shap(capture_id: str, flow_id: str) -> dict[str, Any]:
    """Retrieve local SHAP feature attribution explanation for a single flow."""
    if capture_id not in _state_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture session '{capture_id}' not found.",
        )

    results = _state_store[capture_id].get("results") or {}
    flows = results.get("flows", [])
    for f in flows:
        if f.get("flow_id") == flow_id:
            cls_info = f.get("classification") or {}
            shap_info = cls_info.get("shap")
            if not shap_info:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"No SHAP explanation available for flow '{flow_id}'.",
                )
            return shap_info

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Flow '{flow_id}' not found in capture '{capture_id}'.",
    )


@router.get(
    "/analysis/{capture_id}/ike",
    summary="Get parsed IKE handshake sessions",
)
async def get_ike_details(capture_id: str) -> list[dict[str, Any]]:
    """Retrieve detailed IKE handshake proposals and negotiated transforms."""
    if capture_id not in _state_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture session '{capture_id}' not found.",
        )

    results = _state_store[capture_id].get("results") or {}
    return results.get("ike_sessions", [])
