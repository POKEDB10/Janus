"""
Janus API — Security & BOLA Protection Module
=============================================
Provides authentication dependencies and object-level ownership checks (BOLA defense)
for upload, analysis, and report endpoints.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Optional
from fastapi import HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, APIKeyQuery

JANUS_REQUIRE_AUTH = os.getenv("JANUS_REQUIRE_AUTH", "true").lower() in ("true", "1", "yes")
JANUS_API_KEY = os.getenv("JANUS_API_KEY")
_token_secret_str = os.getenv("JANUS_TOKEN_SECRET")

if JANUS_REQUIRE_AUTH:
    if not JANUS_API_KEY:
        raise RuntimeError(
            "JANUS_REQUIRE_AUTH is true but JANUS_API_KEY environment variable is not set. "
            "A master API key must be configured in the environment."
        )
    if not _token_secret_str:
        raise RuntimeError(
            "JANUS_REQUIRE_AUTH is true but JANUS_TOKEN_SECRET environment variable is not set. "
            "A token secret salt must be configured in the environment."
        )
    JANUS_TOKEN_SECRET = _token_secret_str.encode()
else:
    JANUS_TOKEN_SECRET = _token_secret_str.encode() if _token_secret_str else b""

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
api_key_query = APIKeyQuery(name="api_key", auto_error=False)
capture_token_header = APIKeyHeader(name="X-Capture-Token", auto_error=False)
capture_token_query = APIKeyQuery(name="token", auto_error=False)


DEMO_CAPTURE_IDS: set[str] = {
    "wireshark_ikev2_aes_gcm",
    "sample_1_ikev2_aes_gcm",
    "sample_2_multi_suite",
    "sample_3_heavy_esp",
    "sample_4_sweet32_3des",
}


def is_demo_capture(capture_id: str) -> bool:
    """Check if capture_id corresponds to a built-in demo fixture or sample."""
    if not capture_id:
        return False
    cid = capture_id.strip()
    if cid in DEMO_CAPTURE_IDS:
        return True
    if cid.startswith("sample_") or cid.startswith("wireshark_"):
        return True
    from pathlib import Path
    for candidate in [
        Path("frontend/src/fixtures") / f"{cid}.results.json",
        Path("/app/frontend/src/fixtures") / f"{cid}.results.json",
        Path("fixtures") / f"{cid}.results.json",
    ]:
        if candidate.exists():
            return True
    return False


def generate_capture_token(capture_id: str) -> str:
    """Generate a deterministic HMAC-SHA256 token proving ownership of a capture_id."""
    return hmac.new(JANUS_TOKEN_SECRET, capture_id.encode(), hashlib.sha256).hexdigest()[:24]


def verify_capture_token(capture_id: str, token: str) -> bool:
    """Constant-time verification of a capture ownership token."""
    if is_demo_capture(capture_id):
        return True
    if not token:
        return False
    expected = generate_capture_token(capture_id)
    return hmac.compare_digest(expected, token)


async def verify_auth_or_token(
    request: Request,
    api_key_h: Optional[str] = Security(api_key_header),
    api_key_q: Optional[str] = Security(api_key_query),
    cap_token_h: Optional[str] = Security(capture_token_header),
    cap_token_q: Optional[str] = Security(capture_token_query),
) -> None:
    """
    BOLA & Authentication Guard:
    Grants access if:
    1. Authentication is globally disabled (JANUS_REQUIRE_AUTH=false)
    2. A valid master API Key is provided via X-API-Key header, Authorization Bearer, or ?api_key
    3. The requested resource is a built-in public demonstration capture / fixture
    4. A valid capture ownership token is provided matching the route's capture_id
    """
    if not JANUS_REQUIRE_AUTH:
        return

    # 1. Check master API key
    provided_key = api_key_h or api_key_q
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        provided_key = auth_header[7:].strip()

    if provided_key and JANUS_API_KEY and hmac.compare_digest(provided_key, JANUS_API_KEY):
        return

    # 2. Check object-level authorization (BOLA) for routes with capture_id path parameter
    capture_id = request.path_params.get("capture_id")
    if capture_id and is_demo_capture(capture_id):
        return

    provided_token = cap_token_h or cap_token_q

    if capture_id and provided_token:
        if verify_capture_token(capture_id, provided_token):
            return

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=(
            "Unauthorized access: valid 'X-API-Key' or 'X-Capture-Token' required."
        ),
        headers={"WWW-Authenticate": "ApiKey"},
    )


async def verify_admin_api_key(
    request: Request,
    api_key_h: Optional[str] = Security(api_key_header),
    api_key_q: Optional[str] = Security(api_key_query),
) -> None:
    """
    Unconditional Admin Route Guard:
    Enforces master JANUS_API_KEY authentication on privileged routes (/api/live/*, /api/history/*).
    
    This function intentionally DOES NOT check JANUS_REQUIRE_AUTH and DOES NOT accept
    capture ownership tokens. Setting JANUS_REQUIRE_AUTH=false globally CANNOT bypass this guard.
    """
    if not JANUS_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfiguration: JANUS_API_KEY environment variable is not configured.",
        )

    provided_key = api_key_h or api_key_q
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        provided_key = auth_header[7:].strip()

    if not provided_key or not hmac.compare_digest(provided_key, JANUS_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin access denied: valid master 'X-API-Key' or 'Authorization: Bearer <key>' required.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

