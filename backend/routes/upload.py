"""
Janus API – PCAP upload route.

POST /api/upload
  - Accepts multipart file uploads of .pcap / .pcapng files.
  - Validates file extension and magic bytes before accepting.
  - Saves to captures/{uuid}/input.pcap using async I/O.
  - Immediately enqueues the analysis pipeline as a BackgroundTask.
  - Returns UploadResponse with capture_id, filename, size, and status.

File size limit: 100 MB
"""

from __future__ import annotations

import logging
import struct
import uuid
from pathlib import Path

import aiofiles
from fastapi import APIRouter, BackgroundTasks, HTTPException, UploadFile, status
from fastapi.responses import FileResponse

from models import UploadResponse
from pipeline import run_analysis_pipeline

# Shared in-memory state store imported from analysis module.
from routes.analysis import _state_store

log = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_UPLOAD_BYTES: int = 100 * 1024 * 1024  # 100 MB

# PCAP magic bytes (little-endian and big-endian variants).
_PCAP_MAGIC_LE: bytes = struct.pack("<I", 0xA1B2C3D4)
_PCAP_MAGIC_BE: bytes = struct.pack(">I", 0xA1B2C3D4)
# PCAPng section header block magic.
_PCAPNG_MAGIC: bytes = struct.pack("<I", 0x0A0D0D0A)

_ALLOWED_EXTENSIONS: frozenset[str] = frozenset({".pcap", ".pcapng"})

_CAPTURES_DIR = Path("captures")


# ---------------------------------------------------------------------------
# Helper: magic-byte validation
# ---------------------------------------------------------------------------


def _validate_magic(header: bytes, filename: str) -> None:
    """
    Verify that *header* starts with a recognised PCAP or PCAPng magic sequence.

    Args:
        header:   First 4 bytes of the uploaded file.
        filename: Original filename (used only for the error message).

    Raises:
        HTTPException: 400 if the magic bytes are not recognised.
    """
    if header[:4] in (_PCAP_MAGIC_LE, _PCAP_MAGIC_BE, _PCAPNG_MAGIC):
        return
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=(
            f"File '{filename}' does not appear to be a valid PCAP or PCAPng file "
            f"(unrecognised magic bytes: {header[:4].hex()})."
        ),
    )


# ---------------------------------------------------------------------------
# Upload endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/upload",
    response_model=UploadResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Upload a PCAP or PCAPng file for analysis",
)
@router.post(
    "/captures/upload",
    response_model=UploadResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Upload a PCAP or PCAPng file for analysis (alias)",
)
async def upload_pcap(
    file: UploadFile,
    background_tasks: BackgroundTasks,
) -> UploadResponse:
    """
    Accept a PCAP / PCAPng file upload and enqueue it for analysis.

    The file is saved to ``captures/{capture_id}/input.pcap``.  The analysis
    pipeline is started as a background task immediately after saving.

    Args:
        file:             The uploaded file (multipart/form-data).
        background_tasks: FastAPI background task registry.

    Returns:
        :class:`UploadResponse` with the new ``capture_id``.

    Raises:
        HTTPException 400: Invalid file extension or magic bytes.
        HTTPException 413: File exceeds the 100 MB limit.
    """
    filename = file.filename or "unknown.pcap"
    ext = Path(filename).suffix.lower()

    # --- Extension check ---
    if ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension '{ext}'. Allowed: {sorted(_ALLOWED_EXTENSIONS)}",
        )

    # --- Read file content with size guard ---
    # We read in chunks to avoid loading huge files into memory atomically,
    # but we still accumulate bytes here for magic-byte inspection and disk write.
    # For very large captures this could be replaced with streaming to disk first.
    chunks: list[bytes] = []
    total_bytes = 0

    while True:
        chunk = await file.read(65536)  # 64 KiB chunks
        if not chunk:
            break
        total_bytes += len(chunk)
        if total_bytes > _MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Upload exceeds the maximum allowed size of {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB.",
            )
        chunks.append(chunk)

    raw_content = b"".join(chunks)

    # --- Magic-byte check (needs at least 4 bytes) ---
    if len(raw_content) < 4:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is too small to be a valid PCAP.",
        )
    _validate_magic(raw_content[:4], filename)

    # --- Persist to disk ---
    capture_id = str(uuid.uuid4())
    capture_dir = _CAPTURES_DIR / capture_id
    capture_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = capture_dir / "input.pcap"

    async with aiofiles.open(pcap_path, "wb") as fh:
        await fh.write(raw_content)

    log.info(
        "Upload saved: capture_id=%s, filename=%s, size_bytes=%d, path=%s",
        capture_id,
        filename,
        total_bytes,
        str(pcap_path),
    )

    # --- Initialise state store entry ---
    _state_store[capture_id] = {
        "status": "INIT",
        "filename": filename,
        "size_bytes": total_bytes,
        "results": None,
        "error": None,
    }

    # --- Enqueue pipeline as background task ---
    background_tasks.add_task(
        run_analysis_pipeline,
        capture_id=capture_id,
        pcap_path=str(pcap_path),
        state_store=_state_store,
    )

    return UploadResponse(
        capture_id=capture_id,
        filename=filename,
        size_bytes=total_bytes,
        status="uploaded",
    )


# ---------------------------------------------------------------------------
# Sample PCAPs catalog & download endpoints
# ---------------------------------------------------------------------------

_ROOT_DIR = Path(__file__).resolve().parent.parent

SAMPLE_PCAPS: dict[str, dict] = {
    "wireshark_ikev2_aes_gcm": {
        "id": "wireshark_ikev2_aes_gcm",
        "filename": "wireshark_ikev2_aes_gcm.pcap",
        "title": "Wireshark Public PCAP — Site-to-Site IKEv2 AES-GCM",
        "category": "Compliant Production VPN",
        "rfc_status": "RFC 8221 / 8247 Compliant (Grade A, 96/100)",
        "cipher": "AES-256-GCM / SHA-384 / DH Group 19 (NIST P-256)",
        "description": "Standard Wireshark public capture of strongSwan site-to-site IPsec tunnel with modern AEAD AES-GCM and Perfect Forward Secrecy.",
        "relative_path": "samples/wireshark_ikev2_aes_gcm.pcap",
        "external_url": "https://wiki.wireshark.org/SampleCaptures#ipsec",
        "size_bytes": 3356,
    },
    "scenario_04_weak_3des": {
        "id": "scenario_04_weak_3des",
        "filename": "scenario_04_weak_3des.pcap",
        "title": "Legacy Enterprise IPsec — Broken 3DES + MD5 + No PFS",
        "category": "Vulnerable / Deprecated Suite",
        "rfc_status": "RFC 8221 Critical Failure (Grade F, 25/100)",
        "cipher": "3DES-CBC / MD5-HMAC / DH Group 2 (1024-bit MODP)",
        "description": "Legacy Sweet32-vulnerable capture demonstrating CVE-2016-2183 64-bit block collision risks and Logjam-vulnerable DH group 2.",
        "relative_path": "samples/scenario_04_weak_3des.pcap",
        "external_url": "https://wiki.wireshark.org/SampleCaptures#ipsec",
        "size_bytes": 41624,
    },
    "scenario_01_hardened": {
        "id": "scenario_01_hardened",
        "filename": "scenario_01_hardened.pcap",
        "title": "RFC 9347 IP-TFS Hardened Tunnel — Zero Metadata Leakage",
        "category": "CNSA 2.0 / Post-Quantum Ready",
        "rfc_status": "RFC 9347 & CNSA 2.0 Hardened (Grade A, 100/100)",
        "cipher": "ChaCha20-Poly1305 / SHA-512 / DH Group 31 (Curve25519)",
        "description": "Aggressive traffic-flow confidentiality with constant packet sizing and dummy burst injection defeating ML side-channel classifiers.",
        "relative_path": "samples/scenario_01_hardened.pcap",
        "external_url": "https://wiki.wireshark.org/SampleCaptures#ipsec",
        "size_bytes": 41624,
    },
    "wireshark_http_sample": {
        "id": "wireshark_http_sample",
        "filename": "wireshark_http_sample.pcap",
        "title": "Wireshark Generic Traffic — HTTP Web Trace (Non-IPsec)",
        "category": "External Standard Traffic",
        "rfc_status": "Non-Encrypted Ingestion Test",
        "cipher": "Cleartext HTTP / TCP Port 80",
        "description": "Standard Wireshark public capture demonstrating how Janus handles arbitrary external PCAP files without crashing.",
        "relative_path": "samples/wireshark_http_sample.pcap",
        "external_url": "https://wiki.wireshark.org/SampleCaptures#hypertext-transfer-protocol-http",
        "size_bytes": 25803,
    },
}


@router.get(
    "/samples",
    summary="List available sample PCAP captures for test uploads",
)
@router.get(
    "/captures/samples",
    summary="List available sample PCAP captures for test uploads (alias)",
)
def get_sample_pcaps() -> list[dict]:
    """Return catalog of sample PCAPs available for 1-click download and live testing."""
    samples = []
    for s_id, s in SAMPLE_PCAPS.items():
        sample_copy = dict(s)
        sample_copy["download_url"] = f"/api/samples/{s_id}/download"
        del sample_copy["relative_path"]
        samples.append(sample_copy)
    return samples


@router.get(
    "/samples/{sample_id}/download",
    summary="Download a sample PCAP file",
)
@router.get(
    "/captures/samples/{sample_id}/download",
    summary="Download a sample PCAP file (alias)",
)
def download_sample_pcap(sample_id: str):
    """Serve a sample PCAP file as a binary attachment download."""
    if sample_id not in SAMPLE_PCAPS:
        raise HTTPException(status_code=404, detail=f"Sample PCAP '{sample_id}' not found.")

    meta = SAMPLE_PCAPS[sample_id]
    rel_path = meta["relative_path"]
    candidates = [
        _ROOT_DIR / rel_path,
        Path(rel_path),
        _ROOT_DIR / "dataset" / "public_pcaps" / meta["filename"],
    ]
    file_path = next((p for p in candidates if p.exists() and p.is_file()), None)
    if not file_path:
        raise HTTPException(
            status_code=404,
            detail=f"Sample PCAP file for '{sample_id}' not found on server disk.",
        )

    return FileResponse(
        path=str(file_path),
        filename=meta["filename"],
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f'attachment; filename="{meta["filename"]}"'},
    )

