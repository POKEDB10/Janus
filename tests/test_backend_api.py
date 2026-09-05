"""
tests/test_backend_api.py
=========================
FastAPI test suite verifying REST API endpoints.
"""

import io
import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_health_endpoint():
    """Verify service health endpoint."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "Janus" in data["service"]


def test_adhoc_compliance_evaluation():
    """Test instant ad-hoc compliance scoring via POST /api/compliance/adhoc."""
    payload = {
        "esp_encryption": "ENCR_AES_GCM_16",
        "esp_auth": "AUTH_NONE",
        "dh_group": 19,
        "pfs_enabled": True,
        "sa_lifetime_seconds": 3600,
        "rsa_key_bits": 3072,
        "ike_version": "IKEv2",
    }
    res = client.post("/api/compliance/adhoc", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["overall_score"] >= 90.0
    assert data["grade"] == "A"
    assert len(data["threat_matrix"]) > 0


def test_adhoc_compliance_vulnerable_profile():
    """Test adhoc compliance evaluation on vulnerable 3DES + MD5 + DH2 parameters."""
    payload = {
        "esp_encryption": "ENCR_3DES",
        "esp_auth": "AUTH_HMAC_MD5_96",
        "dh_group": 2,
        "pfs_enabled": False,
        "sa_lifetime_seconds": 86400,
        "rsa_key_bits": 1024,
        "ike_version": "IKEv2",
    }
    res = client.post("/api/compliance/adhoc", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["overall_score"] < 50.0
    assert data["grade"] == "F"
    assert len(data["findings"]) >= 4


def test_upload_invalid_extension():
    """Verify reject on unsupported file extensions."""
    file_content = b"fake binary data"
    res = client.post(
        "/api/upload",
        files={"file": ("capture.txt", io.BytesIO(file_content), "text/plain")},
    )
    assert res.status_code == 400
    assert "Unsupported file extension" in res.json()["detail"]


def test_upload_valid_pcap_and_inspect_pipeline(sample_esp_pcap_bytes):
    """Upload valid synthetic PCAP and verify pipeline initialisation."""
    res = client.post(
        "/api/upload",
        files={"file": ("capture.pcap", io.BytesIO(sample_esp_pcap_bytes), "application/vnd.tcpdump.pcap")},
    )
    assert res.status_code == 202
    data = res.json()
    capture_id = data["capture_id"]
    assert capture_id is not None
    assert data["filename"] == "capture.pcap"

    status_res = client.get(f"/api/analysis/{capture_id}/status")
    assert status_res.status_code == 200
    assert status_res.json()["capture_id"] == capture_id
