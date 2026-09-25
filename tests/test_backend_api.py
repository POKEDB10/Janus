"""
tests/test_backend_api.py
=========================
FastAPI test suite verifying REST API endpoints.
"""

import io
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from tests.conftest import TEST_API_KEY

client = TestClient(app, headers={"X-API-Key": TEST_API_KEY})


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


def test_regression_bug02_pcap_without_ike_returns_indeterminate(sample_esp_pcap_bytes):
    """
    REGRESSION TEST FOR BUG-02:
    Verify that an arbitrary, randomly named PCAP without an IKE handshake
    returns status: INDETERMINATE, score: None, and grade: 'N/A' rather than
    silently defaulting to AES-256-GCM / Grade A based on fallback logic.
    """
    import asyncio
    from backend.pipeline import run_analysis_pipeline
    from routes.analysis import _state_store

    capture_id = "test_reg_bug02_random_94821"
    random_filename = "unlabeled_field_capture_84712.pcap"

    # Save bytes to disk
    import tempfile
    with tempfile.NamedTemporaryFile(suffix="_" + random_filename, delete=False) as f:
        f.write(sample_esp_pcap_bytes)
        pcap_path = f.name

    try:
        _state_store[capture_id] = {
            "status": "INIT",
            "filename": random_filename,
            "size_bytes": len(sample_esp_pcap_bytes),
            "results": None,
        }

        asyncio.run(run_analysis_pipeline(capture_id, pcap_path, _state_store))

        entry = _state_store[capture_id]
        assert entry["status"] == "DONE"
        results = entry["results"]
        assert results is not None
        assert results["status"] == "INDETERMINATE"
        assert results["compliance"]["grade"] == "N/A"
        assert results["compliance"]["overall_score"] is None
        assert "IKE handshake not present" in results["compliance"]["indeterminate_reason"]
    finally:
        from pathlib import Path
        Path(pcap_path).unlink(missing_ok=True)
        _state_store.pop(capture_id, None)


def test_regression_bug02_adversarial_filename_decoupling():
    """
    REGRESSION TEST FOR BUG-02 DECOUPLING:
    Verify that compliance evaluation is 100% driven by actual IKE payload inspection
    and completely decoupled from filename semantics.

    Adversarial cross-check:
    1) A genuinely vulnerable capture (synthetic 3DES/MD5/DH2) renamed to an innocent,
       good-sounding name ('enterprise_hardened_aes256_gcm_pass.pcap') MUST evaluate
       to Grade F (score <= 50.0) with SWEET32 / MD5 findings, NOT Grade A.
    2) A genuinely compliant capture (Wireshark AES-GCM) renamed to an alarming,
       failure-sounding name ('scenario_04_weak_3des_md5_critical_fail.pcap') MUST
       evaluate to Grade A (score 100.0), NOT Grade F.
    """
    import asyncio
    import shutil
    import tempfile
    from pathlib import Path
    from backend.pipeline import run_analysis_pipeline
    from routes.analysis import _state_store

    bad_pcap = Path("tests/fixtures/synthetic_3des_ike_sa_init.pcap")
    good_pcap = Path("samples/wireshark_ikev2_aes_gcm.pcap")
    assert bad_pcap.exists(), "Required fixture tests/fixtures/synthetic_3des_ike_sa_init.pcap missing"
    assert good_pcap.exists(), "Required sample samples/wireshark_ikev2_aes_gcm.pcap missing"

    with tempfile.TemporaryDirectory() as td:
        # Case 1: Bad capture given innocent name
        innocent_name = "enterprise_hardened_aes256_gcm_pass.pcap"
        bad_renamed = Path(td) / innocent_name
        shutil.copy(bad_pcap, bad_renamed)
        cid_bad = "test_adversarial_bad_renamed"
        _state_store[cid_bad] = {
            "status": "INIT",
            "filename": innocent_name,
            "size_bytes": bad_renamed.stat().st_size,
            "results": None,
        }

        # Case 2: Good capture given failing name
        failing_name = "scenario_04_weak_3des_md5_critical_fail.pcap"
        good_renamed = Path(td) / failing_name
        shutil.copy(good_pcap, good_renamed)
        cid_good = "test_adversarial_good_renamed"
        _state_store[cid_good] = {
            "status": "INIT",
            "filename": failing_name,
            "size_bytes": good_renamed.stat().st_size,
            "results": None,
        }

        try:
            # Run Case 1: Vulnerable payload must fail regardless of innocent name
            asyncio.run(run_analysis_pipeline(cid_bad, str(bad_renamed), _state_store))
            res_bad = _state_store[cid_bad]["results"]
            assert res_bad is not None
            assert res_bad["compliance"]["grade"] == "F"
            assert res_bad["compliance"]["overall_score"] == 10.0
            finding_ids = [f["rule_id"] for f in res_bad["compliance"]["findings"]]
            assert "RFC8221-ENCR_3DES" in finding_ids  # 3DES SWEET32
            assert "RFC8221-AUTH_HMAC_MD5_96" in finding_ids  # MD5 SLOTH
            assert "RFC8247-DH_GROUP_2" in finding_ids  # DH Group 2 Logjam

            # Run Case 2: Compliant payload must pass regardless of failing name
            asyncio.run(run_analysis_pipeline(cid_good, str(good_renamed), _state_store))
            res_good = _state_store[cid_good]["results"]
            assert res_good is not None
            assert res_good["compliance"]["grade"] == "A"
            assert res_good["compliance"]["overall_score"] == 100.0
            assert len(res_good["compliance"]["findings"]) == 0
        finally:
            _state_store.pop(cid_bad, None)
            _state_store.pop(cid_good, None)


def test_model_info_returns_live_evaluation():
    """Verify /api/model/info returns structured metrics loaded from artifacts."""
    res = client.get("/api/model/info")
    assert res.status_code == 200
    data = res.json()
    assert "Janus" in data["model_name"]
    assert "evaluation" in data
    assert "holdout_accuracy" in data["evaluation"]
    assert "data_source_caveat" in data["evaluation"]


def test_bola_unauthorized_access_rejected():
    """Verify BOLA defense: accessing an analysis session without auth or valid token is rejected."""
    unauthed_client = TestClient(app)  # No API key
    res = unauthed_client.get("/api/analysis/fake_or_intercepted_session_id/status")
    assert res.status_code == 401
    assert "Unauthorized" in res.json()["detail"] or "valid 'X-API-Key'" in res.json()["detail"]


def test_bola_valid_capture_token_grants_access():
    """Verify BOLA defense: a valid capture_token allows access without master API key."""
    from backend.security import generate_capture_token
    from routes.analysis import _state_store

    capture_id = "test_bola_session_8812"
    valid_token = generate_capture_token(capture_id)
    _state_store[capture_id] = {
        "status": "DONE",
        "progress_pct": 100.0,
        "message": "Done",
        "logs": [],
    }

    try:
        unauthed_client = TestClient(app)  # No master API key

        # 1. Without token -> 401 Unauthorized
        res_no_tok = unauthed_client.get(f"/api/analysis/{capture_id}/status")
        assert res_no_tok.status_code == 401

        # 2. With forged token -> 401 Unauthorized
        res_bad_tok = unauthed_client.get(
            f"/api/analysis/{capture_id}/status",
            headers={"X-Capture-Token": "forged_invalid_token_123"},
        )
        assert res_bad_tok.status_code == 401

        # 3. With legitimate token -> 200 OK
        res_good_tok = unauthed_client.get(
            f"/api/analysis/{capture_id}/status",
            headers={"X-Capture-Token": valid_token},
        )
        assert res_good_tok.status_code == 200
        assert res_good_tok.json()["capture_id"] == capture_id

        # 4. With query param ?token= -> 200 OK
        res_query_tok = unauthed_client.get(f"/api/analysis/{capture_id}/status?token={valid_token}")
        assert res_query_tok.status_code == 200
    finally:
        _state_store.pop(capture_id, None)


