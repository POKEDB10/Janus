"""
tests/test_audit_history.py
===========================
Unit & integration tests for SQLite audit history and compliance trends:
1. Database initialization and CRUD operations
2. Trend analytics generation
3. Pipeline automatic recording
4. API history endpoints (/api/history, /api/history/trend, /api/history/{capture_id})
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.database import (
    delete_audit_record,
    get_audit_by_id,
    get_audit_history,
    get_compliance_trend,
    init_db,
    record_audit,
)
from backend.main import app
from tests.conftest import TEST_API_KEY


@pytest.fixture
def temp_db(tmp_path):
    """Provides an isolated SQLite database path for testing."""
    db_file = tmp_path / "test_janus_history.db"
    init_db(db_file)
    return db_file


def test_init_and_record_audit(temp_db):
    """Verify recording an audit entry with compliance and flow data."""
    results = {
        "capture_id": "test_cap_01",
        "status": "DONE",
        "total_flows": 12,
        "traffic_distribution": {"VoIP": 5, "Web": 7},
        "compliance": {
            "overall_score": 95.0,
            "grade": "A",
            "pqc_status": "CRQC_VULNERABLE",
            "findings": [],
        },
        "flows": [{"flow_id": f"f_{i}"} for i in range(12)],
    }

    row_id = record_audit("test_cap_01", "capture_01.pcap", results, db_path=temp_db)
    assert row_id > 0

    record = get_audit_by_id("test_cap_01", db_path=temp_db)
    assert record is not None
    assert record["capture_id"] == "test_cap_01"
    assert record["filename"] == "capture_01.pcap"
    assert record["overall_score"] == 95.0
    assert record["grade"] == "A"
    assert record["status"] == "DONE"
    assert record["pqc_status"] == "CRQC_VULNERABLE"
    assert record["total_flows"] == 12
    assert record["traffic_breakdown"]["VoIP"] == 5
    assert record["results"]["capture_id"] == "test_cap_01"


def test_upsert_audit_record(temp_db):
    """Verify that re-analyzing the same capture_id updates the existing record."""
    initial_results = {
        "capture_id": "test_cap_02",
        "status": "DONE",
        "total_flows": 3,
        "compliance": {"overall_score": 75.0, "grade": "C", "findings": [{"rule_id": "TEST"}]},
    }
    record_audit("test_cap_02", "initial.pcap", initial_results, db_path=temp_db)

    updated_results = {
        "capture_id": "test_cap_02",
        "status": "DONE",
        "total_flows": 10,
        "compliance": {"overall_score": 100.0, "grade": "A", "findings": []},
    }
    record_audit("test_cap_02", "updated.pcap", updated_results, db_path=temp_db)

    record = get_audit_by_id("test_cap_02", db_path=temp_db)
    assert record["filename"] == "updated.pcap"
    assert record["overall_score"] == 100.0
    assert record["grade"] == "A"
    assert record["total_flows"] == 10

    # Ensure no duplicate entries exist
    history = get_audit_history(db_path=temp_db)
    assert len(history) == 1


def test_compliance_trend_and_history_pagination(temp_db):
    """Verify chronological ordering for trends and pagination for history."""
    for i in range(5):
        score = 60.0 + i * 8.0
        results = {
            "capture_id": f"cap_{i:02d}",
            "status": "DONE",
            "compliance": {"overall_score": score, "grade": "B", "findings": []},
        }
        record_audit(f"cap_{i:02d}", f"file_{i}.pcap", results, db_path=temp_db)

    # Compliance trend: oldest to newest
    trend = get_compliance_trend(db_path=temp_db)
    assert len(trend) == 5
    assert [t["overall_score"] for t in trend] == [60.0, 68.0, 76.0, 84.0, 92.0]

    # History: paginated, newest first
    p1 = get_audit_history(limit=2, offset=0, db_path=temp_db)
    assert len(p1) == 2
    assert p1[0]["capture_id"] == "cap_04"

    p2 = get_audit_history(limit=2, offset=2, db_path=temp_db)
    assert len(p2) == 2
    assert p2[0]["capture_id"] == "cap_02"


def test_delete_audit_record(temp_db):
    """Verify audit record deletion."""
    record_audit("to_delete", "temp.pcap", {"compliance": {"overall_score": 50.0}}, db_path=temp_db)
    assert get_audit_by_id("to_delete", db_path=temp_db) is not None

    deleted = delete_audit_record("to_delete", db_path=temp_db)
    assert deleted is True
    assert get_audit_by_id("to_delete", db_path=temp_db) is None


def test_api_history_endpoints(monkeypatch, temp_db):
    """Verify FastAPI GET /api/history and GET /api/history/trend endpoints."""
    monkeypatch.setenv("JANUS_DB_PATH", str(temp_db))

    # Seed test database
    record_audit(
        "api_cap_1",
        "sample.pcap",
        {
            "capture_id": "api_cap_1",
            "status": "DONE",
            "compliance": {"overall_score": 90.0, "grade": "A", "findings": []},
        },
        db_path=temp_db,
    )

    client = TestClient(app)
    headers = {"X-API-Key": TEST_API_KEY}

    # Test GET /api/history
    resp = client.get("/api/history", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 1
    assert data[0]["capture_id"] == "api_cap_1"

    # Test GET /api/history/trend
    resp_trend = client.get("/api/history/trend", headers=headers)
    assert resp_trend.status_code == 200
    trend_data = resp_trend.json()
    assert len(trend_data) >= 1
    assert trend_data[0]["overall_score"] == 90.0

    # Test GET /api/history/{capture_id}
    resp_item = client.get("/api/history/api_cap_1", headers=headers)
    assert resp_item.status_code == 200
    item_data = resp_item.json()
    assert item_data["capture_id"] == "api_cap_1"

    # Test GET /api/history/nonexistent -> 404
    resp_404 = client.get("/api/history/nonexistent_id", headers=headers)
    assert resp_404.status_code == 404


def test_pipeline_persists_to_database(monkeypatch, temp_db):
    """Verify that run_analysis_pipeline automatically stores results in SQLite database."""
    import asyncio
    import tempfile
    from backend.pipeline import run_analysis_pipeline

    monkeypatch.setenv("JANUS_DB_PATH", str(temp_db))

    # Global PCAP header (24 bytes)
    pcap_bytes = bytes.fromhex(
        "d4c3b2a1"  # magic number
        "02000400"  # v2.4
        "00000000"  # thiszone
        "00000000"  # sigfigs
        "00000400"  # snaplen (1024)
        "01000000"  # linktype Ethernet
    )
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(pcap_bytes)
        tmp_pcap = f.name

    state_store = {}
    cap_id = "test_pipe_persist_01"
    state_store[cap_id] = {
        "status": "INIT",
        "filename": "pipeline_test.pcap",
        "size_bytes": len(pcap_bytes),
        "results": None,
    }

    try:
        asyncio.run(run_analysis_pipeline(cap_id, tmp_pcap, state_store))
        rec = get_audit_by_id(cap_id, db_path=temp_db)
        assert rec is not None
        assert rec["capture_id"] == cap_id
        assert rec["filename"] == "pipeline_test.pcap"
        assert rec["status"] == "INDETERMINATE"
    finally:
        Path(tmp_pcap).unlink(missing_ok=True)

