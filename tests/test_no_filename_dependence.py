"""Regression coverage for result integrity independent of capture names."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.pipeline import run_analysis_pipeline
from routes.analysis import _state_store
from tests.conftest import TEST_API_KEY


async def _no_delay(_: float) -> None:
    """Keep real pipeline work in the test while skipping presentation pacing."""


def _run_capture(capture_id: str, pcap_path: Path) -> dict[str, Any]:
    _state_store[capture_id] = {
        "status": "INIT",
        "filename": pcap_path.name,
        "size_bytes": pcap_path.stat().st_size,
        "results": None,
    }
    try:
        asyncio.run(run_analysis_pipeline(capture_id, str(pcap_path), _state_store))
        results = _state_store[capture_id]["results"]
        assert results is not None
        return results
    finally:
        _state_store.pop(capture_id, None)


@pytest.mark.parametrize(
    ("source_name", "renamed_name"),
    [
        ("scenario_01_hardened.pcap", "capture_x99.pcap"),
        ("wireshark_ikev2_aes_gcm.pcap", "weak_3des_legacy.pcap"),
    ],
)
def test_pipeline_results_do_not_depend_on_capture_filename(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source_name: str,
    renamed_name: str,
) -> None:
    """The same capture has the same verdict after an adversarial rename."""
    monkeypatch.setattr("backend.pipeline.asyncio.sleep", _no_delay)
    source = Path("samples") / source_name
    assert source.is_file(), f"Required sample is missing: {source}"

    renamed = tmp_path / renamed_name
    shutil.copyfile(source, renamed)

    original_results = _run_capture(f"original-{source.stem}", source)
    renamed_results = _run_capture(f"renamed-{source.stem}", renamed)

    original_compliance = original_results["compliance"]
    renamed_compliance = renamed_results["compliance"]
    assert renamed_compliance.get("overall_score") == original_compliance.get("overall_score")
    assert renamed_compliance.get("grade") == original_compliance.get("grade")
    assert renamed_results.get("status") == original_results.get("status")


@pytest.mark.parametrize("capture_id", ["unknown-capture-id", "scenario_01_hardened"])
def test_results_route_returns_404_without_completed_session(capture_id: str) -> None:
    """Arbitrary and legacy sample IDs cannot return generated result data."""
    _state_store.pop(capture_id, None)
    client = TestClient(app, headers={"X-API-Key": TEST_API_KEY})

    response = client.get(f"/api/analysis/{capture_id}/results")

    assert response.status_code == 404
