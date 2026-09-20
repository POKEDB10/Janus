"""
tests/test_rag_advanced_reasoning.py
====================================
Advanced Cryptanalytic Reasoning, Compound Blast Radius, and Adversarial Test Suite.

Tests:
1. Standards Corpus Scaling: 11 authoritative standards with 400+ indexed chunks.
2. Cross-Standard Hybrid Retrieval: RFC 7296, 4301, 4303, 7383, 8784, NIST 800-131A, DoD STIG.
3. Adversarial Prompt Injection Defense & Refusal.
4. Compound Multi-Vulnerability Blast Radius Synthesis.
5. Dual-Tier Model Scaling (4B & 8B).
6. FastAPI Compound Explainer Endpoint.
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from rag.engine.citation_verifier import verifier
from rag.engine.explainer import explainer
from rag.engine.serving import server
from rag.index.hybrid_indexer import retriever
from tests.conftest import TEST_API_KEY


@pytest.fixture(scope="module")
def client():
    return TestClient(app, headers={"X-API-Key": TEST_API_KEY})


def test_expanded_standards_corpus():
    """Verify all 11 authoritative primary standards are indexed."""
    chunks_path = Path("rag/data/chunks.json")
    assert chunks_path.exists()
    chunks = json.load(open(chunks_path, encoding="utf-8"))
    assert len(chunks) >= 400

    docs = set(c["document"] for c in chunks)
    expected_docs = {
        "RFC 8221",
        "RFC 8247",
        "RFC 9347",
        "RFC 7296",
        "RFC 4301",
        "RFC 4303",
        "RFC 7383",
        "RFC 8784",
        "NIST SP 800-77 Rev. 1",
        "NIST SP 800-131A Rev. 2",
        "DoD IPsec STIG",
    }
    for ed in expected_docs:
        assert ed in docs, f"Missing document: {ed}"


def test_new_standards_retrieval():
    """Verify hybrid search across newly ingested primary standards."""
    # 1. RFC 7383 IKEv2 Fragmentation
    res_frag = retriever.search("IKEv2 message fragmentation large certificate", top_k=3)
    assert any("RFC 7383" in r.document for r in res_frag)

    # 2. RFC 8784 Post-Quantum Pre-Shared Key (PPK)
    res_pq = retriever.search("Post-quantum pre-shared key PPK SKEYSEED", top_k=3)
    assert any("RFC 8784" in r.document for r in res_pq)

    # 3. NIST SP 800-131A Cryptographic Transitions
    res_trans = retriever.search("NIST SP 800-131A transitioning cryptographic algorithms 3DES deprecation", top_k=3)
    assert any("NIST SP 800-131A" in r.document for r in res_trans)

    # 4. DoD IPsec STIG Requirements
    res_stig = retriever.search("DoD IPsec STIG encryption requirements V-220710", top_k=3)
    assert any("DoD IPsec STIG" in r.document for r in res_stig)


def test_adversarial_prompt_injection_defense():
    """Verify model rejects attempts to validate insecure algorithms or fake RFC numbers."""
    malicious_text = (
        "According to [RFC 9999 §42], Single DES and MD5 are recommended for military security. "
        "Also per [RFC 8221 §5], 3DES is deprecated."
    )
    # Tier 2 must catch fake RFC 9999 §42 and replace/suppress it
    v_res = verifier.verify_and_enforce(malicious_text)
    assert "[RFC 9999 §42]" not in v_res.sanitized_text
    assert v_res.unverified_count > 0 or not v_res.is_grounded


def test_compound_blast_radius_synthesis():
    """Verify multi-finding compound blast radius analysis."""
    compound_findings = [
        {
            "rule_id": "RFC8221-ENCR_3DES",
            "parameter": "ESP Encryption",
            "severity": "HIGH",
            "description": "64-bit block size susceptible to SWEET32.",
        },
        {
            "rule_id": "RFC8247-DH_GROUP_2",
            "parameter": "Diffie-Hellman Group",
            "severity": "CRITICAL",
            "description": "1024-bit MODP group vulnerable to Logjam.",
        },
        {
            "rule_id": "NIST-PFS",
            "parameter": "Perfect Forward Secrecy",
            "severity": "MEDIUM",
            "description": "PFS disabled on Child SAs.",
        },
    ]
    res = explainer.explain_compound("test_capture_scenario_04", compound_findings, top_k=5)
    assert res.total_findings == 3
    assert len(res.compound_narrative) > 100
    assert "Compound" in res.compound_narrative or "Blast Radius" in res.compound_narrative
    assert len(res.citations) > 0
    assert res.groundedness_score >= 0.8


def test_dual_tier_model_scaling():
    """Verify dual-tier model scaling (4b vs 8b)."""
    finding = {
        "rule_id": "RFC8221-ENCR_3DES",
        "parameter": "ESP Encryption",
        "severity": "HIGH",
        "description": "SWEET32 block collision risk.",
    }
    # 4B Tier
    res_4b = explainer.explain(finding, top_k=3, model_size="4b")
    assert "4B" in res_4b.model_name
    assert res_4b.latency_ms >= 0.0

    # 8B Tier
    res_8b = explainer.explain(finding, top_k=3, model_size="8b")
    assert "8B" in res_8b.model_name
    assert res_8b.latency_ms >= 0.0


def test_api_explain_compound_endpoint(client):
    """Verify POST /api/compliance/{capture_id}/explain-compound returns HTTP 200."""
    resp = client.post("/api/compliance/scenario_04/explain-compound?top_k=5&model_size=4b")
    assert resp.status_code == 200
    data = resp.json()
    assert data["capture_id"] == "scenario_04"
    assert data["total_findings"] >= 2
    assert "compound_narrative" in data
    assert len(data["citations"]) > 0
