"""
tests/test_rag_explainer.py
===========================
Automated test suite for the Janus Compliance-RAG Explainer Model:
1. Standards chunking and page-break sanitization integrity
2. Hybrid Dense + BM25 retrieval accuracy on held-out compliance queries (including RFC 9347 IP-TFS)
3. Citation verification and 3-tier anti-hallucination policy enforcement
4. Explainer engine generation with required RFC/NIST clause citations
5. Report narrative drafting around deterministic tables
6. FastAPI backend endpoints (/api/compliance/explain, /api/report/.../draft-narrative)
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from rag.data.chunk_standards import clean_rfc_text, build_all_chunks
from rag.engine.citation_verifier import verifier, CitationVerifier
from rag.engine.explainer import explainer
from rag.engine.narrative_writer import narrative_writer
from rag.index.hybrid_indexer import retriever
from tests.conftest import TEST_API_KEY


@pytest.fixture(scope="module")
def client():
    return TestClient(app, headers={"X-API-Key": TEST_API_KEY})


def test_standards_chunking_and_sanitization():
    """Verify raw RFC page breaks are stripped and chunks have complete metadata."""
    # Test pagination stripping
    sample_raw_rfc = (
        "Wouters, et al.              Standards Track                    [Page 4]\n"
        "\x0c\n"
        "RFC 8221            ESP and AH Algorithm Requirements       October 2017\n\n"
        "5.  ESP Encryption Algorithms\n\n"
        "   The following table summarizes the ESP encryption requirements:\n"
    )
    cleaned = clean_rfc_text(sample_raw_rfc)
    assert "[Page 4]" not in cleaned
    assert "\x0c" not in cleaned
    assert "5.  ESP Encryption Algorithms" in cleaned

    # Verify loaded chunks
    chunks_path = Path("rag/data/chunks.json")
    assert chunks_path.exists()
    chunks = json.loads(chunks_path.read_text(encoding="utf-8"))
    assert len(chunks) >= 150

    # Verify each chunk has required fields
    valid_docs = {
        "RFC 8221", "RFC 8247", "RFC 9347", "RFC 7296", "RFC 4301",
        "RFC 4303", "RFC 7383", "RFC 8784", "NIST SP 800-77 Rev. 1",
        "NIST SP 800-131A Rev. 2", "DoD IPsec STIG",
    }
    for c in chunks:
        assert c.get("chunk_id")
        assert c.get("document") in valid_docs
        assert c.get("section")
        assert c.get("title")
        assert len(c.get("text", "")) > 20


def test_hybrid_retrieval_accuracy():
    """
    Verify hybrid retrieval correctly ranks the governing standards clause
    for SWEET32, Logjam, MD5 collision, and RFC 9347 IP-TFS.
    """
    # 1. SWEET32 / 3DES -> RFC 8221 §5 or NIST Table 1
    res_3des = retriever.search("SWEET32 3DES collision attack 64-bit block", top_k=3, category="ESP_ENCR")
    assert len(res_3des) > 0
    top_docs_3des = [f"{r.document} {r.section}" for r in res_3des]
    assert any("RFC 8221" in d or "NIST SP 800-77" in d or "DoD IPsec STIG" in d for d in top_docs_3des)

    # 2. Logjam / DH Group 2 -> RFC 8247 §2.4 or NIST Table 1 or DoD STIG
    res_logjam = retriever.search("Logjam attack DH Group 2 MODP 1024-bit key exchange", top_k=3, category="IKE_DH")
    assert len(res_logjam) > 0
    top_docs_logjam = [f"{r.document} {r.section}" for r in res_logjam]
    assert any("RFC 8247" in d or "NIST SP 800-77" in d or "DoD IPsec STIG" in d for d in top_docs_logjam)

    # 3. MD5 Integrity Collision -> RFC 8221 §5
    res_md5 = retriever.search("MD5 collision attack integrity hash broken", top_k=3, category="ESP_AUTH")
    assert len(res_md5) > 0
    top_docs_md5 = [f"{r.document} {r.section}" for r in res_md5]
    assert any("RFC 8221" in d or "NIST" in d or "RFC 4303" in d for d in top_docs_md5)

    # 4. RFC 9347 IP-TFS Traffic Flow Security (explicit differentiator check)
    res_iptfs = retriever.search("RFC 9347 IP-TFS constant rate aggregation fragmentation tunnel framing", top_k=3, category="IP_TFS")
    assert len(res_iptfs) > 0
    top_docs_iptfs = [r.document for r in res_iptfs]
    assert "RFC 9347" in top_docs_iptfs


def test_citation_verifier_and_policy():
    """Verify citation verifier detects valid vs hallucinated citations and applies Tier 2 policy."""
    # Test valid citation
    valid_text = "According to [RFC 8221 §5], 3DES is deprecated due to SWEET32."
    v_valid = verifier.verify_and_enforce(valid_text)
    assert v_valid.is_grounded is True
    assert v_valid.verified_count == 1
    assert v_valid.unverified_count == 0

    # Test hallucinated / invalid citation
    fake_text = "According to [RFC 9999 §99.9], all encryption is broken."
    fallback_chunk = {
        "chunk_id": "RFC8221-SEC-5",
        "document": "RFC 8221",
        "section": "§5",
        "title": "ESP Encryption Algorithms",
    }
    v_fake = verifier.verify_and_enforce(fake_text, retrieved_fallback_chunk=fallback_chunk)
    # Tier 2 replaces unverified citation with verified fallback
    assert "[RFC 8221 §5]" in v_fake.sanitized_text
    assert "[RFC 9999 §99.9]" not in v_fake.sanitized_text
    assert v_fake.warning is not None


def test_explainer_engine_generation():
    """Verify explainer generates cited explanation with groundedness >= 0.8."""
    finding = {
        "rule_id": "RFC8221-ENCR_3DES",
        "parameter": "ESP Encryption",
        "severity": "HIGH",
        "description": "64-bit block cipher susceptible to collision attacks (SWEET32) after 32GB of data.",
        "vulnerability_tag": "SWEET32 (CVE-2016-2183)",
        "category": "ESP_ENCR",
        "recommendation": "Disable 3DES immediately. Migrate to AES-256-GCM.",
    }
    res = explainer.explain(finding, top_k=3)
    assert res.rule_id == "RFC8221-ENCR_3DES"
    assert res.severity == "HIGH"
    assert res.groundedness_score >= 0.8
    assert len(res.citations) > 0
    assert any(c["verified"] for c in res.citations)
    assert len(res.retrieved_chunks) == 3
    assert res.latency_ms >= 0.0


def test_narrative_writer():
    """Verify report narrative generator drafts executive and technical commentary."""
    comp_data = {
        "overall_score": 25.0,
        "grade": "F",
        "summary": "SWEET32 and Logjam vulnerabilities detected.",
        "findings": [
            {
                "rule_id": "RFC8221-ENCR_3DES",
                "severity": "HIGH",
                "parameter": "ESP Encryption",
                "description": "3DES block size is vulnerable to SWEET32.",
                "recommendation": "Migrate to AES-256-GCM.",
            },
            {
                "rule_id": "RFC8247-DH_GROUP_2",
                "severity": "CRITICAL",
                "parameter": "Diffie-Hellman Group",
                "description": "DH Group 2 is vulnerable to Logjam.",
                "recommendation": "Upgrade to DH Group 19.",
            }
        ],
        "threat_matrix": [{"status": "VULNERABLE"}],
        "evaluated_parameters": {"esp_encryption": "ENCR_3DES", "dh_group": 2},
    }
    narr = narrative_writer.draft_narrative(
        capture_id="scenario_04",
        compliance_data=comp_data,
    )
    assert narr.capture_id == "scenario_04"
    assert narr.grade == "F"
    assert "CRITICAL" in narr.executive_narrative
    assert len(narr.technical_narrative) > 50
    assert len(narr.citations) > 0
    assert narr.is_grounded is True


def test_backend_explainer_endpoints(client):
    """Verify FastAPI routes /api/compliance/explain and /api/report/.../draft-narrative."""
    # 1. POST /api/compliance/explain
    payload = {
        "finding": {
            "rule_id": "RFC8247-DH_GROUP_2",
            "parameter": "Diffie-Hellman Group",
            "severity": "CRITICAL",
            "description": "DH Group 2 (MODP-1024) is vulnerable to Logjam.",
            "recommendation": "Upgrade to DH Group 19.",
            "category": "IKE_DH",
        },
        "top_k": 3,
    }
    resp = client.post("/api/compliance/explain", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["rule_id"] == "RFC8247-DH_GROUP_2"
    assert data["severity"] == "CRITICAL"
    assert len(data["explanation"]) > 0
    assert len(data["citations"]) > 0

    # 2. POST /api/report/{capture_id}/draft-narrative
    from routes.analysis import _state_store

    _state_store["test_session"] = {
        "status": "DONE",
        "results": {
            "compliance": {
                "overall_score": 25.0,
                "grade": "F",
                "summary": "SWEET32 and Logjam vulnerabilities detected.",
                "findings": [
                    {
                        "rule_id": "RFC8221-ENCR_3DES",
                        "severity": "HIGH",
                        "parameter": "ESP Encryption",
                        "description": "3DES block size is vulnerable to SWEET32.",
                        "recommendation": "Migrate to AES-256-GCM.",
                    }
                ],
                "threat_matrix": [{"status": "VULNERABLE"}],
                "evaluated_parameters": {"esp_encryption": "ENCR_3DES"},
            }
        },
    }
    try:
        resp_narr = client.post("/api/report/test_session/draft-narrative")
        assert resp_narr.status_code == 200
        narr_data = resp_narr.json()
        assert "executive_narrative" in narr_data
        assert "technical_narrative" in narr_data
        assert narr_data["is_grounded"] is True
    finally:
        _state_store.pop("test_session", None)
