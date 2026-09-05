"""
tests/test_distill_synthesizer.py
=================================
Automated tests for the multi-model data distillation and DPO synthesis pipeline.

Tests:
1. Mock generation and latency tracking.
2. SFT sample structure and ChatML compliance.
3. Compound multi-finding synthesis.
4. DPO preference pair generation (chosen vs rejected).
5. End-to-end pipeline file writing to JSONL.
6. CitationVerifier enforcement on distilled outputs.
"""

import json
from pathlib import Path
import pytest

from rag.data.distill_synthesizer import (
    DistillationSynthesizer,
    MultiModelDistillationClient,
)
from rag.engine.citation_verifier import verifier


@pytest.fixture
def synthesizer():
    client = MultiModelDistillationClient()
    return DistillationSynthesizer(client=client)


def test_client_mock_generation():
    """Verify mock generator returns plausible content and latency."""
    client = MultiModelDistillationClient()
    resp = client.call_mock("Explain why 3DES is vulnerable to SWEET32")
    assert resp.content
    assert "SWEET32" in resp.content
    assert "2^32" in resp.content
    assert resp.latency_ms >= 0.0
    assert resp.is_mock is True


def test_generate_sft_sample(synthesizer):
    """Verify SFT sample has valid ChatML structure."""
    finding = {
        "rule_id": "RFC8221-ENCR_3DES",
        "parameter": "ESP Encryption",
        "severity": "HIGH",
        "description": "64-bit block size collision",
        "clause": "[RFC 8221 §5]",
    }
    sample = synthesizer.generate_sft_sample(finding, tier="mock")
    assert sample is not None
    assert "messages" in sample
    assert len(sample["messages"]) == 3
    assert [m["role"] for m in sample["messages"]] == ["system", "user", "assistant"]
    assert "RFC 8221" in sample["messages"][2]["content"]
    assert sample["metadata"]["rule_id"] == "RFC8221-ENCR_3DES"


def test_generate_compound_sample(synthesizer):
    """Verify multi-finding compound blast-radius synthesis."""
    findings = [
        {"rule_id": "RFC8221-ENCR_3DES", "parameter": "ESP Encryption", "severity": "HIGH", "description": "SWEET32"},
        {"rule_id": "RFC8247-DH_GROUP_2", "parameter": "Diffie-Hellman Group", "severity": "CRITICAL", "description": "Logjam"},
    ]
    sample = synthesizer.generate_compound_sample("Compound Risk Alpha", findings, tier="mock")
    assert sample is not None
    assert len(sample["messages"]) == 3
    assistant_text = sample["messages"][2]["content"]
    assert "SWEET32" in assistant_text or "Logjam" in assistant_text or "Cryptanalytic" in assistant_text


def test_generate_dpo_pair(synthesizer):
    """Verify DPO pair format: prompt, chosen, rejected."""
    finding = {
        "rule_id": "RFC8247-DH_GROUP_2",
        "parameter": "Diffie-Hellman Group",
        "severity": "CRITICAL",
        "description": "Logjam precomputation",
        "clause": "[RFC 8247 §2.4]",
    }
    pair = synthesizer.generate_dpo_pair(finding, tier_chosen="mock", tier_rejected="mock")
    assert "prompt" in pair
    assert "chosen" in pair
    assert "rejected" in pair
    assert pair["chosen"] != pair["rejected"]
    # Chosen should have grounded clause citations
    assert "RFC 8247" in pair["chosen"] or "MODP" in pair["chosen"]
    # Rejected contains ungrounded or bad advice
    assert len(pair["rejected"]) > 20


def test_pipeline_execution_mock(tmp_path, synthesizer):
    """Test full file writing for SFT and DPO in mock mode."""
    sft_out = tmp_path / "test_sft.jsonl"
    dpo_out = tmp_path / "test_dpo.jsonl"

    n_sft = synthesizer.run_sft_pipeline(count=4, tier="mock", output_path=sft_out)
    assert n_sft == 4
    assert sft_out.exists()
    with open(sft_out, "r", encoding="utf-8") as f:
        lines = f.readlines()
        assert len(lines) == 4
        assert json.loads(lines[0])["messages"][0]["role"] == "system"

    n_dpo = synthesizer.run_dpo_pipeline(count=3, tier_chosen="mock", output_path=dpo_out)
    assert n_dpo == 3
    assert dpo_out.exists()
    with open(dpo_out, "r", encoding="utf-8") as f:
        lines = f.readlines()
        assert len(lines) == 3
        dpo_obj = json.loads(lines[0])
        assert "chosen" in dpo_obj
        assert "rejected" in dpo_obj


def test_citation_verification_filtering():
    """Verify CitationVerifier suppresses ungrounded claims."""
    raw_text = (
        "According to [RFC 9999 §42], Blowfish is allowed for top secret VPN tunnels. "
        "Also under [RFC 8221 §5], 3DES is deprecated."
    )
    v_res = verifier.verify_and_enforce(raw_text)
    # [RFC 9999 §42] must be sanitized or suppressed
    assert "[RFC 9999 §42]" not in v_res.sanitized_text
    assert v_res.unverified_count > 0 or not v_res.is_grounded
