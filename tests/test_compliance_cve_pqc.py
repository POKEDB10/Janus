"""
tests/test_compliance_cve_pqc.py
================================
Unit tests verifying:
1. Verified CVE/CWE mapping integrity across all rules in compliance/rules.py
2. Post-Quantum Readiness (PQC) assessment in compliance/score.py (CRQC_VULNERABLE vs TRANSITIONAL_HYBRID vs POST_QUANTUM_RESISTANT)
3. Rendering of CVE advisory and PQC metadata into PDF reports
"""

import pytest
from compliance.rules import (
    CryptoRule,
    RequirementLevel,
    Severity,
    get_dh_group_rule,
    get_esp_auth_rule,
    get_esp_encryption_rule,
)
from compliance.score import ComplianceEvaluator, evaluator
from reports.executive_report import generate_executive_pdf
from reports.technical_report import generate_technical_pdf


def test_verified_cve_and_cwe_integrity():
    """Verify that all cryptographic vulnerability rules have accurate NVD CVE/CWE mappings."""
    # 3DES -> CVE-2016-2183 (SWEET32), NVD primary CWE-200, CVSS 7.5
    rule_3des = get_esp_encryption_rule("3DES")
    assert rule_3des is not None
    assert rule_3des.cve_id == "CVE-2016-2183"
    assert rule_3des.cwe_id == "CWE-200"
    assert rule_3des.cvss_score == 7.5
    assert "nvd.nist.gov" in rule_3des.nvd_url

    # Single DES -> No spurious CVE; mapped to CWE-327 (Broken Crypto Algorithm)
    rule_des = get_esp_encryption_rule("DES")
    assert rule_des is not None
    assert rule_des.cve_id is None
    assert rule_des.cwe_id == "CWE-327"
    assert rule_des.cvss_score == 7.5
    assert "cwe.mitre.org" in rule_des.nvd_url

    # HMAC-MD5 -> CVE-2015-7575 (SLOTH), CWE-328, CVSS 7.1
    rule_md5 = get_esp_auth_rule("HMAC-MD5")
    assert rule_md5 is not None
    assert rule_md5.cve_id == "CVE-2015-7575"
    assert rule_md5.cwe_id == "CWE-328"
    assert rule_md5.cvss_score == 7.1

    # HMAC-SHA1 -> CVE-2005-4900 (Collision vulnerability), CWE-328, CVSS 5.9
    rule_sha1 = get_esp_auth_rule("SHA1")
    assert rule_sha1 is not None
    assert rule_sha1.cve_id == "CVE-2005-4900"
    assert rule_sha1.cwe_id == "CWE-328"

    # Weak DH Groups (1, 2, 5) -> No spurious CVE; mapped to CWE-326 (Inadequate Encryption Strength)
    for g in [1, 2, 5]:
        rule_dh = get_dh_group_rule(g)
        assert rule_dh is not None
        assert rule_dh.cve_id is None
        assert rule_dh.cwe_id == "CWE-326"


def test_pqc_evaluation_classical_vulnerable():
    """Verify standard classical IPsec session is assessed as CRQC_VULNERABLE in prose."""
    report = evaluator.evaluate(
        esp_encryption="ENCR_AES_GCM_16",
        esp_auth="AUTH_NONE",
        dh_group=19,
        pfs_enabled=True,
        sa_lifetime_seconds=3600,
        rsa_key_bits=3072,
        pqc_hybrid=False,
    )
    assert report.pqc_status == "CRQC_VULNERABLE"
    assert "Shor's algorithm" in report.pqc_advisory
    assert "CRQC" in report.pqc_advisory


def test_pqc_evaluation_hybrid_transitional():
    """Verify hybrid classical + post-quantum session is assessed as TRANSITIONAL_HYBRID."""
    report = evaluator.evaluate(
        esp_encryption="ENCR_AES_GCM_16",
        esp_auth="AUTH_NONE",
        dh_group=19,
        pfs_enabled=True,
        pqc_hybrid=True,
        pqc_algorithm="ML-KEM-768",
    )
    assert report.pqc_status == "TRANSITIONAL_HYBRID"
    assert "ML-KEM-768" in report.pqc_advisory
    assert "RFC 9370" in report.pqc_advisory


def test_pqc_evaluation_pure_pqc_resistant():
    """Verify pure post-quantum session without classical DH is POST_QUANTUM_RESISTANT."""
    report = evaluator.evaluate(
        esp_encryption="ENCR_AES_GCM_16",
        esp_auth="AUTH_NONE",
        dh_group=None,
        rsa_key_bits=None,
        pqc_hybrid=False,
        pqc_algorithm="ML-KEM-1024",
    )
    assert report.pqc_status == "POST_QUANTUM_RESISTANT"
    assert "ML-KEM-1024" in report.pqc_advisory


def test_pdf_reports_with_cve_and_pqc(tmp_path):
    """Verify that executive and technical PDF reports render cleanly with CVE and PQC data."""
    report = evaluator.evaluate(
        esp_encryption="3DES",
        esp_auth="HMAC-MD5",
        dh_group=2,
        pfs_enabled=False,
        sa_lifetime_seconds=86400,
        pqc_hybrid=False,
    )
    comp_dict = report.to_dict()
    meta = {"capture_id": "test_cve_pqc", "filename": "weak_test.pcap"}
    analysis_data = {
        "capture_id": "test_cve_pqc",
        "filename": "weak_test.pcap",
        "ike_sessions": [{"initiator_spi": "0x1111", "responder_spi": "0x2222", "version": "IKEv2", "auth_method": "PSK", "sa_lifetime_seconds": 86400, "pfs_enabled": False}],
        "flows": [],
    }

    exec_pdf = tmp_path / "exec_cve_pqc.pdf"
    tech_pdf = tmp_path / "tech_cve_pqc.pdf"

    generate_executive_pdf(comp_dict, meta, exec_pdf)
    generate_technical_pdf(comp_dict, analysis_data, tech_pdf)

    assert exec_pdf.exists() and exec_pdf.stat().st_size > 1000
    assert tech_pdf.exists() and tech_pdf.stat().st_size > 1000
