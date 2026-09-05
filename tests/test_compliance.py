"""
tests/test_compliance.py
========================
Tests for deterministic RFC 8221, RFC 8247, and NIST SP 800-77 Rev. 1 compliance engine.
"""

import pytest
from compliance.rules import (
    CryptoRule,
    RequirementLevel,
    Severity,
    get_dh_group_rule,
    get_esp_auth_rule,
    get_esp_encryption_rule,
    normalize_auth_name,
    normalize_encr_name,
)
from compliance.score import ComplianceEvaluator, evaluator


def test_rfc8221_esp_ciphers():
    """Verify ESP encryption algorithm requirement levels from RFC 8221."""
    # MUST: AES-GCM-16
    gcm_rule = get_esp_encryption_rule("ENCR_AES_GCM_16")
    assert gcm_rule is not None
    assert gcm_rule.requirement_level == RequirementLevel.MUST
    assert gcm_rule.is_aead is True
    assert gcm_rule.severity == Severity.INFO

    # MUST: AES-CBC (suboptimal without AEAD)
    cbc_rule = get_esp_encryption_rule("AES-CBC-256")
    assert cbc_rule is not None
    assert cbc_rule.requirement_level == RequirementLevel.MUST
    assert cbc_rule.is_aead is False
    assert cbc_rule.severity == Severity.LOW

    # SHOULD NOT: 3DES (SWEET32 vulnerable)
    des3_rule = get_esp_encryption_rule("3DES")
    assert des3_rule is not None
    assert des3_rule.requirement_level == RequirementLevel.SHOULD_NOT
    assert des3_rule.severity == Severity.HIGH
    assert "SWEET32" in (des3_rule.vulnerability_tag or "")

    # MUST NOT: Blowfish / RC5 / IDEA / DES
    for broken in ["BLOWFISH", "RC5", "IDEA", "DES"]:
        rule = get_esp_encryption_rule(broken)
        assert rule is not None, f"Rule for {broken} must exist"
        assert rule.requirement_level == RequirementLevel.MUST_NOT
        assert rule.severity == Severity.CRITICAL


def test_rfc8221_esp_auth():
    """Verify ESP authentication/integrity requirements from RFC 8221."""
    # MUST: HMAC-SHA2-256-128
    sha256 = get_esp_auth_rule("HMAC-SHA2-256")
    assert sha256 is not None
    assert sha256.requirement_level == RequirementLevel.MUST
    assert sha256.severity == Severity.INFO

    # MUST-: HMAC-SHA1-96 (Deprecated collision risk)
    sha1 = get_esp_auth_rule("HMAC-SHA1-96")
    assert sha1 is not None
    assert sha1.requirement_level == RequirementLevel.MUST_MINUS
    assert sha1.severity == Severity.MEDIUM

    # MUST NOT: HMAC-MD5-96
    md5 = get_esp_auth_rule("HMAC-MD5")
    assert md5 is not None
    assert md5.requirement_level == RequirementLevel.MUST_NOT
    assert md5.severity == Severity.CRITICAL


def test_rfc8247_diffie_hellman_groups():
    """Verify Diffie-Hellman group requirements from RFC 8247 and NIST SP 800-77."""
    # RECOMMENDED: Group 19 (256-bit ECP) and Group 20 (384-bit ECP)
    g19 = get_dh_group_rule(19)
    assert g19 is not None
    assert g19.requirement_level == RequirementLevel.RECOMMENDED
    assert g19.severity == Severity.INFO

    g20 = get_dh_group_rule(20)
    assert g20 is not None
    assert g20.requirement_level == RequirementLevel.RECOMMENDED

    # SHOULD+: Group 14 (2048-bit MODP)
    g14 = get_dh_group_rule(14)
    assert g14 is not None
    assert g14.requirement_level == RequirementLevel.SHOULD_PLUS

    # MUST NOT / HISTORIC: Group 1, 2, 5 (Logjam vulnerable)
    for g_num in [1, 2, 5]:
        g = get_dh_group_rule(g_num)
        assert g is not None
        assert g.requirement_level == RequirementLevel.MUST_NOT
        assert g.severity == Severity.CRITICAL


def test_evaluator_hardened_profile():
    """Evaluate a fully hardened modern IPsec profile (Grade A, high score)."""
    report = evaluator.evaluate(
        esp_encryption="ENCR_AES_GCM_16",
        esp_auth="AUTH_NONE",
        dh_group=19,
        pfs_enabled=True,
        sa_lifetime_seconds=3600,
        rsa_key_bits=3072,
    )

    assert report.overall_score >= 90.0
    assert report.grade == "A"
    assert len(report.findings) == 0
    assert len(report.threat_matrix) > 0


def test_evaluator_sweet32_and_logjam_profile():
    """Evaluate an insecure legacy profile (3DES + MD5 + DH Group 2, PFS off)."""
    report = evaluator.evaluate(
        esp_encryption="3DES",
        esp_auth="HMAC-MD5",
        dh_group=2,
        pfs_enabled=False,
        sa_lifetime_seconds=86400,
        rsa_key_bits=1024,
    )

    assert report.overall_score < 50.0
    assert report.grade == "F"
    
    finding_rules = [f.rule_id for f in report.findings]
    assert "RFC8221-ENCR_3DES" in finding_rules
    assert "RFC8221-AUTH_HMAC_MD5_96" in finding_rules
    assert "RFC8247-DH_GROUP_2" in finding_rules
    assert "NIST800-77-PFS-DISABLED" in finding_rules
    assert "NIST800-77-RSA-KEY-SIZE" in finding_rules


def test_auth_none_with_cbc_critical():
    """AUTH_NONE paired with non-AEAD CBC mode MUST produce CRITICAL finding."""
    report = evaluator.evaluate(
        esp_encryption="AES-CBC-128",
        esp_auth="AUTH_NONE",
        dh_group=19,
        pfs_enabled=True,
    )
    
    critical_findings = [f for f in report.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) >= 1
    assert any("AUTH-NONE-CRITICAL" in f.rule_id for f in critical_findings)


def test_sa_lifetime_window():
    """Lifetimes outside 1h - 8h window trigger findings."""
    report_long = evaluator.evaluate(
        esp_encryption="AES-GCM",
        dh_group=19,
        sa_lifetime_seconds=36000,
    )
    assert any("LIFETIME" in f.rule_id for f in report_long.findings)

    report_ok = evaluator.evaluate(
        esp_encryption="AES-GCM",
        dh_group=19,
        sa_lifetime_seconds=14400,
    )
    assert not any("LIFETIME" in f.rule_id for f in report_ok.findings)


def test_remediation_swanctl_conf_generation():
    """Verify swanctl.conf remediation snippet is valid, addresses findings, and configures AEAD."""
    report = evaluator.evaluate(
        esp_encryption="3DES",
        esp_auth="HMAC-MD5",
        dh_group=2,
        pfs_enabled=False,
        sa_lifetime_seconds=86400,
    )
    assert report.remediation_config is not None
    assert "connections {" in report.remediation_config
    assert "aes256gcm16-ecp256" in report.remediation_config
    assert "rekey_time = 4h" in report.remediation_config
    assert "copy_dscp = out" in report.remediation_config
    assert "RFC8221-ENCR_3DES" in report.remediation_config
    assert "RFC8247-DH_GROUP_2" in report.remediation_config
