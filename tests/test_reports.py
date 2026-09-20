"""
tests/test_reports.py
=====================
Tests for ReportLab PDF report generation (Executive and Technical PDF reports).
"""

import os
from pathlib import Path
import pytest
from reports.executive_report import generate_executive_pdf
from reports.generator import generate_all_reports
from reports.technical_report import generate_technical_pdf


def test_generate_executive_pdf(tmp_path):
    """Verify generation of the Executive Summary PDF report."""
    comp_data = {
        "overall_score": 95.0,
        "grade": "A",
        "summary": "Compliant modern IPsec security posture.",
        "findings": [],
        "evaluated_parameters": {
            "esp_encryption": "ENCR_AES_GCM_16",
            "esp_auth": "AUTH_NONE",
            "dh_group": 19,
            "pfs_enabled": True,
            "sa_lifetime_seconds": 3600,
        },
        "generated_at": "2026-09-02T00:00:00Z",
    }
    meta = {"capture_id": "test_sess_01", "filename": "sample.pcap"}
    pdf_out = tmp_path / "executive.pdf"

    res_path = generate_executive_pdf(
        compliance_data=comp_data,
        capture_metadata=meta,
        output_path=pdf_out,
    )

    assert res_path.exists()
    assert res_path.stat().st_size > 0
    with open(res_path, "rb") as f:
        header = f.read(5)
        assert header.startswith(b"%PDF-")


def test_generate_technical_pdf(tmp_path):
    """Verify generation of the multi-page Technical Audit PDF report."""
    comp_data = {
        "overall_score": 30.0,
        "grade": "F",
        "summary": "SWEET32 and Logjam vulnerabilities detected.",
        "findings": [
            {
                "rule_id": "RFC8221-ENCR_3DES",
                "severity": "HIGH",
                "parameter": "ESP Encryption",
                "description": "3DES is vulnerable to SWEET32 collisions.",
                "recommendation": "Migrate to AES-GCM.",
                "references": ["RFC 8221 §5"],
            }
        ],
        "threat_matrix": [
            {
                "technique_id": "T1040",
                "technique_name": "Network Sniffing",
                "tactic": "Credential Access",
                "severity": "HIGH",
                "status": "VULNERABLE",
                "details": "Weak cipher allows traffic decryption.",
            }
        ],
        "generated_at": "2026-09-02T00:00:00Z",
    }
    analysis_data = {
        "capture_id": "test_sess_02",
        "filename": "weak_traffic.pcap",
        "ike_sessions": [
            {
                "initiator_spi": "0x12345678",
                "responder_spi": "0x87654321",
                "version": "IKEv2",
                "auth_method": "PSK",
                "sa_lifetime_seconds": 3600,
                "pfs_enabled": True,
            }
        ],
        "flows": [
            {
                "flow_id": "flow_01",
                "spi": "0xdeadbeef",
                "packet_count": 100,
                "classification": {
                    "label": "VoIP",
                    "confidence": 0.95,
                    "is_obfuscated": False,
                },
            }
        ],
    }
    pdf_out = tmp_path / "technical.pdf"

    res_path = generate_technical_pdf(
        compliance_data=comp_data,
        analysis_data=analysis_data,
        output_path=pdf_out,
    )

    assert res_path.exists()
    assert res_path.stat().st_size > 0
    with open(res_path, "rb") as f:
        header = f.read(5)
        assert header.startswith(b"%PDF-")


def test_generate_all_reports(tmp_path):
    """Verify orchestrator generates both PDF files."""
    comp_data = {"overall_score": 90.0, "grade": "A", "findings": [], "threat_matrix": []}
    analysis_data = {"capture_id": "test_all", "filename": "test.pcap"}

    exec_p, tech_p = generate_all_reports(
        capture_id="test_all",
        compliance_data=comp_data,
        analysis_data=analysis_data,
        output_dir=tmp_path,
    )

    assert exec_p.exists()
    assert tech_p.exists()


def test_pdf_unicode_encoding_safety(tmp_path):
    """
    REGRESSION TEST FOR BUG-06:
    Verify ReportLab PDF generation renders without error when findings, summaries,
    or recommendations contain rich Unicode symbols (§, ✓, ✗, —, “, ”, •, →, ≥).
    """
    comp_data = {
        "overall_score": 85.0,
        "grade": "B",
        "generated_at": "2026-09-02T12:00:00Z",
        "summary": "Full compliance check per RFC 8221 §5 & RFC 8247 §3 — status ✓ verified, zero ✗ defects.",
        "evaluated_parameters": {
            "esp_encryption": "ENCR_AES_GCM_16",
            "esp_auth": "AUTH_NONE",
            "dh_group": 19,
            "pfs_enabled": True,
            "sa_lifetime_seconds": 3600,
        },
        "findings": [
            {
                "rule_id": "RULE-TEST-UNICODE",
                "severity": "HIGH",
                "parameter": "Diffie-Hellman Group §3.1",
                "description": "Evaluated per RFC 8247 §2.3 — “recommended” key exchange ≥ 256 bits • zero leaks.",
                "recommendation": "Upgrade to Group 19 (ECP-256) → ensure forward secrecy ✓.",
            }
        ],
        "threat_matrix": [
            {
                "technique_id": "T1040",
                "technique_name": "Traffic Sniffing — Packet Inspection",
                "tactic": "Credential Access",
                "severity": "INFO",
                "status": "SECURE ✓",
                "details": "AEAD integrity verification active per RFC 8221 §4.1 — no plaintext exposure.",
            }
        ],
        "remediation_config": "# Hardened configuration per RFC 8221 §5 & RFC 8247 §3.2 — “Verified”\nconnections { test { version = 2 } }",
    }
    meta = {"capture_id": "test_unicode_session", "filename": "unicode_test.pcap"}
    analysis_data = {"capture_id": "test_unicode_session", "filename": "unicode_test.pcap", "ike_sessions": [], "flows": []}

    exec_path = tmp_path / "executive_unicode.pdf"
    tech_path = tmp_path / "technical_unicode.pdf"

    res_exec = generate_executive_pdf(comp_data, meta, exec_path)
    res_tech = generate_technical_pdf(comp_data, analysis_data, tech_path)

    assert res_exec.exists() and res_exec.stat().st_size > 1000
    assert res_tech.exists() and res_tech.stat().st_size > 1000
