"""
Janus Compliance Engine — Scoring & Evaluation
==============================================
Evaluates extracted IKE and ESP parameters against RFC 8221, RFC 8247,
and NIST SP 800-77 Rev. 1 compliance rules.

Calculates:
- 0-100 Overall Compliance Score
- Letter Grade (A, B, C, D, F)
- Detailed per-parameter findings with severity, RFC references, and remediation
- MITRE ATT&CK style Threat Matrix mapping
"""

from __future__ import annotations

import datetime
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

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


@dataclass
class Finding:
    """A compliance audit finding."""

    rule_id: str
    severity: Severity
    category: str
    parameter: str
    value: str
    description: str
    recommendation: str
    references: list[str]
    vulnerability_tag: Optional[str] = None


@dataclass
class ThreatMatrixItem:
    """A threat matrix entry mapped to MITRE ATT&CK concepts."""

    technique_id: str
    tactic: str
    technique_name: str
    severity: Severity
    status: str  # "VULNERABLE", "SECURE", "WARNING"
    details: str
    affected_parameter: str


@dataclass
class ComplianceReport:
    """Comprehensive compliance evaluation result."""

    overall_score: float
    grade: str
    summary: str
    findings: list[Finding] = field(default_factory=list)
    threat_matrix: list[ThreatMatrixItem] = field(default_factory=list)
    evaluated_parameters: dict[str, Any] = field(default_factory=dict)
    remediation_config: str = ""
    generated_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert compliance report to dictionary."""
        data = asdict(self)
        data["findings"] = [
            {**f, "severity": f["severity"].value if isinstance(f["severity"], Severity) else f["severity"]}
            for f in data["findings"]
        ]
        data["threat_matrix"] = [
            {**t, "severity": t["severity"].value if isinstance(t["severity"], Severity) else t["severity"]}
            for t in data["threat_matrix"]
        ]
        return data


class ComplianceEvaluator:
    """
    Evaluates IPsec session cryptographic configuration against RFC & NIST requirements.
    """

    # Scoring deductions per finding severity
    SEVERITY_DEDUCTIONS = {
        Severity.CRITICAL: 35.0,
        Severity.HIGH: 20.0,
        Severity.MEDIUM: 10.0,
        Severity.LOW: 5.0,
        Severity.INFO: 0.0,
    }

    def evaluate(
        self,
        esp_encryption: str,
        esp_auth: Optional[str] = None,
        dh_group: Optional[int] = None,
        pfs_enabled: bool = True,
        sa_lifetime_seconds: Optional[int] = 3600,
        rsa_key_bits: Optional[int] = None,
        ike_version: str = "IKEv2",
        ike_encryption: Optional[str] = None,
        ike_auth: Optional[str] = None,
        ike_dh_group: Optional[int] = None,
    ) -> ComplianceReport:
        """
        Evaluate complete IPsec session configuration and compute compliance metrics.
        """
        findings: list[Finding] = []
        threats: list[ThreatMatrixItem] = []
        evaluated_params: dict[str, Any] = {
            "esp_encryption": esp_encryption,
            "esp_auth": esp_auth,
            "dh_group": dh_group,
            "pfs_enabled": pfs_enabled,
            "sa_lifetime_seconds": sa_lifetime_seconds,
            "rsa_key_bits": rsa_key_bits,
            "ike_version": ike_version,
            "ike_encryption": ike_encryption,
            "ike_auth": ike_auth,
            "ike_dh_group": ike_dh_group,
        }

        # 1. Evaluate ESP Encryption
        encr_rule = get_esp_encryption_rule(esp_encryption)
        is_aead = encr_rule.is_aead if encr_rule else ("GCM" in esp_encryption.upper() or "POLY1305" in esp_encryption.upper())

        if encr_rule is None:
            findings.append(
                Finding(
                    rule_id="RFC8221-ENCR-UNKNOWN",
                    severity=Severity.HIGH,
                    category="ESP_ENCR",
                    parameter="ESP Encryption",
                    value=esp_encryption,
                    description=f"Unrecognized or non-standard ESP encryption algorithm: {esp_encryption}.",
                    recommendation="Configure standard AES-256-GCM (16 octet ICV) per RFC 8221.",
                    references=["RFC 8221 §5"],
                )
            )
            threats.append(
                ThreatMatrixItem(
                    technique_id="T1040",
                    tactic="Credential Access / Discovery",
                    technique_name="Network Sniffing (Non-standard Cipher)",
                    severity=Severity.HIGH,
                    status="WARNING",
                    details=f"Non-standard cipher '{esp_encryption}' may have unknown cryptanalytic weaknesses.",
                    affected_parameter="esp_encryption",
                )
            )
        else:
            if encr_rule.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                findings.append(
                    Finding(
                        rule_id=f"RFC8221-{encr_rule.algorithm_id}",
                        severity=encr_rule.severity,
                        category="ESP_ENCR",
                        parameter="ESP Encryption",
                        value=esp_encryption,
                        description=encr_rule.description,
                        recommendation=encr_rule.remediation,
                        references=[encr_rule.rfc_reference],
                        vulnerability_tag=encr_rule.vulnerability_tag,
                    )
                )
                threats.append(
                    ThreatMatrixItem(
                        technique_id="T1040",
                        tactic="Credential Access / Discovery",
                        technique_name=f"Network Sniffing ({encr_rule.vulnerability_tag or 'Weak Cipher'})",
                        severity=encr_rule.severity,
                        status="VULNERABLE",
                        details=f"Use of {encr_rule.name} facilitates traffic decryption via {encr_rule.vulnerability_tag or 'cryptanalysis'}.",
                        affected_parameter="esp_encryption",
                    )
                )
            elif encr_rule.severity == Severity.LOW:
                # Suboptimal (e.g. CBC mode)
                findings.append(
                    Finding(
                        rule_id=f"RFC8221-{encr_rule.algorithm_id}",
                        severity=Severity.LOW,
                        category="ESP_ENCR",
                        parameter="ESP Encryption",
                        value=esp_encryption,
                        description=encr_rule.description,
                        recommendation=encr_rule.remediation,
                        references=[encr_rule.rfc_reference],
                    )
                )
                threats.append(
                    ThreatMatrixItem(
                        technique_id="T1557",
                        tactic="Lateral Movement / Interception",
                        technique_name="Suboptimal Cipher (CBC Mode)",
                        severity=Severity.LOW,
                        status="WARNING",
                        details="CBC mode is secure when combined with strong HMAC, but AEAD (GCM) is preferred to avoid padding oracles.",
                        affected_parameter="esp_encryption",
                    )
                )
            else:
                # Compliant MUST/SHOULD AEAD
                threats.append(
                    ThreatMatrixItem(
                        technique_id="T1040",
                        tactic="Defense",
                        technique_name="Strong Cryptographic Protection",
                        severity=Severity.INFO,
                        status="SECURE",
                        details=f"Modern AEAD cipher {encr_rule.name} provides authenticated confidentiality.",
                        affected_parameter="esp_encryption",
                    )
                )

        # 2. Evaluate ESP Authentication / Integrity
        if is_aead:
            # For AEAD, authentication is built-in; AUTH_NONE is expected
            if esp_auth and normalize_auth_name(esp_auth) not in ("AUTH_NONE", ""):
                findings.append(
                    Finding(
                        rule_id="RFC8221-AEAD-AUTH-REDUNDANT",
                        severity=Severity.LOW,
                        category="ESP_AUTH",
                        parameter="ESP Authentication",
                        value=str(esp_auth),
                        description="Redundant separate integrity algorithm configured with an AEAD cipher.",
                        recommendation="Set integrity algorithm to None when using AES-GCM or ChaCha20-Poly1305.",
                        references=["RFC 8221 §5", "RFC 4106"],
                    )
                )
        else:
            # CBC mode requires separate integrity algorithm
            if not esp_auth or normalize_auth_name(esp_auth) in ("AUTH_NONE", ""):
                findings.append(
                    Finding(
                        rule_id="RFC8221-AUTH-NONE-CRITICAL",
                        severity=Severity.CRITICAL,
                        category="ESP_AUTH",
                        parameter="ESP Authentication",
                        value="AUTH_NONE",
                        description="AUTH_NONE paired with a non-AEAD cipher provides zero integrity protection.",
                        recommendation="Configure HMAC-SHA-256-128 or switch to AES-256-GCM AEAD.",
                        references=["RFC 8221 §5"],
                        vulnerability_tag="Bit-Flipping / Ciphertext Tampering",
                    )
                )
                threats.append(
                    ThreatMatrixItem(
                        technique_id="T1565",
                        tactic="Impact",
                        technique_name="Data Manipulation (No Integrity Check)",
                        severity=Severity.CRITICAL,
                        status="VULNERABLE",
                        details="Unauthenticated CBC mode allows active attackers to tamper with ciphertext without detection.",
                        affected_parameter="esp_auth",
                    )
                )
            else:
                auth_rule = get_esp_auth_rule(esp_auth)
                if auth_rule is None:
                    findings.append(
                        Finding(
                            rule_id="RFC8221-AUTH-UNKNOWN",
                            severity=Severity.MEDIUM,
                            category="ESP_AUTH",
                            parameter="ESP Authentication",
                            value=esp_auth,
                            description=f"Unrecognized authentication algorithm: {esp_auth}.",
                            recommendation="Configure HMAC-SHA-256-128 per RFC 8221.",
                            references=["RFC 8221 §5"],
                        )
                    )
                elif auth_rule.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                    findings.append(
                        Finding(
                            rule_id=f"RFC8221-{auth_rule.algorithm_id}",
                            severity=auth_rule.severity,
                            category="ESP_AUTH",
                            parameter="ESP Authentication",
                            value=esp_auth,
                            description=auth_rule.description,
                            recommendation=auth_rule.remediation,
                            references=[auth_rule.rfc_reference],
                            vulnerability_tag=auth_rule.vulnerability_tag,
                        )
                    )
                    threats.append(
                        ThreatMatrixItem(
                            technique_id="T1565",
                            tactic="Impact",
                            technique_name=f"Integrity Violation ({auth_rule.vulnerability_tag or 'Weak Hash'})",
                            severity=auth_rule.severity,
                            status="VULNERABLE",
                            details=f"Use of {auth_rule.name} exposes IPsec packets to hash collision / forgery attacks.",
                            affected_parameter="esp_auth",
                        )
                    )
                else:
                    threats.append(
                        ThreatMatrixItem(
                            technique_id="T1565",
                            tactic="Defense",
                            technique_name="Strong Packet Authentication",
                            severity=Severity.INFO,
                            status="SECURE",
                            details=f"Robust integrity protection via {auth_rule.name}.",
                            affected_parameter="esp_auth",
                        )
                    )

        # 3. Evaluate Diffie-Hellman Group (IKE / Child SA)
        active_dh = dh_group or ike_dh_group
        if active_dh is not None:
            dh_rule = get_dh_group_rule(active_dh)
            if dh_rule is None:
                findings.append(
                    Finding(
                        rule_id="RFC8247-DH-UNKNOWN",
                        severity=Severity.MEDIUM,
                        category="IKE_DH",
                        parameter="Diffie-Hellman Group",
                        value=f"Group {active_dh}",
                        description=f"Non-standard or legacy Diffie-Hellman group {active_dh}.",
                        recommendation="Configure DH Group 19 (256-bit ECP) or DH Group 14 (2048-bit MODP).",
                        references=["RFC 8247 §2.3"],
                    )
                )
            elif dh_rule.severity == Severity.CRITICAL:
                findings.append(
                    Finding(
                        rule_id=f"RFC8247-{dh_rule.algorithm_id}",
                        severity=Severity.CRITICAL,
                        category="IKE_DH",
                        parameter="Diffie-Hellman Group",
                        value=f"Group {active_dh} ({dh_rule.name})",
                        description=dh_rule.description,
                        recommendation=dh_rule.remediation,
                        references=[dh_rule.rfc_reference],
                        vulnerability_tag=dh_rule.vulnerability_tag,
                    )
                )
                threats.append(
                    ThreatMatrixItem(
                        technique_id="T1557",
                        tactic="Credential Access / Discovery",
                        technique_name="Key Recovery (Logjam / Weak DH Group)",
                        severity=Severity.CRITICAL,
                        status="VULNERABLE",
                        details=f"Group {active_dh} ({dh_rule.name}) can be factored using precomputed discrete logs (Logjam).",
                        affected_parameter="dh_group",
                    )
                )
            else:
                threats.append(
                    ThreatMatrixItem(
                        technique_id="T1557",
                        tactic="Defense",
                        technique_name="Resistant Key Exchange",
                        severity=Severity.INFO,
                        status="SECURE",
                        details=f"{dh_rule.name} provides adequate security margin against discrete log attacks.",
                        affected_parameter="dh_group",
                    )
                )

        # 4. Evaluate Perfect Forward Secrecy (PFS)
        if not pfs_enabled:
            findings.append(
                Finding(
                    rule_id="NIST800-77-PFS-DISABLED",
                    severity=Severity.HIGH,
                    category="IKE_PFS",
                    parameter="Perfect Forward Secrecy (PFS)",
                    value="Disabled",
                    description="PFS is disabled for Child SAs. Compromise of long-term IKE SA keys allows retrospective decryption of all past sessions.",
                    recommendation="Enable PFS on all Child SA connections by configuring a DH group during rekeying.",
                    references=["NIST SP 800-77 Rev. 1 §4.1", "RFC 7296 §1.3"],
                    vulnerability_tag="Retrospective Decryption Risk",
                )
            )
            threats.append(
                ThreatMatrixItem(
                    technique_id="T1584",
                    tactic="Credential Access",
                    technique_name="Retrospective Traffic Decryption (No PFS)",
                    severity=Severity.HIGH,
                    status="VULNERABLE",
                    details="Without PFS, an adversary with archived ciphertext can decrypt all sessions if the main key is ever obtained.",
                    affected_parameter="pfs_enabled",
                )
            )
        else:
            threats.append(
                ThreatMatrixItem(
                    technique_id="T1584",
                    tactic="Defense",
                    technique_name="Forward Secrecy Guaranteed",
                    severity=Severity.INFO,
                    status="SECURE",
                    details="PFS is active. Each child SA derives independent session keys via fresh DH exchange.",
                    affected_parameter="pfs_enabled",
                )
            )

        # 5. Evaluate SA Lifetimes (NIST SP 800-77 1 to 8 hour window)
        if sa_lifetime_seconds is not None:
            # 1 hour = 3600s, 8 hours = 28800s
            if sa_lifetime_seconds < 3600 or sa_lifetime_seconds > 28800:
                severity = Severity.MEDIUM if sa_lifetime_seconds > 28800 else Severity.LOW
                reason = "Excessively long lifetime (>8h) increases key-material exposure window" if sa_lifetime_seconds > 28800 else "Excessively short lifetime (<1h) introduces high rekeying overhead and potential DPD storms"
                findings.append(
                    Finding(
                        rule_id="NIST800-77-SA-LIFETIME-WINDOW",
                        severity=severity,
                        category="IKE_LIFETIME",
                        parameter="SA Lifetime",
                        value=f"{sa_lifetime_seconds}s ({sa_lifetime_seconds/3600:.1f} hours)",
                        description=f"SA lifetime is outside the recommended 1 to 8 hour rotation window. {reason}.",
                        recommendation="Configure Phase 1 (IKE) lifetime to 28800s (8h) and Phase 2 (Child SA) lifetime to 3600s (1h).",
                        references=["NIST SP 800-77 Rev. 1 §4.2"],
                        vulnerability_tag="Key Material Exposure Window",
                    )
                )
                threats.append(
                    ThreatMatrixItem(
                        technique_id="T1001",
                        tactic="Command and Control",
                        technique_name="Key Material Overexposure",
                        severity=severity,
                        status="WARNING",
                        details=reason,
                        affected_parameter="sa_lifetime_seconds",
                    )
                )

        # 6. Evaluate RSA Key Length (if applicable)
        if rsa_key_bits is not None and rsa_key_bits > 0:
            if rsa_key_bits < 2048:
                findings.append(
                    Finding(
                        rule_id="NIST800-77-RSA-KEY-SIZE",
                        severity=Severity.CRITICAL,
                        category="IKE_AUTH",
                        parameter="RSA Authentication Key",
                        value=f"{rsa_key_bits} bits",
                        description=f"RSA authentication key ({rsa_key_bits} bits) is below the minimum required 2048 bits.",
                        recommendation="Upgrade RSA certificates to 2048-bit or 3072-bit minimum, or migrate to ECDSA (P-256 / P-384).",
                        references=["NIST SP 800-77 Rev. 1 §3.2", "NIST SP 800-57 Part 1"],
                        vulnerability_tag="RSA Factorization Vulnerability",
                    )
                )
                threats.append(
                    ThreatMatrixItem(
                        technique_id="T1556",
                        tactic="Initial Access / Credential Access",
                        technique_name="Authentication Forgery (Weak RSA Key)",
                        severity=Severity.CRITICAL,
                        status="VULNERABLE",
                        details=f"RSA key size of {rsa_key_bits} bits is insecure against modern factoring capabilities.",
                        affected_parameter="rsa_key_bits",
                    )
                )

        # Calculate Overall Compliance Score (0 - 100)
        total_deduction = sum(self.SEVERITY_DEDUCTIONS.get(f.severity, 0.0) for f in findings)
        score = max(0.0, min(100.0, 100.0 - total_deduction))

        # Assign Letter Grade
        if score >= 90.0:
            grade = "A"
            summary = "Excellent security posture. Fully compliant with modern RFC 8221, RFC 8247, and NIST recommendations."
        elif score >= 80.0:
            grade = "B"
            summary = "Good security posture with minor non-critical recommendations (e.g. legacy CBC mode or lifetime tuning)."
        elif score >= 70.0:
            grade = "C"
            summary = "Acceptable legacy baseline with moderate security risks. Upgrade recommended."
        elif score >= 60.0:
            grade = "D"
            summary = "High risk security posture. Significant weaknesses detected (e.g. PFS disabled or deprecated algorithms)."
        else:
            grade = "F"
            summary = "Critical security failure. Cryptographically broken algorithms (SWEET32, Logjam, MD5, weak keys) detected."

        remediation_config = self.generate_swanctl_remediation(findings, evaluated_params)

        return ComplianceReport(
            overall_score=round(score, 1),
            grade=grade,
            summary=summary,
            findings=findings,
            threat_matrix=threats,
            evaluated_parameters=evaluated_params,
            remediation_config=remediation_config,
        )

    def generate_swanctl_remediation(
        self,
        findings: list[Finding],
        evaluated_params: dict[str, Any],
    ) -> str:
        """
        Generate an authoritative, ready-to-deploy strongSwan 5.7+ (swanctl.conf)
        remediation block resolving all identified compliance findings.
        """
        remediations_applied = []
        for f in findings:
            remediations_applied.append(
                f"# Fix for {f.rule_id} [{f.severity.value}]: {f.recommendation}"
            )

        header_comment = "\n".join(remediations_applied) if remediations_applied else "# Status: Configuration already satisfies RFC 8221, RFC 8247 & NIST SP 800-77."

        return f"""# =============================================================================
# Janus Automated strongSwan Remediation Configuration
# Generated based on RFC 8221 (ESP), RFC 8247 (IKEv2) & NIST SP 800-77 Rev. 1
# =============================================================================
{header_comment}

connections {{
    janus-remediated {{
        version = 2
        local_addrs = %defaultroute
        remote_addrs = %any

        local {{
            auth = pubkey
            certs = cert.pem
            id = vpn-gateway-01.internal
        }}

        remote {{
            auth = pubkey
            id = %any
        }}

        # Hardened IKEv2 Proposal: AES-256-GCM (AEAD) + SHA-256 PRF + DH Group 19 (ECP-256)
        # Complies with RFC 8247 §2.4 (Replaces deprecated DH 1/2/5 & weak MD5/SHA-1)
        proposals = aes256gcm16-prfsha256-ecp256

        # Enforce 4-hour Phase 1 SA rotation (NIST SP 800-77 1h-8h recommended window)
        rekey_time = 4h

        children {{
            net-traffic {{
                local_ts = 0.0.0.0/0
                remote_ts = 0.0.0.0/0
                mode = tunnel

                # Hardened ESP Proposal: AES-256-GCM-16 AEAD + DH Group 19 (PFS enabled)
                # Complies with RFC 8221 §5 (Replaces SWEET32-vulnerable 3DES and non-AEAD CBC)
                esp_proposals = aes256gcm16-ecp256

                # Enforce Perfect Forward Secrecy (PFS) with modern ECP-256 curve
                dpd_action = restart
                close_action = restart
                rekey_time = 4h

                # Auto-labeling support for Janus traffic characterization
                copy_dscp = out
                copy_ecn = yes
            }}
        }}
    }}
}}
""".strip()


# Global evaluator singleton
evaluator = ComplianceEvaluator()
