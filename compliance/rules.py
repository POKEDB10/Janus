"""
Janus Compliance Engine — Rules Specification
==============================================
Deterministic security assessment rules for IPsec (IKEv2 & ESP).

Standards implemented (EXACT compliance table):
- RFC 8221: Cryptographic Algorithm Implementation Requirements and Usage
            Guidance for Encapsulating Security Payload (ESP) and Authentication Header (AH)
- RFC 8247: Cryptographic Algorithm Implementation Requirements and Usage
            Guidance for Internet Key Exchange Version 2 (IKEv2)
- NIST SP 800-77 Rev. 1: Guide to IPsec VPNs

Requirement Levels:
- MUST: Mandatory requirement (modern standard)
- MUST-: Legacy mandatory, deprecated / phasing out
- SHOULD: Recommended for specific environments
- SHOULD+: Recommended baseline acceptable
- RECOMMENDED: Preferred modern standard
- SHOULD NOT: Insecure / vulnerable, avoid
- MUST NOT / HISTORIC: Insecure / broken, prohibited

Risk Severities:
- CRITICAL: Known exploit / broken cryptography (Logjam, SWEET32, MD5, DES/3DES)
- HIGH: Deprecated algorithm, missing PFS, unsafe key sizes
- MEDIUM: Legacy cipher/hash, sub-optimal parameters
- LOW: Informational or slightly non-standard parameter
- INFO: Fully compliant / best practice
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class RequirementLevel(str, Enum):
    MUST = "MUST"
    MUST_MINUS = "MUST-"
    SHOULD_PLUS = "SHOULD+"
    RECOMMENDED = "RECOMMENDED"
    SHOULD = "SHOULD"
    SHOULD_NOT = "SHOULD NOT"
    MUST_NOT = "MUST NOT"
    HISTORIC = "HISTORIC"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class CryptoRule:
    """A single cryptographic parameter compliance rule."""

    category: str  # "ESP_ENCR", "ESP_AUTH", "IKE_DH", "IKE_AUTH", "IKE_LIFETIME", "IKE_PFS"
    algorithm_id: str  # canonical algorithm identifier or parameter name
    name: str  # Human readable name
    requirement_level: RequirementLevel
    severity: Severity  # Severity if this rule is violated or flagged
    is_aead: bool = False
    is_deprecated: bool = False
    vulnerability_tag: Optional[str] = None  # e.g., "SWEET32", "Logjam", "Collision Attack"
    rfc_reference: str = ""
    description: str = ""
    remediation: str = ""


# =============================================================================
# RFC 8221 ESP Encryption Algorithms Table
# =============================================================================
ESP_ENCRYPTION_RULES: dict[str, CryptoRule] = {
    "ENCR_AES_GCM_16": CryptoRule(
        category="ESP_ENCR",
        algorithm_id="ENCR_AES_GCM_16",
        name="AES-GCM (128/256-bit) with 16-octet ICV",
        requirement_level=RequirementLevel.MUST,
        severity=Severity.INFO,
        is_aead=True,
        is_deprecated=False,
        rfc_reference="RFC 8221 §5",
        description="AEAD cipher with built-in authenticated encryption. Preferred standard for ESP.",
        remediation="Compliant. Maintain AES-GCM-16 configuration.",
    ),
    "ENCR_AES_CBC": CryptoRule(
        category="ESP_ENCR",
        algorithm_id="ENCR_AES_CBC",
        name="AES-CBC (128/256-bit)",
        requirement_level=RequirementLevel.MUST,
        severity=Severity.LOW,
        is_aead=False,
        is_deprecated=False,
        rfc_reference="RFC 8221 §5",
        description="Legacy interop only. Requires separate integrity algorithm (AUTH). Flagged as suboptimal.",
        remediation="Upgrade to AEAD cipher (AES-GCM-16 or ChaCha20-Poly1305) to prevent padding oracle risks.",
    ),
    "ENCR_CHACHA20_POLY1305": CryptoRule(
        category="ESP_ENCR",
        algorithm_id="ENCR_CHACHA20_POLY1305",
        name="ChaCha20-Poly1305 AEAD",
        requirement_level=RequirementLevel.SHOULD,
        severity=Severity.INFO,
        is_aead=True,
        is_deprecated=False,
        rfc_reference="RFC 8221 §5",
        description="Modern AEAD cipher, optimal for environments lacking AES hardware acceleration.",
        remediation="Compliant modern AEAD cipher.",
    ),
    "ENCR_3DES": CryptoRule(
        category="ESP_ENCR",
        algorithm_id="ENCR_3DES",
        name="Triple-DES (3DES-EDE-CBC)",
        requirement_level=RequirementLevel.SHOULD_NOT,
        severity=Severity.HIGH,
        is_aead=False,
        is_deprecated=True,
        vulnerability_tag="SWEET32 (CVE-2016-2183)",
        rfc_reference="RFC 8221 §5",
        description="64-bit block cipher susceptible to collision attacks (SWEET32) after 32GB of data.",
        remediation="Disable 3DES immediately. Migrate to AES-256-GCM or AES-128-GCM.",
    ),
    "ENCR_DES": CryptoRule(
        category="ESP_ENCR",
        algorithm_id="ENCR_DES",
        name="DES (Single DES)",
        requirement_level=RequirementLevel.MUST_NOT,
        severity=Severity.CRITICAL,
        is_aead=False,
        is_deprecated=True,
        vulnerability_tag="Brute Force (56-bit key)",
        rfc_reference="RFC 8221 §5",
        description="Single 56-bit DES is broken and can be cracked in minutes.",
        remediation="Prohibit DES entirely. Migrate to AES-GCM.",
    ),
    "ENCR_BLOWFISH": CryptoRule(
        category="ESP_ENCR",
        algorithm_id="ENCR_BLOWFISH",
        name="Blowfish",
        requirement_level=RequirementLevel.MUST_NOT,
        severity=Severity.CRITICAL,
        is_aead=False,
        is_deprecated=True,
        vulnerability_tag="SWEET32 (64-bit block)",
        rfc_reference="RFC 8221 §5",
        description="Deprecated 64-bit block cipher vulnerable to SWEET32 collisions.",
        remediation="Disable Blowfish. Migrate to AES-GCM.",
    ),
    "ENCR_RC5": CryptoRule(
        category="ESP_ENCR",
        algorithm_id="ENCR_RC5",
        name="RC5",
        requirement_level=RequirementLevel.MUST_NOT,
        severity=Severity.CRITICAL,
        is_aead=False,
        is_deprecated=True,
        vulnerability_tag="Deprecated Cipher",
        rfc_reference="RFC 8221 §5",
        description="Deprecated cipher with security weaknesses and small block size.",
        remediation="Disable RC5. Migrate to AES-GCM.",
    ),
    "ENCR_IDEA": CryptoRule(
        category="ESP_ENCR",
        algorithm_id="ENCR_IDEA",
        name="IDEA",
        requirement_level=RequirementLevel.MUST_NOT,
        severity=Severity.CRITICAL,
        is_aead=False,
        is_deprecated=True,
        vulnerability_tag="Deprecated Cipher (64-bit block)",
        rfc_reference="RFC 8221 §5",
        description="Deprecated 64-bit block cipher. Insecure for modern ESP.",
        remediation="Disable IDEA. Migrate to AES-GCM.",
    ),
    "ENCR_NULL": CryptoRule(
        category="ESP_ENCR",
        algorithm_id="ENCR_NULL",
        name="Null Encryption",
        requirement_level=RequirementLevel.MUST_NOT,
        severity=Severity.HIGH,
        is_aead=False,
        is_deprecated=False,
        rfc_reference="RFC 8221 §5",
        description="No confidentiality provided. Only permissible for pure authentication/integrity testing.",
        remediation="Enable encryption (AES-GCM) unless running in an isolated testbed with AH only.",
    ),
}


# =============================================================================
# RFC 8221 ESP Authentication / Integrity Algorithms Table
# =============================================================================
ESP_AUTH_RULES: dict[str, CryptoRule] = {
    "AUTH_HMAC_SHA2_256_128": CryptoRule(
        category="ESP_AUTH",
        algorithm_id="AUTH_HMAC_SHA2_256_128",
        name="HMAC-SHA-256-128",
        requirement_level=RequirementLevel.MUST,
        severity=Severity.INFO,
        rfc_reference="RFC 8221 §5",
        description="Mandatory integrity algorithm providing 128-bit truncated HMAC-SHA-256.",
        remediation="Compliant integrity algorithm.",
    ),
    "AUTH_HMAC_SHA2_384_192": CryptoRule(
        category="ESP_AUTH",
        algorithm_id="AUTH_HMAC_SHA2_384_192",
        name="HMAC-SHA-384-192",
        requirement_level=RequirementLevel.SHOULD,
        severity=Severity.INFO,
        rfc_reference="RFC 8221 §5",
        description="High security integrity algorithm for Top Secret / CNSA Suite profiles.",
        remediation="Compliant high-security integrity algorithm.",
    ),
    "AUTH_HMAC_SHA2_512_256": CryptoRule(
        category="ESP_AUTH",
        algorithm_id="AUTH_HMAC_SHA2_512_256",
        name="HMAC-SHA-512-256",
        requirement_level=RequirementLevel.SHOULD,
        severity=Severity.INFO,
        rfc_reference="RFC 8221 §5",
        description="Strong integrity algorithm for 256-bit security level.",
        remediation="Compliant integrity algorithm.",
    ),
    "AUTH_HMAC_SHA1_96": CryptoRule(
        category="ESP_AUTH",
        algorithm_id="AUTH_HMAC_SHA1_96",
        name="HMAC-SHA-1-96",
        requirement_level=RequirementLevel.MUST_MINUS,
        severity=Severity.MEDIUM,
        is_deprecated=True,
        vulnerability_tag="SHA-1 Collision Attack (SHAttered)",
        rfc_reference="RFC 8221 §5",
        description="Deprecated integrity algorithm with collision vulnerability risks. Legacy compatibility only.",
        remediation="Upgrade integrity algorithm to HMAC-SHA-256-128 or use AEAD cipher.",
    ),
    "AUTH_HMAC_MD5_96": CryptoRule(
        category="ESP_AUTH",
        algorithm_id="AUTH_HMAC_MD5_96",
        name="HMAC-MD5-96",
        requirement_level=RequirementLevel.MUST_NOT,
        severity=Severity.CRITICAL,
        is_deprecated=True,
        vulnerability_tag="MD5 Collision Vulnerability (Broken)",
        rfc_reference="RFC 8221 §5",
        description="MD5 is cryptographically broken and vulnerable to practical collision generation.",
        remediation="Disable HMAC-MD5 immediately. Replace with HMAC-SHA-256-128 or AEAD.",
    ),
    "AUTH_NONE": CryptoRule(
        category="ESP_AUTH",
        algorithm_id="AUTH_NONE",
        name="No Authentication (AUTH_NONE)",
        requirement_level=RequirementLevel.MUST_NOT,
        severity=Severity.CRITICAL,
        rfc_reference="RFC 8221 §5",
        description="No integrity algorithm provided. MUST NOT be used unless combined with an AEAD cipher.",
        remediation="If using non-AEAD cipher (CBC mode), configure HMAC-SHA-256-128. If using AEAD (GCM), AUTH_NONE is expected.",
    ),
}


# =============================================================================
# RFC 8247 & NIST SP 800-77 Rev. 1 Diffie-Hellman Key Exchange Groups
# =============================================================================
DH_GROUP_RULES: dict[int, CryptoRule] = {
    1: CryptoRule(
        category="IKE_DH",
        algorithm_id="DH_GROUP_1",
        name="DH Group 1 (768-bit MODP)",
        requirement_level=RequirementLevel.MUST_NOT,
        severity=Severity.CRITICAL,
        is_deprecated=True,
        vulnerability_tag="Logjam Attack / Inadequate Key Length",
        rfc_reference="RFC 8247 §2.3 / NIST SP 800-77 Rev. 1",
        description="768-bit MODP is completely insecure and factorable by modest compute resources.",
        remediation="Prohibit DH Group 1. Minimum acceptable group is DH Group 14 (2048-bit MODP) or DH Group 19 (ECP-256).",
    ),
    2: CryptoRule(
        category="IKE_DH",
        algorithm_id="DH_GROUP_2",
        name="DH Group 2 (1024-bit MODP)",
        requirement_level=RequirementLevel.MUST_NOT,
        severity=Severity.CRITICAL,
        is_deprecated=True,
        vulnerability_tag="Logjam Attack (WeakDH)",
        rfc_reference="RFC 8247 §2.3 / NIST SP 800-77 Rev. 1",
        description="1024-bit MODP is vulnerable to nation-state precomputation attacks (Logjam). Prohibited by NIST and RFC 8247.",
        remediation="Prohibit DH Group 2 immediately. Upgrade to DH Group 19 (ECP-256) or DH Group 14 (MODP-2048).",
    ),
    5: CryptoRule(
        category="IKE_DH",
        algorithm_id="DH_GROUP_5",
        name="DH Group 5 (1536-bit MODP)",
        requirement_level=RequirementLevel.MUST_NOT,
        severity=Severity.CRITICAL,
        is_deprecated=True,
        vulnerability_tag="Sub-2048-bit MODP Security Deficiency",
        rfc_reference="RFC 8247 §2.3 / NIST SP 800-77 Rev. 1",
        description="1536-bit MODP does not meet the minimum 112-bit security requirement.",
        remediation="Upgrade to DH Group 14 (2048-bit MODP) or DH Group 19 (ECP-256).",
    ),
    14: CryptoRule(
        category="IKE_DH",
        algorithm_id="DH_GROUP_14",
        name="DH Group 14 (2048-bit MODP)",
        requirement_level=RequirementLevel.SHOULD_PLUS,
        severity=Severity.INFO,
        rfc_reference="RFC 8247 §2.3 / NIST SP 800-77 Rev. 1",
        description="2048-bit MODP provides 112-bit security level. Baseline acceptable standard.",
        remediation="Acceptable legacy baseline. For improved performance and security, consider DH Group 19 (ECP-256).",
    ),
    19: CryptoRule(
        category="IKE_DH",
        algorithm_id="DH_GROUP_19",
        name="DH Group 19 (256-bit ECP / NIST P-256)",
        requirement_level=RequirementLevel.RECOMMENDED,
        severity=Severity.INFO,
        rfc_reference="RFC 8247 §2.3 / NIST SP 800-77 Rev. 1",
        description="256-bit Elliptic Curve Diffie-Hellman providing 128-bit security level with high efficiency.",
        remediation="Compliant recommended Diffie-Hellman group.",
    ),
    20: CryptoRule(
        category="IKE_DH",
        algorithm_id="DH_GROUP_20",
        name="DH Group 20 (384-bit ECP / NIST P-384)",
        requirement_level=RequirementLevel.RECOMMENDED,
        severity=Severity.INFO,
        rfc_reference="RFC 8247 §2.3 / NIST SP 800-77 Rev. 1",
        description="384-bit Elliptic Curve Diffie-Hellman providing 192-bit security level (CNSA Suite compliant).",
        remediation="Compliant high-security Diffie-Hellman group.",
    ),
    21: CryptoRule(
        category="IKE_DH",
        algorithm_id="DH_GROUP_21",
        name="DH Group 21 (521-bit ECP / NIST P-521)",
        requirement_level=RequirementLevel.SHOULD,
        severity=Severity.INFO,
        rfc_reference="RFC 8247 §2.3",
        description="521-bit Elliptic Curve Diffie-Hellman providing 256-bit security level.",
        remediation="Compliant high-security Diffie-Hellman group.",
    ),
}


# =============================================================================
# Helper normalizers and rule lookup
# =============================================================================

def normalize_encr_name(name: str) -> str:
    """Normalize common encryption strings to canonical rule keys."""
    raw = name.upper().replace("-", "_").replace(" ", "_")
    if "GCM" in raw:
        return "ENCR_AES_GCM_16"
    if "CHACHA" in raw:
        return "ENCR_CHACHA20_POLY1305"
    if "3DES" in raw or "TRIPLE_DES" in raw or "DES_EDE" in raw:
        return "ENCR_3DES"
    if "BLOWFISH" in raw:
        return "ENCR_BLOWFISH"
    if "RC5" in raw:
        return "ENCR_RC5"
    if "IDEA" in raw:
        return "ENCR_IDEA"
    if "NULL" in raw or raw == "NONE":
        return "ENCR_NULL"
    if "AES_CBC" in raw or ("AES" in raw and "CBC" in raw) or (raw.startswith("AES") and "GCM" not in raw):
        return "ENCR_AES_CBC"
    if "DES" in raw:
        return "ENCR_DES"
    return name


def normalize_auth_name(name: str) -> str:
    """Normalize authentication/integrity strings to canonical rule keys."""
    raw = name.upper().replace("-", "_").replace(" ", "_")
    if "MD5" in raw:
        return "AUTH_HMAC_MD5_96"
    if "SHA1" in raw or "SHA_1" in raw:
        return "AUTH_HMAC_SHA1_96"
    if "SHA384" in raw or "SHA2_384" in raw or "SHA_384" in raw:
        return "AUTH_HMAC_SHA2_384_192"
    if "SHA512" in raw or "SHA2_512" in raw or "SHA_512" in raw:
        return "AUTH_HMAC_SHA2_512_256"
    if "SHA256" in raw or "SHA2_256" in raw or "SHA_256" in raw:
        return "AUTH_HMAC_SHA2_256_128"
    if "NONE" in raw or "NULL" in raw or raw == "":
        return "AUTH_NONE"
    return name


def get_esp_encryption_rule(encr_name: str) -> Optional[CryptoRule]:
    """Retrieve rule definition for an ESP encryption algorithm."""
    norm = normalize_encr_name(encr_name)
    return ESP_ENCRYPTION_RULES.get(norm)


def get_esp_auth_rule(auth_name: str) -> Optional[CryptoRule]:
    """Retrieve rule definition for an ESP authentication algorithm."""
    norm = normalize_auth_name(auth_name)
    return ESP_AUTH_RULES.get(norm)


def get_dh_group_rule(group_num: int) -> Optional[CryptoRule]:
    """Retrieve rule definition for a Diffie-Hellman group."""
    return DH_GROUP_RULES.get(group_num)
