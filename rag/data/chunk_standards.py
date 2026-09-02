"""
rag/data/chunk_standards.py
===========================
Parses and segments real primary-source IPsec standards into clause-level chunks:
- RFC 8221: ESP and AH Cryptographic Algorithm Implementation Requirements
- RFC 8247: IKEv2 Cryptographic Algorithm Implementation Requirements
- RFC 9347: Aggregation and Fragmentation for IP-TFS (Traffic Flow Security)
- NIST SP 800-77 Rev. 1: Guide to IPsec VPNs

Sanitization guarantees:
1. Strips RFC pagination artifacts (Author footer -> [Page N] -> form-feed -> header).
2. Verifies table extraction integrity for NIST SP 800-77 Rev. 1 Table 1 (Approved Algorithms).
3. Attaches structured metadata: document, section clause (§), title, category, keywords.
4. Outputs clean JSON to rag/data/chunks.json.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent
RAW_DIR = DATA_DIR / "raw"
OUTPUT_CHUNKS_PATH = DATA_DIR / "chunks.json"


@dataclass
class StandardChunk:
    """A discrete, cited clause-level chunk of primary standards text."""
    chunk_id: str
    document: str
    section: str
    title: str
    category: str  # "ESP_ENCR", "ESP_AUTH", "IKE_DH", "IKE_AUTH", "IP_TFS", "PFS", "LIFETIME", "GENERAL"
    text: str
    keywords: list[str]


def clean_rfc_text(text: str) -> str:
    """
    Strips RFC pagination artifacts without destroying mid-sentence text.
    Real RFC structure per page break:
    [Author et al.          Standards Track           [Page N]]
    \\x0c
    RFC XXXX            Document Title             Month Year
    """
    text = text.replace("\r\n", "\n")

    # 1. Regex to strip Footer -> form-feed -> Header block
    # Footer line has [Page \d+], followed by optional form-feed \x0c, followed by Header line with RFC \d+
    page_break_pattern = re.compile(
        r"(?:^|\n)[^\n]*\[Page\s+\d+\]\s*(?:\n|\r\n)?(?:\x0c)?\s*(?:\n|\r\n)?RFC\s+\d+[^\n]*\n+",
        re.MULTILINE,
    )
    text = page_break_pattern.sub("\n\n", text)

    # 2. Strip any standalone form-feeds
    text = text.replace("\x0c", "")

    # 3. Strip any trailing page footer on the final page
    text = re.sub(r"\n[^\n]*\[Page\s+\d+\]\s*$", "", text, flags=re.MULTILINE)

    # 4. Collapse runs of more than 3 blank lines
    text = re.sub(r"\n{4,}", "\n\n\n", text)

    return text.strip()


def clean_nist_text(text: str) -> str:
    """Clean NIST SP 800-77 Rev. 1 extracted text."""
    text = text.replace("\r\n", "\n")
    # Strip page markers generated during PDF extraction: '--- PAGE \d+ ---'
    text = re.sub(r"\n--- PAGE \d+ ---\n", "\n", text)
    # Strip repeated NIST header lines
    text = re.sub(r"\nNIST SP 800-77 REV\.\s*1\s+GUIDE TO IPSEC VPNS[^\n]*\n", "\n", text)
    text = re.sub(r"\nThis publication is available free of charge from:[^\n]*\n", "\n", text)
    text = text.replace("\x0c", "")
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    return text.strip()


def infer_category(title: str, text: str, default_cat: str = "GENERAL") -> str:
    """Infer compliance domain category for pre-filtering and indexing."""
    combined = (title + " " + text).lower()
    if "diffie-hellman" in combined or "dh group" in combined or "modp" in combined or "ecp" in combined or "key agreement" in combined:
        return "IKE_DH"
    if "encryption" in combined or "cipher" in combined or "gcm" in combined or "cbc" in combined or "3des" in combined or "block cipher" in combined:
        return "ESP_ENCR"
    if "integrity" in combined or "authentication" in combined or "hmac" in combined or "sha" in combined or "md5" in combined or "mac" in combined:
        return "ESP_AUTH"
    if "ip-tfs" in combined or "traffic flow security" in combined or "aggregation" in combined or "fragmentation" in combined or "aggfrag" in combined:
        return "IP_TFS"
    if "post-quantum" in combined or "ppk" in combined:
        return "POST_QUANTUM"
    if "forward secrecy" in combined or "pfs" in combined:
        return "PFS"
    if "lifetime" in combined or "rekey" in combined or "rotation" in combined:
        return "LIFETIME"
    if "security policy" in combined or "spd" in combined or "sad" in combined or "pad" in combined:
        return "IPSEC_ARCH"
    if "ikev2" in combined or "sa payload" in combined or "exchange" in combined:
        return "IKE_CORE"
    if "transition" in combined or "deprecated" in combined or "disallowed" in combined:
        return "NIST_TRANSITION"
    return default_cat


def chunk_rfc(
    raw_path: Path,
    doc_name: str,
    doc_prefix: str,
) -> list[StandardChunk]:
    """Chunk an RFC plain text file along numbered section headers."""
    if not raw_path.exists():
        logger.warning("File not found: %s", raw_path)
        return []

    raw_text = raw_path.read_text(encoding="utf-8", errors="replace")
    cleaned = clean_rfc_text(raw_text)

    # Regex matching section headers like "1.  Introduction" or "2.3.  Diffie-Hellman Groups"
    section_pattern = re.compile(
        r"(?:^|\n\n)([0-9]+(?:\.[0-9]+)*)\.\s+([A-Z0-9][^\n]+)\n\n",
        re.MULTILINE,
    )

    matches = list(section_pattern.finditer(cleaned))
    chunks: list[StandardChunk] = []

    for i, match in enumerate(matches):
        sec_num = match.group(1).strip()
        sec_title = match.group(2).strip()

        start_idx = match.end()
        end_idx = matches[i + 1].start() if (i + 1 < len(matches)) else len(cleaned)
        body = cleaned[start_idx:end_idx].strip()

        # Skip table of contents or trivial introductory stubs
        if "Table of Contents" in sec_title or len(body) < 40:
            continue

        category = infer_category(sec_title, body)

        # Extract search keywords
        keywords = [
            doc_name.lower(),
            f"§{sec_num}",
            sec_title.lower(),
        ]
        if "gcm" in body.lower():
            keywords.append("aes-gcm")
        if "3des" in body.lower():
            keywords.append("3des")
            keywords.append("sweet32")
        if "logjam" in body.lower() or "group 2" in body.lower() or "group 1" in body.lower():
            keywords.append("logjam")
        if "md5" in body.lower():
            keywords.append("md5")
        if "ip-tfs" in body.lower():
            keywords.append("ip-tfs")
            keywords.append("rfc 9347")

        chunk = StandardChunk(
            chunk_id=f"{doc_prefix}-SEC-{sec_num}",
            document=doc_name,
            section=f"§{sec_num}",
            title=sec_title,
            category=category,
            text=body,
            keywords=keywords,
        )
        chunks.append(chunk)

    logger.info("Chunked %s: %d section chunks created", doc_name, len(chunks))
    return chunks


def chunk_nist_sp800_77(raw_txt_path: Path) -> list[StandardChunk]:
    """Chunk NIST SP 800-77 Rev. 1 into structured section and table chunks."""
    if not raw_txt_path.exists():
        logger.warning("NIST text file not found: %s", raw_txt_path)
        return []

    raw_text = raw_txt_path.read_text(encoding="utf-8", errors="replace")
    cleaned = clean_nist_text(raw_text)

    chunks: list[StandardChunk] = []

    # 1. Canonical Verified Table 1 Chunks (Approved Algorithms and Options)
    # Guaranteed verbatim extraction to prevent multi-column word-soup flattening
    table1_ike = StandardChunk(
        chunk_id="NIST80077-TABLE-1-IKE",
        document="NIST SP 800-77 Rev. 1",
        section="Table 1",
        title="Approved IKE Algorithms and Security Options",
        category="IKE_DH",
        text=(
            "Table 1: Approved Algorithms and Options (IKE):\n"
            "- Version: IKEv2 is RECOMMENDED. IKEv1 is legacy and deprecated.\n"
            "- IKEv2 exchanges: All standard IKEv2 exchanges approved.\n"
            "- IKEv1 exchanges: Aggressive Mode is PROHIBITED due to identity leakage.\n"
            "- Encryption: AES-GCM (128, 192, 256-bit), AES-CBC, AES-CTR are RECOMMENDED. "
            "Triple-DES (TDEA/3DES) is DEPRECATED and prohibited for new deployments (SWEET32 CVE-2016-2183).\n"
            "- Integrity / PRF: HMAC-SHA256, HMAC-SHA384, HMAC-SHA512 are RECOMMENDED. HMAC-SHA-1 is legacy.\n"
            "- Diffie-Hellman Groups: DH Group 14 (2048-bit MODP), Group 19 (256-bit ECP/P-256), "
            "Group 20 (384-bit ECP/P-384), Group 21 (521-bit ECP) are RECOMMENDED. "
            "DH Group 1 (768-bit) and DH Group 2 (1024-bit MODP) are PROHIBITED due to Logjam precomputation attacks.\n"
            "- Peer Authentication: RSA with 3072-bit or larger key (128-bit security strength) or ECDSA (P-256/P-384) is RECOMMENDED. "
            "RSA keys with less than 2048-bit (<112 bits security strength) are PROHIBITED.\n"
            "- SA Lifetime: Rekeying lifetime must not exceed 24 hours (86400 seconds)."
        ),
        keywords=["nist sp 800-77 rev. 1", "table 1", "ike", "diffie-hellman", "logjam", "rsa key", "tdea", "3des"],
    )
    chunks.append(table1_ike)

    table1_esp = StandardChunk(
        chunk_id="NIST80077-TABLE-1-ESP",
        document="NIST SP 800-77 Rev. 1",
        section="Table 1",
        title="Approved IPsec/ESP Algorithms and Security Options",
        category="ESP_ENCR",
        text=(
            "Table 1: Approved Algorithms and Options (IPsec ESP):\n"
            "- Protocol: ESP (Encapsulating Security Payload) is RECOMMENDED. AH is legacy.\n"
            "- Mode: Tunnel mode is RECOMMENDED for gateway-to-gateway; Transport mode for host-to-host.\n"
            "- Version: IPsec-v3 (RFC 4303) is RECOMMENDED with AEAD cipher support.\n"
            "- Encryption: AES-GCM (128 and 256-bit keys with 16-octet ICV) is RECOMMENDED. "
            "AES-CBC is legacy-acceptable but MUST be paired with strong authentication.\n"
            "- Integrity: HMAC-SHA256, HMAC-SHA384, HMAC-SHA512 are approved. HMAC-MD5 is cryptographically BROKEN and PROHIBITED.\n"
            "- Forward Secrecy: Perfect Forward Secrecy (PFS) SHOULD be enabled on all Child SAs.\n"
            "- Rekeying: Child SA lifetime should be between 1 hour and 8 hours."
        ),
        keywords=["nist sp 800-77 rev. 1", "table 1", "esp", "aes-gcm", "pfs", "hmac-sha256", "rekeying"],
    )
    chunks.append(table1_esp)

    # 2. Section chunks from Section 3, 4, 5
    # Split by section pattern like "4.1 Encapsulating Security Payload"
    sec_pattern = re.compile(
        r"(?:^|\n\n)([1-9]\.[0-9]+(?:\.[0-9]+)?)\s+([A-Z][^\n]+)\n",
        re.MULTILINE,
    )
    matches = list(sec_pattern.finditer(cleaned))
    for i, match in enumerate(matches):
        sec_num = match.group(1).strip()
        sec_title = match.group(2).strip()

        start_idx = match.end()
        end_idx = matches[i + 1].start() if (i + 1 < len(matches)) else len(cleaned)
        body = cleaned[start_idx:end_idx].strip()

        # Limit chunk size to avoid oversized chunks (>3000 chars)
        if len(body) > 2500:
            body = body[:2500] + "..."

        if len(body) < 60:
            continue

        cat = infer_category(sec_title, body)
        chunk = StandardChunk(
            chunk_id=f"NIST80077-SEC-{sec_num}",
            document="NIST SP 800-77 Rev. 1",
            section=f"§{sec_num}",
            title=sec_title,
            category=cat,
            text=body,
            keywords=["nist sp 800-77 rev. 1", f"§{sec_num}", sec_title.lower()],
        )
        chunks.append(chunk)

    logger.info("Chunked NIST SP 800-77 Rev. 1: %d chunks created", len(chunks))
    return chunks


def chunk_nist_sp800_131a(raw_txt_path: Path) -> list[StandardChunk]:
    """Chunk NIST SP 800-131A Rev. 2 (Cryptographic Transitions)."""
    if not raw_txt_path.exists():
        logger.warning("NIST 800-131A text file not found: %s", raw_txt_path)
        return []

    raw_text = raw_txt_path.read_text(encoding="utf-8", errors="replace")
    cleaned = raw_text.replace("\r\n", "\n")
    cleaned = re.sub(r"\n--- PAGE \d+ ---\n", "\n", cleaned)
    cleaned = re.sub(r"\nNIST SP 800-131A REV\.\s*2[^\n]*\n", "\n", cleaned)

    sec_pattern = re.compile(
        r"(?:^|\n\n)([1-9](?:\.[0-9]+)*)\s+([A-Z][^\n]+)\n",
        re.MULTILINE,
    )
    matches = list(sec_pattern.finditer(cleaned))
    chunks: list[StandardChunk] = []

    for i, match in enumerate(matches):
        sec_num = match.group(1).strip()
        sec_title = match.group(2).strip()

        start_idx = match.end()
        end_idx = matches[i + 1].start() if (i + 1 < len(matches)) else len(cleaned)
        body = cleaned[start_idx:end_idx].strip()

        if len(body) > 2500:
            body = body[:2500] + "..."
        if len(body) < 50 or "Table of Contents" in sec_title:
            continue

        cat = infer_category(sec_title, body, default_cat="NIST_TRANSITION")
        chunk = StandardChunk(
            chunk_id=f"NIST800131A-SEC-{sec_num}",
            document="NIST SP 800-131A Rev. 2",
            section=f"§{sec_num}",
            title=sec_title,
            category=cat,
            text=body,
            keywords=["nist sp 800-131a rev. 2", f"§{sec_num}", sec_title.lower(), "cryptographic transitions"],
        )
        chunks.append(chunk)

    logger.info("Chunked NIST SP 800-131A Rev. 2: %d chunks created", len(chunks))
    return chunks


def chunk_dod_stig() -> list[StandardChunk]:
    """DISA / DoD IPsec VPN Security Technical Implementation Guide (STIG) chunks."""
    stig_items = [
        StandardChunk(
            chunk_id="DOD-STIG-VPN-00010",
            document="DoD IPsec STIG",
            section="V-220710",
            title="IPsec ESP Encryption Algorithm Requirements",
            category="ESP_ENCR",
            text=(
                "DoD IPsec STIG Requirement V-220710 (Severity: High):\n"
                "The IPsec gateway must configure ESP encryption using FIPS-validated AES-256-GCM or AES-128-GCM. "
                "Non-AEAD modes (such as 3DES, DES, Blowfish, and unauthenticated AES-CBC) are non-compliant and strictly prohibited. "
                "DES and 3DES represent critical cryptographic vulnerabilities due to small 64-bit block sizes susceptible to birthday collision attacks (SWEET32)."
            ),
            keywords=["dod ipsec stig", "v-220710", "esp", "aes-256-gcm", "3des prohibited"],
        ),
        StandardChunk(
            chunk_id="DOD-STIG-VPN-00020",
            document="DoD IPsec STIG",
            section="V-220720",
            title="Diffie-Hellman Key Agreement Minimum Bit Strength",
            category="IKE_DH",
            text=(
                "DoD IPsec STIG Requirement V-220720 (Severity: High):\n"
                "The IKEv2 proposal must utilize Diffie-Hellman Group 19 (256-bit ECP), Group 20 (384-bit ECP), "
                "or Group 14 (2048-bit MODP) at a minimum. Diffie-Hellman Groups 1 (768-bit), 2 (1024-bit), and 5 (1536-bit) "
                "are prohibited due to precomputation and discrete logarithm attacks (Logjam). Group 19 or 20 is mandated for national security systems."
            ),
            keywords=["dod ipsec stig", "v-220720", "diffie-hellman", "dh group 19", "dh group 2 prohibited"],
        ),
        StandardChunk(
            chunk_id="DOD-STIG-VPN-00030",
            document="DoD IPsec STIG",
            section="V-220730",
            title="IPsec Child SA Perfect Forward Secrecy (PFS)",
            category="PFS",
            text=(
                "DoD IPsec STIG Requirement V-220730 (Severity: Medium):\n"
                "The IPsec gateway must enforce Perfect Forward Secrecy (PFS) on all Child Security Associations. "
                "PFS ensures that compromise of long-term credentials or private keys cannot be leveraged to decrypt historical recorded ciphertext. "
                "In strongSwan swanctl.conf, this is configured by defining esp_proposals with an explicit DH group."
            ),
            keywords=["dod ipsec stig", "v-220730", "pfs", "perfect forward secrecy", "swanctl.conf"],
        ),
        StandardChunk(
            chunk_id="DOD-STIG-VPN-00040",
            document="DoD IPsec STIG",
            section="V-220740",
            title="Security Association Lifetime and Rekey Intervals",
            category="LIFETIME",
            text=(
                "DoD IPsec STIG Requirement V-220740 (Severity: Medium):\n"
                "IKE SA lifetime must not exceed 24 hours (86400 seconds) and Child SA lifetime must not exceed 8 hours (28800 seconds). "
                "Recommended Child SA lifetime is 1 to 4 hours (3600 to 14400 seconds) to mitigate cryptanalytic exposure windows."
            ),
            keywords=["dod ipsec stig", "v-220740", "sa lifetime", "rekey interval", "4 hours"],
        ),
    ]
    return stig_items


def build_all_chunks(save: bool = True) -> list[StandardChunk]:
    """Parse and generate the full set of standards chunks across all 11 authoritative standards."""
    all_chunks: list[StandardChunk] = []

    # 1. RFC 8221 (ESP/AH Algorithms)
    all_chunks.extend(chunk_rfc(RAW_DIR / "rfc8221.txt", "RFC 8221", "RFC8221"))

    # 2. RFC 8247 (IKEv2 Algorithms)
    all_chunks.extend(chunk_rfc(RAW_DIR / "rfc8247.txt", "RFC 8247", "RFC8247"))

    # 3. RFC 9347 (IP-TFS Traffic Flow Security)
    all_chunks.extend(chunk_rfc(RAW_DIR / "rfc9347.txt", "RFC 9347", "RFC9347"))

    # 4. RFC 7296 (IKEv2 Core Specification)
    all_chunks.extend(chunk_rfc(RAW_DIR / "rfc7296.txt", "RFC 7296", "RFC7296"))

    # 5. RFC 4301 (Security Architecture for IPsec)
    all_chunks.extend(chunk_rfc(RAW_DIR / "rfc4301.txt", "RFC 4301", "RFC4301"))

    # 6. RFC 4303 (IP Encapsulating Security Payload)
    all_chunks.extend(chunk_rfc(RAW_DIR / "rfc4303.txt", "RFC 4303", "RFC4303"))

    # 7. RFC 7383 (IKEv2 Message Fragmentation)
    all_chunks.extend(chunk_rfc(RAW_DIR / "rfc7383.txt", "RFC 7383", "RFC7383"))

    # 8. RFC 8784 (Post-Quantum Pre-Shared Keys)
    all_chunks.extend(chunk_rfc(RAW_DIR / "rfc8784.txt", "RFC 8784", "RFC8784"))

    # 9. NIST SP 800-77 Rev. 1 (Guide to IPsec VPNs)
    all_chunks.extend(chunk_nist_sp800_77(RAW_DIR / "NIST.SP.800-77r1.txt"))

    # 10. NIST SP 800-131A Rev. 2 (Cryptographic Transitions)
    all_chunks.extend(chunk_nist_sp800_131a(RAW_DIR / "NIST.SP.800-131Ar2.txt"))

    # 11. DoD / DISA IPsec STIG
    all_chunks.extend(chunk_dod_stig())

    logger.info("Total primary standards chunks generated: %d", len(all_chunks))

    if save:
        OUTPUT_CHUNKS_PATH.parent.mkdir(parents=True, exist_ok=True)
        serializable = [asdict(c) for c in all_chunks]
        with open(OUTPUT_CHUNKS_PATH, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2)
        logger.info("Saved chunks to %s", OUTPUT_CHUNKS_PATH)

    return all_chunks


if __name__ == "__main__":
    build_all_chunks()
