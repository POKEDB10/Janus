"""
rag/data/fetch_standards.py
===========================
Fetches real, authoritative primary-source cryptographic and IPsec standards:
- RFC 8221: Cryptographic Algorithm Implementation Requirements for ESP & AH
- RFC 8247: Cryptographic Algorithm Implementation Requirements for IKEv2
- RFC 9347: Aggregation and Fragmentation for IP-TFS
- NIST SP 800-77 Rev. 1: Guide to IPsec VPNs

No synthesized or fabricated standards text is permitted. All documents are
downloaded directly from the official IETF RFC Editor and NIST CSRC portals.
"""

from __future__ import annotations

import logging
import urllib.request
from pathlib import Path
from typing import Optional

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

RAW_DIR = Path(__file__).resolve().parent / "raw"

STANDARDS_URLS = {
    "RFC_8221": {
        "url": "https://www.rfc-editor.org/rfc/rfc8221.txt",
        "filename": "rfc8221.txt",
        "description": "ESP and AH Cryptographic Algorithm Implementation Requirements",
    },
    "RFC_8247": {
        "url": "https://www.rfc-editor.org/rfc/rfc8247.txt",
        "filename": "rfc8247.txt",
        "description": "IKEv2 Cryptographic Algorithm Implementation Requirements",
    },
    "RFC_9347": {
        "url": "https://www.rfc-editor.org/rfc/rfc9347.txt",
        "filename": "rfc9347.txt",
        "description": "Aggregation and Fragmentation for IP-TFS",
    },
    "RFC_7296": {
        "url": "https://www.rfc-editor.org/rfc/rfc7296.txt",
        "filename": "rfc7296.txt",
        "description": "Internet Key Exchange Protocol Version 2 (IKEv2) Core Specification",
    },
    "RFC_4301": {
        "url": "https://www.rfc-editor.org/rfc/rfc4301.txt",
        "filename": "rfc4301.txt",
        "description": "Security Architecture for the Internet Protocol",
    },
    "RFC_4303": {
        "url": "https://www.rfc-editor.org/rfc/rfc4303.txt",
        "filename": "rfc4303.txt",
        "description": "IP Encapsulating Security Payload (ESP)",
    },
    "RFC_7383": {
        "url": "https://www.rfc-editor.org/rfc/rfc7383.txt",
        "filename": "rfc7383.txt",
        "description": "IKEv2 Message Fragmentation",
    },
    "RFC_8784": {
        "url": "https://www.rfc-editor.org/rfc/rfc8784.txt",
        "filename": "rfc8784.txt",
        "description": "Mixing Preshared Keys in IKEv2 for Post-Quantum Pre-shared Keys",
    },
    "NIST_SP_800_77_R1": {
        "url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-77r1.pdf",
        "filename": "NIST.SP.800-77r1.pdf",
        "description": "NIST SP 800-77 Rev. 1: Guide to IPsec VPNs",
    },
    "NIST_SP_800_131A_R2": {
        "url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf",
        "filename": "NIST.SP.800-131Ar2.pdf",
        "description": "NIST SP 800-131A Rev. 2: Cryptographic Transitions & Deprecations",
    },
}


def download_file(url: str, dest_path: Path, timeout: int = 45) -> bool:
    """Download a file with User-Agent header and write to dest_path."""
    try:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) JanusComplianceDownloader/1.0"},
        )
        logger.info("Downloading %s -> %s", url, dest_path.name)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read()
            with open(dest_path, "wb") as f:
                f.write(content)
        logger.info("Downloaded %s (%d bytes)", dest_path.name, len(content))
        return True
    except Exception as exc:
        logger.error("Failed to download %s: %s", url, exc)
        return False


def extract_nist_pdf_text(pdf_path: Path, txt_out_path: Path) -> bool:
    """Extract raw text from NIST SP 800-77 Rev. 1 PDF into plain text."""
    if not pdf_path.exists():
        logger.error("PDF file does not exist: %s", pdf_path)
        return False

    if PdfReader is None:
        logger.error("pypdf is not installed; cannot extract text from %s", pdf_path)
        return False

    try:
        reader = PdfReader(str(pdf_path))
        logger.info("Extracting %d pages from %s", len(reader.pages), pdf_path.name)
        all_text = []
        for idx, page in enumerate(reader.pages):
            page_text = page.extract_text() or ""
            all_text.append(f"\n--- PAGE {idx + 1} ---\n" + page_text)
        
        full_text = "\n".join(all_text)
        with open(txt_out_path, "w", encoding="utf-8") as f:
            f.write(full_text)
        logger.info("Extracted %d characters to %s", len(full_text), txt_out_path.name)
        return True
    except Exception as exc:
        logger.error("PDF extraction failed: %s", exc)
        return False


def fetch_all_standards(force: bool = False) -> dict[str, Path]:
    """Fetch all four primary standards and extract text where needed."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    downloaded = {}

    for key, spec in STANDARDS_URLS.items():
        dest = RAW_DIR / spec["filename"]
        if not dest.exists() or force:
            success = download_file(spec["url"], dest)
            if not success:
                logger.warning("Could not download %s; checking if pre-existing copy exists", key)
        if dest.exists():
            downloaded[key] = dest

    # Extract NIST 800-77 PDF to text
    nist_pdf = RAW_DIR / "NIST.SP.800-77r1.pdf"
    nist_txt = RAW_DIR / "NIST.SP.800-77r1.txt"
    if nist_pdf.exists() and (not nist_txt.exists() or force):
        extract_nist_pdf_text(nist_pdf, nist_txt)
    if nist_txt.exists():
        downloaded["NIST_SP_800_77_R1_TXT"] = nist_txt

    # Extract NIST 800-131A PDF to text
    nist_131a_pdf = RAW_DIR / "NIST.SP.800-131Ar2.pdf"
    nist_131a_txt = RAW_DIR / "NIST.SP.800-131Ar2.txt"
    if nist_131a_pdf.exists() and (not nist_131a_txt.exists() or force):
        extract_nist_pdf_text(nist_131a_pdf, nist_131a_txt)
    if nist_131a_txt.exists():
        downloaded["NIST_SP_800_131A_R2_TXT"] = nist_131a_txt

    return downloaded


if __name__ == "__main__":
    fetch_all_standards()
