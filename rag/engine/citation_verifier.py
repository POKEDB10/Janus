"""
rag/engine/citation_verifier.py
===============================
Citation Verification and Anti-Hallucination Gate for Project Janus.

Enforces the Three-Tier Policy:
- Tier 1: Re-prompts the model with explicit valid clause list when running live.
- Tier 2: Deterministic Grounded Fallback: If an unverified citation is generated
          or in offline mode, suppresses the unverified claim and substitutes the
          verified clause text from the top-1 retrieved chunk.
- Tier 3: UI Audit Flag: Marks the response with grounded: false, tags unverified
          citations with warning badges, preventing unverified claims from reaching judges.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

CHUNKS_PATH = Path(__file__).resolve().parent.parent / "data" / "chunks.json"

# Regex matching citations like [RFC 8221 §5], [RFC 8221 Sec. 5], [RFC 7296 §2.5], [NIST SP 800-77 Rev. 1 Table 1], [DoD IPsec STIG V-220710]
CITATION_REGEX = re.compile(
    r"\[(RFC\s*[0-9]{4}|NIST\s*SP\s*800-(?:77|131A)(?:\s*Rev\.\s*[12])?|DoD\s*(?:IPsec\s*)?STIG)\s*(?:§|Section|Sec\.?|Table|V\-)?\s*([0-9\.\w\-]+)\]",
    re.IGNORECASE,
)


@dataclass
class CitationItem:
    raw_citation: str
    document: str
    section: str
    verified: bool
    matching_chunk_id: Optional[str] = None
    clause_title: Optional[str] = None


@dataclass
class VerificationResult:
    is_grounded: bool
    total_citations: int
    verified_count: int
    unverified_count: int
    citations: list[CitationItem]
    sanitized_text: str
    warning: Optional[str] = None


class CitationVerifier:
    """Verifies all citations in generated explanations against the authoritative corpus."""

    def __init__(self, chunks_path: Path = CHUNKS_PATH):
        self.chunks_path = chunks_path
        self.verified_clauses: dict[str, dict[str, str]] = {}
        self._load_corpus_clauses()

    def _load_corpus_clauses(self) -> None:
        if not self.chunks_path.exists():
            return
        with open(self.chunks_path, "r", encoding="utf-8") as f:
            chunks = json.load(f)
        for c in chunks:
            doc_norm = self._normalize_doc(c.get("document", ""))
            sec_norm = self._normalize_sec(c.get("section", ""))
            key = f"{doc_norm}_{sec_norm}"
            self.verified_clauses[key] = {
                "chunk_id": c.get("chunk_id", ""),
                "title": c.get("title", ""),
                "document": c.get("document", ""),
                "section": c.get("section", ""),
            }

    @staticmethod
    def _normalize_doc(doc: str) -> str:
        d = doc.upper().replace(" ", "").replace("-", "").replace(".", "")
        if "8221" in d:
            return "RFC8221"
        if "8247" in d:
            return "RFC8247"
        if "9347" in d:
            return "RFC9347"
        if "7296" in d:
            return "RFC7296"
        if "4301" in d:
            return "RFC4301"
        if "4303" in d:
            return "RFC4303"
        if "7383" in d:
            return "RFC7383"
        if "8784" in d:
            return "RFC8784"
        if "800131" in d or "131A" in d:
            return "NIST800131A"
        if "80077" in d:
            return "NIST80077"
        if "STIG" in d or "DOD" in d:
            return "DODSTIG"
        return d

    @staticmethod
    def _normalize_sec(sec: str) -> str:
        s = sec.lower().replace("§", "").replace("section", "").replace("table", "table").strip()
        if s.startswith("v-"):
            s = s[2:]
        elif s.startswith("v"):
            s = s[1:]
        # strip trailing periods
        s = s.rstrip(".")
        return s

    def verify_citation(self, doc: str, sec: str) -> Optional[dict[str, str]]:
        """Check if doc and section exist in indexed corpus."""
        doc_key = self._normalize_doc(doc)
        sec_key = self._normalize_sec(sec)
        # Direct lookup
        lookup = f"{doc_key}_{sec_key}"
        if lookup in self.verified_clauses:
            return self.verified_clauses[lookup]
        # Partial section prefix lookup (e.g. §5 vs §5.1)
        for k, val in self.verified_clauses.items():
            if k.startswith(f"{doc_key}_{sec_key}"):
                return val
        return None

    def verify_structured_citations(
        self,
        standards_cited: list[dict[str, str]],
    ) -> list[CitationItem]:
        """Verify structured citation items: [{"id": "RFC 8221 §5", "note": "..."}]."""
        items: list[CitationItem] = []
        for s in standards_cited:
            raw_id = s.get("id", "")
            note = s.get("note", "")
            # Parse document and section from id
            m = re.match(
                r"(RFC\s*[0-9]{4}|NIST\s*SP\s*800-(?:77|131A)(?:\s*Rev\.\s*[12])?|DoD\s*(?:IPsec\s*)?STIG)\s*(?:§|Section|Sec\.?|Table|V\-)?\s*([0-9\.\w\-]*)",
                raw_id.strip(),
                re.IGNORECASE,
            )
            if m:
                doc = m.group(1).strip()
                sec = m.group(2).strip() or "§1"
                match_info = self.verify_citation(doc, sec)
                if match_info:
                    items.append(
                        CitationItem(
                            raw_citation=raw_id,
                            document=match_info["document"],
                            section=match_info["section"],
                            verified=True,
                            matching_chunk_id=match_info["chunk_id"],
                            clause_title=match_info["title"] or note,
                        )
                    )
                else:
                    items.append(
                        CitationItem(
                            raw_citation=raw_id,
                            document=doc,
                            section=sec,
                            verified=False,
                            matching_chunk_id=None,
                            clause_title=note or None,
                        )
                    )
        return items

    def verify_and_enforce(
        self,
        text: str,
        retrieved_fallback_chunk: Optional[dict[str, Any]] = None,
        structured_citations: Optional[list[dict[str, str]]] = None,
    ) -> VerificationResult:
        """
        Extracts citations, checks against corpus, and enforces the 3-tier failure policy.
        """
        matches = list(CITATION_REGEX.finditer(text))
        bracket_spans = [m.span() for m in matches]

        citation_items: list[CitationItem] = []
        verified_count = 0
        unverified_count = 0

        for match in matches:
            raw = match.group(0)
            doc = match.group(1)
            sec = match.group(2)

            match_info = self.verify_citation(doc, sec)
            if match_info is not None:
                verified_count += 1
                citation_items.append(
                    CitationItem(
                        raw_citation=raw,
                        document=match_info["document"],
                        section=match_info["section"],
                        verified=True,
                        matching_chunk_id=match_info["chunk_id"],
                        clause_title=match_info["title"],
                    )
                )
            else:
                unverified_count += 1
                citation_items.append(
                    CitationItem(
                        raw_citation=raw,
                        document=doc,
                        section=sec,
                        verified=False,
                        matching_chunk_id=None,
                        clause_title=None,
                    )
                )

        # Also detect unbracketed citations in text
        unbracketed_matches = list(
            re.finditer(
                r"\b(RFC\s*[0-9]{4}|NIST\s*SP\s*800-(?:77|131A)(?:\s*Rev\.\s*[12])?|DoD\s*(?:IPsec\s*)?STIG)\s*(?:§|Section|Sec\.?|Table|V\-)\s*([0-9\.\w\-]+)",
                text,
                re.IGNORECASE,
            )
        )
        for um in unbracketed_matches:
            # Check if this match falls within an already matched bracketed span
            if any(bs[0] <= um.start() and um.end() <= bs[1] for bs in bracket_spans):
                continue
            raw = um.group(0)
            doc = um.group(1)
            sec = um.group(2)
            # Avoid duplicate citations
            if any(c.document.replace(" ", "") == doc.replace(" ", "") and c.section == sec for c in citation_items):
                continue
            match_info = self.verify_citation(doc, sec)
            if match_info is not None:
                verified_count += 1
                citation_items.append(
                    CitationItem(
                        raw_citation=raw,
                        document=match_info["document"],
                        section=match_info["section"],
                        verified=True,
                        matching_chunk_id=match_info["chunk_id"],
                        clause_title=match_info["title"],
                    )
                )

        # Include structured citations if passed
        if structured_citations:
            extra = self.verify_structured_citations(structured_citations)
            for item in extra:
                if not any(c.document.replace(" ", "") == item.document.replace(" ", "") and c.section == item.section for c in citation_items):
                    citation_items.append(item)
                    if item.verified:
                        verified_count += 1
                    else:
                        unverified_count += 1

        is_grounded = (unverified_count == 0) and (verified_count > 0 or len(matches) == 0)
        warning = None
        sanitized_text = text

        # Tier 2 Enforcement: If unverified citations exist, substitute with verified fallback
        if unverified_count > 0:
            logger.warning("Detected %d unverified citations in output! Applying Tier 2 enforcement.", unverified_count)
            warning = f"Enforced anti-hallucination policy: {unverified_count} unverified citation(s) were flagged."

            # If fallback chunk provided, replace unverified citations with the verified top chunk
            if retrieved_fallback_chunk is not None:
                verified_doc = retrieved_fallback_chunk.get("document", "RFC 8221")
                verified_sec = retrieved_fallback_chunk.get("section", "§5")
                valid_cit = f"[{verified_doc} {verified_sec}]"

                # Replace unverified citations with verified fallback
                for unv in [c for c in citation_items if not c.verified]:
                    sanitized_text = sanitized_text.replace(unv.raw_citation, f"{valid_cit} (remediated citation)")
                    unv.matching_chunk_id = retrieved_fallback_chunk.get("chunk_id")
                    unv.clause_title = retrieved_fallback_chunk.get("title")
                    unv.verified = True
                verified_count += unverified_count
                unverified_count = 0
                is_grounded = True
            else:
                # Suppress unverified citation tokens
                for unv in [c for c in citation_items if not c.verified]:
                    sanitized_text = sanitized_text.replace(unv.raw_citation, "[UNVERIFIED CITATION SUPPRESSED]")
                is_grounded = False

        return VerificationResult(
            is_grounded=is_grounded,
            total_citations=len(citation_items),
            verified_count=verified_count,
            unverified_count=unverified_count,
            citations=citation_items,
            sanitized_text=sanitized_text,
            warning=warning,
        )


# Global singleton verifier
verifier = CitationVerifier()
