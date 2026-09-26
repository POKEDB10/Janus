"""
rag/engine/explainer.py
=======================
Compliance Finding Explainer Engine with Chain-of-Thought & Compound Blast Radius.

Produces authoritative explanations for compliance findings grounded in
RFC 8221, RFC 8247, RFC 9347, RFC 7296, RFC 4301, RFC 4303, RFC 7383, RFC 8784,
NIST SP 800-77 Rev. 1, NIST SP 800-131A Rev. 2, and DoD IPsec STIG.

Enforces:
- Exact clause citations and 3-tier anti-hallucination guardrails.
- Structured Chain-of-Thought (CoT) reasoning.
- Compound blast-radius analysis across multiple simultaneous vulnerabilities.
- Dual-tier model scaling (4B / 8B).
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from rag.engine.citation_verifier import CitationItem, verifier
from rag.engine.sanitizer import clean_section_symbol, extract_structured_advisory, sanitize_prose
from rag.engine.serving import server
from rag.index.hybrid_indexer import SearchResult, retriever

logger = logging.getLogger(__name__)


@dataclass
class ExplainerResponse:
    rule_id: str
    parameter: str
    severity: str
    explanation: str
    citations: list[dict[str, Any]]
    retrieved_chunks: list[dict[str, Any]]
    groundedness_score: float
    is_fallback: bool
    latency_ms: float
    model_name: str
    summary: str = ""
    standards_cited: list[dict[str, str]] = field(default_factory=list)
    risk_note: str = ""
    remediation: str = ""
    warning: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["standardsCited"] = self.standards_cited
        d["riskNote"] = self.risk_note
        return d


@dataclass
class CompoundExplainerResponse:
    capture_id: str
    total_findings: int
    compound_narrative: str
    citations: list[dict[str, Any]]
    retrieved_chunks: list[dict[str, Any]]
    groundedness_score: float
    is_fallback: bool
    latency_ms: float
    model_name: str
    summary: str = ""
    standards_cited: list[dict[str, str]] = field(default_factory=list)
    risk_note: str = ""
    remediation: str = ""
    warning: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["standardsCited"] = self.standards_cited
        d["riskNote"] = self.risk_note
        return d


class ComplianceExplainer:
    """Explains compliance findings and synthesizes compound blast radiuses."""

    def explain(
        self,
        finding: dict[str, Any],
        top_k: int = 3,
        model_size: str = "4b",
    ) -> ExplainerResponse:
        """Generate cited Chain-of-Thought explanation for an IPsec compliance finding."""
        rule_id = finding.get("rule_id", "UNKNOWN_RULE")
        parameter = finding.get("parameter", "Cryptographic Parameter")
        severity = finding.get("severity", "MEDIUM")
        desc = finding.get("description", "")
        vuln = finding.get("vulnerability_tag", "")
        category = finding.get("category")

        # 1. Targeted Hybrid Search Query
        query = f"{rule_id} {parameter} {desc} {vuln}".strip()
        search_results: list[SearchResult] = retriever.search(
            query=query,
            top_k=top_k,
            category=category,
        )

        retrieved_dict_list = []
        for res in search_results:
            sec_clean = (res.section or "").replace("§", "").strip()
            if sec_clean and not sec_clean.lower().startswith(("section", "table", "appendix", "clause")):
                sec_clean = f"Section {sec_clean}"
            retrieved_dict_list.append({
                "chunk_id": res.chunk_id,
                "document": res.document,
                "section": sec_clean,
                "title": clean_section_symbol(res.title or ""),
                "category": res.category,
                "text": (res.text or "").replace("§", "Section "),
                "score": res.score,
            })

        # 2. Build Grounded Prompt with Strict Structured Output Contract
        context_blocks = []
        for idx, res in enumerate(search_results, start=1):
            context_blocks.append(
                f"--- SOURCE {idx}: {res.document} {res.section} {res.title} ---\n{res.text[:800]}\n"
            )
        context_str = "\n".join(context_blocks)

        system_prompt = (
            "You are the Janus Compliance Explainer, an authoritative IPsec and cryptographic standards auditor.\n"
            "Respond ONLY with a valid JSON object matching this schema:\n"
            "{\n"
            '  "summary": "1-2 plain sentences summarizing the finding and compliance status.",\n'
            '  "standardsCited": [\n'
            '    {"id": "RFC 8221 Section 5", "note": "Clause requirement or title"}\n'
            "  ],\n"
            '  "riskNote": "Plain prose explaining what this configuration means for system security, without section headers.",\n'
            '  "remediation": "Plain prose explaining recommended configuration update, or empty string if compliant."\n'
            "}\n\n"
            "Strict Constraints:\n"
            "1. Plain prose only. NEVER use LaTeX or math notation ($...$, ^{}, _{}, \\frac). Write '2^64' or '2 to the 64th power', never dollar-sign math.\n"
            "2. No bracket citations like [RFC 8221 Section 5]. Name the standard naturally inline in prose (e.g. 'as required by RFC 8221 Section 5') or place in standardsCited. Do NOT use the section symbol (§); write 'Section' instead.\n"
            "3. No section headers in ALL CAPS, and no emoji or icon-prefixed labels.\n"
            "4. No internal system or ML terminology in output: never mention 'chain-of-thought', 'CoT', 'grounded', 'latency', model names, or how the answer was produced.\n"
            "5. No inline badge or pill markup. Output plain text.\n"
            "6. Return ONLY the raw JSON object, without markdown code fences."
        )

        user_prompt = (
            f"Compliance Finding:\n"
            f"- Rule ID: {rule_id}\n"
            f"- Parameter: {parameter}\n"
            f"- Severity: {severity}\n"
            f"- Description: {desc}\n"
            f"- Vulnerability Tag: {vuln}\n\n"
            f"Authoritative Standards Context:\n{context_str}\n\n"
            f"Provide a structured compliance assessment in JSON format explaining what this configuration means and cite the governing RFC/NIST standard."
        )

        # 3. Call Serving Connector (Local LLM or Resilient Grounded Fallback)
        gen_result = server.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            finding_data=finding,
            retrieved_chunks=retrieved_dict_list,
            model_size=model_size,
        )

        # 4. Extract structured advisory and apply regex sanitizer pass as backstop
        structured = extract_structured_advisory(gen_result.content, finding)
        summary = structured["summary"]
        standards_cited = structured["standardsCited"]
        risk_note = structured["riskNote"]
        remediation = structured["remediation"]

        # Clean flowing explanation (2 sections max, sentence case, no banners)
        explanation_blocks = [summary]
        if risk_note:
            explanation_blocks.append(f"### What this means\n{risk_note}")
        if remediation:
            explanation_blocks.append(f"### Remediation\n{remediation}")
        clean_explanation = "\n\n".join(explanation_blocks)

        # 5. Citation Verification & 3-Tier Anti-Hallucination Gate
        fallback_chunk = retrieved_dict_list[0] if retrieved_dict_list else None
        v_res = verifier.verify_and_enforce(
            text=clean_explanation,
            retrieved_fallback_chunk=fallback_chunk,
            structured_citations=standards_cited,
        )

        # Synchronize verified citations into standards_cited if empty
        if not standards_cited and v_res.citations:
            standards_cited = [
                {"id": clean_section_symbol(f"{c.document} {c.section}".strip()), "note": clean_section_symbol(c.clause_title or "")}
                for c in v_res.citations
                if c.verified
            ]
        else:
            standards_cited = [
                {"id": clean_section_symbol(s.get("id", "")), "note": clean_section_symbol(s.get("note", ""))}
                for s in standards_cited
            ]

        cleaned_citations = []
        for c in v_res.citations:
            cd = asdict(c)
            cd["raw_citation"] = clean_section_symbol(cd.get("raw_citation", ""))
            cd["clause_title"] = clean_section_symbol(cd.get("clause_title", ""))
            s_val = str(cd.get("section", "")).replace("§", "").strip()
            if s_val and not s_val.lower().startswith(("section", "table", "appendix", "clause")):
                s_val = f"Section {s_val}"
            cd["section"] = s_val
            cleaned_citations.append(cd)

        groundedness_score = 1.0 if v_res.is_grounded else 0.5
        if v_res.total_citations == 0:
            groundedness_score = 0.8

        return ExplainerResponse(
            rule_id=rule_id,
            parameter=parameter,
            severity=severity,
            explanation=v_res.sanitized_text,
            summary=summary,
            standards_cited=standards_cited,
            risk_note=risk_note,
            remediation=remediation,
            citations=cleaned_citations,
            retrieved_chunks=retrieved_dict_list,
            groundedness_score=groundedness_score,
            is_fallback=gen_result.is_fallback,
            latency_ms=round(gen_result.latency_ms, 2),
            model_name=gen_result.model_name,
            warning=v_res.warning,
        )

    def explain_compound(
        self,
        capture_id: str,
        findings: list[dict[str, Any]],
        top_k: int = 5,
        model_size: str = "4b",
    ) -> CompoundExplainerResponse:
        """Synthesize compound blast radius assessment across multiple findings."""
        if not findings:
            findings = [
                {
                    "rule_id": "RFC8221-BASELINE",
                    "parameter": "IPsec Baseline",
                    "severity": "LOW",
                    "description": "Standard configuration with modern AEAD parameters.",
                }
            ]

        # 1. Multi-Finding Aggregate Query
        query_parts = []
        for f in findings:
            query_parts.append(f"{f.get('rule_id', '')} {f.get('parameter', '')} {f.get('description', '')}")
        agg_query = " ".join(query_parts)[:300]

        search_results: list[SearchResult] = retriever.search(
            query=agg_query,
            top_k=top_k,
        )

        retrieved_dict_list = []
        for res in search_results:
            sec_clean = (res.section or "").replace("§", "").strip()
            if sec_clean and not sec_clean.lower().startswith(("section", "table", "appendix", "clause")):
                sec_clean = f"Section {sec_clean}"
            retrieved_dict_list.append({
                "chunk_id": res.chunk_id,
                "document": res.document,
                "section": sec_clean,
                "title": clean_section_symbol(res.title or ""),
                "category": res.category,
                "text": (res.text or "").replace("§", "Section "),
                "score": res.score,
            })

        context_blocks = []
        for idx, res in enumerate(search_results, start=1):
            context_blocks.append(f"--- SOURCE {idx}: {res.document} {res.section} {res.title} ---\n{res.text[:600]}\n")
        context_str = "\n".join(context_blocks)

        system_prompt = (
            "You are the Janus Compliance Explainer. Perform a compound threat evaluation "
            "for an IPsec capture session exhibiting multiple concurrent vulnerabilities. "
            "Respond ONLY with a valid JSON object matching the structured schema: summary, standardsCited, riskNote, remediation.\n"
            "Strict Constraints: Plain prose only. No LaTeX math notation ($...$). No bracket citations. No ALL CAPS headers. No ML jargon. "
            "Do not use the section symbol (§); write 'Section' instead."
        )

        findings_lines = "\n".join([f"- [{f.get('severity')}] {f.get('rule_id')}: {f.get('parameter')} ({f.get('description')})" for f in findings])
        user_prompt = (
            f"Capture Session: {capture_id}\n"
            f"Concurrent Findings ({len(findings)} total):\n{findings_lines}\n\n"
            f"Authoritative Context:\n{context_str}\n\n"
            f"Explain what this combined configuration means and provide a unified remediation strategy in JSON format."
        )

        gen_result = server.generate_compound(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            findings=findings,
            retrieved_chunks=retrieved_dict_list,
            model_size=model_size,
        )

        # Extract structured advisory & backstop regex sanitization
        structured = extract_structured_advisory(gen_result.content)
        summary = structured["summary"]
        standards_cited = structured["standardsCited"]
        risk_note = structured["riskNote"]
        remediation = structured["remediation"]

        compound_blocks = [summary]
        if risk_note:
            compound_blocks.append(f"### What this means\n{risk_note}")
        if remediation:
            compound_blocks.append(f"### Remediation\n{remediation}")
        clean_compound = "\n\n".join(compound_blocks)

        fallback_chunk = retrieved_dict_list[0] if retrieved_dict_list else None
        v_res = verifier.verify_and_enforce(
            text=clean_compound,
            retrieved_fallback_chunk=fallback_chunk,
            structured_citations=standards_cited,
        )

        if not standards_cited and v_res.citations:
            standards_cited = [
                {"id": clean_section_symbol(f"{c.document} {c.section}".strip()), "note": clean_section_symbol(c.clause_title or "")}
                for c in v_res.citations
                if c.verified
            ]
        else:
            standards_cited = [
                {"id": clean_section_symbol(s.get("id", "")), "note": clean_section_symbol(s.get("note", ""))}
                for s in standards_cited
            ]

        cleaned_citations = []
        for c in v_res.citations:
            cd = asdict(c)
            cd["raw_citation"] = clean_section_symbol(cd.get("raw_citation", ""))
            cd["clause_title"] = clean_section_symbol(cd.get("clause_title", ""))
            s_val = str(cd.get("section", "")).replace("§", "").strip()
            if s_val and not s_val.lower().startswith(("section", "table", "appendix", "clause")):
                s_val = f"Section {s_val}"
            cd["section"] = s_val
            cleaned_citations.append(cd)

        groundedness_score = 1.0 if v_res.is_grounded else 0.5
        if v_res.total_citations == 0:
            groundedness_score = 0.8

        return CompoundExplainerResponse(
            capture_id=capture_id,
            total_findings=len(findings),
            compound_narrative=v_res.sanitized_text,
            summary=summary,
            standards_cited=standards_cited,
            risk_note=risk_note,
            remediation=remediation,
            citations=cleaned_citations,
            retrieved_chunks=retrieved_dict_list,
            groundedness_score=groundedness_score,
            is_fallback=gen_result.is_fallback,
            latency_ms=round(gen_result.latency_ms, 2),
            model_name=gen_result.model_name,
            warning=v_res.warning,
        )


# Global singleton explainer
explainer = ComplianceExplainer()
