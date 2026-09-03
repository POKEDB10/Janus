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
from dataclasses import asdict, dataclass
from typing import Any, Optional

from rag.engine.citation_verifier import CitationItem, verifier
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
    warning: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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
    warning: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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

        retrieved_dict_list = [
            {
                "chunk_id": res.chunk_id,
                "document": res.document,
                "section": res.section,
                "title": res.title,
                "category": res.category,
                "text": res.text,
                "score": res.score,
            }
            for res in search_results
        ]

        # 2. Build Grounded Prompt with Chain-of-Thought directives
        context_blocks = []
        for idx, res in enumerate(search_results, start=1):
            cit = f"[{res.document} {res.section}]"
            context_blocks.append(
                f"--- SOURCE {idx}: {cit} {res.title} ---\n{res.text[:800]}\n"
            )
        context_str = "\n".join(context_blocks)

        system_prompt = (
            "You are the Janus Compliance Explainer, a specialized IPsec and cryptography standards domain auditor. "
            "Your task is to explain WHY the given finding is assigned its severity level by citing the provided "
            "authoritative standards clauses (RFC 8221, RFC 8247, RFC 9347, RFC 7296, NIST SP 800-77, NIST SP 800-131A, DoD STIG).\n"
            "Rules:\n"
            "1. You MUST explicitly cite the governing clause in brackets (e.g. [RFC 8221 §5], [RFC 8247 §2.4], [NIST SP 800-77 Rev. 1 Table 1]).\n"
            "2. Structure your reasoning with Chain-of-Thought: Cryptanalytic Threat & Mathematical Analysis, "
            "Primary Standards Grounding, System Impact & Blast Radius, and Verified Actionable Remediation.\n"
            "3. Only make claims directly grounded in the provided sources. Do not invent RFC numbers or clauses.\n"
            "4. Conclude with concrete strongSwan swanctl.conf remediation."
        )

        user_prompt = (
            f"Compliance Finding:\n"
            f"- Rule ID: {rule_id}\n"
            f"- Parameter: {parameter}\n"
            f"- Severity: {severity}\n"
            f"- Description: {desc}\n"
            f"- Vulnerability Tag: {vuln}\n\n"
            f"Authoritative Standards Context:\n{context_str}\n\n"
            f"Provide a structured Chain-of-Thought analysis explaining why this configuration is classified as {severity} and cite the exact clause."
        )

        # 3. Call Serving Connector (Local LLM or Resilient Grounded Fallback)
        gen_result = server.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            finding_data=finding,
            retrieved_chunks=retrieved_dict_list,
            model_size=model_size,
        )

        # 4. Citation Verification & 3-Tier Anti-Hallucination Gate
        fallback_chunk = retrieved_dict_list[0] if retrieved_dict_list else None
        v_res = verifier.verify_and_enforce(
            text=gen_result.content,
            retrieved_fallback_chunk=fallback_chunk,
        )

        groundedness_score = 1.0 if v_res.is_grounded else 0.5
        if v_res.total_citations == 0:
            groundedness_score = 0.8

        return ExplainerResponse(
            rule_id=rule_id,
            parameter=parameter,
            severity=severity,
            explanation=v_res.sanitized_text,
            citations=[asdict(c) for c in v_res.citations],
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

        retrieved_dict_list = [
            {
                "chunk_id": res.chunk_id,
                "document": res.document,
                "section": res.section,
                "title": res.title,
                "category": res.category,
                "text": res.text,
                "score": res.score,
            }
            for res in search_results
        ]

        context_blocks = []
        for idx, res in enumerate(search_results, start=1):
            cit = f"[{res.document} {res.section}]"
            context_blocks.append(f"--- SOURCE {idx}: {cit} {res.title} ---\n{res.text[:600]}\n")
        context_str = "\n".join(context_blocks)

        system_prompt = (
            "You are the Janus Compliance Explainer. Perform a compound threat and blast-radius evaluation "
            "for an IPsec capture session exhibiting multiple concurrent vulnerabilities. "
            "Analyze how the vulnerabilities interact and multiply the attack surface. Always cite primary standards."
        )

        findings_lines = "\n".join([f"- [{f.get('severity')}] {f.get('rule_id')}: {f.get('parameter')} ({f.get('description')})" for f in findings])
        user_prompt = (
            f"Capture Session: {capture_id}\n"
            f"Concurrent Findings ({len(findings)} total):\n{findings_lines}\n\n"
            f"Authoritative Context:\n{context_str}\n\n"
            f"Explain the compound blast radius and unified remediation strategy."
        )

        gen_result = server.generate_compound(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            findings=findings,
            retrieved_chunks=retrieved_dict_list,
            model_size=model_size,
        )

        fallback_chunk = retrieved_dict_list[0] if retrieved_dict_list else None
        v_res = verifier.verify_and_enforce(
            text=gen_result.content,
            retrieved_fallback_chunk=fallback_chunk,
        )

        groundedness_score = 1.0 if v_res.is_grounded else 0.5
        if v_res.total_citations == 0:
            groundedness_score = 0.8

        return CompoundExplainerResponse(
            capture_id=capture_id,
            total_findings=len(findings),
            compound_narrative=v_res.sanitized_text,
            citations=[asdict(c) for c in v_res.citations],
            retrieved_chunks=retrieved_dict_list,
            groundedness_score=groundedness_score,
            is_fallback=gen_result.is_fallback,
            latency_ms=round(gen_result.latency_ms, 2),
            model_name=gen_result.model_name,
            warning=v_res.warning,
        )


# Global singleton explainer
explainer = ComplianceExplainer()
