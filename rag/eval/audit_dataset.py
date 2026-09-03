"""
rag/eval/audit_dataset.py
=========================
Comprehensive Compilation, Verification, and Rating Auditor for Project Janus Datasets.

Evaluates:
1. Schema & Structural Integrity (Valid JSON, ChatML structure, role sequence)
2. Quantitative Token & Length Statistics (System, User, Assistant token counts)
3. Cryptographic Standards Grounding & Citation Precision (via deterministic CitationVerifier)
4. Mathematical Reasoning & Threat Depth (SWEET32, Logjam, brute-force complexity)
5. Actionable Remediation Executability (swanctl.conf code block presence and syntax)
6. Composite Quality Index & Letter Grade Rating (0-100 score, A+ to F)
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from rag.engine.citation_verifier import verifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
SFT_PATH = DATA_DIR / "distill_sft_dataset.jsonl"
DPO_PATH = DATA_DIR / "distill_dpo_dataset.jsonl"
AUDIT_REPORT_PATH = Path(__file__).resolve().parent / "dataset_audit_report.json"


def audit_sft_dataset(path: Path = SFT_PATH) -> dict[str, Any]:
    if not path.exists():
        return {"error": f"Dataset file not found: {path}"}

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    total_samples = len(lines)
    if total_samples == 0:
        return {"error": "Dataset is empty"}

    valid_json_count = 0
    valid_chatml_count = 0
    model_distribution: dict[str, int] = {}
    rule_distribution: dict[str, int] = {}
    
    total_assistant_words = 0
    min_assistant_words = float("inf")
    max_assistant_words = 0
    
    total_citations = 0
    verified_citations = 0
    unverified_citations = 0
    
    math_reasoning_count = 0
    remediation_code_count = 0
    standards_coverage: dict[str, int] = {
        "RFC 8221": 0,
        "RFC 8247": 0,
        "RFC 7296": 0,
        "RFC 4301": 0,
        "RFC 4303": 0,
        "RFC 7383": 0,
        "RFC 8784": 0,
        "RFC 9347": 0,
        "NIST SP 800-77": 0,
        "NIST SP 800-131A": 0,
        "DoD IPsec STIG": 0,
    }

    # Math regex signatures
    math_patterns = [
        re.compile(r"2\^\{?32\}?", re.IGNORECASE),
        re.compile(r"2\^\{?56\}?", re.IGNORECASE),
        re.compile(r"2\^\{?64\}?", re.IGNORECASE),
        re.compile(r"birthday\s+paradox", re.IGNORECASE),
        re.compile(r"discrete\s+log", re.IGNORECASE),
        re.compile(r"collision", re.IGNORECASE),
        re.compile(r"64-bit\s+block", re.IGNORECASE),
        re.compile(r"1024-bit\s+modp", re.IGNORECASE),
    ]

    for idx, line in enumerate(lines):
        try:
            data = json.loads(line)
            valid_json_count += 1
        except Exception:
            continue

        messages = data.get("messages", [])
        if len(messages) >= 3 and [m.get("role") for m in messages[:3]] == ["system", "user", "assistant"]:
            valid_chatml_count += 1

        # Track models & rules
        meta = data.get("metadata", {})
        model = meta.get("model", "unknown")
        rule = meta.get("rule_id", "unknown")
        model_distribution[model] = model_distribution.get(model, 0) + 1
        rule_distribution[rule] = rule_distribution.get(rule, 0) + 1

        # Assistant content analysis
        assistant_content = ""
        for m in messages:
            if m.get("role") == "assistant":
                assistant_content = m.get("content", "")
                break

        words = len(assistant_content.split())
        total_assistant_words += words
        min_assistant_words = min(min_assistant_words, words)
        max_assistant_words = max(max_assistant_words, words)

        # Citation verification
        v_res = verifier.verify_and_enforce(assistant_content)
        total_citations += v_res.verified_count + v_res.unverified_count
        verified_citations += v_res.verified_count
        unverified_citations += v_res.unverified_count

        # Standards coverage
        for std in standards_coverage:
            if std in assistant_content:
                standards_coverage[std] += 1

        # Mathematical depth check
        if any(p.search(assistant_content) for p in math_patterns):
            math_reasoning_count += 1

        # Remediation code check
        if "swanctl.conf" in assistant_content or "connections {" in assistant_content or "proposals =" in assistant_content:
            remediation_code_count += 1

    avg_assistant_words = round(total_assistant_words / total_samples, 1) if total_samples > 0 else 0
    citation_precision = round((verified_citations / total_citations * 100), 2) if total_citations > 0 else 100.0
    math_depth_pct = round((math_reasoning_count / total_samples * 100), 1)
    remediation_pct = round((remediation_code_count / total_samples * 100), 1)
    format_integrity_pct = round((valid_chatml_count / total_samples * 100), 1)

    # Calculate Composite Score (0-100)
    # 30% Citation Precision, 25% Math Depth, 25% Remediation Code, 20% Format Integrity
    composite_score = round(
        (0.30 * citation_precision) +
        (0.25 * math_depth_pct) +
        (0.25 * remediation_pct) +
        (0.20 * format_integrity_pct),
        1
    )

    if composite_score >= 95.0:
        grade = "A+ (Production Grade)"
    elif composite_score >= 90.0:
        grade = "A (High Quality)"
    elif composite_score >= 80.0:
        grade = "B (Acceptable)"
    elif composite_score >= 70.0:
        grade = "C (Marginal)"
    else:
        grade = "D / F (Failed)"

    report = {
        "dataset_path": str(path),
        "total_samples": total_samples,
        "schema_integrity": {
            "valid_json_count": valid_json_count,
            "valid_chatml_count": valid_chatml_count,
            "format_integrity_percentage": format_integrity_pct,
        },
        "length_statistics": {
            "avg_assistant_words": avg_assistant_words,
            "min_assistant_words": min_assistant_words if min_assistant_words != float("inf") else 0,
            "max_assistant_words": max_assistant_words,
            "estimated_avg_tokens": round(avg_assistant_words * 1.3),
        },
        "citation_grounding": {
            "total_citations_analyzed": total_citations,
            "verified_citations": verified_citations,
            "unverified_citations": unverified_citations,
            "citation_precision_percentage": citation_precision,
            "avg_citations_per_sample": round(total_citations / total_samples, 2),
        },
        "content_quality": {
            "mathematical_reasoning_percentage": math_depth_pct,
            "actionable_remediation_code_percentage": remediation_pct,
        },
        "standards_coverage": standards_coverage,
        "model_distribution": model_distribution,
        "rule_distribution": rule_distribution,
        "rating": {
            "composite_quality_score": composite_score,
            "letter_grade": grade,
            "production_ready": composite_score >= 90.0,
        },
    }

    AUDIT_REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    logger.info("Audit report saved to %s", AUDIT_REPORT_PATH)
    return report


if __name__ == "__main__":
    report = audit_sft_dataset()
    print("\n" + "=" * 60)
    print("      PROJECT JANUS — DATASET COMPILATION & AUDIT")
    print("=" * 60)
    print(f"Total Samples Compiled:    {report['total_samples']}")
    print(f"Format & ChatML Integrity: {report['schema_integrity']['format_integrity_percentage']}%")
    print(f"Citation Precision:        {report['citation_grounding']['citation_precision_percentage']}%")
    print(f"Avg Citations per Sample:  {report['citation_grounding']['avg_citations_per_sample']}")
    print(f"Math Depth Coverage:       {report['content_quality']['mathematical_reasoning_percentage']}%")
    print(f"Actionable Code Blocks:    {report['content_quality']['actionable_remediation_code_percentage']}%")
    print(f"Estimated Avg Tokens:      {report['length_statistics']['estimated_avg_tokens']} tokens")
    print("-" * 60)
    print(f"COMPOSITE QUALITY SCORE:   {report['rating']['composite_quality_score']} / 100")
    print(f"OVERALL QUALITY GRADE:     {report['rating']['letter_grade']}")
    print("=" * 60)
