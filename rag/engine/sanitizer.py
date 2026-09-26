"""
rag/engine/sanitizer.py
=======================
Output sanitization and structured advisory extraction pass.

Enforces output contract constraints:
1. Plain prose only. Strips/converts LaTeX or math notation ($...$, ^{}, _{}, \frac).
2. Strips bracket-style citations like [RFC 8221 §5] into inline natural citations (RFC 8221 §5).
3. Eliminates ALL-CAPS section headers and icon banners.
4. Reframes incident-response language ('System Impact & Blast Radius') to neutral 'What this means'.
5. Strips internal system/ML terminology ('chain-of-thought', '(CoT)', 'grounded %', 'latency').
6. Strips inline badge/pill markup.
7. Guarantees structured output: summary, standardsCited, riskNote, remediation.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Human-readable labels for raw IPsec parameter keys.
# Used by narrative_writer.py and anywhere a raw key gets interpolated into prose.
# ---------------------------------------------------------------------------
PARAMETER_HUMAN_LABELS: dict[str, str] = {
    "esp_encryption": "ESP encryption",
    "esp_auth": "ESP integrity",
    "dh_group": "Diffie-Hellman group",
    "pfs_enabled": "Perfect Forward Secrecy",
    "auth_method": "IKE authentication method",
    "sa_lifetime": "SA lifetime",
    "ike_version": "IKE version",
    "ike_encryption": "IKE encryption",
    "ike_auth": "IKE integrity",
    "ike_prf": "IKE pseudorandom function",
    "ike_dh_group": "IKE Diffie-Hellman group",
}


def humanize_param_key(key: str) -> str:
    """Map a raw snake_case parameter key to a human-readable label."""
    if key in PARAMETER_HUMAN_LABELS:
        return PARAMETER_HUMAN_LABELS[key]
    # Fallback: replace underscores with spaces, title-case
    return key.replace("_", " ").title()


# Regex matching LaTeX math notation ($...$ or \$...\$)
LATEX_MATH_REGEX = re.compile(r"\\\$([^\$]+?)\\\$|\$([^\$]+?)\$")

# Regex matching bracket-style standards citations
BRACKET_CITATION_REGEX = re.compile(
    r"\[(RFC\s*[0-9]{4}[^\]]*|NIST\s*SP\s*800-[^\]]*|DoD\s*(?:IPsec\s*)?STIG[^]]*)\]",
    re.IGNORECASE,
)

# Internal ML / System terminology
ML_TERMS_REGEX = re.compile(
    r"\s*[\(\[]?(?:Chain-of-Thought|chain-of-thought|CoT)[\)\]]?"
    r"|\bgroundedness\s*score\s*:\s*[0-9\.]+%?"
    r"|\bgrounded\s*:\s*[0-9\.]+%?"
    r"|\blatency\s*:\s*[0-9\.]+\s*ms"
    r"|\bQwen3-[0-9A-Z\-]+",
    re.IGNORECASE,
)

# LaTeX explicit-brace subscript: C_{i-1}, A_{n}, etc.
# Deliberately scoped to single lowercase/uppercase char + {…} — avoids SCREAMING_SNAKE identifiers.
LATEX_BRACE_SUB_REGEX = re.compile(r"([A-Za-z])_\{([^}]+)\}")
# LaTeX single-token subscript: C_i, P_n — only single alpha/digit token, NOT multi-token like GCM_16
LATEX_TOKEN_SUB_REGEX = re.compile(r"([a-z])_([0-9])(?![A-Za-z_])")


def _convert_math_fragment(fragment: str) -> str:
    """Convert common LaTeX math fragments to plain, readable text."""
    s = fragment.strip()
    # Powers: 2^{64} -> 2^64, 2^{32} -> 2^32, 2^{56} -> 2^56
    s = re.sub(r"([0-9a-zA-Z])\^\{([^}]+)\}", r"\1^\2", s)
    s = re.sub(r"([0-9a-zA-Z])\^([0-9a-zA-Z]+)", r"\1^\2", s)
    # Subscripts with braces only: C_{i-1} -> C[i-1]
    s = LATEX_BRACE_SUB_REGEX.sub(r"\1[\2]", s)
    # Common LaTeX math commands
    s = re.sub(r"\\frac\{([^}]+)\}\{([^}]+)\}", r"\1/\2", s)
    s = s.replace(r"\approx", "~")
    s = s.replace(r"\times", "x")
    s = s.replace(r"\le", "<=")
    s = s.replace(r"\ge", ">=")
    s = s.replace(r"\cdot", "*")
    s = s.replace(r"\\", "")
    return s.strip()


def clean_section_symbol(text: str) -> str:
    """
    Remove or reformat the section sign (§) from technical prose and standards citations:
    - 'Section §4' -> 'Section 4'
    - '§4.1' -> 'Section 4.1'
    - 'RFC 8221 §5' -> 'RFC 8221 Section 5'
    - Lone '§' -> removed
    """
    if not text or "§" not in text:
        return text
    # 'Section § 4' or 'Sec. § 4' -> 'Section 4'
    s = re.sub(r"(?i)\b(?:section|sec\.?)\s*§\s*", "Section ", text)
    # '§ 4' or '§4' -> 'Section 4'
    s = re.sub(r"§\s*([0-9])", r"Section \1", s)
    # Any other remaining §
    s = s.replace("§", "")
    # Clean redundant 'Section Section'
    s = re.sub(r"(?i)\bsection\s+section\b", "Section", s)
    return s.strip()


def sanitize_prose(text: str) -> str:
    """
    Backstop regex sanitizer pass enforcing the strict output contract:
    - Strips math notation ($...$, ^{}, _{}, \\frac).
    - Strips bracket-style citations ([RFC 8221 §5] -> RFC 8221 Section 5).
    - Removes section symbols (§ -> Section).
    - Reframes 'System Impact & Blast Radius' to 'What this means'.
    - Converts ALL-CAPS headers/lines over 3 words to sentence case.
    - Removes internal ML / system jargon.

    IMPORTANT: Does NOT mangle SCREAMING_SNAKE_CASE identifiers (e.g. ENCR_AES_GCM_16,
    AUTH_NONE) — the old LaTeX subscript regex was too broad and corrupted cipher names.
    Only genuine LaTeX subscript patterns with braces (C_{i-1}) or single-digit subscripts
    (C_1) are converted.
    """
    if not text:
        return ""

    s = text

    # 1. LaTeX math notation stripping: $...$ -> clean plain prose
    def math_repl(m: re.Match) -> str:
        content = m.group(1) or m.group(2) or ""
        return _convert_math_fragment(content)

    s = LATEX_MATH_REGEX.sub(math_repl, s)
    # Catch any lingering 2^{64} not enclosed in dollars
    s = re.sub(r"([0-9a-zA-Z])\^\{([^}]+)\}", r"\1^\2", s)
    # Catch LaTeX brace subscripts only: C_{i-1} -> C[i-1]
    # NOTE: deliberately NOT touching A_B style (SCREAMING_SNAKE) — only brace form.
    s = LATEX_BRACE_SUB_REGEX.sub(r"\1[\2]", s)
    # Single-digit subscripts: e.g. C_1, P_2 — only lowercase alpha + single digit
    s = LATEX_TOKEN_SUB_REGEX.sub(r"\1[\2]", s)

    # 2. Bracket citation conversion: [RFC 8221 §5] -> RFC 8221 Section 5
    s = BRACKET_CITATION_REGEX.sub(r"\1", s)
    # Also strip general brackets if they enclose standards-like codes (e.g. [RFC8221-ENCR_3DES] or [RFC 8247])
    # but avoid stripping markdown links [text](url)
    s = re.sub(r"\[([A-Z0-9][A-Za-z0-9\s§\.\-\/]{1,35})\](?!\()", r"\1", s)

    # Clean any section symbols (§)
    s = clean_section_symbol(s)

    # 3. Reframe incident response language
    s = re.sub(
        r"###?\s*System\s+Impact\s*(?:&|and)?\s*Blast\s*Radius",
        "### What this means",
        s,
        flags=re.IGNORECASE,
    )
    s = re.sub(
        r"\bSystem\s+Impact\s*(?:&|and)?\s*Blast\s*Radius\b",
        "What this means",
        s,
        flags=re.IGNORECASE,
    )

    # 4. Standardize headers and replace 4-section template headers with sentence case
    s = re.sub(
        r"###?\s*Cryptanalytic\s+Threat\s*(?:&|and)?\s*Mathematical\s*(?:Grounding|Analysis)",
        "### Summary",
        s,
        flags=re.IGNORECASE,
    )
    s = re.sub(
        r"###?\s*Primary\s+Standards\s+Grounding",
        "### Governing standards",
        s,
        flags=re.IGNORECASE,
    )
    s = re.sub(
        r"###?\s*Verified\s+Actionable\s+Remediation",
        "### Remediation",
        s,
        flags=re.IGNORECASE,
    )

    # 5. ALL-CAPS lines over 3 words -> convert to sentence case
    lines = s.split("\n")
    cleaned_lines = []
    for line in lines:
        stripped = line.strip()
        header_prefix = ""
        content = stripped
        if stripped.startswith("### "):
            header_prefix = "### "
            content = stripped[4:]
        elif stripped.startswith("## "):
            header_prefix = "## "
            content = stripped[3:]
        elif stripped.startswith("# "):
            header_prefix = "# "
            content = stripped[2:]

        words = [w for w in content.split() if any(c.isalpha() for c in w)]
        if len(words) >= 4 and all(w == w.upper() for w in words):
            # Convert 4+ ALL-CAPS words to sentence case
            lower = content.lower()
            content = lower.capitalize()
            cleaned_lines.append(f"{header_prefix}{content}")
        else:
            cleaned_lines.append(line)

    s = "\n".join(cleaned_lines)

    # 6. Remove internal system/ML terminology
    s = ML_TERMS_REGEX.sub("", s)

    # Normalize double spaces
    s = re.sub(r" +", " ", s)
    return s.strip()


def extract_structured_advisory(
    raw_output: str,
    finding_data: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Parse LLM or fallback output into strict structured fields:
    {
      "summary": str,
      "standardsCited": list[{"id": str, "note": str}],
      "riskNote": str,
      "remediation": str
    }
    """
    finding_data = finding_data or {}
    param = finding_data.get("parameter", "Cryptographic parameter")
    severity = finding_data.get("severity", "MEDIUM")
    rule_id = finding_data.get("rule_id", "RULE")
    desc = finding_data.get("description", "")
    recom = finding_data.get("recommendation") or finding_data.get("remediation", "")

    # Try JSON parsing
    cleaned_raw = raw_output.strip()
    if cleaned_raw.startswith("```"):
        cleaned_raw = re.sub(r"^```(?:json)?\s*", "", cleaned_raw)
        cleaned_raw = re.sub(r"\s*```$", "", cleaned_raw)
        cleaned_raw = cleaned_raw.strip()

    parsed_json: Optional[dict[str, Any]] = None
    try:
        data = json.loads(cleaned_raw)
        if isinstance(data, dict):
            parsed_json = data
    except Exception:
        # Check if there is a JSON block embedded inside text
        json_match = re.search(r"\{[\s\S]*\}", cleaned_raw)
        if json_match:
            try:
                candidate = json.loads(json_match.group(0))
                if isinstance(candidate, dict):
                    parsed_json = candidate
            except Exception:
                pass

    if parsed_json:
        summary = sanitize_prose(str(parsed_json.get("summary", "")))
        risk_note = sanitize_prose(str(parsed_json.get("riskNote", parsed_json.get("risk_note", ""))))
        remediation = sanitize_prose(str(parsed_json.get("remediation", "")))
        raw_standards = parsed_json.get("standardsCited") or parsed_json.get("standards_cited") or []

        standards_cited = []
        if isinstance(raw_standards, list):
            for item in raw_standards:
                if isinstance(item, dict):
                    std_id = sanitize_prose(str(item.get("id", item.get("standard", ""))))
                    note = sanitize_prose(str(item.get("note", item.get("description", ""))))
                    if std_id:
                        standards_cited.append({"id": std_id, "note": note})
                elif isinstance(item, str):
                    standards_cited.append({"id": sanitize_prose(item), "note": ""})

        return {
            "summary": summary,
            "standardsCited": standards_cited,
            "riskNote": risk_note,
            "remediation": remediation,
        }

    # Freeform text fallback extraction
    sanitized_full = sanitize_prose(raw_output)

    # Heuristic section splitting if formatted with headers
    sections = re.split(r"(?m)^###?\s+", sanitized_full)
    summary_parts = []
    risk_parts = []
    remediation_parts = []
    standards_cited = []

    for sec in sections:
        sec = sec.strip()
        if not sec:
            continue
        lines = sec.split("\n", 1)
        header = lines[0].strip().lower()
        body = lines[1].strip() if len(lines) > 1 else lines[0].strip()

        if "summary" in header or "threat" in header or "analysis" in header:
            summary_parts.append(body)
        elif "what this means" in header or "impact" in header or "risk" in header:
            risk_parts.append(body)
        elif "remediation" in header or "fix" in header or "action" in header:
            remediation_parts.append(body)
        elif "standard" in header or "governing" in header:
            # Extract standard citations from text
            cits = re.findall(r"(RFC\s*[0-9]{4}(?:(?:\s*§|\s*Section|\s*Sec\.?)\s*[0-9\.\w\-]+)?|NIST\s*SP\s*800-[^\s,\)]+)", body, re.IGNORECASE)
            for c in cits:
                clean_c = clean_section_symbol(c.strip())
                standards_cited.append({"id": clean_c, "note": "Governing specification clause"})
            if not summary_parts:
                summary_parts.append(body)
        else:
            if not summary_parts:
                summary_parts.append(body)
            else:
                risk_parts.append(body)

    summary = " ".join(summary_parts).strip() or f"{param} was evaluated under governing RFC and NIST security baselines ({severity})."
    risk_note = " ".join(risk_parts).strip() or desc or "No adverse operational risk under verified baselines."
    remediation = " ".join(remediation_parts).strip() or recom

    # Extract any standards mentioned inline
    all_text = f"{summary} {risk_note} {remediation}"
    for match in re.finditer(r"\b(RFC\s*[0-9]{4}(?:(?:\s*§|\s*Section|\s*Sec\.?)\s*[0-9\.\w\-]+)?|NIST\s*SP\s*800-(?:77|131A)(?:\s*Rev\.\s*[12])?(?:\s*Table\s*[0-9]+)?)\b", all_text, re.IGNORECASE):
        std_str = clean_section_symbol(match.group(0).strip())
        if not any(s["id"] == std_str for s in standards_cited):
            standards_cited.append({"id": std_str, "note": "Authoritative standard requirement"})

    return {
        "summary": sanitize_prose(summary),
        "standardsCited": standards_cited,
        "riskNote": sanitize_prose(risk_note),
        "remediation": sanitize_prose(remediation),
    }
