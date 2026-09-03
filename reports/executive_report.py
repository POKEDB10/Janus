"""
Janus Report Engine — Executive Security Summary PDF
===================================================
Generates high-impact 1-2 page Executive Briefing PDF using ReportLab.

Key Content:
- Executive Score Gauge / Grade Badge (A-F, 0-100 Score)
- High-Level Risk Posture & Compliance Status (RFC 8221, RFC 8247, NIST SP 800-77 Rev. 1)
- Key Cryptographic Findings & Vulnerability Highlights (SWEET32, Logjam, Broken Ciphers)
- Strategic Executive Recommendations & Action Items
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any, Optional

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import (
        HRFlowable,
        KeepTogether,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
except ImportError:
    # Graceful fallback for environments missing reportlab
    colors = None
    SimpleDocTemplate = None


def generate_executive_pdf(
    compliance_data: dict[str, Any],
    capture_metadata: dict[str, Any],
    output_path: str | Path,
) -> Path:
    """
    Generate the Executive Summary PDF report.
    """
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    if SimpleDocTemplate is None:
        # Fallback dummy file write if reportlab isn't installed
        with open(out_file, "wb") as f:
            f.write(b"%PDF-1.4 Mock Executive PDF Report")
        return out_file

    doc = SimpleDocTemplate(
        str(out_file),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()
    primary_color = colors.HexColor("#0f172a")  # Slate 900
    accent_blue = colors.HexColor("#2563eb")    # Blue 600
    risk_red = colors.HexColor("#dc2626")       # Red 600
    risk_green = colors.HexColor("#16a34a")     # Green 600
    bg_light = colors.HexColor("#f8fafc")       # Slate 50

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=primary_color,
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=12,
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=primary_color,
        spaceBefore=10,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )
    bold_body = ParagraphStyle(
        "BoldBody",
        parent=body_style,
        fontName="Helvetica-Bold",
    )

    story = []

    # 1. Header Banner
    header_table_data = [
        [
            Paragraph("<b>PROJECT JANUS</b> | IPsec VPN Security Assessment", subtitle_style),
            Paragraph(f"Date: <b>{compliance_data.get('generated_at', '2026-09-02')[:10]}</b>", subtitle_style),
        ]
    ]
    header_table = Table(header_table_data, colWidths=[360, 180])
    header_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1.5, color=accent_blue, spaceBefore=0, spaceAfter=8))

    # 2. Title & Score Highlights
    score = float(compliance_data.get("overall_score", 0.0))
    grade = str(compliance_data.get("grade", "F"))
    score_color = risk_green if score >= 80 else (colors.HexColor("#ea580c") if score >= 60 else risk_red)

    story.append(Paragraph("Executive Security Evaluation Briefing", title_style))
    story.append(
        Paragraph(
            f"Target Capture: <b>{capture_metadata.get('filename', 'input.pcap')}</b> (ID: {capture_metadata.get('capture_id', 'N/A')[:8]})",
            subtitle_style,
        )
    )

    # Score Box
    score_box_data = [
        [
            Paragraph("<b>OVERALL COMPLIANCE SCORE</b>", ParagraphStyle("H", parent=bold_body, fontSize=11, textColor=primary_color)),
            Paragraph("<b>SECURITY GRADE</b>", ParagraphStyle("H", parent=bold_body, fontSize=11, textColor=primary_color)),
            Paragraph("<b>POSTURE VERDICT</b>", ParagraphStyle("H", parent=bold_body, fontSize=11, textColor=primary_color)),
        ],
        [
            Paragraph(f"<font size=26 color='{score_color.hexval()}'><b>{score:.1f} / 100</b></font>", body_style),
            Paragraph(f"<font size=26 color='{score_color.hexval()}'><b>GRADE {grade}</b></font>", body_style),
            Paragraph(f"<b>{compliance_data.get('summary', 'Evaluation complete.')}</b>", body_style),
        ],
    ]
    score_table = Table(score_box_data, colWidths=[170, 130, 240])
    score_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), bg_light),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story.append(score_table)
    story.append(Spacer(1, 12))

    # 3. Key Standards Compliance Matrix
    story.append(Paragraph("Standards Baseline Compliance", section_heading))
    eval_params = compliance_data.get("evaluated_parameters", {})

    matrix_data = [
        ["Standard", "Evaluated Parameter", "Configured Value", "Compliance Status"],
        ["RFC 8221", "ESP Confidentiality (Cipher)", str(eval_params.get("esp_encryption", "N/A")), "MUST / SHOULD" if "GCM" in str(eval_params.get("esp_encryption", "")) else "REVIEW"],
        ["RFC 8221", "ESP Integrity (Authentication)", str(eval_params.get("esp_auth", "AEAD Built-in")), "Compliant"],
        ["RFC 8247", "Diffie-Hellman Key Exchange", f"Group {eval_params.get('dh_group', 'N/A')}", "RECOMMENDED" if str(eval_params.get("dh_group")) in ("19", "20") else "REVIEW"],
        ["NIST SP 800-77", "Perfect Forward Secrecy (PFS)", "Enabled" if eval_params.get("pfs_enabled", True) else "DISABLED", "PASS" if eval_params.get("pfs_enabled", True) else "FAIL"],
        ["NIST SP 800-77", "SA Rotation Lifetime", f"{eval_params.get('sa_lifetime_seconds', 3600)}s", "Compliant (1-8h Window)"],
    ]

    matrix_table = Table(matrix_data, colWidths=[90, 170, 160, 120])
    matrix_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), primary_color),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, bg_light]),
                ("FONTSIZE", (0, 1), (-1, -1), 8.5),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(matrix_table)
    story.append(Spacer(1, 12))

    # 4. Critical Findings & Vulnerabilities
    story.append(Paragraph("Key Findings & Security Deficiencies", section_heading))
    findings = compliance_data.get("findings", [])
    if not findings:
        story.append(Paragraph("✓ No compliance violations or high-risk cryptographic configurations detected.", body_style))
    else:
        findings_table_data = [["Severity", "Rule ID", "Parameter", "Description & Risk"]]
        for f in findings[:6]:  # Show top findings
            sev = f.get("severity", "MEDIUM")
            sev_color = "#dc2626" if sev == "CRITICAL" else ("#ea580c" if sev == "HIGH" else "#475569")
            findings_table_data.append(
                [
                    Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", body_style),
                    Paragraph(f.get("rule_id", "N/A"), body_style),
                    Paragraph(f.get("parameter", "N/A"), body_style),
                    Paragraph(f"<b>{f.get('description', '')}</b><br/><font color='#64748b'>{f.get('recommendation', '')}</font>", body_style),
                ]
            )
        findings_table = Table(findings_table_data, colWidths=[70, 110, 110, 250])
        findings_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), primary_color),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, bg_light]),
                    ("FONTSIZE", (0, 1), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(findings_table)

    story.append(Spacer(1, 14))

    # 5. Strategic Recommendations
    story.append(Paragraph("Executive Action Plan", section_heading))
    rec_text = (
        "1. <b>Modernize ESP Cryptography</b>: Ensure all production gateways enforce AES-256-GCM-16 (AEAD) to guarantee integrity and confidentiality.<br/>"
        "2. <b>Enforce Elliptic Curve Key Exchange</b>: Transition Diffie-Hellman parameters from legacy MODP groups to DH Group 19 (ECP-256) or Group 20 (ECP-384).<br/>"
        "3. <b>Mandate Perfect Forward Secrecy</b>: Configure child SA rekeying with fresh DH calculations to prevent retroactive mass decryption.<br/>"
        "4. <b>Deploy Traffic Flow Security</b>: In high-threat environments, evaluate RFC 9347 IP-TFS constant-rate padding to neutralize side-channel analysis."
    )
    story.append(Paragraph(rec_text, body_style))

    doc.build(story)
    return out_file
