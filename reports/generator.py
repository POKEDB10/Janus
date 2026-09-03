"""
Janus Report Engine — Orchestrator
==================================
Unified interface to generate Executive and Technical assessment PDF reports.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Tuple

from reports.executive_report import generate_executive_pdf
from reports.technical_report import generate_technical_pdf

log = logging.getLogger(__name__)

REPORTS_DIR = Path("reports/output")


def generate_all_reports(
    capture_id: str,
    compliance_data: dict[str, Any],
    analysis_data: dict[str, Any],
    output_dir: str | Path = REPORTS_DIR,
) -> Tuple[Path, Path]:
    """
    Generate both executive summary and technical deep-dive PDF reports.

    Returns:
        (executive_pdf_path, technical_pdf_path)
    """
    base_dir = Path(output_dir) / capture_id
    base_dir.mkdir(parents=True, exist_ok=True)

    exec_path = base_dir / "executive_summary.pdf"
    tech_path = base_dir / "technical_assessment.pdf"

    log.info("Generating executive PDF: %s", exec_path)
    generate_executive_pdf(
        compliance_data=compliance_data,
        capture_metadata={"capture_id": capture_id, "filename": analysis_data.get("filename", "capture.pcap")},
        output_path=exec_path,
    )

    log.info("Generating technical PDF: %s", tech_path)
    generate_technical_pdf(
        compliance_data=compliance_data,
        analysis_data=analysis_data,
        output_path=tech_path,
    )

    return exec_path, tech_path
