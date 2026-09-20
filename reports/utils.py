"""
Janus Report Utilities — Font Registration & Text Sanitization
=============================================================
Protects ReportLab PDF generation against encoding crashes when processing
RFC section symbols (§), checkmarks (✓), em-dashes (—), and other Unicode glyphs.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Track whether Unicode font has been registered
_UNICODE_FONT_AVAILABLE = False
_DEFAULT_FONT_NAME = "Helvetica"
_DEFAULT_BOLD_FONT_NAME = "Helvetica-Bold"

try:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    # Candidate system Unicode TTF fonts
    candidate_fonts = [
        ("DejaVuSans", Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")),
        ("Arial", Path("C:/Windows/Fonts/arial.ttf")),
        ("SegoeUI", Path("C:/Windows/Fonts/segoeui.ttf")),
    ]

    for font_alias, font_path in candidate_fonts:
        if font_path.exists():
            try:
                pdfmetrics.registerFont(TTFont(font_alias, str(font_path)))
                _DEFAULT_FONT_NAME = font_alias
                _UNICODE_FONT_AVAILABLE = True
                log.info("Registered Unicode TrueType font '%s' from %s", font_alias, font_path)
                break
            except Exception as exc:
                log.debug("Could not register font %s: %s", font_path, exc)

except ImportError:
    pass


def get_font_names() -> tuple[str, str]:
    """Returns (regular_font_name, bold_font_name)."""
    if _UNICODE_FONT_AVAILABLE and _DEFAULT_FONT_NAME in ("Arial", "SegoeUI", "DejaVuSans"):
        return _DEFAULT_FONT_NAME, f"{_DEFAULT_FONT_NAME}-Bold" if f"{_DEFAULT_FONT_NAME}-Bold" in pdfmetrics.getRegisteredFontNames() else _DEFAULT_FONT_NAME
    return "Helvetica", "Helvetica-Bold"


def clean_reportlab_text(text: Any) -> str:
    """
    Sanitizes text strings for ReportLab PDF rendering with standard Helvetica/Latin-1 fonts.
    Replaces Unicode symbols (section signs, checkmarks, em-dashes, typographic quotes)
    with clean ASCII equivalents to prevent charmap/encoding crashes.
    """
    if text is None:
        return ""
    s = str(text)
    replacements = {
        "§": "Sec.",
        "✓": "[PASS]",
        "✔": "[PASS]",
        "✗": "[FAIL]",
        "✘": "[FAIL]",
        "—": "--",
        "–": "-",
        "…": "...",
        "“": '"',
        "”": '"',
        "‘": "'",
        "’": "'",
        "•": "*",
        "→": "->",
        "←": "<-",
        "≥": ">=",
        "≤": "<=",
        "±": "+/-",
        "\u200b": "",
        "\u00a0": " ",
    }
    for k, v in replacements.items():
        s = s.replace(k, v)
    # Ensure all characters are safe Latin-1 / ASCII
    return s.encode("latin-1", errors="replace").decode("latin-1")
