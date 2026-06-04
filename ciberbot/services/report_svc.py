"""Generación de reportes PDF/Markdown a partir de un dict."""
from __future__ import annotations

import json
from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer


def to_markdown(title: str, payload: dict) -> str:
    body = f"# {title}\n\n```json\n{json.dumps(payload, indent=2, ensure_ascii=False)}\n```\n"
    return body


def to_pdf(title: str, payload: dict) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title=title)
    styles = getSampleStyleSheet()
    story = [
        Paragraph(title, styles["Title"]),
        Spacer(1, 12),
        Paragraph("<font face='Courier' size='8'>" +
                  json.dumps(payload, indent=2, ensure_ascii=False)
                  .replace("&", "&amp;").replace("<", "&lt;").replace("\n", "<br/>") +
                  "</font>", styles["BodyText"]),
    ]
    doc.build(story)
    return buf.getvalue()
