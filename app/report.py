"""
app/report.py
PDF coverage report generator using reportlab.

The output is a multi-page PDF suitable for handing to a CISO or for
attaching to a quarterly compliance review. Sections:
  1. Executive summary (overall numbers)
  2. Coverage by tactic (table + bar chart)
  3. Top covered techniques
  4. Top gaps (uncovered with high adversary usage)
  5. Data source readiness
"""

from __future__ import annotations

import io
from datetime import datetime

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak)


def _styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle(
        name="MyTitle", parent=s["Title"], fontSize=22,
        spaceAfter=12, textColor=colors.HexColor("#1f2937")))
    s.add(ParagraphStyle(
        name="MySection", parent=s["Heading2"], fontSize=14,
        spaceBefore=14, spaceAfter=6,
        textColor=colors.HexColor("#374151")))
    s.add(ParagraphStyle(
        name="Caption", parent=s["BodyText"], fontSize=9,
        textColor=colors.grey))
    return s


def _table(data: list[list], col_widths=None) -> Table:
    t = Table(data, colWidths=col_widths, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f3f4f6")]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def build_report(
    coverage: pd.DataFrame,
    by_tactic: pd.DataFrame,
    rules: pd.DataFrame,
    available_data_sources: pd.DataFrame,
    organization: str = "Your Organization",
) -> bytes:
    """Render the report and return raw PDF bytes."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        rightMargin=0.75 * inch, leftMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        title="ATT&CK Coverage Report", author="Coverage Dashboard")
    s = _styles()
    flow = []

    # ---- Header
    flow.append(Paragraph("MITRE ATT&CK Coverage Report", s["MyTitle"]))
    flow.append(Paragraph(
        f"Organization: {organization}", s["BodyText"]))
    flow.append(Paragraph(
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        s["Caption"]))
    flow.append(Spacer(1, 0.2 * inch))

    # ---- Executive summary
    total = len(coverage)
    covered = int(coverage["is_covered"].sum())
    weighted_total = float(coverage["weighted_score"].sum())
    naive_pct = round(100 * covered / max(total, 1), 1)
    weighted_pct = round(100 * weighted_total / max(total, 1), 1)
    n_rules = len(rules)

    flow.append(Paragraph("Executive Summary", s["MySection"]))
    flow.append(_table([
        ["Metric", "Value"],
        ["Total ATT&CK techniques", str(total)],
        ["Detection rules", str(n_rules)],
        ["Techniques covered", f"{covered} ({naive_pct}%)"],
        ["Weighted coverage", f"{weighted_pct}%"],
        ["Coverage gap", f"{total - covered} techniques"],
    ], col_widths=[3 * inch, 2.5 * inch]))
    flow.append(Spacer(1, 0.15 * inch))
    flow.append(Paragraph(
        "Naive coverage counts a technique as covered if any rule mentions "
        "it. Weighted coverage discounts techniques whose required data "
        "sources are unavailable, producing a more honest score.",
        s["Caption"]))
    flow.append(Spacer(1, 0.2 * inch))

    # ---- Coverage by tactic
    flow.append(Paragraph("Coverage by Tactic", s["MySection"]))
    rows = [["Tactic", "Total", "Covered", "Naive %", "Weighted %"]]
    for _, r in by_tactic.iterrows():
        rows.append([
            r["tactic"], str(r["total"]), str(r["covered"]),
            f"{r['naive_pct']}%", f"{r['weighted_pct']}%",
        ])
    flow.append(_table(rows, col_widths=[
        2.2 * inch, 0.8 * inch, 0.9 * inch, 1.0 * inch, 1.1 * inch]))
    flow.append(PageBreak())

    # ---- Top gaps
    flow.append(Paragraph(
        "Top Coverage Gaps (uncovered techniques)", s["MySection"]))
    gaps = coverage[~coverage["is_covered"]].head(20)
    rows = [["ID", "Technique", "Tactic"]]
    for _, r in gaps.iterrows():
        rows.append([r["id"], r["name"][:50], r["primary_tactic"]])
    flow.append(_table(rows, col_widths=[
        0.9 * inch, 3.6 * inch, 1.5 * inch]))
    flow.append(Spacer(1, 0.2 * inch))

    # ---- Data source readiness
    flow.append(Paragraph("Data Source Readiness", s["MySection"]))
    if available_data_sources.empty:
        flow.append(Paragraph(
            "No data sources have been registered yet.", s["BodyText"]))
    else:
        rows = [["Data Source", "Enabled", "Quality", "Notes"]]
        for _, r in available_data_sources.iterrows():
            rows.append([
                r["name"][:30],
                "Yes" if r["enabled"] else "No",
                f"{r['quality']:.2f}",
                (r["notes"] or "")[:40],
            ])
        flow.append(_table(rows, col_widths=[
            1.8 * inch, 0.8 * inch, 0.8 * inch, 2.6 * inch]))

    doc.build(flow)
    return buf.getvalue()
