"""EgressIQ executive audit PDF generation (reportlab).

Reports only ever contain masked previews, never raw sensitive values.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from datetime import datetime, timezone
from typing import List

from scanner import DETECTORS_BY_NAME, SEVERITY_ORDER, Finding

MAX_DETAIL_ROWS = 500


def build_pdf(findings: List[Finding], source_name: str, source_text: str, out_path: str) -> str:
    # Imported lazily so the scanner and --dry-run path never pay for reportlab.
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    sev_colors = {
        "critical": colors.HexColor("#b42318"),
        "high": colors.HexColor("#c4320a"),
        "medium": colors.HexColor("#b54708"),
        "low": colors.HexColor("#475467"),
    }
    table_style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#101828")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d0d5dd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ])

    by_sev = Counter(f.severity for f in findings)
    by_det = Counter(f.detector for f in findings)
    worst = min(by_sev, key=SEVERITY_ORDER.__getitem__) if findings else None
    digest = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    story = [
        Paragraph("EgressIQ Audit Report", styles["Title"]),
        Paragraph(f"Generated {generated}", styles["Normal"]),
        Spacer(1, 0.2 * inch),
        Paragraph("Executive Summary", styles["Heading2"]),
    ]
    if findings:
        verdict = (
            f"<b>{len(findings)}</b> sensitive item(s) detected across "
            f"<b>{len(by_det)}</b> detector type(s). Highest severity: "
            f"<font color='#{sev_colors[worst].hexval()[2:]}'><b>{worst.upper()}</b></font>. "
            "All items would be redacted before egress to upstream LLM APIs."
        )
    else:
        verdict = "No sensitive data detected. Payload is clear for egress."
    story += [Paragraph(verdict, styles["Normal"]), Spacer(1, 0.15 * inch)]

    meta = Table(
        [["Source", source_name], ["SHA-256", digest], ["Size", f"{len(source_text):,} characters"]],
        colWidths=[1.1 * inch, 5.4 * inch], hAlign="LEFT",
    )
    meta.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d0d5dd")),
    ]))
    story += [meta, Spacer(1, 0.25 * inch)]

    if findings:
        story.append(Paragraph("Findings by Severity", styles["Heading2"]))
        rows = [["Severity", "Count"]] + [
            [s.upper(), str(by_sev[s])] for s in sorted(by_sev, key=SEVERITY_ORDER.__getitem__)
        ]
        t = Table(rows, colWidths=[2 * inch, 1 * inch], hAlign="LEFT")
        t.setStyle(table_style)
        story += [t, Spacer(1, 0.25 * inch)]

        story.append(Paragraph("Findings by Detector", styles["Heading2"]))
        rows = [["Detector", "Category", "Severity", "Count"]]
        for name, count in sorted(
            by_det.items(), key=lambda kv: (SEVERITY_ORDER[DETECTORS_BY_NAME[kv[0]].severity], -kv[1])
        ):
            d = DETECTORS_BY_NAME[name]
            rows.append([name, d.category, d.severity.upper(), str(count)])
        t = Table(rows, colWidths=[2.4 * inch, 1.4 * inch, 1.2 * inch, 0.8 * inch], hAlign="LEFT")
        t.setStyle(table_style)
        story += [t, Spacer(1, 0.25 * inch)]

        story.append(Paragraph("Finding Detail (masked)", styles["Heading2"]))
        rows = [["Line", "Detector", "Severity", "Masked Preview"]]
        for f in findings[:MAX_DETAIL_ROWS]:
            rows.append([str(f.line), f.detector, f.severity.upper(), f.masked])
        t = Table(rows, colWidths=[0.6 * inch, 2.4 * inch, 1.0 * inch, 2.5 * inch], repeatRows=1, hAlign="LEFT")
        t.setStyle(table_style)
        story.append(t)
        if len(findings) > MAX_DETAIL_ROWS:
            story.append(Paragraph(
                f"Detail truncated: showing {MAX_DETAIL_ROWS} of {len(findings)} findings.",
                styles["Italic"],
            ))

    SimpleDocTemplate(
        out_path, pagesize=letter, title="EgressIQ Audit Report", author="EgressIQ",
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
    ).build(story)
    return out_path
