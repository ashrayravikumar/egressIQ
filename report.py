"""EgressIQ executive audit PDF generation (reportlab).

Reports only ever contain masked previews, never raw sensitive values.
cli.py imports this module lazily, so the scan / --dry-run path never loads reportlab.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import (
    Flowable, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from scanner import COMPLIANCE_IMPACT, SEVERITY_ORDER, Finding, RuleSet, load_rules

MAX_DETAIL_ROWS = 500

# Layout (points). Letter width 612 - 2 * 54 margins = 504 usable.
# SimpleDocTemplate's frame adds 6pt padding per side, so page margins sit 6pt outside MARGIN.
MARGIN = 54
FRAME_PAD = 6
CONTENT_W = letter[0] - 2 * MARGIN
DETAIL_COL_WIDTHS = (40, 140, 80, 240)  # Line, Detector, Severity, Masked Preview
BADGE_W, BADGE_H = 58, 13

# Palette
INK = colors.HexColor("#0F172A")
BODY = colors.HexColor("#334155")
MUTED = colors.HexColor("#64748B")
BORDER = colors.HexColor("#E2E8F0")
ZEBRA = colors.HexColor("#F8FAFC")
NAVY = colors.HexColor("#0B1220")
BRAND = colors.HexColor("#0EA5E9")
OK = colors.HexColor("#059669")
SEVERITY_COLORS = {
    "critical": colors.HexColor("#991B1B"),
    "high": colors.HexColor("#DC2626"),
    "medium": colors.HexColor("#D97706"),
    "low": colors.HexColor("#475569"),
    "clear": OK,
    "none": colors.HexColor("#CBD5E1"),  # zero-count chip
}

# ── Risk scoring (shared with the web UI) ────────────────────────────────
# The worst severity sets the band; volume of findings moves the score up within it.
RISK_BANDS = {"critical": (75, 99), "high": (50, 74), "medium": (25, 49), "low": (1, 24)}
SEVERITY_WEIGHTS = {"critical": 0.35, "high": 0.20, "medium": 0.08, "low": 0.02}
RISK_SUMMARIES = {
    "critical": "Live credentials or infrastructure secrets would have left the network.",
    "high": "Regulated PII or bearer tokens would have reached a third-party model.",
    "medium": "Personal identifiers present; redaction required for compliance.",
    "low": "Low-sensitivity identifiers present.",
}


def risk_assessment(findings: Sequence[Finding]) -> Dict[str, Any]:
    if not findings:
        return {"level": "CLEAR", "score": 0, "summary": "No sensitive data detected. Safe for egress."}
    worst = min((f.severity for f in findings), key=SEVERITY_ORDER.__getitem__)
    residual = 1.0
    for f in findings:
        residual *= 1 - SEVERITY_WEIGHTS[f.severity]
    lo, hi = RISK_BANDS[worst]
    return {"level": worst.upper(), "score": lo + round((hi - lo) * (1 - residual)),
            "summary": RISK_SUMMARIES[worst]}


def regulatory_exposure(
    findings: Sequence[Finding], compliance: Optional[Mapping[str, str]] = None
) -> List[Dict[str, Any]]:
    """Frameworks implicated by the findings, most severe first, then by volume.

    compliance maps detector -> framework; pass RuleSet.compliance for custom rules.
    """
    compliance = COMPLIANCE_IMPACT if compliance is None else compliance
    agg: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        name = compliance.get(f.detector)
        if not name:
            continue
        entry = agg.setdefault(name, {"framework": name, "findings": 0, "severity": f.severity, "detectors": []})
        entry["findings"] += 1
        if SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[entry["severity"]]:
            entry["severity"] = f.severity
        if f.detector not in entry["detectors"]:
            entry["detectors"].append(f.detector)
    return sorted(agg.values(), key=lambda e: (SEVERITY_ORDER[e["severity"]], -e["findings"], e["framework"]))


AUDIT_HASH_SCHEME = "egressiq-audit-v1"


def audit_record(
    findings: Sequence[Finding], source_text: str, rules: Optional[RuleSet] = None,
    generated_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Tamper-evidence record for one report: inputs plus their SHA-256 audit hash.

    The hash covers the report time, ruleset version, payload SHA-256 and every
    finding's detector/severity/line/offsets, as canonical JSON. It never covers raw
    values or hashes of them (short values such as SSNs would be brute-forceable).
    Anyone holding the payload can rescan with the same ruleset and recompute it.
    """
    rules = load_rules() if rules is None else rules
    when = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    record: Dict[str, Any] = {
        "scheme": AUDIT_HASH_SCHEME,
        "generated_at": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ruleset_version": rules.version,
        "source_sha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
        "findings": [[f.detector, f.severity, f.line, f.start, f.end] for f in findings],
    }
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    record["audit_hash"] = hashlib.sha256(canonical.encode("ascii")).hexdigest()
    return record


# ── Text styles ──────────────────────────────────────────────────────────
def _style(name: str, **kw: Any) -> ParagraphStyle:
    # Defaults apply only to root styles; a style with a parent inherits everything it doesn't override.
    base = {} if "parent" in kw else {"fontName": "Helvetica", "fontSize": 9, "leading": 12, "textColor": BODY}
    base.update(kw)
    return ParagraphStyle(name, **base)


S_H2 = _style("h2", fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=INK, spaceAfter=2)
S_CAPTION = _style("caption", fontSize=8, leading=11, textColor=MUTED, spaceAfter=8)
S_BODY = _style("body")
S_SMALL = _style("small", fontSize=7.5, leading=10, textColor=MUTED)
S_TH = _style("th", fontName="Helvetica-Bold", fontSize=7, leading=9, textColor=MUTED)
S_TH_R = _style("th_r", parent=S_TH, alignment=TA_RIGHT)
S_TD = _style("td", fontSize=8, leading=10.5, textColor=INK, wordWrap="CJK")
S_TD_R = _style("td_r", parent=S_TD, alignment=TA_RIGHT)
S_TD_REG = _style("td_reg", parent=S_TD, fontName="Helvetica-Bold", fontSize=7.5, textColor=colors.HexColor("#6D28D9"))
S_TD_SMALL = _style("td_small", parent=S_TD, fontSize=7, leading=9, textColor=BODY, wordWrap=None)
S_TD_MONO = _style("td_mono", parent=S_TD, fontName="Courier", fontSize=8, textColor=BODY)
S_STAT_NUM = _style("stat_num", fontName="Helvetica-Bold", fontSize=16, leading=19, textColor=INK)
S_STAT_LBL = _style("stat_lbl", fontSize=6.5, leading=8.5, textColor=MUTED)
S_BOX_TITLE = _style("box_title", fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=INK)
S_STEP_NUM = _style("step_num", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white, alignment=TA_CENTER)
S_STEP = _style("step", fontSize=8, leading=10.5)


def _fit(text: str, font: str, size: float, max_w: float) -> str:
    """Middle-truncate text so it fits max_w (keeps file extensions readable)."""
    if stringWidth(text, font, size) <= max_w:
        return text
    keep = len(text)
    while keep > 4:
        keep -= 1
        head, tail = text[: keep // 2], text[len(text) - (keep - keep // 2):]
        candidate = f"{head}…{tail}"
        if stringWidth(candidate, font, size) <= max_w:
            return candidate
    return "…"


def _badge_w(label: str) -> float:
    return stringWidth(label.upper(), "Helvetica-Bold", 6.8) + 14


# ── Custom flowables ─────────────────────────────────────────────────────
class SeverityBadge(Flowable):
    """Rounded severity chip with white label."""

    def __init__(self, level: str, label: str = "", width: float = BADGE_W, height: float = BADGE_H):
        super().__init__()
        self.level, self.label = level.lower(), (label or level).upper()
        self.width, self.height = width, height

    def wrap(self, aw: float, ah: float):
        return self.width, self.height

    def draw(self) -> None:
        c = self.canv
        c.setFillColor(SEVERITY_COLORS[self.level])
        c.roundRect(0, 0, self.width, self.height, 3, stroke=0, fill=1)
        c.setFillColor(MUTED if self.level == "none" else colors.white)
        c.setFont("Helvetica-Bold", 6.8)
        c.drawCentredString(self.width / 2, self.height / 2 - 2.4, self.label)


class HeaderBanner(Flowable):
    def __init__(self, width: float, meta: List[tuple]):
        super().__init__()
        self.width, self.height, self.meta = width, 120, meta

    def wrap(self, aw: float, ah: float):
        return self.width, self.height

    def draw(self) -> None:
        c, w, h = self.canv, self.width, self.height
        c.setFillColor(NAVY)
        c.roundRect(0, 0, w, h, 8, stroke=0, fill=1)
        c.setFillColor(BRAND)
        c.rect(0, h - 3, w, 3, stroke=0, fill=1)  # brand hairline

        # Badge: shield + wordmark
        bx, by, bw, bh = 18, h - 38, 84, 20
        c.setFillColor(BRAND)
        c.roundRect(bx, by, bw, bh, 4, stroke=0, fill=1)
        p = c.beginPath()
        sx, sy = bx + 7, by + 4
        p.moveTo(sx + 5, sy + 13)
        p.lineTo(sx, sy + 11)
        p.lineTo(sx, sy + 6)
        p.curveTo(sx, sy + 2.5, sx + 2.5, sy + 0.5, sx + 5, sy)
        p.curveTo(sx + 7.5, sy + 0.5, sx + 10, sy + 2.5, sx + 10, sy + 6)
        p.lineTo(sx + 10, sy + 11)
        p.close()
        c.setFillColor(NAVY)
        c.drawPath(p, stroke=0, fill=1)
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(bx + 22, by + 6.2, "EgressIQ")

        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 17)
        c.drawString(18, h - 64, "GenAI Egress Audit Report")
        c.setFillColor(colors.HexColor("#94A3B8"))
        c.setFont("Helvetica", 8.5)
        c.drawString(18, h - 79, "Data loss prevention scan of outbound LLM traffic")

        # Metadata column
        mx = w * 0.56
        max_val_w = w - mx - 18
        y = h - 24
        for label, value in self.meta:
            c.setFillColor(colors.HexColor("#7DD3FC"))
            c.setFont("Helvetica-Bold", 6.3)
            c.drawString(mx, y, label.upper())
            c.setFillColor(colors.white)
            c.setFont("Helvetica", 8.5)
            c.drawString(mx, y - 10, _fit(value, "Helvetica", 8.5, max_val_w))
            y -= 19
        c.setStrokeColor(colors.HexColor("#1E293B"))
        c.setLineWidth(0.6)
        c.line(mx - 14, 14, mx - 14, h - 16)


class RiskScore(Flowable):
    """Large score, level badge and banded gauge."""

    def __init__(self, risk: Dict[str, Any], width: float):
        super().__init__()
        self.risk, self.width, self.height = risk, width, 92

    def wrap(self, aw: float, ah: float):
        return self.width, self.height

    def draw(self) -> None:
        c, w = self.canv, self.width
        level = self.risk["level"].lower()
        color = SEVERITY_COLORS[level]
        score = str(self.risk["score"])

        c.setFillColor(MUTED)
        c.setFont("Helvetica-Bold", 6.5)
        c.drawString(0, 82, "OVERALL RISK SCORE")
        c.setFillColor(color)
        c.setFont("Helvetica-Bold", 38)
        c.drawString(0, 42, score)
        sw = stringWidth(score, "Helvetica-Bold", 38)
        c.setFillColor(MUTED)
        c.setFont("Helvetica", 11)
        c.drawString(sw + 3, 43, "/ 100")

        SeverityBadge(level, self.risk["level"], width=64, height=14).drawOn(c, 0, 20)

        # Gauge: four tinted bands with the filled score on top.
        gy, gh = 4, 6
        c.setFillColor(colors.HexColor("#E2E8F0"))
        c.roundRect(0, gy, w, gh, 3, stroke=0, fill=1)
        fill_w = max(gh, w * self.risk["score"] / 100) if self.risk["score"] else 0
        if fill_w:
            c.setFillColor(color)
            c.roundRect(0, gy, fill_w, gh, 3, stroke=0, fill=1)
        c.setStrokeColor(colors.white)
        c.setLineWidth(1)
        for t in (25, 50, 75):
            c.line(w * t / 100, gy, w * t / 100, gy + gh)


# ── Builders ─────────────────────────────────────────────────────────────
def _section(title: str, caption: str) -> List[Flowable]:
    return [Paragraph(title, S_H2), Paragraph(caption, S_CAPTION)]


def _data_table(rows: List[list], widths: Sequence[float], numeric_cols: Sequence[int] = ()) -> Table:
    t = Table(rows, colWidths=list(widths), repeatRows=1, hAlign="LEFT")
    style = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("BACKGROUND", (0, 0), (-1, 0), ZEBRA),
        ("LINEABOVE", (0, 0), (-1, 0), 0.6, BORDER),
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, BORDER),
        ("LINEBELOW", (0, 1), (-1, -1), 0.35, BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FBFCFE")]),
    ]
    t.setStyle(TableStyle(style))
    return t


def _risk_box(findings: List[Finding], risk: Dict[str, Any], compliance: Mapping[str, str]) -> Table:
    by_sev = Counter(f.severity for f in findings)
    by_cat = Counter(f.category for f in findings)
    detectors = len({f.detector for f in findings})

    if findings:
        worst = risk["level"].lower()
        verdict = (
            f"<b>{len(findings)}</b> sensitive item{'s' if len(findings) != 1 else ''} across "
            f"<b>{detectors}</b> detector type{'s' if detectors != 1 else ''} would have been sent to "
            f"third-party LLM providers. Highest severity: "
            f"<font color='{SEVERITY_COLORS[worst].hexval().replace('0x', '#')}'><b>{risk['level']}</b></font>. "
            f"{escape(risk['summary'])}"
        )
    else:
        verdict = "No sensitive data detected. This payload is clear for egress to upstream LLM APIs."

    def stat(num: Any, label: str) -> list:
        return [Paragraph(str(num), S_STAT_NUM), Paragraph(label.upper(), S_STAT_LBL)]

    stats = Table(
        [[stat(len(findings), "Total findings"),
          stat(by_cat["credential"] + by_cat["infrastructure"], "Secrets blocked"),
          stat(by_cat["pii"], "PII redacted"),
          stat(len(regulatory_exposure(findings, compliance)), "Frameworks hit")]],
        colWidths=[(CONTENT_W - 150 - 28) / 4] * 4, hAlign="LEFT",
    )
    stats.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LINEBEFORE", (1, 0), (-1, 0), 0.5, BORDER), ("LEFTPADDING", (1, 0), (-1, 0), 8),
    ]))

    chips = [[SeverityBadge(s if by_sev[s] else "none", f"{s} {by_sev[s]}", width=66)
              for s in ("critical", "high", "medium", "low")]]
    chip_row = Table(chips, colWidths=[72] * 4, hAlign="LEFT")
    chip_row.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                                  ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))

    left_w = 150
    right = [Paragraph("Executive Risk Summary", S_BOX_TITLE), Spacer(1, 4),
             Paragraph(verdict, S_BODY), Spacer(1, 9), stats, Spacer(1, 9), chip_row]
    box = Table([[RiskScore(risk, left_w - 28), right]], colWidths=[left_w, CONTENT_W - left_w], hAlign="LEFT")
    box.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.8, BORDER),
        ("BACKGROUND", (0, 0), (0, 0), ZEBRA),
        ("LINEAFTER", (0, 0), (0, 0), 0.8, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("VALIGN", (0, 0), (0, 0), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 14), ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 14), ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
    ]))
    return box


def _detector_table(findings: List[Finding], compliance: Mapping[str, str]) -> Table:
    by_det = Counter(f.detector for f in findings)
    severity = {f.detector: f.severity for f in findings}  # from findings, so custom rules work too
    total = len(findings)
    rows: List[list] = [[Paragraph(h, s) for h, s in (
        ("DETECTOR", S_TH), ("STATUTORY IMPACT", S_TH), ("SEVERITY", S_TH), ("FINDINGS", S_TH_R), ("SHARE", S_TH_R))]]
    for name, count in sorted(
        by_det.items(), key=lambda kv: (SEVERITY_ORDER[severity[kv[0]]], -kv[1], kv[0])
    ):
        rows.append([Paragraph(name, S_TD), Paragraph(escape(compliance.get(name, "")), S_TD_REG),
                     SeverityBadge(severity[name]), Paragraph(str(count), S_TD_R),
                     Paragraph(f"{100 * count / total:.0f}%", S_TD_R)])
    return _data_table(rows, (140, 160, 80, 60, 64))


def _detail_table(findings: List[Finding]) -> Table:
    rows: List[list] = [[Paragraph("LINE", S_TH_R), Paragraph("DETECTOR", S_TH),
                         Paragraph("SEVERITY", S_TH), Paragraph("MASKED PREVIEW", S_TH)]]
    for f in findings[:MAX_DETAIL_ROWS]:
        rows.append([Paragraph(str(f.line), S_TD_R), Paragraph(f.detector, S_TD), SeverityBadge(f.severity),
                     Paragraph(escape(f.masked), S_TD_MONO)])
    return _data_table(rows, DETAIL_COL_WIDTHS)


def _remediation_box(findings: List[Finding], compliance: Mapping[str, str]) -> KeepTogether:
    n = len(findings)
    gate = '<font face="Courier">egressiq --fail-on-findings</font>'
    if n:
        status = SeverityBadge("critical", "Action required", width=88, height=14)
        status_text = "<b>Audit Verdict:</b> Non-compliant data egress detected."
        path_label = "Remediation Path"
    else:
        status = SeverityBadge("clear", "Compliant", width=70, height=14)
        status_text = "<b>Audit Verdict:</b> No sensitive data egress detected in this payload."
        path_label = "Prevention Path"

    gap = status.width + 12
    status_row = Table([[status, Paragraph(status_text, S_BODY)]], colWidths=[gap, CONTENT_W - 28 - gap], hAlign="LEFT")
    status_row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                    ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                                    ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))

    pitch = Paragraph(
        f"<b>{path_label}:</b> Enforce pre-flight payload sanitization via the EgressIQ Interception Gateway "
        f"(available in private pilot) or integrate our pre-commit audit gate into CI/CD pipelines using {gate}.",
        S_BODY,
    )

    # Only steps a customer can take today; the Gateway is labelled as a pilot, never as GA.
    steps = [("1", "Gate CI/CD", f"Add {gate} to pre-commit hooks and pipelines; any finding fails the build."),
             ("2", "Rotate &amp; purge", "Rotate exposed credentials and purge logs or prompts that held raw values."),
             ("3", "Pilot the Gateway", "Join the private pilot for inline redaction before requests leave your network.")]
    step_cells = []
    for num, title, text in steps:
        dot = Table([[Paragraph(num, S_STEP_NUM)]], colWidths=[16], rowHeights=[16])
        dot.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), BRAND), ("ROUNDEDCORNERS", [8, 8, 8, 8]),
                                 ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                                 ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
        step_cells.append([dot, Spacer(1, 4), Paragraph(f"<b>{title}</b>", S_STEP), Paragraph(text, S_STEP)])
    col = (CONTENT_W - 28) / 3
    steps_t = Table([step_cells], colWidths=[col] * 3, hAlign="LEFT")
    steps_t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                                 ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))

    inner: List[Flowable] = [Paragraph("Remediation &amp; Compliance Status", S_BOX_TITLE), Spacer(1, 8),
                             status_row, Spacer(1, 10), pitch, Spacer(1, 10), steps_t]

    if n:
        secret_detectors = {f.detector for f in findings if f.category != "pii"}
        rows: List[list] = [[Paragraph(h, s) for h, s in (
            ("FRAMEWORK", S_TH), ("FINDINGS", S_TH_R), ("DETECTORS", S_TH), ("RECOMMENDED CONTROL", S_TH))]]
        w = CONTENT_W - 28
        badge_max = w * 0.37 - 12  # framework column minus cell padding
        for e in regulatory_exposure(findings, compliance):
            control = ("Rotate + redact before egress" if secret_detectors & set(e["detectors"])
                       else "Redact before egress")
            # Custom rule files can name long frameworks; keep the badge inside its column.
            label = _fit(e["framework"].upper(), "Helvetica-Bold", 6.8, badge_max - 14)
            rows.append([
                Table([[SeverityBadge(e["severity"], label, width=_badge_w(label))]],
                      style=[("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                             ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0)],
                      hAlign="LEFT"),
                Paragraph(str(e["findings"]), S_TD_R),
                Paragraph(", ".join(e["detectors"]), S_TD_SMALL),
                Paragraph(control, S_TD),
            ])
        inner += [Spacer(1, 12), _data_table(rows, (w * 0.37, w * 0.12, w * 0.30, w * 0.21))]

    next_step = (f"rotate the exposed credentials above, then add {gate} to CI so new exposures fail the "
                 "build. This audit can serve as the baseline policy for a Gateway pilot." if n else
                 f"add {gate} to CI so future payloads stay this clean.")
    inner += [Spacer(1, 10), Paragraph(f"<b>Next step:</b> {next_step}", S_BODY)]

    box = Table([[inner]], colWidths=[CONTENT_W], hAlign="LEFT")
    box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0F9FF")),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#BAE6FD")),
        ("LINEBEFORE", (0, 0), (0, -1), 3, BRAND),
        ("LEFTPADDING", (0, 0), (-1, -1), 14), ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 14), ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
    ]))
    return KeepTogether([box])


def _footer(canvas: Any, doc: Any) -> None:
    record = doc.egressiq_audit
    canvas.saveState()
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN, 40, letter[0] - MARGIN, 40)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(MARGIN, 28, "EgressIQ Audit Report  ·  Confidential  ·  Values masked; raw secrets are never stored in this report")
    canvas.drawRightString(letter[0] - MARGIN, 28, f"Page {doc.page}")
    canvas.setFont("Helvetica-Bold", 6.3)
    canvas.drawString(MARGIN, 17, "AUDIT HASH (SHA-256)")
    label_w = stringWidth("AUDIT HASH (SHA-256)", "Helvetica-Bold", 6.3) + 6
    canvas.setFont("Courier", 6.6)
    canvas.drawString(MARGIN + label_w, 17, record["audit_hash"])
    canvas.setFont("Helvetica", 6.3)
    canvas.drawRightString(letter[0] - MARGIN, 17, f"{record['generated_at']}  ·  {AUDIT_HASH_SCHEME}")
    canvas.restoreState()


def build_pdf(
    findings: List[Finding], source_name: str, source_text: str, out_path: str,
    compliance: Optional[Mapping[str, str]] = None, rules: Optional[RuleSet] = None,
    record: Optional[Dict[str, Any]] = None,
) -> str:
    """Write the audit PDF.

    rules: the RuleSet that produced the findings (default: built-in); sets the
    ruleset version and, unless compliance is given, the framework mapping.
    record: an audit_record() for these findings, when the caller also needs the
    audit hash (e.g. to log it outside the PDF); built here otherwise.
    """
    rules = load_rules() if rules is None else rules
    compliance = rules.compliance if compliance is None else compliance
    record = audit_record(findings, source_text, rules) if record is None else record
    risk = risk_assessment(findings)
    generated = datetime.strptime(record["generated_at"], "%Y-%m-%dT%H:%M:%SZ")
    lines = source_text.count("\n") + (1 if source_text and not source_text.endswith("\n") else 0)
    meta = [
        ("Scan date", generated.strftime("%d %b %Y, %H:%M UTC")),
        ("Target file", source_name),
        ("Ruleset", f"EgressIQ Ruleset v{rules.version}"),
        ("SHA-256", f"{record['source_sha256'][:24]}…"),
        ("Payload", f"{len(source_text):,} characters · {lines:,} line{'s' if lines != 1 else ''}"),
    ]

    story: List[Flowable] = [HeaderBanner(CONTENT_W, meta), Spacer(1, 16), _risk_box(findings, risk, compliance)]

    if findings:
        story += [Spacer(1, 20), *_section("Findings by Detector", "Grouped by detection rule, most severe first.")]
        story += [_detector_table(findings, compliance), Spacer(1, 20)]
        story += _section("Finding Detail (masked)",
                          "Each finding with its source line. Previews show only the first characters of each value.")
        story.append(_detail_table(findings))
        if len(findings) > MAX_DETAIL_ROWS:
            story += [Spacer(1, 6), Paragraph(
                f"Detail truncated: showing {MAX_DETAIL_ROWS:,} of {len(findings):,} findings.", S_SMALL)]

    story += [Spacer(1, 20), _remediation_box(findings, compliance), Spacer(1, 8), Paragraph(
        "Risk score bands: 75–99 Critical · 50–74 High · 25–49 Medium · 1–24 Low "
        "· 0 Clear. The most severe finding sets the band; finding volume raises the score within it.",
        S_SMALL)]

    doc = SimpleDocTemplate(
        out_path, pagesize=letter, title="EgressIQ Audit Report", author="EgressIQ",
        subject=f"GenAI egress audit: {source_name}",
        keywords=f"audit_hash={record['audit_hash']}",
        leftMargin=MARGIN - FRAME_PAD, rightMargin=MARGIN - FRAME_PAD, topMargin=44, bottomMargin=56,
    )
    doc.egressiq_audit = record
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return out_path
