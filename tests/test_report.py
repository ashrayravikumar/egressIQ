import io
from pathlib import Path

import pytest

from report import (
    CONTENT_W, DETAIL_COL_WIDTHS, MAX_DETAIL_ROWS, build_pdf, regulatory_exposure, risk_assessment,
)
from scanner import COMPLIANCE_IMPACT, Finding, scan

pypdf = pytest.importorskip("pypdf")

FIXTURE = Path(__file__).parent / "fixtures" / "sample_logs.csv"
# Raw values planted in the fixture; none may survive into the PDF text.
RAW_SECRETS = [
    "AKIA" + "IOSFODNN7EXAMPLE", "ASIA" + "Q7RTXW2KJ4NPLM3Z", "wJalrXUtnFEMI", "Pr0d-P%40ssw0rd",
    "ghp_" + "R7tQm2Xc9L", "Zx81-qLp", "c4che-s3cret", "Etl!2026", "Sup3r!Secret", "512-44-8721",
    "4539 1488 0343 6467", "alexandra.konstantinopoulou", "maria.gonzalez@gmail.com", "b3BlbnNzaC1rZXkt",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "415-555-0198",
]


def _pdf_text(findings, source, text, tmp_path) -> str:
    out = tmp_path / "r.pdf"
    build_pdf(findings, source, text, str(out))
    reader = pypdf.PdfReader(io.BytesIO(out.read_bytes()))
    return "\n".join(p.extract_text() for p in reader.pages)


@pytest.fixture(scope="module")
def fixture_text():
    return FIXTURE.read_text()


def test_detail_columns_match_spec_and_fit_page():
    assert DETAIL_COL_WIDTHS == (40, 140, 80, 240)
    assert sum(DETAIL_COL_WIDTHS) <= CONTENT_W


def test_fixture_report_sections_and_mapping(fixture_text, tmp_path):
    findings = scan(fixture_text)
    text = _pdf_text(findings, "sample_logs.csv", fixture_text, tmp_path)
    for heading in ("GenAI Egress Audit Report", "Executive Risk Summary", "Findings by Detector",
                    "Finding Detail (masked)", "Remediation & Compliance Status", "sample_logs.csv"):
        assert heading in text, heading
    assert f"{risk_assessment(findings)['score']}" in text
    for framework in set(COMPLIANCE_IMPACT.values()):
        assert framework in text or framework.upper() in text, framework


def test_fixture_report_never_contains_raw_values(fixture_text, tmp_path):
    text = _pdf_text(scan(fixture_text), "sample_logs.csv", fixture_text, tmp_path)
    leaked = [s for s in RAW_SECRETS if s in text]
    assert leaked == []


def test_clean_report(tmp_path):
    text = _pdf_text([], "clean.txt", "hello\n", tmp_path)
    assert "COMPLIANT" in text and "Finding Detail" not in text
    assert "1 line" in text and "1 lines" not in text


def test_source_name_with_markup_characters(fixture_text, tmp_path):
    text = _pdf_text(scan(fixture_text), "a & b <c>.csv", fixture_text, tmp_path)
    assert "a & b <c>.csv" in text


def test_detail_truncation_note(tmp_path):
    big = "\n".join(f"user{i}@example.com" for i in range(MAX_DETAIL_ROWS + 5))
    text = _pdf_text(scan(big), "big.log", big, tmp_path)
    assert f"showing {MAX_DETAIL_ROWS} of {MAX_DETAIL_ROWS + 5}" in text


def _f(sev, det="EMAIL_ADDRESS"):
    return Finding(det, "pii", sev, 0, 1, 1, "x")


@pytest.mark.parametrize("sev,lo,hi", [("critical", 75, 99), ("high", 50, 74), ("medium", 25, 49), ("low", 1, 24)])
def test_risk_score_stays_in_severity_band(sev, lo, hi):
    one = risk_assessment([_f(sev)])["score"]
    many = risk_assessment([_f(sev)] * 50)["score"]
    assert lo <= one <= many <= hi


def test_risk_clear_and_worst_severity_wins():
    assert risk_assessment([]) ["level"] == "CLEAR"
    assert risk_assessment([_f("medium")] * 40 + [_f("critical")])["level"] == "CRITICAL"


def test_regulatory_exposure_groups_frameworks():
    findings = [_f("critical", "AWS_ACCESS_KEY_ID"), _f("high", "JWT"), _f("medium", "EMAIL_ADDRESS")]
    reg = regulatory_exposure(findings)
    assert [(e["framework"], e["findings"], e["severity"]) for e in reg] == [
        ("SOC 2 CC6.6 (Secrets Exposure)", 2, "critical"),
        ("GDPR / CCPA PII", 1, "medium"),
    ]
