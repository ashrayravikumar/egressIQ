"""Audit hash and ruleset version on the PDF report."""

import io
import json
import re
from datetime import datetime, timezone

import pytest

import cli
from report import AUDIT_HASH_SCHEME, audit_record, build_pdf
from scanner import DEFAULT_RULES, load_rules, scan

pypdf = pytest.importorskip("pypdf")

FIXTURE = open("tests/fixtures/sample_logs.csv").read()
WHEN = datetime(2026, 10, 10, 12, 0, 5, 123456, tzinfo=timezone.utc)
RAW = ["AKIA" + "IOSFODNN7EXAMPLE", "512-44-8721", "4539 1488 0343 6467", "maria.gonzalez@gmail.com"]


def _pdf_text(path):
    return "\n".join(p.extract_text() for p in pypdf.PdfReader(str(path)).pages)


def test_record_is_deterministic_and_documented():
    findings = scan(FIXTURE)
    a, b = audit_record(findings, FIXTURE, generated_at=WHEN), audit_record(findings, FIXTURE, generated_at=WHEN)
    assert a == b
    assert a["scheme"] == AUDIT_HASH_SCHEME
    assert a["generated_at"] == "2026-10-10T12:00:05Z"
    assert a["ruleset_version"] == DEFAULT_RULES["version"]
    assert re.fullmatch(r"[0-9a-f]{64}", a["audit_hash"])


def test_hash_recomputable_from_documented_canonical_form():
    record = audit_record(scan(FIXTURE), FIXTURE, generated_at=WHEN)
    body = {k: v for k, v in record.items() if k != "audit_hash"}
    import hashlib

    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert hashlib.sha256(canonical.encode("ascii")).hexdigest() == record["audit_hash"]


@pytest.mark.parametrize("change", ["finding", "payload", "time", "ruleset"])
def test_hash_changes_with_any_input(change, tmp_path):
    findings = scan(FIXTURE)
    base = audit_record(findings, FIXTURE, generated_at=WHEN)["audit_hash"]
    if change == "finding":
        other = audit_record(findings[:-1], FIXTURE, generated_at=WHEN)
    elif change == "payload":
        other = audit_record(findings, FIXTURE + " ", generated_at=WHEN)
    elif change == "time":
        other = audit_record(findings, FIXTURE, generated_at=WHEN.replace(second=6))
    else:
        path = tmp_path / "p.json"
        path.write_text(json.dumps({"version": "2026.11.0"}))
        other = audit_record(findings, FIXTURE, load_rules(str(path), strict=True), generated_at=WHEN)
    assert other["audit_hash"] != base


def test_record_has_no_raw_values():
    blob = json.dumps(audit_record(scan(FIXTURE), FIXTURE))
    assert [r for r in RAW if r in blob] == []


def test_pdf_shows_ruleset_and_reproducible_hash(tmp_path):
    out = tmp_path / "r.pdf"
    findings = scan(FIXTURE)
    build_pdf(findings, "sample_logs.csv", FIXTURE, str(out))
    text = _pdf_text(out)
    assert f"EgressIQ Ruleset v{DEFAULT_RULES['version']}" in text
    hashes = re.findall(r"AUDIT HASH \(SHA-256\)\s*([0-9a-f]{64})", text)
    stamps = re.findall(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s*·\s*" + AUDIT_HASH_SCHEME, text)
    pages = len(pypdf.PdfReader(str(out)).pages)
    assert len(hashes) == len(stamps) == pages and len(set(hashes)) == 1  # on every page
    # An auditor holding the payload can recompute it from the stamp printed in the footer.
    when = datetime.strptime(stamps[0], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    assert audit_record(findings, FIXTURE, generated_at=when)["audit_hash"] == hashes[0]
    assert pypdf.PdfReader(str(out)).metadata["/Keywords"] == f"audit_hash={hashes[0]}"
    assert [r for r in RAW if r in text] == []


def test_pdf_uses_given_record_and_custom_ruleset(tmp_path):
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"version": "2026.11.0"}))
    rules = load_rules(str(path), strict=True)
    findings = scan(FIXTURE, rules.detectors)
    record = audit_record(findings, FIXTURE, rules, generated_at=WHEN)
    out = tmp_path / "r.pdf"
    build_pdf(findings, "x.csv", FIXTURE, str(out), rules=rules, record=record)
    text = _pdf_text(out)
    assert "EgressIQ Ruleset v2026.11.0" in text and record["audit_hash"] in text
    assert "10 Oct 2026, 12:00 UTC" in text


def test_cli_prints_audit_hash(tmp_path, capsys, monkeypatch):
    out = tmp_path / "r.pdf"
    monkeypatch.setattr("sys.stdin", io.StringIO("ssn 123-45-6789\n"))
    assert cli.main(["--export-pdf", str(out)]) == 0
    err = capsys.readouterr().err
    printed = re.search(r"audit hash ([0-9a-f]{64}) \(generated (\S+), ruleset (\S+)\)", err)
    assert printed and printed.group(1) in _pdf_text(out)
    assert printed.group(3) == DEFAULT_RULES["version"]


def test_web_report_returns_audit_headers():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    pytest.importorskip("multipart")
    from fastapi.testclient import TestClient

    from web import server

    r = TestClient(server.app).post("/api/report", json={"text": "ssn 123-45-6789"})
    assert r.status_code == 200
    audit_hash = r.headers["x-egressiq-audit-hash"]
    assert r.headers["x-egressiq-ruleset"] == DEFAULT_RULES["version"]
    text = "\n".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(r.content)).pages)
    assert audit_hash in text and r.headers["x-egressiq-generated-at"] in text
