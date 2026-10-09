import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("multipart")

from fastapi.testclient import TestClient  # noqa: E402

import cli  # noqa: E402
from scanner import redact  # noqa: E402
from web import server  # noqa: E402
from web.samples import SAMPLES  # noqa: E402

client = TestClient(server.app)
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
LOG = f"user jane.doe@example.com\nkey={AWS_KEY}\nDB=postgres://u:p@db/prod\nok\n"


def _join(segments):
    return "".join(s["t"] for s in segments)


def test_index_and_static_assets():
    r = client.get("/")
    assert r.status_code == 200 and "EgressIQ" in r.text
    for asset in ("/static/app.js", "/static/styles.css"):
        assert client.get(asset).status_code == 200


def test_health_reports_detectors():
    assert client.get("/api/health").json()["detectors"] >= 9


@pytest.mark.parametrize("sample", SAMPLES, ids=[s["id"] for s in SAMPLES])
def test_every_sample_has_findings(sample):
    r = client.post("/api/scan", json={"text": sample["text"]}).json()
    assert r["stats"]["total"] > 0
    assert r["stats"]["risk"]["level"] in {"CRITICAL", "HIGH"}


def test_default_sample_covers_demo_story():
    r = client.post("/api/scan", json={"text": SAMPLES[0]["text"]}).json()
    detectors = {f["detector"] for f in r["findings"]}
    assert {"AWS_ACCESS_KEY_ID", "EMAIL_ADDRESS", "DB_CONNECTION_STRING"} <= detectors


def test_scan_segments_and_kpis():
    r = client.post("/api/scan", json={"text": LOG, "source_name": "app.log"}).json()
    assert r["source_name"] == "app.log"
    assert _join(r["raw_segments"]) == LOG
    assert _join(r["clean_segments"]) == r["sanitized"] == redact(LOG)[0]
    s = r["stats"]
    assert (s["total"], s["secrets_blocked"], s["pii_redacted"]) == (3, 2, 1)
    assert s["risk"]["level"] == "CRITICAL"
    assert AWS_KEY not in r["sanitized"]
    assert all(AWS_KEY not in f["masked"] for f in r["findings"])


def test_scan_clean_text():
    r = client.post("/api/scan", json={"text": "hello world"}).json()
    assert r["stats"]["total"] == 0
    assert r["stats"]["risk"]["level"] == "CLEAR"
    assert _join(r["clean_segments"]) == "hello world"


def test_scan_rejects_oversized_payload(monkeypatch):
    monkeypatch.setattr(server, "MAX_BYTES", 10)
    assert client.post("/api/scan", json={"text": "x" * 11}).status_code == 413


@pytest.mark.parametrize("name", ["app.log", "notes.txt", "data.json", "rows.csv", "UPPER.LOG"])
def test_upload_allowed_types(name):
    r = client.post("/api/upload", files={"file": (name, LOG.encode(), "text/plain")})
    assert r.status_code == 200
    body = r.json()
    assert body["text"] == LOG and body["source_name"] == name
    assert body["stats"]["total"] == 3


def test_upload_rejects_other_types():
    r = client.post("/api/upload", files={"file": ("evil.exe", b"MZ", "application/octet-stream")})
    assert r.status_code == 415


def test_upload_rejects_oversized(monkeypatch):
    monkeypatch.setattr(server, "MAX_BYTES", 10)
    r = client.post("/api/upload", files={"file": ("big.log", b"x" * 11, "text/plain")})
    assert r.status_code == 413


def test_upload_strips_path_from_filename():
    r = client.post("/api/upload", files={"file": ("../../etc/app.log", b"hi", "text/plain")})
    assert r.json()["source_name"] == "app.log"


def test_report_pdf_download():
    r = client.post("/api/report", json={"text": LOG, "source_name": "my app.log"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    cd = r.headers["content-disposition"]
    assert cd.startswith("attachment;") and "EgressIQ-Audit-my-app-" in cd and cd.endswith('.pdf"')
    assert r.content.startswith(b"%PDF")
    assert AWS_KEY.encode() not in r.content


def test_cli_web_subcommand_dispatches(monkeypatch):
    seen = {}
    monkeypatch.setattr(server, "run", lambda argv: seen.setdefault("argv", argv) and 0)
    cli.main(["web", "--port", "9001"])
    assert seen["argv"] == ["--port", "9001"]
