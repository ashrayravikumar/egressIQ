"""EgressIQ local web UI: a thin FastAPI layer over scanner.py and report.py.

Launch with `egressiq web` or `python app.py`. Binds to 127.0.0.1 by default;
payloads are processed in memory and never written to disk except the
temporary PDF, which is deleted once streamed.
"""

from __future__ import annotations

import argparse
import os
import re
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from report import build_pdf, regulatory_exposure, risk_assessment
from scanner import COMPLIANCE_IMPACT, DETECTORS, Finding, redact, scan
from web.samples import SAMPLES

STATIC_DIR = Path(__file__).parent / "static"
ALLOWED_EXTENSIONS = {".txt", ".json", ".csv", ".log"}
MAX_BYTES = 5 * 1024 * 1024
DEFAULT_SOURCE = "pasted-input.txt"

app = FastAPI(title="EgressIQ", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class ScanRequest(BaseModel):
    text: str
    source_name: Optional[str] = None


def _check_size(text: str) -> None:
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise HTTPException(413, f"Payload exceeds {MAX_BYTES // (1024 * 1024)} MB limit")


def _segments(text: str, findings: List[Finding], sanitized: bool) -> List[Dict[str, Any]]:
    """Split text into plain and finding segments so the UI never has to map offsets."""
    out: List[Dict[str, Any]] = []
    cursor = 0
    for i, f in enumerate(findings):
        if f.start > cursor:
            out.append({"t": text[cursor:f.start]})
        out.append({"t": f"[REDACTED:{f.detector}]" if sanitized else text[f.start:f.end], "f": i})
        cursor = f.end
    if cursor < len(text):
        out.append({"t": text[cursor:]})
    return out


def analyze(text: str, source_name: str) -> Dict[str, Any]:
    t0 = time.perf_counter()
    findings = scan(text)
    clean, _ = redact(text, findings)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    by_cat = Counter(f.category for f in findings)
    return {
        "source_name": source_name,
        "chars": len(text),
        "lines": text.count("\n") + (1 if text and not text.endswith("\n") else 0),
        "elapsed_ms": round(elapsed_ms, 2),
        "stats": {
            "total": len(findings),
            "secrets_blocked": by_cat["credential"] + by_cat["infrastructure"],
            "pii_redacted": by_cat["pii"],
            "by_severity": dict(Counter(f.severity for f in findings)),
            "risk": risk_assessment(findings),
            "regulatory": regulatory_exposure(findings),
        },
        "findings": [
            {"detector": f.detector, "category": f.category, "severity": f.severity,
             "line": f.line, "masked": f.masked, "regulation": COMPLIANCE_IMPACT.get(f.detector, "")}
            for f in findings
        ],
        "raw_segments": _segments(text, findings, sanitized=False),
        "clean_segments": _segments(text, findings, sanitized=True),
        "sanitized": clean,
    }


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "detectors": len(DETECTORS)}


@app.get("/api/detectors")
def detectors() -> List[Dict[str, str]]:
    return [{"name": d.name, "category": d.category, "severity": d.severity,
             "description": d.description, "regulation": COMPLIANCE_IMPACT.get(d.name, "")} for d in DETECTORS]


@app.get("/api/samples")
def samples() -> List[Dict[str, str]]:
    return SAMPLES


@app.post("/api/scan")
def scan_text(req: ScanRequest) -> Dict[str, Any]:
    _check_size(req.text)
    return analyze(req.text, req.source_name or DEFAULT_SOURCE)


@app.post("/api/upload")
def upload(file: UploadFile = File(...)) -> Dict[str, Any]:
    name = Path(file.filename or "upload.txt").name
    if Path(name).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(415, f"Unsupported file type. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")
    data = file.file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(413, f"File exceeds {MAX_BYTES // (1024 * 1024)} MB limit")
    text = data.decode("utf-8", errors="replace")
    result = analyze(text, name)
    result["text"] = text
    return result


@app.post("/api/report")
def report(req: ScanRequest) -> Response:
    _check_size(req.text)
    source = req.source_name or DEFAULT_SOURCE
    findings = scan(req.text)
    with tempfile.TemporaryDirectory(prefix="egressiq-") as tmp:
        path = os.path.join(tmp, "report.pdf")
        build_pdf(findings, source, req.text, path)
        with open(path, "rb") as fh:
            pdf = fh.read()
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(source).stem).strip("-") or "payload"
    filename = f"EgressIQ-Audit-{stem}-{time.strftime('%Y%m%d-%H%M%S')}.pdf"
    return Response(
        pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"},
    )


def run(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="egressiq web", description="Launch the EgressIQ demo web UI.")
    p.add_argument("--host", default=os.environ.get("EGRESSIQ_HOST", "127.0.0.1"),
                   help="bind address (default: $EGRESSIQ_HOST or 127.0.0.1, local only)")
    p.add_argument("--port", type=int, default=8000, help="port (default: 8000)")
    p.add_argument("--open", action="store_true", help="open the UI in your default browser")
    args = p.parse_args(argv)

    import uvicorn

    url = f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '::') else args.host}:{args.port}"
    print(f"EgressIQ web UI running at {url}  (Ctrl+C to stop)")
    if args.open:
        import threading
        import webbrowser

        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0
