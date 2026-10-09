# EgressIQ Architecture & Context

## Mission
Turnkey data loss prevention (DLP) and compliance proxy for GenAI egress traffic.
Identifies PII, auth keys, and database strings, redacting them in flight before hitting upstream LLM APIs, and generating executive audit PDFs.

## Tech Stack
- Python 3.9–3.14 supported (`requires-python = ">=3.9"`); dev venv uses 3.14
- Scanner & Redaction: `re` + stdlib dataclasses (no pydantic, to keep the hot path light)
- PDF Audit Generation: `reportlab`
- Web UI (optional `[web]` extra): `fastapi`, `uvicorn`, `python-multipart`; vanilla HTML/CSS/JS, no build step, no CDN
- Proxy Engine (Upcoming): `fastapi`, `httpx`, or `mitmproxy`

## Layout
- `scanner.py` — detector registry (`DETECTORS`), `scan()`, `redact()`
- `report.py` — reportlab audit PDF (masked values only; reportlab imported lazily)
- `cli.py` — argparse CLI
- `web/server.py` — FastAPI wrapper: `/api/scan`, `/api/upload`, `/api/report` (calls `scanner`/`report`, never reimplements them)
- `web/static/` — single-page UI (`index.html`, `styles.css`, `app.js`); `web/samples.py` — fake demo payloads
- `app.py` — `python app.py` launcher for the web UI
- `tests/samples.py` — labelled positive/negative corpus for every detector

## Commands
- Virtual environment: `source venv/bin/activate` (setup: `python3.14 -m venv venv && pip install -e '.[test,web]'`)
- Run scanner demo: `python scanner.py`
- Run tests: `python -m pytest -q`
- Run tests on all supported versions (needs `uv`): `scripts/test_matrix.sh`
- CLI: `egressiq --file <path> [--dry-run] [--export-pdf [OUT]] [--fail-on-findings]` (or `python cli.py ...`; stdin if no `--file`)
- Web UI: `egressiq web [--port 8000] [--open]` or `python app.py` → http://127.0.0.1:8000

## Web UI demo
1. `source venv/bin/activate && egressiq web --open`
2. The "Production app log" sample auto-scans on load: KPI cards (Total Findings, Critical Secrets Blocked, PII Redacted, Risk Level) and the raw-vs-sanitized diff populate immediately.
3. Switch samples (copilot prompt → PII, service config → GitHub token / Mongo URI / private key, customer CSV → SSNs + cards), or type/paste — live scan updates as you type.
4. Drag a `.log/.txt/.json/.csv` file (≤ 5 MB) onto the payload panel, or use Upload file.
5. Hover a highlight or findings row to trace it across both panes; click a row to jump to it.
6. "Download Executive Audit PDF" streams the `report.py` PDF (masked values only).
- Binds to 127.0.0.1 by default; use `--host 0.0.0.0` only on a trusted network.
- Web tests (`tests/test_web.py`) skip automatically if the `[web]` extra isn't installed.

## Rules
- Stay compatible with Python 3.9: no `match`, no `X | Y` type unions at runtime, no 3.10+ stdlib APIs; keep `from __future__ import annotations`. Run `scripts/test_matrix.sh` before finishing changes.
- Keep zero-trust egress sanitization fast and low-latency.
- Do not introduce heavy dependencies unless strictly necessary.
- Always include automated tests for new regex pattern matchers: add positives and negatives to `tests/samples.py` (the suite fails if a detector has none).
- Never write raw sensitive values to reports or logs; use `Finding.masked`.
- Web layer is a thin wrapper: keep detection/report logic in `scanner.py`/`report.py`, and insert payload text in the UI via `textContent` only (never `innerHTML`).
