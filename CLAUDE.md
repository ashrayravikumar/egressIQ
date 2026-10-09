# EgressIQ Architecture & Context

## Mission
Turnkey data loss prevention (DLP) and compliance proxy for GenAI egress traffic.
Identifies PII, auth keys, and database strings, redacting them in flight before hitting upstream LLM APIs, and generating executive audit PDFs.

## Tech Stack
- Python 3.9–3.14 supported (`requires-python = ">=3.9"`); dev venv uses 3.14
- Scanner & Redaction: `re` + stdlib dataclasses (no pydantic, to keep the hot path light)
- PDF Audit Generation: `reportlab`
- Proxy Engine (Upcoming): `fastapi`, `httpx`, or `mitmproxy`

## Layout
- `scanner.py` — detector registry (`DETECTORS`), `scan()`, `redact()`
- `report.py` — reportlab audit PDF (masked values only; reportlab imported lazily)
- `cli.py` — argparse CLI
- `tests/samples.py` — labelled positive/negative corpus for every detector

## Commands
- Virtual environment: `source venv/bin/activate` (setup: `python3.14 -m venv venv && pip install -e '.[test]'`)
- Run scanner demo: `python scanner.py`
- Run tests: `python -m pytest -q`
- Run tests on all supported versions (needs `uv`): `scripts/test_matrix.sh`
- CLI: `egressiq --file <path> [--dry-run] [--export-pdf [OUT]] [--fail-on-findings]` (or `python cli.py ...`; stdin if no `--file`)

## Rules
- Stay compatible with Python 3.9: no `match`, no `X | Y` type unions at runtime, no 3.10+ stdlib APIs; keep `from __future__ import annotations`. Run `scripts/test_matrix.sh` before finishing changes.
- Keep zero-trust egress sanitization fast and low-latency.
- Do not introduce heavy dependencies unless strictly necessary.
- Always include automated tests for new regex pattern matchers: add positives and negatives to `tests/samples.py` (the suite fails if a detector has none).
- Never write raw sensitive values to reports or logs; use `Finding.masked`.
