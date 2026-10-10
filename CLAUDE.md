# EgressIQ Architecture & Context

## Mission
Turnkey data loss prevention (DLP) and compliance proxy for GenAI egress traffic.
Identifies PII, auth keys, and database strings, redacting them in flight before hitting upstream LLM APIs, and generating executive audit PDFs.

## Product principles (never compromise)
Every change is judged against these four. If a change trades one away, stop and raise it instead of shipping it.
1. **Sub-1 ms execution.** Scan+redact p99 ≤ 1 ms for payloads ≤ 4 KB and < 10 ms for 128 KB. Run `python scripts/bench.py` before and after any detector or scan-path change, and report both. No per-request network calls, disk I/O, regex compilation or work that grows faster than linearly with payload size or finding count.
2. **Real, continuous threat intelligence.** Detection rules must stay current without a code release: rules ship as data (`DEFAULT_RULES`, rule files), are versioned, and can be updated centrally. Never fold detection logic back into code paths that only a redeploy can change.
3. **Operational zero touch (drop-in proxy architecture).** Adopting EgressIQ must not require application changes: no SDK swaps, no prompt rewrites. Features should fit an inline proxy that sits between apps and LLM providers; anything that needs per-app integration is a stopgap, not the product.
4. **Executive peace of mind (audit-ready artifacts).** Every scan can produce evidence an auditor accepts: accurate, reproducible, masked (never raw values), mapped to frameworks, and honest about what the product does today.

## Tech Stack
- Python 3.9–3.14 supported (`requires-python = ">=3.9"`); dev venv uses 3.14
- Scanner & Redaction: `re` + stdlib dataclasses (no pydantic, to keep the hot path light)
- PDF Audit Generation: `reportlab`
- Web UI (optional `[web]` extra): `fastapi`, `uvicorn`, `python-multipart`; vanilla HTML/CSS/JS, no build step, no CDN
- Proxy Engine (Upcoming): `fastapi`, `httpx`, or `mitmproxy`

## Layout
- `scanner.py` — built-in rules (`DEFAULT_RULES`, plain data in rule-file shape), `load_rules()` → compiled `RuleSet`, `scan()`, `redact()`, `check_rule_updates()`. `DETECTORS` / `DETECTORS_BY_NAME` / `COMPLIANCE_IMPACT` are the compiled defaults, kept for existing callers
- `report.py` — reportlab audit PDF (masked values only; cli imports it lazily). Also owns `risk_assessment()` and `regulatory_exposure()`, shared with the web UI so PDF and UI always agree
- `scanner.COMPLIANCE_IMPACT` — detector → compliance framework label (reporting metadata; `scan()` never reads it). With custom rules use `RuleSet.compliance`; `report.build_pdf()` / `regulatory_exposure()` take it as `compliance=`
- `cli.py` — argparse CLI
- `web/server.py` — FastAPI wrapper: `/api/scan`, `/api/upload`, `/api/report` (calls `scanner`/`report`, never reimplements them)
- `web/static/` — single-page UI (`index.html`, `styles.css`, `app.js`); `web/samples.py` — fake demo payloads
- `app.py` — `python app.py` launcher for the web UI
- `Dockerfile` — `python:3.12-slim` image, entrypoint `egressiq` (CLI by default, `web` subcommand for the UI); sets `EGRESSIQ_HOST=0.0.0.0`, runs as non-root, writes PDFs to `/data`
- `tests/samples.py` — labelled positive/negative corpus for every detector
- `report.audit_record()` — audit hash (SHA-256 over canonical JSON of generation time, ruleset version, payload SHA-256 and each finding's detector/severity/line/offsets; scheme `egressiq-audit-v1`). Printed in every PDF footer and the PDF keywords, on CLI stderr, and in `/api/report`'s `X-EgressIQ-Audit-Hash` header. Evidence only when stored outside the PDF (it isn't signed)
- `tests/fixtures/sample_logs.csv` — 33-finding fixture covering every detector; `tests/test_report.py` extracts PDF text with `pypdf` to assert sections, framework labels and zero raw secrets

## Commands
- Virtual environment: `source venv/bin/activate` (setup: `python3.14 -m venv venv && pip install -e '.[test,web]'`)
- Run scanner demo: `python scanner.py`
- Run tests: `python -m pytest -q`
- Run tests on all supported versions (needs `uv`): `scripts/test_matrix.sh`
- Latency vs targets (principle 1): `python scripts/bench.py` (exit 1 if any case misses; not in CI, too noisy)
- CLI: `egressiq --file <path> [--dry-run] [--export-pdf [OUT]] [--fail-on-findings] [--rules policy.yaml]` (or `python cli.py ...`; stdin if no `--file`)
- Web UI: `egressiq web [--port 8000] [--open]` or `python app.py` → http://127.0.0.1:8000
- Docker: `docker build -t egressiq .`, then `docker run --rm -v "$PWD:/data" egressiq --file /data/app.log --export-pdf` or `docker run --rm -p 8000:8000 egressiq web` (on Linux add `--user "$(id -u):$(id -g)"` so the PDF can be written to the mount)

## Custom rules (`--rules` / `$EGRESSIQ_RULES`)
JSON, or YAML with the `[yaml]` extra. Merged over the built-in rules; works for the CLI and `egressiq web`:
```yaml
version: "2026.11.0"          # optional; reported by /api/health and used by check_rule_updates
extends_defaults: true        # false = only the rules below
disable: [PHONE_NUMBER]       # drop built-in detectors by name
detectors:
  - name: EMAIL_ADDRESS       # existing name: override just these fields
    severity: critical
  - name: INTERNAL_PROJECT_CODE   # new name: category, severity, pattern required
    category: infrastructure      # credential | pii | infrastructure
    severity: high                # critical | high | medium | low
    pattern: '\bPRJ-\d{6}\b'     # Python regex; optional group: N redacts only that capture group
                                  # optional validator: <name> from scanner.VALIDATORS (e.g. luhn)
    compliance: "Internal: Trade Secret"   # <= 40 chars; default "Custom policy"
    hints: ["PRJ-"]               # optional speed gate: skip the regex unless one occurs
```
- Regexes compile once in `load_rules()`; scans never recompile. A file that can't be read, parsed or validated is rejected whole (never half-applied): defaults are used and a warning goes to stderr (`RuleSet.errors`; `strict=True` raises `RulesError`).
- Overriding a `pattern` resets `group` to 0 and drops inherited `hints`/`prefilter` unless the override sets them; validators are kept.
- Speed gates (principle 1): `hints` (any substring must occur; `hints_ignore_case: true` compares lowercased) and `prefilter` (a regex that must match somewhere) let `scan()` skip a detector cheaply. They are a correctness contract: every string the pattern can match must contain a hint and match the prefilter, or findings are silently lost. Prefer a prefilter/pattern that starts with a literal or character class (Python's regex engine only skips ahead fast then). `tests/test_prefilters.py` checks built-in gates against the corpus and compares `scan()` with an ungated reference on random text.
- Rule patterns are trusted admin config: a catastrophic-backtracking regex will slow every scan.
- `check_rule_updates(url, current_version)` returns a `Future` (background thread) resolving to the remote manifest if its `version` is newer, else `None`. Check only: nothing is downloaded or applied. HTTPS required except localhost.

## Web UI demo
1. `source venv/bin/activate && egressiq web --open`
2. The "Production app log" sample auto-scans on load: KPI cards (Total Findings, Critical Secrets Blocked, PII Redacted, Risk Level) and the raw-vs-sanitized diff populate immediately.
3. Switch samples (copilot prompt → PII, service config → GitHub token / Mongo URI / private key, customer CSV → SSNs + cards), or type/paste — live scan updates as you type.
4. Drag a `.log/.txt/.json/.csv` file (≤ 5 MB) onto the payload panel, or use Upload file.
5. Hover a highlight or findings row to trace it across both panes; click a row to jump to it.
6. "Download Executive Audit PDF" streams the `report.py` PDF (masked values only).
7. Screen-sharing real client data? Click **Mask raw values** in the top bar (or Shift+M) first: the editor and raw pane show masked previews only. Remembered per browser; `?mask=1` starts masked with no flash of raw values.
- Binds to 127.0.0.1 by default (`EGRESSIQ_HOST` overrides; the Docker image sets 0.0.0.0); use `--host 0.0.0.0` only on a trusted network.
- Web tests (`tests/test_web.py`) skip automatically if the `[web]` extra isn't installed.

## Rules
- Stay compatible with Python 3.9: no `match`, no `X | Y` type unions at runtime, no 3.10+ stdlib APIs; keep `from __future__ import annotations`. Run `scripts/test_matrix.sh` before finishing changes.
- Keep zero-trust egress sanitization fast and low-latency.
- Do not introduce heavy dependencies unless strictly necessary.
- Always include automated tests for new regex pattern matchers: add positives and negatives to `tests/samples.py` (the suite fails if a detector has none).
- Never write raw sensitive values to reports or logs; use `Finding.masked`. That includes hashes of raw values (short values like SSNs are brute-forceable).
- Don't present the Interception Gateway (proxy) as generally available in reports or UI copy: it is in private pilot. Only claim what ships (scanner, CLI gate, web UI, PDF).
- Web layer is a thin wrapper: keep detection/report logic in `scanner.py`/`report.py`, and insert payload text in the UI via `textContent` only (never `innerHTML`).

## Backlog
- **Enterprise: signed audit hashes.** `report.audit_record()`'s hash is unsigned: it's tamper evidence only when the customer stores it outside the PDF (GRC system, ticket). For Enterprise-tier integrations, sign it server-side (HMAC-SHA256 with a managed key, or an asymmetric signature verifiable without the key) and print the signature plus key ID in the footer and `/api/report` headers. Bump the scheme to `egressiq-audit-v2`; keep v1 verifiable.
- **Latency on dense 128 KB payloads (accepted 2026-10-10).** Typical payloads meet principle 1; secret-dense ones don't (`scripts/bench.py`: ~19 ms source code, ~25 ms log with ~1 secret/100 B, vs < 10 ms target). Deferred options: candidate-window regex evaluation (pure Python, ~2x), or a compiled multi-pattern engine (native dependency; conflicts with the no-heavy-dependencies rule).
