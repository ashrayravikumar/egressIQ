"""EgressIQ Interception Gateway: a drop-in reverse proxy that redacts LLM prompts in flight.

Point existing LLM clients at it instead of the provider; no code changes:

    egressiq gateway --port 8080 --upstream https://api.openai.com
    OPENAI_BASE_URL=http://127.0.0.1:8080/v1     # OpenAI SDKs
    ANTHROPIC_BASE_URL=http://127.0.0.1:8080     # Anthropic SDKs (with --upstream https://api.anthropic.com)

Requests to /v1/... are forwarded to the upstream with the same method, path, query and
headers (Authorization / x-api-key included). The body is sanitized in memory first:

- JSON: every string value goes through scanner.redact(), except protocol fields that never
  carry user text and must reach the provider unchanged (SKIP_KEYS: model, role, ids, names,
  base64 media, signed reasoning blocks). There is no per-provider field list to maintain, so
  new API fields are covered automatically. A body with nothing to redact is forwarded
  byte-for-byte (no re-serialization).
- multipart/form-data (file uploads, e.g. batch JSONL): each UTF-8 part is redacted; binary
  parts (images, audio) pass unchanged and are reported as unscanned.
- Any other body: redacted as text if it is UTF-8, otherwise forwarded unchanged (unscanned).
- Malformed JSON and compressed request bodies are rejected, never forwarded unscanned.

Responses (status, headers, body) are relayed as they arrive, so streaming (SSE) works.
Nothing is written to disk; logs carry detector names and counts, never values.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, List, Optional
from urllib.parse import urlsplit, urlunsplit

from scanner import Detector, RuleSet, load_rules, redact, scan

try:  # the [gateway] extra; sanitize_body() needs only the stdlib
    import httpx
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse, StreamingResponse
    from starlette.background import BackgroundTask
except ImportError as exc:
    _MISSING_DEP: Optional[ImportError] = exc
else:
    _MISSING_DEP = None

log = logging.getLogger("egressiq.gateway")
log.addHandler(logging.NullHandler())

DEFAULT_UPSTREAM = "https://api.openai.com"
DEFAULT_PORT = 8080
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

# JSON keys whose values are forwarded untouched.
SKIP_KEYS = frozenset({
    # Identifiers and enums: an edit breaks the request, and they never carry prompt text.
    "model", "role", "type", "id", "object", "name", "tool_call_id", "tool_use_id", "call_id",
    "file_id", "previous_response_id", "media_type", "mime_type", "detail", "format",
    # Base64 media: not text, and a stray match would corrupt the file.
    "data", "file_data",
    # Model-generated reasoning signed by the provider: any edit is rejected upstream, and it
    # only contains what the provider already saw.
    "thinking", "signature", "encrypted_content",
})
_DATA_URI = re.compile(r"data:[\w.+-]+/[\w.+-]+(?:;[\w.+-]+=[\w.+-]+)*;base64,")

_HOP_BY_HOP = frozenset({
    b"connection", b"keep-alive", b"proxy-authenticate", b"proxy-authorization", b"te",
    b"trailer", b"trailers", b"transfer-encoding", b"upgrade",
})
_DROP_REQUEST_HEADERS = _HOP_BY_HOP | {b"host", b"content-length", b"expect"}
# LLM responses can pause for minutes between streamed chunks; connecting should be quick.
UPSTREAM_TIMEOUT = (10.0, 600.0)  # (connect/write/pool, read)


class Rejected(Exception):
    """The body can't be scanned, so it must not be forwarded."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class Sanitized:
    body: bytes
    counts: Counter = field(default_factory=Counter)  # detector name -> redactions
    unscanned: int = 0  # bytes forwarded unchanged because they aren't text (images, audio)


def _redact_text(text: str, detectors: List[Detector], counts: Counter) -> str:
    findings = scan(text, detectors)
    if not findings:
        return text
    counts.update(f.detector for f in findings)
    return redact(text, findings)[0]


def _walk(node: Any, detectors: List[Detector], counts: Counter) -> Any:
    """Redact every string in a parsed JSON document in place (except SKIP_KEYS values)."""
    if isinstance(node, str):
        return node if _DATA_URI.match(node) else _redact_text(node, detectors, counts)
    if isinstance(node, dict):
        for key, value in node.items():
            if key not in SKIP_KEYS and isinstance(value, (str, dict, list)):
                node[key] = _walk(value, detectors, counts)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            if isinstance(value, (str, dict, list)):
                node[i] = _walk(value, detectors, counts)
    return node


def _sanitize_json(body: bytes, detectors: List[Detector]) -> Sanitized:
    try:
        doc = json.loads(body)
        counts: Counter = Counter()
        doc = _walk(doc, detectors, counts)
    except RecursionError:
        raise Rejected(400, "request JSON is nested too deeply to scan; refusing to forward it") from None
    except ValueError:  # includes UnicodeDecodeError
        raise Rejected(400, "request body is not valid JSON; refusing to forward it unscanned") from None
    if not counts:
        return Sanitized(body)
    return Sanitized(json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), counts)


def _sanitize_multipart(body: bytes, content_type: str, detectors: List[Detector]) -> Sanitized:
    m = re.search(r'boundary="?([^";]+)"?', content_type, re.I)
    if not m:
        raise Rejected(400, "multipart body has no boundary; refusing to forward it unscanned")
    delimiter = b"--" + m.group(1).encode("latin-1")
    result = Sanitized(body)
    pieces = body.split(delimiter)
    out = [pieces[0]]  # preamble: ignored by servers
    for piece in pieces[1:]:
        head, sep, content = piece.partition(b"\r\n\r\n")
        if not sep:  # the closing "--" or malformed: nothing to scan
            out.append(piece)
            continue
        tail = b"\r\n" if content.endswith(b"\r\n") else b""
        payload = content[: len(content) - len(tail)]
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            result.unscanned += len(payload)
            out.append(piece)
            continue
        out.append(head + sep + _redact_text(text, detectors, result.counts).encode("utf-8") + tail)
    if result.counts:
        result.body = delimiter.join(out)
    return result


def sanitize_body(body: bytes, content_type: str, detectors: List[Detector]) -> Sanitized:
    """Redact a request body for forwarding. Raises Rejected if it can't be scanned safely."""
    if not body:
        return Sanitized(body)
    mime = content_type.split(";", 1)[0].strip().lower()
    if mime == "application/json" or mime.endswith("+json") or (not mime and body.lstrip()[:1] in (b"{", b"[")):
        return _sanitize_json(body, detectors)
    if mime == "multipart/form-data":
        return _sanitize_multipart(body, content_type, detectors)
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return Sanitized(body, unscanned=len(body))
    result = Sanitized(body)
    clean = _redact_text(text, detectors, result.counts)
    if result.counts:
        result.body = clean.encode("utf-8")
    return result


def normalize_upstream(url: str, allow_insecure: bool = False) -> str:
    """Validate the upstream base URL; returns it without a trailing slash or /v1."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"upstream must be an http(s) URL such as {DEFAULT_UPSTREAM}, got {url!r}")
    if parts.username or parts.password:
        raise ValueError("upstream must not embed credentials; clients send their own API keys")
    if parts.query or parts.fragment:
        raise ValueError("upstream must not have a query string or fragment")
    if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS and not allow_insecure:
        raise ValueError("refusing a plain-http upstream: API keys would cross the network unencrypted "
                         "(use https, or --insecure-upstream for a trusted internal endpoint)")
    path = parts.path.rstrip("/")
    if path.endswith("/v1"):  # clients already send /v1/...
        path = path[:-3]
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _error(status: int, message: str) -> "JSONResponse":
    # Shaped so both the OpenAI ({"error": {...}}) and Anthropic ({"type": "error", ...}) SDKs surface it.
    return JSONResponse({"type": "error", "error": {"type": "egressiq_gateway_error", "message": message}},
                        status_code=status)


def create_app(upstream: str = DEFAULT_UPSTREAM, rules: Optional[RuleSet] = None, *,
               allow_insecure_upstream: bool = False, transport: Any = None) -> "FastAPI":
    """Build the gateway app. `transport` (an httpx transport) is for tests."""
    if _MISSING_DEP is not None:
        raise _MISSING_DEP
    base = normalize_upstream(upstream, allow_insecure_upstream)
    ruleset = rules if rules is not None else load_rules()
    detectors = ruleset.detectors

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        timeout = httpx.Timeout(UPSTREAM_TIMEOUT[0], read=UPSTREAM_TIMEOUT[1])
        async with httpx.AsyncClient(transport=transport, timeout=timeout) as client:
            app.state.client = client
            yield

    app = FastAPI(title="EgressIQ Gateway", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.upstream = base
    app.state.rules = ruleset

    @app.get("/egressiq/health")
    async def health():
        return {"status": "ok", "upstream": base, "rules_version": ruleset.version, "detectors": len(detectors)}

    @app.api_route("/v1/{path:path}", methods=METHODS)
    async def proxy(request: Request, path: str):
        raw_path = request.scope.get("raw_path") or request.url.path.encode()
        route = raw_path.decode("latin-1")
        if request.headers.get("content-encoding", "identity").lower() != "identity":
            log.warning("%s %s rejected: compressed request body", request.method, route)
            return _error(415, "compressed request bodies can't be scanned; send them uncompressed")

        body = await request.body()
        t0 = time.perf_counter()
        try:
            clean = sanitize_body(body, request.headers.get("content-type", ""), detectors)
        except Rejected as exc:
            log.warning("%s %s rejected: %s", request.method, route, exc.message)
            return _error(exc.status, exc.message)
        sanitize_ms = (time.perf_counter() - t0) * 1000

        query = request.scope.get("query_string", b"").decode("latin-1")
        headers = [(k, v) for k, v in request.headers.raw if k.lower() not in _DROP_REQUEST_HEADERS]
        client: httpx.AsyncClient = request.app.state.client
        outbound = client.build_request(request.method, base + route + ("?" + query if query else ""),
                                        headers=headers, content=clean.body or None)
        try:
            upstream_resp = await client.send(outbound, stream=True)
        except httpx.TimeoutException:
            log.warning("%s %s -> upstream timed out", request.method, route)
            return _error(504, "upstream timed out")
        except httpx.HTTPError as exc:
            log.warning("%s %s -> upstream unreachable (%s)", request.method, route, type(exc).__name__)
            return _error(502, f"upstream unreachable ({type(exc).__name__})")

        total = sum(clean.counts.values())
        detail = ", ".join(f"{name} x{n}" for name, n in sorted(clean.counts.items()))
        log.info("%s %s -> %d  redacted %d%s  sanitize %.3f ms%s", request.method, route,
                 upstream_resp.status_code, total, f" ({detail})" if detail else "", sanitize_ms,
                 f"  unscanned binary {clean.unscanned} B" if clean.unscanned else "")

        async def relay():
            try:
                async for chunk in upstream_resp.aiter_raw():
                    yield chunk
            finally:
                await upstream_resp.aclose()

        response = StreamingResponse(relay(), status_code=upstream_resp.status_code,
                                     background=BackgroundTask(upstream_resp.aclose))
        response.raw_headers = [(k, v) for k, v in upstream_resp.headers.raw if k.lower() not in _HOP_BY_HOP] + [
            (b"x-egressiq-redactions", str(total).encode()),
            (b"x-egressiq-ruleset", ruleset.version.encode()),
            (b"server-timing", f"egressiq;desc=sanitize;dur={sanitize_ms:.3f}".encode()),
        ]
        if clean.counts:
            response.raw_headers.append((b"x-egressiq-detectors", ",".join(sorted(clean.counts)).encode()))
        if clean.unscanned:
            response.raw_headers.append((b"x-egressiq-unscanned-bytes", str(clean.unscanned).encode()))
        return response

    return app


def run(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="egressiq gateway",
        description="Run the EgressIQ Interception Gateway: a reverse proxy that redacts secrets and PII "
                    "from LLM API requests before forwarding them upstream.",
    )
    p.add_argument("--host", default=os.environ.get("EGRESSIQ_HOST", "127.0.0.1"),
                   help="bind address (default: $EGRESSIQ_HOST or 127.0.0.1, local only)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port (default: {DEFAULT_PORT})")
    p.add_argument("--upstream", default=os.environ.get("EGRESSIQ_UPSTREAM", DEFAULT_UPSTREAM),
                   help=f"provider base URL (default: $EGRESSIQ_UPSTREAM or {DEFAULT_UPSTREAM})")
    p.add_argument("--rules", metavar="PATH", default=os.environ.get("EGRESSIQ_RULES"),
                   help="JSON/YAML rule file merged over the built-in detectors (default: $EGRESSIQ_RULES)")
    p.add_argument("--insecure-upstream", action="store_true",
                   help="allow a plain-http upstream that isn't on this machine")
    p.add_argument("--quiet", action="store_true", help="don't log a line per request")
    args = p.parse_args(argv)

    try:
        import uvicorn
    except ImportError as exc:
        missing = exc
    else:
        missing = _MISSING_DEP
    if missing is not None:
        print(f"egressiq: gateway needs extra dependencies ({missing.name}); "
              "install with: pip install -e '.[gateway]'", file=sys.stderr)
        return 2
    try:
        upstream = normalize_upstream(args.upstream, args.insecure_upstream)
    except ValueError as exc:
        p.error(str(exc))

    from cli import load_rules_or_warn

    rules = load_rules_or_warn(args.rules)
    app = create_app(upstream, rules, allow_insecure_upstream=args.insecure_upstream)
    if not args.quiet:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(asctime)s egressiq.gateway %(message)s"))
        log.addHandler(handler)
        log.setLevel(logging.INFO)

    url = f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '::') else args.host}:{args.port}"
    print(f"EgressIQ gateway on {url} -> {upstream}  (Ctrl+C to stop)")
    print(f"Rules {rules.version}: {len(rules.detectors)} detectors from {rules.source}")
    print(f"Point clients at it: OPENAI_BASE_URL={url}/v1  or  ANTHROPIC_BASE_URL={url}")
    sys.stdout.flush()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning", server_header=False, date_header=False)
    return 0


if __name__ == "__main__":
    sys.exit(run())
