"""Interception Gateway: prompts reach the upstream redacted; everything else passes through intact."""

import gzip
import json
import logging
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

import cli  # noqa: E402
import gateway  # noqa: E402
from gateway import create_app, normalize_upstream, sanitize_body  # noqa: E402
from scanner import DETECTORS, load_rules, redact  # noqa: E402

AWS = "AKIA" + "IOSFODNN7EXAMPLE"
CARD = "4111 1111 1111 1111"
SSN = "123-45-6789"
EMAIL = "jane.doe@example.com"
UPSTREAM = "https://llm.upstream.test"
COMPLETION = {"id": "chatcmpl-1", "object": "chat.completion", "choices": [{"message": {"content": "ok"}}]}


class _Body(httpx.AsyncByteStream):
    """Unread body, as from a real network transport (httpx.Response(content=...) pre-reads it)."""

    def __init__(self, chunks):
        self.chunks = chunks

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk


def reply(status=200, json_body=None, content=b"", headers=(), chunks=None):
    headers = list(headers)
    if json_body is not None:
        content = json.dumps(json_body).encode()
        headers.append(("content-type", "application/json"))
    return httpx.Response(status, headers=headers, stream=_Body(chunks or [content]))


class Upstream:
    """httpx.MockTransport handler that records what the provider would receive."""

    def __init__(self, respond=None):
        self.requests = []
        self.respond = respond or (lambda req: reply(json_body=COMPLETION, headers=[("x-request-id", "req_1")]))

    def __call__(self, request):
        self.requests.append(request)
        return self.respond(request)

    @property
    def last(self):
        (req,) = self.requests
        return req


@pytest.fixture
def upstream():
    return Upstream()


def _client(upstream, base=UPSTREAM, **kw):
    return TestClient(create_app(base, transport=httpx.MockTransport(upstream), **kw))


@pytest.fixture
def client(upstream):
    with _client(upstream) as c:
        yield c


# ── Redaction ────────────────────────────────────────────────────────────
def test_chat_completions_secrets_arrive_redacted(client, upstream):
    body = {
        "model": "gpt-4o",
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": f"Why does this fail? key={AWS} card {CARD}"},
        ],
    }
    r = client.post("/v1/chat/completions?api-version=2026-01-01", json=body,
                    headers={"Authorization": "Bearer sk-test-123", "OpenAI-Organization": "org-1"})
    assert r.status_code == 200 and r.json() == COMPLETION

    sent = upstream.last
    assert str(sent.url) == f"{UPSTREAM}/v1/chat/completions?api-version=2026-01-01"
    assert sent.method == "POST"
    assert sent.headers["authorization"] == "Bearer sk-test-123"
    assert sent.headers["openai-organization"] == "org-1"
    assert sent.headers["host"] == "llm.upstream.test"
    assert sent.headers["content-length"] == str(len(sent.content))
    raw = sent.content.decode()
    assert AWS not in raw and CARD not in raw
    got = json.loads(raw)
    assert got["messages"][1]["content"] == (
        "Why does this fail? key=[REDACTED:AWS_ACCESS_KEY_ID] card [REDACTED:CREDIT_CARD]")
    assert {k: v for k, v in got.items() if k != "messages"} == {"model": "gpt-4o", "temperature": 0.2}
    assert got["messages"][0] == body["messages"][0]

    assert r.headers["x-egressiq-redactions"] == "2"
    assert r.headers["x-egressiq-detectors"] == "AWS_ACCESS_KEY_ID,CREDIT_CARD"
    assert r.headers["x-request-id"] == "req_1"
    assert r.headers["server-timing"].startswith("egressiq;desc=sanitize;dur=")


def test_clean_body_forwarded_byte_for_byte(client, upstream):
    raw = b'{"model": "gpt-4o",\n  "messages": [{"role": "user", "content": "caf\\u00e9 roadmap"}]}'
    r = client.post("/v1/chat/completions", content=raw, headers={"Content-Type": "application/json"})
    assert r.status_code == 200 and r.headers["x-egressiq-redactions"] == "0"
    assert upstream.last.content == raw
    assert "x-egressiq-detectors" not in r.headers


def test_anthropic_messages(client, upstream):
    image = "iVBORw0KGgo" + "4111111111111111" + "AAAA"  # base64 media must never be altered
    body = {
        "model": "claude-sonnet-5-5",
        "max_tokens": 512,
        "system": [{"type": "text", "text": f"Escalate to {EMAIL}", "cache_control": {"type": "ephemeral"}}],
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": f"Customer SSN {SSN}"},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": image}},
            ]},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": f"signed reasoning {AWS}", "signature": "EqQBCkYIARgC"},
                {"type": "tool_use", "id": "toolu_01", "name": "lookup", "input": {"email": EMAIL}},
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_01", "content": "phone +1-415-555-0198"},
            ]},
        ],
    }
    r = client.post("/v1/messages", json=body, headers={"x-api-key": "sk-ant-test", "anthropic-version": "2023-06-01"})
    assert r.status_code == 200
    sent = upstream.last
    assert sent.headers["x-api-key"] == "sk-ant-test" and sent.headers["anthropic-version"] == "2023-06-01"
    got = json.loads(sent.content)
    assert got["system"][0]["text"] == "Escalate to [REDACTED:EMAIL_ADDRESS]"
    assert got["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert got["messages"][0]["content"][0]["text"] == "Customer SSN [REDACTED:US_SSN]"
    assert got["messages"][0]["content"][1] == body["messages"][0]["content"][1]
    assert got["messages"][1]["content"][0] == body["messages"][1]["content"][0]  # signed: untouched
    assert got["messages"][1]["content"][1]["input"] == {"email": "[REDACTED:EMAIL_ADDRESS]"}
    assert got["messages"][1]["content"][1]["id"] == "toolu_01"
    assert got["messages"][2]["content"][0]["content"] == "phone [REDACTED:PHONE_NUMBER]"
    assert got["model"] == "claude-sonnet-5-5" and got["max_tokens"] == 512


def test_openai_content_parts_tool_calls_and_user(client, upstream):
    data_uri = "data:image/png;base64,iVBORw0KGgo" + AWS
    body = {
        "model": "gpt-4o",
        "user": EMAIL,
        "messages": [
            {"role": "user", "name": "jane_doe", "content": [
                {"type": "text", "text": f"card {CARD}"},
                {"type": "image_url", "image_url": {"url": data_uri, "detail": "low"}},
            ]},
            {"role": "assistant", "tool_calls": [{"id": "call_1", "type": "function", "function": {
                "name": "lookup_customer", "arguments": json.dumps({"ssn": SSN})}}]},
        ],
        "tools": [{"type": "function", "function": {"name": "lookup_customer", "parameters": {"type": "object"}}}],
    }
    client.post("/v1/chat/completions", json=body)
    got = json.loads(upstream.last.content)
    assert got["user"] == "[REDACTED:EMAIL_ADDRESS]"
    parts = got["messages"][0]["content"]
    assert parts[0]["text"] == "card [REDACTED:CREDIT_CARD]"
    assert parts[1]["image_url"]["url"] == data_uri
    assert got["messages"][0]["name"] == "jane_doe"
    call = got["messages"][1]["tool_calls"][0]
    assert call["function"]["name"] == "lookup_customer" and call["id"] == "call_1"
    assert json.loads(call["function"]["arguments"]) == {"ssn": "[REDACTED:US_SSN]"}
    assert got["tools"] == body["tools"]


def test_data_prefix_in_prose_is_still_scanned(client, upstream):
    client.post("/v1/responses", json={"model": "gpt-4o", "input": f"data: the key is {AWS}",
                                       "instructions": f"reply to {EMAIL}"})
    got = json.loads(upstream.last.content)
    assert got == {"model": "gpt-4o", "input": "data: the key is [REDACTED:AWS_ACCESS_KEY_ID]",
                   "instructions": "reply to [REDACTED:EMAIL_ADDRESS]"}


def test_multipart_upload_text_parts_redacted_binary_untouched(client, upstream):
    jsonl = (json.dumps({"custom_id": "1", "body": {"messages": [{"role": "user", "content": f"key {AWS}"}]}})
             + "\n").encode()
    png = b"\x89PNG\r\n\x1a\n\x00\xff" + CARD.encode() + b"\xfe"
    r = client.post("/v1/files", data={"purpose": "batch"},
                    files={"file": ("batch.jsonl", jsonl, "application/jsonl"), "image": ("x.png", png, "image/png")})
    assert r.status_code == 200
    sent = upstream.last
    assert sent.headers["content-type"].startswith("multipart/form-data; boundary=")
    assert AWS.encode() not in sent.content and b"[REDACTED:AWS_ACCESS_KEY_ID]" in sent.content
    assert png in sent.content and b'name="purpose"\r\n\r\nbatch\r\n' in sent.content
    assert r.headers["x-egressiq-unscanned-bytes"] == str(len(png))
    # Still a well-formed multipart body the provider can parse.
    from email.parser import BytesParser

    msg = BytesParser().parsebytes(b"Content-Type: " + sent.headers["content-type"].encode() + b"\r\n\r\n" + sent.content)
    payloads = {p.get_param("name", header="content-disposition"): p.get_payload(decode=True) for p in msg.get_payload()}
    assert payloads["image"] == png and payloads["purpose"] == b"batch"
    assert json.loads(payloads["file"])["body"]["messages"][0]["content"] == "key [REDACTED:AWS_ACCESS_KEY_ID]"


def test_text_body_redacted_binary_body_passes_unscanned(client, upstream):
    client.post("/v1/notes", content=f"ssn {SSN}".encode(), headers={"Content-Type": "text/plain"})
    assert upstream.requests[-1].content == b"ssn [REDACTED:US_SSN]"
    audio = b"ID3\x04\x00\xff\xfe" + SSN.encode()
    r = client.post("/v1/audio/raw", content=audio, headers={"Content-Type": "audio/mpeg"})
    assert upstream.requests[-1].content == audio
    assert r.headers["x-egressiq-unscanned-bytes"] == str(len(audio))


def test_custom_rules_apply(upstream, tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"version": "2026.11.0", "detectors": [
        {"name": "TICKET_ID", "category": "infrastructure", "severity": "low", "pattern": r"\bTCK-\d{4}\b"}]}))
    with _client(upstream, rules=load_rules(str(path), strict=True)) as c:
        r = c.post("/v1/chat/completions", json={"messages": [{"role": "user", "content": "see TCK-1234"}]})
        assert c.get("/egressiq/health").json()["rules_version"] == "2026.11.0"
    assert json.loads(upstream.last.content)["messages"][0]["content"] == "see [REDACTED:TICKET_ID]"
    assert r.headers["x-egressiq-ruleset"] == "2026.11.0"


# ── Pass-through ─────────────────────────────────────────────────────────
def test_get_passthrough(client, upstream):
    r = client.get("/v1/models", headers={"Authorization": "Bearer sk-test"})
    assert r.status_code == 200
    assert upstream.last.method == "GET" and upstream.last.content == b""
    assert "content-length" not in upstream.last.headers
    assert str(upstream.last.url) == f"{UPSTREAM}/v1/models"


def test_error_status_body_and_headers_relayed():
    error = {"error": {"type": "rate_limit_error", "message": "slow down"}}
    up = Upstream(lambda req: reply(429, error, headers=[
        ("retry-after", "7"), ("set-cookie", "a=1"), ("set-cookie", "b=2"), ("keep-alive", "timeout=5")]))
    with _client(up) as c:
        r = c.post("/v1/chat/completions", json={"messages": []})
    assert r.status_code == 429 and r.json() == error
    assert r.headers["retry-after"] == "7"
    assert r.headers.get_list("set-cookie") == ["a=1", "b=2"]
    assert "keep-alive" not in r.headers


def test_compressed_upstream_response_relayed_raw():
    payload = json.dumps(COMPLETION).encode()
    up = Upstream(lambda req: reply(content=gzip.compress(payload),
                                    headers=[("content-encoding", "gzip"), ("content-type", "application/json")]))
    with _client(up) as c:
        r = c.post("/v1/chat/completions", json={"messages": []})
    assert r.json() == COMPLETION


def test_hop_by_hop_request_headers_dropped(client, upstream):
    client.post("/v1/chat/completions", json={}, headers={"Proxy-Authorization": "Basic x", "TE": "trailers",
                                                          "X-Trace": "keep"})
    sent = upstream.last.headers
    assert "proxy-authorization" not in sent and "te" not in sent and sent["x-trace"] == "keep"


def test_upstream_base_path_and_trailing_v1(upstream):
    with _client(upstream, base="https://gw.example.test/openai/v1/") as c:
        c.post("/v1/chat/completions", json={})
    assert str(upstream.last.url) == "https://gw.example.test/openai/v1/chat/completions"


# ── Streaming ────────────────────────────────────────────────────────────
EVENTS = [b'data: {"choices":[{"delta":{"content":"Hel"}}]}\n\n', b'data: {"choices":[{"delta":{"content":"lo"}}]}\n\n',
          b"data: [DONE]\n\n"]


def test_streaming_response_relayed():
    up = Upstream(lambda req: reply(chunks=EVENTS, headers=[("content-type", "text/event-stream")]))
    with _client(up) as c, c.stream("POST", "/v1/chat/completions",
                                    json={"stream": True, "messages": [{"role": "user", "content": SSN}]}) as r:
        assert r.headers["content-type"] == "text/event-stream"
        assert b"".join(r.iter_bytes()) == b"".join(EVENTS)
    assert json.loads(up.last.content)["messages"][0]["content"] == "[REDACTED:US_SSN]"


@pytest.fixture
def slow_sse_upstream():
    """A real HTTP upstream that sends one event, then blocks until the test releases it."""
    release, received = threading.Event(), []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(EVENTS[0])
            self.wfile.flush()
            release.wait(10)
            for e in EVENTS[1:]:
                self.wfile.write(e)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", release, received
    release.set()
    server.shutdown()
    server.server_close()


@pytest.fixture
def live_gateway():
    uvicorn = pytest.importorskip("uvicorn")
    servers = []

    def start(app):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="on"))
        threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True).start()
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started
        servers.append(server)
        return f"http://127.0.0.1:{sock.getsockname()[1]}"

    yield start
    for server in servers:
        server.should_exit = True


def test_streaming_is_incremental_over_real_sockets(slow_sse_upstream, live_gateway):
    """The first event reaches the client while the upstream is still mid-response."""
    upstream_url, release, received = slow_sse_upstream
    url = live_gateway(create_app(upstream_url))
    body = {"stream": True, "messages": [{"role": "user", "content": f"key {AWS}"}]}
    with httpx.Client(timeout=10) as http, http.stream("POST", url + "/v1/chat/completions", json=body) as r:
        stream = r.iter_raw()
        first = next(stream)
        assert not release.is_set()
        assert first == EVENTS[0]
        release.set()
        assert first + b"".join(stream) == b"".join(EVENTS)
    assert AWS.encode() not in received[0] and b"[REDACTED:AWS_ACCESS_KEY_ID]" in received[0]


# ── Fail closed ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("content,status", [
    (b'{"messages": [', 400),
    (b"\xff\xfe{}", 400),
    (b"[" * 100000 + b"]" * 100000, 400),
])
def test_unscannable_json_is_rejected_not_forwarded(client, upstream, content, status):
    r = client.post("/v1/chat/completions", content=content, headers={"Content-Type": "application/json"})
    assert r.status_code == status
    assert r.json()["error"]["type"] == "egressiq_gateway_error"
    assert upstream.requests == []


def test_compressed_request_rejected(client, upstream):
    r = client.post("/v1/chat/completions", content=gzip.compress(f'{{"x":"{SSN}"}}'.encode()),
                    headers={"Content-Type": "application/json", "Content-Encoding": "gzip"})
    assert r.status_code == 415 and upstream.requests == []


def test_multipart_without_boundary_rejected(client, upstream):
    r = client.post("/v1/files", content=b"--x\r\n\r\nssn\r\n--x--", headers={"Content-Type": "multipart/form-data"})
    assert r.status_code == 400 and upstream.requests == []


@pytest.mark.parametrize("exc,status", [(httpx.ConnectError, 502), (httpx.ReadTimeout, 504)])
def test_upstream_failures(exc, status):
    def fail(request):
        raise exc("boom", request=request)

    with _client(Upstream(fail)) as c:
        r = c.post("/v1/chat/completions", json={"messages": []})
    assert r.status_code == status and r.json()["error"]["type"] == "egressiq_gateway_error"


# ── Operations ───────────────────────────────────────────────────────────
def test_health(client):
    assert client.get("/egressiq/health").json() == {
        "status": "ok", "upstream": UPSTREAM, "rules_version": load_rules().version, "detectors": len(DETECTORS)}


def test_logs_have_counts_never_values(client, caplog):
    with caplog.at_level(logging.INFO, logger="egressiq.gateway"):
        client.post("/v1/chat/completions", json={"messages": [{"role": "user", "content": f"{AWS} {CARD} {SSN}"}]})
    assert "AWS_ACCESS_KEY_ID x1" in caplog.text and "redacted 3" in caplog.text
    assert not [v for v in (AWS, CARD, SSN, "IOSFODNN7") if v in caplog.text]


@pytest.mark.parametrize("url,want", [
    ("https://api.openai.com", "https://api.openai.com"),
    ("https://api.openai.com/v1/", "https://api.openai.com"),
    ("https://gw.example.com/openai/v1", "https://gw.example.com/openai"),
    ("http://localhost:11434", "http://localhost:11434"),
    ("http://[::1]:8000/", "http://[::1]:8000"),
])
def test_normalize_upstream(url, want):
    assert normalize_upstream(url) == want


@pytest.mark.parametrize("url", ["api.openai.com", "ftp://x.test", "http://api.openai.com",
                                 "https://user:pw@api.openai.com", "https://api.openai.com?x=1"])
def test_normalize_upstream_rejects(url):
    with pytest.raises(ValueError):
        normalize_upstream(url)


def test_insecure_upstream_needs_opt_in():
    assert normalize_upstream("http://vllm.internal:8000", allow_insecure=True) == "http://vllm.internal:8000"


def test_cli_launches_gateway(monkeypatch, capsys):
    uvicorn = pytest.importorskip("uvicorn")
    seen = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(app=app, **kw))
    monkeypatch.setattr(gateway.log, "handlers", list(gateway.log.handlers))
    assert cli.main(["gateway", "--port", "9999", "--upstream", "https://api.anthropic.com/v1"]) == 0
    assert seen["port"] == 9999 and seen["host"] == "127.0.0.1"
    assert seen["app"].state.upstream == "https://api.anthropic.com"
    assert "ANTHROPIC_BASE_URL=http://127.0.0.1:9999" in capsys.readouterr().out


def test_cli_rejects_plain_http_upstream(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["gateway", "--upstream", "http://api.openai.com"])
    assert exc.value.code == 2 and "plain-http" in capsys.readouterr().err


# ── Overhead ─────────────────────────────────────────────────────────────
def _best_ms(fn, runs=200):
    best = float("inf")
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        fn()
        best = min(best, time.perf_counter_ns() - t0)
    return best / 1e6


@pytest.mark.parametrize("secrets", [True, False])
def test_overhead_beyond_scanner_is_json_only(secrets):
    """Gateway CPU per request = the scanner's work + JSON parse (+ serialize when something changed)."""
    prose = "Summarise the roadmap and list open questions about latency budgets and staffing. " * 5
    contents = [prose + (f" key={AWS} card {CARD} ssn {SSN}" if secrets else "") for _ in range(8)]
    raw = json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": c} for c in contents]}).encode()
    assert 3500 < len(raw) < 4500  # a ~4 KB request

    scanner_ms = _best_ms(lambda: [redact(c) for c in contents])
    gateway_ms = _best_ms(lambda: sanitize_body(raw, "application/json", DETECTORS))
    assert sum(sanitize_body(raw, "application/json", DETECTORS).counts.values()) == (24 if secrets else 0)
    assert gateway_ms - scanner_ms < 0.15, (gateway_ms, scanner_ms)
