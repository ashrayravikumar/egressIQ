"""External rule files: load_rules() merging, overrides, fallback, and the update check."""

import io
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import cli
import scanner
from report import build_pdf, regulatory_exposure
from scanner import COMPLIANCE_IMPACT, DETECTORS, RulesError, check_rule_updates, load_rules, redact, scan

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
PROJECT_RULE = {
    "name": "INTERNAL_PROJECT_CODE",
    "category": "infrastructure",
    "severity": "high",
    "pattern": r"\bPRJ-\d{6}\b",
    "description": "Internal project codename",
    "compliance": "Internal: Trade Secret",
}
YAML_POLICY = r"""
version: "2026.11.0"
disable: [PHONE_NUMBER]
detectors:
  - name: INTERNAL_PROJECT_CODE
    category: infrastructure
    severity: high
    pattern: '\bPRJ-\d{6}\b'
    compliance: "Internal: Trade Secret"
  - name: EMAIL_ADDRESS
    severity: critical
"""


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content if isinstance(content, str) else json.dumps(content))
    return str(path)


def _names(rules):
    return [d.name for d in rules.detectors]


# ── Defaults ─────────────────────────────────────────────────────────────
def test_defaults_are_the_module_detectors_and_cached():
    rules = load_rules()
    assert rules is load_rules()  # compiled once at import, never per call
    assert rules.detectors is DETECTORS
    assert rules.compliance == COMPLIANCE_IMPACT
    assert rules.source == "built-in" and rules.errors == ()


def test_default_rules_are_plain_data():
    """DEFAULT_RULES has the same shape as a rule file, so it can be dumped and reloaded."""
    json.dumps(scanner.DEFAULT_RULES)


# ── Custom rules ─────────────────────────────────────────────────────────
def test_json_custom_rule_added_to_defaults(tmp_path):
    rules = load_rules(_write(tmp_path, "policy.json", {"detectors": [PROJECT_RULE]}), strict=True)
    assert _names(rules) == _names(load_rules()) + ["INTERNAL_PROJECT_CODE"]
    assert rules.version == f"{scanner.DEFAULT_RULES['version']}+custom"

    text = f"ship PRJ-004211 with key {AWS_KEY}"
    found = {f.detector: f for f in scan(text, rules.detectors)}
    assert set(found) == {"INTERNAL_PROJECT_CODE", "AWS_ACCESS_KEY_ID"}
    assert found["INTERNAL_PROJECT_CODE"].severity == "high"
    assert redact(text, detectors=rules.detectors)[0] == (
        "ship [REDACTED:INTERNAL_PROJECT_CODE] with key [REDACTED:AWS_ACCESS_KEY_ID]")
    # Defaults are untouched by loading a custom file.
    assert [f.detector for f in scan(text)] == ["AWS_ACCESS_KEY_ID"]


def test_yaml_policy_adds_overrides_and_disables(tmp_path):
    pytest.importorskip("yaml")
    rules = load_rules(_write(tmp_path, "policy.yaml", YAML_POLICY), strict=True)
    assert rules.version == "2026.11.0"
    assert "PHONE_NUMBER" not in _names(rules)
    assert rules.by_name["EMAIL_ADDRESS"].severity == "critical"
    assert rules.by_name["EMAIL_ADDRESS"].pattern.pattern == scanner.DETECTORS_BY_NAME["EMAIL_ADDRESS"].pattern.pattern
    found = {f.detector: f.severity for f in scan("PRJ-123456 jane@example.com phone=+14155550198", rules.detectors)}
    assert found == {"INTERNAL_PROJECT_CODE": "high", "EMAIL_ADDRESS": "critical"}


def test_override_severity_keeps_other_fields(tmp_path):
    rules = load_rules(_write(tmp_path, "p.json", {"detectors": [{"name": "CREDIT_CARD", "severity": "critical"}]}),
                       strict=True)
    card = rules.by_name["CREDIT_CARD"]
    default = scanner.DETECTORS_BY_NAME["CREDIT_CARD"]
    assert card.severity == "critical"
    assert (card.pattern.pattern, card.validator, card.compliance) == (
        default.pattern.pattern, default.validator, default.compliance)
    assert [f.severity for f in scan("4111 1111 1111 1111", rules.detectors)] == ["critical"]
    assert scan("4111 1111 1111 1112", rules.detectors) == []  # Luhn validator still applied


def test_override_pattern(tmp_path):
    """Widen US_SSN to also catch undashed numbers."""
    rule = {"name": "US_SSN", "pattern": r"\b(?!000|666|9\d\d)\d{3}-?(?!00)\d{2}-?(?!0000)\d{4}\b"}
    rules = load_rules(_write(tmp_path, "p.json", {"detectors": [rule]}), strict=True)
    assert [f.value for f in scan("ssn 123456789", rules.detectors)] == ["123456789"]
    assert scan("ssn 123456789") == []  # built-in still dashed-only


def test_pattern_override_resets_capture_group(tmp_path):
    """AWS_SECRET_ACCESS_KEY reports group 1; a replacement pattern without groups must still load."""
    rule = {"name": "AWS_SECRET_ACCESS_KEY", "pattern": r"\bSECRET-[A-Z]{8}\b"}
    rules = load_rules(_write(tmp_path, "p.json", {"detectors": [rule]}), strict=True)
    assert rules.by_name["AWS_SECRET_ACCESS_KEY"].group == 0
    assert [f.value for f in scan("x SECRET-ABCDEFGH y", rules.detectors)] == ["SECRET-ABCDEFGH"]


def test_extends_defaults_false_uses_only_custom_rules(tmp_path):
    rules = load_rules(_write(tmp_path, "p.json", {"extends_defaults": False, "detectors": [PROJECT_RULE]}),
                       strict=True)
    assert _names(rules) == ["INTERNAL_PROJECT_CODE"]
    assert rules.version == "custom"
    assert scan(f"key {AWS_KEY}", rules.detectors) == []


def test_custom_rule_without_compliance_gets_label(tmp_path):
    rule = {k: v for k, v in PROJECT_RULE.items() if k != "compliance"}
    rules = load_rules(_write(tmp_path, "p.json", {"detectors": [rule]}), strict=True)
    assert rules.compliance["INTERNAL_PROJECT_CODE"] == "Custom policy"


# ── Malformed files fall back to defaults ────────────────────────────────
MALFORMED = {
    "bad-json.json": '{"detectors": [',
    "not-a-mapping.json": "[1, 2]",
    "bad-regex.json": {"detectors": [{**PROJECT_RULE, "pattern": "PRJ-(\\d+"}]},
    "bad-severity.json": {"detectors": [{**PROJECT_RULE, "severity": "urgent"}]},
    "bad-category.json": {"detectors": [{**PROJECT_RULE, "category": "secret"}]},
    "typo-field.json": {"detectors": [{"name": "EMAIL_ADDRESS", "severty": "low"}]},
    "typo-top-level.json": {"detector": [PROJECT_RULE]},
    "missing-pattern.json": {"detectors": [{"name": "NEW_RULE", "category": "pii", "severity": "low"}]},
    "bad-name.json": {"detectors": [{**PROJECT_RULE, "name": "has spaces"}]},
    "bad-group.json": {"detectors": [{**PROJECT_RULE, "group": 3}]},
    "bad-validator.json": {"detectors": [{**PROJECT_RULE, "validator": "os.system"}]},
    "unknown-disable.json": {"disable": ["NOT_A_DETECTOR"]},
    "empty-policy.json": {"extends_defaults": False, "detectors": []},
    "long-compliance.json": {"detectors": [{**PROJECT_RULE, "compliance": "X" * 41}]},
}


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_malformed_file_falls_back_to_defaults(tmp_path, name):
    path = _write(tmp_path, name, MALFORMED[name])
    rules = load_rules(path)
    assert rules.detectors is DETECTORS and rules.source == "built-in"
    assert len(rules.errors) == 1 and rules.errors[0].startswith(path)
    with pytest.raises(RulesError):
        load_rules(path, strict=True)


def test_one_bad_rule_rejects_whole_file(tmp_path):
    """Never half-apply a policy: a valid rule next to a broken one is not loaded either."""
    rules = load_rules(_write(tmp_path, "p.json", {"detectors": [PROJECT_RULE, {**PROJECT_RULE, "name": "X_", "pattern": "("}]}))
    assert "INTERNAL_PROJECT_CODE" not in _names(rules) and rules.errors


def test_malformed_yaml_falls_back(tmp_path):
    pytest.importorskip("yaml")
    rules = load_rules(_write(tmp_path, "p.yaml", "detectors: [unclosed"))
    assert rules.detectors is DETECTORS and "invalid YAML" in rules.errors[0]


def test_missing_file_falls_back(tmp_path):
    rules = load_rules(str(tmp_path / "nope.json"))
    assert rules.detectors is DETECTORS and rules.errors


# ── Reports, CLI and web use the active rules ────────────────────────────
def test_custom_framework_flows_into_report(tmp_path):
    pypdf = pytest.importorskip("pypdf")
    rules = load_rules(_write(tmp_path, "p.json", {"detectors": [PROJECT_RULE]}), strict=True)
    text = f"PRJ-004211 and {AWS_KEY}"
    findings = scan(text, rules.detectors)
    assert [e["framework"] for e in regulatory_exposure(findings, rules.compliance)] == [
        "SOC 2 CC6.6 (Secrets Exposure)", "Internal: Trade Secret"]
    out = tmp_path / "r.pdf"
    build_pdf(findings, "t.log", text, str(out), compliance=rules.compliance)
    pdf_text = "\n".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(out.read_bytes())).pages)
    assert "INTERNAL_PROJECT_CODE" in pdf_text and "Internal: Trade Secret" in pdf_text
    assert "PRJ-004211" not in pdf_text


def test_cli_rules_flag(tmp_path, capsys, monkeypatch):
    path = _write(tmp_path, "p.json", {"detectors": [PROJECT_RULE]})
    monkeypatch.setattr("sys.stdin", io.StringIO("deploy PRJ-004211 now\n"))
    assert cli.main(["--rules", path, "--dry-run"]) == 0
    assert capsys.readouterr().out == "deploy [REDACTED:INTERNAL_PROJECT_CODE] now\n"


def test_cli_rules_from_env(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("EGRESSIQ_RULES", _write(tmp_path, "p.json", {"detectors": [PROJECT_RULE]}))
    monkeypatch.setattr("sys.stdin", io.StringIO("PRJ-004211"))
    assert cli.main(["--dry-run", "--fail-on-findings"]) == 1
    assert "[REDACTED:INTERNAL_PROJECT_CODE]" in capsys.readouterr().out


def test_cli_malformed_rules_warns_and_still_scans(tmp_path, capsys, monkeypatch):
    path = _write(tmp_path, "p.json", "{oops")
    monkeypatch.setattr("sys.stdin", io.StringIO(f"key {AWS_KEY}\n"))
    assert cli.main(["--rules", path, "--dry-run"]) == 0
    out = capsys.readouterr()
    assert out.out == "key [REDACTED:AWS_ACCESS_KEY_ID]\n"
    assert "warning: ignoring rule file, using built-in rules" in out.err and path in out.err


def test_web_uses_loaded_rules(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    pytest.importorskip("multipart")
    from fastapi.testclient import TestClient

    from web import server

    rules = load_rules(_write(tmp_path, "p.json", {"version": "9.9", "detectors": [PROJECT_RULE]}), strict=True)
    monkeypatch.setattr(server, "RULES", rules)
    client = TestClient(server.app)
    health = client.get("/api/health").json()
    assert (health["rules_version"], health["detectors"], health["rules_source"]) == ("9.9", len(DETECTORS) + 1, "p.json")
    r = client.post("/api/scan", json={"text": "PRJ-004211"}).json()
    assert [(f["detector"], f["regulation"]) for f in r["findings"]] == [("INTERNAL_PROJECT_CODE", "Internal: Trade Secret")]
    assert r["stats"]["regulatory"][0]["framework"] == "Internal: Trade Secret"
    assert client.post("/api/report", json={"text": "PRJ-004211"}).status_code == 200


# ── check_rule_updates ───────────────────────────────────────────────────
@pytest.fixture
def rules_endpoint():
    """Local HTTP server; set .body / .delay on the returned state to shape responses."""
    state = type("State", (), {"body": b'{"version": "2026.11.0"}', "delay": 0.0, "hits": 0})()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state.hits += 1
            time.sleep(state.delay)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(state.body)

        def log_message(self, *args):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    state.url = f"http://127.0.0.1:{httpd.server_port}/rules/latest.json"
    yield state
    httpd.shutdown()
    httpd.server_close()


def test_update_available(rules_endpoint):
    assert check_rule_updates(rules_endpoint.url, "2026.10.0").result(5) == {"version": "2026.11.0"}


@pytest.mark.parametrize("current", ["2026.11.0", "2026.12.0", "2027.1"])
def test_no_update_when_current_or_newer(rules_endpoint, current):
    assert check_rule_updates(rules_endpoint.url, current).result(5) is None


def test_update_check_does_not_block(rules_endpoint):
    rules_endpoint.delay = 0.5
    t0 = time.perf_counter()
    future = check_rule_updates(rules_endpoint.url, "2026.10.0")
    scan(f"key {AWS_KEY}")  # scanning proceeds while the check is in flight
    assert time.perf_counter() - t0 < 0.2 and not future.done()
    assert future.result(5)["version"] == "2026.11.0"


@pytest.mark.parametrize("body", [b"not json", b'{"no_version": 1}', b'{"version": "latest"}', b"[]"])
def test_bad_manifest_resolves_none(rules_endpoint, body):
    rules_endpoint.body = body
    assert check_rule_updates(rules_endpoint.url, "2026.10.0").result(5) is None


def test_unreachable_endpoint_resolves_none():
    assert check_rule_updates("http://127.0.0.1:9/rules.json", "1.0", timeout=1).result(5) is None


@pytest.mark.parametrize("url", ["http://rules.example.com/latest.json", "file:///etc/passwd", "ftp://x/y"])
def test_non_https_remote_refused_without_request(url):
    assert check_rule_updates(url, "1.0").result(5) is None


def test_web_health_reports_rejected_file_without_server_path(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    pytest.importorskip("multipart")
    from fastapi.testclient import TestClient

    from web import server

    monkeypatch.setattr(server, "RULES", load_rules(_write(tmp_path, "broken.json", "{oops")))
    health = TestClient(server.app).get("/api/health").json()
    assert health["rules_source"] == "built-in" and health["detectors"] == len(DETECTORS)
    assert health["rules_errors"][0].startswith("broken.json: invalid JSON")
    assert str(tmp_path) not in str(health)
