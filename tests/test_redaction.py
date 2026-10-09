from scanner import redact, scan
from tests.samples import STANDALONE


def test_mixed_payload_redacts_everything():
    values = [vals[0] for vals in STANDALONE.values()]
    text = "\n".join(f"item {i}: {v}" for i, v in enumerate(values))
    sanitized, findings = redact(text)
    for v in values:
        assert v not in sanitized
    assert len(findings) == len(values)


def test_overlap_prefers_higher_severity_and_longer_match():
    text = "DATABASE_URL=postgres://jane.doe@example.com:pw@db/prod"
    findings = scan(text)
    assert [f.detector for f in findings] == ["DB_CONNECTION_STRING"]


def test_line_numbers():
    text = "ok\nok\nssn 123-45-6789\n"
    (f,) = scan(text)
    assert f.line == 3


def test_masked_preview_never_leaks_full_value():
    secret = "AKIA" + "IOSFODNN7EXAMPLE"
    (f,) = scan(secret)
    assert f.masked.startswith("AKIA")
    assert secret not in f.masked
    assert "IOSFODNN7EXAMPLE" not in f.masked


def test_clean_text_untouched():
    text = "Summarise the Q3 roadmap for the platform team."
    sanitized, findings = redact(text)
    assert sanitized == text and findings == []
