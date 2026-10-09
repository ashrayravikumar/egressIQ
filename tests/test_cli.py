import io

import cli

LOG = (
    "2026-10-09 INFO user jane.doe@example.com logged in\n"
    "2026-10-09 DEBUG key=" + "AKIA" + "IOSFODNN7EXAMPLE" + "\n"
    "2026-10-09 INFO healthcheck ok\n"
)


def _write_log(tmp_path):
    p = tmp_path / "app.log"
    p.write_text(LOG)
    return p


def test_summary_default(tmp_path, capsys):
    rc = cli.main(["--file", str(_write_log(tmp_path))])
    out = capsys.readouterr().out
    assert rc == 0
    assert "2 finding(s)" in out
    assert "AWS_ACCESS_KEY_ID" in out and "EMAIL_ADDRESS" in out
    assert "IOSFODNN7EXAMPLE" not in out


def test_dry_run_stdout_is_only_sanitized_stream(tmp_path, capsys):
    rc = cli.main(["--file", str(_write_log(tmp_path)), "--dry-run"])
    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out == (
        "2026-10-09 INFO user [REDACTED:EMAIL_ADDRESS] logged in\n"
        "2026-10-09 DEBUG key=[REDACTED:AWS_ACCESS_KEY_ID]\n"
        "2026-10-09 INFO healthcheck ok\n"
    )
    assert "2 finding(s)" in captured.err


def test_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("ssn 123-45-6789"))
    rc = cli.main(["--dry-run"])
    assert rc == 0
    assert capsys.readouterr().out == "ssn [REDACTED:US_SSN]"


def test_export_pdf(tmp_path, capsys):
    out = tmp_path / "audit.pdf"
    rc = cli.main(["--file", str(_write_log(tmp_path)), "--export-pdf", str(out)])
    assert rc == 0
    data = out.read_bytes()
    assert data.startswith(b"%PDF")
    assert b"IOSFODNN7EXAMPLE" not in data


def test_export_pdf_default_name(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cli.main(["--file", str(_write_log(tmp_path)), "--export-pdf"])
    assert (tmp_path / cli.DEFAULT_PDF).read_bytes().startswith(b"%PDF")


def test_export_pdf_clean_input(tmp_path, capsys):
    src = tmp_path / "clean.txt"
    src.write_text("nothing to see here\n")
    out = tmp_path / "clean.pdf"
    assert cli.main(["--file", str(src), "--export-pdf", str(out)]) == 0
    assert out.read_bytes().startswith(b"%PDF")


def test_fail_on_findings(tmp_path, capsys):
    assert cli.main(["--file", str(_write_log(tmp_path)), "--fail-on-findings"]) == 1


def test_missing_file(tmp_path, capsys):
    rc = cli.main(["--file", str(tmp_path / "nope.log")])
    assert rc == 2
    assert "cannot read" in capsys.readouterr().err
