"""EgressIQ command-line interface.

Examples:
    python cli.py --file app.log                      # findings summary
    python cli.py --file app.log --dry-run            # sanitized text -> stdout
    python cli.py --file app.log --export-pdf         # egressiq_audit_report.pdf
    cat prompt.txt | python cli.py --dry-run          # read from stdin
    python cli.py --file app.log --rules policy.yaml  # custom/override detectors
    python cli.py web [--port 8000] [--open]          # launch the demo web UI
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional, TextIO

from scanner import Finding, RuleSet, load_rules, redact, scan

DEFAULT_PDF = "egressiq_audit_report.pdf"


def load_rules_or_warn(path: Optional[str]) -> RuleSet:
    """load_rules(), with any rejected-file problem printed to stderr (shared with `egressiq web`)."""
    rules = load_rules(path)
    for err in rules.errors:
        print(f"egressiq: warning: ignoring rule file, using built-in rules: {err}", file=sys.stderr)
    return rules


def _print_summary(findings: List[Finding], source: str, out: TextIO) -> None:
    if not findings:
        print(f"EgressIQ: no sensitive data found in {source}", file=out)
        return
    print(f"EgressIQ: {len(findings)} finding(s) in {source}", file=out)
    for f in findings:
        print(f"  line {f.line:>5}  {f.severity:<8}  {f.detector:<22}  {f.masked}", file=out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="egressiq",
        description="Scan text for secrets and PII and redact them before GenAI egress.",
    )
    p.add_argument("--file", metavar="PATH", help="text/log file to audit (default: stdin; '-' also means stdin)")
    p.add_argument(
        "--export-pdf", metavar="OUT", nargs="?", const=DEFAULT_PDF,
        help=f"write an executive audit PDF (default name: {DEFAULT_PDF})",
    )
    p.add_argument(
        "--rules", metavar="PATH", default=os.environ.get("EGRESSIQ_RULES"),
        help="JSON/YAML rule file merged over the built-in detectors (default: $EGRESSIQ_RULES)",
    )
    p.add_argument("--dry-run", action="store_true", help="write the sanitized text to stdout")
    p.add_argument(
        "--fail-on-findings", action="store_true",
        help="exit with status 1 when anything is detected (for CI / pre-commit gating)",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["web"]:
        try:
            from web.server import run
        except ImportError as exc:
            print(f"egressiq: web UI needs extra dependencies ({exc.name}); "
                  "install with: pip install -e '.[web]'", file=sys.stderr)
            return 2
        return run(argv[1:])

    args = build_parser().parse_args(argv)
    rules = load_rules_or_warn(args.rules)

    if args.file and args.file != "-":
        source = args.file
        try:
            with open(args.file, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            print(f"egressiq: cannot read {args.file}: {exc.strerror}", file=sys.stderr)
            return 2
    else:
        source = "<stdin>"
        text = sys.stdin.read()

    findings = scan(text, rules.detectors)

    if args.dry_run:
        sanitized, _ = redact(text, findings)
        sys.stdout.write(sanitized)
        sys.stdout.flush()
        # Keep stdout a clean sanitized stream; diagnostics go to stderr.
        _print_summary(findings, source, sys.stderr)
    else:
        _print_summary(findings, source, sys.stdout)

    if args.export_pdf:
        from report import audit_record, build_pdf

        record = audit_record(findings, text, rules)
        path = build_pdf(findings, source, text, args.export_pdf, rules=rules, record=record)
        print(f"EgressIQ: audit report written to {path}", file=sys.stderr)
        print(f"EgressIQ: audit hash {record['audit_hash']} (generated {record['generated_at']}, "
              f"ruleset {record['ruleset_version']})", file=sys.stderr)

    return 1 if args.fail_on_findings and findings else 0


def main_entry() -> None:
    sys.exit(main())


if __name__ == "__main__":
    main_entry()
