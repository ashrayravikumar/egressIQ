"""EgressIQ command-line interface.

Examples:
    python cli.py --file app.log                      # findings summary
    python cli.py --file app.log --dry-run            # sanitized text -> stdout
    python cli.py --file app.log --export-pdf         # egressiq_audit_report.pdf
    cat prompt.txt | python cli.py --dry-run          # read from stdin
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional, TextIO

from scanner import Finding, redact, scan

DEFAULT_PDF = "egressiq_audit_report.pdf"


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
    p.add_argument("--dry-run", action="store_true", help="write the sanitized text to stdout")
    p.add_argument(
        "--fail-on-findings", action="store_true",
        help="exit with status 1 when anything is detected (for CI / pre-commit gating)",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

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

    findings = scan(text)

    if args.dry_run:
        sanitized, _ = redact(text, findings)
        sys.stdout.write(sanitized)
        sys.stdout.flush()
        # Keep stdout a clean sanitized stream; diagnostics go to stderr.
        _print_summary(findings, source, sys.stderr)
    else:
        _print_summary(findings, source, sys.stdout)

    if args.export_pdf:
        from report import build_pdf

        path = build_pdf(findings, source, text, args.export_pdf)
        print(f"EgressIQ: audit report written to {path}", file=sys.stderr)

    return 1 if args.fail_on_findings and findings else 0


def main_entry() -> None:
    sys.exit(main())


if __name__ == "__main__":
    main_entry()
