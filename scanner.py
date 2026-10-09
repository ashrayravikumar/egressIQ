"""EgressIQ scanner: detect and redact sensitive data in GenAI egress traffic.

Detectors are registered in DETECTORS. Each is a precompiled regex plus an
optional validator (e.g. Luhn for card numbers). To add a detector, append a
Detector to DETECTORS and add positive/negative samples in tests/samples.py;
tests/test_patterns.py fails if a detector has no samples.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Pattern, Tuple

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class Detector:
    name: str
    category: str  # "credential" | "pii" | "infrastructure"
    severity: str
    pattern: Pattern[str]
    description: str
    group: int = 0  # capture group holding the sensitive value
    validator: Optional[Callable[[str], bool]] = None


@dataclass(frozen=True)
class Finding:
    detector: str
    category: str
    severity: str
    start: int
    end: int
    line: int
    value: str

    @property
    def masked(self) -> str:
        """Safe-to-display preview; never put raw values in reports."""
        v = self.value
        if len(v) <= 8:
            return "*" * len(v)
        return f"{v[:4]}{'*' * min(len(v) - 4, 12)}"


def _luhn_valid(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_DB_SCHEMES = (
    r"postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|mssql|sqlserver"
    r"|oracle|cockroachdb|clickhouse|amqps?|snowflake"
)

DETECTORS: List[Detector] = [
    Detector(
        name="AWS_ACCESS_KEY_ID",
        category="credential",
        severity="critical",
        pattern=re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA|A3T[A-Z0-9])[A-Z0-9]{16}\b"),
        description="AWS access key ID (long-term AKIA or temporary ASIA, etc.)",
    ),
    Detector(
        name="AWS_SECRET_ACCESS_KEY",
        category="credential",
        severity="critical",
        pattern=re.compile(
            r"(?i)(?:(?:aws_?)?secret_?access_?key|aws_?secret_?key)[\"']?\s*[:=]\s*[\"']?"
            r"([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"
        ),
        group=1,
        description="AWS secret access key assigned to a recognisable key name",
    ),
    Detector(
        name="GITHUB_TOKEN",
        category="credential",
        severity="critical",
        pattern=re.compile(
            r"\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82,255})\b"
        ),
        description="GitHub classic (ghp/gho/ghu/ghs/ghr) or fine-grained (github_pat_) token",
    ),
    Detector(
        name="JWT",
        category="credential",
        severity="high",
        pattern=re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*"
        ),
        description="JSON Web Token (header.payload.signature; unsigned alg=none included)",
    ),
    Detector(
        name="PRIVATE_KEY",
        category="credential",
        severity="critical",
        pattern=re.compile(
            r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----"
        ),
        description="PEM-encoded private key block",
    ),
    Detector(
        name="DB_CONNECTION_STRING",
        category="infrastructure",
        severity="critical",
        pattern=re.compile(
            rf"(?i)\b(?:jdbc:)?(?:{_DB_SCHEMES})://[^\s'\"<>`]+"
            r"|\b(?:Server|Data Source|Host)=[^;\r\n]+;[^\r\n]*?(?:Password|Pwd)=[^;\r\n]+;?"
        ),
        description="Database URI or ADO.NET-style connection string",
    ),
    Detector(
        name="EMAIL_ADDRESS",
        category="pii",
        severity="medium",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"),
        description="Email address",
    ),
    Detector(
        name="US_SSN",
        category="pii",
        severity="high",
        pattern=re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        description="US Social Security Number (dashed format)",
    ),
    Detector(
        name="CREDIT_CARD",
        category="pii",
        severity="high",
        pattern=re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])"),
        validator=_luhn_valid,
        description="Payment card number (13-19 digits, Luhn-validated)",
    ),
]

DETECTORS_BY_NAME: Dict[str, Detector] = {d.name: d for d in DETECTORS}


def _line_index(text: str) -> List[int]:
    starts = [0]
    starts.extend(m.end() for m in re.finditer(r"\n", text))
    return starts


def _line_of(starts: List[int], offset: int) -> int:
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= offset:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


def scan(text: str, detectors: Optional[List[Detector]] = None) -> List[Finding]:
    """Return non-overlapping findings ordered by position.

    When matches overlap (e.g. an email inside a DB URI), the higher-severity,
    then longer, match wins so the whole secret is redacted.
    """
    detectors = DETECTORS if detectors is None else detectors
    candidates: List[Finding] = []
    starts = _line_index(text)
    for det in detectors:
        for m in det.pattern.finditer(text):
            value = m.group(det.group)
            if not value or (det.validator and not det.validator(value)):
                continue
            s, e = m.span(det.group)
            candidates.append(
                Finding(det.name, det.category, det.severity, s, e, _line_of(starts, s), value)
            )

    candidates.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -(f.end - f.start), f.start))
    chosen: List[Finding] = []
    for f in candidates:
        if all(f.end <= c.start or f.start >= c.end for c in chosen):
            chosen.append(f)
    chosen.sort(key=lambda f: f.start)
    return chosen


def redact(text: str, findings: Optional[List[Finding]] = None) -> Tuple[str, List[Finding]]:
    """Replace each finding with a [REDACTED:<DETECTOR>] token."""
    findings = scan(text) if findings is None else findings
    out: List[str] = []
    cursor = 0
    for f in findings:
        out.append(text[cursor:f.start])
        out.append(f"[REDACTED:{f.detector}]")
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out), findings


if __name__ == "__main__":
    demo = (
        "user=jane.doe@example.com ssn=123-45-6789 card=4111 1111 1111 1111\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "DATABASE_URL=postgres://admin:hunter2@db.internal:5432/prod\n"
    )
    sanitized, found = redact(demo)
    print(sanitized)
    for f in found:
        print(f"line {f.line:>3}  {f.severity:<8}  {f.detector:<22}  {f.masked}")
