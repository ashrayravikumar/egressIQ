"""EgressIQ scanner: detect and redact sensitive data in GenAI egress traffic.

Built-in detectors live in DEFAULT_RULES (the same shape as a --rules JSON/YAML
file). load_rules() compiles them, or a custom file merged over them, into a
RuleSet once; scan() then just runs the precompiled regexes. To add a built-in
detector, append it to DEFAULT_RULES and add positive/negative samples in
tests/samples.py; tests/test_patterns.py fails if a detector has no samples.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from bisect import bisect_right
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Pattern, Tuple

if TYPE_CHECKING:
    from concurrent.futures import Future

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
    compliance: str = ""  # framework label for reports (scan() ignores it)
    # Cheap gates checked before the regex runs; the detector is skipped when they fail.
    # Every match must contain one of `hints` and match `prefilter`, or findings are lost.
    hints: Tuple[str, ...] = ()  # any one must occur in the text (lowercased when hints_ignore_case)
    hints_ignore_case: bool = False
    prefilter: Optional[Pattern[str]] = None  # fast regex (literal/charset first) that must match somewhere


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
# Every scheme spelling _DB_SCHEMES accepts, as "<scheme>://" (tests check the two stay in sync).
_DB_URI_HINTS = [
    f"{s}://" for s in ("postgres", "postgresql", "mysql", "mariadb", "mongodb", "mongodb+srv", "redis", "rediss",
                        "mssql", "sqlserver", "oracle", "cockroachdb", "clickhouse", "amqp", "amqps", "snowflake")
]

# NANP: area code and exchange start 2-9; parenthesised area code optional.
_NANP_AREA = r"(?:\([2-9]\d{2}\)[-. ]?|[2-9]\d{2}[-. ]?)"
_NANP_PLUS = rf"\+1[-. ]?{_NANP_AREA}[2-9]\d{{2}}[-. ]?\d{{4}}"
_NANP_SEPARATED = r"(?:1[-. ])?(?:\([2-9]\d{2}\)[-. ]?|[2-9]\d{2}[-. ])[2-9]\d{2}[-. ]\d{4}"
_NANP_KEYED = rf"(?:\+?1[-. ]?)?{_NANP_AREA}[2-9]\d{{2}}[-. ]?\d{{4}}"
_PHONE_KEY = r"(?i:phone|mobile|\bcell|fax|\btel)[\w.-]*[\"']?\s*[:=]\s*[\"']?"

_SECRETS_EXPOSURE = "SOC 2 CC6.6 (Secrets Exposure)"

# Validators referenced by name from rule files (code can't live in YAML/JSON).
VALIDATORS: Dict[str, Callable[[str], bool]] = {"luhn": _luhn_valid}

# Built-in policy, in the same shape a --rules file uses. "compliance" is reporting
# metadata only: scan()/redact() never read it.
DEFAULT_RULES: Dict[str, Any] = {
    "version": "2026.10.0",
    "detectors": [
        {
            "name": "AWS_ACCESS_KEY_ID",
            "category": "credential",
            "severity": "critical",
            # Same matches as \b(?:AKIA|ASIA|...)…, but starting with a literal lets the regex engine skip
            # straight to each "A"; (?<!\wA) is the leading word boundary.
            "pattern": r"A(?<!\wA)(?:KIA|SIA|BIA|CCA|GPA|IDA|ROA|IPA|NPA|NVA|PKA|3T[A-Z0-9])[A-Z0-9]{16}\b",
            "description": "AWS access key ID (long-term AKIA or temporary ASIA, etc.)",
            "compliance": _SECRETS_EXPOSURE,
        },
        {
            "name": "AWS_SECRET_ACCESS_KEY",
            "category": "credential",
            "severity": "critical",
            "pattern": (
                # (?=[as]) rejects most positions with one check (every match starts "aws" or "secret").
                r"(?i)(?=[as])(?:(?:aws_?)?secret_?access_?key|aws_?secret_?key)[\"']?\s*[:=]\s*[\"']?"
                r"([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"
            ),
            "group": 1,
            "hints": ["secret"],
            "hints_ignore_case": True,
            "description": "AWS secret access key assigned to a recognisable key name",
            "compliance": _SECRETS_EXPOSURE,
        },
        {
            "name": "GITHUB_TOKEN",
            "category": "credential",
            "severity": "critical",
            "pattern": r"g(?<!\wg)(?:h[pousr]_[A-Za-z0-9]{36,255}|ithub_pat_[A-Za-z0-9_]{82,255})\b",
            "description": "GitHub classic (ghp/gho/ghu/ghs/ghr) or fine-grained (github_pat_) token",
            "compliance": _SECRETS_EXPOSURE,
        },
        {
            "name": "JWT",
            "category": "credential",
            "severity": "high",
            "pattern": r"e(?<![A-Za-z0-9_-]e)yJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*",
            "description": "JSON Web Token (header.payload.signature; unsigned alg=none included)",
            "compliance": _SECRETS_EXPOSURE,
        },
        {
            "name": "PRIVATE_KEY",
            "category": "credential",
            "severity": "critical",
            "pattern": r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----",
            "hints": ["-----BEGIN"],
            "description": "PEM-encoded private key block",
            "compliance": _SECRETS_EXPOSURE,
        },
        {
            "name": "DB_CONNECTION_STRING",
            "category": "infrastructure",
            "severity": "critical",
            "pattern": (
                rf"(?i)\b(?:jdbc:)?(?:{_DB_SCHEMES})://[^\s'\"<>`]+"
                r"|\b(?:Server|Data Source|Host)=[^;\r\n]+;[^\r\n]*?(?:Password|Pwd)=[^;\r\n]+;?"
            ),
            "hints": [*_DB_URI_HINTS, "password=", "pwd="],
            "hints_ignore_case": True,
            "description": "Database URI or ADO.NET-style connection string",
            "compliance": _SECRETS_EXPOSURE,
        },
        {
            "name": "EMAIL_ADDRESS",
            "category": "pii",
            "severity": "medium",
            "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b",
            "hints": ["@"],
            "description": "Email address",
            "compliance": "GDPR / CCPA PII",
        },
        {
            "name": "PHONE_NUMBER",
            "category": "pii",
            "severity": "medium",
            # Group 1: optional phone-ish key (phone=, "mobile": , tel:). When present,
            # compact digits are accepted; bare 10-digit runs without a key or "+1"
            # are too often order IDs/timestamps to flag.
            # (?=…) lists every possible first character (key letters, "+", "(", digits), so most
            # positions are rejected with one check instead of trying the whole alternation.
            "pattern": (
                r"(?=[PpMmCcFfTt+(1-9])"
                rf"(?:({_PHONE_KEY})|(?<![\w+.-]))"
                rf"((?(1){_NANP_KEYED}|(?:{_NANP_PLUS}|{_NANP_SEPARATED})))"
                r"(?![\w-]|\.\d)"
            ),
            "group": 2,
            # Every form contains area code + exchange: "415-555", "(415) 555", "4155550198".
            "prefilter": r"[2-9]\d\d\)?[-. ]?[2-9]\d\d",
            "description": "North American phone number (formatted, +1 E.164, or compact after a phone/tel key)",
            "compliance": "GDPR / CCPA PII",
        },
        {
            "name": "US_SSN",
            "category": "pii",
            "severity": "high",
            "pattern": r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
            "prefilter": r"-\d\d-\d{4}",  # literal "-" first; dates like 2026-10-08 don't pass
            "description": "US Social Security Number (dashed format)",
            "compliance": "SOC 2 CC6.1 / GLBA",
        },
        {
            "name": "CREDIT_CARD",
            "category": "pii",
            "severity": "high",
            "pattern": r"(?=\d)(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])",
            "validator": "luhn",
            "prefilter": r"\d(?:[ -]?\d){12}",  # 13+ digits, single separators allowed
            "description": "Payment card number (13-19 digits, Luhn-validated)",
            "compliance": "PCI-DSS 4.0 Req 4.2 / 3.4",
        },
    ],
}

CATEGORIES = ("credential", "pii", "infrastructure")
_RULE_KEYS = {"name", "category", "severity", "pattern", "description", "group", "validator", "compliance",
              "hints", "hints_ignore_case", "prefilter"}
_FILE_KEYS = {"version", "extends_defaults", "disable", "detectors"}
_NAME_RE = re.compile(r"[A-Z][A-Z0-9_]{1,31}")  # shown in [REDACTED:NAME] tokens and fixed-width PDF columns
_MAX_COMPLIANCE_LEN = 40

log = logging.getLogger("egressiq.rules")
log.addHandler(logging.NullHandler())  # library: callers decide how to surface warnings


class RulesError(ValueError):
    """A rule file could not be read, parsed or validated."""


@dataclass(frozen=True)
class RuleSet:
    """A compiled, ready-to-scan policy. Build with load_rules(); reuse it for every scan."""

    version: str
    detectors: List[Detector]
    source: str = "built-in"
    errors: Tuple[str, ...] = ()  # why a custom file was rejected (we fell back to defaults)

    @property
    def by_name(self) -> Dict[str, Detector]:
        return {d.name: d for d in self.detectors}

    @property
    def compliance(self) -> Dict[str, str]:
        return {d.name: d.compliance for d in self.detectors}


def _compile_rule(spec: Dict[str, Any]) -> Detector:
    name = spec.get("name")
    where = f"rule {name!r}" if name else "rule"
    unknown = set(spec) - _RULE_KEYS
    if unknown:
        raise RulesError(f"{where}: unknown field(s) {', '.join(sorted(unknown))}")
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise RulesError(f"{where}: name must be 2-32 chars of A-Z, 0-9, _ starting with a letter")
    missing = [k for k in ("category", "severity", "pattern") if not spec.get(k)]
    if missing:
        raise RulesError(f"{where}: missing {', '.join(missing)}")
    if spec["category"] not in CATEGORIES:
        raise RulesError(f"{where}: category must be one of {', '.join(CATEGORIES)}")
    if spec["severity"] not in SEVERITY_ORDER:
        raise RulesError(f"{where}: severity must be one of {', '.join(SEVERITY_ORDER)}")
    if not isinstance(spec["pattern"], str):
        raise RulesError(f"{where}: pattern must be a string")
    try:
        pattern = re.compile(spec["pattern"])
    except re.error as exc:
        raise RulesError(f"{where}: invalid regex: {exc}") from None
    group = spec.get("group", 0)
    if not isinstance(group, int) or isinstance(group, bool) or not 0 <= group <= pattern.groups:
        raise RulesError(f"{where}: group {group!r} out of range (pattern has {pattern.groups} groups)")
    validator_name = spec.get("validator")
    if validator_name is not None and validator_name not in VALIDATORS:
        raise RulesError(f"{where}: unknown validator {validator_name!r} (available: {', '.join(VALIDATORS)})")
    compliance = spec.get("compliance") or "Custom policy"
    if not isinstance(compliance, str) or len(compliance) > _MAX_COMPLIANCE_LEN:
        raise RulesError(f"{where}: compliance must be a string of at most {_MAX_COMPLIANCE_LEN} chars")
    hints = spec.get("hints", [])
    if not isinstance(hints, list) or not all(isinstance(h, str) and h for h in hints):
        raise RulesError(f"{where}: hints must be a list of non-empty strings")
    ignore_case = spec.get("hints_ignore_case", False)
    if not isinstance(ignore_case, bool):
        raise RulesError(f"{where}: hints_ignore_case must be true or false")
    prefilter = None
    if spec.get("prefilter") is not None:
        if not isinstance(spec["prefilter"], str):
            raise RulesError(f"{where}: prefilter must be a string")
        try:
            prefilter = re.compile(spec["prefilter"])
        except re.error as exc:
            raise RulesError(f"{where}: invalid prefilter regex: {exc}") from None
    return Detector(
        name=name,
        category=spec["category"],
        severity=spec["severity"],
        pattern=pattern,
        description=str(spec.get("description") or name),
        group=group,
        validator=VALIDATORS[validator_name] if validator_name else None,
        compliance=compliance,
        hints=tuple(h.lower() for h in hints) if ignore_case else tuple(hints),
        hints_ignore_case=ignore_case,
        prefilter=prefilter,
    )


def _parse_file(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        raw = fh.read()
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml  # optional: pip install 'egressiq[yaml]'
        except ImportError:
            raise RulesError("YAML rule files need PyYAML: pip install 'egressiq[yaml]' (or use JSON)") from None
        try:
            doc = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise RulesError(f"invalid YAML: {exc}") from None
    else:
        try:
            doc = json.loads(raw)
        except ValueError as exc:
            raise RulesError(f"invalid JSON: {exc}") from None
    if not isinstance(doc, dict):
        raise RulesError("rule file must be a mapping with a 'detectors' list")
    return doc


def _merge(doc: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
    unknown = set(doc) - _FILE_KEYS
    if unknown:
        raise RulesError(f"unknown top-level field(s) {', '.join(sorted(unknown))}")
    custom = doc.get("detectors", [])
    disable = doc.get("disable", [])
    extends = doc.get("extends_defaults", True)
    if not isinstance(custom, list) or not all(isinstance(r, dict) for r in custom):
        raise RulesError("'detectors' must be a list of mappings")
    if not isinstance(disable, list) or not all(isinstance(n, str) for n in disable):
        raise RulesError("'disable' must be a list of detector names")
    if not isinstance(extends, bool):
        raise RulesError("'extends_defaults' must be true or false")

    merged: Dict[str, Dict[str, Any]] = {}
    if extends:
        merged = {r["name"]: dict(r) for r in DEFAULT_RULES["detectors"]}
    for rule in custom:
        name = rule.get("name")
        if name in merged:
            base = merged[name]
            if "pattern" in rule:
                # A new pattern has its own groups, and the old pattern's gates may not cover it.
                base = {k: v for k, v in base.items()
                        if k not in ("group", "hints", "hints_ignore_case", "prefilter") or k in rule}
            merged[name] = {**base, **rule}
        else:
            merged[str(name)] = dict(rule)
    for name in disable:
        if name not in merged:
            raise RulesError(f"cannot disable unknown detector {name!r}")
        del merged[name]
    if not merged:
        raise RulesError("policy has no detectors left")

    version = doc.get("version")
    if version is None:
        version = f"{DEFAULT_RULES['version']}+custom" if extends else "custom"
    return str(version), list(merged.values())


def _build(version: str, specs: List[Dict[str, Any]], source: str) -> RuleSet:
    return RuleSet(version=version, detectors=[_compile_rule(s) for s in specs], source=source)


_DEFAULT_RULESET = _build(DEFAULT_RULES["version"], DEFAULT_RULES["detectors"], "built-in")


def load_rules(source: Optional[str] = None, strict: bool = False) -> RuleSet:
    """Return a compiled RuleSet. Every regex is compiled here, once, never per scan.

    source=None gives the built-in defaults (cached, free to call repeatedly).
    A JSON or YAML path is merged over the defaults: rules whose name matches a
    default override only the fields they set; new names add detectors;
    `disable: [NAME]` removes one; `extends_defaults: false` drops all defaults.

    A file that can't be read, parsed or validated is rejected as a whole (never
    half-applied). With strict=False the built-in defaults are returned, the
    problem is logged, and RuleSet.errors says why; strict=True raises RulesError.
    """
    if source is None:
        return _DEFAULT_RULESET
    try:
        version, specs = _merge(_parse_file(source))
        return _build(version, specs, source)
    except (OSError, RulesError) as exc:
        message = exc.strerror if isinstance(exc, OSError) and exc.strerror else str(exc)
        message = f"{source}: {message}"
        if strict:
            raise RulesError(message) from None
        log.warning("ignoring rule file, using built-in rules: %s", message)
        return RuleSet(_DEFAULT_RULESET.version, _DEFAULT_RULESET.detectors, "built-in", (message,))


# Module-level defaults, kept for callers that predate load_rules().
DETECTORS: List[Detector] = _DEFAULT_RULESET.detectors
DETECTORS_BY_NAME: Dict[str, Detector] = _DEFAULT_RULESET.by_name
# tests/test_compliance.py requires an entry per detector.
COMPLIANCE_IMPACT: Dict[str, str] = _DEFAULT_RULESET.compliance


def _version_key(version: str) -> Tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", version))


_update_executor: Any = None
_update_lock = threading.Lock()


def check_rule_updates(url: str, current_version: str, timeout: float = 5.0) -> "Future[Optional[Dict[str, Any]]]":
    """Ask a rules endpoint whether a newer policy exists, without blocking the caller.

    Returns a concurrent.futures.Future immediately; the HTTP GET runs on a single
    background thread, never on a scan thread. The Future resolves to the endpoint's
    JSON manifest (which must include "version") when it is newer than
    current_version, else None. Failures resolve to None and are logged; they never
    raise. Only a version check: nothing is downloaded or applied, and no scan data
    is sent. HTTPS is required except for localhost.
    """
    global _update_executor
    from concurrent.futures import ThreadPoolExecutor

    with _update_lock:
        if _update_executor is None:
            _update_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="egressiq-rules")
    return _update_executor.submit(_fetch_update, url, current_version, timeout)


def _fetch_update(url: str, current_version: str, timeout: float) -> Optional[Dict[str, Any]]:
    import urllib.parse
    import urllib.request

    parts = urllib.parse.urlsplit(url)
    if not (parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1"))):
        log.warning("rule update check skipped: %s is not an https URL", url)
        return None
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "egressiq-rules"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (scheme checked above)
            manifest = json.loads(resp.read(64 * 1024))
        remote = manifest["version"]
        if not isinstance(remote, str) or not _version_key(remote):
            raise ValueError(f"bad version {remote!r}")
    except Exception as exc:  # network, HTTP, JSON or schema errors: report, never raise
        log.warning("rule update check failed for %s: %s", url, exc)
        return None
    return manifest if _version_key(remote) > _version_key(current_version) else None



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
    starts: Optional[List[int]] = None
    lowered: Optional[str] = None
    for det in detectors:
        if det.hints:
            if det.hints_ignore_case:
                lowered = text.lower() if lowered is None else lowered
                haystack = lowered
            else:
                haystack = text
            if not any(h in haystack for h in det.hints):
                continue
        if det.prefilter is not None and det.prefilter.search(text) is None:
            continue
        for m in det.pattern.finditer(text):
            value = m.group(det.group)
            if not value or (det.validator and not det.validator(value)):
                continue
            s, e = m.span(det.group)
            starts = _line_index(text) if starts is None else starts
            candidates.append(
                Finding(det.name, det.category, det.severity, s, e, _line_of(starts, s), value)
            )

    # Highest priority first; keep a candidate only if it overlaps nothing kept so far.
    # Kept findings are disjoint, so only the neighbours by start can overlap: O(k log k).
    candidates.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -(f.end - f.start), f.start))
    kept_starts: List[int] = []
    kept: List[Finding] = []
    for f in candidates:
        i = bisect_right(kept_starts, f.start)
        if (i and kept[i - 1].end > f.start) or (i < len(kept) and kept[i].start < f.end):
            continue
        kept_starts.insert(i, f.start)
        kept.insert(i, f)
    return kept


def redact(
    text: str, findings: Optional[List[Finding]] = None, detectors: Optional[List[Detector]] = None
) -> Tuple[str, List[Finding]]:
    """Replace each finding with a [REDACTED:<DETECTOR>] token."""
    findings = scan(text, detectors) if findings is None else findings
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
