"""Detector gates (hints / prefilter) and the scan fast path must never lose a finding."""

import json
import random
import re
import time

import pytest

import scanner
from scanner import DETECTORS, SEVERITY_ORDER, Finding, RulesError, load_rules, scan
from tests.samples import POSITIVES


def _gate_passes(det, text):
    if det.hints:
        haystack = text.lower() if det.hints_ignore_case else text
        if not any(h in haystack for h in det.hints):
            return False
    return det.prefilter is None or det.prefilter.search(text) is not None


def _reference_scan(text, detectors=DETECTORS):
    """scan() as it was before gates and the O(k log k) overlap pass: run every regex, naive overlap."""
    starts = [0] + [m.end() for m in re.finditer(r"\n", text)]
    found = []
    for det in detectors:
        for m in det.pattern.finditer(text):
            value = m.group(det.group)
            if not value or (det.validator and not det.validator(value)):
                continue
            s, e = m.span(det.group)
            line = sum(1 for st in starts if st <= s)
            found.append(Finding(det.name, det.category, det.severity, s, e, line, value))
    found.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -(f.end - f.start), f.start))
    chosen = []
    for f in found:
        if all(f.end <= c.start or f.start >= c.end for c in chosen):
            chosen.append(f)
    return sorted(chosen, key=lambda f: f.start)


@pytest.mark.parametrize("det", DETECTORS, ids=lambda d: d.name)
def test_gate_passes_on_every_match_in_the_corpus(det):
    """A gate is only safe if every string the regex can match also passes it."""
    texts = [t for cases in POSITIVES.values() for t, _ in cases]
    matches = [m.group(0) for t in texts for m in det.pattern.finditer(t)]
    assert matches, f"{det.name} matched nothing in the corpus"
    failing = [m for m in matches if not _gate_passes(det, m)]
    assert failing == []


def _expand_schemes(alternation):
    """Spellings accepted by _DB_SCHEMES (handles the "(?:x)?" and trailing "s?" forms it uses)."""
    out = set()
    for alt in alternation.split("|"):
        m = re.fullmatch(r"([a-z]+)(?:\(\?:(.+)\)\?|(s)\?)?", alt)
        assert m, f"unexpected scheme syntax {alt!r}; update _DB_URI_HINTS and this test"
        base, opt = m.group(1), m.group(2) or m.group(3)
        out.add(base)
        if opt:
            out.add(base + opt.replace("\\", ""))
    return out


def test_db_hints_cover_every_scheme():
    assert {f"{s}://" for s in _expand_schemes(scanner._DB_SCHEMES)} == set(scanner._DB_URI_HINTS)


FRAGMENTS = [
    "AKIA", "ASIA", "A3TX", "IOSFODNN7EXAMPLE", "ghp_", "ghs_", "github_pat_", "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ01",
    "eyJhbGciOiJIUzI1NiJ9", ".eyJzdWIiOiIxIn0", ".sig", "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n",
    "-----END RSA PRIVATE KEY-----", "postgres://u:p@h/db", "POSTGRESQL://", "Mongodb+srv://a:b@c", "jdbc:mysql://h/d",
    "Server=x;", "Password=p;", "PWD=q;", "jane.doe@example.com", "@", "phone=", "Tel:", "+1-415-555-0198",
    "(415) 555-0198", "4155550198", "123-45-6789", "-12-3456", "4111 1111 1111 1111", "5500-0055-5555-5559",
    "aws_secret_access_key=", "SECRET_KEY: ", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    " ", "\n", "-", "=", ":", "x", "9", "2026-10-08", "İ", "ß",
]


def test_scan_matches_reference_on_random_text():
    rng = random.Random(20261010)
    for _ in range(1500):
        text = "".join(rng.choice(FRAGMENTS) for _ in range(rng.randint(1, 50)))
        got = [(f.detector, f.start, f.end, f.line) for f in scan(text)]
        want = [(f.detector, f.start, f.end, f.line) for f in _reference_scan(text)]
        assert got == want, text


def test_scan_matches_reference_on_fixture():
    text = open("tests/fixtures/sample_logs.csv").read() * 3
    assert [(f.detector, f.start, f.end) for f in scan(text)] == [(f.detector, f.start, f.end) for f in _reference_scan(text)]


def test_many_findings_scale():
    """Overlap resolution used to be O(k^2): 40k findings took minutes."""
    text = "user a@example.com key=AKIA" + "IOSFODNN7EXAMPLE\n"
    text *= 20000
    t0 = time.perf_counter()
    findings = scan(text)
    assert len(findings) == 40000
    assert time.perf_counter() - t0 < 5


# ── Gates in rule files ──────────────────────────────────────────────────
def _rules(tmp_path, rule, strict=True):
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"extends_defaults": False, "detectors": [rule]}))
    return load_rules(str(path), strict=strict)


BASE = {"name": "TICKET_ID", "category": "infrastructure", "severity": "low", "pattern": r"\bTCK-\d{4}\b"}


def test_hints_gate_custom_rule(tmp_path):
    rules = _rules(tmp_path, {**BASE, "hints": ["TCK-"]})
    assert [f.value for f in scan("see TCK-1234", rules.detectors)] == ["TCK-1234"]
    # A hint that a match doesn't contain hides it: hints are a contract, not a suggestion.
    wrong = _rules(tmp_path, {**BASE, "hints": ["XYZ"]})
    assert scan("see TCK-1234", wrong.detectors) == []


def test_hints_ignore_case(tmp_path):
    rules = _rules(tmp_path, {**BASE, "pattern": r"(?i)\btck-\d{4}\b", "hints": ["TCK-"], "hints_ignore_case": True})
    assert rules.detectors[0].hints == ("tck-",)
    assert [f.value for f in scan("see tck-1234", rules.detectors)] == ["tck-1234"]


def test_prefilter_custom_rule(tmp_path):
    rules = _rules(tmp_path, {**BASE, "prefilter": r"\d{4}"})
    assert [f.value for f in scan("see TCK-1234", rules.detectors)] == ["TCK-1234"]
    assert scan("see TCK-12", rules.detectors) == []


def test_pattern_override_drops_inherited_gates(tmp_path):
    """EMAIL_ADDRESS has hint "@"; a replacement pattern without "@" must still run."""
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"detectors": [{"name": "EMAIL_ADDRESS", "pattern": r"\bEMP-\d{4}\b"}]}))
    rules = load_rules(str(path), strict=True)
    assert rules.by_name["EMAIL_ADDRESS"].hints == ()
    assert [f.detector for f in scan("badge EMP-0042", rules.detectors)] == ["EMAIL_ADDRESS"]


def test_severity_override_keeps_gates(tmp_path):
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"detectors": [{"name": "EMAIL_ADDRESS", "severity": "low"}]}))
    assert load_rules(str(path), strict=True).by_name["EMAIL_ADDRESS"].hints == ("@",)


@pytest.mark.parametrize("bad", [
    {"hints": "TCK-"}, {"hints": [""]}, {"hints": [1]}, {"hints_ignore_case": "yes"},
    {"prefilter": "("}, {"prefilter": 5},
])
def test_invalid_gates_rejected(tmp_path, bad):
    with pytest.raises(RulesError):
        _rules(tmp_path, {**BASE, **bad})
