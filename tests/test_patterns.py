"""Zero-false-negative checks for every regex detector."""

import pytest

from scanner import DETECTORS, DETECTORS_BY_NAME, redact, scan
from tests.samples import NEGATIVES, POSITIVES, STANDALONE

POSITIVE_CASES = [(name, text, value) for name, cases in POSITIVES.items() for text, value in cases]
NEGATIVE_CASES = [(name, text) for name, texts in NEGATIVES.items() for text in texts]


def _case_id(case):
    name, text = case[0], case[1]
    return f"{name}:{text[:40]!r}"


@pytest.mark.parametrize("detector", [d.name for d in DETECTORS])
def test_every_detector_has_samples(detector):
    """Adding a detector without positive and negative samples fails CI."""
    assert POSITIVES.get(detector), f"{detector} has no positive samples in tests/samples.py"
    assert NEGATIVES.get(detector), f"{detector} has no negative samples in tests/samples.py"


def test_samples_reference_real_detectors():
    assert set(POSITIVES) <= set(DETECTORS_BY_NAME)
    assert set(NEGATIVES) <= set(DETECTORS_BY_NAME)


@pytest.mark.parametrize("name,text,value", POSITIVE_CASES, ids=[_case_id(c) for c in POSITIVE_CASES])
def test_no_false_negatives(name, text, value):
    start = text.index(value)
    end = start + len(value)
    findings = scan(text)
    assert any(
        f.detector == name and f.start <= start and f.end >= end for f in findings
    ), f"{name} missed {value!r}; got {[(f.detector, f.value) for f in findings]}"

    sanitized, _ = redact(text, findings)
    assert value not in sanitized
    assert f"[REDACTED:{name}]" in sanitized


@pytest.mark.parametrize(
    "name,value", [(n, v) for n, vals in STANDALONE.items() for v in vals]
)
def test_exact_span_on_bare_value(name, value):
    findings = scan(value)
    assert [(f.detector, f.value) for f in findings] == [(name, value)]


@pytest.mark.parametrize("name,text", NEGATIVE_CASES, ids=[_case_id(c) for c in NEGATIVE_CASES])
def test_negatives_are_clean(name, text):
    findings = scan(text)
    assert findings == [], f"unexpected: {[(f.detector, f.value) for f in findings]}"
