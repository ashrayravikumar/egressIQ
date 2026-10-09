import pytest

from scanner import COMPLIANCE_IMPACT, DETECTORS, DETECTORS_BY_NAME


@pytest.mark.parametrize("detector", [d.name for d in DETECTORS])
def test_every_detector_has_compliance_mapping(detector):
    """Adding a detector without a mapped framework fails CI."""
    assert COMPLIANCE_IMPACT.get(detector, "").strip()


def test_mapping_references_real_detectors():
    assert set(COMPLIANCE_IMPACT) <= set(DETECTORS_BY_NAME)


@pytest.mark.parametrize("detector,framework", [
    ("CREDIT_CARD", "PCI-DSS 4.0 Req 4.2 / 3.4"),
    ("US_SSN", "SOC 2 CC6.1 / GLBA"),
    ("EMAIL_ADDRESS", "GDPR / CCPA PII"),
    ("AWS_ACCESS_KEY_ID", "SOC 2 CC6.6 (Secrets Exposure)"),
    ("DB_CONNECTION_STRING", "SOC 2 CC6.6 (Secrets Exposure)"),
])
def test_specified_mappings(detector, framework):
    assert COMPLIANCE_IMPACT[detector] == framework


def test_all_secret_detectors_map_to_secrets_exposure():
    for d in DETECTORS:
        if d.category in ("credential", "infrastructure"):
            assert COMPLIANCE_IMPACT[d.name] == "SOC 2 CC6.6 (Secrets Exposure)", d.name
