"""
ComplianceEngine.validate_glba_safeguards -- no DB required, pure
function of live env vars + module importability. Deliberately GLBA
only, not HIPAA/FINRA -- see the method's own docstring for why those
two don't apply to any current CGC Core consumer.
"""

import os

from app.modules.compliance.compliance_engine import ComplianceEngine, GLBASafeguardsElement


class FakeTCO:
    def log_decision(self, **kwargs):
        pass


def _status_for(result, element: GLBASafeguardsElement) -> str:
    return next(e["status"] for e in result["elements"] if e["element"] == element)


def test_reports_both_hipaa_and_finra_as_explicitly_not_applicable():
    result = ComplianceEngine(scm=None, tco=FakeTCO()).validate_glba_safeguards()
    assert "HIPAA" in result["not_applicable"]
    assert "FINRA" in result["not_applicable"]


def test_no_element_ever_silently_passes_without_a_real_basis(monkeypatch):
    """Every element must be PASS/FAIL (a live check), VERIFIED_BY_TESTS
    (cited), or MANUAL_REVIEW_REQUIRED -- never any other status, and a
    PASS must always carry the evidence that justified it."""
    monkeypatch.delenv("CGC_SCM_ENC_MASTER_V1", raising=False)
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    monkeypatch.delenv("SLACK_MONITOR_CHANNEL", raising=False)

    result = ComplianceEngine(scm=None, tco=FakeTCO()).validate_glba_safeguards()
    valid_statuses = {"PASS", "FAIL", "VERIFIED_BY_TESTS", "MANUAL_REVIEW_REQUIRED"}
    for element in result["elements"]:
        assert element["status"] in valid_statuses
        assert element["evidence"]  # never an empty/missing evidence block


def test_encryption_reflects_the_real_env_var_live(monkeypatch):
    monkeypatch.delenv("CGC_SCM_ENC_MASTER_V1", raising=False)
    result = ComplianceEngine(scm=None, tco=FakeTCO()).validate_glba_safeguards()
    assert _status_for(result, GLBASafeguardsElement.ENCRYPTION) == "FAIL"

    monkeypatch.setenv("CGC_SCM_ENC_MASTER_V1", "some-real-key-value")
    result2 = ComplianceEngine(scm=None, tco=FakeTCO()).validate_glba_safeguards()
    assert _status_for(result2, GLBASafeguardsElement.ENCRYPTION) == "PASS"


def test_incident_response_requires_both_slack_secrets(monkeypatch):
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-fake")
    monkeypatch.delenv("SLACK_MONITOR_CHANNEL", raising=False)
    result = ComplianceEngine(scm=None, tco=FakeTCO()).validate_glba_safeguards()
    assert _status_for(result, GLBASafeguardsElement.INCIDENT_RESPONSE) == "FAIL"

    monkeypatch.setenv("SLACK_MONITOR_CHANNEL", "#alerts")
    result2 = ComplianceEngine(scm=None, tco=FakeTCO()).validate_glba_safeguards()
    assert _status_for(result2, GLBASafeguardsElement.INCIDENT_RESPONSE) == "PASS"


def test_monitoring_fails_when_tco_is_not_wired():
    result = ComplianceEngine(scm=None, tco=None).validate_glba_safeguards()
    assert _status_for(result, GLBASafeguardsElement.MONITORING_AND_LOGGING) == "FAIL"


def test_periodic_testing_is_honestly_fail_no_third_party_pentest_exists():
    result = ComplianceEngine(scm=None, tco=FakeTCO()).validate_glba_safeguards()
    assert _status_for(result, GLBASafeguardsElement.PERIODIC_TESTING) == "FAIL"
