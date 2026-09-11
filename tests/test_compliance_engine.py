"""
Real logic for ComplianceEngine.validate_eu_ai_act -- no DB required.
Before 2026-09-11, 2 of the 7 EU AI Act requirements were hardcoded
placeholders always returning PASS regardless of input (caught during an
external assessment of this codebase), and the other 5 were never
evaluated at all. These tests exercise the real checks directly against
plain dicts, the same shape as cgc_loop.py's real decision_artifact.
"""

from app.modules.compliance.compliance_engine import ComplianceEngine, EUAIActRequirement


class FakeTCO:
    def log_decision(self, **kwargs):
        pass


_DEFAULT_TCO = object()  # sentinel: distinguishes "use the default fake" from "no TCO at all"


def _engine(tco=_DEFAULT_TCO):
    return ComplianceEngine(scm=None, tco=FakeTCO() if tco is _DEFAULT_TCO else tco)


def _base_decision(**overrides):
    decision = {
        "reason": "All checks passed; decision approved",
        "module_scores": {"pan": 0.9, "ecm": 0.95, "pfm": 0.88, "sda": 0.99},
        "critical_framework_violated": False,
        "outcome": "APPROVE",
        "human_review_required": False,
        "signature": {"signature_id": "sig-123", "data_hash": "abcd", "key_id": "key-1"},
    }
    decision.update(overrides)
    return decision


def _status_for(summary, requirement: EUAIActRequirement) -> str:
    return next(c.status for c in summary.profile.checklist if c.requirement == requirement)


def test_transparency_passes_with_reason_and_full_module_breakdown():
    summary = _engine().validate_eu_ai_act(_base_decision(), industry="banking")
    assert _status_for(summary, EUAIActRequirement.TRANSPARENCY) == "PASS"


def test_transparency_fails_when_reason_is_missing():
    decision = _base_decision(reason="")
    summary = _engine().validate_eu_ai_act(decision, industry="banking")
    assert _status_for(summary, EUAIActRequirement.TRANSPARENCY) == "FAIL"


def test_transparency_fails_when_module_scores_incomplete():
    decision = _base_decision(module_scores={"pan": 0.9, "ecm": 0.95})
    summary = _engine().validate_eu_ai_act(decision, industry="banking")
    assert _status_for(summary, EUAIActRequirement.TRANSPARENCY) == "FAIL"


def test_human_oversight_passes_for_a_normal_approval():
    summary = _engine().validate_eu_ai_act(_base_decision(), industry="banking")
    assert _status_for(summary, EUAIActRequirement.HUMAN_OVERSIGHT) == "PASS"


def test_human_oversight_fails_when_critical_violation_was_silently_approved():
    """The real regression this check exists to catch: _make_decision()
    (cgc_loop.py) is supposed to guarantee a critical_framework_violated
    decision is never outcome==APPROVE -- this proves the compliance
    layer actually verifies that invariant instead of assuming it."""
    decision = _base_decision(critical_framework_violated=True, outcome="APPROVE")
    summary = _engine().validate_eu_ai_act(decision, industry="banking")
    assert _status_for(summary, EUAIActRequirement.HUMAN_OVERSIGHT) == "FAIL"


def test_human_oversight_passes_when_critical_violation_correctly_escalated():
    decision = _base_decision(critical_framework_violated=True, outcome="REQUIRE_HUMAN")
    summary = _engine().validate_eu_ai_act(decision, industry="banking")
    assert _status_for(summary, EUAIActRequirement.HUMAN_OVERSIGHT) == "PASS"


def test_cybersecurity_passes_with_a_real_signature_block():
    summary = _engine().validate_eu_ai_act(_base_decision(), industry="banking")
    assert _status_for(summary, EUAIActRequirement.CYBERSECURITY) == "PASS"


def test_cybersecurity_fails_with_no_signature():
    decision = _base_decision(signature=None)
    summary = _engine().validate_eu_ai_act(decision, industry="banking")
    assert _status_for(summary, EUAIActRequirement.CYBERSECURITY) == "FAIL"


def test_cybersecurity_fails_with_a_malformed_signature_block():
    decision = _base_decision(signature={"key_id": "key-1"})  # missing signature_id/data_hash
    summary = _engine().validate_eu_ai_act(decision, industry="banking")
    assert _status_for(summary, EUAIActRequirement.CYBERSECURITY) == "FAIL"


def test_performance_logs_passes_when_tco_is_wired():
    summary = _engine(tco=FakeTCO()).validate_eu_ai_act(_base_decision(), industry="banking")
    assert _status_for(summary, EUAIActRequirement.PERFORMANCE_LOGS) == "PASS"


def test_performance_logs_fails_when_tco_is_not_wired():
    summary = _engine(tco=None).validate_eu_ai_act(_base_decision(), industry="banking")
    assert _status_for(summary, EUAIActRequirement.PERFORMANCE_LOGS) == "FAIL"


def test_non_automatable_requirements_are_honestly_manual_not_faked_pass():
    """The core fix this whole rewrite is about: these 3 requirements
    cannot be verified from a runtime decision payload, so they must
    never silently report PASS."""
    summary = _engine().validate_eu_ai_act(_base_decision(), industry="banking")
    for requirement in (
        EUAIActRequirement.DATA_REPRESENTATIVE,
        EUAIActRequirement.CE_MARKING,
        EUAIActRequirement.SYSTEM_REGISTRY,
    ):
        item = next(c for c in summary.profile.checklist if c.requirement == requirement)
        assert item.status == "MANUAL_REVIEW_REQUIRED"
        assert item.score is None


def test_overall_score_excludes_manual_review_items_from_the_average():
    summary = _engine().validate_eu_ai_act(_base_decision(), industry="banking")
    # 4 automatable checks, all PASS on a clean decision -> 100.0 average,
    # not diluted by the 3 manual-review items having no numeric score.
    assert summary.overall_score == 100.0
    assert summary.manual_review == 3
    assert summary.passed == 4
    assert summary.failed == 0
