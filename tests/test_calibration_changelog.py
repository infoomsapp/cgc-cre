"""
Versioned changelog for the PAN/ECM/PFM/SDA scoring calibration
(Database._CALIBRATION_MODULES / cgc_calibration_changelog). Needs a real
Postgres -- see conftest.py's `db` fixture -- because the bug that
motivated writing these tests (Decimal not being JSON-serializable) only
exists against real psycopg2/RealDictCursor rows, not a mock.
"""

from decimal import Decimal


def test_update_calibration_row_only_touches_editable_columns(db):
    before = db.get_calibration_row("ecm", "DEFAULT")
    assert before is not None

    updated = db.update_calibration_row(
        "ecm", "DEFAULT",
        {"compliance_owner_bonus": 0.05, "not_a_real_column": "ignored"},
    )
    assert updated is not None
    assert float(updated["compliance_owner_bonus"]) == 0.05
    # every other column must be untouched
    assert updated["base_frameworks"] == before["base_frameworks"]
    assert updated["critical_frameworks"] == before["critical_frameworks"]

    # restore, so this test doesn't leave DEFAULT permanently mutated
    db.update_calibration_row(
        "ecm", "DEFAULT", {"compliance_owner_bonus": float(before["compliance_owner_bonus"])},
    )


def test_update_calibration_row_returns_none_for_unknown_module(db):
    assert db.update_calibration_row("not_a_module", "DEFAULT", {"x": 1}) is None


def test_update_calibration_row_returns_none_when_no_fields_are_editable(db):
    assert db.update_calibration_row("ecm", "DEFAULT", {"not_a_real_column": 1}) is None


def test_record_calibration_change_survives_decimal_values(db):
    """Regression test: cgc_jla.ecm_calibration.compliance_owner_bonus is
    NUMERIC, which psycopg2's RealDictCursor returns as decimal.Decimal --
    passing that straight into psycopg2.extras.Json() crashes with
    'Object of type Decimal is not JSON serializable' the first time this
    was tried against the real column (caught live during rollout, not
    invented for this test)."""
    entry = db.record_calibration_change({
        "module": "ecm",
        "governance_area": "DEFAULT",
        "action_type": None,
        "previous_value": {"compliance_owner_bonus": Decimal("0.02")},
        "new_value": {"compliance_owner_bonus": Decimal("0.05")},
        "reason": "regression test for the Decimal serialization bug",
        "source_name": "pytest",
        "source_url": None,
        "changed_by": "pytest@local",
    })
    assert entry["previous_value"] == {"compliance_owner_bonus": 0.02}
    assert entry["new_value"] == {"compliance_owner_bonus": 0.05}
    assert isinstance(entry["previous_value"]["compliance_owner_bonus"], float)


def test_get_calibration_changelog_filters_by_module_and_area(db):
    db.record_calibration_change({
        "module": "pan", "governance_area": "DEFAULT", "action_type": None,
        "previous_value": {"sensitivity_multiplier": 1.0},
        "new_value": {"sensitivity_multiplier": 1.1},
        "reason": "changelog filter test", "source_name": None, "source_url": None,
        "changed_by": "pytest@local",
    })

    ecm_entries = db.get_calibration_changelog(module="ecm", governance_area="DEFAULT")
    assert all(e["module"] == "ecm" for e in ecm_entries)

    pan_entries = db.get_calibration_changelog(module="pan", governance_area="DEFAULT")
    assert any(e["reason"] == "changelog filter test" for e in pan_entries)
