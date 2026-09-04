"""
Gap 1 (per-tenant API keys) -- no DB required, same reasoning as
test_auth.py: AuthSystem() degrades to the JSON fallback when no
DATABASE_URL is reachable, and generate_api_key/verify_token route through
that same self._db.use_postgres dispatch as everything else in this class,
so these tests exercise the real logic either way.
"""

import os

from app.Core.auth.auth_system import AuthSystem


def _fresh_auth(tmp_path):
    """A throwaway data_dir per test so api_keys.json runs don't bleed
    into each other -- same isolation concern as any test touching the
    JSON fallback files."""
    return AuthSystem(data_dir=str(tmp_path))


def test_generated_key_authenticates_as_its_own_app_source(tmp_path):
    auth = _fresh_auth(tmp_path)
    result = auth.generate_api_key("controlmiles", created_by="test@olympusmont.com")
    assert result["success"] is True
    assert result["key"].startswith(AuthSystem.API_KEY_PREFIX)

    principal = auth.verify_token(result["key"])
    assert principal is not None
    assert principal["app_source"] == "controlmiles"
    assert principal["role"] == "service"


def test_two_keys_resolve_to_their_own_distinct_app_source(tmp_path):
    """The whole point of Gap 1: a key for one app can never resolve to
    another app's identity."""
    auth = _fresh_auth(tmp_path)
    key_a = auth.generate_api_key("ledgiproof", created_by="test@olympusmont.com")["key"]
    key_b = auth.generate_api_key("controlmiles", created_by="test@olympusmont.com")["key"]

    assert auth.verify_token(key_a)["app_source"] == "ledgiproof"
    assert auth.verify_token(key_b)["app_source"] == "controlmiles"


def test_revoked_key_no_longer_authenticates(tmp_path):
    auth = _fresh_auth(tmp_path)
    issued = auth.generate_api_key("controlmiles", created_by="test@olympusmont.com")
    assert auth.verify_token(issued["key"]) is not None

    revoked = auth.revoke_api_key(issued["id"])
    assert revoked["success"] is True
    assert auth.verify_token(issued["key"]) is None


def test_garbage_token_with_the_right_prefix_is_rejected_not_crashed(tmp_path):
    auth = _fresh_auth(tmp_path)
    fake_token = AuthSystem.API_KEY_PREFIX + "this-was-never-issued"
    assert auth.verify_token(fake_token) is None


def test_legacy_shared_key_still_authenticates_with_no_bound_app_source(tmp_path, monkeypatch):
    """Migration safety: the 3 existing first-party apps keep working on
    CGC_SERVICE_API_KEY until each is migrated to its own per-tenant key --
    app_source stays None for this principal, which is what main.py/
    monitor.py/flow_score.py use to fall back to today's client-declared
    (allowlist-checked) app_source instead of trusting a forged claim."""
    monkeypatch.setenv("CGC_SERVICE_API_KEY", "a-legacy-shared-secret")
    auth = AuthSystem(data_dir=str(tmp_path))

    principal = auth.verify_token("a-legacy-shared-secret")
    assert principal is not None
    assert principal["role"] == "service"
    assert principal["app_source"] is None


def test_list_api_keys_never_exposes_the_hash_or_plaintext(tmp_path):
    auth = _fresh_auth(tmp_path)
    issued = auth.generate_api_key("controlmiles", created_by="test@olympusmont.com")

    rows = auth.list_api_keys(app_source="controlmiles")
    assert len(rows) == 1
    assert rows[0]["id"] == issued["id"]
    assert "key_hash" not in rows[0]
    assert "key" not in rows[0]
    assert rows[0]["key_prefix"] == issued["key_prefix"]
