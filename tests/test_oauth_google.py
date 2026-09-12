"""
AuthSystem.login_federated() -- the session-issuing half of Google OIDC
login (api/v1/endpoints/oauth_google.py handles the actual Google
exchange/verification, which needs real Google Cloud credentials and a
browser consent flow to exercise; this covers everything on our side of
that boundary). No DB required -- same JSON-fallback pattern as
test_api_keys.py.
"""

from app.Core.auth.auth_system import AuthSystem


def _fresh_auth(tmp_path):
    return AuthSystem(data_dir=str(tmp_path))


def test_first_federated_login_auto_provisions_the_account(tmp_path):
    auth = _fresh_auth(tmp_path)
    result = auth.login_federated("new-user@example.com", ip="127.0.0.1")
    assert result["success"] is True
    assert result["user"]["email"] == "new-user@example.com"
    assert result["user"]["role"] == "user"
    assert auth.verify_token(result["token"]) is not None


def test_second_federated_login_reuses_the_existing_account(tmp_path):
    auth = _fresh_auth(tmp_path)
    first = auth.login_federated("repeat-user@example.com")
    second = auth.login_federated("repeat-user@example.com")
    assert first["success"] is True
    assert second["success"] is True
    # Two distinct sessions/tokens, same underlying account -- not a
    # duplicate account created on the second call.
    assert first["token"] != second["token"]


def test_federated_login_account_cannot_authenticate_with_a_password(tmp_path):
    """The auto-provisioned password hash must be genuinely unusable --
    regression guard for the whole point of generating it from
    secrets.token_urlsafe() rather than something guessable."""
    auth = _fresh_auth(tmp_path)
    auth.login_federated("google-only@example.com")
    result = auth.login("google-only@example.com", "password123456", ip="127.0.0.1")
    assert result["success"] is False


def test_federated_login_respects_disabled_account(tmp_path):
    auth = _fresh_auth(tmp_path)
    auth.login_federated("to-be-disabled@example.com")
    auth._update_user("to-be-disabled@example.com", active=False)
    result = auth.login_federated("to-be-disabled@example.com")
    assert result["success"] is False
    assert result["error"] == "Account disabled"


def test_federated_login_respects_blocked_ip(tmp_path):
    auth = _fresh_auth(tmp_path)
    auth.block_user(ip="10.0.0.1", reason="test block")
    result = auth.login_federated("someone@example.com", ip="10.0.0.1")
    assert result["success"] is False
    assert result.get("blocked") is True
