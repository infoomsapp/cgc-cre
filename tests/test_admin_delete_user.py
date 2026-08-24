"""
Tests for AuthSystem.delete_user() -- added alongside the new
DELETE /admin/users/{email} endpoint (main.py), the first delete capability
this codebase has ever had for user accounts. Runs against whichever
backend AuthSystem() resolves to (real Postgres in CI via conftest's
DATABASE_URL, JSON fallback on a dev machine with no local Postgres) --
same dual-mode pattern as test_auth.py, and the real point of this test:
a delete must actually revoke the user's existing sessions, not just
remove the row, since verify_token() checks a live session on every
request.
"""

import uuid

from app.Core.auth.auth_system import AuthSystem


def _unique_email() -> str:
    return f"delete-test-{uuid.uuid4().hex[:12]}@example.com"


def test_delete_user_removes_the_account():
    auth = AuthSystem()
    email = _unique_email()
    try:
        result = auth.create_user(email, "a-real-password-123!", role="user")
        assert result["success"] is True
        assert auth._get_user(email) is not None

        deleted = auth.delete_user(email)
        assert deleted["success"] is True
        assert auth._get_user(email) is None
    finally:
        auth.delete_user(email)


def test_delete_user_revokes_existing_sessions():
    auth = AuthSystem()
    email = _unique_email()
    password = "a-real-password-123!"
    try:
        assert auth.create_user(email, password, role="user")["success"] is True
        login = auth.login(email, password)
        assert login["success"] is True
        token = login["token"]

        assert auth.verify_token(token) is not None

        deleted = auth.delete_user(email)
        assert deleted["success"] is True

        assert auth.verify_token(token) is None
    finally:
        auth.delete_user(email)


def test_delete_nonexistent_user_returns_error_not_exception():
    auth = AuthSystem()
    result = auth.delete_user(_unique_email())
    assert result["success"] is False
    assert result["error"] == "User not found"
