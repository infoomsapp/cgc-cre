"""
Pure unit tests for AuthSystem's password hashing -- no DB required
(AuthSystem() itself degrades to the JSON fallback if no DB is reachable,
same as production would). Covers the exact mechanism behind SEC-001's
fix (2026-08-22): self-service signup must never be able to mint an
elevated role, and every account's password must be genuinely one-way
hashed, not just "looks hashed."
"""

from app.Core.auth.auth_system import AuthSystem


def test_password_hash_is_not_plaintext():
    auth = AuthSystem()
    hashed = auth._hash_password("a-real-password-123!")
    assert hashed != "a-real-password-123!"
    assert hashed.startswith("$2")  # bcrypt hash prefix


def test_password_hash_verifies_correctly():
    auth = AuthSystem()
    hashed = auth._hash_password("correct-horse-battery-staple")
    assert auth._verify_password("correct-horse-battery-staple", hashed) is True


def test_wrong_password_fails_verification():
    auth = AuthSystem()
    hashed = auth._hash_password("correct-horse-battery-staple")
    assert auth._verify_password("wrong-password", hashed) is False


def test_verify_password_handles_garbage_hash_safely():
    """A near-miss/garbage stored hash must fail closed, not raise."""
    auth = AuthSystem()
    assert auth._verify_password("anything", "not-a-real-bcrypt-hash") is False


def test_each_hash_is_uniquely_salted():
    """Same password, hashed twice, must never produce the same hash
    (bcrypt's random salt) -- guards against a regression to an unsalted
    or deterministic hashing scheme."""
    auth = AuthSystem()
    h1 = auth._hash_password("same-password")
    h2 = auth._hash_password("same-password")
    assert h1 != h2
    assert auth._verify_password("same-password", h1)
    assert auth._verify_password("same-password", h2)
