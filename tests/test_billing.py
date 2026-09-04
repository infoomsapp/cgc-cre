"""
Gap 2 (Stripe billing) -- StripeBilling's own "degrades to not-configured,
never crashes" contract, same reasoning as ControlMiles' own edge functions
(create-checkout-session/cgc-seal-trip both return {configured: false}
rather than raising when their secrets aren't set). No real Stripe account
needed for these -- they cover the code path that runs BEFORE any real API
call would happen.
"""

import os

import pytest

from app.integrations.stripe.billing import StripeBilling, StripeBillingError


def test_not_configured_without_secret_key(monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    billing = StripeBilling()
    assert billing.is_configured is False


def test_checkout_session_returns_not_configured_instead_of_raising(monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    billing = StripeBilling()
    result = billing.create_checkout_session(
        app_source="test-tenant", plan="STANDARD",
        success_url="https://example.com/ok", cancel_url="https://example.com/cancel",
    )
    assert result == {"configured": False}


def test_portal_session_returns_not_configured_instead_of_raising(monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    billing = StripeBilling()
    result = billing.create_portal_session("cus_fake", "https://example.com/return")
    assert result == {"configured": False}


def test_configured_when_secret_key_present(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_fake_for_this_test_only")
    billing = StripeBilling()
    assert billing.is_configured is True


def test_price_id_for_plan_reads_the_right_env_var(monkeypatch):
    monkeypatch.setenv("STRIPE_PRICE_ID_STANDARD", "price_standard_123")
    monkeypatch.setenv("STRIPE_PRICE_ID_ENTERPRISE", "price_enterprise_456")
    assert StripeBilling.price_id_for_plan("STANDARD") == "price_standard_123"
    assert StripeBilling.price_id_for_plan("standard") == "price_standard_123"  # case-insensitive
    assert StripeBilling.price_id_for_plan("ENTERPRISE") == "price_enterprise_456"


def test_price_id_for_plan_is_none_for_free_and_sovereign(monkeypatch):
    """FREE never checks out; SOVEREIGN is contact-us custom pricing --
    neither has a self-checkout Stripe price by design."""
    assert StripeBilling.price_id_for_plan("FREE") is None
    assert StripeBilling.price_id_for_plan("SOVEREIGN") is None


def test_checkout_raises_when_configured_but_plan_has_no_price(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_fake_for_this_test_only")
    monkeypatch.delenv("STRIPE_PRICE_ID_STANDARD", raising=False)
    billing = StripeBilling()
    with pytest.raises(StripeBillingError):
        billing.create_checkout_session(
            app_source="test-tenant", plan="STANDARD",
            success_url="https://example.com/ok", cancel_url="https://example.com/cancel",
        )


def test_construct_event_raises_without_webhook_secret(monkeypatch):
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    billing = StripeBilling()
    with pytest.raises(StripeBillingError):
        billing.construct_event(b"{}", "fake-sig")
