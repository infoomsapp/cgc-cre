"""
Stripe integration — CGC Core billing its own tenants (Gap 2)

Distinct from any of the 3 first-party apps' own Stripe integrations
(ControlMiles bills ITS end users; this bills whoever pays CGC Core
directly for governance-engine access). One Stripe account, configured via
STRIPE_SECRET_KEY/STRIPE_WEBHOOK_SECRET/STRIPE_PRICE_ID_* -- same
"degrades to not-configured, never crashes" pattern already used
throughout this codebase (Slack alerting, CGC_ENDPOINT/CGC_API_KEY in
ControlMiles' own edge functions).

Not self-serve by design (see the roadmap's own scope note): an admin
creates the Checkout Session on a prospect's behalf (POST
/admin/billing/checkout-link) and sends them the link -- there's no public
signup flow yet.

Olympus Mont Systems LLC (c) 2026
"""

import logging
import os
from typing import Any, Dict, Optional

try:
    import stripe as stripe_sdk
    STRIPE_SDK_AVAILABLE = True
except ImportError:
    STRIPE_SDK_AVAILABLE = False

logger = logging.getLogger("cgc.billing.stripe")

# Plan -> Stripe Price ID. FREE has no Stripe price (never checked out).
# SOVEREIGN is intentionally absent -- that tier is "contact us" custom
# pricing, not a self-checkout price, matching PLAN_QUOTAS/PLAN_FEATURES'
# own framing in multi_tenant.py.
_PLAN_PRICE_ENV = {
    "STANDARD": "STRIPE_PRICE_ID_STANDARD",
    "ENTERPRISE": "STRIPE_PRICE_ID_ENTERPRISE",
}


class StripeBillingError(Exception):
    """Raised only for real Stripe API failures -- "not configured" is
    signaled by is_configured, not an exception, same as every other
    optional integration in this codebase."""


class StripeBilling:
    def __init__(self) -> None:
        self.secret_key = os.getenv("STRIPE_SECRET_KEY")
        self.webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
        if STRIPE_SDK_AVAILABLE and self.secret_key:
            stripe_sdk.api_key = self.secret_key

    @property
    def is_configured(self) -> bool:
        return bool(STRIPE_SDK_AVAILABLE and self.secret_key)

    @staticmethod
    def price_id_for_plan(plan: str) -> Optional[str]:
        env_var = _PLAN_PRICE_ENV.get(plan.upper())
        return os.getenv(env_var) if env_var else None

    def create_checkout_session(
        self,
        app_source: str,
        plan: str,
        success_url: str,
        cancel_url: str,
        existing_customer_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self.is_configured:
            return {"configured": False}

        price_id = self.price_id_for_plan(plan)
        if not price_id:
            raise StripeBillingError(f"No Stripe price configured for plan {plan}")

        params: Dict[str, Any] = {
            "mode": "subscription",
            "line_items": [{"price": price_id, "quantity": 1}],
            "success_url": success_url,
            "cancel_url": cancel_url,
            # app_source flows back on every subsequent webhook event via
            # the subscription/session metadata -- same reasoning as
            # ControlMiles' own create-checkout-session: avoids needing a
            # second Stripe API call just to figure out which tenant a
            # webhook event belongs to.
            "subscription_data": {"metadata": {"app_source": app_source, "plan": plan}},
            "metadata": {"app_source": app_source, "plan": plan},
        }
        if existing_customer_id:
            params["customer"] = existing_customer_id

        try:
            session = stripe_sdk.checkout.Session.create(**params)
        except Exception as e:
            logger.error(f"[billing] Stripe checkout session creation failed: {e}")
            raise StripeBillingError(str(e)) from e

        return {"configured": True, "url": session.url, "session_id": session.id}

    def create_portal_session(self, stripe_customer_id: str, return_url: str) -> Dict[str, Any]:
        if not self.is_configured:
            return {"configured": False}
        try:
            session = stripe_sdk.billing_portal.Session.create(
                customer=stripe_customer_id, return_url=return_url
            )
        except Exception as e:
            logger.error(f"[billing] Stripe portal session creation failed: {e}")
            raise StripeBillingError(str(e)) from e
        return {"configured": True, "url": session.url}

    def construct_event(self, payload: bytes, sig_header: str):
        """Verifies the Stripe-Signature header against STRIPE_WEBHOOK_SECRET
        -- the ONLY thing that should ever be trusted to mean "this really
        came from Stripe", same principle as every HMAC-verified webhook
        elsewhere in the Olympus Mont codebase (ControlMiles' own
        stripe-webhook edge function)."""
        if not self.webhook_secret:
            raise StripeBillingError("STRIPE_WEBHOOK_SECRET not configured")
        return stripe_sdk.Webhook.construct_event(payload, sig_header, self.webhook_secret)
