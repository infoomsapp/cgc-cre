"""
CGC Core — App-level billing (Gap 2 of the sellable-service roadmap)

Distinct from TenantManager (multi_tenant.py), which manages quotas/rate
limits per org_id -- for our 3 first-party apps, org_id is one row PER
END-CUSTOMER within that app (e.g. every ControlMiles fleet org gets its
own org_id; confirmed live via cgc-seal-trip). Billing the wrong grain
would double- or mis-charge any customer with more than one org_id of
their own, exactly like our own apps have.

The actual paying account is app_source -- the same identity Gap 1's API
keys are cryptographically bound to. This module tracks ONE Stripe
subscription per app_source, in cgc_guard.app_billing. Deliberately NOT
wired into TenantManager's quota enforcement yet (see the roadmap's own
"not in scope" note) -- this pass is billing state + the Stripe plumbing,
not rewriting how quotas are decided.

Olympus Mont Systems LLC (c) 2026
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.Core.db.database import get_database

logger = logging.getLogger("cgc.billing")


class AppBillingManager:
    def get_billing(self, app_source: str) -> Optional[Dict[str, Any]]:
        db = get_database()
        with db.get_connection() as conn:
            if conn is None:
                return None
            cur = conn.cursor()
            cur.execute("SELECT * FROM cgc_guard.app_billing WHERE app_source = %s", (app_source,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_billing(self) -> list:
        db = get_database()
        with db.get_connection() as conn:
            if conn is None:
                return []
            cur = conn.cursor()
            cur.execute("SELECT * FROM cgc_guard.app_billing ORDER BY created_at DESC")
            return [dict(r) for r in cur.fetchall()]

    def upsert_billing(
        self,
        app_source: str,
        plan: Optional[str] = None,
        stripe_customer_id: Optional[str] = None,
        stripe_subscription_id: Optional[str] = None,
        stripe_price_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Insert-or-update, only touching the fields actually passed --
        e.g. a webhook that only knows the new status shouldn't blank out
        the plan this row already has."""
        db = get_database()
        with db.get_connection() as conn:
            if conn is None:
                raise RuntimeError("No database connection")
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM cgc_guard.app_billing WHERE app_source = %s", (app_source,))
            exists = cur.fetchone() is not None

            if not exists:
                cur.execute(
                    "INSERT INTO cgc_guard.app_billing "
                    "(app_source, plan, stripe_customer_id, stripe_subscription_id, stripe_price_id, status) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (app_source, plan or "FREE", stripe_customer_id, stripe_subscription_id,
                     stripe_price_id, status or "active")
                )
            else:
                fields, values = [], []
                for col, val in (
                    ("plan", plan), ("stripe_customer_id", stripe_customer_id),
                    ("stripe_subscription_id", stripe_subscription_id),
                    ("stripe_price_id", stripe_price_id), ("status", status),
                ):
                    if val is not None:
                        fields.append(f"{col} = %s")
                        values.append(val)
                fields.append("updated_at = %s")
                values.append(datetime.now(timezone.utc))
                values.append(app_source)
                cur.execute(
                    f"UPDATE cgc_guard.app_billing SET {', '.join(fields)} WHERE app_source = %s",
                    values
                )
            conn.commit()
        logger.info(f"[billing] app_billing upserted for app_source={app_source}")
        return self.get_billing(app_source)


# Singleton, same pattern as TenantManager's own `tenant_manager` (multi_tenant.py)
app_billing_manager = AppBillingManager()
