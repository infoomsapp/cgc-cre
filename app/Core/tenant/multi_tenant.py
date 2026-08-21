"""
CGC Core — Multi-tenant Manager
Gestiona quotas y features por tenant.

Olympus Mont Systems LLC © 2026
"""

import os
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from app.Core.db.database import get_database

logger = logging.getLogger("cgc.tenant")


class TenantManager:
    """
    Manages tenant quotas, feature flags, and plan assignment.

    Two things were genuinely broken here, both fixed the same pass:
    1. Usage counts lived in a plain in-memory dict (self._usage), so a
       "monthly" quota reset every Vercel cold start instead of every
       month -- it never actually enforced the limit it claimed to. Usage
       is now a real Postgres counter (cgc_guard.tenant_usage), keyed by
       (org_id, resource, period) -- the same durable-counter pattern
       already built 3 times this session.
    2. main.py's /billing/upgrade and /billing/usage/{org_id} called
       tenant_manager.upgrade_plan(...) / .get_tenant(...) -- neither
       method existed on this class at all, so both endpoints 500'd on
       every real call. Plan assignment was env-var-only
       (CGC_TENANT_{ORG}_PLAN, which can't be changed by a running
       function), so there was no real write path for a plan change
       either. Both closed together: cgc_guard.tenant_plans is a real,
       writable plan store; the env var is kept as the fallback default
       when no row exists, so nothing that relied on it before breaks.
    """

    # Default monthly quotas per plan
    PLAN_QUOTAS = {
        "FREE":       {"decisions": 1_000,    "api_calls": 5_000},
        "STANDARD":   {"decisions": 50_000,   "api_calls": 200_000},
        "ENTERPRISE": {"decisions": 5_000_000,"api_calls": 20_000_000},
        "SOVEREIGN":  {"decisions": -1,        "api_calls": -1},  # unlimited
    }

    PLAN_FEATURES = {
        "FREE":       {"custom_policies": False, "pdf_reports": False},
        "STANDARD":   {"custom_policies": True,  "pdf_reports": True},
        "ENTERPRISE": {"custom_policies": True,  "pdf_reports": True},
        "SOVEREIGN":  {"custom_policies": True,  "pdf_reports": True},
    }

    # Per-minute burst ceilings for the Phase 2 distributed rate limiter --
    # a distinct concept from PLAN_QUOTAS above (monthly business volume).
    # Before this, /governance/decision's org-scoped rate limit was one
    # hardcoded constant (300/min) for every tenant regardless of plan.
    PLAN_RATE_LIMITS = {
        "FREE":       {"decisions_per_min": 60},
        "STANDARD":   {"decisions_per_min": 300},
        "ENTERPRISE": {"decisions_per_min": 1000},
        "SOVEREIGN":  {"decisions_per_min": 5000},
    }

    def __init__(self):
        pass

    def _period(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m")

    def _get_plan(self, org_id: str) -> str:
        """A row in cgc_guard.tenant_plans wins if present; otherwise the
        legacy env var; otherwise STANDARD. Keeps every existing
        CGC_TENANT_{ORG}_PLAN deployment working unchanged."""
        db = get_database()
        try:
            with db.get_connection() as conn:
                if conn is not None:
                    cur = conn.cursor()
                    cur.execute("SELECT plan FROM cgc_guard.tenant_plans WHERE org_id = %s", (org_id,))
                    row = cur.fetchone()
                    if row:
                        return row["plan"]
        except Exception as e:
            logger.warning(f"[tenant] plan lookup failed for {org_id}, falling back to env (non-fatal): {e}")
        return os.getenv(f"CGC_TENANT_{org_id.upper()}_PLAN", "STANDARD")

    def upgrade_plan(self, org_id: str, plan: str) -> Dict[str, Any]:
        plan = (plan or "").upper()
        if plan not in self.PLAN_QUOTAS:
            return {"success": False, "error": f"Unknown plan: {plan}", "valid_plans": sorted(self.PLAN_QUOTAS.keys())}

        db = get_database()
        try:
            with db.get_connection() as conn:
                if conn is None:
                    return {"success": False, "error": "no database connection"}
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO cgc_guard.tenant_plans (org_id, plan) VALUES (%s, %s) "
                    "ON CONFLICT (org_id) DO UPDATE SET plan = EXCLUDED.plan, updated_at = NOW()",
                    (org_id, plan)
                )
                conn.commit()
            logger.info(f"[tenant] {org_id} upgraded to {plan}")
            return {"success": True, "org_id": org_id, "plan": plan}
        except Exception as e:
            logger.warning(f"[tenant] upgrade_plan failed for {org_id} (non-fatal): {e}")
            return {"success": False, "error": str(e)}

    def get_tenant(self, org_id: str) -> Optional[Dict[str, Any]]:
        plan = self._get_plan(org_id)
        return {
            "org_id": org_id,
            "plan": plan,
            "quotas": self.PLAN_QUOTAS.get(plan, self.PLAN_QUOTAS["STANDARD"]),
            "features": self.PLAN_FEATURES.get(plan, self.PLAN_FEATURES["STANDARD"]),
            "usage": self.get_usage(org_id),
        }

    def _get_usage(self, org_id: str, resource: str) -> int:
        db = get_database()
        try:
            with db.get_connection() as conn:
                if conn is None:
                    return 0
                cur = conn.cursor()
                cur.execute(
                    "SELECT count FROM cgc_guard.tenant_usage WHERE org_id = %s AND resource = %s AND period = %s",
                    (org_id, resource, self._period())
                )
                row = cur.fetchone()
                return row["count"] if row else 0
        except Exception as e:
            logger.warning(f"[tenant] usage read failed for {org_id}/{resource} (non-fatal, allowing): {e}")
            return 0

    def _increment_usage(self, org_id: str, resource: str, amount: int) -> None:
        db = get_database()
        try:
            with db.get_connection() as conn:
                if conn is None:
                    return
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO cgc_guard.tenant_usage (org_id, resource, period, count) "
                    "VALUES (%s, %s, %s, %s) "
                    "ON CONFLICT (org_id, resource, period) "
                    "DO UPDATE SET count = cgc_guard.tenant_usage.count + EXCLUDED.count, updated_at = NOW()",
                    (org_id, resource, self._period(), amount)
                )
                conn.commit()
        except Exception as e:
            logger.warning(f"[tenant] usage increment failed for {org_id}/{resource} (non-fatal): {e}")

    def check_quota(
        self,
        org_id: str,
        resource: str,
        increment: int = 0
    ) -> bool:
        """
        Check if tenant has quota remaining.
        increment=1 to consume quota after a successful decision.
        Returns True if quota available, False if exceeded.

        Same calling contract as before: a call with increment>0 always
        records and returns True (fire-and-forget consumption); the actual
        gate is a call with increment=0, which compares the durable count
        against the plan's monthly limit.
        """
        plan = self._get_plan(org_id)
        limit = self.PLAN_QUOTAS.get(plan, self.PLAN_QUOTAS["STANDARD"]).get(resource, 50_000)

        if limit == -1:
            # unlimited
            if increment:
                self._increment_usage(org_id, resource, increment)
            return True

        if increment:
            self._increment_usage(org_id, resource, increment)
            return True

        current = self._get_usage(org_id, resource)
        return current < limit

    def check_feature(self, org_id: str, feature: str) -> bool:
        """Check if tenant has access to a feature."""
        plan = self._get_plan(org_id)
        return self.PLAN_FEATURES.get(plan, self.PLAN_FEATURES["STANDARD"]).get(feature, False)

    def get_rate_limit(self, org_id: str, resource: str, default: int) -> int:
        """Per-minute burst ceiling for this tenant's plan, for the distributed rate limiter."""
        plan = self._get_plan(org_id)
        return self.PLAN_RATE_LIMITS.get(plan, self.PLAN_RATE_LIMITS["STANDARD"]).get(resource, default)

    def get_usage(self, org_id: str) -> Dict[str, Any]:
        db = get_database()
        try:
            with db.get_connection() as conn:
                if conn is None:
                    return {}
                cur = conn.cursor()
                cur.execute(
                    "SELECT resource, count FROM cgc_guard.tenant_usage WHERE org_id = %s AND period = %s",
                    (org_id, self._period())
                )
                rows = cur.fetchall()
                return {r["resource"]: r["count"] for r in rows}
        except Exception as e:
            logger.warning(f"[tenant] get_usage failed for {org_id} (non-fatal): {e}")
            return {}


# Singleton
tenant_manager = TenantManager()
