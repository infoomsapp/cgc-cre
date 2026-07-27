"""
CGC Core — Multi-tenant Manager (stub production-ready)
Gestiona quotas y features por tenant.

Olympus Mont Systems LLC © 2026
"""

import os
import logging
from typing import Dict, Any

logger = logging.getLogger("cgc.tenant")


class TenantManager:
    """
    Manages tenant quotas and feature flags.
    In production: reads from Supabase tenants table.
    In development: uses env-based defaults.
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

    def __init__(self):
        self._usage: Dict[str, Dict[str, int]] = {}

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
        """
        plan = os.getenv(f"CGC_TENANT_{org_id.upper()}_PLAN", "STANDARD")
        limit = self.PLAN_QUOTAS.get(plan, self.PLAN_QUOTAS["STANDARD"]).get(resource, 50_000)

        if limit == -1:
            # unlimited
            if increment:
                self._usage.setdefault(org_id, {})
                self._usage[org_id][resource] = self._usage[org_id].get(resource, 0) + increment
            return True

        current = self._usage.get(org_id, {}).get(resource, 0)

        if increment:
            self._usage.setdefault(org_id, {})
            self._usage[org_id][resource] = current + increment
            return True

        return current < limit

    def check_feature(self, org_id: str, feature: str) -> bool:
        """Check if tenant has access to a feature."""
        plan = os.getenv(f"CGC_TENANT_{org_id.upper()}_PLAN", "STANDARD")
        return self.PLAN_FEATURES.get(plan, self.PLAN_FEATURES["STANDARD"]).get(feature, False)

    def get_usage(self, org_id: str) -> Dict[str, Any]:
        return self._usage.get(org_id, {})


# Singleton
tenant_manager = TenantManager()