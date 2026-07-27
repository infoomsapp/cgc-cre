"""
CGC CORE™ Tenant Management Package
Olympus Mont Systems LLC

This package provides:
- Multi-tenant isolation
- Plan and quota enforcement
- Feature gating
- Billing integration (Stripe)
"""

from .multi_tenant import TenantManager, tenant_manager

__all__ = [
    "TenantManager",
    "tenant_manager",
]