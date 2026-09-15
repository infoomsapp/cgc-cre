"""
Per-tenant conditional action policies -- item #3 of the AI-agent
action-governance plan (item #1: PreFilter's action_within_capabilities
check; item #2: the circuit breaker over repeated violations).

Both prior items are agent- or actor-scoped and code/env-defined. Neither
lets the TENANT itself declare "no agent, however configured, may take
action X against my data" or "action X always needs a human" -- that is
a business decision belonging to the tenant, not something PreFilter's
static AREA_DATA_MAPPINGS or an agent's own capability list can express.
This closes that gap: a tenant-owned, self-service table of
(action -> BLOCK | REQUIRE_HUMAN_REVIEW) rules, each optionally
conditioned on area and/or data domains -- see
Database.set_tenant_action_policy()'s docstring context for the schema.

Evaluated in main.py's run_cgc_prefilter(), after the circuit breaker
check and before PreFilter.evaluate() -- cheaper to reject here than to
run PreFilter's checks first. A tenant with no policies configured
behaves exactly as before this feature existed (same override-then-
fallback convention as tenant weighting overrides).

Fails open on any DB error, same posture as every other cgc_guard.*-
adjacent check in this codebase: a broken policy lookup must not itself
take down governance decisions for tenants that never configured one.
"""

import logging
from typing import Any, Dict, List, Optional

from app.Core.db.database import get_database

logger = logging.getLogger("cgc.guard.tenant_policy")

VALID_POLICY_TYPES = {"BLOCK", "REQUIRE_HUMAN_REVIEW"}


def evaluate_tenant_policy(
    app_source: str,
    action: str,
    area: Optional[str],
    data_domains: List[str],
) -> Optional[Dict[str, Any]]:
    """
    Returns None if no policy applies (request proceeds to PreFilter as
    normal). Returns {"policy_type", "reason"} if a policy fires.
    """
    if not app_source or app_source == "unknown":
        return None

    db = get_database()
    try:
        policy = db.get_tenant_action_policy(app_source, action)
    except Exception as e:
        logger.warning(f"[guard] tenant policy lookup failed for {app_source}/{action} (non-fatal, allowing): {e}")
        return None

    if not policy:
        return None

    # Condition 1: area. NULL/empty on the row means "applies to every
    # area"; a set value means the policy only fires when the request's
    # own area matches it.
    policy_area = policy.get("area")
    if policy_area and policy_area != area:
        return None

    # Condition 2: data domains. NULL/empty on the row means "no domain
    # condition, area match (or unconditional) is enough"; a set value
    # means the policy only fires when at least one requested domain is
    # in the blocked set.
    blocked_domains = set(policy.get("blocked_data_domains") or [])
    if blocked_domains and not (blocked_domains & set(data_domains or [])):
        return None

    policy_type = policy.get("policy_type")
    reason = policy.get("reason") or (
        f"Tenant policy: action '{action}' is {policy_type} for app_source '{app_source}'"
    )
    return {"policy_type": policy_type, "reason": reason}
