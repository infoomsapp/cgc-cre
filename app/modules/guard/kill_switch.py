"""
Kill switch -- item #4, last of the AI-agent action-governance plan
(item #1: PreFilter's action_within_capabilities check; item #2: the
circuit breaker; item #3: per-tenant conditional action policies).

Everything built for items #1-3 is conditional: it evaluates a request
against a rule and only denies if that rule is tripped. A real incident
(a compromised credential, a runaway agent, a tenant policy that turns
out to be wrong under load) needs the opposite: an unconditional,
immediate stop that requires no request to look any particular way, no
code deploy, and no waiting for a threshold to trip. That's what this
module is -- a single boolean per scope, checked first, before anything
else in run_cgc_prefilter.

Two scopes:
  - 'GLOBAL': platform-wide. Every /governance/decision call is denied
    regardless of tenant, actor, or action. Operator-only (this is the
    literal "pull the plug on everything" control).
  - a real app_source: one tenant's emergency stop. Self-service --
    the tenant that owns app_source can trip and clear their own, same
    ownership model as weighting overrides/tenant action policies. This
    matters independent of any admin action: a tenant who suspects their
    own integration or agent has gone wrong should not have to file a
    support ticket to stop it.

GLOBAL and the per-tenant scope are checked in a single query (both are
candidate primary keys), and GLOBAL wins if both happen to be active --
there's never a reason to report a narrower scope once the wider one
already applies.

Fails CLOSED on a DB error for the kill switch specifically. This is a
deliberate reversal of every other guard module in this codebase, all of
which fail open -- there, a broken check must not itself cause an
outage. A kill switch's entire purpose is to be reliable exactly when
something else has already gone wrong; degrading it to "allow through"
on its own failure would defeat that purpose at precisely the moment it
matters most. On error this returns SAFE_DEFAULT below.
"""

import logging
import os
from typing import Any, Dict, List, Optional

from app.Core.db.database import get_database

logger = logging.getLogger("cgc.guard.kill_switch")

GLOBAL_SCOPE = "GLOBAL"

# What to do when the kill-switch check itself fails (DB unreachable,
# etc). True = treat as killed (deny everything until the DB issue is
# fixed); False = treat as not killed (fail open, like every other
# guard module). Deliberately env-overridable rather than hardcoded --
# "how paranoid should an infra outage make us" is an operational
# judgment call, not a constant this module should assert unilaterally.
import os
FAIL_CLOSED = os.getenv("CGC_KILL_SWITCH_FAIL_CLOSED", "true").lower() == "true"


def is_killed(app_source: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Returns None if neither GLOBAL nor this app_source's kill switch is
    active. Returns {"scope", "reason", "activated_at"} if either is.
    """
    db = get_database()
    if not db.use_postgres:
        return None

    scopes = [GLOBAL_SCOPE]
    if app_source and app_source != "unknown":
        scopes.append(app_source)

    try:
        with db.get_connection() as conn:
            if conn is None:
                return None
            cur = conn.cursor()
            cur.execute(
                "SELECT scope, reason, activated_at FROM cgc_guard.kill_switch_state "
                "WHERE scope = ANY(%s) AND active = TRUE",
                (scopes,)
            )
            rows = {r["scope"]: r for r in cur.fetchall()}

            hit = rows.get(GLOBAL_SCOPE) or (rows.get(app_source) if app_source else None)
            if not hit:
                return None
            return {
                "scope": hit["scope"],
                "reason": hit["reason"] or f"Kill switch active for scope '{hit['scope']}'",
                "activated_at": hit["activated_at"].isoformat() if hit["activated_at"] else None,
            }
    except Exception as e:
        logger.error(f"[guard] kill switch check failed (fail_closed={FAIL_CLOSED}): {e}")
        if FAIL_CLOSED:
            return {"scope": "UNKNOWN", "reason": f"Kill switch check failed, failing closed: {e}", "activated_at": None}
        return None


def activate_kill_switch(scope: str, reason: Optional[str], activated_by: str) -> Dict[str, Any]:
    db = get_database()
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO cgc_guard.kill_switch_state
                    (scope, active, reason, activated_by, activated_at, deactivated_by, deactivated_at)
                VALUES (%s, TRUE, %s, %s, NOW(), NULL, NULL)
                ON CONFLICT (scope) DO UPDATE SET
                    active = TRUE, reason = EXCLUDED.reason, activated_by = EXCLUDED.activated_by,
                    activated_at = NOW(), deactivated_by = NULL, deactivated_at = NULL, updated_at = NOW()
                RETURNING scope, active, reason, activated_by, activated_at
            """, (scope, reason, activated_by))
            row = cur.fetchone()
            logger.warning(f"[guard] KILL SWITCH ACTIVATED: scope={scope} by={activated_by} reason={reason}")
            return dict(row) if row else {}


def deactivate_kill_switch(scope: str, deactivated_by: str) -> bool:
    db = get_database()
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE cgc_guard.kill_switch_state SET
                    active = FALSE, deactivated_by = %s, deactivated_at = NOW(), updated_at = NOW()
                WHERE scope = %s AND active = TRUE
            """, (deactivated_by, scope))
            found = cur.rowcount > 0
            if found:
                logger.warning(f"[guard] kill switch deactivated: scope={scope} by={deactivated_by}")
            return found


def get_kill_switch_status(scope: str) -> Optional[Dict[str, Any]]:
    db = get_database()
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM cgc_guard.kill_switch_state WHERE scope = %s",
                (scope,)
            )
            row = cur.fetchone()
            return dict(row) if row else None


def list_active_kill_switches() -> List[Dict[str, Any]]:
    db = get_database()
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM cgc_guard.kill_switch_state WHERE active = TRUE ORDER BY activated_at DESC"
            )
            return [dict(r) for r in cur.fetchall()]
