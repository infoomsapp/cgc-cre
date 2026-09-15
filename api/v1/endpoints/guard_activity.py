"""
GET /guard/activity/suspicious-payloads
GET /guard/activity/internal-flags
GET /guard/activity/login-stats

Dashboard-visibility reads over what Phase 2 (external guard) and Phase 3
(internal guard) have already been persisting since they shipped -- none of
it had any read surface before this. Pure read, no new capture point.

Auth: same Bearer-token scheme as the rest of the API, applied at the
router-mount level in main.py (dependencies=[Depends(get_current_user)]),
so this file has no auth logic of its own - same pattern as every other router.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel

from app.Core.db.database import get_database
from app.modules.guard.payload_guard import get_recent_suspicious_payloads
from app.modules.guard.internal_guard import get_recent_internal_flags
from app.modules.guard.login_guard import get_login_activity_stats
from app.modules.guard.circuit_breaker import list_open_breakers, reset_breaker
from app.modules.guard.kill_switch import (
    activate_kill_switch, deactivate_kill_switch, get_kill_switch_status,
    list_active_kill_switches, GLOBAL_SCOPE,
)

router = APIRouter()


@router.get("/suspicious-payloads", summary="Recent soft-flagged payloads")
async def list_suspicious_payloads(limit: int = Query(50, ge=1, le=500)) -> Dict[str, Any]:
    rows = get_recent_suspicious_payloads(limit=limit)
    return {"total": len(rows), "payloads": rows}


@router.get("/internal-flags", summary="Recent internal-guard findings")
async def list_internal_flags(
    limit: int = Query(50, ge=1, le=500),
    flag_type: Optional[str] = Query(None),
) -> Dict[str, Any]:
    rows = get_recent_internal_flags(limit=limit, flag_type=flag_type)
    return {"total": len(rows), "flags": rows}


@router.get("/login-stats", summary="Login activity + credential-stuffing-flagged IPs")
async def login_stats(hours: int = Query(24, ge=1, le=168)) -> Dict[str, Any]:
    return get_login_activity_stats(hours=hours)


@router.get("/timeseries", summary="Hourly guard event counts (payloads/flags/failed logins)")
async def guard_timeseries(hours: int = Query(24, ge=1, le=168)) -> Dict[str, Any]:
    """Powers the Security dashboard's live chart. See
    Database.get_guard_events_timeseries()'s docstring for the query shape."""
    return get_database().get_guard_events_timeseries(hours=hours)


@router.get("/circuit-breakers", summary="Currently OPEN/HALF_OPEN circuit breakers")
async def circuit_breakers(limit: int = Query(50, ge=1, le=500)) -> Dict[str, Any]:
    rows = list_open_breakers(limit=limit)
    return {"total": len(rows), "breakers": rows}


class CircuitBreakerResetRequest(BaseModel):
    org_id: str
    user_email: str


@router.post("/circuit-breakers/reset", summary="Manually close a tripped circuit breaker")
async def reset_circuit_breaker(body: CircuitBreakerResetRequest) -> Dict[str, Any]:
    reset = reset_breaker(body.org_id, body.user_email)
    return {"reset": reset, "org_id": body.org_id, "user_email": body.user_email}


class KillSwitchActionRequest(BaseModel):
    scope: str  # 'GLOBAL' or a specific app_source
    reason: Optional[str] = None


@router.get("/kill-switches", summary="Currently active kill switches (GLOBAL + any tenant)")
async def kill_switches() -> Dict[str, Any]:
    rows = list_active_kill_switches()
    return {"total": len(rows), "kill_switches": rows}


@router.post("/kill-switches/activate", summary="Activate a kill switch (GLOBAL halts every tenant)")
async def activate_kill_switch_endpoint(body: KillSwitchActionRequest) -> Dict[str, Any]:
    # Operator override -- unlike the self-service /tenants/my-apps/{app_source}/
    # kill-switch/* routes, this can target ANY scope including GLOBAL, for
    # incident response when a tenant can't (or shouldn't have to) act
    # themselves, or the whole platform needs to stop.
    #
    # activated_by is a generic "admin" label, not the caller's real
    # email, same limitation every other route in this file already has:
    # this router only gets require_admin_or_service applied at the
    # mount level in main.py (see module docstring), with no per-route
    # access to the resolved user object -- an existing gap in this
    # codebase's router architecture, not something to special-case a new
    # pattern around here just for this one action's audit trail.
    return activate_kill_switch(body.scope, body.reason, activated_by="admin")


@router.post("/kill-switches/deactivate", summary="Deactivate a kill switch")
async def deactivate_kill_switch_endpoint(body: KillSwitchActionRequest) -> Dict[str, Any]:
    deactivated = deactivate_kill_switch(body.scope, deactivated_by="admin")
    return {"deactivated": deactivated, "scope": body.scope}
