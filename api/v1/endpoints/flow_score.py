"""
GET /flow-score/{app_source}   - business-flow score for one connected app

Phase 1 of the CGC Core reinforcement plan: a read-only aggregation over
cgc_tco.audit_trail (no new capture point, no write path touched). See
app/modules/flow_scoring/flow_scoring.py for the full scoring design and its
explicitly scoped limitations.

Auth: same Bearer-token scheme as the rest of the API, applied at the
router-mount level in main.py (dependencies=[Depends(get_current_user)]),
so this file has no auth logic of its own - same pattern as monitor.py.
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query, Request

from app.modules.flow_scoring.flow_scoring import FlowScoring
from api.v1.endpoints.monitor import ALLOWED_APP_SOURCES

router = APIRouter()


@router.get("/{app_source}", summary="Business-flow score for one connected app")
async def get_flow_score(
    app_source: str,
    request: Request,
    window_days: int = Query(7, ge=1, le=90),
    baseline_days: int = Query(30, ge=7, le=180),
    tenant_id: Optional[str] = Query(None, description="Narrow to one organization within app_source"),
) -> Dict[str, Any]:
    if app_source not in ALLOWED_APP_SOURCES:
        raise HTTPException(status_code=400, detail=f"Unknown app_source: {app_source}")

    # Gap 1 (per-tenant API keys): a caller authenticated with a per-tenant
    # key may only ever query ITS OWN app_source's score, never another
    # tenant's -- see monitor.py's report_error for why this re-resolves
    # the principal here (request.app.auth) instead of importing
    # get_current_user (circular import against main.py). The legacy
    # shared key and admin dashboard sessions have no bound app_source and
    # keep today's cross-tenant visibility (that's the intended admin view).
    auth_header = request.headers.get("authorization", "")
    token = auth_header[7:] if auth_header.lower().startswith("bearer ") else auth_header
    principal = request.app.auth.verify_token(token) if (token and request.app.auth) else None
    bound_app_source = (principal or {}).get("app_source")
    if bound_app_source and bound_app_source != app_source:
        raise HTTPException(status_code=403, detail="This key is not authorized for that app_source")

    # Instantiated per-request, same as monitor.py's get_database() calls -
    # no module-level singleton, no extra import-time side effect on main.py's
    # import chain.
    flow_scoring = FlowScoring()
    return flow_scoring.compute_flow_score(
        app_source, window_days=window_days, baseline_days=baseline_days, tenant_id=tenant_id
    )
